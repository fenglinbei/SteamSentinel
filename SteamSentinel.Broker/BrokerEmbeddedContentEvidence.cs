using System.Security.Cryptography;
using SteamSentinel.Core.Inspection;
using SteamSentinel.Core.Models;
using SteamSentinel.Core.Remediation;
using SteamSentinel.Core.Reporting;
using SteamSentinel.Core.Utilities;

namespace SteamSentinel.Broker;

internal sealed partial class BrokerEngine
{
    internal static void ValidateContentEvidenceRequestShape(RemediationPlan plan)
    {
        foreach (RemediationAction action in plan.Actions) ValidateContentEvidenceActionShape(action);
    }

    internal static void ValidateContentEvidenceActionShape(RemediationAction action)
    {
        if (action.ContentEvidenceRuleId is null) return;
        if (action.ContentEvidenceRuleId == SteamAlertUpdateHandoff.RuleId && action.Type == RemediationActionType.StopHostProcess)
        { SteamAlertHandoffStopper.ValidateRequest(action); return; }
        if (action.ContentEvidenceRuleId is not (SteamAlertEmbeddedEvidence.RuleId or SteamAlertUpdateHandoff.RuleId) || action.Type != RemediationActionType.QuarantineFile ||
            action.UserSelectedRisk || action.IsKnownMalware || action.ConfidenceScore != 100 || action.RelatedFilePath is not null ||
            !Validation.IsHexSha256(action.ExpectedSha256) || !FileScopeSafety.IsValidIdentity(action.ExpectedFileIdentity) ||
            !FileScopeSafety.IsValidIdentity(action.ExpectedParentIdentity) || !FileScopeSafety.EvaluatePath(action.Target).Allowed)
            throw InvalidContentEvidence();
    }

    private static async Task VerifyContentEvidencePreparationAsync(RemediationPlan plan, CancellationToken token)
    {
        foreach (RemediationAction action in plan.Actions.Where(a => a.ContentEvidenceRuleId is not null && a.Type == RemediationActionType.QuarantineFile))
        {
            using BrokerDirectoryLease parent = BrokerDirectoryLease.OpenParent(action.Target, action.ExpectedParentIdentity);
            await using SecureFileLease source = SecureFileLease.Open(action.Target);
            _ = await VerifyQuarantineContentEvidenceAsync(action, source, token);
        }
    }

    internal static async Task<string?> VerifyQuarantineContentEvidenceAsync(RemediationAction action, SecureFileLease source, CancellationToken token)
    {
        ValidateContentEvidenceActionShape(action);
        if (action.ContentEvidenceRuleId is null) return null;
        BrokerFileScopeAuthorization.RequireSafePath(source.FinalPath);
        FileScopeSafety.ValidateHandlePath(source.Handle, action.Target);
        if (!PathsEquivalent(source.FinalPath, action.Target) || FileScopeSafety.ReadLinkCount(source.Handle) != 1 ||
            FileScopeSafety.ReadIdentity(source.Handle) != action.ExpectedFileIdentity)
            throw InvalidContentEvidence();
        if (action.ContentEvidenceRuleId == SteamAlertUpdateHandoff.RuleId)
        {
            await using SteamAlertHandoffLease proof = await OpenHandoffProofLeaseAsync(action.Target, action.ExpectedSha256!, token, source);
            return SteamAlertUpdateHandoff.RuleId;
        }
        byte[] bytes = await source.ReadBytesAsync(checked((int)SteamAlertEmbeddedEvidence.MaximumBytes), token);
        // Production callers always use the catalog embedded in this independently running Broker.
        // Neither a report, a plan nor the scanner's supplied RuleSet can replace it.
        return VerifyEmbeddedQuarantineBytes(action, bytes, token);
    }

    private static string VerifyEmbeddedQuarantineBytes(RemediationAction action, byte[] bytes, CancellationToken token)
    {
        ValidateContentEvidenceActionShape(action);
        if (action.ContentEvidenceRuleId != SteamAlertEmbeddedEvidence.RuleId ||
            !Convert.ToHexString(SHA256.HashData(bytes)).Equals(action.ExpectedSha256, StringComparison.OrdinalIgnoreCase))
            throw InvalidContentEvidence();
        using MemoryStream stream = new(bytes, writable: false);
        SteamAlertEmbeddedProof? proof = SteamAlertEmbeddedEvidence.Inspect(stream, token: token);
        if (proof?.RuleId != action.ContentEvidenceRuleId) throw InvalidContentEvidence();
        return proof.RuleId;
    }

    private static async Task VerifyEmbeddedQuarantineRecordAsync(QuarantineRecord record, CancellationToken token)
    {
        if (record.UserSelectedRisk || record.Type != RemediationActionType.QuarantineFile ||
            record.VerifiedContentRuleId != SteamAlertEmbeddedEvidence.RuleId || !Validation.IsHexSha256(record.Sha256))
            throw InvalidContentEvidence();
        string? path = File.Exists(record.OriginalTarget) ? record.OriginalTarget : record.QuarantinedPath;
        if (path is null) throw InvalidContentEvidence();
        await using SecureFileLease source = SecureFileLease.Open(path);
        if (FileScopeSafety.ReadLinkCount(source.Handle) != 1) throw InvalidContentEvidence();
        byte[] bytes = await source.ReadBytesAsync(checked((int)SteamAlertEmbeddedEvidence.MaximumBytes), token);
        if (!Convert.ToHexString(SHA256.HashData(bytes)).Equals(record.Sha256, StringComparison.OrdinalIgnoreCase))
            throw InvalidContentEvidence();
        using MemoryStream stream = new(bytes, writable: false);
        if (SteamAlertEmbeddedEvidence.Inspect(stream, token: token) is null) throw InvalidContentEvidence();
    }

    private static InvalidDataException InvalidContentEvidence() => MessageExceptions.Create(
        MessageText.Create("Remediation.ContentEvidence.Invalid"), text => new InvalidDataException(text));

    private static async Task VerifyHandoffQuarantineRecordAsync(QuarantineRecord record, QuarantineManifest manifest, CancellationToken token)
    {
        if (record.UserSelectedRisk || record.Type != RemediationActionType.QuarantineFile ||
            record.VerifiedContentRuleId != SteamAlertUpdateHandoff.RuleId || !Validation.IsHexSha256(record.Sha256)) throw InvalidContentEvidence();
        string? scriptPath = File.Exists(record.OriginalTarget) ? record.OriginalTarget : record.QuarantinedPath;
        if (scriptPath is null) throw InvalidContentEvidence();
        await using SecureFileLease script = SecureFileLease.Open(scriptPath);
        byte[] bytes = await script.ReadBytesAsync(SteamAlertUpdateHandoff.MaximumScriptBytes, token);
        if (!Convert.ToHexString(SHA256.HashData(bytes)).Equals(record.Sha256, StringComparison.OrdinalIgnoreCase) ||
            !SteamAlertUpdateHandoff.TryParse(bytes, record.OriginalTarget, out var descriptor)) throw InvalidContentEvidence();
        foreach (string original in new[] { descriptor.TargetExe, descriptor.StagedExe, descriptor.BackupExe })
        {
            QuarantineRecord? payloadRecord = manifest.Records.FirstOrDefault(item => item.Type == RemediationActionType.QuarantineFile &&
                PathsEquivalent(item.OriginalTarget, original) && SteamAlertWatchdog.RoleForHash(item.Sha256) == SteamAlertWatchdog.PayloadRole);
            string? payloadPath = File.Exists(original) ? original : payloadRecord?.QuarantinedPath;
            if (payloadPath is null || !File.Exists(payloadPath)) continue;
            await using SecureFileLease payload = SecureFileLease.Open(payloadPath);
            if (payload.Length > 32 * 1024 * 1024) continue;
            if (SteamAlertWatchdog.RoleForHash(await payload.ComputeSha256Async(token)) == SteamAlertWatchdog.PayloadRole) return;
        }
        throw InvalidContentEvidence();
    }
}
