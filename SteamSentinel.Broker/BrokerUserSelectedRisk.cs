using SteamSentinel.Core.Models;
using SteamSentinel.Core.Remediation;
using SteamSentinel.Core.Reporting;
using SteamSentinel.Core.Utilities;

namespace SteamSentinel.Broker;

internal sealed partial class BrokerEngine
{
    private readonly Dictionary<Guid, RemediationAction> _userRiskFiles = [];

    internal static void ValidateUserRiskRequestShape(RemediationPlan plan)
    {
        if (!RemediationModePolicy.IsValid(plan.Mode) ||
            plan.Actions.Any(a => a.UserSelectedRisk) &&
            (plan.Mode != RemediationMode.Aggressive || !plan.ExplicitFileTargetsRequested))
            throw InvalidRiskRequest();
        RemediationAction[] files = plan.Actions.Where(a => a.UserSelectedRisk && a.Type == RemediationActionType.QuarantineFile).ToArray();
        if (files.Select(f => Path.GetFullPath(f.Target)).Distinct(StringComparer.OrdinalIgnoreCase).Count() != files.Length)
            throw InvalidRiskRequest();
        foreach (RemediationAction action in plan.Actions.Where(a => a.UserSelectedRisk))
        {
            if (action.IsKnownMalware || action.Type is not (RemediationActionType.QuarantineFile or
                    RemediationActionType.StopProcess or RemediationActionType.RemoveRegistryValue) ||
                !FileScopeSafety.IsValidIdentity(action.ExpectedFileIdentity) ||
                !FileScopeSafety.IsValidIdentity(action.ExpectedParentIdentity)) throw InvalidRiskRequest();
            string? path = action.Type == RemediationActionType.RemoveRegistryValue ? action.RelatedFilePath : action.Target;
            string? hash = action.Type == RemediationActionType.RemoveRegistryValue ? action.RelatedFileSha256 : action.ExpectedSha256;
            if (path is null || !Validation.IsHexSha256(hash) || !FileScopeSafety.EvaluatePath(path).Allowed)
                throw InvalidRiskRequest();
            if (action.Type == RemediationActionType.QuarantineFile) continue;
            RemediationAction? file = files.FirstOrDefault(f => PathsEquivalent(f.Target, path) &&
                string.Equals(f.ExpectedSha256, hash, StringComparison.OrdinalIgnoreCase) &&
                f.ExpectedFileIdentity == action.ExpectedFileIdentity && f.ExpectedParentIdentity == action.ExpectedParentIdentity);
            if (file is null || action.RelatedFilePath is null || !PathsEquivalent(action.RelatedFilePath, file.Target) ||
                !string.Equals(action.RelatedFileSha256, file.ExpectedSha256, StringComparison.OrdinalIgnoreCase))
                throw InvalidRiskRequest();
            if (action.Type == RemediationActionType.RemoveRegistryValue &&
                (action.ExpectedValueData is null || !BoundContentEvidence.IsDirectInvocation(action.ExpectedValueData, file.Target)))
                throw InvalidRiskRequest();
        }
    }

    private void ValidateUserRiskPlan(RemediationPlan plan)
    {
        _userRiskFiles.Clear();
        ValidateUserRiskRequestShape(plan);
        RemediationAction[] files = plan.Actions.Where(a => a.UserSelectedRisk && a.Type == RemediationActionType.QuarantineFile).ToArray();
        var dependencies = RemediationDependencies.Build(plan.Actions);
        foreach (RemediationAction action in plan.Actions.Where(a => a.UserSelectedRisk))
        {
            string path = action.Type == RemediationActionType.RemoveRegistryValue ? action.RelatedFilePath! : action.Target;
            RemediationAction file = files.First(f => PathsEquivalent(f.Target, path));
            BrokerFileScopeAuthorization? authorization = _preparingFileTargets ?? _confirmedFileTargets;
            if (authorization is null || !authorization.Contains(file, file.Target, file.ExpectedSha256) ||
                action.ActionId != file.ActionId && !dependencies[file.ActionId].Contains(action.ActionId))
                throw InvalidRiskRequest();
            _userRiskFiles.Add(action.ActionId, file);
        }
    }

    private bool HasUserRiskBinding(RemediationAction action) => action.UserSelectedRisk &&
        _userRiskFiles.TryGetValue(action.ActionId, out RemediationAction? file) &&
        (_preparingFileTargets ?? _confirmedFileTargets)?.Contains(file, file.Target, file.ExpectedSha256) == true;

    private async Task VerifyUserRiskLeaseAsync(RemediationAction action, SecureFileLease lease, CancellationToken token)
    {
        if (!HasUserRiskBinding(action)) throw InvalidRiskRequest();
        RemediationAction file = _userRiskFiles[action.ActionId];
        BrokerFileScopeAuthorization.RequireSafePath(lease.FinalPath);
        FileScopeSafety.ValidateHandlePath(lease.Handle, file.Target);
        if (!PathsEquivalent(lease.FinalPath, file.Target) || FileScopeSafety.ReadLinkCount(lease.Handle) != 1 ||
            FileScopeSafety.ReadIdentity(lease.Handle) != file.ExpectedFileIdentity ||
            !(await lease.ComputeSha256Async(token)).Equals(file.ExpectedSha256, StringComparison.OrdinalIgnoreCase))
            throw InvalidRiskRequest();
    }

    private static bool IsUserRiskRegistryRecord(QuarantineRecord record) => record.UserSelectedRisk &&
        record.Type == RemediationActionType.RemoveRegistryValue && record.RelatedFilePath is { } path &&
        FileScopeSafety.IsValidIdentity(record.OriginalFileIdentity) && FileScopeSafety.IsValidIdentity(record.OriginalParentIdentity) &&
        FileScopeSafety.EvaluatePath(path).Allowed && Validation.IsHexSha256(record.RelatedFileSha256) &&
        record.RegistryValueData is { } command && BoundContentEvidence.IsDirectInvocation(command, path);

    internal static async Task VerifyUserRiskRecordedContentAsync(QuarantineRecord record, QuarantineManifest manifest, CancellationToken token)
    {
        if (record.Type == RemediationActionType.QuarantineFile) return;
        if (!IsUserRiskRegistryRecord(record)) throw InvalidRiskRequest();
        // Content classification is deliberately not upgraded. Authenticate the exact selected
        // object (or its same-incident backup) before restoring a saved direct startup command.
        QuarantineRecord? file = manifest.Records.FirstOrDefault(r => r.UserSelectedRisk && r.Type == RemediationActionType.QuarantineFile &&
            PathsEquivalent(r.OriginalTarget, record.RelatedFilePath!) &&
            r.OriginalFileIdentity == record.OriginalFileIdentity && r.OriginalParentIdentity == record.OriginalParentIdentity &&
            string.Equals(r.Sha256, record.RelatedFileSha256, StringComparison.OrdinalIgnoreCase));
        string? path = File.Exists(record.RelatedFilePath) ? record.RelatedFilePath : file?.QuarantinedPath;
        if (path is null) throw InvalidRiskRequest();
        using BrokerDirectoryLease? parent = file is null ? BrokerDirectoryLease.OpenParent(path, record.OriginalParentIdentity) : null;
        await using SecureFileLease lease = SecureFileLease.Open(path);
        if (file is null && FileScopeSafety.ReadIdentity(lease.Handle) != record.OriginalFileIdentity ||
            FileScopeSafety.ReadLinkCount(lease.Handle) != 1 ||
            !(await lease.ComputeSha256Async(token)).Equals(record.RelatedFileSha256, StringComparison.OrdinalIgnoreCase))
            throw InvalidRiskRequest();
    }

    // An interrupted intent may have left the original untouched. A completed restore may
    // also have reached disk before the manifest commit. Exact equality is a no-op in both cases.
    internal static async Task RestoreUserRiskFileAsync(QuarantineRecord record, CancellationToken token)
    {
        if (!record.UserSelectedRisk || !record.ExplicitFileAuthorization) throw InvalidRiskRequest();
        ValidateExplicitRestoreRecord(record);
        if (!File.Exists(record.OriginalTarget))
        {
            await RestoreExplicitFileAsync(record, token);
            return;
        }
        using BrokerDirectoryLease parent = BrokerDirectoryLease.OpenParent(record.OriginalTarget, record.OriginalParentIdentity);
        await using SecureFileLease current = SecureFileLease.OpenWithSecurity(record.OriginalTarget);
        if (FileScopeSafety.ReadLinkCount(current.Handle) != 1 ||
            !(await current.ComputeSha256Async(token)).Equals(record.Sha256, StringComparison.OrdinalIgnoreCase) ||
            BrokerFileMetadata.CaptureLocked(current.Handle) != BrokerFileMetadata.FromRecord(record))
            throw InvalidRiskRequest();
    }

    internal static async Task RestoreUserRiskRegistryValueAsync(QuarantineRecord record, CancellationToken token)
    {
        if (!IsUserRiskRegistryRecord(record)) throw InvalidRiskRequest();
        using BrokerDirectoryLease parent = BrokerDirectoryLease.OpenParent(record.RelatedFilePath!, record.OriginalParentIdentity);
        await using SecureFileLease target = SecureFileLease.Open(record.RelatedFilePath!);
        BrokerFileScopeAuthorization.RequireSafePath(target.FinalPath);
        FileScopeSafety.ValidateHandlePath(target.Handle, record.RelatedFilePath!);
        if (FileScopeSafety.ReadLinkCount(target.Handle) != 1 ||
            !(await target.ComputeSha256Async(token)).Equals(record.RelatedFileSha256, StringComparison.OrdinalIgnoreCase))
            throw InvalidRiskRequest();
        using Microsoft.Win32.RegistryKey baseKey = Microsoft.Win32.RegistryKey.OpenBaseKey(
            record.RegistryHive == "HKCU" ? Microsoft.Win32.RegistryHive.CurrentUser : Microsoft.Win32.RegistryHive.LocalMachine,
            Enum.Parse<Microsoft.Win32.RegistryView>(record.RegistryView!));
        using Microsoft.Win32.RegistryKey? key = baseKey.OpenSubKey(record.RegistryKey!);
        object? current = key?.GetValue(record.RegistryValueName!, null, Microsoft.Win32.RegistryValueOptions.DoNotExpandEnvironmentNames);
        if (current is null) { RestoreRegistryValue(record); return; }
        if (current is not string text || text != record.RegistryValueData || (int)key!.GetValueKind(record.RegistryValueName!) != record.RegistryValueKind)
            throw InvalidRiskRequest();
    }

    private static InvalidDataException InvalidRiskRequest() => MessageExceptions.Create(
        MessageText.Create("Remediation.Mode.InvalidRiskRequest"), text => new InvalidDataException(text));
}
