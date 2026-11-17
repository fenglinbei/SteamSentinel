using System.Diagnostics;
using System.Security.Cryptography;
using SteamSentinel.Core.Models;
using SteamSentinel.Core.Remediation;
using SteamSentinel.Core.Reporting;
using SteamSentinel.Core.Utilities;

namespace SteamSentinel.Broker;

internal sealed partial class BrokerEngine
{
    private static bool IsUpdateHandoffHostAction(RemediationAction action) => action.Type == RemediationActionType.StopHostProcess &&
        action.ConfigurationKind == SteamAlertUpdateHandoff.ScriptHostKind;

    private static void ValidateUpdateHandoffHostAction(RemediationAction action) => SteamAlertHandoffStopper.ValidateRequest(action);

    private async Task<MessageText> StopUpdateHandoffHostAsync(RemediationAction action, CancellationToken token)
    {
        ValidateUpdateHandoffHostAction(action);
        await using SteamAlertHandoffLease bound = await OpenHandoffProofLeaseAsync(action.RelatedFilePath!, action.RelatedFileSha256!, token);
        await using FileStream image = new(action.Target, FileMode.Open, FileAccess.Read, FileShare.Read,
            64 * 1024, FileOptions.Asynchronous | FileOptions.SequentialScan);
        FileScopeSafety.ValidateHandlePath(image.SafeFileHandle, action.Target);
        if (image.Length is <= 0 or > 16 * 1024 * 1024)
            throw SteamAlertScriptHostStopper.Denied("Watchdog.ImageChanged");
        string imageHash = Convert.ToHexString(await SHA256.HashDataAsync(image, token));
        using Process process = Process.GetProcessById(action.ProcessId!.Value);
        _ = process.SafeHandle;
        FileScopeSafety.ValidateHandlePath(image.SafeFileHandle, action.Target);
        await SteamAlertHandoffStopper.StopAsync(action, new HandoffHostProcess(process), bound.Proof, imageHash, token);
        return MessageText.Create("Watchdog.Stopped", action.ProcessId);
    }

    /// <summary>
    /// Retains deny-write/delete leases on every payload used as evidence, and on the script
    /// unless its caller already owns that lease. Callers must keep this alive through mutation.
    /// </summary>
    internal static async Task<SteamAlertHandoffLease> OpenHandoffProofLeaseAsync(string scriptPath, string expectedHash,
        CancellationToken token, SecureFileLease? alreadyLockedScript = null)
    {
        SecureFileLease? ownedScript = null;
        List<FileStream> payloadLeases = [];
        try
        {
            SecureFileLease script = alreadyLockedScript ?? (ownedScript = SecureFileLease.Open(scriptPath));
            if (!PathsEquivalent(script.FinalPath, scriptPath) ||
                !(await script.ComputeSha256Async(token)).Equals(expectedHash, StringComparison.OrdinalIgnoreCase))
                throw SteamAlertScriptHostStopper.Denied("Watchdog.ScriptChanged");
            SteamAlertUpdateHandoffProof proof = await SteamAlertUpdateHandoff.VerifyAsync(scriptPath, expectedHash, token)
                ?? throw SteamAlertScriptHostStopper.Denied("Watchdog.HandoffProofInvalid");
            if (proof.Payloads.Count is < 1 or > 3) throw SteamAlertScriptHostStopper.Denied("Watchdog.HandoffProofInvalid");
            foreach (SteamAlertUpdatePayloadProof payload in proof.Payloads)
            {
                token.ThrowIfCancellationRequested();
                FileStream lease = new(payload.Path, FileMode.Open, FileAccess.Read, FileShare.Read,
                    64 * 1024, FileOptions.Asynchronous | FileOptions.SequentialScan);
                payloadLeases.Add(lease);
                FileScopeSafety.ValidateHandlePath(lease.SafeFileHandle, payload.Path);
                if (lease.Length is <= 0 or > 32 * 1024 * 1024 ||
                    SteamAlertWatchdog.RoleForHash(payload.Sha256) != SteamAlertWatchdog.PayloadRole ||
                    !Convert.ToHexString(await SHA256.HashDataAsync(lease, token)).Equals(payload.Sha256, StringComparison.OrdinalIgnoreCase))
                    throw SteamAlertScriptHostStopper.Denied("Watchdog.HandoffProofInvalid");
            }
            // Re-read the entire fixed template and its referenced identities only after every
            // piece of byte evidence is locked. A newly appeared/disappeared payload changes proof.
            SteamAlertUpdateHandoffProof? checkedProof = await SteamAlertUpdateHandoff.VerifyAsync(scriptPath, expectedHash, token);
            if (!SameHandoffProof(proof, checkedProof)) throw SteamAlertScriptHostStopper.Denied("Watchdog.HandoffProofInvalid");
            for (int index = 0; index < proof.Payloads.Count; index++)
                FileScopeSafety.ValidateHandlePath(payloadLeases[index].SafeFileHandle, proof.Payloads[index].Path);
            return new(proof, ownedScript, payloadLeases);
        }
        catch
        {
            foreach (FileStream lease in payloadLeases) await lease.DisposeAsync();
            if (ownedScript is not null) await ownedScript.DisposeAsync();
            throw;
        }
    }

    internal static bool SameHandoffProof(SteamAlertUpdateHandoffProof first, SteamAlertUpdateHandoffProof? second) =>
        second is not null && first.Descriptor == second.Descriptor &&
        first.ScriptSha256.Equals(second.ScriptSha256, StringComparison.OrdinalIgnoreCase) &&
        first.Payloads.Count == second.Payloads.Count && first.Payloads.All(payload => second.Payloads.Any(other =>
            PathsEquivalent(payload.Path, other.Path) && payload.Sha256.Equals(other.Sha256, StringComparison.OrdinalIgnoreCase)));

    private sealed class HandoffHostProcess(Process process) : ISteamAlertScriptHostProcess
    {
        public PowerShellScriptHostSnapshot Read() => PowerShellScriptHost.ReadRaw(process.SafeHandle, process.Id);
        public void Kill() => process.Kill(entireProcessTree: false);
        public Task WaitForExitAsync(CancellationToken token) => process.WaitForExitAsync(token);
    }
}

internal sealed class SteamAlertHandoffLease(SteamAlertUpdateHandoffProof proof, SecureFileLease? script,
    IReadOnlyList<FileStream> payloads) : IAsyncDisposable
{
    public SteamAlertUpdateHandoffProof Proof { get; } = proof;
    public async ValueTask DisposeAsync()
    {
        foreach (FileStream payload in payloads) await payload.DisposeAsync();
        if (script is not null) await script.DisposeAsync();
    }
}

internal static class SteamAlertHandoffStopper
{
    internal static void ValidateRequest(RemediationAction action)
    {
        if (action.Type != RemediationActionType.StopHostProcess || action.ConfigurationKind != SteamAlertUpdateHandoff.ScriptHostKind ||
            action.ContentEvidenceRuleId != SteamAlertUpdateHandoff.RuleId || action.UserSelectedRisk || action.IsKnownMalware ||
            action.ConfidenceScore != 100 || action.ProcessId is null or <= 4 || action.ProcessStartedAtUtc is null ||
            !Validation.IsHexSha256(action.ExpectedSha256) || !Validation.IsHexSha256(action.RelatedFileSha256) ||
            !SteamAlertUpdateHandoff.IsTrustedImagePath(action.Target) ||
            !SteamAlertUpdateHandoff.TryParseCommandLine(action.ConfigurationSnapshot, out string? scriptPath) ||
            !string.Equals(scriptPath, action.RelatedFilePath, StringComparison.OrdinalIgnoreCase))
            throw SteamAlertScriptHostStopper.Denied("Watchdog.InvalidBinding");
    }

    internal static async Task StopAsync(RemediationAction action, ISteamAlertScriptHostProcess process,
        SteamAlertUpdateHandoffProof proof, string observedImageHash, CancellationToken token)
    {
        ValidateRequest(action);
        if (!string.Equals(proof.Descriptor.ScriptPath, action.RelatedFilePath, StringComparison.OrdinalIgnoreCase) ||
            !proof.ScriptSha256.Equals(action.RelatedFileSha256, StringComparison.OrdinalIgnoreCase) ||
            proof.Payloads.Count is < 1 or > 3 || proof.Payloads.Any(payload =>
                SteamAlertWatchdog.RoleForHash(payload.Sha256) != SteamAlertWatchdog.PayloadRole ||
                !new[] { proof.Descriptor.TargetExe, proof.Descriptor.StagedExe, proof.Descriptor.BackupExe }
                    .Contains(payload.Path, StringComparer.OrdinalIgnoreCase)))
            throw SteamAlertScriptHostStopper.Denied("Watchdog.HandoffProofInvalid");
        if (!observedImageHash.Equals(action.ExpectedSha256, StringComparison.OrdinalIgnoreCase))
            throw SteamAlertScriptHostStopper.Denied("Watchdog.ImageChanged");
        token.ThrowIfCancellationRequested();
        PowerShellScriptHostSnapshot before = process.Read();
        RequireIdentity(action, before);
        token.ThrowIfCancellationRequested();
        PowerShellScriptHostSnapshot final = process.Read();
        RequireIdentity(action, final);
        if (!PowerShellScriptHost.SameRawIdentity(before, final)) throw SteamAlertScriptHostStopper.Denied("Watchdog.ProcessChanged");
        token.ThrowIfCancellationRequested();
        process.Kill();
        using CancellationTokenSource timeout = CancellationTokenSource.CreateLinkedTokenSource(token);
        timeout.CancelAfter(TimeSpan.FromSeconds(15));
        await process.WaitForExitAsync(timeout.Token);
    }

    private static void RequireIdentity(RemediationAction action, PowerShellScriptHostSnapshot current)
    {
        if (!current.IsReadable || current.ProcessId != action.ProcessId || current.StartedAtUtc != action.ProcessStartedAtUtc ||
            !string.Equals(current.ImagePath, action.Target, StringComparison.OrdinalIgnoreCase) ||
            !SteamAlertUpdateHandoff.IsTrustedImagePath(current.ImagePath) ||
            !string.Equals(current.CommandLine, action.ConfigurationSnapshot, StringComparison.Ordinal) ||
            !SteamAlertUpdateHandoff.TryParseCommandLine(current.CommandLine, out string? scriptPath) ||
            !string.Equals(scriptPath, action.RelatedFilePath, StringComparison.OrdinalIgnoreCase))
            throw SteamAlertScriptHostStopper.Denied("Watchdog.ProcessChanged");
    }
}
