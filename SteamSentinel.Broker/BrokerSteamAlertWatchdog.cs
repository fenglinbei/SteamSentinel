using System.Diagnostics;
using System.Security.Cryptography;
using SteamSentinel.Core.Models;
using SteamSentinel.Core.Remediation;
using SteamSentinel.Core.Reporting;
using SteamSentinel.Core.Utilities;

namespace SteamSentinel.Broker;

internal sealed partial class BrokerEngine
{
    private static bool IsScriptHostAction(RemediationAction action) =>
        action.Type == RemediationActionType.StopHostProcess && action.ConfigurationKind == SteamAlertWatchdog.ScriptHostKind;

    private void ValidateScriptHostAction(RemediationAction action)
    {
        SteamAlertScriptHostStopper.ValidateRequest(action);
        if (!HasKnownBinding(action) || !IsAllowedFileTarget(action.RelatedFilePath!, action.RelatedFileSha256))
            throw SteamAlertScriptHostStopper.Denied("Watchdog.InvalidBinding");
    }

    private async Task<MessageText> StopScriptHostAsync(RemediationAction action, CancellationToken token)
    {
        ValidateScriptHostAction(action);
        // The script lease denies writes/deletion until the action finishes. The Windows
        // interpreter is opened read-only; no DELETE or quarantine authority is requested.
        await using SecureFileLease script = SecureFileLease.Open(action.RelatedFilePath!);
        string scriptHash = await script.ComputeSha256Async(token).ConfigureAwait(false);
        await using FileStream image = new(action.Target, FileMode.Open, FileAccess.Read, FileShare.Read,
            64 * 1024, FileOptions.Asynchronous | FileOptions.SequentialScan);
        FileScopeSafety.ValidateHandlePath(image.SafeFileHandle, action.Target);
        if (image.Length is <= 0 or > 16 * 1024 * 1024)
            throw SteamAlertScriptHostStopper.Denied("Watchdog.ImageChanged");
        string imageHash = Convert.ToHexString(await SHA256.HashDataAsync(image, token).ConfigureAwait(false));
        using Process process = Process.GetProcessById(action.ProcessId!.Value);
        _ = process.SafeHandle; // Pin the instance used for both native reads and Kill(false).
        FileScopeSafety.ValidateHandlePath(image.SafeFileHandle, action.Target);
        await SteamAlertScriptHostStopper.StopAsync(action, new ScriptHostProcess(process), scriptHash, imageHash, token).ConfigureAwait(false);
        return MessageText.Create("Watchdog.Stopped", action.ProcessId);
    }

    /// <summary>
    /// Check every exact family target at each family action boundary. Only exact instances
    /// with an approved, still-pending Stop may remain. Even a file-only plan is checked,
    /// so an interpreter created after preflight cannot escape merely by lacking a Stop row.
    /// </summary>
    private async Task RecheckWatchdogPredecessorsAsync(RemediationPlan plan, RemediationAction action, CancellationToken token)
    {
        if (!RemediationDependencies.IsSteamAlertChainAction(action)) return;
        token.ThrowIfCancellationRequested();
        // Re-discover bounded installed companions too: the resident may have written its
        // first temporary handoff after the preview, before any target was in this plan.
        RequireSteamAlertClosure(plan, duringExecution: true);
        token.ThrowIfCancellationRequested();
        RemediationAction[] targets = plan.Actions.Select(WatchdogObservationTarget).OfType<RemediationAction>()
            .DistinctBy(candidate => (candidate.RelatedFilePath ?? candidate.Target).ToUpperInvariant() + "|" +
                (candidate.RelatedFileSha256 ?? candidate.ExpectedSha256)?.ToUpperInvariant()).ToArray();
        if (targets.Length == 0) return;
        RemediationAction[] pendingStops = plan.Actions.Where(candidate =>
            candidate.Type is RemediationActionType.StopProcess or RemediationActionType.StopHostProcess &&
            SteamAlertWatchdogStateProbe.IsFamilyTargetAction(candidate) &&
            !_result.Actions.Any(result => result.ActionId == candidate.ActionId)).ToArray();
        SteamAlertWatchdogStateProbe probe = new();
        using CancellationTokenSource budget = CancellationTokenSource.CreateLinkedTokenSource(token);
        budget.CancelAfter(TimeSpan.FromSeconds(8));
        foreach (RemediationAction target in targets)
        {
            RemediationVerificationObservation state;
            try
            {
                state = await Task.Run(() => probe.ObserveUnexpectedInstancesAsync(target, pendingStops, budget.Token), budget.Token)
                    .WaitAsync(budget.Token).ConfigureAwait(false);
            }
            catch (Exception ex) when (ex is not OutOfMemoryException)
            {
                state = new()
                {
                    Status = RemediationVerificationStatus.Unknown,
                    MessageText = MessageText.Create("Watchdog.ReadIncomplete", MessageExceptions.Describe(ex))
                };
            }
            if (state.Status is RemediationVerificationStatus.Verified or RemediationVerificationStatus.NoResidual) continue;
            string targetPath = target.RelatedFilePath ?? target.Target;
            foreach (RemediationAction stopped in plan.Actions.Where(candidate =>
                candidate.Type is RemediationActionType.StopProcess or RemediationActionType.StopHostProcess &&
                SteamAlertWatchdogStateProbe.IsFamilyTargetAction(candidate) &&
                PathsEquivalent(candidate.RelatedFilePath ?? candidate.Target, targetPath)))
            {
                RemediationActionResult? outcome = _result.Actions.FirstOrDefault(item => item.ActionId == stopped.ActionId);
                if (outcome?.ExecutionStatus != RemediationExecutionStatus.Succeeded) continue;
                outcome.VerificationStatus = state.Status == RemediationVerificationStatus.ResidualDetected
                    ? RemediationVerificationStatus.Reappeared : state.Status;
                outcome.VerificationSummaryText = state.MessageText.Limit(512);
            }
            throw MessageExceptions.Create(MessageText.Create("Watchdog.PredecessorActive") + " " + state.MessageText,
                text => new UnauthorizedAccessException(text));
        }
    }

    // A persistence-only selection still names an approved script/image. This creates
    // only an observation target, never an extra quarantine or termination capability.
    internal static RemediationAction? WatchdogObservationTarget(RemediationAction action)
    {
        if (SteamAlertWatchdogStateProbe.IsFamilyTargetAction(action)) return action;
        if (SteamAlertWatchdog.IsFamilyHash(action.RelatedFileSha256) &&
            FileScopeSafety.IsLocalFilePath(action.RelatedFilePath ?? string.Empty))
            return new() { Type = RemediationActionType.QuarantineFile, Target = action.RelatedFilePath!, ExpectedSha256 = action.RelatedFileSha256 };
        return null;
    }

    private void ValidateWatchdogPersistenceAction(RemediationAction action)
    {
        if (!SteamAlertWatchdog.IsScriptHash(action.RelatedFileSha256) &&
            !string.Equals(action.RegistryValueName, "SteamAlertWatch", StringComparison.OrdinalIgnoreCase)) return;
        if (!SteamAlertWatchdog.IsScriptHash(action.RelatedFileSha256) || !HasKnownBinding(action) ||
            !IsBoundWatchdogInvocation(action.ExpectedValueData, action.RelatedFilePath))
            throw SteamAlertScriptHostStopper.Denied("Watchdog.InvalidBinding");
    }

    internal static bool IsBoundWatchdogInvocation(string? command, string? scriptPath) =>
        command is not null && scriptPath is not null && PowerShellScriptHost.TryParse(command, out PowerShellScriptInvocation? invocation) &&
        PathsEquivalent(invocation.ScriptPath, scriptPath);

    private sealed class ScriptHostProcess(Process process) : ISteamAlertScriptHostProcess
    {
        public PowerShellScriptHostSnapshot Read() => PowerShellScriptHost.Read(process.SafeHandle, process.Id);
        public void Kill() => process.Kill(entireProcessTree: false);
        public Task WaitForExitAsync(CancellationToken token) => process.WaitForExitAsync(token);
    }
}

internal interface ISteamAlertScriptHostProcess
{
    PowerShellScriptHostSnapshot Read();
    void Kill();
    Task WaitForExitAsync(CancellationToken token);
}

/// <summary>Pure request/identity validation plus a narrow injected process capability for regression tests.</summary>
internal static class SteamAlertScriptHostStopper
{
    internal static void ValidateRequest(RemediationAction action)
    {
        if (action.Type != RemediationActionType.StopHostProcess || action.ConfigurationKind != SteamAlertWatchdog.ScriptHostKind ||
            action.UserSelectedRisk || action.IsKnownMalware || action.ConfidenceScore != 100 || action.ProcessId is null or <= 4 || action.ProcessStartedAtUtc is null ||
            !Validation.IsHexSha256(action.ExpectedSha256) || !SteamAlertWatchdog.IsScriptHash(action.RelatedFileSha256) ||
            !PowerShellScriptHost.IsTrustedImagePath(action.Target) || !FileScopeSafety.IsLocalFilePath(action.RelatedFilePath ?? string.Empty) ||
            !PowerShellScriptHost.TryParse(action.ConfigurationSnapshot, out PowerShellScriptInvocation? invocation) ||
            !SamePath(invocation.ScriptPath, action.RelatedFilePath!))
            throw Denied("Watchdog.InvalidBinding");
    }

    internal static async Task StopAsync(RemediationAction action, ISteamAlertScriptHostProcess process,
        string observedScriptHash, string observedImageHash, CancellationToken token)
    {
        ValidateRequest(action);
        if (!observedScriptHash.Equals(action.RelatedFileSha256, StringComparison.OrdinalIgnoreCase))
            throw Denied("Watchdog.ScriptChanged");
        if (!observedImageHash.Equals(action.ExpectedSha256, StringComparison.OrdinalIgnoreCase))
            throw Denied("Watchdog.ImageChanged");
        token.ThrowIfCancellationRequested();
        PowerShellScriptHostSnapshot before = process.Read();
        RequireIdentity(action, before);
        token.ThrowIfCancellationRequested();
        PowerShellScriptHostSnapshot final = process.Read();
        RequireIdentity(action, final);
        if (!PowerShellScriptHost.SameIdentity(before, final)) throw Denied("Watchdog.ProcessChanged");
        token.ThrowIfCancellationRequested();
        process.Kill();
        using CancellationTokenSource timeout = CancellationTokenSource.CreateLinkedTokenSource(token);
        timeout.CancelAfter(TimeSpan.FromSeconds(15));
        await process.WaitForExitAsync(timeout.Token).ConfigureAwait(false);
    }

    private static void RequireIdentity(RemediationAction action, PowerShellScriptHostSnapshot current)
    {
        if (!current.IsReadable || current.ProcessId != action.ProcessId || current.StartedAtUtc != action.ProcessStartedAtUtc ||
            !SamePath(current.ImagePath, action.Target) || !PowerShellScriptHost.IsTrustedImagePath(current.ImagePath) ||
            !string.Equals(current.CommandLine, action.ConfigurationSnapshot, StringComparison.Ordinal) ||
            !PowerShellScriptHost.TryParse(current.CommandLine, out PowerShellScriptInvocation? invocation) ||
            !SamePath(invocation.ScriptPath, action.RelatedFilePath!))
            throw Denied("Watchdog.ProcessChanged");
    }

    private static bool SamePath(string? left, string right)
    {
        try { return left is not null && Path.GetFullPath(left).Equals(Path.GetFullPath(right), StringComparison.OrdinalIgnoreCase); }
        catch (Exception ex) when (ex is ArgumentException or NotSupportedException or PathTooLongException) { return false; }
    }

    internal static UnauthorizedAccessException Denied(string key) =>
        MessageExceptions.Create(MessageText.Create(key), text => new UnauthorizedAccessException(text));
}
