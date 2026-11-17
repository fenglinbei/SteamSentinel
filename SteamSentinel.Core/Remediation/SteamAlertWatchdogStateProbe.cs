using System.ComponentModel;
using System.Diagnostics;
using System.Security.Cryptography;
using SteamSentinel.Core.Models;
using SteamSentinel.Core.Reporting;
using SteamSentinel.Core.Utilities;

namespace SteamSentinel.Core.Remediation;

/// <summary>A read-only observation of an image at an already approved exact path.</summary>
public sealed record SteamAlertImageObservation(int ProcessId, DateTimeOffset? StartedAtUtc,
    string? ImagePath, bool Readable, bool Exited = false);

/// <summary>Injection boundary for tests; production never creates or terminates processes here.</summary>
public interface ISteamAlertWatchdogStateSource
{
    IReadOnlyList<PowerShellScriptHostSnapshot> ReadScriptHosts(CancellationToken token);
    IReadOnlyList<PowerShellScriptHostSnapshot> ReadHandoffHosts(CancellationToken token);
    IReadOnlyList<SteamAlertImageObservation> ReadImageInstances(string exactPath, CancellationToken token);
    Task<string?> ReadFileHashAsync(string exactPath, CancellationToken token);
}

/// <summary>
/// Re-enumerates the approved target, not just its old PID. A script can remain in an
/// interpreter after its file has gone; file absence must never imply interpreter absence.
/// This observer reports a replacement instance and never extends termination authority.
/// </summary>
public sealed class SteamAlertWatchdogStateProbe(ISteamAlertWatchdogStateSource? source = null)
{
    private readonly ISteamAlertWatchdogStateSource _source = source ?? new WindowsWatchdogStateSource();
    public const int MaximumInstances = 256;

    public static bool IsFamilyTargetAction(RemediationAction action) => TryTarget(action, out _, out _);

    private static bool TryTarget(RemediationAction action, out string path, out string hash)
    {
        path = hash = string.Empty;
        if (action.ContentEvidenceRuleId == SteamAlertUpdateHandoff.RuleId &&
            (action.Type == RemediationActionType.QuarantineFile || action.Type == RemediationActionType.StopHostProcess &&
                action.ConfigurationKind == SteamAlertUpdateHandoff.ScriptHostKind))
        {
            path = action.Type == RemediationActionType.QuarantineFile ? action.Target : action.RelatedFilePath ?? string.Empty;
            hash = (action.Type == RemediationActionType.QuarantineFile ? action.ExpectedSha256 : action.RelatedFileSha256) ?? string.Empty;
        }
        else if (action.Type == RemediationActionType.StopHostProcess &&
            action.ConfigurationKind == SteamAlertWatchdog.ScriptHostKind &&
            SteamAlertWatchdog.IsScriptHash(action.RelatedFileSha256))
        {
            path = action.RelatedFilePath ?? string.Empty;
            hash = action.RelatedFileSha256!;
        }
        else if (action.Type is RemediationActionType.StopProcess or RemediationActionType.QuarantineFile &&
                 SteamAlertWatchdog.IsFamilyHash(action.ExpectedSha256))
        {
            path = action.Target;
            hash = action.ExpectedSha256!;
        }
        return FileScopeSafety.IsLocalFilePath(path) && Validation.IsHexSha256(hash);
    }

    public Task<RemediationVerificationObservation> ObserveAsync(RemediationAction action,
        CancellationToken token = default) => ObserveUnexpectedInstancesAsync(action, [], token);

    /// <summary>
    /// An action-boundary check may allow only exact instances already approved for a later
    /// Stop. A new PID, creation time or command line is never absorbed into that authority.
    /// File existence is intentionally separate, so this can run before a quarantine.
    /// </summary>
    public async Task<RemediationVerificationObservation> ObserveUnexpectedInstancesAsync(RemediationAction action,
        IReadOnlyCollection<RemediationAction> pendingStops, CancellationToken token = default)
    {
        if (pendingStops.Count > 64) return State(RemediationVerificationStatus.Unknown, "Watchdog.ReadLimit");
        if (!TryTarget(action, out string path, out string expectedHash))
            return State(RemediationVerificationStatus.Unknown, "Watchdog.InvalidBinding");
        token.ThrowIfCancellationRequested();
        try
        {
            return action.ContentEvidenceRuleId == SteamAlertUpdateHandoff.RuleId || SteamAlertWatchdog.IsScriptHash(expectedHash)
                ? await ObserveScriptAsync(action, path, expectedHash, token,
                    action.ContentEvidenceRuleId == SteamAlertUpdateHandoff.RuleId, pendingStops).ConfigureAwait(false)
                : await ObserveImageAsync(action, path, expectedHash, token, pendingStops).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            return new()
            {
                Status = RemediationVerificationStatus.Unknown,
                MessageText = MessageText.Create("Watchdog.ReadIncomplete", MessageExceptions.Describe(ex)).Limit(512)
            };
        }
    }

    private async Task<RemediationVerificationObservation> ObserveScriptAsync(RemediationAction action,
        string path, string expectedHash, CancellationToken token, bool handoff,
        IReadOnlyCollection<RemediationAction> pendingStops)
    {
        IReadOnlyList<PowerShellScriptHostSnapshot> snapshots = handoff ? _source.ReadHandoffHosts(token) : _source.ReadScriptHosts(token);
        if (snapshots.Count > MaximumInstances)
            return State(RemediationVerificationStatus.Unknown, "Watchdog.ReadLimit");
        bool incomplete = false;
        List<PowerShellScriptHostSnapshot> matching = [];
        foreach (PowerShellScriptHostSnapshot snapshot in snapshots)
        {
            token.ThrowIfCancellationRequested();
            if (snapshot.Status == ScriptHostReadStatus.Exited) continue;
            if (!snapshot.IsReadable)
            {
                // Enumerators return only interpreter candidates. An unreadable command cannot
                // establish that the interpreter is unrelated to this approved script.
                incomplete = true;
                continue;
            }
            if (!(handoff ? SteamAlertUpdateHandoff.IsTrustedImagePath(snapshot.ImagePath)
                    : PowerShellScriptHost.IsTrustedImagePath(snapshot.ImagePath))) continue;
            string? scriptPath;
            bool parsed;
            if (handoff) parsed = SteamAlertUpdateHandoff.TryParseCommandLine(snapshot.CommandLine, out scriptPath);
            else
            {
                parsed = PowerShellScriptHost.TryParse(snapshot.CommandLine, out PowerShellScriptInvocation? invocation);
                scriptPath = invocation?.ScriptPath;
            }
            if (!parsed)
            {
                // Malformed/unsupported syntax is never authorization. If it names our exact
                // script, preserve uncertainty instead of reporting a falsely clean chain.
                if (snapshot.CommandLine?.Contains(path, StringComparison.OrdinalIgnoreCase) == true)
                    incomplete = true;
                continue;
            }
            if (SamePath(scriptPath, path)) matching.Add(snapshot);
        }
        matching.RemoveAll(snapshot => pendingStops.Any(pending => pending.Type == RemediationActionType.StopHostProcess &&
            pending.ConfigurationKind == (handoff ? SteamAlertUpdateHandoff.ScriptHostKind : SteamAlertWatchdog.ScriptHostKind) &&
            (!handoff || pending.ContentEvidenceRuleId == SteamAlertUpdateHandoff.RuleId) &&
            SamePath(pending.RelatedFilePath, path) && string.Equals(pending.RelatedFileSha256, expectedHash, StringComparison.OrdinalIgnoreCase) &&
            pending.ProcessId == snapshot.ProcessId && pending.ProcessStartedAtUtc == snapshot.StartedAtUtc &&
            SamePath(pending.Target, snapshot.ImagePath!) &&
            string.Equals(pending.ConfigurationSnapshot, snapshot.CommandLine, StringComparison.Ordinal)));
        if (matching.Count > 0)
        {
            string? currentHash = await _source.ReadFileHashAsync(path, token).ConfigureAwait(false);
            // A missing script may already be loaded. A changed script cannot prove what a
            // still running interpreter loaded, and must remain unresolved.
            if (currentHash is not null && !currentHash.Equals(expectedHash, StringComparison.OrdinalIgnoreCase))
                return State(RemediationVerificationStatus.Unknown, "Watchdog.ScriptChanged");
            bool replacement = action.ProcessId is null || matching.Any(item =>
                item.ProcessId != action.ProcessId || item.StartedAtUtc != action.ProcessStartedAtUtc);
            return State(replacement ? RemediationVerificationStatus.Reappeared : RemediationVerificationStatus.ResidualDetected,
                "Watchdog.ScriptStillRunning", string.Join(", ", matching.Select(item => item.ProcessId).Distinct()));
        }
        return incomplete ? State(RemediationVerificationStatus.Unknown, "Watchdog.ReadIncomplete", string.Empty)
            : State(RemediationVerificationStatus.NoResidual, "Watchdog.NoBoundInstance");
    }

    private async Task<RemediationVerificationObservation> ObserveImageAsync(RemediationAction action,
        string path, string expectedHash, CancellationToken token, IReadOnlyCollection<RemediationAction> pendingStops)
    {
        IReadOnlyList<SteamAlertImageObservation> snapshots = _source.ReadImageInstances(path, token);
        if (snapshots.Count > MaximumInstances)
            return State(RemediationVerificationStatus.Unknown, "Watchdog.ReadLimit");
        bool incomplete = snapshots.Any(item => !item.Exited && !item.Readable);
        SteamAlertImageObservation[] matching = snapshots.Where(item => !item.Exited && item.Readable &&
            SamePath(item.ImagePath, path) && !pendingStops.Any(pending => pending.Type == RemediationActionType.StopProcess &&
                SamePath(pending.Target, path) && string.Equals(pending.ExpectedSha256, expectedHash, StringComparison.OrdinalIgnoreCase) &&
                pending.ProcessId == item.ProcessId && pending.ProcessStartedAtUtc == item.StartedAtUtc)).ToArray();
        if (matching.Length > 0)
        {
            string? currentHash = await _source.ReadFileHashAsync(path, token).ConfigureAwait(false);
            if (currentHash is not null && !currentHash.Equals(expectedHash, StringComparison.OrdinalIgnoreCase))
                return State(RemediationVerificationStatus.Unknown, "Watchdog.ImageChanged");
            bool replacement = action.ProcessId is null || matching.Any(item =>
                item.ProcessId != action.ProcessId || item.StartedAtUtc != action.ProcessStartedAtUtc);
            return State(replacement ? RemediationVerificationStatus.Reappeared : RemediationVerificationStatus.ResidualDetected,
                "Watchdog.ImageStillRunning", string.Join(", ", matching.Select(item => item.ProcessId).Distinct()));
        }
        return incomplete ? State(RemediationVerificationStatus.Unknown, "Watchdog.ReadIncomplete", string.Empty)
            : State(RemediationVerificationStatus.NoResidual, "Watchdog.NoBoundInstance");
    }

    private static bool SamePath(string? first, string second)
    {
        try { return first is not null && Path.GetFullPath(first).Equals(Path.GetFullPath(second), StringComparison.OrdinalIgnoreCase); }
        catch (Exception ex) when (ex is ArgumentException or NotSupportedException or PathTooLongException) { return false; }
    }

    private static RemediationVerificationObservation State(RemediationVerificationStatus status, string key,
        params object?[] arguments) => new() { Status = status, MessageText = MessageText.Create(key, arguments) };

    private sealed class WindowsWatchdogStateSource : ISteamAlertWatchdogStateSource
    {
        public IReadOnlyList<PowerShellScriptHostSnapshot> ReadScriptHosts(CancellationToken token) =>
            PowerShellScriptHost.ReadAll(token);

        public IReadOnlyList<PowerShellScriptHostSnapshot> ReadHandoffHosts(CancellationToken token) =>
            PowerShellScriptHost.ReadAllByNames(["cmd"], token);

        public IReadOnlyList<SteamAlertImageObservation> ReadImageInstances(string exactPath, CancellationToken token)
        {
            List<SteamAlertImageObservation> observations = [];
            Process[] processes = Process.GetProcessesByName(Path.GetFileNameWithoutExtension(exactPath));
            try
            {
                foreach (Process process in processes.Take(MaximumInstances + 1))
                {
                    token.ThrowIfCancellationRequested();
                    try
                    {
                        _ = process.SafeHandle; // Pin this instance while reading its identity.
                        if (process.HasExited) continue;
                        DateTimeOffset started = new(process.StartTime.ToUniversalTime());
                        string? image = process.MainModule?.FileName;
                        if (process.HasExited) continue;
                        observations.Add(new(process.Id, started, image, image is not null));
                    }
                    catch (ArgumentException) { }
                    catch (Exception ex) when (ex is InvalidOperationException or Win32Exception or UnauthorizedAccessException)
                    { observations.Add(new(process.Id, null, null, false)); }
                }
                return observations;
            }
            finally { foreach (Process process in processes) process.Dispose(); }
        }

        public async Task<string?> ReadFileHashAsync(string exactPath, CancellationToken token)
        {
            try
            {
                await using FileStream stream = new(exactPath, FileMode.Open, FileAccess.Read, FileShare.Read,
                    64 * 1024, FileOptions.Asynchronous | FileOptions.SequentialScan);
                FileScopeSafety.ValidateHandlePath(stream.SafeFileHandle, exactPath);
                if (stream.Length > 64 * 1024 * 1024) throw new IOException("Bound image size limit.");
                string hash = Convert.ToHexString(await SHA256.HashDataAsync(stream, token).ConfigureAwait(false));
                FileScopeSafety.ValidateHandlePath(stream.SafeFileHandle, exactPath);
                return hash;
            }
            catch (FileNotFoundException) { return null; }
            catch (DirectoryNotFoundException) { return null; }
        }
    }
}
