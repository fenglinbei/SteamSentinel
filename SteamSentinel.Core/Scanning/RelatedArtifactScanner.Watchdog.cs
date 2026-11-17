using System.ComponentModel;
using SteamSentinel.Core.Models;
using SteamSentinel.Core.Remediation;
using SteamSentinel.Core.Reporting;
using SteamSentinel.Core.Steam;
using SteamSentinel.Core.Utilities;

namespace SteamSentinel.Core.Scanning;

public sealed partial class RelatedArtifactScanner
{
    private const int MaximumUpdaterDirectoryEntries = 32;
    private const int MaximumScriptHosts = 64;

    // Two exact installation directories, top-level only. Names seed inspection, never actions.
    internal IReadOnlyList<string> DiscoverUpdaterScripts(ScanReport report, string? residentDirectory = null,
        string? updaterDirectory = null)
    {
        string resident = residentDirectory ?? _residentDirectory;
        string updater = updaterDirectory ?? _updaterDirectory;
        HashSet<string> files = new(StringComparer.OrdinalIgnoreCase);
        foreach (string role in SteamAlertInstallation.FamilyRoles)
            if (role is not (SteamAlertInstallation.LoaderRule or SteamAlertInstallation.ResidentRule))
                foreach (string path in SteamAlertInstallation.ProbePaths(role, new SteamLayout(), resident, updater))
                    if (File.Exists(path) && ContentDiscovery.IsLocalSafePath(path)) files.Add(path);
        foreach (string directory in SteamAlertInstallation.UpdaterDirectories(resident, updater))
        {
            try
            {
                if ((File.GetAttributes(directory) & FileAttributes.Directory) == 0) continue;
                MessageTextCollection notes = [];
                foreach (string file in ContentDiscovery.Children(directory, false, notes, MaximumUpdaterDirectoryEntries))
                    if (Path.GetExtension(file).Equals(".ps1", StringComparison.OrdinalIgnoreCase)) files.Add(file);
                foreach (MessageText note in notes.Texts) Note(report, note);
            }
            catch (Exception error) when (error is FileNotFoundException or DirectoryNotFoundException) { }
            catch (Exception error) when (error is IOException or UnauthorizedAccessException or Win32Exception)
            { Note(report, MessageText.Create("SteamAlert.Watchdog.ScriptUnconfirmed", directory)); }
        }
        return files.ToArray();
    }

    private async Task AddInstalledScriptPeersAsync(HashSet<string> candidates, ScanReport report, CancellationToken token)
    {
        IEnumerable<string> paths = DiscoverUpdaterScripts(report).Concat(SteamAlertInstallation.ProbePaths(
            SteamAlertInstallation.ResidentRule, new SteamLayout(), _residentDirectory, _updaterDirectory).Where(File.Exists));
        foreach (string path in paths.Distinct(StringComparer.OrdinalIgnoreCase))
        {
            token.ThrowIfCancellationRequested();
            if (_blockedPaths.Contains(path)) continue;
            if (candidates.Count >= 64 && !candidates.Contains(path))
            { Note(report, MessageText.Create("Backend.Core.RelatedArtifactExpansion.ExpandCoreAsync.03")); break; }
            string? hash = await HashAsync(path, report, token);
            if (hash is not null && (_known.TryGetValue(hash, out HashRule? rule) &&
                SteamAlertInstallation.FamilyRole(rule.Id) is SteamAlertWatchdog.WatchdogRole or
                    SteamAlertWatchdog.UpdaterRole or SteamAlertWatchdog.LauncherRole or SteamAlertInstallation.ResidentRule ||
                SteamAlertInstallation.IsInstalledResidentPath(path, _residentDirectory) && ReadEmbeddedProof(path, hash) is not null))
                candidates.Add(path);
            else Note(report, MessageText.Create("SteamAlert.Watchdog.ScriptUnconfirmed", path));
        }
    }

    private static bool IsDirectScriptCommand(string command, string path) =>
        PowerShellScriptHost.TryParse(Environment.ExpandEnvironmentVariables(command), out PowerShellScriptInvocation? invocation) &&
        RelatedArtifactRelations.SamePath(invocation!.ScriptPath, path);

    private async Task CollectScriptHostsAsync(ScanReport report, CancellationToken token)
    {
        IReadOnlyList<PowerShellScriptHostSnapshot> hosts = PowerShellScriptHost.ReadAll(token);
        int incomplete = 0, unreadable = 0;
        foreach (PowerShellScriptHostSnapshot before in hosts.Take(MaximumScriptHosts))
        {
            token.ThrowIfCancellationRequested();
            if (!before.IsReadable)
            {
                if (before.Status != ScriptHostReadStatus.Exited) unreadable++;
                continue;
            }
            if (!PowerShellScriptHost.IsTrustedImagePath(before.ImagePath)) continue;
            if (!PowerShellScriptHost.TryParse(before.CommandLine, out PowerShellScriptInvocation? invocation))
            {
                // Ordinary interactive/-Command shells are unrelated. Unsupported syntax is
                // incomplete only when its text points at this confirmed installation chain.
                if (ReferencesInstalledFamily(before.CommandLine, report)) incomplete++;
                continue;
            }
            string script = invocation!.ScriptPath;
            if (_blockedPaths.Contains(script) || _closureOnly && !_proofs.ContainsKey(script)) continue;
            AddCandidate(script, report);
            string? scriptHash = await HashAsync(script, report, token);
            if (scriptHash is null || !SteamAlertWatchdog.IsScriptHash(scriptHash) || !_known.ContainsKey(scriptHash)) continue;
            try
            {
                string? imageHash = await HashScriptHostImageAsync(before.ImagePath!, report, token);
                if (imageHash is null) { incomplete++; continue; }
                PowerShellScriptHostSnapshot after = PowerShellScriptHost.Read(before.ProcessId);
                Finding? process = CreateScriptHostFinding(before, after, imageHash, script, scriptHash);
                if (process is null)
                {
                    if (after.Status != ScriptHostReadStatus.Exited) incomplete++;
                    continue;
                }
                Finding? file = RegisterVerifiedFileFinding(script, scriptHash, null);
                if (file is not null && !report.Findings.Any(f => f.Category == FindingCategory.File &&
                    RelatedArtifactRelations.SamePath(f.Target, script) && f.Sha256 == scriptHash)) report.Findings.Add(file);
                AddCurrent(process, report);
            }
            catch (Exception error) when (error is IOException or UnauthorizedAccessException or Win32Exception or InvalidOperationException)
            { incomplete++; }
        }
        if (HasInstalledFamilyEvidence(report))
        {
            incomplete += unreadable;
            if (hosts.Count > MaximumScriptHosts) Note(report, MessageText.Create("SteamAlert.Watchdog.HostLimit"));
        }
        if (incomplete > 0) Note(report, MessageText.Create("SteamAlert.Watchdog.HostReadIncomplete", incomplete));
    }

    private bool HasInstalledFamilyEvidence(ScanReport report) => _installedFamilyScope ||
        _proofs.Values.Concat(report.Findings).Any(finding =>
            SteamAlertInstallation.InstalledSeedRole(finding, _known) is { } role &&
            SteamAlertInstallation.IsInstalled(role, finding.RelatedFilePath ?? finding.Target, new SteamLayout(),
                _residentDirectory, _updaterDirectory));

    private bool ReferencesInstalledFamily(string? command, ScanReport report) => command is not null &&
        HasInstalledFamilyEvidence(report) &&
        (_proofs.Keys.Any(path => command.Contains(path, StringComparison.OrdinalIgnoreCase)) ||
         SteamAlertInstallation.UpdaterDirectories(_residentDirectory, _updaterDirectory).Append(_residentDirectory)
             .Any(path => command.Contains(path, StringComparison.OrdinalIgnoreCase)));

    private async Task<string?> HashScriptHostImageAsync(string imagePath, ScanReport report, CancellationToken token)
    {
        if (!PowerShellScriptHost.IsTrustedImagePath(imagePath) || !ContentDiscovery.IsLocalSafePath(imagePath)) return null;
        // This narrow read exception never enters the general protected-file action path.
        await using FileStream stream = RelatedArtifactReader.Open(imagePath);
        if (stream.Length > 16L * 1024 * 1024 || stream.Length > _verificationByteLimit - _relatedBytesHashed) return null;
        return await Hashing.Sha256StreamAsync(stream, token,
            bytes => { _relatedBytesHashed += bytes; report.Metrics.BytesHashed += bytes; }, 16L * 1024 * 1024);
    }

    internal static Finding? CreateScriptHostFinding(PowerShellScriptHostSnapshot before, PowerShellScriptHostSnapshot after,
        string imageHash, string scriptPath, string scriptHash)
    {
        if (!PowerShellScriptHost.SameIdentity(before, after) || before.StartedAtUtc is null ||
            !PowerShellScriptHost.IsTrustedImagePath(before.ImagePath) || !Validation.IsHexSha256(imageHash) ||
            !SteamAlertWatchdog.IsScriptHash(scriptHash) ||
            !PowerShellScriptHost.TryParse(before.CommandLine, out PowerShellScriptInvocation? invocation) ||
            !RelatedArtifactRelations.SamePath(invocation!.ScriptPath, scriptPath)) return null;
        return new Finding
        {
            RuleId = "STEAMALERT-SCRIPT-HOST",
            Category = FindingCategory.Process,
            Severity = FindingSeverity.Critical,
            Score = 100,
            TitleText = MessageText.Create("SteamAlert.Watchdog.HostTitle"),
            DescriptionText = MessageText.Create("SteamAlert.Watchdog.HostDescription"),
            Target = before.ImagePath!,
            Sha256 = imageHash,
            ProcessId = before.ProcessId,
            ProcessStartedAtUtc = before.StartedAtUtc,
            RelatedFilePath = scriptPath,
            RelatedFileSha256 = scriptHash,
            ConfigurationKind = SteamAlertWatchdog.ScriptHostKind,
            ConfigurationSnapshot = before.CommandLine,
            IsKnownMalware = false,
            CanRemediate = true,
            EvidenceText = MessageText.Create("SteamAlert.Watchdog.HostEvidence", before.ProcessId, scriptPath,
                before.ParentProcessId?.ToString(System.Globalization.CultureInfo.InvariantCulture) ?? "?"),
            SuggestedActions = [SuggestedActionKind.StopHostProcess]
        };
    }
}
