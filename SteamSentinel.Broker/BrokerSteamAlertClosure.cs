using System.ComponentModel;
using System.Diagnostics;
using System.Security.Cryptography;
using Microsoft.Win32;
using SteamSentinel.Core.Inspection;
using SteamSentinel.Core.Models;
using SteamSentinel.Core.Remediation;
using SteamSentinel.Core.Reporting;
using SteamSentinel.Core.Scanning;
using SteamSentinel.Core.Steam;
using SteamSentinel.Core.Utilities;

namespace SteamSentinel.Broker;

internal sealed partial class BrokerEngine
{
    private const int MaximumClosureFiles = 128;
    private const int MaximumClosureScripts = 32;
    private const int MaximumClosureHandoffs = 16;
    private const long MaximumClosureBytes = 64L * 1024 * 1024;

    // Read-only, before any incident or mutation. A stale preview must not remove only
    // the payload while leaving a newly installed updater or newly started interpreter.
    private void RequireSteamAlertClosure(RemediationPlan plan, bool duringExecution = false)
    {
        RemediationAction[] family = plan.Actions.Where(RemediationDependencies.IsSteamAlertChainAction).ToArray();
        if (family.Length == 0) return;
        HashSet<Guid> completed = [];
        if (duringExecution)
        {
            if (_result is null || _result.PlanId != plan.PlanId ||
                _result.PlanIdentitySha256 != RemediationPlanIdentity.Fingerprint(plan)) throw WatchdogClosureFailure();
            completed.UnionWith(_result.Actions.Where(result => result.Success && result.ExecutionStatus == RemediationExecutionStatus.Succeeded)
                .Select(result => result.ActionId));
        }
        string resident = SteamAlertInstallation.ResidentDirectory;
        Dictionary<string, string> claims = new(StringComparer.OrdinalIgnoreCase);
        foreach (RemediationAction action in family)
        {
            // Inspect both bindings. A caller's UserSelectedRisk or unrelated RelatedFile
            // field must not hide a compiled family hash on the actual file target.
            if (SteamAlertWatchdog.IsFamilyHash(action.ExpectedSha256) && ContentDiscovery.IsLocalSafePath(action.Target))
                AddClaim(action.Target, action.ExpectedSha256!);
            if (SteamAlertWatchdog.IsFamilyHash(action.RelatedFileSha256))
                AddClaim(action.RelatedFilePath ?? string.Empty, action.RelatedFileSha256!);
        }
        Dictionary<string, string> identities = new(StringComparer.OrdinalIgnoreCase);
        Dictionary<string, string> scopeSeeds = new(StringComparer.OrdinalIgnoreCase);
        Dictionary<string, ClosureFileRead> reads = new(StringComparer.OrdinalIgnoreCase);
        long bytes = 0;
        foreach ((string path, string expected) in claims)
        {
            ClosureFileRead? current = ReadClosureFile(path, 16 * 1024 * 1024, false, ref bytes);
            if (current is null)
            {
                if (!WasQuarantined(path, expected)) throw WatchdogClosureFailure();
                scopeSeeds[path] = expected; // A successful action in this run is still an established installation seed.
                continue;
            }
            if (!expected.Equals(current.Hash, StringComparison.OrdinalIgnoreCase)) throw WatchdogClosureFailure();
            reads[path] = current;
            AddSteamAlertClosureIdentity(identities, path, current.Hash);
            scopeSeeds[path] = current.Hash;
        }
        SteamAlertClosureScope scope = BuildSteamAlertClosureScope(scopeSeeds, _steamLayout, resident,
            SteamAlertInstallation.UpdaterDirectory, directory => EnumerateClosureFiles(directory, "*.ps1", MaximumClosureScripts));
        foreach (string path in scope.CandidateFiles)
        {
            if (reads.ContainsKey(path)) continue;
            ClosureFileRead? current = ReadClosureFile(path, 16 * 1024 * 1024, false, ref bytes);
            if (current is null) continue;
            reads[path] = current;
            // An installed family's fixed restore paths and top-level scripts require
            // review when their bytes are unknown. They must never be silently skipped.
            AddSteamAlertClosureIdentity(identities, path, current.Hash);
        }
        bool inspectRuntime = scope.Installed || family.Any(action => action.Type is RemediationActionType.StopProcess or RemediationActionType.StopHostProcess);
        IReadOnlyList<PowerShellScriptHostSnapshot> hosts = inspectRuntime &&
            identities.Values.Concat(scopeSeeds.Values).Any(SteamAlertWatchdog.IsScriptHash)
            ? PowerShellScriptHost.ReadAll() : [];
        RequireSteamAlertCoverage(plan, identities, hosts, completed, scopeSeeds);

        Dictionary<string, string> handoffClaims = new(StringComparer.OrdinalIgnoreCase);
        foreach (RemediationAction action in family.Where(action => action.ContentEvidenceRuleId == SteamAlertUpdateHandoff.RuleId ||
            action.ConfigurationKind == SteamAlertUpdateHandoff.ScriptHostKind))
        {
            string path = action.Type == RemediationActionType.StopHostProcess ? action.RelatedFilePath ?? string.Empty : action.Target;
            string? hash = action.Type == RemediationActionType.StopHostProcess ? action.RelatedFileSha256 : action.ExpectedSha256;
            if (!FileScopeSafety.IsLocalFilePath(path) || !Validation.IsHexSha256(hash)) throw WatchdogClosureFailure();
            path = Path.GetFullPath(path);
            if (handoffClaims.TryGetValue(path, out string? previous) && !previous.Equals(hash, StringComparison.OrdinalIgnoreCase)) throw WatchdogClosureFailure();
            handoffClaims[path] = hash!;
        }
        IReadOnlyList<PowerShellScriptHostSnapshot> cmdHosts = inspectRuntime || handoffClaims.Count > 0
            ? PowerShellScriptHost.ReadAllByNames(["cmd"]) : [];
        HashSet<string> handoffCandidates = handoffClaims.Keys.ToHashSet(StringComparer.OrdinalIgnoreCase);
        if (inspectRuntime) handoffCandidates.UnionWith(EnumerateClosureFiles(Path.GetTempPath(), "sa_update_*.cmd", MaximumClosureHandoffs));
        foreach (PowerShellScriptHostSnapshot host in cmdHosts)
            if (host.IsReadable && SteamAlertUpdateHandoff.IsTrustedImagePath(host.ImagePath) &&
                SteamAlertUpdateHandoff.TryParseCommandLine(host.CommandLine, out string? script) &&
                (inspectRuntime || handoffClaims.ContainsKey(script))) handoffCandidates.Add(script);
        if (handoffCandidates.Count > MaximumClosureHandoffs) throw WatchdogClosureFailure();
        List<SteamAlertUpdateHandoffProof> handoffs = [];
        foreach (string script in handoffCandidates)
        {
            ClosureFileRead? current = ReadClosureFile(script, SteamAlertUpdateHandoff.MaximumScriptBytes, true, ref bytes);
            bool selected = handoffClaims.TryGetValue(script, out string? expected);
            if (current is null)
            {
                if (selected && !WasQuarantined(script, expected!) || cmdHosts.Any(host => host.IsReadable && SteamAlertUpdateHandoff.TryParseCommandLine(host.CommandLine, out string? path) &&
                    PathsEquivalent(path, script))) throw WatchdogClosureFailure();
                continue;
            }
            if (selected && !current.Hash.Equals(expected, StringComparison.OrdinalIgnoreCase)) throw WatchdogClosureFailure();
            if (!SteamAlertUpdateHandoff.TryParse(current.Content!, script, out SteamAlertUpdateHandoffDescriptor? descriptor))
            {
                if (selected || ReferencesClosurePaths(current.Content!, identities.Keys.Concat(scopeSeeds.Keys))) throw WatchdogClosureFailure();
                continue; // A readable, unrelated temporary CMD is not evidence of this installation.
            }
            if (!IsSteamAlertHandoffInScope(descriptor, scopeSeeds, scope, _steamLayout))
            {
                if (selected) throw WatchdogClosureFailure();
                continue;
            }
            long repeatedBytes = current.Length;
            foreach (string payload in new[] { descriptor.TargetExe, descriptor.StagedExe, descriptor.BackupExe })
            {
                // Read every present restore source, including unknown or unreadable .bak/.new
                // files; VerifyAsync's positive proof alone cannot certify absent restore gaps.
                ClosureFileRead? file = ReadClosureFile(payload, 16 * 1024 * 1024, false, ref bytes);
                if (file is null) continue;
                repeatedBytes += file.Length;
                AddSteamAlertClosureIdentity(identities, payload, file.Hash);
                if (SteamAlertWatchdog.RoleForHash(file.Hash) != SteamAlertWatchdog.PayloadRole) throw WatchdogClosureFailure();
            }
            bytes += repeatedBytes; // VerifyAsync independently rereads the script and payload bytes.
            if (bytes > MaximumClosureBytes) throw WatchdogClosureFailure();
            SteamAlertUpdateHandoffProof proof = SteamAlertUpdateHandoff.VerifyAsync(script, current.Hash).GetAwaiter().GetResult()
                ?? throw WatchdogClosureFailure();
            if (proof.Descriptor != descriptor || proof.Payloads.Any(payload =>
                !identities.TryGetValue(payload.Path, out string? observed) || !observed.Equals(payload.Sha256, StringComparison.OrdinalIgnoreCase)))
                throw WatchdogClosureFailure();
            handoffs.Add(proof);
        }
        RequireSteamAlertCoverage(plan, identities, hosts, completed, scopeSeeds);
        RequireSteamAlertHandoffCoverage(plan, handoffs, cmdHosts, completed, handoffClaims.Keys.ToArray());

        if (!inspectRuntime && handoffs.Count == 0) return; // Quarantining offline samples does not inspect unrelated live installations.
        Dictionary<string, string> established = new(scopeSeeds, StringComparer.OrdinalIgnoreCase);
        foreach ((string path, string hash) in identities) established[path] = hash;
        foreach ((string path, string hash) in established.Where(pair => SteamAlertWatchdog.RoleForHash(pair.Value) == SteamAlertWatchdog.PayloadRole))
        {
            // Same path, even if the image has since been replaced, requires a new preview.
            // Process names only bound enumeration; path/start time supply the identity.
            Process[] processes = Process.GetProcessesByName(Path.GetFileNameWithoutExtension(path));
            try
            {
                foreach (Process process in processes)
                {
                    DateTimeOffset started;
                    int pid;
                    try
                    {
                        if (!PathsEquivalent(process.MainModule?.FileName ?? string.Empty, path)) continue;
                        started = new(process.StartTime.ToUniversalTime());
                        pid = process.Id;
                    }
                    catch (InvalidOperationException) { continue; }
                    catch (Win32Exception) { throw WatchdogClosureFailure(); }
                    if (!plan.Actions.Any(action => action.Type == RemediationActionType.StopProcess && !completed.Contains(action.ActionId) &&
                        action.ProcessId == pid && action.ProcessStartedAtUtc == started &&
                        PathsEquivalent(action.Target, path) && string.Equals(action.ExpectedSha256, hash, StringComparison.OrdinalIgnoreCase)))
                        throw WatchdogClosureFailure();
                }
            }
            finally { foreach (Process process in processes) process.Dispose(); }
        }
        RequireSteamAlertRunCoverage(plan, established, completed);

        void AddClaim(string path, string hash)
        {
            if (!FileScopeSafety.IsLocalFilePath(path)) throw WatchdogClosureFailure();
            path = Path.GetFullPath(path);
            if (claims.TryGetValue(path, out string? previous) && !previous.Equals(hash, StringComparison.OrdinalIgnoreCase)) throw WatchdogClosureFailure();
            claims[path] = hash;
            if (claims.Count > 64) throw WatchdogClosureFailure();
        }

        bool WasQuarantined(string path, string hash) => plan.Actions.Any(action => completed.Contains(action.ActionId) &&
            action.Type == RemediationActionType.QuarantineFile && PathsEquivalent(action.Target, path) &&
            string.Equals(action.ExpectedSha256, hash, StringComparison.OrdinalIgnoreCase));
    }

    internal static SteamAlertClosureScope BuildSteamAlertClosureScope(IReadOnlyDictionary<string, string> seeds,
        SteamLayout layout, string resident, string updater, Func<string, IReadOnlyList<string>> enumerateScripts)
    {
        bool installed = seeds.Any(pair => SteamAlertWatchdog.RoleForHash(pair.Value) is { } role &&
            ContentDiscovery.IsLocalSafePath(pair.Key) && SteamAlertInstallation.IsInstalled(role, pair.Key, layout, resident, updater));
        HashSet<string> candidates = seeds.Keys.Select(Path.GetFullPath).ToHashSet(StringComparer.OrdinalIgnoreCase);
        if (installed)
        {
            foreach (string role in new[] { SteamAlertInstallation.ResidentRule, SteamAlertWatchdog.WatchdogRole,
                SteamAlertWatchdog.UpdaterRole, SteamAlertWatchdog.LauncherRole })
                candidates.UnionWith(SteamAlertInstallation.ProbePaths(role, layout, resident, updater));
            int count = 0;
            foreach (string directory in SteamAlertInstallation.UpdaterDirectories(resident, updater))
            {
                IReadOnlyList<string> scripts = enumerateScripts(directory);
                count += scripts.Count;
                if (count > MaximumClosureScripts) throw WatchdogClosureFailure();
                foreach (string script in scripts)
                {
                    if (!FileScopeSafety.IsLocalFilePath(script) || !Path.GetExtension(script).Equals(".ps1", StringComparison.OrdinalIgnoreCase) ||
                        !PathsEquivalent(Path.GetDirectoryName(script) ?? string.Empty, directory)) throw WatchdogClosureFailure();
                    candidates.Add(Path.GetFullPath(script));
                }
            }
        }
        if (candidates.Count > MaximumClosureFiles) throw WatchdogClosureFailure();
        return new(installed, resident, updater, candidates.ToArray());
    }

    internal static void AddSteamAlertClosureIdentity(IDictionary<string, string> identities, string path, string? hash)
    {
        if (hash is null) return; // Only a positively established missing file reaches this branch.
        if (!SteamAlertWatchdog.IsFamilyHash(hash) || !FileScopeSafety.IsLocalFilePath(path)) throw WatchdogClosureFailure();
        path = Path.GetFullPath(path);
        if (identities.TryGetValue(path, out string? previous) && !previous.Equals(hash, StringComparison.OrdinalIgnoreCase)) throw WatchdogClosureFailure();
        identities[path] = hash;
    }

    internal static bool IsSteamAlertHandoffInScope(SteamAlertUpdateHandoffDescriptor descriptor, IReadOnlyDictionary<string, string> identities,
        SteamAlertClosureScope scope, SteamLayout layout) =>
        new[] { descriptor.TargetExe, descriptor.StagedExe, descriptor.BackupExe }.Any(path =>
            identities.Any(pair => SteamAlertWatchdog.RoleForHash(pair.Value) == SteamAlertWatchdog.PayloadRole && PathsEquivalent(pair.Key, path)) ||
            scope.Installed && SteamAlertInstallation.IsInstalled(SteamAlertInstallation.ResidentRule, path, layout, scope.ResidentDirectory, scope.UpdaterDirectory));

    private static IReadOnlyList<string> EnumerateClosureFiles(string directory, string pattern, int maximum)
    {
        if (!FileScopeSafety.IsLocalFilePath(directory) || Validation.ContainsReparsePoint(directory)) throw WatchdogClosureFailure();
        try
        {
            if ((File.GetAttributes(directory) & FileAttributes.Directory) == 0) throw WatchdogClosureFailure();
            string[] paths = Directory.EnumerateFiles(directory, pattern, SearchOption.TopDirectoryOnly).Take(maximum + 1).ToArray();
            if (paths.Length > maximum) throw WatchdogClosureFailure();
            return paths;
        }
        catch (FileNotFoundException) { return []; }
        catch (DirectoryNotFoundException) { return []; }
    }

    private static ClosureFileRead? ReadClosureFile(string path, int maximum, bool content, ref long bytes)
    {
        if (!FileScopeSafety.IsLocalFilePath(path) || Validation.ContainsReparsePoint(path)) throw WatchdogClosureFailure();
        try
        {
            using FileStream input = new(path, FileMode.Open, FileAccess.Read, FileShare.Read);
            FileScopeSafety.ValidateHandlePath(input.SafeFileHandle, path);
            if (input.Length > maximum || input.Length > MaximumClosureBytes - bytes) throw WatchdogClosureFailure();
            bytes += input.Length;
            byte[]? data = content ? new byte[checked((int)input.Length)] : null;
            string hash;
            if (data is null) hash = Convert.ToHexString(SHA256.HashData(input));
            else { input.ReadExactly(data); hash = Convert.ToHexString(SHA256.HashData(data)); }
            return new(hash, input.Length, data);
        }
        catch (FileNotFoundException) { return null; }
        catch (DirectoryNotFoundException) { return null; }
    }

    private static bool ReferencesClosurePaths(byte[] content, IEnumerable<string> paths)
    {
        // This is only a fail-closed ambiguity check, never an authorization or detection rule.
        string text = System.Text.Encoding.UTF8.GetString(content);
        string unicode = System.Text.Encoding.Unicode.GetString(content.AsSpan(0, content.Length & ~1));
        return paths.Any(path => MentionsClosurePath(text, path) || MentionsClosurePath(unicode, path));
    }

    private static bool MentionsClosurePath(string text, string path)
    {
        int from = 0;
        while (from <= text.Length - path.Length)
        {
            int start = text.IndexOf(path, from, StringComparison.OrdinalIgnoreCase);
            if (start < 0) return false;
            int end = start + path.Length;
            bool left = start == 0 || char.IsWhiteSpace(text[start - 1]) || text[start - 1] is '"' or '\'' or '=' or '(' or ';' or '&' or '|';
            bool right = end == text.Length || char.IsWhiteSpace(text[end]) || text[end] is '"' or '\'' or ')' or ';' or '&' or '|' or '>' or '<' or ',';
            if (left && right) return true;
            from = start + 1;
        }
        return false;
    }

    internal static void RequireSteamAlertCoverage(RemediationPlan plan, IReadOnlyDictionary<string, string> identities,
        IReadOnlyList<PowerShellScriptHostSnapshot> hosts, IReadOnlySet<Guid>? completed = null,
        IReadOnlyDictionary<string, string>? historicalBindings = null)
    {
        if (identities.Count > 64 || hosts.Count > 256) throw WatchdogClosureFailure();
        Dictionary<string, string> bindings = new(StringComparer.OrdinalIgnoreCase);
        if (historicalBindings is not null)
            foreach ((string path, string hash) in historicalBindings) bindings[path] = hash;
        foreach ((string path, string hash) in identities) bindings[path] = hash;
        foreach ((string path, string hash) in identities.Where(pair => SteamAlertWatchdog.IsFamilyHash(pair.Value)))
            if (!plan.Actions.Any(action => action.Type == RemediationActionType.QuarantineFile && completed?.Contains(action.ActionId) != true &&
                PathsEquivalent(action.Target, path) && string.Equals(action.ExpectedSha256, hash, StringComparison.OrdinalIgnoreCase)))
                throw WatchdogClosureFailure();
        foreach (PowerShellScriptHostSnapshot host in hosts)
        {
            if (host.Status == ScriptHostReadStatus.Exited) continue;
            if (!host.IsReadable)
            {
                // Unsupported but fully read non-system interpreters can be positively
                // unrelated; access-denied or changing instances cannot establish that.
                if (host.Status == ScriptHostReadStatus.Unsupported && host.CommandLine is not null &&
                    !bindings.Keys.Any(path => MentionsClosurePath(host.CommandLine, path))) continue;
                throw WatchdogClosureFailure();
            }
            if (!PowerShellScriptHost.TryParse(host.CommandLine, out var invocation))
            {
                if (bindings.Any(pair => SteamAlertWatchdog.IsScriptHash(pair.Value) &&
                    MentionsClosurePath(host.CommandLine!, pair.Key))) throw WatchdogClosureFailure();
                continue;
            }
            string? hash = bindings.FirstOrDefault(pair => PathsEquivalent(pair.Key, invocation.ScriptPath)).Value;
            if (!SteamAlertWatchdog.IsScriptHash(hash)) continue;
            if (!PowerShellScriptHost.IsTrustedImagePath(host.ImagePath)) throw WatchdogClosureFailure();
            if (!plan.Actions.Any(action => action.Type == RemediationActionType.StopHostProcess && completed?.Contains(action.ActionId) != true &&
                action.ConfigurationKind == SteamAlertWatchdog.ScriptHostKind && action.ProcessId == host.ProcessId &&
                !action.UserSelectedRisk && !action.IsKnownMalware && Validation.IsHexSha256(action.ExpectedSha256) &&
                action.ProcessStartedAtUtc == host.StartedAtUtc && PathsEquivalent(action.Target, host.ImagePath ?? string.Empty) &&
                action.ConfigurationSnapshot == host.CommandLine && PathsEquivalent(action.RelatedFilePath ?? string.Empty, invocation.ScriptPath) &&
                string.Equals(action.RelatedFileSha256, hash, StringComparison.OrdinalIgnoreCase))) throw WatchdogClosureFailure();
        }
    }

    internal static void RequireSteamAlertHandoffCoverage(RemediationPlan plan, IReadOnlyList<SteamAlertUpdateHandoffProof> proofs,
        IReadOnlyList<PowerShellScriptHostSnapshot> hosts, IReadOnlySet<Guid>? completed = null, IReadOnlyList<string>? knownScriptPaths = null)
    {
        if (proofs.Count > MaximumClosureHandoffs || hosts.Count > 256) throw WatchdogClosureFailure();
        HashSet<string> paths = proofs.Select(proof => proof.Descriptor.ScriptPath).Concat(knownScriptPaths ?? [])
            .ToHashSet(StringComparer.OrdinalIgnoreCase);
        foreach (SteamAlertUpdateHandoffProof proof in proofs)
        {
            if (!Validation.IsHexSha256(proof.ScriptSha256) || proof.Payloads.Count is < 1 or > 3 ||
                !plan.Actions.Any(action => action.Type == RemediationActionType.QuarantineFile && completed?.Contains(action.ActionId) != true &&
                    action.ContentEvidenceRuleId == SteamAlertUpdateHandoff.RuleId && PathsEquivalent(action.Target, proof.Descriptor.ScriptPath) &&
                    string.Equals(action.ExpectedSha256, proof.ScriptSha256, StringComparison.OrdinalIgnoreCase))) throw WatchdogClosureFailure();
            foreach (SteamAlertUpdatePayloadProof payload in proof.Payloads)
                if (SteamAlertWatchdog.RoleForHash(payload.Sha256) != SteamAlertWatchdog.PayloadRole ||
                    !new[] { proof.Descriptor.TargetExe, proof.Descriptor.StagedExe, proof.Descriptor.BackupExe }.Any(path => PathsEquivalent(path, payload.Path)) ||
                    !plan.Actions.Any(action => action.Type == RemediationActionType.QuarantineFile && completed?.Contains(action.ActionId) != true &&
                        PathsEquivalent(action.Target, payload.Path) && string.Equals(action.ExpectedSha256, payload.Sha256, StringComparison.OrdinalIgnoreCase)))
                    throw WatchdogClosureFailure();
        }
        foreach (PowerShellScriptHostSnapshot host in hosts)
        {
            if (host.Status == ScriptHostReadStatus.Exited) continue;
            if (!host.IsReadable) throw WatchdogClosureFailure();
            if (!SteamAlertUpdateHandoff.TryParseCommandLine(host.CommandLine, out string? script))
            {
                if (paths.Any(path => MentionsClosurePath(host.CommandLine!, path))) throw WatchdogClosureFailure();
                continue;
            }
            SteamAlertUpdateHandoffProof? proof = proofs.FirstOrDefault(candidate => PathsEquivalent(candidate.Descriptor.ScriptPath, script));
            if (proof is null)
            {
                if (paths.Contains(script)) throw WatchdogClosureFailure();
                continue;
            }
            if (!SteamAlertUpdateHandoff.IsTrustedImagePath(host.ImagePath) ||
                !plan.Actions.Any(action => action.Type == RemediationActionType.StopHostProcess && completed?.Contains(action.ActionId) != true &&
                    action.ConfigurationKind == SteamAlertUpdateHandoff.ScriptHostKind && action.ContentEvidenceRuleId == SteamAlertUpdateHandoff.RuleId &&
                    !action.UserSelectedRisk && !action.IsKnownMalware && Validation.IsHexSha256(action.ExpectedSha256) &&
                    action.ProcessId == host.ProcessId && action.ProcessStartedAtUtc == host.StartedAtUtc &&
                    PathsEquivalent(action.Target, host.ImagePath ?? string.Empty) && action.ConfigurationSnapshot == host.CommandLine &&
                    PathsEquivalent(action.RelatedFilePath ?? string.Empty, script) &&
                    string.Equals(action.RelatedFileSha256, proof.ScriptSha256, StringComparison.OrdinalIgnoreCase))) throw WatchdogClosureFailure();
        }
    }

    private static void RequireSteamAlertRunCoverage(RemediationPlan plan, IReadOnlyDictionary<string, string> identities, IReadOnlySet<Guid>? completed = null)
    {
        foreach ((RegistryHive hive, RegistryView view) in new[]
        {
            (RegistryHive.CurrentUser, RegistryView.Default), (RegistryHive.LocalMachine, RegistryView.Registry32),
            (RegistryHive.LocalMachine, RegistryView.Registry64)
        })
            foreach (string keyName in new[] { @"Software\Microsoft\Windows\CurrentVersion\Run", @"Software\Microsoft\Windows\CurrentVersion\RunOnce" })
            {
                using RegistryKey baseKey = RegistryKey.OpenBaseKey(hive, view);
                using RegistryKey? key = baseKey.OpenSubKey(keyName);
                if (key is null) continue;
                string[] names = key.GetValueNames();
                if (names.Length > 4096) throw WatchdogClosureFailure();
                foreach (string name in names)
                {
                    if (key.GetValueKind(name) is not (RegistryValueKind.String or RegistryValueKind.ExpandString) ||
                        key.GetValue(name, null, RegistryValueOptions.DoNotExpandEnvironmentNames) is not string command) continue;
                    RequireSteamAlertRunEntry(plan, identities, new(hive == RegistryHive.CurrentUser ? "HKCU" : "HKLM",
                        view.ToString(), keyName, name, command), completed);
                }
            }
    }

    internal static void RequireSteamAlertRunEntry(RemediationPlan plan, IReadOnlyDictionary<string, string> identities,
        SteamAlertClosureRunEntry entry, IReadOnlySet<Guid>? completed = null)
    {
        string expanded = Environment.ExpandEnvironmentVariables(entry.Command);
        foreach ((string path, string hash) in identities)
        {
            bool direct = SteamAlertWatchdog.IsScriptHash(hash)
                ? PowerShellScriptHost.TryParse(expanded, out var invocation) && PathsEquivalent(invocation.ScriptPath, path)
                : BoundContentEvidence.IsDirectInvocation(expanded, path);
            if (!direct)
            {
                if (MentionsClosurePath(expanded, path)) throw WatchdogClosureFailure();
                continue;
            }
            if (!plan.Actions.Any(action => action.Type == RemediationActionType.RemoveRegistryValue && completed?.Contains(action.ActionId) != true &&
                action.RegistryHive == entry.Hive && action.RegistryView == entry.View && action.RegistryKey == entry.Key && action.RegistryValueName == entry.Name &&
                action.ExpectedValueData == entry.Command && PathsEquivalent(action.RelatedFilePath ?? string.Empty, path) &&
                string.Equals(action.RelatedFileSha256, hash, StringComparison.OrdinalIgnoreCase))) throw WatchdogClosureFailure();
        }
    }

    private static InvalidOperationException WatchdogClosureFailure() => MessageExceptions.Create(
        MessageText.Create("SteamAlert.Watchdog.ClosureChanged"), text => new InvalidOperationException(text));

    private sealed record ClosureFileRead(string Hash, long Length, byte[]? Content);
}

internal sealed record SteamAlertClosureScope(bool Installed, string ResidentDirectory, string UpdaterDirectory,
    IReadOnlyList<string> CandidateFiles);
internal sealed record SteamAlertClosureRunEntry(string Hive, string View, string Key, string Name, string Command);
