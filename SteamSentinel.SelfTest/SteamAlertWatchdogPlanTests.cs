using System.IO;
using System.Text.Json;
using System.Text.Json.Nodes;
using SteamSentinel.Broker;
using SteamSentinel.Core.Models;
using SteamSentinel.Core.Remediation;
using SteamSentinel.Core.Reporting;

namespace SteamSentinel.SelfTest;

internal static partial class Program
{
    private static async Task TestSteamAlertWatchdogPlanAsync(string root)
    {
        TestRemediationFailureDetails();
        string script = Path.Combine(root, "plan-only", "sa_watch.ps1");
        string updater = Path.Combine(root, "plan-only", "sa_updater.ps1");
        string payload = Path.Combine(root, "plan-only", "Application Frame Host.exe");
        string systemHost = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "WindowsPowerShell", "v1.0", "powershell.exe");
        DateTimeOffset started = DateTimeOffset.Parse("2026-11-17T00:00:00Z");
        RemediationAction Stop(string path, string hash, int pid) => new()
        {
            Type = RemediationActionType.StopHostProcess,
            ConfigurationKind = SteamAlertWatchdog.ScriptHostKind,
            ConfigurationSnapshot = $"\"{systemHost}\" -NoProfile -WindowStyle Hidden -File \"{path}\"",
            Target = systemHost,
            ExpectedSha256 = new string('A', 64),
            RelatedFilePath = path,
            RelatedFileSha256 = hash,
            ProcessId = pid,
            ProcessStartedAtUtc = started,
            ConfidenceScore = 100
        };
        RemediationAction File(string path, string hash) => new()
        { Type = RemediationActionType.QuarantineFile, Target = path, ExpectedSha256 = hash, IsKnownMalware = true, ConfidenceScore = 100 };
        RemediationAction watchStop = Stop(script, SteamAlertWatchdog.WatchdogHash, 62001);
        RemediationAction updateStop = Stop(updater, SteamAlertWatchdog.UpdaterHash, 62002);
        RemediationAction run = new()
        {
            Type = RemediationActionType.RemoveRegistryValue,
            Target = watchStop.ConfigurationSnapshot!,
            RelatedFilePath = script,
            RelatedFileSha256 = SteamAlertWatchdog.WatchdogHash,
            RegistryHive = "HKCU",
            RegistryView = "Default",
            RegistryKey = @"Software\Microsoft\Windows\CurrentVersion\Run",
            RegistryValueName = "SteamAlertWatch",
            ExpectedValueData = watchStop.ConfigurationSnapshot
        };
        RemediationAction payloadStop = new()
        { Type = RemediationActionType.StopProcess, Target = payload, ExpectedSha256 = SteamAlertWatchdog.ResidentHash, ProcessId = 62003, ProcessStartedAtUtc = started };
        RemediationAction watchFile = File(script, SteamAlertWatchdog.WatchdogHash), updaterFile = File(updater, SteamAlertWatchdog.UpdaterHash);
        RemediationAction payloadFile = File(payload, SteamAlertWatchdog.ResidentHash);
        RemediationAction independent = File(Path.Combine(root, "unrelated.txt"), new string('B', 64));
        List<RemediationAction> actions = [payloadFile, independent, run, updateStop, updaterFile, payloadStop, watchFile, watchStop];
        RemediationDependencies.AssignAndOrder(actions);
        Check("watchdog plan orders watch, child scripts, persistence, payload, script files, payload file",
            actions.IndexOf(watchStop) < actions.IndexOf(updateStop) && actions.IndexOf(updateStop) < actions.IndexOf(run) &&
            actions.IndexOf(run) < actions.IndexOf(payloadStop) && actions.IndexOf(payloadStop) < actions.IndexOf(watchFile) &&
            actions.IndexOf(watchFile) < actions.IndexOf(payloadFile));
        Check("watchdog plan independent file is not joined to the updater chain", independent.ChainId is null &&
            RemediationDependencies.Groups(actions).Select(g => g.Count).Order().SequenceEqual([1, 7]));
        foreach (RemediationAction action in actions) { action.ChainId = null; action.DependsOnActionIds.Clear(); }
        var reconstructed = RemediationDependencies.Build(actions);
        Check("watchdog plan removing client chain labels cannot bypass script stop dependencies",
            reconstructed[payloadFile.ActionId].Contains(watchStop.ActionId) && reconstructed[payloadStop.ActionId].Contains(updateStop.ActionId) &&
            reconstructed[payloadStop.ActionId].Contains(run.ActionId));
        List<Guid> executed = [];
        RemediationRunResult result = new();
        await BrokerActionSequencer.RunAsync(new() { Actions = actions }, result, new Dictionary<Guid, string>(),
            (action, _) => { executed.Add(action.ActionId); return Task.FromResult("inert result"); },
            (action, outcome, _) =>
            { outcome.VerificationStatus = action == watchStop ? RemediationVerificationStatus.Reappeared : RemediationVerificationStatus.Verified; return Task.CompletedTask; },
            _ => Task.CompletedTask);
        Check("watchdog plan a replacement watcher blocks payload cleanup while preserving unrelated work",
            executed.Contains(watchStop.ActionId) && executed.Contains(independent.ActionId) && !executed.Contains(payloadStop.ActionId) &&
            result.Actions.Single(r => r.ActionId == payloadFile.ActionId).ExecutionStatus == RemediationExecutionStatus.SkippedDependency);

        RemediationPlan complete = new() { Actions = actions };
        Dictionary<string, string> identities = new(StringComparer.OrdinalIgnoreCase)
        { [script] = SteamAlertWatchdog.WatchdogHash, [updater] = SteamAlertWatchdog.UpdaterHash, [payload] = SteamAlertWatchdog.ResidentHash };
        PowerShellScriptHostSnapshot Snapshot(RemediationAction action) => new()
        {
            ProcessId = action.ProcessId!.Value,
            StartedAtUtc = action.ProcessStartedAtUtc,
            ImagePath = action.Target,
            CommandLine = action.ConfigurationSnapshot,
            Status = ScriptHostReadStatus.Readable
        };
        BrokerEngine.RequireSteamAlertCoverage(complete, identities, [Snapshot(watchStop), Snapshot(updateStop)]);
        Check("watchdog closure accepts the exact complete preview", true);
        bool Reject(RemediationPlan plan, IReadOnlyDictionary<string, string> files, params PowerShellScriptHostSnapshot[] hosts)
        {
            try { BrokerEngine.RequireSteamAlertCoverage(plan, files, hosts); return false; }
            catch (InvalidOperationException) { return true; }
        }
        Check("watchdog closure rejects a missing updater file action",
            Reject(new() { Actions = actions.Where(a => a != updaterFile).ToList() }, identities, Snapshot(watchStop), Snapshot(updateStop)));
        Check("watchdog closure rejects a new PID after preview", Reject(complete, identities, Snapshot(watchStop) with { ProcessId = 62009 }));
        Check("watchdog closure rejects a reused PID", Reject(complete, identities, Snapshot(watchStop) with { StartedAtUtc = started.AddSeconds(1) }));
        Check("watchdog closure rejects changed command arguments", Reject(complete, identities,
            Snapshot(watchStop) with { CommandLine = watchStop.ConfigurationSnapshot + " -EveryMin 1" }));
        Check("watchdog closure does not act on an unrelated normal PowerShell", !Reject(complete, identities,
            Snapshot(watchStop) with { ProcessId = 62010, CommandLine = "powershell.exe -NoProfile -Command Get-Date" }));
        Check("watchdog closure refuses to claim completeness when an instance cannot be read", Reject(complete, identities,
            Snapshot(watchStop) with { Status = ScriptHostReadStatus.AccessDenied, CommandLine = null }));
        Check("watchdog closure safely skips protected system interpreter", !Reject(complete, identities,
            Snapshot(watchStop), Snapshot(updateStop),
            Snapshot(watchStop) with { ProcessId = 62099, Status = ScriptHostReadStatus.AccessDenied, CommandLine = null, IsProtectedSystemProcess = true }));
        Dictionary<string, string> extra = new(identities, StringComparer.OrdinalIgnoreCase)
        { [Path.Combine(root, "newly-created", "sa_launch.ps1")] = SteamAlertWatchdog.LauncherHash };
        Check("watchdog closure detects a newly dropped verified family component", Reject(complete, extra));

        Finding[] findings = identities.Select(pair => new Finding
        {
            Category = FindingCategory.File,
            Target = pair.Key,
            Sha256 = pair.Value,
            TargetSha256 = pair.Value,
            CanRemediate = true,
            IsKnownMalware = true,
            SuggestedActions = [SuggestedActionKind.QuarantineFile]
        }).ToArray();
        Check("watchdog preparation does not split different family hashes into separate batches",
            RemediationBatchPlanner.DependencyGroups(findings).Single().Length == 3);
        string original = RemediationPlanIdentity.Fingerprint(complete);
        JsonObject json = JsonSerializer.SerializeToNode(complete)!.AsObject();
        JsonObject stopJson = json["Actions"]!.AsArray().OfType<JsonObject>().Single(a => a["ActionId"]!.GetValue<Guid>() == watchStop.ActionId);
        stopJson["ConfigurationSnapshot"] = watchStop.ConfigurationSnapshot + " -EveryMin 1";
        Check("watchdog exact command is included in typed plan identity", RemediationPlanIdentity.Fingerprint(json.Deserialize<RemediationPlan>()!) != original);
        using (DisplayText.UseCulture(DisplayText.English))
            Check("watchdog preview shows the bound command and preserves the system interpreter",
                RemediationCasePresentation.ActionIdentity(watchStop).Contains(watchStop.ConfigurationSnapshot!, StringComparison.Ordinal) &&
                RemediationCasePresentation.ActionIdentity(watchStop).Contains("preserved", StringComparison.Ordinal));
    }
}
