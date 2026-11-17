using System.IO;
using SteamSentinel.Broker;
using SteamSentinel.Core.Models;
using SteamSentinel.Core.Remediation;
using SteamSentinel.Core.Scanning;
using SteamSentinel.Core.Steam;

namespace SteamSentinel.SelfTest;

internal static partial class Program
{
    private static Task TestSteamAlertClosureAsync(string root)
    {
        string resident = Path.Combine(root, "closure", "profile", "SteamAlertDemo");
        string updater = Path.Combine(root, "closure", "program-data", "SteamAlertUpdater");
        string fallback = Path.Combine(resident, "Updater");
        string payload = Path.Combine(resident, "Application Frame Host.exe");
        string watch = Path.Combine(updater, "sa_watch.ps1"), renamed = Path.Combine(fallback, "renamed.ps1");
        SteamLayout layout = new();
        Dictionary<string, string> seeds = new(StringComparer.OrdinalIgnoreCase) { [payload] = SteamAlertWatchdog.ResidentHash };
        List<string> enumerated = [];
        SteamAlertClosureScope scope = BrokerEngine.BuildSteamAlertClosureScope(seeds, layout, resident, updater, directory =>
        {
            enumerated.Add(directory);
            return directory == fallback ? [renamed] : [watch];
        });
        Check("Closure: verified installation enumerates both updater directories", scope.Installed && enumerated.SequenceEqual([updater, fallback]));
        Check("Closure: renamed top-level script is a mandatory candidate", scope.CandidateFiles.Contains(renamed));
        Check("Closure: staged, old, backup and cached payloads are candidates", new[]
        {
            Path.Combine(resident,"Application Frame Host.new.exe"), payload+".old", payload+".bak",
            Path.Combine(updater,"cache","new.exe"), Path.Combine(fallback,"cache","new.exe")
        }.All(scope.CandidateFiles.Contains));
        string sample = Path.Combine(root, "Samples", "Application Frame Host.exe");
        SteamAlertClosureScope sampleScope = BrokerEngine.BuildSteamAlertClosureScope(
            new Dictionary<string, string> { [sample] = SteamAlertWatchdog.ResidentHash }, layout, resident, updater,
            _ => throw new InvalidOperationException("Offline samples must not enumerate installed directories."));
        Check("Closure: offline sample does not chase the local installation", !sampleScope.Installed && sampleScope.CandidateFiles.SequenceEqual([sample]));
        Check("Closure: caller risk flag cannot hide compiled family identity", RemediationDependencies.IsSteamAlertChainAction(new()
        { Type = RemediationActionType.QuarantineFile, Target = payload, ExpectedSha256 = SteamAlertWatchdog.ResidentHash, UserSelectedRisk = true }));

        static bool Reject(Action action)
        {
            try { action(); return false; }
            catch (Exception error) when (error is InvalidOperationException or UnauthorizedAccessException or IOException) { return true; }
        }
        Check("Closure: script enumeration has a combined 32-file limit", Reject(() => BrokerEngine.BuildSteamAlertClosureScope(seeds, layout,
            resident, updater, directory => Enumerable.Range(0, directory == updater ? 17 : 16).Select(index => Path.Combine(directory, $"file{index}.ps1")).ToArray())));
        Check("Closure: inaccessible updater directory is not treated as absent", Reject(() => BrokerEngine.BuildSteamAlertClosureScope(seeds,
            layout, resident, updater, _ => throw new UnauthorizedAccessException("inert access-denied fixture"))));
        Check("Closure: enumeration cannot escape its declared top-level directory", Reject(() => BrokerEngine.BuildSteamAlertClosureScope(seeds,
            layout, resident, updater, _ => [Path.Combine(root, "unrelated.ps1")])));
        Dictionary<string, string> observed = new(StringComparer.OrdinalIgnoreCase);
        BrokerEngine.AddSteamAlertClosureIdentity(observed, renamed, SteamAlertWatchdog.WatchdogHash);
        Check("Closure: renamed script requires content identity", observed[renamed] == SteamAlertWatchdog.WatchdogHash);
        foreach (string unknown in new[] { watch, renamed, Path.Combine(resident, "Application Frame Host.new.exe"), payload + ".old", payload + ".bak" })
            Check("Closure: present unknown restore source blocks " + Path.GetFileName(unknown), Reject(() =>
                BrokerEngine.AddSteamAlertClosureIdentity(observed, unknown, new string('A', 64))));
        BrokerEngine.AddSteamAlertClosureIdentity(observed, Path.Combine(updater, "missing.ps1"), null);
        Check("Closure: positively absent optional file supplies no identity", observed.Count == 1);

        RemediationAction File(string path, string hash, string? proof = null) => new()
        { Type = RemediationActionType.QuarantineFile, Target = path, ExpectedSha256 = hash, ContentEvidenceRuleId = proof };
        RemediationAction watchFile = File(watch, SteamAlertWatchdog.WatchdogHash), payloadFile = File(payload, SteamAlertWatchdog.ResidentHash);
        DateTimeOffset started = DateTimeOffset.Parse("2026-11-17T00:00:00Z");
        string psImage = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "System32", "WindowsPowerShell", "v1.0", "powershell.exe");
        string psCommand = $"\"{psImage}\" -NoProfile -WindowStyle Hidden -File \"{watch}\"";
        RemediationAction stopWatch = new()
        {
            Type = RemediationActionType.StopHostProcess,
            Target = psImage,
            ExpectedSha256 = new string('B', 64),
            RelatedFilePath = watch,
            RelatedFileSha256 = SteamAlertWatchdog.WatchdogHash,
            ConfigurationKind = SteamAlertWatchdog.ScriptHostKind,
            ConfigurationSnapshot = psCommand,
            ProcessId = 24680,
            ProcessStartedAtUtc = started
        };
        PowerShellScriptHostSnapshot ps = new()
        { ProcessId = 24680, StartedAtUtc = started, ImagePath = psImage, CommandLine = psCommand, Status = ScriptHostReadStatus.Readable };
        RemediationPlan psPlan = new() { Actions = [watchFile, payloadFile, stopWatch] };
        Dictionary<string, string> bindings = new() { [watch] = SteamAlertWatchdog.WatchdogHash, [payload] = SteamAlertWatchdog.ResidentHash };
        Check("Closure: complete exact PS preview passes", !Reject(() => BrokerEngine.RequireSteamAlertCoverage(psPlan, bindings, [ps])));
        Check("Closure: known renamed script outside preview blocks", Reject(() => BrokerEngine.RequireSteamAlertCoverage(psPlan,
            new Dictionary<string, string>(bindings) { [renamed] = SteamAlertWatchdog.WatchdogHash }, [ps])));
        Check("Closure: already quarantined file reappearing blocks", Reject(() => BrokerEngine.RequireSteamAlertCoverage(psPlan, bindings, [], new HashSet<Guid> { watchFile.ActionId })));
        Check("Closure: completed missing files do not require a second quarantine", !Reject(() => BrokerEngine.RequireSteamAlertCoverage(psPlan,
            new Dictionary<string, string>(), [], new HashSet<Guid> { watchFile.ActionId, payloadFile.ActionId, stopWatch.ActionId }, bindings)));
        Check("Closure: missing script still binds a newly running interpreter", Reject(() => BrokerEngine.RequireSteamAlertCoverage(psPlan,
            new Dictionary<string, string>(), [ps with { ProcessId = 24681 }], new HashSet<Guid> { watchFile.ActionId, stopWatch.ActionId }, bindings)));
        Check("Closure: completed stop cannot cover an active instance", Reject(() => BrokerEngine.RequireSteamAlertCoverage(psPlan, bindings, [ps],
            new HashSet<Guid> { stopWatch.ActionId })));
        Check("Closure: completely unrelated ordinary PS remains unaffected", !Reject(() => BrokerEngine.RequireSteamAlertCoverage(psPlan, bindings,
            [ps with { ProcessId = 24682, CommandLine = "powershell.exe -NoProfile -Command Get-Date" }])));
        Check("Closure: a similar script name is not an exact family reference", !Reject(() => BrokerEngine.RequireSteamAlertCoverage(psPlan, bindings,
            [ps with { ProcessId = 24683, CommandLine = $"powershell.exe -File \"{watch}.backup\"" }])));

        string cmd = Path.Combine(root, "Temp", "sa_update_1234.cmd");
        string staged = Path.Combine(resident, "Application Frame Host.new.exe"), backup = payload + ".bak";
        SteamAlertUpdateHandoffDescriptor descriptor = new(cmd, 1234, payload, staged, backup);
        string cmdHash = new string('C', 64);
        SteamAlertUpdateHandoffProof proof = new(descriptor, cmdHash, [new(payload, SteamAlertWatchdog.ResidentHash)]);
        Check("Closure: handoff joins an established resident installation", BrokerEngine.IsSteamAlertHandoffInScope(descriptor, seeds, scope, layout));
        SteamAlertUpdateHandoffDescriptor unrelated = new(Path.Combine(root, "Temp", "sa_update_9999.cmd"), 9999,
            Path.Combine(root, "Other", "Application Frame Host.exe"), Path.Combine(root, "Other", "Application Frame Host.new.exe"), Path.Combine(root, "Other", "Application Frame Host.exe.bak"));
        Check("Closure: matching family names in another directory do not join this installation", !BrokerEngine.IsSteamAlertHandoffInScope(unrelated, seeds, scope, layout));
        Check("Closure: offline target only permits its explicitly bound payload path", !BrokerEngine.IsSteamAlertHandoffInScope(descriptor,
            new Dictionary<string, string> { [sample] = SteamAlertWatchdog.ResidentHash }, sampleScope, layout));
        string cmdImage = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "System32", "cmd.exe");
        string command = $"\"{cmdImage}\" /c \"{cmd}\"";
        RemediationAction cmdFile = File(cmd, cmdHash, SteamAlertUpdateHandoff.RuleId);
        RemediationAction stopCmd = new()
        {
            Type = RemediationActionType.StopHostProcess,
            Target = cmdImage,
            ExpectedSha256 = new string('D', 64),
            RelatedFilePath = cmd,
            RelatedFileSha256 = cmdHash,
            ContentEvidenceRuleId = SteamAlertUpdateHandoff.RuleId,
            ConfigurationKind = SteamAlertUpdateHandoff.ScriptHostKind,
            ConfigurationSnapshot = command,
            ProcessId = 24690,
            ProcessStartedAtUtc = started
        };
        PowerShellScriptHostSnapshot cmdHost = new()
        { ProcessId = 24690, StartedAtUtc = started, ImagePath = cmdImage, CommandLine = command, Status = ScriptHostReadStatus.Readable };
        RemediationPlan cmdPlan = new() { Actions = [cmdFile, payloadFile, stopCmd] };
        Check("Closure: exact CMD, payload quarantine and host preview passes", !Reject(() => BrokerEngine.RequireSteamAlertHandoffCoverage(cmdPlan, [proof], [cmdHost])));
        Check("Closure: CMD file without approved strong-content quarantine blocks", Reject(() => BrokerEngine.RequireSteamAlertHandoffCoverage(
            new() { Actions = [File(cmd, cmdHash), payloadFile, stopCmd] }, [proof], [cmdHost])));
        Check("Closure: every CMD proof payload needs its quarantine action", Reject(() => BrokerEngine.RequireSteamAlertHandoffCoverage(
            new() { Actions = [cmdFile, stopCmd] }, [proof], [cmdHost])));
        SteamAlertUpdateHandoffProof withBackup = proof with { Payloads = [new(payload, SteamAlertWatchdog.ResidentHash), new(backup, SteamAlertWatchdog.ResidentHash)] };
        Check("Closure: discovered rollback copy cannot be omitted", Reject(() => BrokerEngine.RequireSteamAlertHandoffCoverage(cmdPlan, [withBackup], [cmdHost])));
        Check("Closure: script or loader hash cannot stand in for resident payload", Reject(() => BrokerEngine.RequireSteamAlertHandoffCoverage(cmdPlan,
            [proof with { Payloads = [new(payload, SteamAlertWatchdog.WatchdogHash)] }], [cmdHost])));
        Check("Closure: actual CMD process requires an exact stop action", Reject(() => BrokerEngine.RequireSteamAlertHandoffCoverage(
            new() { Actions = [cmdFile, payloadFile] }, [proof], [cmdHost])));
        Check("Closure: replacement CMD PID blocks", Reject(() => BrokerEngine.RequireSteamAlertHandoffCoverage(cmdPlan, [proof], [cmdHost with { ProcessId = 24691 }])));
        Check("Closure: reused CMD PID blocks", Reject(() => BrokerEngine.RequireSteamAlertHandoffCoverage(cmdPlan, [proof], [cmdHost with { StartedAtUtc = started.AddTicks(1) }])));
        Check("Closure: changed CMD arguments block", Reject(() => BrokerEngine.RequireSteamAlertHandoffCoverage(cmdPlan, [proof], [cmdHost with { CommandLine = command + " /extra" }])));
        Check("Closure: unreadable CMD is not reported as clean", Reject(() => BrokerEngine.RequireSteamAlertHandoffCoverage(cmdPlan, [proof],
            [cmdHost with { Status = ScriptHostReadStatus.AccessDenied, CommandLine = null }])));
        Check("Closure: unrelated readable CMD is not associated", !Reject(() => BrokerEngine.RequireSteamAlertHandoffCoverage(cmdPlan, [proof],
            [cmdHost with { ProcessId = 24692, CommandLine = "cmd.exe /c echo benign" }])));
        Check("Closure: a CMD path prefix cannot impersonate the exact script", !Reject(() => BrokerEngine.RequireSteamAlertHandoffCoverage(cmdPlan, [proof],
            [cmdHost with { ProcessId = 24694, CommandLine = $"cmd.exe /c \"{cmd}.disabled\"" }])));
        Check("Closure: unrelated sa_update command is not associated by basename", !Reject(() => BrokerEngine.RequireSteamAlertHandoffCoverage(cmdPlan, [proof],
            [cmdHost with { ProcessId = 24693, CommandLine = $"cmd.exe /c \"{unrelated.ScriptPath}\"" }])));
        Check("Closure: completed CMD quarantine may be absent without rereading its old proof", !Reject(() => BrokerEngine.RequireSteamAlertHandoffCoverage(cmdPlan,
            [], [], new HashSet<Guid> { cmdFile.ActionId }, [cmd])));
        Check("Closure: live CMD referencing a deleted known script still blocks", Reject(() => BrokerEngine.RequireSteamAlertHandoffCoverage(cmdPlan,
            [], [cmdHost], new HashSet<Guid> { cmdFile.ActionId }, [cmd])));
        Check("Closure: completed CMD stop cannot cover a live instance", Reject(() => BrokerEngine.RequireSteamAlertHandoffCoverage(cmdPlan, [proof], [cmdHost],
            new HashSet<Guid> { stopCmd.ActionId })));
        Check("Closure: reappearing CMD file cannot reuse a completed quarantine", Reject(() => BrokerEngine.RequireSteamAlertHandoffCoverage(cmdPlan, [proof], [],
            new HashSet<Guid> { cmdFile.ActionId })));

        const string key = @"Software\Microsoft\Windows\CurrentVersion\Run";
        RemediationAction run = new()
        {
            Type = RemediationActionType.RemoveRegistryValue,
            RegistryHive = "HKCU",
            RegistryView = "Default",
            RegistryKey = key,
            RegistryValueName = "SteamAlertWatch",
            ExpectedValueData = psCommand,
            RelatedFilePath = watch,
            RelatedFileSha256 = SteamAlertWatchdog.WatchdogHash
        };
        RemediationPlan runPlan = new() { Actions = [run] };
        SteamAlertClosureRunEntry entry = new("HKCU", "Default", key, "SteamAlertWatch", psCommand);
        Check("Closure: exact approved Run value is covered", !Reject(() => BrokerEngine.RequireSteamAlertRunEntry(runPlan, bindings, entry)));
        Check("Closure: new Run name referencing deleted script remains a binding", Reject(() => BrokerEngine.RequireSteamAlertRunEntry(runPlan, bindings,
            entry with { Name = "RenamedWatch" }, new HashSet<Guid> { run.ActionId })));
        Check("Closure: recreated old Run value cannot reuse completed action", Reject(() => BrokerEngine.RequireSteamAlertRunEntry(runPlan, bindings, entry,
            new HashSet<Guid> { run.ActionId })));
        Check("Closure: ambiguous Run command containing exact family path blocks", Reject(() => BrokerEngine.RequireSteamAlertRunEntry(runPlan, bindings,
            entry with { Command = psCommand + "; extra" })));
        Check("Closure: unrelated ordinary Run entry is untouched", !Reject(() => BrokerEngine.RequireSteamAlertRunEntry(runPlan, bindings,
            entry with { Name = "OrdinaryUpdater", Command = "powershell.exe -NoProfile -Command Get-Date" })));
        Check("Closure: similar-name Run target is not the bound script", !Reject(() => BrokerEngine.RequireSteamAlertRunEntry(runPlan, bindings,
            entry with { Name = "OrdinaryUpdater", Command = $"powershell.exe -File \"{watch}.backup\"" })));
        return Task.CompletedTask;
    }
}
