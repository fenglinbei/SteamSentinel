using System.IO;
using SteamSentinel.Core.Inspection;
using SteamSentinel.Core.Models;
using SteamSentinel.Core.Remediation;
using SteamSentinel.Core.Rules;
using SteamSentinel.Core.Scanning;
using SteamSentinel.Core.Steam;
using SteamSentinel.Core.Utilities;

namespace SteamSentinel.SelfTest;

internal static partial class Program
{
    private static async Task TestSteamAlertWatchdogDiscoveryAsync(string root)
    {
        RuleSet production = RuleLoader.LoadEmbedded();
        const string watchHash = "94FCA6D53A1D7DF49E0AAA6C8388950B1527DF7439969FE3F16FB64832E12699";
        const string updateHash = "35233E36BF0F03B4CEA2F2DCD296E927CCD014F35ACCB126D2BAF9861D49BBA8";
        const string launchHash = "3CFBC8C910FB4F24E88380948655873486DD3D0A505F451816FD9A50C362940F";
        const string payloadHash = "54799E1B7B90961F29284226210CD6029CAB87EC82635B3FB7AB99D0BDB72FE2";
        Check("Watchdog exact rules: three unique scripts and rebuilt resident", new[]
        {
            (watchHash, SteamAlertWatchdog.WatchdogRole), (updateHash, SteamAlertWatchdog.UpdaterRole),
            (launchHash, SteamAlertWatchdog.LauncherRole), (payloadHash, SteamAlertInstallation.UpdatedResidentRule)
        }.All(expected => production.KnownHashes.Any(rule => rule.Malware && rule.Sha256 == expected.Item1 && rule.Id == expected.Item2)));
        Check("Watchdog resident version retains the resident family role",
            SteamAlertInstallation.FamilyRole(SteamAlertInstallation.UpdatedResidentRule) == SteamAlertInstallation.ResidentRule);
        Check("Watchdog rebuilt resident and scripts map cleanly to family roles",
            SteamAlertWatchdog.RoleForHash(watchHash) == SteamAlertWatchdog.WatchdogRole &&
            SteamAlertWatchdog.RoleForHash(updateHash) == SteamAlertWatchdog.UpdaterRole &&
            SteamAlertWatchdog.RoleForHash(launchHash) == SteamAlertWatchdog.LauncherRole &&
            production.KnownHashes.Any(rule => rule.Sha256 == payloadHash && SteamAlertInstallation.FamilyRole(rule.Id) == SteamAlertInstallation.ResidentRule));
        Check("Watchdog BOM-free resources keep precise rules and the same script family roles", new[]
        {
            ("STEAMALERT-WATCHDOG-NOBOM", "4D68A9C6F0C2802339BC572CF3E4EFF0462C01D1E894CFF9E8B578F9C2736FFF", SteamAlertWatchdog.WatchdogRole),
            ("STEAMALERT-UPDATER-NOBOM", "0EC69EF47D19F52DA69B88FCA57191F5323D3CFD7DE9F3A933313A44EA090150", SteamAlertWatchdog.UpdaterRole),
            ("STEAMALERT-LAUNCHER-NOBOM", "DFD442A5B61AF0607A94F5E2AEFF69E8F68F3B89264C424A91BFEA6D2184FD4B", SteamAlertWatchdog.LauncherRole)
        }.All(expected => production.KnownHashes.Any(rule => rule.Malware && rule.Id == expected.Item1 && rule.Sha256 == expected.Item2) &&
            SteamAlertInstallation.FamilyRole(expected.Item1) == expected.Item3 && SteamAlertWatchdog.RoleForHash(expected.Item2) == expected.Item3));
        Check("Watchdog rebuilt embedded core has an exact independent rule", production.KnownHashes.Any(rule =>
            rule.Malware && rule.Id == "STEAMALERT-CORE-20261117" && rule.Sha256 == "CDE5643722DBD6487625D5CF592E445FFA3C771FB8A5197EC9A97D249C19C7B7"));
        byte[] inertCore = EmbeddedCoreFixture();
        byte[] inertHost = EmbeddedHostFixture(inertCore);
        SteamAlertEmbeddedProof? InspectCoreRule(string ruleId)
        {
            using MemoryStream stream = new(inertHost);
            return SteamAlertEmbeddedEvidence.Inspect(stream, new RuleSet
            {
                KnownHashes = [new() { Id = ruleId, Sha256 = Hashing.Sha256Bytes(inertCore), Malware = true }]
            });
        }
        Check("Watchdog rebuilt embedded core ID preserves exact resource proof without accepting a CORE prefix wildcard",
            InspectCoreRule("STEAMALERT-CORE-20261117") is not null && InspectCoreRule("STEAMALERT-CORE-UNVERIFIED") is null);

        string fixture = Path.Combine(root, "watchdog-discovery-" + Guid.NewGuid().ToString("N"));
        string resident = Path.Combine(fixture, "LocalAppData", "SteamAlertDemo");
        string updater = Path.Combine(fixture, "ProgramData", "SteamAlertUpdater");
        string embeddedUpdater = Path.Combine(resident, "Updater");
        string mod = Path.Combine(fixture, "game", "Mods", "3835179592", "PWLoader.dll");
        string downloads = Path.Combine(fixture, "Downloads");
        foreach (string directory in new[] { resident, updater, embeddedUpdater, Path.GetDirectoryName(mod)!, downloads,
            Path.Combine(updater, "cache"), Path.Combine(embeddedUpdater, "cache") }) Directory.CreateDirectory(directory);
        string payload = Path.Combine(resident, "Application Frame Host.exe");
        string watch = Path.Combine(updater, "sa_watch.ps1");
        string update = Path.Combine(updater, "sa_updater.ps1");
        string updateCopy = Path.Combine(updater, "update.ps1");
        string launch = Path.Combine(updater, "sa_launch.ps1");
        string alternate = Path.Combine(embeddedUpdater, "sa_watch.ps1");
        string renamed = Path.Combine(updater, "renamed-watch.ps1");
        string clean = Path.Combine(updater, "user-script.ps1");
        // Fixtures are inert text, never copied from or executed as malware samples.
        await File.WriteAllTextAsync(payload, "inert resident fixture");
        await File.WriteAllTextAsync(mod, "inert loader fixture");
        await File.WriteAllTextAsync(watch, "# inert watch fixture");
        await File.WriteAllTextAsync(update, "# inert updater fixture");
        await File.WriteAllTextAsync(launch, "# inert launcher fixture");
        await File.WriteAllTextAsync(clean, "# legitimate user script");
        File.Copy(update, updateCopy);
        File.Copy(watch, alternate);
        File.Copy(watch, renamed);
        string[] stages = [Path.Combine(resident, "Application Frame Host.new.exe"),
            Path.Combine(resident, "Application Frame Host.exe.old"), Path.Combine(resident, "Application Frame Host.exe.bak"),
            Path.Combine(updater, "cache", "new.exe"), Path.Combine(embeddedUpdater, "cache", "new.exe")];
        foreach (string stage in stages) File.Copy(payload, stage);
        RuleSet fixtures = new()
        {
            KnownHashes = [
                new() { Id = SteamAlertInstallation.UpdatedResidentRule, Sha256 = await Hashing.Sha256FileAsync(payload) },
                new() { Id = SteamAlertInstallation.LoaderRule, Sha256 = await Hashing.Sha256FileAsync(mod) },
                new() { Id = SteamAlertWatchdog.WatchdogRole, Sha256 = await Hashing.Sha256FileAsync(watch) },
                new() { Id = SteamAlertWatchdog.UpdaterRole, Sha256 = await Hashing.Sha256FileAsync(update) },
                new() { Id = SteamAlertWatchdog.LauncherRole, Sha256 = await Hashing.Sha256FileAsync(launch) }
            ]
        };
        Finding FileFinding(string path, int ruleIndex) => new()
        {
            Category = FindingCategory.File,
            RuleId = fixtures.KnownHashes[ruleIndex].Id,
            Target = path,
            ContentPath = path,
            Sha256 = fixtures.KnownHashes[ruleIndex].Sha256,
            TargetSha256 = fixtures.KnownHashes[ruleIndex].Sha256,
            CanRemediate = true,
            IsKnownMalware = true,
            Score = 100,
            SuggestedActions = [SuggestedActionKind.QuarantineFile]
        };
        SteamLayout layout = new();
        layout.ContentRoots.Add(new(Path.Combine(fixture, "game", "Mods"), "1234", "mod", "Test"));
        ScanReport discovery = new();
        IReadOnlyList<string> discovered = new RelatedArtifactScanner(fixtures).DiscoverUpdaterScripts(discovery, resident, updater);
        Check("Watchdog discovery includes ProgramData and resident Updater script locations",
            new[] { watch, update, updateCopy, launch, alternate, renamed, clean }.All(discovered.Contains));
        string nested = Path.Combine(updater, "nested", "sa_watch.ps1");
        Directory.CreateDirectory(Path.GetDirectoryName(nested)!);
        File.Copy(watch, nested);
        Check("Watchdog directory probing is nonrecursive and does not scan arbitrary ProgramData siblings",
            !new RelatedArtifactScanner(fixtures).DiscoverUpdaterScripts(new(), resident, updater).Contains(nested));

        async Task<RelatedArtifactExpansion> Expand(Finding selected) => await new RelatedArtifactScanner(fixtures, LiveAssociationProbeMode.InertEmptyHost).ExpandLocalAsync(
            [selected], new ScanReport { Findings = [selected] }, default, RelatedArtifactScanner.MaximumVerificationBytes,
            true, layout, resident, updater, Path.Combine(fixture, "Temp"));
        Finding main = FileFinding(payload, 0);
        RelatedArtifactExpansion fromMain = await Expand(main);
        string[] expected = [payload, mod, watch, update, updateCopy, launch, alternate, renamed, .. stages];
        Check("Watchdog preview expands an installed resident to exact scripts, loader and staged copies",
            expected.All(path => fromMain.Findings.Any(f => f.Target == path && f.CanRemediate &&
                f.SuggestedActions.Contains(SuggestedActionKind.QuarantineFile))) &&
            fromMain.Findings.All(f => !f.SuggestedActions.Contains(SuggestedActionKind.QuarantineDirectory)));
        Check("Watchdog unknown same-directory script remains unmodified and produces a coverage note",
            !fromMain.Findings.Any(f => f.Target == clean && f.CanRemediate) && fromMain.NoteTexts.Any(n =>
                n.Message?.MessageId == "SteamAlert.Watchdog.ScriptUnconfirmed" && n.Message.Arguments.Any(a => a.OriginalText == clean)));
        RelatedArtifactExpansion fromWatch = await Expand(FileFinding(watch, 2));
        Check("Watchdog preview works when the installed script is the selected seed",
            expected.All(path => fromWatch.Findings.Any(f => f.Target == path && f.CanRemediate)));
        await File.WriteAllTextAsync(launch, "# clean script with the expected launcher filename");
        Check("Watchdog known filename never authorizes quarantining a replaced benign script",
            !(await Expand(main)).Findings.Any(f => f.Target == launch && f.CanRemediate));
        string copied = Path.Combine(downloads, "sa_watch.ps1");
        File.Copy(watch, copied);
        RelatedArtifactExpansion evidenceCopy = await Expand(FileFinding(copied, 2));
        Check("Watchdog sample copy cannot authorize live installed-family cleanup",
            !evidenceCopy.Findings.Any(f => expected.Contains(f.Target)));
        Finding archive = new()
        {
            Category = FindingCategory.Archive,
            RuleId = SteamAlertWatchdog.WatchdogRole,
            Target = copied,
            ContentPath = copied + "!/sa_watch.ps1",
            Sha256 = fixtures.KnownHashes[2].Sha256,
            TargetSha256 = fixtures.KnownHashes[2].Sha256,
            CanRemediate = true,
            IsKnownMalware = true,
            SuggestedActions = [SuggestedActionKind.QuarantineFile]
        };
        Check("Watchdog archive member is never an installed-family seed",
            SteamAlertInstallation.InstalledSeedRole(archive, fixtures.KnownHashes.ToDictionary(r => r.Sha256)) is null);
        await File.AppendAllTextAsync(watch, " changed after scan");
        Check("Watchdog stale selected script cannot introduce fresh family companions",
            !(await Expand(FileFinding(watch, 2))).Findings.Any(f => f.Target == payload && f.CanRemediate));

        string systemPowerShell = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "System32",
            "WindowsPowerShell", "v1.0", "powershell.exe");
        string command = "\"" + systemPowerShell + "\" -NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File \"" + watch + "\"";
        PowerShellScriptHostSnapshot snapshot = new()
        {
            ProcessId = 8123,
            ParentProcessId = 4000,
            StartedAtUtc = DateTimeOffset.UtcNow,
            ImagePath = systemPowerShell,
            CommandLine = command,
            Status = ScriptHostReadStatus.Readable
        };
        string inertImageHash = new('A', 64);
        Finding? hostFinding = RelatedArtifactScanner.CreateScriptHostFinding(snapshot, snapshot, inertImageHash, watch, watchHash);
        Check("Watchdog system host binds exact command, start time and known script without labeling its image malware",
            hostFinding is { CanRemediate: true, IsKnownMalware: false, ConfigurationKind: SteamAlertWatchdog.ScriptHostKind } &&
            hostFinding.ConfigurationSnapshot == command && hostFinding.RelatedFileSha256 == watchHash &&
            hostFinding.SuggestedActions.SequenceEqual([SuggestedActionKind.StopHostProcess]));
        Check("Watchdog host rejects PID reuse and command-line replacement",
            RelatedArtifactScanner.CreateScriptHostFinding(snapshot, snapshot with { StartedAtUtc = snapshot.StartedAtUtc!.Value.AddSeconds(1) },
                inertImageHash, watch, watchHash) is null &&
            RelatedArtifactScanner.CreateScriptHostFinding(snapshot, snapshot with { CommandLine = command + " -EveryMin 1" },
                inertImageHash, watch, watchHash) is null);
        Check("Watchdog host rejects unreadable identity, benign script hash and mismatched script binding",
            RelatedArtifactScanner.CreateScriptHostFinding(snapshot, snapshot with { Status = ScriptHostReadStatus.AccessDenied }, inertImageHash, watch, watchHash) is null &&
            RelatedArtifactScanner.CreateScriptHostFinding(snapshot, snapshot, inertImageHash, watch, new string('B', 64)) is null &&
            RelatedArtifactScanner.CreateScriptHostFinding(snapshot, snapshot, inertImageHash, launch, watchHash) is null);
        PowerShellScriptHostSnapshot fakeHost = snapshot with { ImagePath = Path.Combine(downloads, "powershell.exe") };
        Check("Watchdog host refuses a renamed executable outside trusted Windows PowerShell paths",
            RelatedArtifactScanner.CreateScriptHostFinding(fakeHost, fakeHost, inertImageHash, watch, watchHash) is null);
    }
}
