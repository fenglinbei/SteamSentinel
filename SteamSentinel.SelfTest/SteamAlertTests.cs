using System.IO;
using SteamSentinel.Core.Models;
using SteamSentinel.Core.Remediation;
using SteamSentinel.Core.Scanning;
using SteamSentinel.Core.Steam;
using SteamSentinel.Core.Utilities;

namespace SteamSentinel.SelfTest;

internal static partial class Program
{
    private static async Task TestSteamAlertAsync(string root)
    {
        TestPawnshopExactRules();
        await TestManagedSteamAlertAsync(root);
        await TestPawnshopSteamUiAsync(root);
        await TestSteamAlertInstallationAsync(root);
    }

    private static async Task TestSteamAlertInstallationAsync(string root)
    {
        string installation = Path.Combine(root, "steamalert-" + Guid.NewGuid().ToString("N"));
        string mods = Path.Combine(installation, "game", "Mods");
        string residentHome = Path.Combine(installation, "profile", "SteamAlertDemo");
        string downloads = Path.Combine(installation, "Downloads");
        string workshop = Path.Combine(installation, "steamapps", "workshop", "content", "1234");
        string item = Path.Combine(workshop, "5678");
        foreach (string dir in new[] { mods, residentHome, downloads, item }) Directory.CreateDirectory(dir);
        SteamLayout layout = new();
        layout.ContentRoots.Add(new(mods, "1234", "mod", "Test"));
        layout.WorkshopRoots.Add(workshop);
        string loader = Path.Combine(mods, "renamed.dll"), host = Path.Combine(residentHome, "renamed.exe");
        string copy = Path.Combine(downloads, "renamed.dll"), otherLoader = Path.Combine(item, "other.dll");
        await File.WriteAllTextAsync(loader, "inert test mod");
        await File.WriteAllTextAsync(host, "inert test host");
        File.Copy(loader, copy);
        File.Copy(loader, otherLoader);
        string loaderHash = await Hashing.Sha256FileAsync(loader), hostHash = await Hashing.Sha256FileAsync(host);
        RuleSet rules = new()
        {
            KnownHashes = [
            new() { Id = SteamAlertInstallation.LoaderRule, Sha256 = loaderHash },
            new() { Id = SteamAlertInstallation.ResidentRule, Sha256 = hostHash }]
        };
        Finding ScanFile(string path, HashRule rule, string? content = null, string? hash = null) => new()
        {
            Category = FindingCategory.File,
            RuleId = rule.Id,
            Target = path,
            Sha256 = hash ?? rule.Sha256,
            ContentPath = content ?? path,
            TargetSha256 = rule.Sha256,
            IsKnownMalware = true,
            CanRemediate = true,
            Score = 100,
            SuggestedActions = [SuggestedActionKind.QuarantineFile]
        };
        var known = rules.KnownHashes.ToDictionary(r => r.Sha256, StringComparer.OrdinalIgnoreCase);
        var process = new Finding
        {
            Category = FindingCategory.Process,
            RuleId = SteamAlertInstallation.ResidentRule,
            Target = host,
            ProcessId = 12345,
            Sha256 = hostHash,
            CanRemediate = true
        };
        var run = new Finding
        {
            Category = FindingCategory.Persistence,
            RuleId = "PERSISTENCE-RUN-BOUND",
            Target = "command",
            RelatedFilePath = host,
            RelatedFileSha256 = hostHash,
            CanRemediate = true
        };
        Check("SteamAlert accepts a direct process or file-bound Run entry as a resident seed",
            new[] { process, run }.All(f => SteamAlertInstallation.InstalledSeedRole(f, known) == SteamAlertInstallation.ResidentRule));
        Finding[] peers = SteamAlertInstallation.InstalledPeers([
            ScanFile(loader, rules.KnownHashes[0]), ScanFile(host, rules.KnownHashes[1]),
            ScanFile(otherLoader, rules.KnownHashes[0]), ScanFile(copy, rules.KnownHashes[0]),
            ScanFile(loader, rules.KnownHashes[0], loader + "!/PWLoader.dll"),
            ScanFile(host, rules.KnownHashes[1], hash: loaderHash)], known, layout, residentHome).ToArray();
        Check("SteamAlert pairs installed mod, workshop copy and resident, excluding evidence copies, members and mismatched content",
            peers.Select(f => f.Target).SequenceEqual(new[] { loader, host, otherLoader }));
        RemediationPlan plan = await new RemediationPlanBuilder(rules).BuildAsync(peers, false, requestExplicitFileTargets: true);
        Check("SteamAlert preview includes three independent exact quarantine targets and no directory",
            plan.Actions.Where(a => a.Type == RemediationActionType.QuarantineFile).Select(a => a.Target)
                .ToHashSet(StringComparer.OrdinalIgnoreCase).SetEquals(new[] { loader, host, otherLoader }) &&
            plan.Actions.All(a => a.Type != RemediationActionType.QuarantineDirectory));
        string installedHost = Path.Combine(residentHome, "Application Frame Host.exe");
        File.Copy(host, installedHost);
        string installedLoader = Path.Combine(mods, "3835179592", "PWLoader.dll");
        string differentFile = Path.Combine(mods, "3835252991", "PWLoader.dll");
        Directory.CreateDirectory(Path.GetDirectoryName(installedLoader)!);
        Directory.CreateDirectory(Path.GetDirectoryName(differentFile)!);
        File.Copy(loader, installedLoader);
        await File.WriteAllTextAsync(differentFile, "legitimate file under the same name");
        async Task<RelatedArtifactExpansion> Expand(Finding selected) =>
            await new RelatedArtifactScanner(rules).ExpandLocalAsync([selected], new ScanReport { Findings = [selected] },
                default, RelatedArtifactScanner.MaximumVerificationBytes, true, layout, residentHome);
        var fromLoader = await Expand(peers[0]);
        var fromHost = await Expand(peers[1]);
        Check("SteamAlert isolated mod scan additionally verifies its installed resident",
            fromLoader.Findings.Any(f => f.Target == installedHost && f.CanRemediate && f.Sha256 == hostHash));
        Check("SteamAlert resident scan includes a matching installed mod but skips a same-name clean DLL",
            fromHost.Findings.Any(f => f.Target == installedLoader && f.CanRemediate && f.Sha256 == loaderHash) &&
            !fromHost.Findings.Any(f => f.Target == differentFile));
        Check("SteamAlert an exact sample in Downloads does not probe live installation companions",
            !(await Expand(ScanFile(copy, rules.KnownHashes[0]))).Findings.Any(f => f.Target == installedHost));
        await File.AppendAllTextAsync(host, " changed since scan");
        Check("SteamAlert a stale selected host cannot introduce its mod as a companion",
            !(await Expand(peers[1])).Findings.Any(f => f.Target == installedLoader));
        bool refused = false;
        try { await new RemediationPlanBuilder(rules).BuildAsync([peers[1]], false, requestExplicitFileTargets: true); }
        catch (InvalidDataException) { refused = true; }
        catch (UnauthorizedAccessException) { refused = true; }
        Check("SteamAlert refuses a changed resident before preview", refused);
    }
}
