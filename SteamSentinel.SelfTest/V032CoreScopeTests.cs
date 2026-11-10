using System.IO;
using System.Text.Json;
using System.Text.Json.Nodes;
using SteamSentinel.Core.Models;
using SteamSentinel.Core.Remediation;
using SteamSentinel.Core.Reporting;
using SteamSentinel.Core.Scanning;
using SteamSentinel.Core.Steam;
using SteamSentinel.Core.Utilities;

namespace SteamSentinel.SelfTest;

internal static partial class Program
{
    private static async Task TestV032CoreScopeAsync(string root)
    {
        string directory = Path.Combine(root, "v032-exact-scope");
        Directory.CreateDirectory(directory);
        string first = Path.Combine(directory, "first.inert");
        string twin = Path.Combine(directory, "same-content.inert");
        await File.WriteAllTextAsync(first, "SteamSentinel inert scope fixture; never execute.");
        File.Copy(first, twin);
        string hash = await Hashing.Sha256FileAsync(first);
        string firstIdentity = FileScopeSafety.CaptureIdentity(first);
        string parentIdentity = FileScopeSafety.CaptureIdentity(directory, true);
        Check("v032 scope exact identity includes volume and file id", FileScopeSafety.IsValidIdentity(firstIdentity) && FileScopeSafety.IsValidIdentity(parentIdentity));
        Check("v032 scope equal bytes do not authorize another file identity", firstIdentity != FileScopeSafety.CaptureIdentity(twin));
        Check("v032 scope drive-root parent has a verified identity", FileScopeSafety.IsValidIdentity(FileScopeSafety.CaptureIdentity(Path.GetPathRoot(first)!, true)));
        Check("v032 scope malformed identities are rejected", new string?[] { null, "", new('A', 49), "C:\\same-file", new string('A', 16) + ":" + new string('X', 32), new string('0', 16) + ":" + new string('0', 32) }.All(id => !FileScopeSafety.IsValidIdentity(id)));
        await using (FileStream locked = RelatedArtifactReader.Open(first))
        {
            FileScopeSafety.ValidateHandlePath(locked.SafeFileHandle, first);
            Check("v032 scope identity is read from the exact locked handle", FileScopeSafety.ReadIdentity(locked.SafeFileHandle) == firstIdentity && FileScopeSafety.ReadLinkCount(locked.SafeFileHandle) == 1);
        }

        RuleSet rules = new();
        SteamLayout layout = new();
        string windows = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        Check("v032 scope protected directory can be an exact file parent without directory authority", FileScopeSafety.IsValidIdentity(FileScopeSafety.CaptureIdentity(windows, true)) &&
            FileScopeSafety.IsValidIdentity(FileScopeSafety.CaptureIdentity(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), true)) &&
            !FileScopeSafety.EvaluatePath(windows).Allowed);
        string windowsCandidate = Path.Combine(windows, "Temp", "SteamSentinel-Scope-NotCreated", "inert.bin");
        string programCandidate = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "SteamSentinel-Scope-NotCreated", "inert.bin");
        Check("v032 scope Windows ordinary file can request exact consent", FileRemediationScope.Assess(windowsCandidate, hash, rules, layout).Status == FileScopeStatus.SensitiveRequiresConsent);
        Check("v032 scope program file can request exact consent", FileRemediationScope.Assess(programCandidate, hash, rules, layout).Status == FileScopeStatus.SensitiveRequiresConsent);
        Check("v032 scope legacy automatic Windows policy remains closed", !FileRemediationScope.IsAllowed(windowsCandidate, hash, rules, layout));
        Check("v032 scope protected Windows resource is blocked before consent", FileRemediationScope.Assess(Path.Combine(Environment.SystemDirectory, "kernel32.dll"), hash, rules, layout).Status == FileScopeStatus.Blocked);
        Check("v032 scope tool and trusted-state paths cannot be authorized", !FileScopeSafety.EvaluatePath(Path.Combine(AppContext.BaseDirectory, "inert.bin")).Allowed &&
            !FileScopeSafety.EvaluatePath(Path.Combine(AppPaths.MachineStateRoot, "inert.bin")).Allowed &&
            !FileScopeSafety.EvaluatePath(Path.Combine(AppPaths.UserStateRoot, "inert.bin")).Allowed);
        Check("v032 scope unsafe namespaces and whole roots are not file targets", new[] { @"\\server.invalid\share\inert.bin", @"\\?\C:\inert.bin", @"C:\inert.bin:stream", Path.GetPathRoot(first)!, "relative.bin" }
            .All(path => !FileScopeSafety.EvaluatePath(path).Allowed));

        Finding finding = new()
        {
            RuleId = "HEUR-STEAM-UI-PATCHER",
            Category = FindingCategory.File,
            CanRemediate = true,
            Score = 90,
            Sha256 = hash,
            TargetSha256 = hash,
            Target = first,
            SuggestedActions = [SuggestedActionKind.QuarantineFile]
        };
        string original = JsonSerializer.Serialize(finding, JsonFile.Options);
        RemediationPlan plan = await new RemediationPlanBuilder(rules).BuildAsync([finding], false, requestExplicitFileTargets: true);
        RemediationAction action = plan.Actions.Single();
        Check("v032 scope plan request binds exact file and parent identities", plan.ExplicitFileTargetsRequested &&
            action.ExpectedFileIdentity == firstIdentity && action.ExpectedParentIdentity == parentIdentity &&
            action.ExpectedSha256 == hash && action.Target == first && action.Type == RemediationActionType.QuarantineFile);
        Check("v032 scope authorization does not change heuristic evidence", !action.IsKnownMalware && action.ConfidenceScore == 90 &&
            JsonSerializer.Serialize(finding, JsonFile.Options) == original);

        string fingerprint = RemediationPlanIdentity.Fingerprint(plan);
        JsonObject changed = JsonNode.Parse(JsonSerializer.Serialize(plan, JsonFile.Options))!.AsObject();
        changed[nameof(RemediationPlan.ExplicitFileTargetsRequested)] = false;
        Check("v032 scope explicit request is included in typed plan identity", RemediationPlanIdentity.Fingerprint(changed.Deserialize<RemediationPlan>(JsonFile.Options)!) != fingerprint);
        changed = JsonNode.Parse(JsonSerializer.Serialize(plan, JsonFile.Options))!.AsObject();
        changed[nameof(RemediationPlan.Actions)]![0]![nameof(RemediationAction.ExpectedFileIdentity)] = FileScopeSafety.CaptureIdentity(twin);
        Check("v032 scope replacing file identity changes typed plan identity", RemediationPlanIdentity.Fingerprint(changed.Deserialize<RemediationPlan>(JsonFile.Options)!) != fingerprint);
        RemediationPlan legacy = new() { Actions = [new() { Type = RemediationActionType.QuarantineFile, Target = first, ExpectedSha256 = hash }] };
        string legacyJson = JsonSerializer.Serialize(legacy, JsonFile.Options);
        Check("v032 scope legacy plan serialization omits all new default authority fields", !legacyJson.Contains(nameof(RemediationPlan.ExplicitFileTargetsRequested), StringComparison.Ordinal) &&
            !legacyJson.Contains(nameof(RemediationAction.ExpectedFileIdentity), StringComparison.Ordinal) && !legacyJson.Contains(nameof(RemediationAction.ExpectedParentIdentity), StringComparison.Ordinal));
        Check("v032 scope importing an old plan does not request expanded scope", !JsonSerializer.Deserialize<RemediationPlan>(legacyJson, JsonFile.Options)!.ExplicitFileTargetsRequested);

        List<List<RemediationAction>> groups = Enumerable.Range(0, 130).Select(index => new List<RemediationAction>
        { new() { Type = RemediationActionType.QuarantineFile, Target = Path.Combine(directory, $"not-created-{index}.bin"), ExpectedSha256 = hash,
            ExpectedFileIdentity = firstIdentity, ExpectedParentIdentity = parentIdentity } }).ToList();
        List<RemediationPlan> packed = RemediationBatchPlanner.PackActions(groups, true);
        Check("v032 scope every child batch preserves the finite request", packed.Count == 3 && packed.All(p => p.ExplicitFileTargetsRequested && p.Actions.Count <= 64) &&
            packed.SelectMany(p => p.Actions).Select(a => a.ActionId).SequenceEqual(groups.SelectMany(g => g).Select(a => a.ActionId)));
        Check("v032 scope legacy batch packing never invents authorization", RemediationBatchPlanner.PackActions(groups).All(p => !p.ExplicitFileTargetsRequested));

        Finding weak = new()
        {
            RuleId = "HEUR-SCRIPT-TOKEN-COOCCURRENCE",
            CanRemediate = true,
            Score = 100,
            Target = first,
            Sha256 = hash,
            SuggestedActions = [SuggestedActionKind.QuarantineFile]
        };
        bool weakRejected = false;
        try { await new RemediationPlanBuilder(rules).BuildAsync([weak], false, requestExplicitFileTargets: true); }
        catch (RemediationEvidenceException) { weakRejected = true; }
        Check("v032 scope consent cannot promote review-only evidence", weakRejected);
        await File.AppendAllTextAsync(first, " changed");
        bool changedRejected = false;
        try { await new RemediationPlanBuilder(rules).BuildAsync([finding], false, requestExplicitFileTargets: true); }
        catch (InvalidDataException) { changedRejected = true; }
        Check("v032 scope changed content cannot reuse the scanned snapshot", changedRejected);
        Check("v032 scope historical cases cannot replay saved requests", !new RemediationCaseRecord { Plans = [plan] }.MayReplaySavedPlans);

        foreach (string key in new[] { "Automatic", "ExplicitConsent", "SensitiveConsent", "NeedsVerification", "UnsupportedPath", "ProductProtected", "RedirectedPath", "SystemProtected" })
        {
            string chinese, english;
            using (DisplayText.UseCulture(DisplayText.Chinese)) chinese = MessageText.Create("Scope." + key).Display;
            using (DisplayText.UseCulture(DisplayText.English)) english = MessageText.Create("Scope." + key).Display;
            Check("v032 scope bilingual reason " + key, chinese != english && !chinese.Contains("Scope.", StringComparison.Ordinal) && !english.Contains("Scope.", StringComparison.Ordinal));
        }
    }
}
