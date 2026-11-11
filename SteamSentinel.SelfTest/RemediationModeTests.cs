using System.ComponentModel;
using System.IO;
using System.Security.Principal;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.Win32;
using SteamSentinel.Broker;
using SteamSentinel.Core.Models;
using SteamSentinel.Core.Remediation;
using SteamSentinel.Core.Utilities;

namespace SteamSentinel.SelfTest;

internal static partial class Program
{
    private static async Task TestRemediationModesAsync(string root)
    {
        string directory = Path.Combine(root, "mode-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        string path = Path.Combine(directory, "user-reviewed.inert");
        const string contents = "Inert user-selected risk fixture; never executable.";
        await File.WriteAllTextAsync(path, contents);
        string hash = await Hashing.Sha256FileAsync(path);
        Finding weak = new()
        {
            RuleId = "HEUR-SCRIPT-TOKEN-COOCCURRENCE", Target = path, Sha256 = hash,
            Category = FindingCategory.File, Severity = FindingSeverity.High, Score = 90,
            CanRemediate = false, SuggestedActions = [SuggestedActionKind.ReviewOnly]
        };
        string original = JsonSerializer.Serialize(weak, JsonFile.Options);
        Check("Modes conservative keeps review-only evidence", ReferenceEquals(weak, RemediationModePolicy.ProjectFinding(weak, RemediationMode.Conservative)));
        Finding projected = RemediationModePolicy.ProjectFinding(weak, RemediationMode.Aggressive);
        Check("Modes aggressive separates user choice from malware", projected.UserSelectedRisk && projected.CanRemediate && !projected.IsKnownMalware &&
            projected.RuleId == weak.RuleId && projected.Score == 90 && projected.SuggestedActions.SequenceEqual([SuggestedActionKind.QuarantineFile]));
        Check("Modes original report stays unchanged", JsonSerializer.Serialize(weak, JsonFile.Options) == original && !original.Contains("UserSelectedRisk"));
        Check("Modes serialized reports cannot import user authority", !JsonSerializer.Deserialize<Finding>(JsonSerializer.Serialize(projected, JsonFile.Options), JsonFile.Options)!.UserSelectedRisk);
        Check("Modes missing target hash cannot be selected", !RemediationModePolicy.CanRequestQuarantine(new() { Target = path, Severity = FindingSeverity.High }));
        Check("Modes archive inner hash cannot authorize outer file", !RemediationModePolicy.CanRequestQuarantine(new()
            { Target = path, ContentPath = path + ">inside.exe", Sha256 = hash, Severity = FindingSeverity.High }));
        Check("Modes archive outer hash can authorize physical file", RemediationModePolicy.CanRequestQuarantine(new()
            { Target = path, ContentPath = path + ">inside.exe", Sha256 = new('A', 64), TargetSha256 = hash, Severity = FindingSeverity.High }));
        Check("Modes coverage and configuration do not become arbitrary file actions", !RemediationModePolicy.CanRequestQuarantine(new()
            { Category = FindingCategory.Coverage, Target = path, Sha256 = hash, Severity = FindingSeverity.High }));
        RemediationPlanBuilder builder = new(new RuleSet());
        bool conservativeDenied = false;
        try { await builder.BuildAsync([weak], false); } catch (UnauthorizedAccessException) { conservativeDenied = true; }
        Check("Modes conservative refuses weak evidence", conservativeDenied);
        RemediationPlan plan = await builder.BuildAsync([weak], false, remediationMode: RemediationMode.Aggressive);
        RemediationAction file = plan.Actions.Single();
        Check("Modes risk plan captures exact file and parent", plan.Mode == RemediationMode.Aggressive && plan.ExplicitFileTargetsRequested &&
            file.UserSelectedRisk && !file.IsKnownMalware && file.ExpectedSha256 == hash && FileScopeSafety.IsValidIdentity(file.ExpectedFileIdentity) &&
            FileScopeSafety.IsValidIdentity(file.ExpectedParentIdentity));
        BrokerEngine.ValidateUserRiskRequestShape(plan);
        string identity = RemediationPlanIdentity.Fingerprint(plan);
        foreach (string property in new[] { nameof(RemediationPlan.Mode), nameof(RemediationPlan.ExplicitFileTargetsRequested) })
        {
            JsonObject node = JsonSerializer.SerializeToNode(plan, JsonFile.Options)!.AsObject(); node.Remove(property);
            RemediationPlan downgraded = node.Deserialize<RemediationPlan>(JsonFile.Options)!;
            Check("Modes authority fingerprint binds " + property, RemediationPlanIdentity.Fingerprint(downgraded) != identity);
            Check("Modes Broker rejects risk without " + property, ScopeRejects(() => BrokerEngine.ValidateUserRiskRequestShape(downgraded)));
        }
        Check("Modes invalid enum rejected", ScopeRejects(() => BrokerEngine.ValidateUserRiskRequestShape(new() { Mode = (RemediationMode)99 })));
        Check("Modes legacy plan defaults to conservative", JsonSerializer.Deserialize<RemediationPlan>(JsonSerializer.Serialize(new RemediationPlan(), JsonFile.Options), JsonFile.Options)!.Mode == RemediationMode.Conservative);
        RemediationBatchSession batch = await new RemediationBatchPlanner(new RuleSet()).PrepareAsync([weak], new() { Findings = [weak] }, false,
            remediationMode: RemediationMode.Aggressive);
        Check("Modes batch preserves user-risk choice", batch.Plans.Count == 1 && batch.Plans[0].Mode == RemediationMode.Aggressive &&
            batch.Plans[0].Actions.Single().UserSelectedRisk && batch.Targets.Count == 1);
        RemediationBatchSession conservative = await new RemediationBatchPlanner(new RuleSet()).PrepareAsync([weak], new() { Findings = [weak] }, false);
        Check("Modes conservative batch accounts for rejected target", conservative.Plans.Count == 0 && conservative.PreparationNotes.Count > 0);

        const string runPath = @"Software\Microsoft\Windows\CurrentVersion\Run";
        string name = "SteamSentinel-Inert-Mode-Test-" + Guid.NewGuid().ToString("N");
        using RegistryKey key = Registry.CurrentUser.CreateSubKey(runPath, writable: true);
        string command = $"\"{path}\" --inert";
        RemediationPlan companions;
        try
        {
            key.SetValue(name, command, RegistryValueKind.String);
            companions = await builder.BuildAsync([weak], false, remediationMode: RemediationMode.Aggressive);
            RemediationAction startup = companions.Actions.Single(a => a.Type == RemediationActionType.RemoveRegistryValue);
            RemediationAction companionFile = companions.Actions.Single(a => a.Type == RemediationActionType.QuarantineFile);
            Check("Modes direct startup included in same confirmation", startup.UserSelectedRisk && !startup.IsKnownMalware && startup.RegistryValueName == name &&
                startup.RelatedFileSha256 == hash && RemediationDependencies.Build(companions.Actions)[companionFile.ActionId].Contains(startup.ActionId));
            BrokerEngine.ValidateUserRiskRequestShape(companions);
            Check("Modes orphan companion rejected", ScopeRejects(() => BrokerEngine.ValidateUserRiskRequestShape(new()
                { Mode = RemediationMode.Aggressive, ExplicitFileTargetsRequested = true, Actions = [startup] })));
            JsonObject tampered = JsonSerializer.SerializeToNode(companions, JsonFile.Options)!.AsObject();
            tampered[nameof(RemediationPlan.Actions)]![0]![nameof(RemediationAction.ExpectedValueData)] = "cmd.exe /c " + command;
            Check("Modes wrapped companion rejected", ScopeRejects(() => BrokerEngine.ValidateUserRiskRequestShape(tampered.Deserialize<RemediationPlan>(JsonFile.Options)!)));
            QuarantineRecord registryRecord = new()
            {
                Type = RemediationActionType.RemoveRegistryValue, UserSelectedRisk = true, OriginalTarget = command,
                RelatedFilePath = path, RelatedFileSha256 = hash, RegistryValueData = command,
                RegistryHive = "HKCU", RegistryView = "Default", RegistryKey = runPath, RegistryValueName = name,
                RegistryValueKind = (int)RegistryValueKind.String,
                OriginalFileIdentity = file.ExpectedFileIdentity, OriginalParentIdentity = file.ExpectedParentIdentity
            };
            await BrokerEngine.VerifyUserRiskRecordedContentAsync(registryRecord, new() { Records = [registryRecord] }, CancellationToken.None);
            Check("Modes interrupted cleanup can validate still-present source for rollback", File.Exists(path));
            await BrokerEngine.RestoreUserRiskRegistryValueAsync(registryRecord, CancellationToken.None);
            key.DeleteValue(name);
            await BrokerEngine.RestoreUserRiskRegistryValueAsync(registryRecord, CancellationToken.None);
            await BrokerEngine.RestoreUserRiskRegistryValueAsync(registryRecord, CancellationToken.None);
            Check("Modes interrupted startup restoration is idempotent", key.GetValue(name) as string == command);
            key.SetValue(name, "different user value");
            bool registryChanged = false;
            try { await BrokerEngine.RestoreUserRiskRegistryValueAsync(registryRecord, CancellationToken.None); } catch (InvalidDataException) { registryChanged = true; }
            Check("Modes startup restoration preserves later user value", registryChanged &&
                key.GetValue(name) as string == "different user value");
            key.SetValue(name, command);
            await File.AppendAllTextAsync(path, "changed");
            bool changedDenied = false;
            try { await BrokerEngine.VerifyUserRiskRecordedContentAsync(registryRecord, new() { Records = [registryRecord] }, CancellationToken.None); }
            catch (InvalidDataException) { changedDenied = true; }
            Check("Modes startup rollback rejects changed source", changedDenied);
            key.DeleteValue(name);
            bool lateSourceChanged = false;
            try { await BrokerEngine.RestoreUserRiskRegistryValueAsync(registryRecord, CancellationToken.None); } catch (InvalidDataException) { lateSourceChanged = true; }
            Check("Modes startup write independently rejects a source changed after preview", lateSourceChanged && key.GetValue(name) is null);
            await File.WriteAllTextAsync(path, contents);
        }
        finally { key.DeleteValue(name, throwOnMissingValue: false); }

        plan = await builder.BuildAsync([weak], false, remediationMode: RemediationMode.Aggressive);
        file = plan.Actions.Single();
        BrokerEngine engine = new(new FixtureTrustStore(null), new FixtureIncidentStateSecurity());
        RemediationRunResult refused = await engine.ExecuteAsync(plan);
        Check("Modes raw aggressive request has no execution authority", refused.Disposition == RemediationRunDisposition.NotStarted && File.Exists(path));
        using WindowsIdentity user = WindowsIdentity.GetCurrent();
        if (!new WindowsPrincipal(user).IsInRole(WindowsBuiltInRole.Administrator)) return;
        BrokerFileScopeAuthorization prepared = (await engine.PrepareForConfirmationAsync(plan))!;
        Check("Modes read-only preview grants no execution authority", ScopeRejects(() => engine.ValidateBeforeExecution(plan)) && File.Exists(path));
        engine.ConfirmFileTargets(plan, prepared); engine.ValidateBeforeExecution(plan); prepared.BeginExecution(plan);
        string backup = Path.Combine(directory, "selected.quarantined"); bool persisted = false;
        QuarantineRecord record = await BrokerEngine.QuarantineExplicitFileAsync(file, prepared, backup,
            (entry, _) => { persisted = entry.UserSelectedRisk && File.Exists(path); return Task.CompletedTask; }, ScopeProtectPayload, CancellationToken.None);
        Check("Modes user-selected file quarantines with saved attribution and metadata", persisted && record.UserSelectedRisk && record.ExplicitFileAuthorization &&
            !File.Exists(path) && File.Exists(backup));
        await BrokerEngine.RestoreUserRiskFileAsync(record, CancellationToken.None);
        await BrokerEngine.RestoreUserRiskFileAsync(record, CancellationToken.None);
        Check("Modes user-selected file restores from exact backup", File.Exists(path) && !File.Exists(backup) && await File.ReadAllTextAsync(path) == contents);
        await File.AppendAllTextAsync(path, " changed after review");
        bool restoreChanged = false;
        try { await BrokerEngine.RestoreUserRiskFileAsync(record, CancellationToken.None); } catch (InvalidDataException) { restoreChanged = true; }
        Check("Modes rollback does not overwrite a changed selected file", restoreChanged && (await File.ReadAllTextAsync(path)).EndsWith("changed after review"));
        bool stale = false;
        try { await builder.BuildAsync([weak], false, remediationMode: RemediationMode.Aggressive); }
        catch (InvalidDataException) { stale = true; }
        Check("Modes stale scanned target refused", stale);
    }
}
