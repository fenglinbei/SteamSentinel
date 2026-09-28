using System.IO;
using System.Text.Json;
using SteamSentinel.App.ViewModels;
using SteamSentinel.Core.Models;
using SteamSentinel.Core.Remediation;
using SteamSentinel.Core.Reporting;
using SteamSentinel.Core.Utilities;

namespace SteamSentinel.SelfTest;

internal static partial class Program
{
    private static async Task TestV030RemediationEvidencePolicyAsync(string root)
    {
        string[] retiredRules = ["HEUR-STEAM-DEPLOYMENT-CHAIN", "HEUR-SCRIPT-TOKEN-COOCCURRENCE",
            "INSTALLER-STRUCTURE", "SHORTCUT-EXECUTION-CHAIN", "HISTORY-CLICKFIX"];
        foreach (string rule in retiredRules)
        {
            Finding legacy = new()
            {
                RuleId = rule, Category = FindingCategory.File, Severity = FindingSeverity.High,
                Score = 100, IsKnownMalware = true, CanRemediate = true,
                Target = Path.Combine(root, "missing-token-evidence-fixture.bin"), Sha256 = new string('A', 64),
                Evidence = "Unchanged historical text", SuggestedActions = [SuggestedActionKind.QuarantineFile]
            };
            string original = JsonSerializer.Serialize(legacy, JsonFile.Options);
            Finding received = JsonSerializer.Deserialize<Finding>(original, JsonFile.Options)!;
            Check("0.3.0 弱证据旧规则不被分数或恶意标志重新授权 " + rule,
                RemediationEvidencePolicy.IsReviewOnlyEvidence(received) && !RemediationEvidencePolicy.CanRemediate(received));
            FindingItemViewModel item = new(received);
            item.IsSelected = true;
            Check("0.3.0 历史弱项不可默认预选或再次选中 " + rule,
                !item.CanSelect && !item.IsSelected && item.Handling.Disposition == FindingDisposition.NeedsReview);
            RemediationEvidenceException? refusal = null;
            try { await new RemediationPlanBuilder(new()).BuildAsync([received], false, allFindings: [received]); }
            catch (RemediationEvidenceException ex) { refusal = ex; }
            Check("0.3.0 弱证据计划明确拒绝且先于文件读取 " + rule, refusal is not null &&
                refusal.ReasonCode == RemediationEvidencePolicy.ReviewOnlyReasonCode &&
                MessageExceptions.Describe(refusal).Message?.MessageId == RemediationEvidencePolicy.ReviewOnlyMessageId);
            Check("0.3.0 旧报告资格检查不重写历史JSON " + rule,
                JsonSerializer.Serialize(received, JsonFile.Options) == original && received.CanRemediate && received.Score == 100);
        }

        Finding tagged = new()
        {
            RuleId = "FUTURE-OR-FORGED-ID", ReasonCode = RemediationEvidencePolicy.ReviewOnlyReasonCode,
            CanRemediate = true, Score = 100, IsKnownMalware = true,
            SuggestedActions = [SuggestedActionKind.QuarantineFile]
        };
        Check("0.3.0 弱证据稳定原因码独立阻止伪装规则ID", !RemediationEvidencePolicy.CanRemediate(tagged));
        bool reasonRejected = false;
        try { await new RemediationPlanBuilder(new()).BuildAsync([tagged], false); }
        catch (RemediationEvidenceException) { reasonRejected = true; }
        Check("0.3.0 弱证据原因码不能构建新计划", reasonRejected);

        Finding review = new()
        {
            RuleId = "HEUR-SCRIPT-TOKEN-COOCCURRENCE", CanRemediate = false,
            SuggestedActions = [SuggestedActionKind.ReviewOnly]
        };
        bool reviewRejected = false;
        try { await new RemediationPlanBuilder(new()).BuildAsync([review], false); }
        catch (RemediationEvidenceException) { reviewRejected = true; }
        Check("0.3.0 显式传入复核项不会静默生成空计划", reviewRejected);

        foreach (Finding weak in new[] { tagged, review })
        {
            string before = JsonSerializer.Serialize(weak, JsonFile.Options);
            int inspections = 0;
            RuleSet domainRules = new() { KnownDomains = ["inert.example.invalid"] };
            RemediationBatchSession denied = await new RemediationBatchPlanner(domainRules).PrepareAsync([weak],
                new() { Findings = [weak] }, true, (_, _) => { inspections++; return Task.FromResult(new ScanReport()); });
            Check("0.3.0 弱项批次不触发补查或独立域名动作 " + weak.RuleId,
                denied.SelectedFindingCount == 1 && denied.Plans.Count == 0 && inspections == 0);
            Check("0.3.0 弱项批次保留未纳入目标与稳定原因 " + weak.RuleId,
                denied.Targets.Count == 1 && denied.Targets[0].State == RemediationTargetState.NotIncluded &&
                denied.PreparationNotes.Any(note => note.ReasonCode == ReasonCodes.ActionsNotIncluded &&
                    note.DetailText.Message?.MessageId == RemediationEvidencePolicy.ReviewOnlyMessageId));
            Check("0.3.0 批次拒绝不重写原报告 " + weak.RuleId, JsonSerializer.Serialize(weak, JsonFile.Options) == before);
        }

        foreach (string rule in new[] { "HEUR-STEAM-UI-PATCHER", "HEUR-STEAM-TOKEN-STEALER",
            "HEUR-STEAM-CREDENTIAL-PLUGIN", "HEUR-ENCRYPTED-PYTHON-LOADER", "KNOWN-HASH-FIXTURE" })
        {
            Finding supported = new() { RuleId = rule, CanRemediate = true };
            Check("0.3.0 弱证据拒绝集不替换既有强规则资格 " + rule, RemediationEvidencePolicy.CanRemediate(supported));
        }
        Check("0.3.0 家族复核项不会被共享策略升级", !RemediationEvidencePolicy.CanRemediate(new()
        { RuleId = "VPET-FAMILY-STRUCTURE", CanRemediate = false, Score = 90 }));

        Finding excessive = new()
        {
            RuleId = new string('X', 5000) + "\nprivate command", ReasonCode = RemediationEvidencePolicy.ReviewOnlyReasonCode
        };
        MessageText bounded = RemediationEvidencePolicy.ReviewOnlyMessage(excessive);
        Check("0.3.0 弱证据拒绝说明有界且只含规则标识", bounded.Message?.Arguments is { Count: 1 } arguments &&
            arguments[0].OriginalText.Length == 96 && !arguments[0].OriginalText.Contains('\n'));
        bounded.Message!.Validate();

        string file = Path.Combine(root, "known-hash-policy-fixture.bin");
        await File.WriteAllTextAsync(file, "inert independently hash-bound fixture");
        string hash = await Hashing.Sha256FileAsync(file);
        RuleSet rules = new() { KnownHashes = [new() { Id = "KNOWN-HASH-FIXTURE", Sha256 = hash, Malware = true }] };
        Finding known = new()
        {
            RuleId = "KNOWN-HASH-FIXTURE", Target = file, Sha256 = hash, TargetSha256 = hash,
            CanRemediate = true, IsKnownMalware = true, Score = 100, SuggestedActions = [SuggestedActionKind.QuarantineFile]
        };
        RemediationPlan plan = await new RemediationPlanBuilder(rules).BuildAsync([known], false);
        Check("0.3.0 精确已知哈希仍可准备文件隔离且不执行动作", plan.Actions.Count == 1 &&
            plan.Actions[0].Type == RemediationActionType.QuarantineFile && plan.Actions[0].ExpectedSha256 == hash && File.Exists(file));
        bool mixedRejected = false;
        try { await new RemediationPlanBuilder(rules).BuildAsync([known, tagged], false); }
        catch (RemediationEvidenceException) { mixedRejected = true; }
        Check("0.3.0 混选弱项不静默丢弃后返回部分计划", mixedRejected && File.Exists(file));
    }
}
