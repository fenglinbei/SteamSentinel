using System.IO;
using SteamSentinel.App.ViewModels;
using SteamSentinel.Core.Models;
using SteamSentinel.Core.Remediation;
using SteamSentinel.Core.Scanning;
using SteamSentinel.Core.Utilities;

namespace SteamSentinel.SelfTest;

internal static partial class Program
{
    private static async Task TestV030FalsePositiveAssociationAsync(string root)
    {
        string directory = Path.Combine(root, "v030-false-positive-association");
        Directory.CreateDirectory(directory);
        string component = Path.Combine(directory, "inert-component.txt");
        string host = Path.Combine(directory, "inert-host.txt");
        await File.WriteAllTextAsync(component, "Inert component identity. Never loaded or executed.");
        await File.WriteAllTextAsync(host, "Inert host identity. No process is started.");
        string hash = await Hashing.Sha256FileAsync(component);
        string hostHash = await Hashing.Sha256FileAsync(host);
        DateTimeOffset start = DateTimeOffset.UnixEpoch;

        Finding Source(string rule, bool actionable, int score = 90, FindingSeverity severity = FindingSeverity.High,
            string? expectedHash = null, bool claimedKnown = false, string? reasonCode = null) => new()
        {
            RuleId = rule,
            Category = FindingCategory.File,
            Target = component,
            ContentPath = component,
            Sha256 = expectedHash ?? hash,
            TargetSha256 = expectedHash ?? hash,
            Severity = severity,
            Score = score,
            ReasonCode = reasonCode,
            IsKnownMalware = claimedKnown,
            CanRemediate = actionable,
            SuggestedActions = actionable ? [SuggestedActionKind.QuarantineFile] : [SuggestedActionKind.ReviewOnly]
        };

        foreach (string rule in new[] { "HEUR-STEAM-DEPLOYMENT-CHAIN", "HEUR-SCRIPT-TOKEN-COOCCURRENCE",
            "INSTALLER-STRUCTURE", "SHORTCUT-EXECUTION-CHAIN", "HISTORY-CLICKFIX" })
        {
            RelatedArtifactScanner scanner = new(new RuleSet());
            // Legacy action flags and even a claimed malware flag are not a known-hash match.
            Finding old = Source(rule, true, 100, FindingSeverity.High, claimedKnown: true);
            Finding current = scanner.RegisterVerifiedFileFinding(component, hash, old)!;
            Check("0.3 弱字符串证据不能从历史分数恢复隔离 " + rule,
                !current.CanRemediate && !current.IsKnownMalware && current.Severity == FindingSeverity.Medium &&
                current.ReasonCode == "ScriptTokenCooccurrenceOnly" &&
                current.SuggestedActions.SequenceEqual([SuggestedActionKind.ReviewOnly]));
            Check("0.3 退役弱规则不能进入文件证据闭包 " + rule, !RelatedArtifactRelations.IsFileEvidence(old));
            Check("0.3 关联复核不改写历史告警 " + rule,
                old.CanRemediate && old.IsKnownMalware && old.Score == 100 && old.Severity == FindingSeverity.High &&
                old.SuggestedActions.SequenceEqual([SuggestedActionKind.QuarantineFile]));

            Finding[] hosts = Enumerable.Range(1, 13).Select(pid =>
                scanner.CreateProcessAssociation(host, hostHash, component, hash, pid, start)!).ToArray();
            Check("0.3 同一弱DLL的13个宿主不制造13条高危 " + rule,
                hosts.All(f => f is not null && f.RuleId == "PROCESS-RELATED-OBSERVATION" &&
                    f.Severity == FindingSeverity.Information && f.Score == 0 && !f.CanRemediate && !f.IsKnownMalware &&
                    f.AssociationEvidenceTier == RelatedEvidenceTier.Observation &&
                    f.RelatedFilePath == component && f.RelatedFileSha256 == hash &&
                    f.SuggestedActions.SequenceEqual([SuggestedActionKind.ReviewOnly])));
            Finding direct = scanner.CreateProcessAssociation(component, hash, component, hash, 20, start)!;
            Check("0.3 弱字符串直接映像也不得停止进程 " + rule,
                !direct.CanRemediate && direct.Severity == FindingSeverity.Information &&
                direct.SuggestedActions.SequenceEqual([SuggestedActionKind.ReviewOnly]));
        }

        RelatedArtifactScanner reviewScanner = new(new RuleSet());
        Finding review = Source("HEUR-SCRIPT-TOKEN-COOCCURRENCE", false, 40, FindingSeverity.Medium,
            reasonCode: RemediationEvidencePolicy.ReviewOnlyReasonCode);
        Finding reviewCurrent = reviewScanner.RegisterVerifiedFileFinding(component, hash, review)!;
        Finding reviewHost = reviewScanner.CreateProcessAssociation(host, hostHash, component, hash, 30, start)!;
        Check("0.3 新的只读告警仍保留精确诊断关联", !reviewCurrent.CanRemediate &&
            reviewHost.RelatedFileSha256 == hash && reviewHost.ReasonCode == "RelatedFileObservationOnly" &&
            !reviewHost.CanRemediate && reviewHost.ProcessStartedAtUtc == start);

        RelatedArtifactScanner identityScanner = new(new RuleSet());
        string changedHash = new('A', 64);
        Check("0.3 关联拒绝过期的组件哈希", identityScanner.RegisterVerifiedFileFinding(component, hash,
            Source("HEUR-SCRIPT-TOKEN-COOCCURRENCE", false, expectedHash: changedHash)) is null &&
            identityScanner.CreateProcessAssociation(host, hostHash, component, hash, 31, start) is null);
        identityScanner.RegisterVerifiedFileFinding(component, hash, review);
        Check("0.3 模块身份变化不沿用已核验观察", identityScanner.CreateProcessAssociation(host, hostHash,
            component, changedHash, 32, start) is null);
        Check("0.3 直接映像与组件身份必须一致", identityScanner.CreateProcessAssociation(component, hostHash,
            component, hash, 33, start) is null);

        foreach (string rule in new[] { "HEUR-STEAM-UI-PATCHER", "HEUR-STEAM-TOKEN-STEALER", "HEUR-STEAM-CREDENTIAL-PLUGIN" })
        {
            RelatedArtifactScanner scanner = new(new RuleSet());
            Finding strong = scanner.RegisterVerifiedFileFinding(component, hash, Source(rule, true))!;
            Finding direct = scanner.CreateProcessAssociation(component, hash, component, hash, 40, start)!;
            Finding loaded = scanner.CreateProcessAssociation(host, hostHash, component, hash, 41, start)!;
            Check("0.3 特定强证据保留直接映像防护 " + rule,
                strong.CanRemediate && direct.CanRemediate && direct.Severity == FindingSeverity.High &&
                direct.SuggestedActions.SequenceEqual([SuggestedActionKind.StopProcess]));
            Check("0.3 强启发式不冒称已确认恶意或任停宿主 " + rule,
                loaded.RuleId == "PROCESS-LOADED-COMPONENT" && loaded.Severity == FindingSeverity.High &&
                !loaded.IsKnownMalware && !loaded.CanRemediate && loaded.RelatedFileSha256 == hash &&
                loaded.SuggestedActions.SequenceEqual([SuggestedActionKind.ReviewOnly]));
        }

        RuleSet knownRules = new() { KnownHashes = [new() { Id = "INERT-KNOWN-HASH", Sha256 = hash, Malware = true }] };
        RelatedArtifactScanner knownScanner = new(knownRules);
        Finding confirmed = knownScanner.RegisterVerifiedFileFinding(component, hash, review)!;
        Finding confirmedHost = knownScanner.CreateProcessAssociation(host, hostHash, component, hash, 50, start)!;
        Finding confirmedDirect = knownScanner.CreateProcessAssociation(component, hash, component, hash, 51, start)!;
        Check("0.3 真正已确认哈希不因弱规则标签失去防护", confirmed.IsKnownMalware && confirmed.CanRemediate &&
            confirmed.Severity == FindingSeverity.Critical && confirmedHost.RuleId == "PROCESS-LOADED-MALWARE" &&
            confirmedHost.IsKnownMalware && confirmedHost.CanRemediate && confirmedHost.Severity == FindingSeverity.Critical &&
            confirmedHost.RelatedFilePath == component && confirmedHost.RelatedFileSha256 == hash &&
            confirmedHost.Sha256 == hostHash && confirmedHost.SuggestedActions.SequenceEqual([SuggestedActionKind.StopHostProcess]) &&
            confirmedDirect.SuggestedActions.SequenceEqual([SuggestedActionKind.StopProcess]));
        FindingItemViewModel confirmedItem = new(confirmed);
        RemediationPlan confirmedPlan = await new RemediationPlanBuilder(knownRules).BuildAsync([confirmed], false);
        Check("0.3 独立恶意哈希替换弱来源标签与原因且可通过实际资格入口",
            confirmed.RuleId == "INERT-KNOWN-HASH" && confirmed.ReasonCode is null && confirmed.ContentPath == component &&
            RemediationEvidencePolicy.CanRemediate(confirmed) && confirmedItem.CanSelect && confirmedItem.IsSelected &&
            confirmedPlan.Actions.Count == 1 && confirmedPlan.Actions[0].Type == RemediationActionType.QuarantineFile &&
            confirmedPlan.Actions[0].ExpectedSha256 == hash && File.Exists(component));
        Check("0.3 独立哈希资格不重写旧词共现报告", review.RuleId == "HEUR-SCRIPT-TOKEN-COOCCURRENCE" &&
            review.ReasonCode == RemediationEvidencePolicy.ReviewOnlyReasonCode && !review.CanRemediate);

        Finding taggedStrong = Source("HEUR-STEAM-UI-PATCHER", true, reasonCode: RemediationEvidencePolicy.ReviewOnlyReasonCode);
        RelatedArtifactScanner taggedScanner = new(new RuleSet());
        Finding taggedCurrent = taggedScanner.RegisterVerifiedFileFinding(component, hash, taggedStrong)!;
        Finding taggedProcess = taggedScanner.CreateProcessAssociation(component, hash, component, hash, 52, start)!;
        Check("0.3 强规则ID不能覆盖显式弱证据原因码以派生停止动作", !taggedCurrent.CanRemediate &&
            !RelatedArtifactRelations.SupportsHeuristicEntry(taggedStrong) && !taggedProcess.CanRemediate &&
            taggedProcess.RuleId == "PROCESS-RELATED-OBSERVATION");

        Finding weakRun = new()
        {
            RuleId = "PERSISTENCE-RUN-BOUND", ReasonCode = RemediationEvidencePolicy.ReviewOnlyReasonCode,
            CanRemediate = true, Target = "unchanged inert command", RegistryHive = "HKCU", RegistryView = "Default",
            RegistryKey = @"Software\Microsoft\Windows\CurrentVersion\Run", RegistryValueName = "InertAllowedEntry",
            SuggestedActions = [SuggestedActionKind.RemoveRegistryValue]
        };
        Finding freshRun = new()
        {
            Target = weakRun.Target, RegistryHive = weakRun.RegistryHive, RegistryView = weakRun.RegistryView,
            RegistryKey = weakRun.RegistryKey, RegistryValueName = weakRun.RegistryValueName
        };
        RelatedArtifactScanner allowlistedScanner = new(new RuleSet { KnownRunValueNames = ["InertAllowedEntry"] });
        Check("0.3 旧弱原因码不被同名启动项快照保留逻辑洗去", allowlistedScanner.PreserveAllowlistedSnapshot(weakRun, freshRun) is null &&
            weakRun.ReasonCode == RemediationEvidencePolicy.ReviewOnlyReasonCode && weakRun.CanRemediate);

        RelatedArtifactScanner nonMalwareHashScanner = new(new RuleSet
        { KnownHashes = [new() { Id = "INERT-NONMALWARE-HASH", Sha256 = hash, Malware = false }] });
        Finding nonMalware = nonMalwareHashScanner.RegisterVerifiedFileFinding(component, hash, review)!;
        Check("0.3 非恶意哈希规则不能把弱证据变成可隔离", !nonMalware.IsKnownMalware && !nonMalware.CanRemediate);

        RelatedArtifactScanner configScanner = new(new RuleSet());
        Finding config = configScanner.RegisterVerifiedFileFinding(component, hash,
            Source("STEAM-CFG-UPDATE-SUPPRESSION-PAIR", true, 85))!;
        Finding configHost = configScanner.CreateProcessAssociation(host, hostHash, component, hash, 60, start)!;
        Check("0.3 独立配置处置保留但装载关系不自动升级高危", config.CanRemediate &&
            configHost.Severity == FindingSeverity.Information && !configHost.CanRemediate);
    }
}
