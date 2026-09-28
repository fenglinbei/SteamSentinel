using System.IO;
using SteamSentinel.Core.Models;
using SteamSentinel.Core.Scanning;
using SteamSentinel.Core.Utilities;

namespace SteamSentinel.SelfTest;

internal static partial class Program
{
    private static async Task TestV030FalsePositiveScriptConsumersAsync(string root)
    {
        string directory = Path.Combine(root, "v030-false-positive-script-consumers");
        Directory.CreateDirectory(directory);
        string target = Path.Combine(directory, "never-created-tool.exe");
        string normal = Path.Combine(directory, "normal.lnk");
        string quoted = Path.Combine(directory, "quoted-tokens.lnk");
        // Inert LNK bytes are read by the scanner only. The target never exists and no link is opened.
        const string quotedTokens = "--help \"captcha https://example.invalid/docs wscript\" token=fixture-private-value";
        await File.WriteAllBytesAsync(normal, CreateBoundedShortcut(target, "--open https://example.invalid/docs"));
        await File.WriteAllBytesAsync(quoted, CreateBoundedShortcut(target, quotedTokens));
        ScanReport normalReport = await ScanV030FormatFixtureAsync(normal, new RuleSet());
        Check("0.3.0 普通快捷方式 URL 不触发脚本词组合告警",
            normalReport.Findings.All(f => f.RuleId != "SHORTCUT-EXECUTION-CHAIN"));
        ScanReport quotedReport = await ScanV030FormatFixtureAsync(quoted, new RuleSet());
        Finding shortcut = quotedReport.Findings.Single(f => f.RuleId == "SHORTCUT-EXECUTION-CHAIN");
        Check("0.3.0 快捷方式引用词组合仅为中风险待复核且不能隔离",
            shortcut is
            {
                Severity: FindingSeverity.Medium, Score: 40, IsKnownMalware: false,
                CanRemediate: false, ReasonCode: "ScriptTokenCooccurrenceOnly",
                HandlingReason: FindingHandlingReason.InsufficientEvidence
            } &&
            shortcut.SuggestedActions.SequenceEqual([SuggestedActionKind.ReviewOnly]) &&
            shortcut.Target == quoted && shortcut.TargetSha256 == await Hashing.Sha256FileAsync(quoted));
        Check("0.3.0 快捷方式弱证据脱敏且保留可翻译说明",
            !shortcut.Evidence.Contains("fixture-private-value", StringComparison.Ordinal) &&
            shortcut.DescriptionMessage is not null && shortcut.HandlingDetailsMessage is not null);

        string knownHash = await Hashing.Sha256FileAsync(quoted);
        RuleSet knownRules = new()
        {
            KnownHashes = [new()
        {
            Id = "TEST-SHORTCUT-EXACT-HASH", Sha256 = knownHash, Malware = true,
            Label = "Inert shortcut identity fixture", Severity = FindingSeverity.Critical
        }]
        };
        ScanReport known = await ScanV030FormatFixtureAsync(quoted, knownRules);
        Check("0.3.0 快捷方式弱信号降级不抑制独立精确恶意哈希",
            known.Findings.Any(f => f.RuleId == "TEST-SHORTCUT-EXACT-HASH" &&
                f.Severity == FindingSeverity.Critical && f.IsKnownMalware && f.CanRemediate &&
                f.Sha256 == knownHash && f.SuggestedActions.Contains(SuggestedActionKind.QuarantineFile)));

        Check("0.3.0 普通运行历史不产生脚本词组合告警",
            RelatedArtifactScanner.CreateHistoryFinding("a", "https://example.invalid/docs") is null);
        Finding history = RelatedArtifactScanner.CreateHistoryFinding("b", quotedTokens)!;
        Check("0.3.0 运行历史引用词组合仅为中风险且不证明执行",
            history is
            {
                RuleId: "HISTORY-CLICKFIX", Severity: FindingSeverity.Medium, Score: 40,
                IsKnownMalware: false, CanRemediate: false, ReasonCode: "ScriptTokenCooccurrenceOnly",
                HandlingReason: FindingHandlingReason.InsufficientEvidence
            } && history.Target == "RunMRU/b" &&
            history.SuggestedActions.SequenceEqual([SuggestedActionKind.ReviewOnly]) &&
            !history.Evidence.Contains("fixture-private-value", StringComparison.Ordinal) &&
            history.HandlingDetailsMessage is not null);
        Check("0.3.0 脚本消费者回归只读快捷方式且不创建运行目标",
            File.Exists(normal) && File.Exists(quoted) && !File.Exists(target));
    }
}
