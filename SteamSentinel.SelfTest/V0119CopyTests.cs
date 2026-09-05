using SteamSentinel.Core.Models;
using SteamSentinel.Core.Reporting;

namespace SteamSentinel.SelfTest;

internal static partial class Program
{
    // Pure Core presentation checks: no WPF, filesystem, scanner, or remediation calls.
    private static void TestV0119Copy()
    {
        Check("0.1.19 补查动作明确所选内容而非承诺覆盖", CoveragePresentation.FullScanAction == "使用完整内容扫描补查所选内容");
        Check("0.1.19 完整扫描说明保留勾选压缩检查及未完成限制", new[]
        {
            "本次所选范围", "不是全盘扫描", "勾选“递归检查压缩包”", "正确密码", "访问权限不足", "文件损坏", "格式不支持", "安全上限", "仍可能无法完成全部检查"
        }.All(CoveragePresentation.FullScope.Contains));
        Check("0.1.19 快速扫描说明仍明确不是全盘扫描", CoveragePresentation.QuickScope.Contains("不是全盘扫描"));

        CoverageEntry restricted = CoveragePresentation.Describe("READ-INERT", "仅文案示例", "拒绝访问");
        Check("0.1.19 范围说明不承诺完整扫描能解决权限问题", restricted.Kind == "读取受限或其他检查范围说明" &&
            !restricted.CanFullScan && restricted.NextStep.Contains("不一定能补齐"));
        Check("0.1.19 改文案不改变支持补查的规则分支", new[]
        {
            "QUICK-MEDIA-STRUCTURE", "QUICK-CONTENT-NOT-HASHED", "QUICK-FILE-SIZE", "CONTENT-BYTE-BUDGET",
            "ARCHIVE-NOT-REQUESTED", "COMPOUND-CONTENT-NOT-EXPANDED", "ARCHIVE-PASSWORD-FAILED",
            "ARCHIVE-ENCRYPTED-NOT-SCANNED", "ARCHIVE-ENCRYPTED-DEFERRED"
        }.All(rule => CoveragePresentation.Describe(rule, "仅文案示例", string.Empty) is { CanFullScan: true }));
        Check("0.1.19 安全上限失败和AMSI不可用仍不承诺自动补齐", new[]
        {
            CoveragePresentation.Describe("CONTENT-SCAN-FAILED", "仅文案示例", "ScanResourceLimitException"),
            CoveragePresentation.Describe("CONTENT-SCAN-FAILED", "仅文案示例", "OutOfMemoryException"),
            CoveragePresentation.Describe("CONTENT-SCAN-CANCELLED", "仅文案示例", string.Empty),
            CoveragePresentation.Describe("ARCHIVE-RATIO-LIMIT", "仅文案示例", "压缩比超过上限"),
            CoveragePresentation.Describe("AMSI-INERT", "仅文案示例", "AMSI 不可用")
        }.All(entry => !entry.CanFullScan));

        Finding policyBlocked = new()
        {
            Severity = FindingSeverity.Critical,
            IsKnownMalware = false,
            Description = "策略阻止不等同于已确认病毒。"
        };
        Check("0.1.19 严重度标签不会把安全策略阻止标成已确认病毒", !policyBlocked.IsKnownMalware &&
            ReportExporter.SeverityLabel(policyBlocked.Severity) == "严重");
        Check("0.1.19 完整检查标签仍限定本次范围", ReportExporter.CoverageLabel(ScanCoverage.Complete) == "已完成本次范围内的检查");
        Check("0.1.19 部分检查标签明确未检查或未做完整比对", ReportExporter.CoverageLabel(ScanCoverage.Partial) == "部分内容未检查或未做完整比对");
        Check("0.1.19 跳过检查标签明确本次未执行", ReportExporter.CoverageLabel(ScanCoverage.Skipped) == "本次未执行检查");
        Check("0.1.19 覆盖分类显示为检查范围说明", ReportExporter.CategoryLabel(FindingCategory.Coverage) == "检查范围说明");

        DateTimeOffset ended = new(2026, 9, 5, 0, 0, 0, TimeSpan.Zero);
        Check("0.1.19 未结束扫描不会因默认Complete显示已完成", new ScanReport().ExecutionStatus == "尚未结束");
        Check("0.1.19 完整扫描结束状态不附加不存在的未检查内容", new ScanReport { CompletedAtUtc = ended, Coverage = ScanCoverage.Complete }.ExecutionStatus == "本次扫描已完成");
        Check("0.1.19 部分扫描结束状态保留未检查提示", new ScanReport { CompletedAtUtc = ended, Coverage = ScanCoverage.Partial }.ExecutionStatus == "本次扫描已结束，仍有未检查内容");
        Check("0.1.19 跳过扫描不能显示全部完成", new ScanReport { CompletedAtUtc = ended, Coverage = ScanCoverage.Skipped }.ExecutionStatus == "本次扫描已结束，仍有未检查内容");
        Check("0.1.19 内容失败状态继续优先于完成时间和完整性", new ScanReport
        {
            CompletedAtUtc = ended,
            Coverage = ScanCoverage.Complete,
            Findings = [new() { RuleId = "CONTENT-SCAN-FAILED" }]
        }.ExecutionStatus == "内容检查失败，已保留可用结果");
        Check("0.1.19 取消状态继续优先于完成时间和完整性", new ScanReport
        {
            CompletedAtUtc = ended,
            Coverage = ScanCoverage.Complete,
            CoverageNotes = ["用户取消了扫描"]
        }.ExecutionStatus == "扫描已取消，已保留可用结果");
    }
}
