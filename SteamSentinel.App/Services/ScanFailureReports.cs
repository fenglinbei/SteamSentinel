using SteamSentinel.Core.Models;

namespace SteamSentinel.App.Services;

internal static class ScanFailureReports
{
    internal static ScanReport PreserveSystemResults(ScanReport? systemReport, ScanMode mode,
        IReadOnlyList<string> customRoots, string rulesVersion, Exception failure, bool cancelled)
    {
        bool beforeScan = failure is WorkerFailureException { BeforeScan: true };
        string title = cancelled ? "内容扫描已取消" : beforeScan ? "内容扫描未能启动" : "内容扫描未能完成";
        string detail = WorkerFailureException.Limit(failure.Message);
        ScanReport report = systemReport ?? new ScanReport { Mode = mode, RuleSetVersion = rulesVersion };
        report.Coverage = ScanCoverage.Partial;
        report.CompletedAtUtc = DateTimeOffset.UtcNow;
        string explanation = systemReport is null
            ? "本次未取得可用的内容扫描结果，不能判断所选内容是否安全。"
            : "已保留系统与 Steam 只读检查结果，工坊与文件内容检查未完成，不能作为完整复扫。";
        report.CoverageNotes.Add(title + "。" + explanation);
        report.Findings.Add(new Finding
        {
            RuleId = cancelled ? "CONTENT-SCAN-CANCELLED" : "CONTENT-SCAN-FAILED",
            Category = FindingCategory.Coverage,
            Severity = FindingSeverity.Medium,
            Title = title,
            Description = explanation,
            Target = mode == ScanMode.Custom ? "所选文件或目录" : "工坊与文件内容检查",
            Evidence = detail,
            CanRemediate = false
        });
        foreach (string root in customRoots.Distinct(StringComparer.OrdinalIgnoreCase))
        {
            if (!report.Roots.Contains(root, StringComparer.OrdinalIgnoreCase)) report.Roots.Add(root);
            report.RootSummaries.Add(new ScanRootSummary(root, ScanCoverage.Partial, 0, 0, 0));
        }
        return report;
    }
}
