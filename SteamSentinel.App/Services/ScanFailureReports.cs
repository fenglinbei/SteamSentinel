using SteamSentinel.Core.Models;

namespace SteamSentinel.App.Services;

internal static class ScanFailureReports
{
    internal static async Task CollectSupplementAsync(ScanReport completed, Func<Task> collect)
    {
        try { await collect(); }
        catch (Exception ex)
        {
            // A failed optional probe must not replace already completed content findings.
            completed.Coverage = ScanCoverage.Partial;
            completed.CoverageNotes.Add("补充安全配置检查未完成，已保留系统与内容扫描结果。");
            completed.Findings.Add(new Finding
            {
                RuleId = "PROTECTION-SUPPLEMENT-INCOMPLETE",
                Category = FindingCategory.Coverage,
                Severity = FindingSeverity.Information,
                Title = "补充安全配置检查未完成",
                Description = "已完成的内容结果保持不变，此报告不能作为完整复扫。",
                Evidence = WorkerFailureException.Limit(ex.Message)
            });
            AppErrorLog.Write("ProtectionSupplement", ex);
        }
    }

    internal static ScanReport PreserveSystemResults(ScanReport? systemReport, ScanMode mode,
        IReadOnlyList<string> customRoots, string rulesVersion, Exception failure, bool cancelled)
    {
        bool beforeScan = failure is WorkerFailureException { BeforeScan: true };
        string title = cancelled ? "内容扫描已取消" : beforeScan ? "内容扫描未能启动" : "内容扫描未能完成";
        string detail = WorkerFailureException.Limit(failure.Message);
        ScanReport report = systemReport ?? new ScanReport { Mode = mode, RuleSetVersion = rulesVersion };
        ScanReport? partial = failure switch
        {
            WorkerFailureException worker => worker.PartialReport,
            WorkerCancelledException worker => worker.PartialReport,
            _ => null
        };
        if (partial is not null) report = ScanReportMerger.Merge(report, partial);
        report.Coverage = ScanCoverage.Partial;
        report.CompletedAtUtc = DateTimeOffset.UtcNow;
        string explanation = partial is not null && (partial.Metrics.FilesVisited > 0 || partial.Findings.Count > 0)
            ? "已保留系统检查与扫描组件此前交回的内容结果，中断时正在处理的文件和其余内容仍未完成检查，不能作为完整复扫。"
            : systemReport is null
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
