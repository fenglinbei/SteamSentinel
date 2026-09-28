using SteamSentinel.Core.Reporting;
using SteamSentinel.Core.Models;

namespace SteamSentinel.App.Services;

internal static class ScanFailureReports
{
    internal static ScanReport PreserveSystemStage(ScanReport? checkpoint, ScanMode mode,
        string rulesVersion, Exception failure, bool cancelled)
    {
        ScanReport report = checkpoint ?? new() { Mode = mode, RuleSetVersion = rulesVersion };
        report.Coverage = ScanCoverage.Partial;
        report.CompletedAtUtc = DateTimeOffset.UtcNow;
        ScanExecution.Set(report, cancelled ? ScanExecutionState.Cancelled : ScanExecutionState.Failed,
            cancelled ? ReasonCodes.UserCancelled : failure is WorkerFailureException wf ? wf.ReasonCode : ReasonCodes.ForFailureType(failure.GetType().Name));
        report.Findings.Add(new()
        {
            RuleId = "SYSTEM-SCAN-INCOMPLETE",
            ReasonCode = ReasonCodes.SystemIncomplete,
            Category = FindingCategory.Coverage,
            Severity = FindingSeverity.Information,
            TitleText = cancelled ? MessageText.Create("ScanFailureReports.PreserveSystemStage.01") : MessageText.Create("ScanFailureReports.PreserveSystemStage.02"),
            TargetText = MessageText.Create("ScanFailureReports.PreserveSystemStage.03"),
            DescriptionText = MessageText.Create("ScanFailureReports.PreserveSystemStage.04"),
            EvidenceText = WorkerFailureException.Limit(MessageExceptions.Describe(failure)),
            HandlingReason = FindingHandlingReason.IncompleteInspection
        });
        return report;
    }

    internal static async Task CollectSupplementAsync(ScanReport completed, Func<Task> collect)
    {
        try { await collect(); }
        catch (Exception ex)
        {
            // A failed optional probe must not replace already completed content findings.
            completed.Coverage = ScanCoverage.Partial;
            completed.AddCoverageNote(MessageText.Create("ScanFailureReports.CollectSupplementAsync.01"));
            completed.Findings.Add(new Finding
            {
                RuleId = "PROTECTION-SUPPLEMENT-INCOMPLETE",
                Category = FindingCategory.Coverage,
                Severity = FindingSeverity.Information,
                TitleText = MessageText.Create("ScanFailureReports.CollectSupplementAsync.02"),
                DescriptionText = MessageText.Create("ScanFailureReports.CollectSupplementAsync.03"),
                EvidenceText = WorkerFailureException.Limit(MessageExceptions.Describe(ex))
            });
            AppErrorLog.Write("ProtectionSupplement", ex);
        }
    }

    internal static ScanReport PreserveSystemResults(ScanReport? systemReport, ScanMode mode,
        IReadOnlyList<string> customRoots, string rulesVersion, Exception failure, bool cancelled)
    {
        bool beforeScan = failure is WorkerFailureException { BeforeScan: true };
        MessageText title = cancelled ? MessageText.Create("ScanFailureReports.PreserveSystemResults.01") : beforeScan ? MessageText.Create("ScanFailureReports.PreserveSystemResults.02") : MessageText.Create("ScanFailureReports.PreserveSystemResults.03");
        MessageText detail = WorkerFailureException.Limit(MessageExceptions.Describe(failure));
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
        ScanExecution.Set(report, cancelled ? ScanExecutionState.Cancelled : ScanExecutionState.Failed,
            cancelled ? ReasonCodes.UserCancelled : failure is WorkerFailureException wf ? wf.ReasonCode : ReasonCodes.ForFailureType(failure.GetType().Name));
        MessageText explanation = partial is not null && (partial.Metrics.FilesVisited > 0 || partial.Findings.Count > 0)
            ? MessageText.Create("ScanFailureReports.PreserveSystemResults.04")
            : systemReport is null
            ? MessageText.Create("ScanFailureReports.PreserveSystemResults.05")
            : MessageText.Create("ScanFailureReports.PreserveSystemResults.06");
        report.AddCoverageNote(MessageText.Create("Common.Sentences", title, explanation));
        report.Findings.Add(new Finding
        {
            RuleId = cancelled ? "CONTENT-SCAN-CANCELLED" : "CONTENT-SCAN-FAILED",
            ReasonCode = report.ExecutionReasonCode,
            Category = FindingCategory.Coverage,
            Severity = FindingSeverity.Medium,
            TitleText = title,
            DescriptionText = explanation,
            TargetText = mode == ScanMode.Custom ? MessageText.Create("ScanFailureReports.PreserveSystemResults.07") : MessageText.Create("ScanFailureReports.PreserveSystemResults.08"),
            EvidenceText = detail,
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
