using System.Globalization;
using System.IO;
using System.Reflection;
using System.Text.Json;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using SteamSentinel.App;
using SteamSentinel.Core.Models;
using SteamSentinel.Core.Reporting;
using SteamSentinel.Core.Utilities;

namespace SteamSentinel.SelfTest;

internal static partial class Program
{
    private const BindingFlags SummaryPrivate = BindingFlags.Instance | BindingFlags.NonPublic;
    private static string PartialSafeTitle => UiExpected("已完成部分检查，未发现需处理的风险", "Checks incomplete; no actionable risk found");
    private static string CompleteSafeTitle => UiExpected("本次检查已完成，未发现需处理的风险", "Checks complete; no actionable risk found");
    private static string SkippedScanTitle => UiExpected("本次未执行检查，无法判断风险", "No checks ran; risk cannot be assessed");
    private static string QuickPartialGuidance => UiExpected("仍有未检查内容，若要完整排查，请使用完整内容扫描，并按需勾选额外的检查内容。", "Some content remains unchecked. For broader coverage, use a full content scan and select additional scope options as needed.");

    private enum SummaryFindings { None, Information, Suspicious, Known, KnownWithHostEvidence }

    // Run on the existing layout suite's STA/Application. Every report and failure is synthetic.
    private static void TestV0119Summary(string? output)
    {
        ScanReport semanticTampering = new()
        {
            Findings = [new() { RuleId = "STEAM-UI-SEMANTIC-TAMPERING", Category = FindingCategory.Steam, Severity = FindingSeverity.High, CanRemediate = true }]
        };
        Check("UI 系统复查不把非已知恶意的篡改发现概括为无篡改证据",
            MainWindow.SystemFollowUpSummary(semanticTampering).Contains(UiExpected("未发现已知活动威胁", "No known active threats were found"), StringComparison.Ordinal) &&
            !MainWindow.SystemFollowUpSummary(semanticTampering).Contains(UiExpected("未发现已知威胁活动或篡改证据", "No known threat activity or tampering evidence was found"), StringComparison.Ordinal));
        MainWindow matrixWindow = new();
        try
        {
            foreach (ScanMode mode in Enum.GetValues<ScanMode>())
                foreach (ScanCoverage coverage in Enum.GetValues<ScanCoverage>())
                    foreach (SummaryFindings findings in Enum.GetValues<SummaryFindings>())
                    {
                        ScanReport report = CreateSummaryReport(mode, coverage, findings);
                        typeof(MainWindow).GetMethod("PopulateFindings", SummaryPrivate)!.Invoke(matrixWindow, [report]);
                        InvokeSummary(matrixWindow, report);
                        TextBlock title = SummaryText(matrixWindow, "HeaderStatusText");
                        TextBlock detail = SummaryText(matrixWindow, "HeaderDetailText");
                        TextBlock stage = SummaryText(matrixWindow, "ProgressStageText");
                        Check($"UI 摘要 {mode}/{coverage}/{findings} 结论与下一步保持准确",
                            title.Text == ExpectedSummaryTitle(coverage, findings) &&
                            SummaryDetailIsAccurate(mode, coverage, findings, detail.Text) &&
                            SummaryStageIsAccurate(coverage, stage.Text) &&
                            ((TabItem)matrixWindow.FindName("CoverageTab")).Header?.ToString() ==
                                (CoveragePresentation.Groups(report).Count > 0 ? (IsEnglishUi ? $"Unchecked ({CoveragePresentation.Groups(report).Count})" : $"未检查内容（{CoveragePresentation.Groups(report).Count} 类）") :
                                    coverage == ScanCoverage.Complete ? UiExpected("检查范围", "Coverage") : UiExpected("未检查内容", "Unchecked")));
                    }

            foreach (bool cancelled in new[] { false, true })
                foreach (SummaryFindings findings in new[]
                {
                    SummaryFindings.None, SummaryFindings.Information, SummaryFindings.Suspicious, SummaryFindings.Known
                })
                {
                    ScanReport previous = CreateSummaryReport(ScanMode.Quick, ScanCoverage.Complete, findings);
                    InvokeSummary(matrixWindow, previous);
                    typeof(MainWindow).GetMethod("PreserveScanFailure", SummaryPrivate)!.Invoke(matrixWindow,
                        [previous, ScanMode.Quick, Array.Empty<string>(),
                            new IOException("无害摘要回归：模拟工作进程中断，没有启动扫描。"), cancelled]);
                    string title = SummaryText(matrixWindow, "HeaderStatusText").Text;
                    string detail = SummaryText(matrixWindow, "HeaderDetailText").Text;
                    string stage = SummaryText(matrixWindow, "ProgressStageText").Text;
                    string expectedTitle = findings is SummaryFindings.Suspicious or SummaryFindings.Known
                        ? ExpectedSummaryTitle(ScanCoverage.Partial, findings)
                        : cancelled ? UiExpected("扫描已取消", "Scan cancelled") : UiExpected("扫描不完整", "Scan incomplete");
                    ScanReport retained = (ScanReport)typeof(MainWindow).GetField("_lastReport", SummaryPrivate)!.GetValue(matrixWindow)!;
                    Check($"UI 摘要 {(cancelled ? "取消" : UiExpected("失败", "failed"))}/{findings} 保留结果且覆盖安全结论",
                        title == expectedTitle && !title.Contains(UiExpected("未发现", "no actionable risk found"), StringComparison.Ordinal) &&
                        detail.Contains(UiExpected("已保留", "retained"), StringComparison.Ordinal) && detail.Contains(UiExpected("检查未完成", "checks are incomplete"), StringComparison.Ordinal) &&
                        stage == (cancelled ? UiExpected("扫描已取消", "Scan cancelled") : UiExpected("内容检查未完成", "Content checks incomplete")) &&
                        retained.Coverage == ScanCoverage.Partial &&
                        retained.Findings.Any(f => f.RuleId == (cancelled ? "CONTENT-SCAN-CANCELLED" : "CONTENT-SCAN-FAILED")) &&
                        ((Button)matrixWindow.FindName("ExportButton")).IsEnabled);
                }
        }
        finally { CloseSummaryFixture(matrixWindow); }

        List<object> snapshots = [];
        foreach ((int width, int height) in new[] { (1148, 780), (784, 460) })
            foreach (ScanMode mode in Enum.GetValues<ScanMode>())
            {
                MainWindow window = new();
                try
                {
                    using UiLayoutHarness layout = new(window, width, height);
                    ScanReport report = CreateSummaryReport(mode, ScanCoverage.Partial, SummaryFindings.Information);
                    typeof(MainWindow).GetField("_lastReport", SummaryPrivate)!.SetValue(window, report);
                    typeof(MainWindow).GetMethod("PopulateFindings", SummaryPrivate)!.Invoke(window, [report]);
                    InvokeSummary(window, report);
                    UiPreview.ApplyAccessState(window, InstallationSecurityStatus.Protected, new(true, true));
                    layout.Refresh();

                    TextBlock title = SummaryText(window, "HeaderStatusText");
                    TextBlock detail = SummaryText(window, "HeaderDetailText");
                    TextBlock stage = SummaryText(window, "ProgressStageText");
                    FormattedText measured = new(title.Text, CultureInfo.CurrentUICulture, title.FlowDirection,
                        new Typeface(title.FontFamily, title.FontStyle, title.FontWeight, title.FontStretch),
                        title.FontSize, title.Foreground, VisualTreeHelper.GetDpi(title).PixelsPerDip);
                    string size = $"{width}x{height}";
                    Check($"UI 摘要 {mode}/{size} 部分检查标题全文在实际顶部可读",
                        title.Text == PartialSafeTitle && layout.IsFullyVisible(title) &&
                        measured.WidthIncludingTrailingWhitespace <= title.ActualWidth + 1 &&
                        measured.Height <= title.ActualHeight + 1 &&
                        title.ToolTip?.ToString() == title.Text &&
                        layout.IsFullyVisible(stage) && SummaryStageIsAccurate(ScanCoverage.Partial, stage.Text));
                    Check($"UI 摘要 {mode}/{size} 下一步说明保持单行且提示可读全文",
                        layout.IsFullyVisible(detail) && detail.TextWrapping == TextWrapping.NoWrap &&
                        detail.TextTrimming == TextTrimming.CharacterEllipsis &&
                        detail.ToolTip?.ToString() == detail.Text &&
                        SummaryDetailIsAccurate(mode, ScanCoverage.Partial, SummaryFindings.Information, detail.Text));

                    snapshots.Add(new
                    {
                        viewport = size,
                        mode = mode.ToString(),
                        coverage = report.Coverage.ToString(),
                        title = title.Text,
                        detail = detail.Text,
                        detailToolTip = detail.ToolTip?.ToString(),
                        stage = stage.Text,
                        measuredTitleWidth = measured.WidthIncludingTrailingWhitespace,
                        availableTitleWidth = title.ActualWidth,
                        safety = "Synthetic information-only report; no files scanned and no actions executed."
                    });
                    if (output is not null) layout.Save($"summary-{mode.ToString().ToLowerInvariant()}-partial-{size}", output);
                }
                finally { CloseSummaryFixture(window); }
            }
        if (output is not null) File.WriteAllText(Path.Combine(output, "summary-ui-texts.json"),
            JsonSerializer.Serialize(snapshots, new JsonSerializerOptions { WriteIndented = true }));
    }

    private static TextBlock SummaryText(MainWindow window, string name) => (TextBlock)window.FindName(name);

    private static void CloseSummaryFixture(MainWindow window)
    {
        // The constructor starts busy until Loaded; hidden fixtures never run Loaded.
        // Return the synthetic fixture to idle so closing it cannot open an operation dialog.
        typeof(MainWindow).GetMethod("SetBusy", SummaryPrivate)!.Invoke(window, [false]);
        window.Close();
    }

    private static void InvokeSummary(MainWindow window, ScanReport report) =>
        typeof(MainWindow).GetMethod("UpdateSummary", SummaryPrivate)!.Invoke(window, [report]);

    private static string ExpectedSummaryTitle(ScanCoverage coverage, SummaryFindings findings) => findings switch
    {
        SummaryFindings.KnownWithHostEvidence => UiExpected("发现威胁与本机异常", "Threats and local anomalies found"),
        SummaryFindings.Known => UiExpected("扫描内容包含已知威胁", "Known threats in scanned content"),
        SummaryFindings.Suspicious => UiExpected("发现可疑项", "Suspicious items found"),
        _ => coverage switch
        {
            ScanCoverage.Partial => PartialSafeTitle,
            ScanCoverage.Complete => CompleteSafeTitle,
            _ => SkippedScanTitle
        }
    };

    private static bool SummaryDetailIsAccurate(ScanMode mode, ScanCoverage coverage, SummaryFindings findings, string text)
    {
        if (findings is SummaryFindings.Known or SummaryFindings.KnownWithHostEvidence)
            return text.Contains(UiExpected("文件检出不等于本机已感染", "A file detection does not establish an active infection on this computer"), StringComparison.Ordinal) && !text.Contains(UiExpected("未发现", "no actionable risk found"), StringComparison.Ordinal);
        if (findings == SummaryFindings.Suspicious)
            return text.Contains(UiExpected("人工复核", "Manual review required"), StringComparison.Ordinal) && text.Contains(UiExpected("未自动判定为病毒", "have not automatically been classified as malware"), StringComparison.Ordinal) &&
                !text.Contains(UiExpected("未发现", "no actionable risk found"), StringComparison.Ordinal);
        return coverage switch
        {
            ScanCoverage.Partial when mode == ScanMode.Quick => text == QuickPartialGuidance,
            ScanCoverage.Partial => text.Contains(UiExpected("未检查内容", "Unchecked"), StringComparison.Ordinal) &&
                text.Contains(UiExpected("原因", "reasons"), StringComparison.Ordinal) && text.Contains(UiExpected("选项", "options"), StringComparison.Ordinal) &&
                text != QuickPartialGuidance,
            ScanCoverage.Complete => text.Contains(UiExpected("本次", "selected"), StringComparison.Ordinal) && text.Contains(UiExpected("范围", "scope"), StringComparison.Ordinal) &&
                text.Contains(UiExpected("不代表", "does not establish"), StringComparison.Ordinal) && text.Contains(UiExpected("绝对安全", "entire computer is safe"), StringComparison.Ordinal),
            _ => !string.IsNullOrWhiteSpace(text) && !text.Contains(UiExpected("已完成支持范围内", "All supported checks complete"), StringComparison.Ordinal)
        };
    }

    private static bool SummaryStageIsAccurate(ScanCoverage coverage, string stage) => coverage switch
    {
        ScanCoverage.Partial => stage.Contains(UiExpected("扫描已结束", "scan ended"), StringComparison.OrdinalIgnoreCase) && !stage.Contains(UiExpected("已完成", " complete"), StringComparison.Ordinal),
        ScanCoverage.Complete => stage.Contains(UiExpected("已完成", " complete"), StringComparison.Ordinal),
        _ => !stage.Contains(UiExpected("已完成", " complete"), StringComparison.Ordinal)
    };

    private static ScanReport CreateSummaryReport(ScanMode mode, ScanCoverage coverage, SummaryFindings findings)
    {
        ScanReport report = new()
        {
            Mode = mode,
            Coverage = coverage,
            CompletedAtUtc = DateTimeOffset.UtcNow,
            Metrics = new() { FilesVisited = coverage == ScanCoverage.Skipped ? 0 : 3 }
        };
        if (findings == SummaryFindings.Information)
        {
            report.Findings.Add(new()
            {
                RuleId = "UI-SUMMARY-INFORMATION",
                Category = FindingCategory.Network,
                Severity = FindingSeverity.Information,
                Title = "无害摘要示例：代理配置信息",
                Target = "127.0.0.1:7890",
                Description = "仅测试文字，不读取代理配置。"
            });
            report.Findings.Add(new()
            {
                RuleId = "UI-SUMMARY-LOW",
                Category = FindingCategory.Network,
                Severity = FindingSeverity.Low,
                Title = "无害摘要示例：低等级配置提示",
                Target = "ui-fixture",
                Description = "仅测试文字，没有实际扫描。"
            });
            // A coverage-only Medium record must not promote information to a suspicious result.
            if (coverage != ScanCoverage.Complete) report.Findings.Add(new()
            {
                RuleId = "READ-LIMIT",
                Category = FindingCategory.Coverage,
                Severity = FindingSeverity.Medium,
                Title = "无害摘要示例：未检查内容",
                Target = "ui-fixture",
                Description = "仅测试覆盖说明。"
            });
        }
        if (findings is SummaryFindings.Suspicious or SummaryFindings.KnownWithHostEvidence) report.Findings.Add(new()
        {
            RuleId = "UI-SUMMARY-SUSPICIOUS",
            Category = FindingCategory.File,
            Severity = FindingSeverity.Medium,
            Title = "无害摘要示例：可疑项",
            Target = "ui-fixture",
            Description = "仅测试摘要优先级，不是实际威胁。"
        });
        if (findings is SummaryFindings.Known or SummaryFindings.KnownWithHostEvidence) report.Findings.Add(new()
        {
            RuleId = "UI-SUMMARY-KNOWN",
            Category = FindingCategory.File,
            Severity = FindingSeverity.Critical,
            IsKnownMalware = true,
            Title = "无害摘要示例：已知规则命中",
            Target = "ui-fixture",
            Description = "合成结果，不对应真实文件。"
        });
        if (findings == SummaryFindings.KnownWithHostEvidence) report.Findings.Add(new()
        {
            RuleId = "UI-SUMMARY-HOST",
            Category = FindingCategory.Process,
            Severity = FindingSeverity.High,
            Title = "无害摘要示例：主机证据",
            Target = "ui-fixture",
            Description = "合成结果，不读取或停止进程。"
        });
        return report;
    }
}
