using System.Text.Json;
using System.Windows;
using System.Windows.Automation;
using System.Windows.Controls;
using SteamSentinel.App;
using SteamSentinel.App.Services;
using SteamSentinel.Core.Models;
using SteamSentinel.Core.Reporting;
using SteamSentinel.Core.Utilities;
using AvailabilityAction = SteamSentinel.App.MainWindow.RemediationAvailabilityAction;
using AvailabilityState = SteamSentinel.App.MainWindow.RemediationAvailabilityState;

namespace SteamSentinel.SelfTest;

internal static partial class Program
{
    // Hidden STA fixtures: no Loaded, real case store, administrator process, scan or target mutation.
    private static void TestV030RemediationAvailabilityUi(string? output)
    {
        foreach (var culture in new[] { DisplayText.Chinese, DisplayText.English })
        {
            using IDisposable language = DisplayText.UseCulture(culture);
            foreach ((int width, int height) in new[] { (1148, 780), (784, 460) })
            {
                MainWindow window = new();
                try
                {
                    using UiLayoutHarness layout = new(window, width, height);
                    string fixture = $"{culture.Name}/{width}x{height}";
                    ScanReport report = RemediationAvailabilityUiReport();
                    string originalReport = JsonSerializer.Serialize(report, JsonFile.Options);
                    SetTrustProxyUiReport(window, report);
                    UiPreview.ApplyAccessState(window, InstallationSecurityStatus.Protected, new(false, true));
                    Button remediate = TrustProxyUiButton(window, "RemediateButton");
                    Button selectAll = TrustProxyUiButton(window, "SelectAllButton");
                    Button action = TrustProxyUiButton(window, "RemediationAvailabilityActionButton");
                    TextBlock explanation = TrustProxyUiText(window, "RemediationAvailabilityTextBlock");
                    Border panel = (Border)window.FindName("RemediationAvailabilityPanel");
                    typeof(MainWindow).GetMethod("SelectAll_Click", TrustProxyUiPrivate)!.Invoke(window, [selectAll, new RoutedEventArgs()]);
                    layout.Refresh();
                    Check($"处置可用UI {fixture} 当前有资格项目可选择且入口可见",
                        window.GetRemediationAvailability().State == AvailabilityState.Ready && remediate.IsEnabled && selectAll.IsEnabled &&
                        window.Findings.Single().IsSelected && layout.IsFullyVisible(explanation) && layout.IsFullyVisible(remediate));

                    SetRemediationAvailabilityFlag(window, "_caseRecoveryUnavailable", true);
                    layout.Refresh();
                    Check($"处置可用UI {fixture} 不能读取旧记录时原因就地可读且保留选中项目",
                        window.GetRemediationAvailability() == new MainWindow.RemediationAvailability(AvailabilityState.RecoveryUnavailable, AvailabilityAction.CheckRecovery, false) &&
                        !remediate.IsEnabled && selectAll.IsEnabled && window.Findings.Single().IsSelected &&
                        explanation.Text == DisplayText.Get("Ui.RemediationAvailability.RecoveryUnavailable") &&
                        action.Content?.ToString() == UiExpected("检查并继续", "Check and continue") &&
                        AutomationProperties.GetName(action) == action.Content?.ToString() &&
                        explanation.TextWrapping == TextWrapping.Wrap && explanation.TextTrimming == TextTrimming.None &&
                        layout.IsFullyVisible(panel) && layout.IsFullyVisible(explanation) && layout.IsFullyVisible(action) &&
                        layout.DoNotOverlap([explanation, action]) &&
                        !explanation.Text.Contains("Pending", StringComparison.Ordinal) && !explanation.Text.Contains("Broker", StringComparison.Ordinal));
                    if (output is not null) layout.Save($"remediation-availability-blocked-{culture.Name}-{width}x{height}", output);

                    int checks = 0;
                    RunTrustProxyUiTask(window, () => window.RunRemediationAvailabilityActionAsync(recoveryCheck: async () =>
                    {
                        checks++;
                        Check($"处置可用UI {fixture} 检查期间不能重复开始处理",
                            window.GetRemediationAvailability().State == AvailabilityState.Busy && !remediate.IsEnabled && !action.IsEnabled);
                        await Task.Yield();
                        SetRemediationAvailabilityFlag(window, "_caseRecoveryUnavailable", false);
                        SetRemediationAvailabilityFlag(window, "_hasEndedUnknownExecution", true);
                        SetRemediationAvailabilityFlag(window, "_reportNeedsRefresh", true);
                    }));
                    layout.Refresh();
                    Check($"处置可用UI {fixture} 已结束但结果未知只给重新扫描且不改写旧报告",
                        checks == 1 && window.GetRemediationAvailability().State == AvailabilityState.EndedUnknownRescanRequired &&
                        !remediate.IsEnabled && !selectAll.IsEnabled && action.Content?.ToString() == UiExpected("重新扫描", "Scan again") &&
                        explanation.Text == DisplayText.Get("Ui.RemediationAvailability.EndedUnknownRescanRequired") &&
                        originalReport == JsonSerializer.Serialize(report, JsonFile.Options) &&
                        layout.IsFullyVisible(explanation) && layout.IsFullyVisible(action));

                    int scans = 0;
                    RunTrustProxyUiTask(window, () => window.RunRemediationAvailabilityActionAsync(rescan: (mode, roots, options) =>
                    {
                        scans++;
                        Check($"处置可用UI {fixture} 直接重扫沿用范围并移除旧恢复目录授权",
                            mode == report.Mode && roots.SequenceEqual(report.ContentScanSettings!.CustomRoots) &&
                            options is not null && !ReferenceEquals(options, report.ContentScanSettings) && options.RecoveryOutputDirectory is null &&
                            !ReferenceEquals(options.CustomRoots, report.ContentScanSettings.CustomRoots) &&
                            options.MaximumFiles == report.ContentScanSettings.MaximumFiles &&
                            options.InspectArchives == report.ContentScanSettings.InspectArchives && !options.UseAmsi);
                        return Task.CompletedTask;
                    }));
                    Check($"处置可用UI {fixture} 只读重扫入口调用一次且不提前解除旧扫描门槛",
                        scans == 1 && !remediate.IsEnabled && originalReport == JsonSerializer.Serialize(report, JsonFile.Options));

                    SetRemediationAvailabilityFlag(window, "_reportNeedsRefresh", false);
                    SetTrustProxyUiReport(window, RemediationAvailabilityUiReport());
                    layout.Refresh();
                    Check($"处置可用UI {fixture} 新扫描可处理但历史未知不显示为成功",
                        window.GetRemediationAvailability().State == AvailabilityState.EndedUnknown && remediate.IsEnabled &&
                        action.Content?.ToString() == UiExpected("查看记录", "View records") &&
                        explanation.Text == DisplayText.Get("Ui.RemediationAvailability.EndedUnknown") &&
                        layout.IsFullyVisible(explanation) && layout.IsFullyVisible(action));
                    if (output is not null) layout.Save($"remediation-availability-recovered-{culture.Name}-{width}x{height}", output);
                    RunTrustProxyUiTask(window, () => window.RunRemediationAvailabilityActionAsync());
                    layout.Refresh();
                    Check($"处置可用UI {fixture} 查看记录直接到只读页而不显示旧计划执行入口",
                        ((TabControl)window.FindName("ResultTabs")).SelectedItem == window.FindName("CasesTab") &&
                        remediate.Visibility == Visibility.Collapsed && !layout.IsFullyVisible(panel));
                    ((TabControl)window.FindName("ResultTabs")).SelectedIndex = 0;

                    DateTimeOffset finishedAt = GetTrustProxyUiReport(window).StartedAtUtc.AddSeconds(1);
                    typeof(MainWindow).GetMethod("ObserveFinishedRemediation", TrustProxyUiPrivate)!.Invoke(window,
                        [new RemediationRunResult { CompletedAtUtc = finishedAt, Disposition = RemediationRunDisposition.ExecutionUnknown }]);
                    typeof(MainWindow).GetMethod("UpdateRemediationEligibility", TrustProxyUiPrivate)!.Invoke(window, null);
                    Check($"处置可用UI {fixture} 晚于当前扫描完成的结束收据要求重新扫描",
                        window.GetRemediationAvailability().Action == AvailabilityAction.Rescan && !remediate.IsEnabled && !selectAll.IsEnabled);
                    SetRemediationAvailabilityFlag(window, "_reportNeedsRefresh", false);
                    SetTrustProxyUiReport(window, RemediationAvailabilityUiReport(finishedAt.AddSeconds(1)));
                    Check($"处置可用UI {fixture} 执行结束后开始的新扫描允许处理并保留未知历史说明",
                        window.GetRemediationAvailability().State == AvailabilityState.EndedUnknown && remediate.IsEnabled && selectAll.IsEnabled);
                    SetRemediationAvailabilityFlag(window, "_reportNeedsRefresh", false);
                    SetTrustProxyUiReport(window, RemediationAvailabilityUiReport(finishedAt.AddSeconds(-1)));
                    Check($"处置可用UI {fixture} 延迟发布的旧扫描仍由填充入口标记过期",
                        window.GetRemediationAvailability().Action == AvailabilityAction.Rescan && !remediate.IsEnabled && !selectAll.IsEnabled);
                    SetRemediationAvailabilityFlag(window, "_reportNeedsRefresh", false);
                    SetTrustProxyUiReport(window, RemediationAvailabilityUiReport(finishedAt.AddSeconds(1)));

                    SetRemediationAvailabilityFlag(window, "_recoveryRequired", true);
                    layout.Refresh();
                    Check($"处置可用UI {fixture} 程序错误要求重新打开且不会被历史结束状态解锁",
                        window.GetRemediationAvailability().State == AvailabilityState.RestartRequired && !remediate.IsEnabled &&
                        explanation.Text == DisplayText.Get("Ui.RemediationAvailability.RestartRequired") && layout.IsFullyVisible(explanation));
                    SetRemediationAvailabilityFlag(window, "_recoveryRequired", false);
                    UiPreview.ApplyAccessState(window, new(false, "inert installation unavailable"), new(false, true));
                    layout.Refresh();
                    int installationChecks = 0;
                    RunTrustProxyUiTask(window, () => window.RunRemediationAvailabilityActionAsync(installationCheck: () =>
                    {
                        installationChecks++;
                        return Task.CompletedTask;
                    }));
                    Check($"处置可用UI {fixture} 安装检查独立提供直接入口且未通过前不放行",
                        window.GetRemediationAvailability().State == AvailabilityState.InstallationUnavailable && !remediate.IsEnabled &&
                        action.Content?.ToString() == UiExpected("检查安装", "Check installation") && installationChecks == 1 &&
                        layout.IsFullyVisible(explanation) && layout.IsFullyVisible(action));

                    UiPreview.ApplyAccessState(window, InstallationSecurityStatus.Protected, new(false, true));
                    RemediationClient client = (RemediationClient)typeof(MainWindow).GetField("_remediationClient", TrustProxyUiPrivate)!.GetValue(window)!;
                    RemediationPlan pending = new();
                    client.RestoreUnresolvedPlan(pending);
                    SetRemediationAvailabilityFlag(window, "_reportNeedsRefresh", false);
                    layout.Refresh();
                    RunTrustProxyUiTask(window, () => window.RunRemediationAvailabilityActionAsync(recoveryCheck: () => Task.CompletedTask));
                    Check($"处置可用UI {fixture} 没有结束收据时检查不能仅因按钮点击解除阻断",
                        client.IsUnresolved(pending.PlanId) && window.GetRemediationAvailability().State == AvailabilityState.PreviousExecutionUnresolved &&
                        !remediate.IsEnabled && selectAll.IsEnabled && action.Content?.ToString() == UiExpected("检查并继续", "Check and continue") &&
                        layout.IsFullyVisible(explanation) && layout.IsFullyVisible(action));
                }
                finally { CloseSummaryFixture(window); }
            }
        }
    }

    private static void SetRemediationAvailabilityFlag(MainWindow window, string field, bool value)
    {
        typeof(MainWindow).GetField(field, TrustProxyUiPrivate)!.SetValue(window, value);
        typeof(MainWindow).GetMethod("UpdateRemediationEligibility", TrustProxyUiPrivate)!.Invoke(window, null);
    }

    private static ScanReport RemediationAvailabilityUiReport(DateTimeOffset? startedAtUtc = null) => new()
    {
        Mode = ScanMode.Custom,
        StartedAtUtc = startedAtUtc ?? DateTimeOffset.UtcNow,
        CompletedAtUtc = (startedAtUtc ?? DateTimeOffset.UtcNow).AddMilliseconds(1),
        ContentScanSettings = new()
        {
            Mode = ScanMode.Custom,
            IncludeSystem = false,
            IncludeSteam = false,
            IncludeWorkshop = false,
            CustomRoots = [@"C:\inert-fixtures\selected-folder"],
            MaximumFiles = 1234,
            InspectArchives = true,
            UseAmsi = false,
            RecoveryOutputDirectory = @"C:\inert-fixtures\one-time-export"
        },
        Findings = [new()
        {
            Id = "inert-current-actionable", RuleId = "UI-KNOWN-INERT", Title = "Inert actionable fixture",
            Target = @"C:\inert-fixtures\selected-folder\sample.bin", Category = FindingCategory.File,
            Severity = FindingSeverity.High, IsKnownMalware = true, CanRemediate = true,
            SuggestedActions = [SuggestedActionKind.QuarantineFile]
        }]
    };
}
