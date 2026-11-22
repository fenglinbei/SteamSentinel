using System.IO;
using System.Reflection;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Interop;
using System.Windows.Media;
using SteamSentinel.App;
using SteamSentinel.App.Services;
using SteamSentinel.Core.Models;
using SteamSentinel.Core.Reporting;
using SteamSentinel.Core.Utilities;

namespace SteamSentinel.SelfTest;

internal static partial class Program
{
    private static void RunP2CUiSuite()
    {
        AppContext.SetSwitch("Switch.System.Windows.Media.ShouldRenderEvenWhenNoDisplayDevicesAreAvailable", true);
        Exception? failure = null;
        Thread thread = new(() =>
        {
            SteamSentinel.App.App? app = null;
            try
            {
                RenderOptions.ProcessRenderMode = RenderMode.SoftwareOnly;
                app = UiFixtureApplication.Create();
                TestP2CUiSimplification(null);
                TestScanSettingsUi(null);
                Check("P2-C UI 夹具没有安排或加载真实产品窗口", app.StartupUri is null &&
                    app.Windows.OfType<MainWindow>().All(window => !window.IsLoaded));
            }
            catch (Exception ex) { failure = ex; }
            finally { app?.Shutdown(); }
        });
        thread.SetApartmentState(ApartmentState.STA);
        thread.Start();
        thread.Join();
        if (failure is not null) Failures.Add("P2-C UI 测试异常：" + failure);
    }

    private static void TestP2CUiSimplification(string? output)
    {
        foreach (var culture in new[] { DisplayText.Chinese, DisplayText.English })
        {
            using IDisposable language = DisplayText.UseCulture(culture);
            foreach ((int width, int height) in new[] { (1148, 780), (784, 460) })
            {
                string tag = $"{culture.Name}/{width}x{height}";
                MainWindow window = new();
                try
                {
                    using UiLayoutHarness layout = new(window, width, height);
                    TabControl resultTabs = (TabControl)window.FindName("ResultTabs");
                    TabItem[] expertTabs =
                    [
                        (TabItem)window.FindName("TrustProxyTab"),
                        (TabItem)window.FindName("RelatedComponentsTab"),
                        (TabItem)window.FindName("CasesTab"),
                        (TabItem)window.FindName("ContainerTab")
                    ];
                    WrapPanel scanBar = (WrapPanel)window.FindName("ScanActionsBar");
                    Button retryPasswords = (Button)window.FindName("RetryPasswordsButton");
                    Button cancelScan = (Button)window.FindName("CancelScanButton");
                    Expander scanOptions = (Expander)window.FindName("ScanOptionsExpander");
                    ComboBox modeCombo = (ComboBox)window.FindName("RemediationModeComboBox");
                    FrameworkElement aggressiveBadge = (FrameworkElement)window.FindName("AggressiveModeBadge");
                    CheckBox showAdvanced = (CheckBox)window.FindName("ShowAdvancedTabsCheckBox");

                    // 1. 首次打开主窗口：默认 3 个页签 + 5 个扫描按钮 + 处置模式折叠
                    int visibleTabs = resultTabs.Items.Cast<TabItem>().Count(t => t.Visibility == Visibility.Visible);
                    int visibleScanButtons = scanBar.Children.OfType<Button>().Count(b => b.Visibility == Visibility.Visible);
                    Check($"P2-C {tag} 初始只显示3个核心页签与5个扫描按钮并折叠专家选项",
                        visibleTabs == 3 &&
                        expertTabs.All(t => t.Visibility == Visibility.Collapsed) &&
                        visibleScanButtons == 5 &&
                        retryPasswords.Visibility == Visibility.Collapsed &&
                        cancelScan.Visibility == Visibility.Collapsed &&
                        !scanOptions.IsExpanded &&
                        IsInsideControl(modeCombo, scanOptions) &&
                        aggressiveBadge.Visibility == Visibility.Collapsed);

                    // 2. 动态按钮显隐：取消按钮与加密包重试按钮
                    cancelScan.IsEnabled = true;
                    layout.Refresh();
                    Check($"P2-C {tag} 启用取消扫描时自动显现且停用时自动隐藏",
                        cancelScan.Visibility == Visibility.Visible &&
                        IsInsideControl(modeCombo, scanOptions));
                    cancelScan.IsEnabled = false;
                    layout.Refresh();
                    Check($"P2-C {tag} 禁用取消扫描后重新隐藏", cancelScan.Visibility == Visibility.Collapsed);

                    string encryptedFixture = Path.Combine(Path.GetTempPath(), "p2c-enc-" + Guid.NewGuid().ToString("N") + ".zip");
                    File.WriteAllText(encryptedFixture, "Inert encrypted placeholder.");
                    try
                    {
                        ScanReport encryptedReport = new()
                        {
                            Mode = ScanMode.Custom,
                            Coverage = ScanCoverage.Partial,
                            CompletedAtUtc = DateTimeOffset.UtcNow,
                            Findings =
                            [
                                new()
                                {
                                    RuleId = "ARCHIVE-ENCRYPTED-NOT-SCANNED",
                                    Category = FindingCategory.Coverage,
                                    Target = encryptedFixture,
                                    Description = "Inert encrypted coverage finding."
                                }
                            ]
                        };
                        SetTrustProxyUiReport(window, encryptedReport);
                        typeof(MainWindow).GetMethod("SetBusy", TrustProxyUiPrivate)!.Invoke(window, [false]);
                        layout.Refresh();
                        Check($"P2-C {tag} 存在未解密压缩包时重试密码按钮空闲自动显现",
                            retryPasswords.IsEnabled && retryPasswords.Visibility == Visibility.Visible);
                    }
                    finally { if (File.Exists(encryptedFixture)) File.Delete(encryptedFixture); }

                    // 3. 高级页签开关与安全回退
                    showAdvanced.IsChecked = true;
                    layout.Refresh();
                    Check($"P2-C {tag} 勾选显示高级诊断页签后7个页签全部可见",
                        resultTabs.Items.Cast<TabItem>().All(t => t.Visibility == Visibility.Visible));
                    resultTabs.SelectedItem = expertTabs[1]; // RelatedComponentsTab
                    layout.Refresh();
                    showAdvanced.IsChecked = false;
                    layout.Refresh();
                    Check($"P2-C {tag} 取消勾选高级页签后隐藏专家页签并安全回退至第0页",
                        expertTabs[1].Visibility == Visibility.Collapsed &&
                        resultTabs.SelectedIndex == 0);

                    // 4. 人话结论卡 4 档结论 + 短视口避让 + ClearSelectionButton 联动
                    Border verdictBanner = (Border)window.FindName("ScanVerdictBanner");
                    TextBlock verdictText = (TextBlock)window.FindName("ScanVerdictText");
                    Button clearSelection = TrustProxyUiButton(window, "ClearSelectionButton");

                    ScanReport cleanReport = new() { Mode = ScanMode.Quick, Coverage = ScanCoverage.Complete, CompletedAtUtc = DateTimeOffset.UtcNow };
                    SetTrustProxyUiReport(window, cleanReport);
                    layout.Refresh();
                    Check($"P2-C {tag} 完整无威胁扫描显示绿色人话结论且未选中时禁用清除按钮",
                        verdictBanner.Visibility == Visibility.Visible &&
                        verdictText.Text == DisplayText.Get("Ui.P2C.Verdict.Clean") &&
                        !clearSelection.IsEnabled);

                    ScanReport incompleteReport = new() { Mode = ScanMode.Quick, Coverage = ScanCoverage.Partial, CompletedAtUtc = DateTimeOffset.UtcNow };
                    SetTrustProxyUiReport(window, incompleteReport);
                    layout.Refresh();
                    Check($"P2-C {tag} 未完整扫描显示提示切到未检查内容页签",
                        verdictBanner.Visibility == Visibility.Visible &&
                        verdictText.Text == DisplayText.Get("Ui.P2C.Verdict.Incomplete"));

                    ScanReport reviewReport = new()
                    {
                        Mode = ScanMode.Quick,
                        Coverage = ScanCoverage.Complete,
                        CompletedAtUtc = DateTimeOffset.UtcNow,
                        Findings =
                        [
                            new()
                            {
                                RuleId = "P2C-REVIEW",
                                Category = FindingCategory.Network,
                                Severity = FindingSeverity.High,
                                Title = "Review item",
                                Target = @"C:\inert\review.txt",
                                SuggestedActions = [SuggestedActionKind.ReviewOnly]
                            }
                        ]
                    };
                    SetTrustProxyUiReport(window, reviewReport);
                    layout.Refresh();
                    Check($"P2-C {tag} 需人工确认发现显示对应人话指引",
                        verdictBanner.Visibility == Visibility.Visible &&
                        verdictText.Text == DisplayText.Format("Ui.P2C.Verdict.Review", 1));

                    ScanReport actionableReport = new()
                    {
                        Mode = ScanMode.Quick,
                        Coverage = ScanCoverage.Complete,
                        CompletedAtUtc = DateTimeOffset.UtcNow,
                        Findings =
                        [
                            new()
                            {
                                RuleId = "P2C-KNOWN",
                                Category = FindingCategory.File,
                                Severity = FindingSeverity.Critical,
                                IsKnownMalware = true,
                                CanRemediate = true,
                                Title = "Known item",
                                Target = @"C:\inert\known.exe",
                                Sha256 = new string('A', 64),
                                SuggestedActions = [SuggestedActionKind.QuarantineFile]
                            }
                        ]
                    };
                    SetTrustProxyUiReport(window, actionableReport);
                    UiPreview.ApplyAccessState(window, InstallationSecurityStatus.Protected, new(false, true));
                    layout.Refresh();
                    window.Findings.Single().IsSelected = true;
                    layout.Refresh();
                    Check($"P2-C {tag} 存在可处置威胁时展示红色人话结论并随选中联动清除按钮",
                        verdictBanner.Visibility == Visibility.Visible &&
                        verdictText.Text == DisplayText.Format("Ui.P2C.Verdict.Actionable", 1) &&
                        window.Findings.Single().IsSelected && clearSelection.IsEnabled);

                    window.Findings.Single().IsSelected = false;
                    layout.Refresh();
                    Check($"P2-C {tag} 取消全部勾选后清除选择按钮自动禁用", !clearSelection.IsEnabled);

                    if (height < 540)
                    {
                        scanOptions.IsExpanded = true;
                        layout.Refresh();
                        DataGrid grid = (DataGrid)window.FindName("FindingsGrid");
                        DataGridRow? row = grid.ItemContainerGenerator.ContainerFromIndex(0) as DataGridRow;
                        Check($"P2-C {tag} 短视口展开扫描选项时隐藏人话结论卡以保住首行结果",
                            verdictBanner.Visibility == Visibility.Collapsed &&
                            row is not null && layout.IsFullyVisible(row));
                        scanOptions.IsExpanded = false;
                        layout.Refresh();
                    }

                    if (output is not null) layout.Save($"p2c-verdict-{culture.Name}-{width}x{height}", output);
                }
                finally { CloseSummaryFixture(window); }

                // 5. 上下文自动显露（TrustProxy / Cases / Container / 未决执行）
                MainWindow contextWindow = new();
                try
                {
                    using UiLayoutHarness contextLayout = new(contextWindow, width, height);
                    typeof(MainWindow).GetMethod("SetBusy", TrustProxyUiPrivate)!.Invoke(contextWindow, [false]);
                    TabControl resultTabs = (TabControl)contextWindow.FindName("ResultTabs");
                    TabItem trustTab = (TabItem)contextWindow.FindName("TrustProxyTab");
                    TabItem casesTab = (TabItem)contextWindow.FindName("CasesTab");
                    TabItem containerTab = (TabItem)contextWindow.FindName("ContainerTab");

                    contextWindow.ApplyTrustProxyDiagnosticReport(TrustProxyUiDiagnosticReport("p2c-ctx", false));
                    contextLayout.Refresh();
                    Check($"P2-C {tag} 触发代理诊断后TrustProxyTab自动显现并选中",
                        trustTab.Visibility == Visibility.Visible && resultTabs.SelectedItem == trustTab);

                    RemediationClient client = (RemediationClient)typeof(MainWindow).GetField("_remediationClient", TrustProxyUiPrivate)!.GetValue(contextWindow)!;
                    client.RestoreUnresolvedPlan(new());
                    contextWindow.UpdateUnresolvedExecutionBanner();
                    contextLayout.Refresh();
                    Check($"P2-C {tag} 存在未决执行时CasesTab自动显现", casesTab.Visibility == Visibility.Visible);

                    string dummyArchive = Path.Combine(Path.GetTempPath(), "p2c-container-" + Guid.NewGuid().ToString("N") + ".zip");
                    File.WriteAllText(dummyArchive, "Inert container fixture.");
                    try
                    {
                        RunTrustProxyUiTask(contextWindow, () => contextWindow.RunContainerReviewAsync([dummyArchive], [], null,
                            (_, _, _) => Task.FromResult(V020ContainerPresentationFixture(dummyArchive, dummyArchive, dummyArchive))));
                        contextLayout.Refresh();
                        Check($"P2-C {tag} 容器补查执行后ContainerTab自动显现并选中",
                            containerTab.Visibility == Visibility.Visible && resultTabs.SelectedItem == containerTab);
                    }
                    finally { if (File.Exists(dummyArchive)) File.Delete(dummyArchive); }
                }
                finally { CloseSummaryFixture(contextWindow); }
            }
        }
    }

    private static bool IsInsideControl(DependencyObject child, DependencyObject targetAncestor)
    {
        DependencyObject? current = child;
        while (current is not null)
        {
            if (ReferenceEquals(current, targetAncestor)) return true;
            current = LogicalTreeHelper.GetParent(current) ?? VisualTreeHelper.GetParent(current);
        }
        return false;
    }
}
