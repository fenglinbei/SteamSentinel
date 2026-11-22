using System.IO;
using System.Reflection;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Interop;
using System.Windows.Media;
using SteamSentinel.App;
using SteamSentinel.App.Services;
using SteamSentinel.App.ViewModels;
using SteamSentinel.Core.Models;
using SteamSentinel.Core.Reporting;
using SteamSentinel.Core.Scanning;
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
                    FrameworkElement modePanel = (FrameworkElement)window.FindName("RemediationModePanel");
                    ComboBox modeCombo = (ComboBox)window.FindName("RemediationModeComboBox");
                    FrameworkElement aggressiveBadge = (FrameworkElement)window.FindName("AggressiveModeBadge");
                    CheckBox showAdvanced = (CheckBox)window.FindName("ShowAdvancedTabsCheckBox");

                    // 1. 首次打开主窗口：默认 3 个页签 + 5 个扫描按钮 + 处置模式下拉框已隐藏且折叠专家选项
                    int visibleTabs = resultTabs.Items.Cast<TabItem>().Count(t => t.Visibility == Visibility.Visible);
                    int visibleScanButtons = scanBar.Children.OfType<Button>().Count(b => b.Visibility == Visibility.Visible);
                    Check($"P2-C {tag} 初始只显示3个核心页签与5个扫描按钮并隐藏处置模式下拉框",
                        visibleTabs == 3 &&
                        expertTabs.All(t => t.Visibility == Visibility.Collapsed) &&
                        visibleScanButtons == 5 &&
                        retryPasswords.Visibility == Visibility.Collapsed &&
                        cancelScan.Visibility == Visibility.Collapsed &&
                        !scanOptions.IsExpanded &&
                        IsInsideControl(modeCombo, scanOptions) &&
                        modePanel.Visibility == Visibility.Collapsed &&
                        modeCombo.Visibility == Visibility.Collapsed &&
                        !modeCombo.IsVisible &&
                        aggressiveBadge.Visibility == Visibility.Collapsed);

                    // 2. 动态按钮显隐：取消按钮与加密包重试按钮
                    cancelScan.IsEnabled = true;
                    layout.Refresh();
                    Check($"P2-C {tag} 启用取消扫描时自动显现且处置模式保持隐藏",
                        cancelScan.Visibility == Visibility.Visible &&
                        IsInsideControl(modeCombo, scanOptions) &&
                        modeCombo.Visibility == Visibility.Collapsed);
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
                    Expander detailCard = (Expander)window.FindName("FindingDetailCard");
                    bool collapsedAfterScan = detailCard.Visibility == Visibility.Visible && !detailCard.IsExpanded;
                    detailCard.IsExpanded = true;
                    layout.Refresh();
                    bool expandedOnClick = detailCard.IsExpanded;
                    detailCard.IsExpanded = false;
                    layout.Refresh();
                    window.Findings.Single().IsSelected = true;
                    layout.Refresh();
                    Check($"P2-C {tag} 存在可处置威胁时展示红色人话结论并默认折叠详细信息且支持手动展开",
                        collapsedAfterScan && expandedOnClick && !detailCard.IsExpanded &&
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

                    // 5. 现代设计系统与防复读机回归检查（无阻断底栏透明、详情不重复标题、表格无原始记录前缀、严重度语义着色、按钮对比度）
                    Border availabilityPanel = (Border)window.FindName("RemediationAvailabilityPanel");
                    Check($"P2-C {tag} 无阻断态底部指导条透明无框融合",
                        availabilityPanel.BorderThickness == new Thickness(0) &&
                        Equals(availabilityPanel.Background, Brushes.Transparent));

                    ScanReport clarityReport = new()
                    {
                        Mode = ScanMode.Quick,
                        Coverage = ScanCoverage.Complete,
                        CompletedAtUtc = DateTimeOffset.UtcNow,
                        Findings =
                        [
                            new()
                            {
                                Id = "clarity-high",
                                RuleId = "P2C-KNOWN-CLARITY",
                                Category = FindingCategory.File,
                                Severity = FindingSeverity.Critical,
                                IsKnownMalware = true,
                                CanRemediate = true,
                                Title = "Known item",
                                Target = @"C:\inert\known-clarity.exe",
                                Description = "Clarity file description.",
                                Sha256 = new string('B', 64),
                                SuggestedActions = [SuggestedActionKind.QuarantineFile]
                            },
                            new()
                            {
                                Id = "clarity-proxy",
                                RuleId = "NETWORK-PROXY-PRESENT",
                                Category = FindingCategory.Network,
                                Severity = FindingSeverity.Information,
                                Score = 5,
                                TitleText = MessageText.Create("Backend.Core.TrustProxyCorrelator.Apply.07"),
                                Target = "http://inert.invalid/proxy.pac",
                                DescriptionText = MessageText.Create("Backend.Core.TrustProxyCorrelator.Apply.08"),
                                HandlingReason = FindingHandlingReason.InsufficientEvidence,
                                HandlingDetailsText = MessageText.Create("Backend.Core.TrustProxyCorrelator.Apply.12"),
                                SuggestedActions = [SuggestedActionKind.ReviewOnly]
                            }
                        ]
                    };
                    SetTrustProxyUiReport(window, clarityReport);
                    layout.Refresh();
                    DataGrid findingsGrid = (DataGrid)window.FindName("FindingsGrid");
                    findingsGrid.SelectedIndex = 1;
                    layout.Refresh();
                    FindingItemViewModel proxyVm = window.PriorityFindings[1];
                    TextBlock detailDesc = TrustProxyUiText(window, "DetailDescriptionText");
                    TextBlock? critSeverityCell = findingsGrid.Columns[1].GetCellContent(window.PriorityFindings[0]) as TextBlock;
                    TextBlock? infoSeverityCell = findingsGrid.Columns[1].GetCellContent(window.PriorityFindings[1]) as TextBlock;
                    DataGridRow? selectableRow = findingsGrid.ItemContainerGenerator.ContainerFromIndex(0) as DataGridRow;
                    DataGridRow? nonSelectableRow = findingsGrid.ItemContainerGenerator.ContainerFromIndex(1) as DataGridRow;
                    CheckBox? selectableCheck = selectableRow is null ? null : UiLayoutHarness.Descendants<CheckBox>(findingsGrid.Columns[0].GetCellContent(selectableRow)).FirstOrDefault();
                    CheckBox? nonSelectableCheck = nonSelectableRow is null ? null : UiLayoutHarness.Descendants<CheckBox>(findingsGrid.Columns[0].GetCellContent(nonSelectableRow)).FirstOrDefault();
                    Check($"P2-C {tag} 代理摘要无原始记录前缀且详情去重标题与严重度语义着色",
                        !proxyVm.HandlingReasonSummary.Contains("原始记录：", StringComparison.Ordinal) &&
                        !proxyVm.HandlingReasonSummary.Contains("Original record:", StringComparison.Ordinal) &&
                        !detailDesc.Text.StartsWith(proxyVm.Title + "\n", StringComparison.Ordinal) &&
                        detailDesc.Text.Contains(proxyVm.Description, StringComparison.Ordinal) &&
                        critSeverityCell is not null && infoSeverityCell is not null &&
                        UiLayoutHarness.BrushColor(critSeverityCell.Foreground) != UiLayoutHarness.BrushColor(infoSeverityCell.Foreground));
                    Check($"P2-C {tag} 可选行显示启用复选框而不可选行隐藏并禁用复选框",
                        selectableCheck is { Visibility: Visibility.Visible, IsEnabled: true } &&
                        nonSelectableCheck is { Visibility: Visibility.Collapsed, IsEnabled: false });

                    // 纯常规参考场景：hosts 已阻断 + 纯本地环回代理 127.0.0.1:7897 自动折叠进「信息与参考」，主表为 0 且不产生需人工确认警报
                    ScanReport referenceOnlyReport = new()
                    {
                        Mode = ScanMode.Full,
                        Coverage = ScanCoverage.Complete,
                        StatusSchemaVersion = ScanExecution.SchemaVersion,
                        ExecutionState = ScanExecutionState.Completed,
                        CompletedAtUtc = DateTimeOffset.UtcNow,
                        Findings =
                        [
                            new()
                            {
                                Id = "p2c-hosts-blocked",
                                RuleId = "NETWORK-C2-BLOCKED",
                                Category = FindingCategory.Network,
                                Severity = FindingSeverity.Information,
                                Title = "已知 C2 已在 hosts 中阻断",
                                Target = @"C:\Windows\System32\drivers\etc\hosts",
                                Description = "无害测试：hosts 已阻断已知恶意域名。",
                                SuggestedActions = [SuggestedActionKind.None]
                            },
                            new()
                            {
                                Id = "p2c-loopback-proxy",
                                RuleId = "NETWORK-PROXY-PRESENT",
                                Category = FindingCategory.Network,
                                Severity = FindingSeverity.Information,
                                Score = 5,
                                TitleText = MessageText.Create("Backend.Core.TrustProxyCorrelator.Apply.07"),
                                Target = "127.0.0.1:7897",
                                DescriptionText = MessageText.Create("Backend.Core.TrustProxyCorrelator.Apply.08"),
                                HandlingReason = FindingHandlingReason.InsufficientEvidence,
                                HandlingDetailsText = MessageText.Create("Backend.Core.TrustProxyCorrelator.Apply.12"),
                                SuggestedActions = [SuggestedActionKind.ReviewOnly]
                            }
                        ]
                    };
                    SetTrustProxyUiReport(window, referenceOnlyReport);
                    layout.Refresh();
                    Border statusHeader = (Border)window.FindName("ScanStatusHeader");
                    Expander referenceExpander = (Expander)window.FindName("ReferenceFindingsExpander");
                    DataGrid referenceGrid = (DataGrid)window.FindName("ReferenceFindingsGrid");
                    bool refCollapsedClean = window.PriorityFindings.Count == 0 &&
                        window.ReferenceFindings.Count == 2 &&
                        referenceExpander.Visibility == Visibility.Visible &&
                        !referenceExpander.IsExpanded &&
                        TrustProxyUiText(window, "HeaderStatusText").Text == DisplayText.Get("FindingPriority.ReferenceOnly") &&
                        UiLayoutHarness.BrushColor(statusHeader.Background) == Color.FromRgb(0xEC, 0xFD, 0xF5) &&
                        verdictText.Text == DisplayText.Get("Ui.P2C.Verdict.Clean") &&
                        detailCard.Visibility == Visibility.Collapsed && !detailCard.IsExpanded;
                    referenceExpander.IsExpanded = true;
                    layout.Refresh();
                    DataGridRow? firstRefRow = referenceGrid.ItemContainerGenerator.ContainerFromIndex(0) as DataGridRow;
                    CheckBox? firstRefCheck = firstRefRow is null ? null : UiLayoutHarness.Descendants<CheckBox>(referenceGrid.Columns[0].GetCellContent(firstRefRow)).FirstOrDefault();
                    bool refTitlesAndCheckboxesValid =
                        window.ReferenceFindings.All(item => item.Title != DisplayText.Get("FindingPriority.FormatHint")) &&
                        firstRefCheck is { Visibility: Visibility.Collapsed, IsEnabled: false };
                    referenceExpander.IsExpanded = false;
                    layout.Refresh();
                    Check($"P2-C {tag} hosts阻断与本地环回代理自动折叠至信息与参考且呈安心绿无灰勾选框",
                        refCollapsedClean && refTitlesAndCheckboxesValid);

                    Button? quickScanBtn = window.FindName("QuickScanButton") as Button;
                    Border? quickSurface = quickScanBtn?.Template.FindName("ButtonBorder", quickScanBtn) as Border;
                    TabControl mainTabs = (TabControl)window.FindName("MainTabs");
                    mainTabs.SelectedIndex = 1;
                    Button? deleteBtn = window.FindName("DeleteIncidentButton") as Button;
                    deleteBtn!.IsEnabled = true;
                    layout.Refresh();
                    Border? deleteSurface = deleteBtn.Template.FindName("ButtonBorder", deleteBtn) as Border;
                    Check($"P2-C {tag} 主操作与危险操作按钮满足WCAG对比度及圆角契约",
                        quickScanBtn is not null && quickSurface is not null &&
                        UiLayoutHarness.Contrast(quickScanBtn.Foreground, quickSurface.Background) >= 4.5 &&
                        quickSurface.CornerRadius == new CornerRadius(5) &&
                        deleteSurface is not null &&
                        UiLayoutHarness.Contrast(deleteBtn.Foreground, deleteSurface.Background) >= 4.5);
                    mainTabs.SelectedIndex = 0;
                }
                finally { CloseSummaryFixture(window); }

                // 6. 上下文自动显露（TrustProxy / Cases / Container / 未决执行）
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

                if (width == 1148 && output is null)
                {
                    VerifyCoreAndUiDeterminateProgress();
                }
            }
        }
    }

    private static void VerifyCoreAndUiDeterminateProgress()
    {
        string tempRoot = Path.Combine(Path.GetTempPath(), "p2c-progress-" + Guid.NewGuid().ToString("N"));
        try
        {
            for (int d = 0; d < 4; d++)
            {
                string sub = Path.Combine(tempRoot, "dir-" + d);
                Directory.CreateDirectory(sub);
                File.WriteAllText(Path.Combine(sub, "a.txt"), "harmless content " + d);
                File.WriteAllText(Path.Combine(sub, "b.txt"), "more harmless content " + d);
            }
            List<ScanProgress> coreReports = [];
            ScanCoordinator coordinator = new();
            ScanOptions options = new()
            {
                Mode = ScanMode.Custom,
                IncludeSystem = false,
                IncludeSteam = false,
                IncludeWorkshop = false,
                IncludeRelatedContent = false,
                InspectArchives = false,
                UseAmsi = false,
                CustomRoots = [tempRoot]
            };
            coordinator.RunAsync(options, progress: new P2CInlineProgress(coreReports.Add)).GetAwaiter().GetResult();
            ScanProgress[] bounded = coreReports.Where(p => p.Total is > 0).ToArray();
            bool monotonic = true;
            double prevRatio = -1;
            foreach (ScanProgress p in bounded)
            {
                double ratio = (double)p.Completed / p.Total!.Value;
                if (ratio + 1e-9 < prevRatio) { monotonic = false; break; }
                prevRatio = ratio;
            }
            Check("P2-C Core单根目录内容扫描输出真实且单调递增的总进度",
                bounded.Length >= 2 && monotonic && bounded[^1].Completed == bounded[^1].Total);

            MainWindow progressWindow = new();
            try
            {
                using UiLayoutHarness progressLayout = new(progressWindow, 1148, 780);
                ProgressBar bar = (ProgressBar)progressWindow.FindName("ActivityProgressBar");
                ProgressBar legacyScanBar = (ProgressBar)progressWindow.FindName("ScanProgressBar");
                Border percentBadge = (Border)progressWindow.FindName("ActivityPercentBadge");
                TextBlock percentText = (TextBlock)progressWindow.FindName("ActivityPercentText");
                TextBlock elapsedText = (TextBlock)progressWindow.FindName("ActivityElapsedText");
                Border stageOverlay = (Border)progressWindow.FindName("ScanStageOverlay");
                TextBlock stagePercentNumber = (TextBlock)progressWindow.FindName("ScanStagePercentNumber");
                System.Windows.Shapes.Path ringProgressPath = (System.Windows.Shapes.Path)progressWindow.FindName("ScanRingProgressPath");
                TextBlock stageItemText = (TextBlock)progressWindow.FindName("ScanStageItemText");
                ScaleTransform pulseScale1 = (ScaleTransform)progressWindow.FindName("ScanPulseScale1");
                System.Windows.Shapes.Ellipse pulseRing1 = (System.Windows.Shapes.Ellipse)progressWindow.FindName("ScanPulseRing1");
                RotateTransform ringIndetRot = (RotateTransform)progressWindow.FindName("ScanRingIndeterminateRotation");
                TranslateTransform barShimmer = (TranslateTransform)progressWindow.FindName("ScanStageBarShimmerTransform");
                TranslateTransform barIndet = (TranslateTransform)progressWindow.FindName("ScanStageBarIndeterminateTransform");

                bool noHeaderCard = progressWindow.FindName("HeaderCard") is null;

                progressWindow.ShowActivity(MainWindow.ActivityPhase.Scanning);
                progressWindow.BeginScanProgressStage(0, 18, reset: true);
                progressWindow.ReportScanProgressPercent(new("System", "processes", 2, 4, "checking"));
                double afterSys = progressWindow.CurrentScanProgressPercent;
                bool percentAfterSysValid = !bar.IsIndeterminate &&
                    percentBadge.Visibility == Visibility.Visible && percentText.Visibility == Visibility.Visible &&
                    percentText.Text.EndsWith('%') && !elapsedText.Text.Contains('%') && Math.Abs(afterSys - 9.0) < 0.1;

                progressWindow.BeginScanProgressStage(18, 96);
                double afterStageJump = progressWindow.CurrentScanProgressPercent;
                progressWindow.ReportScanProgressPercent(new("Content", "workshop-1", 500, 1000, "scanning"));
                double midContent = progressWindow.CurrentScanProgressPercent;
                // 穿插未知总数压缩包不能让确定进度倒退或闪回流光态
                progressWindow.ReportScanProgressPercent(new("压缩包目录", "inner.zip", 12, null, "archive"));
                double afterArchiveNull = progressWindow.CurrentScanProgressPercent;

                // 若系统允许动画，等待 260ms 验证实际 ProgressBar 与圆环动画同步推进
                if (SystemParameters.ClientAreaAnimation)
                {
                    System.Windows.Threading.DispatcherFrame frame = new();
                    System.Windows.Threading.DispatcherTimer timer = new(
                        TimeSpan.FromMilliseconds(260),
                        System.Windows.Threading.DispatcherPriority.Background,
                        (_, _) => { frame.Continue = false; },
                        progressWindow.Dispatcher);
                    timer.Start();
                    System.Windows.Threading.Dispatcher.PushFrame(frame);
                    timer.Stop();
                }

                string expectedPercentNum = ((int)Math.Round(midContent)).ToString(System.Globalization.CultureInfo.InvariantCulture);
                bool stageActiveAndSynced = stageOverlay.Visibility == Visibility.Visible &&
                    legacyScanBar.Visibility == Visibility.Collapsed &&
                    ringProgressPath.Visibility == Visibility.Visible &&
                    stagePercentNumber.Text == expectedPercentNum;

                MethodInfo updateProgressMethod = typeof(MainWindow).GetMethod("UpdateProgress", TrustProxyUiPrivate)!;
                updateProgressMethod.Invoke(progressWindow, [new ScanProgress("容器内容",
                    @"C:\Program Files\Netease\GameViewer\GameViewer.exe", 35, 100,
                    "深度 0；读取 72,946,856，解码 0 字节；临时 0 字节")]);
                bool friendlyPathFormatted = stageItemText.Text == @"…\GameViewer\GameViewer.exe";
                updateProgressMethod.Invoke(progressWindow, [new ScanProgress("容器内容",
                    string.Empty, 35, 100,
                    "深度 0；读取 72,946,856，解码 0 字节；临时 0 字节")]);
                bool rawBytesHidden = !stageItemText.Text.Contains("深度", StringComparison.Ordinal) &&
                    !stageItemText.Text.Contains("解码", StringComparison.Ordinal);

                bool determinateAndMonotonic = percentAfterSysValid &&
                    Math.Abs(afterStageJump - 18.0) < 0.1 &&
                    midContent > 50.0 && Math.Abs(afterArchiveNull - midContent) < 0.01 &&
                    !bar.IsIndeterminate && bar.Value >= 50.0;

                progressWindow.ShowActivity(MainWindow.ActivityPhase.Preparing);
                progressLayout.Refresh();
                bool resetInPreparing = percentText.Visibility == Visibility.Collapsed &&
                    percentBadge.Visibility == Visibility.Collapsed &&
                    stageOverlay.Visibility == Visibility.Collapsed &&
                    bar.IsIndeterminate == SystemParameters.ClientAreaAnimation &&
                    !pulseScale1.HasAnimatedProperties && !pulseRing1.HasAnimatedProperties &&
                    !ringIndetRot.HasAnimatedProperties && !barShimmer.HasAnimatedProperties &&
                    !barIndet.HasAnimatedProperties;

                Check("P2-C UI扫描分层进度、大号百分比与高级动效舞台正常联动且非扫描阶段彻底停机",
                    noHeaderCard && determinateAndMonotonic && stageActiveAndSynced &&
                    friendlyPathFormatted && rawBytesHidden && resetInPreparing);
            }
            finally { CloseSummaryFixture(progressWindow); }
        }
        finally
        {
            if (Directory.Exists(tempRoot)) Directory.Delete(tempRoot, recursive: true);
        }
    }

    private sealed class P2CInlineProgress(Action<ScanProgress> callback) : IProgress<ScanProgress>
    {
        public void Report(ScanProgress value) => callback(value);
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
