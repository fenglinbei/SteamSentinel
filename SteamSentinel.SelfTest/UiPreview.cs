using System.IO;
using System.Reflection;
using System.Text.Json;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using SteamSentinel.App;
using SteamSentinel.App.Dialogs;
using SteamSentinel.App.Services;
using SteamSentinel.Core.Models;
using SteamSentinel.Core.Utilities;

namespace SteamSentinel.SelfTest;

internal static class UiPreview
{
    public static int Render(string output)
    {
        Exception? failure = null;
        Thread thread = new(() =>
        {
            try
            {
                Directory.CreateDirectory(output);
                SteamSentinel.App.App app = new();
                app.InitializeComponent();
                ArchivePasswordRequest request = new("preview", "C:\\示例内容\\外层加密包.rar!/" +
                    string.Concat(Enumerable.Repeat("较长的成员目录/", 16)) + "内部加密包.zip",
                    new string('A', 64), "ZIP 压缩包", 2, null, "已尝试本次暂存且适用的密码，仍未解开这一层。内层可能使用不同密码，也不能排除内容损坏或格式兼容问题。",
                    ArchivePasswordReuseScope.Session, ArchivePasswordPromptKind.CachedPasswordFailed);
                foreach ((string name, int width, int height) in new[] { ("password-normal", 596, 554), ("password-small", 420, 340) })
                {
                    PasswordDialog dialog = new(request);
                    Capture(dialog, name, width, height, output);
                }
                MainWindow window = new();
                ScanReport report = new() { Coverage = ScanCoverage.Partial };
                report.Findings.Add(new Finding { IsKnownMalware = true, Severity = FindingSeverity.Critical });
                typeof(MainWindow).GetMethod("UpdateSummary", BindingFlags.Instance | BindingFlags.NonPublic)!.Invoke(window, [report]);
                Capture(window, "main-partial-threat", 980, 680, output);
                Capture(window, "main-small-workarea", 940, 500, output);
                foreach ((int width, int height) in UiLayoutFixtures.Viewports)
                {
                    MainWindow populated = UiLayoutFixtures.CreateThreatWindow();
                    string viewport = $"{width}x{height}";
                    Capture(populated, "layout-risk-" + viewport, width, height, output);
                    ((TabControl)populated.FindName("ResultTabs")).SelectedIndex = 1;
                    Capture(populated, "layout-coverage-" + viewport, width, height, output);
                    ((TabControl)populated.FindName("ResultTabs")).SelectedIndex = 2;
                    Capture(populated, "layout-results-" + viewport, width, height, output);
                    ((TabControl)populated.FindName("MainTabs")).SelectedIndex = 1;
                    Capture(populated, "layout-quarantine-" + viewport, width, height, output);
                    populated.Close();
                }
                foreach ((int width, int height) in new[] { (1148, 780), (784, 460) })
                {
                    MainWindow information = new();
                    UiLayoutFixtures.PopulateInformationWindow(information);
                    Capture(information, $"visual-information-{width}x{height}", width, height, output);
                    ((TabControl)information.FindName("ResultTabs")).SelectedIndex = 1;
                    Capture(information, $"visual-coverage-{width}x{height}", width, height, output);
                    ((TabControl)information.FindName("MainTabs")).SelectedIndex = 1;
                    Capture(information, $"visual-quarantine-{width}x{height}", width, height, output);
                    information.Close();
                }
                foreach ((int width, int height) in new[] { (760, 520), (600, 420), (440, 360) })
                {
                    RemediationPreviewWindow longPreview = new(UiLayoutFixtures.CreateBatch());
                    ((TabControl)longPreview.FindName("PreviewTabs")).SelectedIndex = 0;
                    ((DataGrid)longPreview.FindName("PreviewActionsGrid")).SelectedIndex = 0;
                    Capture(longPreview, $"layout-preview-{width}x{height}", width, height, output);
                    ((TabControl)longPreview.FindName("PreviewTabs")).SelectedIndex = 1;
                    ((DataGrid)longPreview.FindName("PreviewOmittedGrid")).SelectedIndex = 0;
                    Capture(longPreview, $"layout-preview-omitted-{width}x{height}", width, height, output);
                    longPreview.Close();
                }
                PasswordDialog longPassword = new(UiLayoutFixtures.CreatePasswordRequest());
                Capture(longPassword, "layout-password-420x340", 420, 340, output);
                ((Expander)longPassword.FindName("PasswordDetailsExpander")).IsExpanded = true;
                Capture(longPassword, "layout-password-expanded-420x340", 420, 340, output);
                longPassword.Close();
                MainWindow coverageWindow = new();
                ScanReport coverageReport = new() { Mode = ScanMode.Quick, Coverage = ScanCoverage.Partial, CompletedAtUtc = DateTimeOffset.UtcNow };
                for (int i = 0; i < 6500; i++) coverageReport.Findings.Add(new()
                {
                    RuleId = "QUICK-MEDIA-STRUCTURE",
                    Category = FindingCategory.Coverage,
                    Target = @"C:\示例内容\视频" + i + ".mp4",
                    Description = "视频已检查格式、顶层结构与尾随数据，未做整文件哈希比对。"
                });
                coverageReport.Findings.Add(new()
                {
                    RuleId = "ARCHIVE-PASSWORD-FAILED",
                    Category = FindingCategory.Coverage,
                    Target = @"C:\示例内容\压缩包.rar",
                    Description = "内层密码未能解开，尚未读取内部内容。"
                });
                typeof(MainWindow).GetField("_lastReport", BindingFlags.Instance | BindingFlags.NonPublic)!.SetValue(coverageWindow, coverageReport);
                typeof(MainWindow).GetMethod("PopulateFindings", BindingFlags.Instance | BindingFlags.NonPublic)!.Invoke(coverageWindow, [coverageReport]);
                typeof(MainWindow).GetMethod("UpdateSummary", BindingFlags.Instance | BindingFlags.NonPublic)!.Invoke(coverageWindow, [coverageReport]);
                ApplyAccessState(coverageWindow, InstallationSecurityStatus.Protected, new(false, true));
                Capture(coverageWindow, "quick-scope-complete", 980, 720, output);
                ((TabControl)coverageWindow.FindName("ResultTabs")).SelectedIndex = 1;
                Capture(coverageWindow, "quick-coverage-groups", 980, 720, output);
                ((DataGrid)coverageWindow.FindName("CoverageGrid")).SelectedIndex = 1;
                Capture(coverageWindow, "quick-encrypted-next-step", 1180, 830, output);
                string previewTarget = @"C:\Users\用户\AppData\Local\ServiceApp\示例文件.exe";
                RemediationPlan previewPlan = new()
                {
                    Actions =
                    [
                        new() { Type = RemediationActionType.StopProcess, Target = previewTarget, RelatedFilePath = previewTarget,
                            DisplayName = "停止已核实的关联进程", ConfidenceScore = 90, ExpectedSha256 = new string('A', 64) },
                        new() { Type = RemediationActionType.RemoveRegistryValue, Target = "示例启动项", RelatedFilePath = previewTarget,
                            DisplayName = "移除关联启动入口", ConfidenceScore = 90 },
                        new() { Type = RemediationActionType.QuarantineFile, Target = previewTarget,
                            DisplayName = "隔离关联文件", ConfidenceScore = 90, ExpectedSha256 = new string('A', 64) }
                    ]
                };
                RemediationPreviewWindow relationPreview = new(previewPlan,
                    ["这里只展示无害的界面测试数据，没有读取或处置对应路径。", "按关联目标分组展示，执行顺序以管理员组件核对后的方案为准。"]);
                Capture(relationPreview, "remediation-related-preview", 820, 600, output);
                RemediationBatchSession batch = new()
                {
                    Plans = [previewPlan, new() { Actions = [new() { Type = RemediationActionType.QuarantineFile, Target = @"C:\示例内容\第二份文件.zip", DisplayName = "隔离文件", ConfidenceScore = 95 }] }],
                    Targets = [new() { Target = previewTarget, Status = "已完成", ActionIds = [previewPlan.Actions[0].ActionId], Reason = "所选动作已执行并完成目标核验，不代表整台电脑安全。" },
                        new() { Target = @"C:\示例内容\第二份文件.zip", Status = "尚未执行", ActionIds = [Guid.NewGuid()], Reason = "后续批次已暂停，没有执行。" },
                        new() { Target = @"C:\示例内容\较长目录\本次扫描后已经变化的文件.zip", Status = "未处理", MissingActions = ["inert"], Reason = "文件在扫描后发生变化，未纳入处置，请重新扫描。" }],
                    Notes = ["只展示无害界面示例，没有读取或处置这些路径。"]
                };
                RemediationPreviewWindow batchPreview = new(batch);
                Capture(batchPreview, "batch-omissions", 820, 600, output);
                ((TabControl)batchPreview.FindName("PreviewTabs")).SelectedIndex = 0;
                Capture(batchPreview, "batch-actions", 820, 600, output);
                batch.ExecutionStarted = true;
                MainWindow batchWindow = new(); ApplyAccessState(batchWindow, InstallationSecurityStatus.Protected, new(true, true));
                typeof(MainWindow).GetField("_caseBatch", BindingFlags.Instance | BindingFlags.NonPublic)!.SetValue(batchWindow, batch);
                typeof(MainWindow).GetMethod("UpdateBatchResults", BindingFlags.Instance | BindingFlags.NonPublic)!.Invoke(batchWindow, null);
                ((TextBlock)batchWindow.FindName("BatchFollowUpText")).Text = "原扫描范围：仍有可处置项，尚未全部清除。\n系统与 Steam：Windows 安全防护未完全开启，这是配置提示，不是样本复活。";
                ((TabControl)batchWindow.FindName("ResultTabs")).SelectedIndex = 2;
                Capture(batchWindow, "batch-outcomes", 980, 720, output);
                MainWindow failedWindow = new();
                typeof(MainWindow).GetMethod("PreserveScanFailure", BindingFlags.Instance | BindingFlags.NonPublic)!.Invoke(failedWindow,
                    [new ScanReport { Mode = ScanMode.Quick, Metrics = new ScanMetrics { ProcessesVisited = 7 } },
                     ScanMode.Quick, Array.Empty<string>(),
                     new WorkerFailureException(WorkerStage.Handshake, unchecked((int)0xC0000142), "扫描组件在安全握手前关闭了输出通道，未发送扫描路径。"), false]);
                ApplyAccessState(failedWindow, InstallationSecurityStatus.Protected, new ElevationContext(true, true));
                Capture(failedWindow, "main-worker-failed", 980, 680, output);
                foreach ((string name, InstallationSecurityStatus status, ElevationContext context) in new[]
                {
                    ("access-normal", InstallationSecurityStatus.Protected, new ElevationContext(false, true)),
                    ("access-standard", InstallationSecurityStatus.Protected, new ElevationContext(false, false)),
                    ("access-administrator", InstallationSecurityStatus.Protected, new ElevationContext(true, true)),
                    ("access-unsafe", new InstallationSecurityStatus(false, "安装对象允许非受信任账户写入：SteamSentinel.Core.dll"), new ElevationContext(false, true))
                })
                {
                    MainWindow accessWindow = new();
                    ScanReport accessReport = new() { Coverage = ScanCoverage.Partial };
                    accessReport.Findings.Add(new Finding
                    {
                        Title = "示例检测项（仅界面预览）",
                        Description = "这是用于核对布局的无害示例，不是实际扫描结果。",
                        Target = "C:\\示例内容\\样例.zip",
                        CanRemediate = true,
                        Severity = FindingSeverity.Critical,
                        IsKnownMalware = true,
                        Sha256 = new string('A', 64)
                    });
                    typeof(MainWindow).GetField("_lastReport", BindingFlags.Instance | BindingFlags.NonPublic)!.SetValue(accessWindow, accessReport);
                    typeof(MainWindow).GetMethod("PopulateFindings", BindingFlags.Instance | BindingFlags.NonPublic)!.Invoke(accessWindow, [accessReport]);
                    ApplyAccessState(accessWindow, status, context);
                    Capture(accessWindow, name, 980, 680, output);
                }
                foreach (MainWindow.ActivityPhase phase in new[] { MainWindow.ActivityPhase.Preparing,
                    MainWindow.ActivityPhase.Confirmation, MainWindow.ActivityPhase.Applying, MainWindow.ActivityPhase.FollowUp, MainWindow.ActivityPhase.ContentFollowUp })
                {
                    MainWindow active = new();
                    ApplyAccessState(active, InstallationSecurityStatus.Protected, new(true, true));
                    typeof(MainWindow).GetMethod("SetBusy", BindingFlags.Instance | BindingFlags.NonPublic)!.Invoke(active, [true]);
                    active.ShowActivity(phase);
                    Capture(active, "activity-" + phase.ToString().ToLowerInvariant(), 980, 720, output);
                }
                foreach (MainWindow created in app.Windows.OfType<MainWindow>().ToArray())
                    typeof(MainWindow).GetMethod("SetBusy", BindingFlags.Instance | BindingFlags.NonPublic)!.Invoke(created, [false]);
                app.Shutdown();
            }
            catch (Exception ex) { failure = ex; }
        });
        thread.SetApartmentState(ApartmentState.STA);
        thread.Start();
        thread.Join();
        if (failure is not null) throw new InvalidOperationException("UI preview failed", failure);
        Console.WriteLine("UI_PREVIEW_OK");
        return 0;
    }

    internal static void ApplyAccessState(MainWindow window, InstallationSecurityStatus status, ElevationContext context)
    {
        const BindingFlags flags = BindingFlags.Instance | BindingFlags.NonPublic;
        typeof(MainWindow).GetField("_installationSecurity", flags)!.SetValue(window, status);
        typeof(MainWindow).GetField("_elevationContext", flags)!.SetValue(window, context);
        typeof(MainWindow).GetMethod("SetBusy", flags)!.Invoke(window, [false]);
        typeof(MainWindow).GetMethod("ApplyInstallationSecurityStatus", flags)!.Invoke(window, null);
    }

    private static void Capture(Window window, string name, int width, int height, string output)
    {
        using UiLayoutHarness layout = new(window, width, height);
        layout.Save(name, output);
    }
}
