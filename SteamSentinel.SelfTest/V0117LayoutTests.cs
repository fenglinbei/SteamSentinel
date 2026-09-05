using System.Globalization;
using System.IO;
using System.Reflection;
using System.Text.Json;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;
using System.Windows.Documents;
using System.Windows.Interop;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Threading;
using SteamSentinel.App;
using SteamSentinel.App.Dialogs;
using SteamSentinel.App.ViewModels;
using SteamSentinel.Core.Models;
using SteamSentinel.Core.Utilities;

namespace SteamSentinel.SelfTest;

internal static partial class Program
{
    // Reuse TestV016Dialog's STA/Application. WPF allows only one Application per process.
    private static int RunV0117LayoutUi(string output)
    {
        output = Path.GetFullPath(output);
        Directory.CreateDirectory(output);
        Exception? error = null;
        Thread thread = new(() =>
        {
            SteamSentinel.App.App? app = null;
            try
            {
                app = new();
                app.InitializeComponent();
                app.ShutdownMode = ShutdownMode.OnExplicitShutdown;
                TestV0117Layout(output);
            }
            catch (Exception ex) { error = ex; }
            finally { app?.Shutdown(); }
        });
        thread.SetApartmentState(ApartmentState.STA);
        thread.Start();
        thread.Join();
        if (error is not null) Failures.Add("UI 布局测试异常：" + error);
        File.WriteAllText(Path.Combine(output, "layout-test-results.json"), JsonSerializer.Serialize(new
        {
            passed = _passed,
            failed = Failures.Count,
            failures = Failures,
            buildIdentity = ProductInfo.BuildIdentity,
            completedAtUtc = DateTimeOffset.UtcNow,
            safety = "Only synthetic WPF UI fixtures; no scan, remediation, installation, or sample execution."
        }, new JsonSerializerOptions { WriteIndented = true }));
        foreach (string failure in Failures) Console.WriteLine("FAIL: " + failure);
        Console.WriteLine($"UI 布局验证：通过 {_passed}，失败 {Failures.Count}。" + (Failures.Count == 0 ? " UI_LAYOUT_OK" : string.Empty));
        return Failures.Count == 0 ? 0 : 1;
    }

    private static void TestV0117Layout(string? output = null)
    {
        Check("UI 布局回归使用真实应用资源", Application.Current is SteamSentinel.App.App &&
            Application.Current.TryFindResource(typeof(Button)) is Style);
        foreach ((int width, int height) in UiLayoutFixtures.Viewports)
        {
            MainWindow window = new();
            using (UiLayoutHarness layout = new(window, width, height))
            {
                // Match the real workflow: the empty table is already on screen when scan results arrive.
                UiLayoutFixtures.PopulateThreatWindow(window);
                layout.Refresh();
                string size = $"{width}x{height}";
                FrameworkElement header = (FrameworkElement)window.FindName("HeaderCard");
                Check($"UI {size} 顶栏高度紧凑", header.ActualHeight is >= 48 and <= 92);
                Check($"UI {size} 扫描入口无需整页滚动", UiLayoutFixtures.ScanButtons.All(name =>
                    layout.IsFullyVisible((FrameworkElement)window.FindName(name)) &&
                    !layout.HasScrollingAncestor((FrameworkElement)window.FindName(name))));
                Check($"UI {size} 报告与处置按钮完整可见且不重叠", UiLayoutFixtures.ResultButtons.All(name =>
                    layout.IsFullyVisible((FrameworkElement)window.FindName(name)) &&
                    !layout.HasScrollingAncestor((FrameworkElement)window.FindName(name))) &&
                    layout.DoNotOverlap(UiLayoutFixtures.ResultButtons.Select(name => (FrameworkElement)window.FindName(name))));
                DataGrid findings = (DataGrid)window.FindName("FindingsGrid");
                Check($"UI {size} 92 条长路径风险表完整布局", findings.Items.Count == 92 &&
                    findings.ActualHeight >= 80 && layout.HasReadableColumns(findings));
                Check($"UI {size} 风险行已真实生成且保留纵向浏览", UiLayoutHarness.Descendants<DataGridRow>(findings).Any() &&
                    UiLayoutHarness.Descendants<ScrollViewer>(findings).Any(viewer => viewer.ScrollableHeight > 0));
                DataGridRow? first = findings.ItemContainerGenerator.ContainerFromIndex(0) as DataGridRow;
                Check($"UI {size} 风险严重度分类和分数实际绑定可读", first is not null &&
                    ((TextBlock?)findings.Columns[1].GetCellContent(first))?.Text == window.Findings[0].Severity &&
                    ((TextBlock?)findings.Columns[2].GetCellContent(first))?.Text == window.Findings[0].Category &&
                    ((TextBlock?)findings.Columns[3].GetCellContent(first))?.Text == "100");
                Check($"UI {size} 默认至少完整显示第一条风险摘要", first is not null && layout.IsFullyVisible(first));
                if (output is not null) layout.Save("layout-risk-" + size, output);
                findings.SelectedIndex = 45;
                findings.ScrollIntoView(findings.SelectedItem);
                layout.Refresh();
                Check($"UI {size} 动态填充及切换风险行不会把列压缩到最小宽", layout.HasReadableColumns(findings));
                if (output is not null) layout.Save("layout-risk-selected-" + size, output);
                findings.SelectedIndex = 0;
                findings.ScrollIntoView(findings.SelectedItem);
                layout.Refresh();
                ((Expander)window.FindName("FindingDetailCard")).IsExpanded = true;
                layout.Refresh();
                Check($"UI {size} 展开证据不会遮挡操作栏", UiLayoutFixtures.ResultButtons.All(name => layout.IsFullyVisible((FrameworkElement)window.FindName(name))) && findings.ActualHeight >= 48);
                if (output is not null) layout.Save("layout-details-" + size, output);
                ((Expander)window.FindName("FindingDetailCard")).IsExpanded = false;
                ((Expander)window.FindName("ScanOptionsExpander")).IsExpanded = true;
                layout.Refresh();
                Check($"UI {size} 展开扫描选项仍可扫描导出和处置", UiLayoutFixtures.ScanButtons.Concat(UiLayoutFixtures.ResultButtons).All(name =>
                    layout.IsFullyVisible((FrameworkElement)window.FindName(name))) && findings.ActualHeight >= 48);
                if (output is not null) layout.Save("layout-options-" + size, output);
                ((Expander)window.FindName("ScanOptionsExpander")).IsExpanded = false;
                TabControl results = (TabControl)window.FindName("ResultTabs");
                results.SelectedIndex = 1;
                layout.Refresh();
                DataGrid coverage = (DataGrid)window.FindName("CoverageGrid");
                Check($"UI {size} 未检查内容标题与补查按钮可见", coverage.ActualHeight >= 48 &&
                    layout.HasReadableColumns(coverage) && layout.IsFullyVisible((FrameworkElement)window.FindName("CoverSelectedButton")) &&
                    layout.IsFullyVisible((FrameworkElement)window.FindName("ExportButton")));
                if (output is not null) layout.Save("layout-coverage-" + size, output);
                results.SelectedIndex = 2;
                layout.Refresh();
                DataGrid batch = (DataGrid)window.FindName("BatchResultsGrid");
                Check($"UI {size} 处置结果表保留阅读空间", batch.Items.Count > 0 && batch.ActualHeight >= 48 && layout.HasReadableColumns(batch));
                Check($"UI {size} 处置结果复查详情与导出入口固定可见", layout.IsFullyVisible((FrameworkElement)window.FindName("FollowUpDetailsButton")) &&
                    layout.IsFullyVisible((FrameworkElement)window.FindName("ExportButton")));
                if (output is not null) layout.Save("layout-results-" + size, output);
                batch.SelectedIndex = batch.Items.Count - 1;
                batch.ScrollIntoView(batch.SelectedItem);
                layout.Refresh();
                ScrollViewer batchScroll = UiLayoutHarness.Descendants<ScrollViewer>(batch).First();
                for (int pass = 0; pass < 2; pass++) { batchScroll.ScrollToBottom(); layout.Refresh(); }
                TextBlock? lastReason = batch.Columns[2].GetCellContent(batch.SelectedItem) as TextBlock;
                Check($"UI {size} 超长处置原因可用像素滚动阅读到最后一行", VirtualizingPanel.GetScrollUnit(batch) == ScrollUnit.Pixel &&
                    batchScroll.VerticalOffset >= batchScroll.ScrollableHeight - 2 &&
                    lastReason?.Text.EndsWith(UiLayoutFixtures.LongReasonEnd, StringComparison.Ordinal) == true);
                if (output is not null) layout.Save("layout-results-bottom-" + size, output);
                results.SelectedIndex = 0;
                typeof(MainWindow).GetMethod("SetBusy", BindingFlags.Instance | BindingFlags.NonPublic)!.Invoke(window, [true]);
                window.ShowActivity(MainWindow.ActivityPhase.Preparing);
                layout.Refresh();
                Check($"UI {size} 活动状态不覆盖扫描与处置按钮", UiLayoutFixtures.ScanButtons.Concat(UiLayoutFixtures.ResultButtons).All(name =>
                    layout.IsFullyVisible((FrameworkElement)window.FindName(name))) && findings.ActualHeight >= 48);
                if (output is not null) layout.Save("layout-activity-" + size, output);
                Expander activeOptions = (Expander)window.FindName("ScanOptionsExpander");
                if (activeOptions.IsEnabled) activeOptions.IsExpanded = true;
                layout.Refresh();
                Check($"UI {size} 活动期间展开选项仍保留有效结果行与按钮", UiLayoutFixtures.ScanButtons.Concat(UiLayoutFixtures.ResultButtons).All(name =>
                    layout.IsFullyVisible((FrameworkElement)window.FindName(name))) && findings.ActualHeight >= 48);
                if (output is not null) layout.Save("layout-activity-options-" + size, output);
                activeOptions.IsExpanded = false;
                ((TabControl)window.FindName("MainTabs")).SelectedIndex = 1;
                typeof(MainWindow).GetMethod("SetBusy", BindingFlags.Instance | BindingFlags.NonPublic)!.Invoke(window, [false]);
                layout.Refresh();
                Check($"UI {size} 活动中切换页面再完成后恢复顶部状态", header.Visibility == Visibility.Visible && layout.IsFullyVisible(header));
                DataGrid quarantine = (DataGrid)window.FindName("QuarantineGrid");
                Check($"UI {size} 隔离列表与回滚删除入口无横向溢出", quarantine.Items.Count > 0 &&
                    layout.HasReadableColumns(quarantine) && layout.IsFullyVisible((FrameworkElement)window.FindName("RollbackButton")) &&
                    layout.IsFullyVisible((FrameworkElement)window.FindName("DeleteIncidentButton")));
                if (output is not null) layout.Save("layout-quarantine-" + size, output);
            }
            window.Close();
        }
        MainWindow resized = UiLayoutFixtures.CreateThreatWindow();
        foreach ((int width, int height) in new[] { (1148, 780), (800, 500), (1148, 780) })
        {
            using UiLayoutHarness layout = new(resized, width, height);
            Check($"UI 同一窗口缩放到 {width}x{height} 后列宽和按钮位置恢复", layout.HasReadableColumns((DataGrid)resized.FindName("FindingsGrid")) &&
                UiLayoutFixtures.ScanButtons.Concat(UiLayoutFixtures.ResultButtons).All(name => layout.IsFullyVisible((FrameworkElement)resized.FindName(name))));
        }
        using (UiLayoutHarness layout = new(resized, 784, 460))
        {
            const BindingFlags flags = BindingFlags.Instance | BindingFlags.NonPublic;
            ScanReport noCoverage = (ScanReport)typeof(MainWindow).GetField("_lastReport", flags)!.GetValue(resized)!;
            noCoverage.Findings.RemoveAll(finding => finding.Category == FindingCategory.Coverage);
            typeof(MainWindow).GetMethod("PopulateFindings", flags)!.Invoke(resized, [noCoverage]);
            ((TabControl)resized.FindName("ResultTabs")).SelectedIndex = 1;
            layout.Refresh();
            Check("UI 空覆盖页不残留上一风险的路径与哈希", ((DataGrid)resized.FindName("CoverageGrid")).Items.Count == 0 &&
                !((TextBlock)resized.FindName("DetailEvidenceText")).Text.Contains(UiLayoutFixtures.LongPath, StringComparison.Ordinal) &&
                string.IsNullOrEmpty(((TextBlock)resized.FindName("DetailHashText")).Text));
            if (output is not null) layout.Save("layout-empty-coverage-784x460", output);
        }
        resized.Close();
        foreach ((int width, int height) in new[] { (760, 520), (600, 420), (440, 360) })
        {
            RemediationPreviewWindow preview = new(UiLayoutFixtures.CreateBatch());
            using (UiLayoutHarness layout = new(preview, width, height))
            {
                ((TabControl)preview.FindName("PreviewTabs")).SelectedIndex = 0;
                layout.Refresh();
                DataGrid grid = (DataGrid)preview.FindName("PreviewActionsGrid");
                grid.SelectedIndex = 0;
                layout.Refresh();
                Check($"UI 处置预览 {width}x{height} 确认与执行按钮不被长路径挤走", layout.IsFullyVisible((FrameworkElement)preview.FindName("ConfirmCheckBox")) &&
                    layout.IsFullyVisible((FrameworkElement)preview.FindName("ExecuteButton")) && grid.ActualHeight >= 48 && layout.HasReadableColumns(grid));
                if (output is not null) layout.Save($"layout-preview-{width}x{height}", output);
                ((TabControl)preview.FindName("PreviewTabs")).SelectedIndex = 1;
                grid = (DataGrid)preview.FindName("PreviewOmittedGrid");
                grid.SelectedIndex = 0;
                layout.Refresh();
                Check($"UI 处置预览 {width}x{height} 遗漏目标与原因有阅读区域", grid.Items.Count > 0 && grid.ActualHeight >= 48 &&
                    layout.HasReadableColumns(grid) && layout.IsFullyVisible((FrameworkElement)preview.FindName("ConfirmCheckBox")) &&
                    layout.IsFullyVisible((FrameworkElement)preview.FindName("ExecuteButton")));
                if (output is not null) layout.Save($"layout-preview-omitted-{width}x{height}", output);
            }
            preview.Close();
        }
        foreach ((int width, int height) in new[] { (596, 554), (420, 340) })
        {
            PasswordDialog password = new(UiLayoutFixtures.CreatePasswordRequest());
            using (UiLayoutHarness layout = new(password, width, height))
            {
                Check($"UI 密码窗口 {width}x{height} 输入与继续跳过按钮默认可见", layout.IsFullyVisible((FrameworkElement)password.FindName("PasswordInput")) &&
                    layout.IsFullyVisible((FrameworkElement)password.FindName("ContinuePasswordButton")) &&
                    layout.IsFullyVisible((FrameworkElement)password.FindName("SkipPasswordButton")));
                Check($"UI 密码窗口 {width}x{height} 三种密码复用范围默认均可见", new[] { "CurrentOnlyRadio", "ArchiveTreeRadio", "SessionRadio" }
                    .All(name => layout.IsFullyVisible((FrameworkElement)password.FindName(name))));
                if (output is not null) layout.Save($"layout-password-{width}x{height}", output);
                ((Expander)password.FindName("PasswordDetailsExpander")).IsExpanded = true;
                layout.Refresh();
                Check($"UI 密码窗口 {width}x{height} 长路径展开不遮挡底部操作", layout.IsFullyVisible((FrameworkElement)password.FindName("ContinuePasswordButton")) &&
                    layout.IsFullyVisible((FrameworkElement)password.FindName("SkipPasswordButton")));
                if (output is not null) layout.Save($"layout-password-expanded-{width}x{height}", output);
            }
            password.Close();
        }
        string longDetails = string.Concat(Enumerable.Repeat("这是一段无害的长诊断文本，用于验证完整说明可以滚动、选择和复制，不会启动扫描或执行任何处置。\n", 80)) + "UI-END-OF-LONG-TEXT";
        foreach ((int width, int height) in new[] { (740, 480), (420, 340) })
        {
            TextDetailsWindow details = new("完整复查说明 · 无害界面测试", longDetails);
            using (UiLayoutHarness layout = new(details, width, height))
            {
                TextBox body = (TextBox)details.FindName("DetailsTextBox");
                ScrollViewer bodyScroll = UiLayoutHarness.Descendants<ScrollViewer>(body).First();
                Check($"UI 长文本窗口 {width}x{height} 完整只读正文局部滚动且关闭复制固定可见", body.IsReadOnly && body.Text == longDetails &&
                    body.ActualHeight >= 100 && body.HorizontalScrollBarVisibility == ScrollBarVisibility.Disabled && bodyScroll.ScrollableHeight > 0 &&
                    layout.IsFullyVisible((FrameworkElement)details.FindName("CloseDetailsButton")) &&
                    layout.IsFullyVisible((FrameworkElement)details.FindName("CopyDetailsButton")));
                if (output is not null) layout.Save($"layout-text-details-{width}x{height}", output);
                body.CaretIndex = body.Text.Length;
                body.ScrollToEnd();
                layout.Refresh();
                Rect lastCharacter = body.GetRectFromCharacterIndex(body.Text.Length - 1);
                Check($"UI 长文本窗口 {width}x{height} 尾部说明可达", !lastCharacter.IsEmpty && lastCharacter.Top >= 0 &&
                    lastCharacter.Bottom <= body.ActualHeight + 1 && lastCharacter.Right <= body.ActualWidth + 1 &&
                    layout.IsFullyVisible((FrameworkElement)details.FindName("CloseDetailsButton")));
                if (output is not null) layout.Save($"layout-text-details-bottom-{width}x{height}", output);
            }
            details.Close();
        }
        TestV0119TableAndButtonConsistency(output);
        TestV0119Summary(output);
        TestV0119PasswordUi(output);
    }

    private static void TestV0119TableAndButtonConsistency(string? output)
    {
        foreach ((int width, int height) in new[] { (1148, 780), (784, 460) })
        {
            MainWindow window = new();
            using (UiLayoutHarness layout = new(window, width, height))
            {
                UiLayoutFixtures.PopulateInformationWindow(window);
                layout.Refresh();
                string size = $"{width}x{height}";
                DataGrid findings = (DataGrid)window.FindName("FindingsGrid");
                DataGridRow first = (DataGridRow)findings.ItemContainerGenerator.ContainerFromIndex(0);
                Check($"UI 表格 {size} 两条信息提示仍是不可处置的真实绑定", findings.Items.Count == 2 &&
                    window.Findings.All(finding => finding.Severity == "信息" && !finding.CanSelect) &&
                    !((Button)window.FindName("RemediateButton")).IsEnabled);
                Check($"UI 表格 {size} 单行风险行高为30至34像素", first.ActualHeight is >= 30 and <= 34);
                Check($"UI 表格 {size} 真实单元格保留左右8上下3像素留白", layout.CellsHaveRealPadding(findings));
                Check($"UI 表格 {size} 严重度分类分数与处置复选框居中", new[] { 1, 2, 3 }.All(column => layout.CellTextIsCentered(findings, 0, column)) &&
                    layout.CellCheckIsCentered(findings, 0, 0));
                Check($"UI 表格 {size} 发现和目标左对齐并垂直居中", new[] { 4, 5 }.All(column => layout.CellTextIsLeftAligned(findings, 0, column)));
                if (output is not null) layout.Save("visual-information-" + size, output);

                ((TabControl)window.FindName("ResultTabs")).SelectedIndex = 1;
                layout.Refresh();
                DataGrid coverage = (DataGrid)window.FindName("CoverageGrid");
                Check($"UI 表格 {size} 五类覆盖记录布局且操作栏可达", coverage.Items.Count == 5 && layout.HasReadableColumns(coverage) &&
                    layout.IsFullyVisible((Button)window.FindName("ExportButton")) && layout.IsFullyVisible((Button)window.FindName("CoverSelectedButton")));
                Check($"UI 表格 {size} 覆盖表真实留白与记录数居中", layout.CellsHaveRealPadding(coverage) && layout.CellTextIsCentered(coverage, 0, 1));
                Check($"UI 表格 {size} 覆盖原因和下一步左对齐且垂直居中", layout.CellTextIsLeftAligned(coverage, 0, 0) && layout.CellTextIsLeftAligned(coverage, 0, 2));
                if (output is not null) layout.Save("visual-coverage-" + size, output);

                ((TabControl)window.FindName("MainTabs")).SelectedIndex = 1;
                layout.Refresh();
                DataGrid quarantine = (DataGrid)window.FindName("QuarantineGrid");
                DataGridRow firstQuarantine = (DataGridRow)quarantine.ItemContainerGenerator.ContainerFromIndex(0);
                Check($"UI 表格 {size} 隔离表真实留白以及日期记录数重启居中", layout.CellsHaveRealPadding(quarantine) &&
                    layout.CellTextIsCentered(quarantine, 0, 1) && layout.CellTextIsCentered(quarantine, 0, 2) && layout.CellCheckIsCentered(quarantine, 0, 4));
                Check($"UI 表格 {size} 隔离事件和状态左对齐且行高紧凑", layout.CellTextIsLeftAligned(quarantine, 0, 0) &&
                    layout.CellTextIsLeftAligned(quarantine, 0, 3) && (width < 1000 || firstQuarantine.ActualHeight is >= 30 and <= 34));
                if (output is not null) layout.Save("visual-quarantine-" + size, output);
            }
            window.Close();
        }

        // Preserve the 0.1.18 control templates. This fixture tests only the requested button
        // contrast refinement and contains no scan, remediation, or other command handlers.
        Button enabled = new() { Content = "可以点击的次要操作", HorizontalAlignment = HorizontalAlignment.Left };
        Button disabled = new() { Content = "当前不可用的操作", IsEnabled = false, HorizontalAlignment = HorizontalAlignment.Left };
        Button primary = new() { Content = "主要操作", Style = (Style)Application.Current.FindResource("PrimaryButton"), HorizontalAlignment = HorizontalAlignment.Left };
        StackPanel panel = new() { Margin = new Thickness(16) };
        foreach (Button button in new[] { enabled, disabled, primary })
        {
            button.Margin = new Thickness(0, 0, 0, 8);
            panel.Children.Add(button);
        }
        Window controls = new() { Content = panel, FontFamily = new FontFamily("Microsoft YaHei UI, Segoe UI"), FontSize = 12, Background = Brushes.White };
        using (UiLayoutHarness layout = new(controls, 600, 180))
        {
            Border enabledSurface = (Border)enabled.Template.FindName("ButtonBorder", enabled);
            Border primarySurface = (Border)primary.Template.FindName("ButtonBorder", primary);
            Check("UI 按钮 可用按钮真实文字对比度至少4.5且描边至少3", UiLayoutHarness.Contrast(enabled.Foreground, enabledSurface.Background) >= 4.5 &&
                UiLayoutHarness.Contrast(enabledSurface.BorderBrush, enabledSurface.Background) >= 3 && enabled.Opacity >= 0.99 && enabledSurface.Opacity >= 0.99);
            Check("UI 按钮 主要按钮真实文字对比度至少4.5", UiLayoutHarness.Contrast(primary.Foreground, primarySurface.Background) >= 4.5);
            Check("UI 按钮 禁用态明显区别可用态且保留原有圆角", !disabled.IsEnabled && disabled.Cursor != System.Windows.Input.Cursors.Hand &&
                (disabled.Opacity < 0.9 || UiLayoutHarness.BrushColor(disabled.Foreground) != UiLayoutHarness.BrushColor(enabled.Foreground)) &&
                enabledSurface.CornerRadius == new CornerRadius(5));
            if (output is not null) layout.Save("visual-button-contrast", output);
        }
        controls.Close();
    }

}

internal static class UiLayoutFixtures
{
    internal static readonly (int Width, int Height)[] Viewports = [(1148, 780), (1024, 650), (900, 580), (800, 500), (784, 460)];
    internal static readonly string[] ScanButtons = ["QuickScanButton", "FullScanButton", "FileScanButton", "FolderScanButton", "RetryPasswordsButton", "CancelScanButton"];
    internal static readonly string[] ResultButtons = ["SelectAllButton", "ClearSelectionButton", "ExportButton", "ReviewFindingButton", "OccupancyButton", "RemediateButton"];
    private const BindingFlags Private = BindingFlags.Instance | BindingFlags.NonPublic;
    internal static readonly string LongPath = @"C:\Users\界面测试用户\Desktop\仅用于布局验证的无害示例资料\" +
        string.Concat(Enumerable.Repeat("较长目录名称\\", 8)) + "外层内容包.zip!/内部成员/示例文件.exe";
    internal const string LongReasonEnd = "UI-END-OF-LONG-RESULT-REASON";

    internal static MainWindow CreateThreatWindow()
    {
        MainWindow window = new();
        PopulateThreatWindow(window);
        return window;
    }

    internal static void PopulateInformationWindow(MainWindow window)
    {
        ScanReport report = new()
        {
            Mode = ScanMode.Quick,
            Coverage = ScanCoverage.Partial,
            CompletedAtUtc = DateTimeOffset.UtcNow,
            Metrics = new() { FilesVisited = 1541, WorkshopItemsVisited = 59 },
            Findings =
            [
                new() { RuleId = "UI-INERT-PROXY", Title = "检测到用户代理配置", Target = "127.0.0.1:7890", Category = FindingCategory.Network,
                    Severity = FindingSeverity.Information, Score = 5, Description = "代理本身不是恶意证据。这是无害界面示例，不是实际扫描结果。", Evidence = "界面测试：ProxyEnable=1; ProxyServer=127.0.0.1:7890" },
                new() { RuleId = "UI-INERT-HOSTS", Title = "已知 C2 已在 hosts 中阻断", Target = @"C:\WINDOWS\system32\drivers\etc\hosts", Category = FindingCategory.Network,
                    Severity = FindingSeverity.Information, Description = "只复现用户反馈中的单行表格布局，不读取或修改 hosts。" },
                new() { RuleId = "UI-INERT-READ", Category = FindingCategory.Coverage, Target = "本次扫描", Description = "无害界面示例：部分文件未读取。" },
                new() { RuleId = "UI-INERT-READ-2", Category = FindingCategory.Coverage, Target = "本次扫描", Description = "无害界面示例：部分进程已退出。" },
                new() { RuleId = "UI-INERT-AMSI", Category = FindingCategory.Coverage, Target = "本次扫描", Description = "AMSI 无害界面示例，不查询真实安全软件状态。" }
            ],
            CoverageAggregates =
            [
                new("QUICK-CONTENT-NOT-HASHED", @"C:\无害界面示例", 2, []),
                new("QUICK-MEDIA-STRUCTURE", @"C:\无害界面示例", 43, []),
                new("CONTENT-BYTE-BUDGET", @"C:\无害界面示例", 1144, [])
            ]
        };
        typeof(MainWindow).GetField("_lastReport", Private)!.SetValue(window, report);
        typeof(MainWindow).GetMethod("PopulateFindings", Private)!.Invoke(window, [report]);
        typeof(MainWindow).GetMethod("UpdateSummary", Private)!.Invoke(window, [report]);
        UiPreview.ApplyAccessState(window, InstallationSecurityStatus.Protected, new(true, true));
        for (int i = 0; i < 12; i++) window.QuarantineItems.Add(new QuarantineItemViewModel
        {
            ManifestPath = @"C:\无害界面示例\不会读取.json",
            Manifest = new()
            {
                IncidentId = Guid.Parse($"00000000-0000-0000-0000-{i + 1:D12}"),
                CreatedAtUtc = new DateTimeOffset(2026, 9, 5, 8, 0, 0, TimeSpan.Zero).AddDays(-i),
                Records = [new() { RolledBack = i % 2 == 0 }],
                MachineBootTimeUtc = i % 2 == 0 ? DateTimeOffset.UnixEpoch : DateTimeOffset.UtcNow.AddDays(1)
            }
        });
    }

    internal static void PopulateThreatWindow(MainWindow window)
    {
        ScanReport report = new()
        {
            Mode = ScanMode.Custom,
            Coverage = ScanCoverage.Partial,
            CompletedAtUtc = DateTimeOffset.UtcNow,
            Metrics = new() { FilesVisited = 9659, ArchiveEntriesVisited = 10513 }
        };
        for (int i = 0; i < 92; i++) report.Findings.Add(new()
        {
            RuleId = "UI-INERT-FIXTURE",
            Title = $"已知威胁界面示例 {i + 1:D2}（没有扫描或执行任何文件）",
            IsKnownMalware = true,
            Severity = FindingSeverity.Critical,
            Category = FindingCategory.File,
            Score = 100,
            CanRemediate = true,
            Target = LongPath + $"-{i:D2}",
            Sha256 = new string('A', 64),
            Description = "文件 SHA-256 与已确认规则完全一致。这是无害界面测试数据，不代表此电脑的真实扫描结果。",
            Evidence = "命中 UI-INERT-FIXTURE；内容位置：" + LongPath
        });
        report.Findings.Add(new()
        {
            RuleId = "QUICK-MEDIA-STRUCTURE",
            Category = FindingCategory.Coverage,
            Target = LongPath,
            Description = "视频已检查格式、顶层结构与尾随数据，未做整文件哈希比对。"
        });
        report.Findings.Add(new()
        {
            RuleId = "ARCHIVE-PASSWORD-FAILED",
            Category = FindingCategory.Coverage,
            Target = LongPath,
            Description = "内层密码未能解开，尚未读取内部内容。"
        });
        typeof(MainWindow).GetField("_lastReport", Private)!.SetValue(window, report);
        typeof(MainWindow).GetMethod("PopulateFindings", Private)!.Invoke(window, [report]);
        typeof(MainWindow).GetMethod("UpdateSummary", Private)!.Invoke(window, [report]);
        UiPreview.ApplyAccessState(window, InstallationSecurityStatus.Protected, new(true, true));
        RemediationBatchSession batch = CreateBatch();
        batch.ExecutionStarted = true;
        typeof(MainWindow).GetField("_caseBatch", Private)!.SetValue(window, batch);
        typeof(MainWindow).GetMethod("UpdateBatchResults", Private)!.Invoke(window, null);
        ((TextBlock)window.FindName("BatchFollowUpText")).Text = "原扫描范围：还有未处理项。\n系统与 Steam：这是只用于检验换行与阅读区域的界面示例，没有执行真实处置。";
        for (int i = 0; i < 12; i++) window.QuarantineItems.Add(new QuarantineItemViewModel
        {
            ManifestPath = @"C:\无害界面示例\不会读取.json",
            Manifest = new() { IncidentId = Guid.NewGuid(), CreatedAtUtc = DateTimeOffset.UtcNow.AddDays(-i), Records = [new() { RolledBack = i % 2 == 0 }] }
        });
    }

    internal static RemediationBatchSession CreateBatch()
    {
        RemediationPlan plan = new()
        {
            Actions = Enumerable.Range(1, 16).Select(i => new RemediationAction
            {
                Type = RemediationActionType.QuarantineFile,
                Target = LongPath + "-" + i,
                DisplayName = "隔离经过核验的关联文件；仅为界面布局示例",
                ConfidenceScore = 100,
                ExpectedSha256 = new string('A', 64)
            }).ToList()
        };
        return new()
        {
            Plans = [plan],
            Targets = plan.Actions.Select((action, i) => new RemediationTargetOutcome
            {
                Target = action.Target,
                Status = i % 2 == 0 ? "已完成" : "尚未执行",
                ActionIds = [action.ActionId],
                MissingActions = i % 4 == 0 ? ["inert omitted action"] : [],
                Reason = i == 15 ? string.Concat(Enumerable.Repeat("这是超过六百字的无害处置结果说明，需要确认每一行都可通过表格内滚动读到。", 24)) + "\n" + LongReasonEnd :
                    "这是无害测试数据；用于确认较长的目标路径与结果说明不会挤压列宽或覆盖底部操作按钮。"
            }).ToList(),
            Notes = ["只展示无害的界面示例，不读取、扫描或处置所列路径。", string.Concat(Enumerable.Repeat("较长的计划说明，仍须保留确认按钮与列表可读区域。", 12))]
        };
    }

    internal static ArchivePasswordRequest CreatePasswordRequest() => new("layout-inert", LongPath,
        new string('A', 64), "ZIP 压缩包", 2, null,
        string.Concat(Enumerable.Repeat("已尝试本次暂存且适用的密码，仍未解开这一层。可能需要不同密码，也可能是内容损坏或格式兼容问题。", 8)),
        ArchivePasswordReuseScope.Session, ArchivePasswordPromptKind.CachedPasswordFailed);
}

internal sealed class UiLayoutHarness : IDisposable
{
    private readonly Window _window;
    private readonly FrameworkElement _content;
    private readonly HwndSource _source;
    private readonly int _width;
    private readonly int _height;
    internal Border Root { get; }

    internal UiLayoutHarness(Window window, int width, int height)
    {
        _window = window;
        _width = width;
        _height = height;
        _content = (FrameworkElement)window.Content;
        window.Content = null;
        Root = new Border
        {
            Width = width,
            Height = height,
            Background = window.Background ?? Brushes.White,
            Resources = window.Resources,
            DataContext = window.DataContext,
            UseLayoutRounding = window.UseLayoutRounding,
            SnapsToDevicePixels = window.SnapsToDevicePixels,
            FlowDirection = window.FlowDirection,
            Language = window.Language,
            Child = _content
        };
        TextElement.SetFontFamily(Root, window.FontFamily);
        TextElement.SetFontSize(Root, window.FontSize);
        TextElement.SetForeground(Root, window.Foreground);
        // A hidden native presentation source activates actual WPF templates/styles without
        // showing MainWindow, firing its Loaded handler, scanning or opening machine state.
        _source = new HwndSource(new HwndSourceParameters("SteamSentinel harmless UI layout fixture")
        {
            Width = width,
            Height = height,
            PositionX = -32000,
            PositionY = -32000,
            WindowStyle = unchecked((int)0x80000000)
        });
        _source.RootVisual = Root;
        Refresh();
    }

    internal void Refresh()
    {
        for (int pass = 0; pass < 3; pass++)
        {
            Root.Measure(new Size(_width, _height));
            Root.Arrange(new Rect(0, 0, _width, _height));
            foreach (Control control in Descendants<Control>(Root).ToArray()) control.ApplyTemplate();
            Root.UpdateLayout();
            Root.Dispatcher.Invoke(() => { }, DispatcherPriority.ContextIdle);
        }
    }

    internal Rect Bounds(FrameworkElement element) => element.TransformToAncestor(Root).TransformBounds(new Rect(element.RenderSize));

    internal bool CellsHaveRealPadding(DataGrid grid)
    {
        DataGridCell[] cells = Descendants<DataGridCell>(grid).Where(cell => cell.ActualWidth > 0 && cell.ActualHeight > 0).ToArray();
        return cells.Length >= grid.Columns.Count && cells.All(cell =>
        {
            if (cell.Template.FindName("CellContent", cell) is not ContentPresenter content) return false;
            Rect inner = content.TransformToAncestor(cell).TransformBounds(new Rect(content.RenderSize));
            return inner.Left >= 7.9 && cell.ActualWidth - inner.Right >= 7.9 &&
                inner.Top >= 2.9 && cell.ActualHeight - inner.Bottom >= 2.9;
        });
    }

    internal bool CellTextIsCentered(DataGrid grid, int rowIndex, int columnIndex)
    {
        if (CellContent(grid, rowIndex, columnIndex) is not TextBlock text || ParentCell(text) is not DataGridCell cell) return false;
        Rect content = text.TransformToAncestor(cell).TransformBounds(new Rect(text.RenderSize));
        return text.TextAlignment == TextAlignment.Center && Math.Abs(content.Left + content.Width / 2 - cell.ActualWidth / 2) <= 1.1 &&
            Math.Abs(content.Top + content.Height / 2 - cell.ActualHeight / 2) <= 1.1;
    }

    internal bool CellTextIsLeftAligned(DataGrid grid, int rowIndex, int columnIndex)
    {
        if (CellContent(grid, rowIndex, columnIndex) is not TextBlock text || ParentCell(text) is not DataGridCell cell) return false;
        Rect content = text.TransformToAncestor(cell).TransformBounds(new Rect(text.RenderSize));
        return text.TextAlignment == TextAlignment.Left && content.Left >= 7.9 && content.Left <= 10 &&
            Math.Abs(content.Top + content.Height / 2 - cell.ActualHeight / 2) <= 1.1;
    }

    internal bool CellCheckIsCentered(DataGrid grid, int rowIndex, int columnIndex)
    {
        FrameworkElement? content = CellContent(grid, rowIndex, columnIndex);
        CheckBox? check = content as CheckBox ?? Descendants<CheckBox>(content).FirstOrDefault();
        if (check is null || ParentCell(check) is not DataGridCell cell) return false;
        Rect glyph = check.TransformToAncestor(cell).TransformBounds(new Rect(check.RenderSize));
        return Math.Abs(glyph.Left + glyph.Width / 2 - cell.ActualWidth / 2) <= 1.1 &&
            Math.Abs(glyph.Top + glyph.Height / 2 - cell.ActualHeight / 2) <= 1.1;
    }

    private static FrameworkElement? CellContent(DataGrid grid, int rowIndex, int columnIndex) =>
        grid.ItemContainerGenerator.ContainerFromIndex(rowIndex) is DataGridRow row ? grid.Columns[columnIndex].GetCellContent(row) : null;

    private static DataGridCell? ParentCell(DependencyObject element)
    {
        for (DependencyObject? current = element; current is not null; current = VisualTreeHelper.GetParent(current))
            if (current is DataGridCell cell) return cell;
        return null;
    }

    internal static Color BrushColor(Brush brush) => brush is SolidColorBrush solid ? solid.Color : Colors.Transparent;

    internal static double Contrast(Brush foreground, Brush background)
    {
        static double Luminance(Color color)
        {
            static double Linear(byte channel)
            {
                double value = channel / 255d;
                return value <= 0.04045 ? value / 12.92 : Math.Pow((value + 0.055) / 1.055, 2.4);
            }
            return 0.2126 * Linear(color.R) + 0.7152 * Linear(color.G) + 0.0722 * Linear(color.B);
        }
        double first = Luminance(BrushColor(foreground)), second = Luminance(BrushColor(background));
        return (Math.Max(first, second) + 0.05) / (Math.Min(first, second) + 0.05);
    }

    internal bool IsFullyVisible(FrameworkElement element)
    {
        if (element.Visibility != Visibility.Visible || element.ActualWidth < 1 || element.ActualHeight < 1) return false;
        Rect bounds = Bounds(element);
        if (bounds.Left < -1 || bounds.Top < -1 || bounds.Right > _width + 1 || bounds.Bottom > _height + 1) return false;
        for (DependencyObject? ancestor = VisualTreeHelper.GetParent(element); ancestor is not null && ancestor != Root;
             ancestor = VisualTreeHelper.GetParent(ancestor))
        {
            if (ancestor is not FrameworkElement parent) continue;
            if (parent.Visibility != Visibility.Visible) return false;
            if (!parent.ClipToBounds && parent is not ScrollContentPresenter) continue;
            Rect clipping = Bounds(parent);
            clipping.Inflate(1, 1);
            if (!clipping.Contains(bounds)) return false;
        }
        return true;
    }

    internal bool DoNotOverlap(IEnumerable<FrameworkElement> elements)
    {
        Rect[] boxes = elements.Select(Bounds).ToArray();
        return boxes.SelectMany((left, index) => boxes.Skip(index + 1).Select(right => Rect.Intersect(left, right)))
            .All(overlap => overlap.IsEmpty || overlap.Width < 1 || overlap.Height < 1);
    }

    internal bool HasScrollingAncestor(FrameworkElement element)
    {
        for (DependencyObject? ancestor = VisualTreeHelper.GetParent(element); ancestor is not null && ancestor != Root;
             ancestor = VisualTreeHelper.GetParent(ancestor))
            if (ancestor is ScrollViewer viewer && (viewer.VerticalScrollBarVisibility != ScrollBarVisibility.Disabled ||
                viewer.HorizontalScrollBarVisibility != ScrollBarVisibility.Disabled)) return true;
        return false;
    }

    internal bool HasReadableColumns(DataGrid grid)
    {
        DataGridColumnHeader[] headers = Descendants<DataGridColumnHeader>(grid).Where(header => header.Column is not null).ToArray();
        double totalWidth = grid.Columns.Sum(column => column.ActualWidth);
        if (headers.Length != grid.Columns.Count || totalWidth > grid.ActualWidth + 1) return false;
        ScrollViewer? viewport = Descendants<ScrollViewer>(grid).FirstOrDefault();
        if (grid.Columns.Any(column => column.Width.IsStar) && viewport is not null && Math.Abs(totalWidth - viewport.ViewportWidth) > 2) return false;
        foreach (DataGridColumnHeader header in headers)
        {
            FormattedText label = new(header.Content?.ToString() ?? string.Empty, CultureInfo.CurrentUICulture,
                FlowDirection.LeftToRight, new Typeface(header.FontFamily, header.FontStyle, header.FontWeight, header.FontStretch),
                header.FontSize, Brushes.Black, VisualTreeHelper.GetDpi(header).PixelsPerDip);
            if (header.ActualWidth < Math.Max(32, label.Width + 10) || !IsFullyVisible(header)) return false;
        }
        return Descendants<ScrollViewer>(grid).All(viewer => viewer.ScrollableWidth <= 1);
    }

    internal object Describe() => new
    {
        width = _width,
        height = _height,
        buttons = Descendants<Button>(Root).Select(button => new
        {
            button.Name,
            content = button.Content?.ToString(),
            bounds = Bounds(button).ToString(CultureInfo.InvariantCulture),
            fullyVisible = IsFullyVisible(button),
            button.IsEnabled,
            button.Opacity,
            foreground = BrushColor(button.Foreground).ToString(),
            background = BrushColor(button.Background).ToString()
        }).ToArray(),
        passwordScopes = Descendants<RadioButton>(Root).Select(radio => new
        {
            radio.Name,
            radio.IsChecked,
            bounds = Bounds(radio).ToString(CultureInfo.InvariantCulture),
            fullyVisible = IsFullyVisible(radio)
        }).ToArray(),
        tables = Descendants<DataGrid>(Root).Select(grid => new
        {
            grid.Name,
            grid.ActualWidth,
            grid.ActualHeight,
            count = grid.Items.Count,
            readableColumns = HasReadableColumns(grid),
            firstRowHeight = (grid.ItemContainerGenerator.ContainerFromIndex(0) as DataGridRow)?.ActualHeight,
            firstRowFullyVisible = grid.ItemContainerGenerator.ContainerFromIndex(0) is DataGridRow row && IsFullyVisible(row),
            realCellPadding = CellsHaveRealPadding(grid),
            columns = grid.Columns.Select(column => new { label = column.Header?.ToString(), column.ActualWidth }).ToArray(),
            scrollViewers = Descendants<ScrollViewer>(grid).Select(viewer => new { viewer.ScrollableWidth, viewer.ScrollableHeight, viewer.ViewportWidth, viewer.ViewportHeight }).ToArray()
        }).ToArray()
    };

    internal void Save(string name, string output)
    {
        RenderTargetBitmap bitmap = new(_width, _height, 96, 96, PixelFormats.Pbgra32);
        bitmap.Render(Root);
        PngBitmapEncoder encoder = new();
        encoder.Frames.Add(BitmapFrame.Create(bitmap));
        using (FileStream stream = File.Create(Path.Combine(output, name + ".png"))) encoder.Save(stream);
        File.WriteAllText(Path.Combine(output, name + ".layout.json"), JsonSerializer.Serialize(Describe(), new JsonSerializerOptions { WriteIndented = true }));
    }

    internal static IEnumerable<T> Descendants<T>(DependencyObject? parent) where T : DependencyObject
    {
        if (parent is null) yield break;
        for (int i = 0; i < VisualTreeHelper.GetChildrenCount(parent); i++)
        {
            DependencyObject child = VisualTreeHelper.GetChild(parent, i);
            if (child is T match) yield return match;
            foreach (T descendant in Descendants<T>(child)) yield return descendant;
        }
    }

    public void Dispose()
    {
        _source.RootVisual = null;
        _source.Dispose();
        Root.Child = null;
        _window.Content = _content;
    }
}
