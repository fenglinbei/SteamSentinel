using System.IO;
using System.Reflection;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Threading;
using SteamSentinel.App;
using SteamSentinel.App.ViewModels;
using SteamSentinel.Core.Models;
using SteamSentinel.Core.Reporting;
using SteamSentinel.Core.Utilities;

namespace SteamSentinel.SelfTest;

internal static partial class Program
{
    private const BindingFlags TrustProxyUiPrivate = BindingFlags.Instance | BindingFlags.NonPublic;

    // Registered in the existing hidden STA layout suite. No real proxy/certificate access or mutation.
    private static void TestTrustProxyUi(string? output)
    {
        foreach ((int width, int height) in new[] { (1148, 780), (784, 460) })
        {
            MainWindow window = new();
            try
            {
                using UiLayoutHarness layout = new(window, width, height);
                string viewport = $"{width}x{height}";
                ScanReport pac = TrustProxyUiReport(TrustProxyUiFinding("legacy-pac"));
                SetTrustProxyUiReport(window, pac);
                UiPreview.ApplyAccessState(window, InstallationSecurityStatus.Protected, new(false, false));
                layout.Refresh();
                TextBlock title = TrustProxyUiText(window, "HeaderStatusText");
                TextBlock counts = TrustProxyUiText(window, "FindingHandlingSummaryText");
                Button remediate = TrustProxyUiButton(window, "RemediateButton");
                Button selectAll = TrustProxyUiButton(window, "SelectAllButton");
                DataGrid grid = (DataGrid)window.FindName("FindingsGrid");
                DataGridRow? row = grid.ItemContainerGenerator.ContainerFromIndex(0) as DataGridRow;
                Check($"诊断UI {viewport} 信息级PAC仍明确尚未处理且资格可见",
                    title.Text.Contains(UiExpected("尚未处理", "remain unresolved"), StringComparison.Ordinal) && !title.Text.Contains(UiExpected("未发现", "no actionable risk found"), StringComparison.Ordinal) &&
                    counts.Text.Contains(UiExpected("待确认 1 项", "Review needed 1"), StringComparison.Ordinal) && layout.IsFullyVisible(counts) &&
                    counts.ToolTip?.ToString() == counts.Text && row is not null && layout.IsFullyVisible(row));
                Check($"诊断UI {viewport} 零可处理项禁用全选和处理并说明真实原因",
                    !remediate.IsEnabled && !selectAll.IsEnabled &&
                    remediate.ToolTip?.ToString()?.Contains(UiExpected("没有可处理项", "No items are currently actionable"), StringComparison.Ordinal) == true &&
                    selectAll.ToolTip?.ToString()?.Contains(UiExpected("没有可选择处理", "No items are currently eligible"), StringComparison.Ordinal) == true &&
                    !remediate.ToolTip!.ToString()!.Contains(UiExpected("管理员处置可用", "Administrator remediation available"), StringComparison.Ordinal) &&
                    ToolTipService.GetShowOnDisabled(remediate) && ToolTipService.GetShowOnDisabled(selectAll));
                Check($"诊断UI {viewport} PAC提供只读诊断而不提供文件占用操作",
                    TrustProxyUiButton(window, "ReviewFindingButton") is { IsEnabled: true } reviewButton &&
                    Equals(reviewButton.Content, UiExpected("检查代理与证书", "Check proxy & certificates")) &&
                    TrustProxyUiButton(window, "OccupancyButton").Visibility == Visibility.Collapsed &&
                    TrustProxyUiText(window, "DetailDescriptionText").Text.Contains(UiExpected("尚不能确认", "unconfirmed"), StringComparison.Ordinal));
                Check($"诊断UI {viewport} 新状态列不挤出表格且原因不只存在于悬浮提示",
                    grid.Columns.Count == 7 && layout.HasReadableColumns(grid) && row is not null &&
                    grid.Columns[6].GetCellContent(row) is { } cell &&
                    UiLayoutHarness.Descendants<TextBlock>(cell).Any(text => text.Text == UiExpected("需进一步确认", "Further review needed") && layout.IsFullyVisible(text)) &&
                    UiLayoutHarness.Descendants<TextBlock>(cell).Any(text => text.Text.Contains(UiExpected("配置线索", "Configuration indicators"), StringComparison.Ordinal) && layout.IsFullyVisible(text)));
                if (output is not null) layout.Save("trust-proxy-pending-" + viewport, output);

                ScanReport completePac = TrustProxyUiReport(TrustProxyUiFinding("complete-pac"));
                completePac.Coverage = ScanCoverage.Complete;
                SetTrustProxyUiReport(window, completePac);
                Check($"诊断UI {viewport} 完整读取PAC也不概括为无需处理",
                    TrustProxyUiText(window, "HeaderStatusText").Text.Contains(UiExpected("尚未处理", "remain unresolved"), StringComparison.Ordinal));

                ScanReport ordinary = TrustProxyUiReport(new Finding
                {
                    RuleId = "NETWORK-C2-BLOCKED",
                    Category = FindingCategory.Network,
                    Severity = FindingSeverity.Information,
                    Title = "已知 C2 已在 hosts 中阻断",
                    Evidence = "无害测试：防御性配置，无需删除。",
                    SuggestedActions = [SuggestedActionKind.None]
                });
                SetTrustProxyUiReport(window, ordinary);
                Check($"诊断UI {viewport} 真实普通信息规则不会被算作未能处理",
                    TrustProxyUiText(window, "HeaderStatusText").Text == UiExpected("已完成部分检查，未发现需处理的风险", "Checks incomplete; no actionable risk found") &&
                    window.Findings.Single().HandlingLabel == UiExpected("信息提示", "Information") &&
                    counts.Text.Contains(UiExpected("待确认 0 项", "Review needed 0"), StringComparison.Ordinal) && counts.Text.Contains(UiExpected("普通说明 1 项", "Informational 1"), StringComparison.Ordinal));

                Finding file = new()
                {
                    Id = "preserved-file",
                    RuleId = "UI-KNOWN-INERT",
                    Title = "无害测试：已知文件发现",
                    Target = @"C:\inert\fixture.exe",
                    Category = FindingCategory.File,
                    Severity = FindingSeverity.High,
                    IsKnownMalware = true,
                    CanRemediate = true,
                    SuggestedActions = [SuggestedActionKind.QuarantineFile]
                };
                Finding unsupported = new()
                {
                    RuleId = "UI-UNSUPPORTED",
                    Title = "无害测试：暂不支持",
                    HandlingReason = FindingHandlingReason.UnsupportedAction,
                    HandlingDetails = "该动作尚未实现，未执行任何修改。"
                };
                Finding blocked = new()
                {
                    RuleId = "UI-BLOCKED",
                    Title = "无害测试：条件未满足",
                    HandlingReason = FindingHandlingReason.PrerequisiteNotMet,
                    HandlingDetails = "目标身份尚未完成核验。"
                };
                Finding informational = new() { RuleId = "UI-ORDINARY", Title = "无害测试：普通说明", Severity = FindingSeverity.Information };
                ScanReport mixed = TrustProxyUiReport(file, TrustProxyUiFinding("mixed-pac"), unsupported, blocked, informational);
                SetTrustProxyUiReport(window, mixed);
                UiPreview.ApplyAccessState(window, InstallationSecurityStatus.Protected, new(false, true));
                layout.Refresh();
                typeof(MainWindow).GetMethod("SelectAll_Click", TrustProxyUiPrivate)!.Invoke(window, [selectAll, new RoutedEventArgs()]);
                Check($"诊断UI {viewport} 混合发现只选择有资格目标且单独计数其他状态",
                    remediate.IsEnabled && selectAll.IsEnabled && window.Findings.Count(item => item.IsSelected) == 1 &&
                    window.Findings.Single(item => item.IsSelected).Finding.Id == file.Id &&
                    counts.Text.Contains(UiExpected("可处理 1 项", "Eligible 1"), StringComparison.Ordinal) && counts.Text.Contains(UiExpected("暂不支持 1 项", "Unsupported 1"), StringComparison.Ordinal) &&
                    counts.Text.Contains(UiExpected("条件未满足 1 项", "Prerequisites unmet 1"), StringComparison.Ordinal) && counts.Text.Contains(UiExpected("普通说明 1 项", "Informational 1"), StringComparison.Ordinal));
                Check($"诊断UI {viewport} 资格原因不会被称为执行失败或待重启",
                    window.Findings.Where(item => !item.CanSelect).All(item =>
                        !item.HandlingLabel.Contains(UiExpected("失败", "failed"), StringComparison.Ordinal) && !item.HandlingLabel.Contains(UiExpected("重启", "restart"), StringComparison.Ordinal)));
                if (output is not null) layout.Save("trust-proxy-mixed-" + viewport, output);

                ScanReport basis = TrustProxyUiReport(file, TrustProxyUiFinding("old-pac"));
                basis.Coverage = ScanCoverage.Complete;
                basis.ScopeNotes.Add("原扫描范围：保留的无害测试说明");
                SetTrustProxyUiReport(window, basis);
                typeof(MainWindow).GetField("_lastFullSystemAndContentScanId", TrustProxyUiPrivate)!.SetValue(window, basis.ScanId);
                ScanReport first = TrustProxyUiDiagnosticReport("first", incomplete: true);
                window.ApplyTrustProxyDiagnosticReport(first);
                ScanReport second = TrustProxyUiDiagnosticReport("second", incomplete: false);
                window.ApplyTrustProxyDiagnosticReport(second);
                ScanReport merged = GetTrustProxyUiReport(window);
                Check($"诊断UI {viewport} 再次诊断替换旧来源并保留其他发现和原始报告",
                    merged.Findings.Count == 2 && merged.Findings.Any(f => f.Id == file.Id) &&
                    merged.Findings.Count(FindingHandlingPresentation.IsTrustProxyFinding) == 1 &&
                    merged.Findings.All(f => f.Id is not ("old-pac" or "diagnostic-first")) &&
                    ReferenceEquals(merged.TrustProxyDiagnostics, second.TrustProxyDiagnostics) &&
                    basis.Findings.Count == 2 && basis.Findings.Any(f => f.Id == "old-pac") && basis.TrustProxyDiagnostics is null &&
                    merged.ScopeNotes.Contains("原扫描范围：保留的无害测试说明") &&
                    merged.ScopeNotes.Count == 3 && merged.ScopeNotes.Contains(TrustProxyUiDiagnosticReport("second", incomplete: false).ScopeNotes.Single()) &&
                    merged.ScopeNotes.Any(note => note.Contains(basis.ScanId.ToString("N"), StringComparison.Ordinal)) &&
                    merged.ScopeNotes.All(note => !note.Contains("无害测试 first", StringComparison.Ordinal)));
                Check($"诊断UI {viewport} 旧诊断缺口不累计且新诊断不能充当完整复扫凭据",
                    merged.Coverage == ScanCoverage.Complete && merged.ScanId != basis.ScanId && merged.ScanId != second.ScanId &&
                    merged.StartedAtUtc == basis.StartedAtUtc && merged.CompletedAtUtc == basis.CompletedAtUtc &&
                    typeof(MainWindow).GetField("_lastFullSystemAndContentScanId", TrustProxyUiPrivate)!.GetValue(window) is null);

                UiPreview.ApplyAccessState(window, new(false, "无害测试：未通过安装检查"), new(false, false));
                layout.Refresh();
                Button diagnosticButton = TrustProxyUiButton(window, "TrustProxyScanButton");
                TextBox diagnosticText = (TextBox)window.FindName("TrustProxyDetailsText");
                TextBlock diagnosticStatus = TrustProxyUiText(window, "TrustProxyStatusText");
                Check($"诊断UI {viewport} 未安装普通用户仍可只读诊断但不解锁处置",
                    diagnosticButton.IsEnabled && !remediate.IsEnabled && !TrustProxyUiButton(window, "ElevateButton").IsEnabled &&
                    layout.IsFullyVisible(diagnosticButton) && layout.IsFullyVisible(TrustProxyUiButton(window, "ExportButton")));
                Check($"诊断UI {viewport} 采集范围边界不会把可选未检查算成本地采集失败",
                    diagnosticStatus.Text.Contains(UiExpected("本地采集已完成", "Local collection complete"), StringComparison.Ordinal) &&
                    MainWindow.IncompleteDiagnosticChecks(second.TrustProxyDiagnostics!) == 0 &&
                    diagnosticText.Text.Contains("不访问网络", StringComparison.Ordinal));
                Check($"诊断UI {viewport} 证书与代理来源可读可复制且仅正文纵向滚动",
                    diagnosticText.IsReadOnly && diagnosticText.TextWrapping == TextWrapping.Wrap &&
                    diagnosticText.HorizontalScrollBarVisibility == ScrollBarVisibility.Disabled &&
                    diagnosticText.Text.Contains("UI-WinINET-second", StringComparison.Ordinal) &&
                    diagnosticText.Text.Contains("CN=UI Inert Certificate", StringComparison.Ordinal) &&
                    diagnosticText.Text.Contains("LocalMachine", StringComparison.Ordinal) &&
                    diagnosticText.ActualHeight >= 70 && layout.IsFullyVisible(diagnosticText) &&
                    UiLayoutHarness.Descendants<ScrollViewer>(diagnosticText).All(viewer => viewer.ScrollableWidth <= 1));
                if (output is not null) layout.Save("trust-proxy-diagnostics-" + viewport, output);

                ((TabControl)window.FindName("ResultTabs")).SelectedIndex = 2;
                layout.Refresh();
                Check($"诊断UI {viewport} 追加诊断页保留处置结果原索引及独立结果入口",
                    ((TabControl)window.FindName("ResultTabs")).Items[2] == window.FindName("BatchResultsTab") &&
                    ((TabControl)window.FindName("ResultTabs")).Items[3] == window.FindName("TrustProxyTab") &&
                    layout.IsFullyVisible(TrustProxyUiButton(window, "FollowUpDetailsButton")));
            }
            finally { CloseSummaryFixture(window); }
        }
        TestTrustProxyUiReadOnlyLifecycle();
    }

    private static void TestTrustProxyUiReadOnlyLifecycle()
    {
        MainWindow window = new();
        try
        {
            using UiLayoutHarness layout = new(window, 784, 460);
            ScanReport original = TrustProxyUiReport(new Finding { Id = "kept-ordinary", Title = "保留的普通说明" });
            SetTrustProxyUiReport(window, original);
            UiPreview.ApplyAccessState(window, new(false, "无害测试：不安全安装"), new(false, false));
            int calls = 0;
            RunTrustProxyUiTask(window, () => window.RunTrustProxyDiagnosticsAsync((_, _) =>
            {
                Interlocked.Increment(ref calls);
                return Task.FromResult(TrustProxyUiDiagnosticReport("inert-runner", incomplete: false));
            }));
            Check("诊断UI 普通用户实际只读入口使用注入采集器并保留原结果",
                calls == 1 && GetTrustProxyUiReport(window).Findings.Any(f => f.Id == "kept-ordinary") &&
                TrustProxyUiButton(window, "TrustProxyScanButton").IsEnabled && !TrustProxyUiButton(window, "RemediateButton").IsEnabled);
            ScanReport beforeMissingSnapshot = GetTrustProxyUiReport(window);
            bool rejected = false;
            try { window.ApplyTrustProxyDiagnosticReport(new ScanReport()); }
            catch (InvalidDataException) { rejected = true; }
            Check("诊断UI 未返回诊断快照不能静默清空上次代理线索",
                rejected && ReferenceEquals(GetTrustProxyUiReport(window), beforeMissingSnapshot));
            RunTrustProxyUiTask(window, () => window.RunTrustProxyDiagnosticsAsync((_, _) =>
                Task.FromException<ScanReport>(new OperationCanceledException("无害测试：用户取消，只读采集停止"))));
            ScanReport cancelled = GetTrustProxyUiReport(window);
            Check("诊断UI 取消记录为采集未完成并保留已有非诊断发现",
                cancelled.TrustProxyDiagnostics!.Checks.Any(check => check.Status == DiagnosticReadStatus.Cancelled) &&
                cancelled.Coverage == ScanCoverage.Partial && cancelled.Findings.Any(f => f.Id == "kept-ordinary") &&
                TrustProxyUiText(window, "HeaderStatusText").Text == UiExpected("代理与证书检查未完成", "Proxy and certificate checks incomplete") &&
                TrustProxyUiText(window, "TrustProxyStatusText").Text.Contains(UiExpected("未完成", "incomplete"), StringComparison.Ordinal) &&
                !TrustProxyUiButton(window, "CancelScanButton").IsEnabled && TrustProxyUiButton(window, "TrustProxyScanButton").IsEnabled);
        }
        finally { CloseSummaryFixture(window); }
    }

    private static void RunTrustProxyUiTask(MainWindow window, Func<Task> action)
    {
        Exception? failure = null;
        bool completed = false;
        DispatcherFrame frame = new();
        DispatcherTimer timeout = new(DispatcherPriority.Send, window.Dispatcher) { Interval = TimeSpan.FromSeconds(8) };
        timeout.Tick += (_, _) => frame.Continue = false;
        timeout.Start();
        window.Dispatcher.BeginInvoke(new Action(async () =>
        {
            try { await action(); }
            catch (Exception ex) { failure = ex; }
            finally { completed = true; frame.Continue = false; }
        }));
        Dispatcher.PushFrame(frame);
        timeout.Stop();
        if (!completed) throw new TimeoutException("无害诊断UI回归未在时限内返回。");
        if (failure is not null) throw new InvalidOperationException("无害诊断UI回归失败。", failure);
    }

    private static Finding TrustProxyUiFinding(string id) => new()
    {
        Id = id,
        RuleId = "NETWORK-PROXY-PRESENT",
        Category = FindingCategory.Network,
        Severity = FindingSeverity.Information,
        Score = 5,
        Title = "检测到用户代理配置",
        Target = "http://inert.invalid/proxy.pac",
        Description = "无害界面测试：仅有配置线索，未读取实际代理。",
        SuggestedActions = [SuggestedActionKind.ReviewOnly]
    };

    private static ScanReport TrustProxyUiReport(params Finding[] findings) => new()
    {
        Mode = ScanMode.Quick,
        Coverage = ScanCoverage.Partial,
        CompletedAtUtc = DateTimeOffset.UtcNow,
        Findings = [.. findings]
    };

    private static ScanReport TrustProxyUiDiagnosticReport(string identity, bool incomplete)
    {
        ProxyConfigurationObservation proxy = new()
        {
            Id = "proxy-" + identity,
            Source = "UI-WinINET-" + identity,
            Scope = "CurrentUser",
            UserSid = "S-1-5-21-100-200-300-1001",
            Location = @"HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings",
            Status = DiagnosticReadStatus.Complete,
            ProxyEnabled = false,
            AutoConfigUrl = "http://inert.invalid/proxy.pac",
            Detail = "无害测试配置；不访问网络。"
        };
        TrustProxyDiagnosticReport diagnostic = new()
        {
            CompletedAtUtc = DateTimeOffset.UtcNow,
            TargetUserSid = proxy.UserSid!,
            Proxies = [proxy],
            CertificateStores = [new() { Id = "store-" + identity, Scope = "LocalMachine", StoreName = "Root", Provider = "UI Registry snapshot",
                Status = DiagnosticReadStatus.Complete, CertificatesRead = 1 }],
            Certificates = [new() { Id = "cert-" + identity, StoreObservationId = "store-" + identity, Subject = "CN=UI Inert Certificate",
                Issuer = "CN=UI Inert Certificate", DerSha256 = new string('A', 64), Sha1Thumbprint = new string('B', 40),
                NotBeforeUtc = DateTimeOffset.UtcNow.AddDays(-1), NotAfterUtc = DateTimeOffset.UtcNow.AddDays(30),
                SubjectEqualsIssuer = true, SelfSignatureVerified = null, ChainStatus = DiagnosticReadStatus.NotChecked,
                ChainDetail = "无害测试：仅显示合成证书摘要，不构建证书链。" }],
            Checks =
            [
                new() { Name = "本地代理", Status = DiagnosticReadStatus.Complete },
                new() { Name = "本地证书", Status = incomplete ? DiagnosticReadStatus.AccessDenied : DiagnosticReadStatus.Complete,
                    Detail = incomplete ? "无害测试：权限受限，状态未知。" : "无害测试：完成本地快照。" },
                new() { Name = "PAC正文与联网TLS", Status = DiagnosticReadStatus.NotChecked, Required = false, Detail = "不访问网络，未下载PAC正文。" }
            ]
        };
        return new ScanReport
        {
            Mode = ScanMode.Custom,
            Coverage = incomplete ? ScanCoverage.Partial : ScanCoverage.Complete,
            CompletedAtUtc = diagnostic.CompletedAtUtc,
            TrustProxyDiagnostics = diagnostic,
            Findings = [new() { Id = "diagnostic-" + identity, RuleId = "TRUST-PROXY-UI-CONFIG", SourceKind = "trust-proxy-diagnostics",
                DiagnosticObservationIds = [proxy.Id], Category = FindingCategory.Network, Severity = FindingSeverity.Information,
                Title = "无害测试：待确认代理", Target = proxy.AutoConfigUrl!, HandlingReason = FindingHandlingReason.InsufficientEvidence }],
            ScopeNotes = ["证书与代理诊断：无害测试 " + identity + "，只读且不访问网络。"]
        };
    }

    private static void SetTrustProxyUiReport(MainWindow window, ScanReport report)
    {
        typeof(MainWindow).GetField("_lastReport", TrustProxyUiPrivate)!.SetValue(window, report);
        typeof(MainWindow).GetMethod("PopulateFindings", TrustProxyUiPrivate)!.Invoke(window, [report]);
        typeof(MainWindow).GetMethod("UpdateSummary", TrustProxyUiPrivate)!.Invoke(window, [report]);
    }

    private static ScanReport GetTrustProxyUiReport(MainWindow window) =>
        (ScanReport)typeof(MainWindow).GetField("_lastReport", TrustProxyUiPrivate)!.GetValue(window)!;
    private static Button TrustProxyUiButton(MainWindow window, string name) => (Button)window.FindName(name);
    private static TextBlock TrustProxyUiText(MainWindow window, string name) => (TextBlock)window.FindName(name);
}
