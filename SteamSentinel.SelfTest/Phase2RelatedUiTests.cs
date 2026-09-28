using System.IO;
using System.IO.Compression;
using System.Text.Json;
using System.Windows;
using System.Windows.Controls;
using SteamSentinel.App;
using SteamSentinel.App.ViewModels;
using SteamSentinel.Core.Models;
using SteamSentinel.Core.Reporting;
using SteamSentinel.Core.Utilities;

namespace SteamSentinel.SelfTest;

internal static partial class Program
{
    private const string Phase2PresentationSecret = "phase2-inert-secret-do-not-display";

    // Hidden STA fixtures use synthetic observations and inert local text, never real processes or samples.
    private static void TestPhase2RelatedUi(string? output)
    {
        string directory = Path.Combine(Path.GetTempPath(), "SteamSentinel-Phase2Ui-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        string file = Path.Combine(directory, "inert-component.txt");
        File.WriteAllText(file, "Inert UI review target. No executable content.");
        try
        {
            foreach ((int width, int height) in new[] { (1148, 780), (784, 460) })
            {
                MainWindow window = new();
                try
                {
                    using UiLayoutHarness layout = new(window, width, height);
                    string viewport = $"{width}x{height}";
                    RelatedComponentDiagnosticReport diagnostic = Phase2PresentationFixture(file);
                    Finding associated = new()
                    {
                        Id = "phase2-associated",
                        RuleId = "RELATED-COMPONENT-UI-INERT",
                        SourceKind = RelatedComponentReportPresentation.SourceKind,
                        Category = FindingCategory.Process,
                        Severity = FindingSeverity.Information,
                        Target = file,
                        Title = "无害测试：宿主加载未知组件",
                        Description = "仅为关联观察，没有获得新的处理权限。",
                        AssociationObservationIds = ["phase2-source", "phase2-host", "phase2-candidate"],
                        AssociationEvidenceTier = RelatedEvidenceTier.RelatedRisk,
                        HandlingReason = FindingHandlingReason.InsufficientEvidence,
                        SuggestedActions = [SuggestedActionKind.ReviewOnly]
                    };
                    ScanReport report = new()
                    {
                        Mode = ScanMode.Quick,
                        CompletedAtUtc = DateTimeOffset.UtcNow,
                        RelatedComponentDiagnostics = diagnostic,
                        Findings = [associated]
                    };
                    SetTrustProxyUiReport(window, report);
                    UiPreview.ApplyAccessState(window, InstallationSecurityStatus.Protected, new(false, true));
                    layout.Refresh();
                    Button review = TrustProxyUiButton(window, "ReviewFindingButton");
                    FindingItemViewModel item = window.Findings.Single();
                    Check($"组件UI {viewport} 关联发现不误入代理页且不新增处置资格",
                        !item.IsTrustProxyFinding && RelatedComponentReportPresentation.IsRelatedFinding(item.Finding) &&
                        !item.CanSelect && !item.IsSelected && !TrustProxyUiButton(window, "RemediateButton").IsEnabled &&
                        !TrustProxyUiButton(window, "SelectAllButton").IsEnabled && item.HandlingLabel == UiExpected("需进一步确认", "Further review needed"));
                    Check($"组件UI {viewport} 仅适用本地文件可进一步检查且展示观察原因",
                        review.IsEnabled && review.Content?.ToString() == UiExpected("进一步检查", "Inspect further") &&
                        TrustProxyUiButton(window, "OccupancyButton").Visibility == Visibility.Collapsed &&
                        TrustProxyUiText(window, "DetailDescriptionText").Text.Contains("无害测试：由宿主模块列表定位", StringComparison.Ordinal) &&
                        TrustProxyUiText(window, "DetailDescriptionText").Text.Contains(UiExpected("证据层级：关联风险", "Evidence tier: Related risk"), StringComparison.Ordinal) &&
                        TrustProxyUiText(window, "DetailDescriptionText").Text.Contains("phase2-candidate", StringComparison.Ordinal));
                    if (output is not null) layout.Save("related-components-finding-" + viewport, output);

                    TabControl tabs = (TabControl)window.FindName("ResultTabs");
                    tabs.SelectedIndex = 4;
                    layout.Refresh();
                    TextBox details = (TextBox)window.FindName("RelatedComponentsDetailsText");
                    TextBlock status = TrustProxyUiText(window, "RelatedComponentsStatusText");
                    Check($"组件UI {viewport} 第五页只读且原处置和代理页索引保持",
                        tabs.Items.Count == 7 && tabs.Items[2] == window.FindName("BatchResultsTab") &&
                        tabs.Items[3] == window.FindName("TrustProxyTab") && tabs.Items[4] == window.FindName("RelatedComponentsTab") &&
                        details.IsReadOnly && details.TextWrapping == TextWrapping.Wrap &&
                        details.HorizontalScrollBarVisibility == ScrollBarVisibility.Disabled &&
                        details.ActualHeight >= 70 && layout.IsFullyVisible(details) && layout.IsFullyVisible(status) &&
                        layout.IsFullyVisible(TrustProxyUiButton(window, "ExportButton")) &&
                        TrustProxyUiButton(window, "RemediateButton").Visibility == Visibility.Collapsed &&
                        UiLayoutHarness.Descendants<Button>((FrameworkElement)window.FindName("RelatedComponentsPage")).Count() == 0 &&
                        UiLayoutHarness.Descendants<ScrollViewer>(details).All(viewer => viewer.ScrollableWidth <= 1));
                    Check($"组件UI {viewport} 来源宿主候选哈希及真实预算可复制且凭据隐藏",
                        details.Text.Contains(UiExpected("来源 → 宿主 → 候选组件", "Source → host → candidate component"), StringComparison.Ordinal) &&
                        details.Text.Contains(UiExpected("宿主 PID 4242", "Host PID 4242"), StringComparison.Ordinal) && details.Text.Contains(file, StringComparison.Ordinal) &&
                        details.Text.Contains(new string('A', 64), StringComparison.Ordinal) && details.Text.Contains(UiExpected("第 1 轮", "Round 1"), StringComparison.Ordinal) &&
                        details.Text.Contains(UiExpected("第 2 轮", "Round 2"), StringComparison.Ordinal) && details.Text.Contains(UiExpected("本轮预算 512 字节", "round budget 512 bytes"), StringComparison.Ordinal) &&
                        details.Text.Contains(UiExpected("本轮预算 256 字节", "round budget 256 bytes"), StringComparison.Ordinal) && details.Text.Contains(UiExpected("写入者仍未定位", "The writer remains unidentified"), StringComparison.Ordinal) &&
                        !details.Text.Contains(Phase2PresentationSecret, StringComparison.Ordinal));
                    if (output is not null) layout.Save("related-components-diagnostics-" + viewport, output);

                    ScanReport proxyRefresh = TrustProxyUiDiagnosticReport("phase2-preserve", incomplete: false);
                    window.ApplyTrustProxyDiagnosticReport(proxyRefresh);
                    ScanReport merged = GetTrustProxyUiReport(window);
                    Check($"组件UI {viewport} 独立代理刷新保留组件诊断与关联发现",
                        ReferenceEquals(merged.RelatedComponentDiagnostics, diagnostic) &&
                        merged.Findings.Any(finding => finding.Id == associated.Id) &&
                        !FindingHandlingPresentation.IsTrustProxyFinding(associated) &&
                        ReferenceEquals(report.RelatedComponentDiagnostics, diagnostic));

                    Finding noFile = new()
                    {
                        Id = "phase2-no-file",
                        Title = "无害测试：只有来源线索",
                        Target = "https://inert.invalid/not-a-file",
                        SourceKind = RelatedComponentReportPresentation.SourceKind,
                        AssociationObservationIds = ["phase2-source"],
                        HandlingReason = FindingHandlingReason.InsufficientEvidence,
                        SuggestedActions = [SuggestedActionKind.ReviewOnly]
                    };
                    tabs.SelectedIndex = 0;
                    SetTrustProxyUiReport(window, new()
                    {
                        CompletedAtUtc = DateTimeOffset.UtcNow,
                        RelatedComponentDiagnostics = diagnostic,
                        Findings = [noFile]
                    });
                    layout.Refresh();
                    Check($"组件UI {viewport} 无适用文件的关系记录不提供误导性进一步检查",
                        !review.IsEnabled && review.Content?.ToString() == UiExpected("进一步检查", "Inspect further") &&
                        ToolTipService.GetShowOnDisabled(review) &&
                        review.ToolTip?.ToString()?.Contains(UiExpected("尚未定位", "No local file"), StringComparison.Ordinal) == true &&
                        TrustProxyUiButton(window, "OccupancyButton").Visibility == Visibility.Collapsed);
                    diagnostic.Rounds[1].Status = DiagnosticReadStatus.Cancelled;
                    SetTrustProxyUiReport(window, new()
                    {
                        CompletedAtUtc = DateTimeOffset.UtcNow,
                        RelatedComponentDiagnostics = diagnostic,
                        Findings = [noFile]
                    });
                    Check($"组件UI {viewport} 取消轮次明确为未完成而非关联检查已完成",
                        status.Text.Contains(UiExpected("关联检查未完成", "Association inspection is incomplete"), StringComparison.Ordinal) &&
                        !status.Text.Contains(UiExpected("本轮关联检查已完成", "Association inspection for this run is complete"), StringComparison.Ordinal));
                    SetTrustProxyUiReport(window, new() { CompletedAtUtc = DateTimeOffset.UtcNow });
                    Check($"组件UI {viewport} 新报告无组件诊断时清空旧显示",
                        status.Text == UiExpected("尚无组件关联记录", "No component association records yet") && !details.Text.Contains("phase2-candidate", StringComparison.Ordinal));
                }
                finally { CloseSummaryFixture(window); }
            }
        }
        finally { File.Delete(file); Directory.Delete(directory); }
    }

    private static async Task TestPhase2RelatedPresentationAsync(string root)
    {
        RelatedComponentDiagnosticReport diagnostic = Phase2PresentationFixture(@"C:\inert\component.dll");
        ScanReport report = new()
        {
            CompletedAtUtc = DateTimeOffset.UtcNow,
            RelatedComponentDiagnostics = diagnostic,
            TrustProxyDiagnostics = TrustProxyUiDiagnosticReport("phase2-export", incomplete: false).TrustProxyDiagnostics
        };
        string path = Path.Combine(root, "phase2-related-presentation");
        Directory.CreateDirectory(path);
        string markdownPath = Path.Combine(path, "report.md"), jsonPath = Path.Combine(path, "report.json"), zipPath = Path.Combine(path, "case.zip");
        await ReportExporter.ExportMarkdownAsync(report, markdownPath);
        await ReportExporter.ExportJsonAsync(report, jsonPath);
        await CaseBundleExporter.ExportAsync(zipPath, new ScanReport(), null, null, null,
            latestDiagnostics: report.TrustProxyDiagnostics, latestRelatedDiagnostics: diagnostic);
        string markdown = await File.ReadAllTextAsync(markdownPath), json = await File.ReadAllTextAsync(jsonPath);
        using ZipArchive zip = ZipFile.OpenRead(zipPath);
        string relatedJson, originalScanJson;
        using (StreamReader reader = new(zip.GetEntry("related-components.json")!.Open())) relatedJson = await reader.ReadToEndAsync();
        using (StreamReader reader = new(zip.GetEntry("scan.json")!.Open())) originalScanJson = await reader.ReadToEndAsync();
        RelatedComponentDiagnosticReport? bundledRelated = JsonSerializer.Deserialize<RelatedComponentDiagnosticReport>(relatedJson, JsonFile.Options);
        ScanReport? bundledOriginal = JsonSerializer.Deserialize<ScanReport>(originalScanJson, JsonFile.Options);
        Check("组件报告 Markdown与JSON保留来源关系和各轮实际预算并与代理诊断分节",
            markdown.Contains("## 组件关联只读诊断", StringComparison.Ordinal) && markdown.Contains("## 证书与代理只读诊断", StringComparison.Ordinal) &&
            markdown.Contains(UiExpected("本轮预算 512 字节", "round budget 512 bytes"), StringComparison.Ordinal) && markdown.Contains(UiExpected("本轮预算 256 字节", "round budget 256 bytes"), StringComparison.Ordinal) &&
            json.Contains("phase2-source", StringComparison.Ordinal) && json.Contains("phase2-host", StringComparison.Ordinal) &&
            json.Contains("phase2-candidate", StringComparison.Ordinal));
        Check("组件报告 完整包独立保存最新关联记录且不改写处置前scan",
            zip.GetEntry("scan.json") is not null && zip.GetEntry("trust-proxy-diagnostics.json") is not null &&
            bundledRelated?.Candidates.Any(c => c.Id == "phase2-candidate") == true &&
            bundledRelated.Rounds.Select(round => round.MaximumBytes).SequenceEqual(new long?[] { 512, 256 }) &&
            bundledOriginal is not null && bundledOriginal.RelatedComponentDiagnostics is null &&
            !originalScanJson.Contains("phase2-candidate", StringComparison.Ordinal));
        Check("组件报告 所有展示与导出路径隐藏已识别凭据",
            !markdown.Contains(Phase2PresentationSecret, StringComparison.Ordinal) && !json.Contains(Phase2PresentationSecret, StringComparison.Ordinal) &&
            !relatedJson.Contains(Phase2PresentationSecret, StringComparison.Ordinal));
        Check("组件报告 区分路径加载观察、磁盘文件核验与进程内存身份",
            markdown.Contains("路径关系观察与文件核验可能来自不同时间", StringComparison.Ordinal) &&
            markdown.Contains("该路径磁盘文件离线签名：本地信任缓存验证通过", StringComparison.Ordinal) &&
            markdown.Contains("未读取进程内存", StringComparison.Ordinal) && markdown.Contains("文件核验时间", StringComparison.Ordinal));
        RelatedComponentDiagnosticReport absentBudget = new()
        {
            CompletedAtUtc = DateTimeOffset.UtcNow,
            Rounds = [new() { Number = 1, CompletedAtUtc = DateTimeOffset.UtcNow, Status = DiagnosticReadStatus.Complete }]
        };
        string absentText = RelatedComponentReportPresentation.Describe(absentBudget);
        Check("组件报告 缺失预算不冒充默认配置且正常范围说明不算失败",
            absentText.Contains("预算上限未记录", StringComparison.Ordinal) && absentText.Contains("本轮预算 未记录", StringComparison.Ordinal) &&
            RelatedComponentReportPresentation.Summary(diagnostic).Contains(UiExpected("本轮关联检查已完成", "Association inspection for this run is complete"), StringComparison.Ordinal));
        Check("组件报告 证据层级本身不增加处置资格",
            !new FindingItemViewModel(new()
            {
                SourceKind = RelatedComponentReportPresentation.SourceKind,
                AssociationEvidenceTier = RelatedEvidenceTier.ConfirmedTarget,
                AssociationObservationIds = ["phase2-candidate"],
                Target = @"C:\inert\component.dll"
            }).CanSelect);
        RelatedComponentDiagnosticReport large = new()
        {
            CompletedAtUtc = DateTimeOffset.UtcNow,
            Sources = Enumerable.Range(0, 300).Select(index => new RelatedSourceObservation
            {
                Id = "phase2-large-source-" + index,
                Kind = "无害长文本",
                Location = @"C:\inert\source-" + index,
                RawCommand = new string('x', 4000),
                Status = DiagnosticReadStatus.Complete
            }).ToList()
        };
        string bounded = RelatedComponentReportPresentation.Describe(large);
        string largeJsonPath = Path.Combine(path, "large.json");
        await ReportExporter.ExportJsonAsync(new() { RelatedComponentDiagnostics = large }, largeJsonPath);
        string largeJson = await File.ReadAllTextAsync(largeJsonPath);
        Check("组件报告 有界展示明确省略且不截断模型或完整JSON",
            bounded.Length <= RelatedComponentReportPresentation.MaximumDescriptionCharacters &&
            bounded.Contains("部分显示内容已达到上限", StringComparison.Ordinal) && large.Sources.Count == 300 &&
            largeJson.Contains("phase2-large-source-299", StringComparison.Ordinal));
    }

    private static RelatedComponentDiagnosticReport Phase2PresentationFixture(string componentPath)
    {
        DateTimeOffset time = new(2026, 9, 6, 0, 0, 0, TimeSpan.Zero);
        return new()
        {
            StartedAtUtc = time,
            CompletedAtUtc = time.AddSeconds(3),
            TargetUserSid = "S-1-5-21-100-200-300-1001",
            AppliedLimits = new() { MaximumRounds = 2, MaximumTotalBytes = 1024, MaximumFileBytes = 512, MaximumCandidates = 8, MaximumHosts = 4 },
            Sources = [new()
            {
                Id = "phase2-source", Kind = "无害启动来源", Scope = "CurrentUser", Location = @"HKCU\Inert\Run",
                RawCommand = "inert.exe token=" + Phase2PresentationSecret, WorkingDirectory = @"C:\inert",
                Status = DiagnosticReadStatus.Complete, ResolvedTargets = [componentPath], Detail = "无害测试：读取启动命令，不执行命令。"
            }],
            Hosts = [new()
            {
                Id = "phase2-host", ProcessId = 4242, StartedAtUtc = time.AddMinutes(-1), ImagePath = @"C:\inert\signed-host.exe",
                ImageSha256 = new string('B', 64), SignatureStatus = "Valid", SignatureDetail = "无害测试：签名有效也不豁免组件检查。",
                Status = DiagnosticReadStatus.Complete, SourceObservationIds = ["phase2-source"], Detail = "无害测试：宿主加载关系，不证明写入行为。"
            }],
            Candidates = [new()
            {
                Id = "phase2-candidate", Path = componentPath, Reason = "无害测试：由宿主模块列表定位", Status = DiagnosticReadStatus.Complete,
                Sha256 = new string('A', 64), Length = 128, VerifiedAtUtc = time.AddSeconds(1), ContentStatus = DiagnosticReadStatus.Complete,
                ContentDetail = "无害测试：已由注入的受限扫描结果描述，不运行实际组件。", SourceObservationIds = ["phase2-source"],
                HostObservationIds = ["phase2-host"], EvidenceObservationIds = ["phase2-source", "phase2-host"]
            }],
            Relations = [new("phase2-source", "phase2-host", "launches", "无害测试：命令与宿主身份对应"),
                new("phase2-host", "phase2-candidate", "loads", "无害测试：只读加载关系")],
            Checks = [new() { Name = "本地组件关联", Status = DiagnosticReadStatus.Complete },
                new() { Name = "写入者定位", Status = DiagnosticReadStatus.NotChecked, Required = false, Detail = "写入者仍未定位。" }],
            Rounds = [new() { Number = 1, StartedAtUtc = time, CompletedAtUtc = time.AddSeconds(1), Status = DiagnosticReadStatus.Complete,
                MaximumBytes = 512, BytesRead = 128, CandidateIds = ["phase2-candidate"], Detail = "无害测试：第一轮补查" },
                new() { Number = 2, StartedAtUtc = time.AddSeconds(1), CompletedAtUtc = time.AddSeconds(3), Status = DiagnosticReadStatus.Complete,
                MaximumBytes = 256, BytesRead = 64, CandidateIds = ["phase2-candidate"], Detail = "无害测试：第二轮核对" }]
        };
    }
}
