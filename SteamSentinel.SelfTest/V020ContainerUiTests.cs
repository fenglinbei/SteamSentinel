using System.IO;
using System.Text.Json;
using System.Windows;
using System.Windows.Controls;
using SteamSentinel.App;
using SteamSentinel.Core.Models;
using SteamSentinel.Core.Remediation;
using SteamSentinel.Core.Reporting;
using SteamSentinel.Core.Utilities;

namespace SteamSentinel.SelfTest;

internal static partial class Program
{
    private const string V020ContainerUiSecret = "v020-inert-secret-never-export";

    private static void TestV020ContainerUi(string? output)
    {
        string directory = Path.Combine(Path.GetTempPath(), "SteamSentinel-V020ContainerUi-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        string original = Path.Combine(directory, "inert.part1.rar"), volume = Path.Combine(directory, "inert.part2.rar"), temporary = Path.Combine(directory, "temporary-member.txt");
        File.WriteAllText(original, "Inert metadata UI fixture. Not an archive.");
        File.WriteAllText(volume, "Inert second volume metadata fixture.");
        File.WriteAllText(temporary, "Inert temporary representation metadata fixture.");
        string supplemental = Path.Combine(directory, "explicit-supplement"), recovery = Path.Combine(directory, "explicit-recovery");
        Directory.CreateDirectory(supplemental); Directory.CreateDirectory(recovery);
        try
        {
            ScanReport fixture = V020ContainerPresentationFixture(original, volume, temporary);
            ContainerScanReport containers = fixture.Containers!;
            List<string> targets = MainWindow.GetContainerReviewTargets(containers, containers.Nodes[1]);
            Check("0.2容器UI 补查只返回原始外层和非临时卷组", targets.Count == 2 && targets.Contains(original) && targets.Contains(volume) && !targets.Contains(temporary));
            Check("0.2容器UI 原始目录不能同时当恢复输出目录", !MainWindow.TryContainerDirectory(directory, true, targets, out _, out _) &&
                MainWindow.TryContainerDirectory(recovery, true, targets, out string selectedRecovery, out _) && selectedRecovery == recovery);
            Check("0.2容器UI 补卷目录明确选取本地目录并拒绝UNC", MainWindow.TryContainerDirectory(supplemental, false, targets, out string selectedSupplemental, out _) &&
                selectedSupplemental == supplemental && !MainWindow.TryContainerDirectory(@"\\inert.invalid\share", false, targets, out _, out _));
            ScanOptions old = new()
            {
                Mode = ScanMode.Custom,
                RecoveryOutputDirectory = recovery,
                SupplementalVolumeDirectories = [supplemental],
                ContainerLimits = new() { MaximumWorkBytes = 17L * 1024 * 1024 * 1024 },
                InspectDeepSignatures = false
            };
            ScanOptions retry = MainWindow.BuildContainerReviewOptions(old, targets, [], null, true, false);
            Check("0.2容器UI 普通补查不会重用旧恢复写出授权", retry.RecoveryOutputDirectory is null && retry.SupplementalVolumeDirectories.Count == 0 && !retry.InspectDeepSignatures && retry.ContainerLimits?.MaximumWorkBytes == old.ContainerLimits.MaximumWorkBytes);
            ScanOptions deep = MainWindow.BuildContainerReviewOptions(new() { Mode = ScanMode.Quick }, targets, [supplemental], recovery, true, true);
            Check("0.2容器UI 快速扫描补查升级为8GiB32GiB深度12且明确传目录", deep.Mode == ScanMode.Custom && deep.MaximumEntryBytes == 8L * 1024 * 1024 * 1024 && deep.MaximumExpandedBytes == 32L * 1024 * 1024 * 1024 &&
                deep.MaximumArchiveDepth == 12 && deep.InspectDeepSignatures && deep.RecoveryOutputDirectory == recovery && deep.SupplementalVolumeDirectories.SequenceEqual([supplemental]) &&
                !deep.IncludeSystem && !deep.IncludeSteam && !deep.IncludeWorkshop && deep.HashEveryFile && deep.InspectArchives);
            ScanOptions clone = RemediationBatchPlanner.CloneOptions(old)!;
            Check("0.2容器UI 通用设置克隆保留深查预算与补卷元数据", clone.ContainerLimits?.MaximumWorkBytes == old.ContainerLimits.MaximumWorkBytes &&
                clone.SupplementalVolumeDirectories.SequenceEqual(old.SupplementalVolumeDirectories) && !clone.InspectDeepSignatures);

            foreach ((int width, int height) in new[] { (1148, 780), (784, 460) })
            {
                MainWindow window = new();
                try
                {
                    using UiLayoutHarness layout = new(window, width, height);
                    SetTrustProxyUiReport(window, fixture);
                    UiPreview.ApplyAccessState(window, InstallationSecurityStatus.Protected, new(false, true));
                    TabControl tabs = (TabControl)window.FindName("ResultTabs");
                    Check($"0.2容器UI {width}x{height} 原六页索引保留且容器页追加为6", tabs.Items.Count == 7 &&
                        ReferenceEquals(tabs.Items[3], window.FindName("TrustProxyTab")) && ReferenceEquals(tabs.Items[4], window.FindName("RelatedComponentsTab")) &&
                        ReferenceEquals(tabs.Items[5], window.FindName("CasesTab")) && ReferenceEquals(tabs.Items[6], window.FindName("ContainerTab")));
                    tabs.SelectedIndex = 6;
                    ComboBox selection = (ComboBox)window.FindName("ContainerNodesComboBox"); selection.SelectedIndex = 1;
                    layout.Refresh();
                    TextBox details = (TextBox)window.FindName("ContainerDetailsText");
                    Check($"0.2容器UI {width}x{height} 完整长路径阶段链只读可复制且纵向滚动", details.IsReadOnly && details.TextWrapping == TextWrapping.Wrap &&
                        details.HorizontalScrollBarVisibility == ScrollBarVisibility.Disabled && details.VerticalScrollBarVisibility == ScrollBarVisibility.Auto &&
                        details.Text.Contains(containers.Nodes[1].DisplayPath, StringComparison.Ordinal) && details.Text.Contains(UiExpected("五阶段", "Five stages"), StringComparison.Ordinal) &&
                        details.Text.Contains(UiExpected("完整性算法暂不支持", "Integrity algorithm not supported"), StringComparison.Ordinal) && details.Text.Contains(UiExpected("本轮预算", "Budget and work performed in this run"), StringComparison.Ordinal) &&
                        details.ActualHeight >= 70 && layout.IsFullyVisible(details));
                    string[] actions = ["ContainerRecheckButton", "ContainerSupplementButton", "ContainerRecoveryButton", "ContainerFullDetailsButton", "ContainerExportButton"];
                    Check($"0.2容器UI {width}x{height} 三类补查和元数据导出入口完整可见", actions.All(name =>
                        ((Button)window.FindName(name)).IsEnabled && layout.IsFullyVisible((Button)window.FindName(name))));
                    Check($"0.2容器UI {width}x{height} 页面不产生处置资格且未知状态不显示安全", !TrustProxyUiButton(window, "RemediateButton").IsEnabled &&
                        TrustProxyUiText(window, "ContainerStatusText").Text.Contains(UiExpected("未完成", "incomplete"), StringComparison.Ordinal) &&
                        !details.Text.Contains(V020ContainerUiSecret, StringComparison.Ordinal) && details.Text.Contains(UiExpected("未签名不等于恶意", "Unsigned does not mean malicious"), StringComparison.Ordinal));
                    if (output is not null) layout.Save($"v020-container-{width}x{height}", output);
                }
                finally { window.Close(); }
            }

            MainWindow reviewWindow = new();
            try
            {
                using UiLayoutHarness layout = new(reviewWindow, 784, 460);
                SetTrustProxyUiReport(reviewWindow, fixture);
                UiPreview.ApplyAccessState(reviewWindow, InstallationSecurityStatus.Protected, new(false, true));
                ScanOptions? invoked = null;
                RunTrustProxyUiTask(reviewWindow, async () => await reviewWindow.RunContainerReviewAsync(targets, [supplemental], recovery,
                    (options, progress, token) =>
                    {
                        invoked = options;
                        progress.Report(new("无害容器UI替代Worker", original, 1, 1, "仅验证请求转交，不解析样本，不写出恢复内容。"));
                        return Task.FromResult(V020ContainerPresentationFixture(original, volume, temporary));
                    }));
                layout.Refresh();
                Check("0.2容器UI 生产补查路径向Worker runner转交精确来源与当轮目录", invoked is not null &&
                    invoked.CustomRoots.SequenceEqual(targets) && invoked.SupplementalVolumeDirectories.SequenceEqual([supplemental]) && invoked.RecoveryOutputDirectory == recovery &&
                    !invoked.IncludeSystem && !invoked.IncludeSteam && ((TabControl)reviewWindow.FindName("ResultTabs")).SelectedIndex == 6);
                Check("0.2容器UI 结束后恢复操作入口且取消按钮关闭", TrustProxyUiButton(reviewWindow, "ContainerRecheckButton").IsEnabled &&
                    !TrustProxyUiButton(reviewWindow, "CancelScanButton").IsEnabled && GetTrustProxyUiReport(reviewWindow).Containers?.Nodes.Count == 2);
            }
            finally { reviewWindow.Close(); }
        }
        finally
        {
            string full = Path.GetFullPath(directory), temp = Path.GetFullPath(Path.GetTempPath());
            if (full.StartsWith(temp, StringComparison.OrdinalIgnoreCase) && Path.GetFileName(full).StartsWith("SteamSentinel-V020ContainerUi-", StringComparison.Ordinal)) Directory.Delete(full, true);
        }
    }

    private static async Task TestV020ContainerExportAsync(string root)
    {
        string directory = Path.Combine(root, "v020-container-export-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        string payload = Path.Combine(directory, "inert-original.txt");
        const string payloadSentinel = "INERT_PAYLOAD_BYTES_NOT_PART_OF_A_REPORT_37C01";
        await File.WriteAllTextAsync(payload, payloadSentinel);
        ScanReport report = V020ContainerPresentationFixture(payload, Path.Combine(directory, "inert.part2.rar"), Path.Combine(directory, "temporary.txt"));
        string json = Path.Combine(directory, "report.json"), markdown = Path.Combine(directory, "report.md");
        await ReportExporter.ExportJsonAsync(report, json);
        await ReportExporter.ExportMarkdownAsync(report, markdown);
        string jsonText = await File.ReadAllTextAsync(json), markdownText = await File.ReadAllTextAsync(markdown);
        ScanReport? restored = JsonSerializer.Deserialize<ScanReport>(jsonText, JsonFile.Options);
        Check("0.2容器报告 JSON保留父子ID外层哈希五阶段引擎与资源", restored?.Containers is { Nodes.Count: 2 } containers &&
            containers.Nodes[1].ParentId == containers.Nodes[0].NodeId && containers.Nodes[1].Integrity == ContainerStageStatus.UnsupportedIntegrity &&
            containers.Nodes[0].Volumes.Count == 3 && containers.Resources.PasswordAttempts == 2 && containers.Resources.NativeReservedReadBytes == 1024 &&
            containers.Limits.MaximumWorkBytes == 64L * 1024 * 1024 * 1024);
        Check("0.2容器报告 Markdown保存可读完整阶段链与实际预算", markdownText.Contains("容器递归、完整性与检查预算", StringComparison.Ordinal) &&
            markdownText.Contains("完整性算法暂不支持", StringComparison.Ordinal) && markdownText.Contains("五阶段", StringComparison.Ordinal) &&
            markdownText.Contains(report.Containers!.Nodes[1].DisplayPath, StringComparison.Ordinal) && markdownText.Contains("64.00 GiB", StringComparison.Ordinal));
        Check("0.2容器报告 普通JSON和Markdown不包含样本bytes或秘密", !jsonText.Contains(payloadSentinel, StringComparison.Ordinal) &&
            !markdownText.Contains(payloadSentinel, StringComparison.Ordinal) && !jsonText.Contains(V020ContainerUiSecret, StringComparison.Ordinal) &&
            !markdownText.Contains(V020ContainerUiSecret, StringComparison.Ordinal) && Directory.GetFiles(directory).Length == 3);
        string described = ContainerReportPresentation.Describe(report.Containers!);
        Check("0.2容器报告 元数据说明区分签名完整性与风险", described.Contains("未签名不等于恶意", StringComparison.Ordinal) &&
            described.Contains("任一阶段完成都不单独证明内容安全", StringComparison.Ordinal) && described.Contains("本轮未请求写出恢复内容", StringComparison.Ordinal) &&
            described.Contains("原生接口预留读取预算", StringComparison.Ordinal) && described.Contains("预留解码预算", StringComparison.Ordinal) &&
            described.Contains("工作预算占用（含原生预留）", StringComparison.Ordinal));
        ContainerScanReport inconsistent = new()
        {
            Complete = true,
            Nodes = [new() { Overall = ContainerStageStatus.Complete, Recognition = ContainerStageStatus.Complete,
            DirectoryRead = ContainerStageStatus.Complete, Decryption = ContainerStageStatus.Complete, Integrity = ContainerStageStatus.UnsupportedIntegrity, ContentCheck = ContainerStageStatus.Complete }]
        };
        Check("0.2容器报告 总状态完成不能遮盖阶段缺口", ContainerReportPresentation.Summary(inconsistent).Contains("未完成", StringComparison.Ordinal));
        ContainerScanNode cycle = new() { NodeId = Guid.Parse("366423dd-5a20-4672-b642-03334d0257ea"), ParentId = Guid.Parse("366423dd-5a20-4672-b642-03334d0257ea") };
        Check("0.2容器报告 损坏父链不会无限循环", ContainerReportPresentation.Ancestors(new() { Nodes = [cycle] }, cycle).Count == 1);
    }

    private static ScanReport V020ContainerPresentationFixture(string original, string volume, string temporary)
    {
        Guid outerId = Guid.Parse("175b2f35-9c38-4f89-9af0-552413dca168"), innerId = Guid.Parse("39c97a0f-9d49-4bca-b8bc-dc5fb77f5b4a");
        string longPath = original + "::RAR::" + string.Join("/", Enumerable.Repeat("无害长路径容器节点", 28)) + "/inert.msi";
        ContainerScanNode outer = new()
        {
            NodeId = outerId,
            Kind = ContainerNodeKind.VolumeGroup,
            DisplayPath = original,
            OriginalTarget = original,
            OriginalTargetSha256 = new string('A', 64),
            Sha256 = new string('A', 64),
            Format = "RAR5",
            Length = 1234,
            Recognition = ContainerStageStatus.Complete,
            DirectoryRead = ContainerStageStatus.Complete,
            Decryption = ContainerStageStatus.Complete,
            Integrity = ContainerStageStatus.Complete,
            ContentCheck = ContainerStageStatus.Partial,
            Overall = ContainerStageStatus.Partial,
            Signature = ContentSignatureStatus.NotSigned,
            CompletedAtUtc = DateTimeOffset.UtcNow,
            Volumes = [new() { OriginalPath = original, DisplayName = "inert.part1.rar", Sha256 = new string('A', 64), Length = 1234 },
                new() { OriginalPath = volume, DisplayName = "inert.part2.rar", Sha256 = new string('B', 64), Length = 5678 },
                new() { OriginalPath = temporary, DisplayName = "temporary.bin", IsTemporary = true, Length = 111 }]
        };
        ContainerScanNode inner = new()
        {
            NodeId = innerId,
            ParentId = outerId,
            Kind = ContainerNodeKind.ArchiveMember,
            DisplayPath = longPath,
            OriginalTarget = temporary,
            OriginalTargetSha256 = new string('A', 64),
            Sha256 = new string('C', 64),
            Format = "MSI",
            Length = 4096,
            Depth = 2,
            Recognition = ContainerStageStatus.Complete,
            DirectoryRead = ContainerStageStatus.Complete,
            Decryption = ContainerStageStatus.NotRequested,
            Integrity = ContainerStageStatus.UnsupportedIntegrity,
            ContentCheck = ContainerStageStatus.Complete,
            Overall = ContainerStageStatus.Partial,
            ParentOffset = 512,
            ParentLength = 4096,
            Signature = ContentSignatureStatus.Untrusted,
            CompletedAtUtc = DateTimeOffset.UtcNow,
            Engines = [new() { Engine = "inert-metadata-engine", Status = ContainerStageStatus.UnsupportedIntegrity, Offset = 0, Length = 4096, Detail = "无害测试：该完整性算法暂不支持。token=" + V020ContainerUiSecret }],
            Details = ["这是无害UI测试记录，不读取真实归档或证书。"]
        };
        return new()
        {
            Mode = ScanMode.Custom,
            Coverage = ScanCoverage.Partial,
            CompletedAtUtc = DateTimeOffset.UtcNow,
            ContentScanSettings = new() { Mode = ScanMode.Custom, IncludeSystem = false, IncludeSteam = false, IncludeWorkshop = false, CustomRoots = [original] },
            Containers = new()
            {
                Nodes = [outer, inner],
                Complete = false,
                Resources = new()
                {
                    ReadBytes = 512,
                    DecodedBytes = 256,
                    AcceptedExpandedBytes = 128,
                    RangeCopyBytes = 32,
                    NativeReservedReadBytes = 1024,
                    CurrentTemporaryBytes = 0,
                    PeakTemporaryBytes = 256,
                    PeakPrivateMemoryBytes = 65536,
                    MetadataAttempts = 3,
                    PasswordAttempts = 2,
                    ElapsedMilliseconds = 1250
                }
            }
        };
    }
}
