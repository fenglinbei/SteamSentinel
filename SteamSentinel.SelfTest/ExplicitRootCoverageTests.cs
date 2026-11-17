using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Windows.Controls;
using SteamSentinel.App;
using SteamSentinel.App.Services;
using SteamSentinel.Core.Models;
using SteamSentinel.Core.Reporting;
using SteamSentinel.Core.Scanning;
using SteamSentinel.Core.Utilities;

namespace SteamSentinel.SelfTest;

internal static partial class Program
{
    private static async Task TestExplicitRootCoverageScannerAsync(string output)
    {
        string directory = Path.Combine(Path.GetFullPath(output), "explicit-root-coverage-" + Guid.NewGuid().ToString("N"));
        string physical = Path.Combine(directory, "physical");
        string nested = Path.Combine(physical, "nested");
        string empty = Path.Combine(directory, "empty");
        string junction = Path.Combine(directory, "junction");
        Directory.CreateDirectory(nested);
        Directory.CreateDirectory(empty);
        Directory.CreateDirectory(junction);
        byte[] bytes = Encoding.UTF8.GetBytes("Locally generated harmless text for skipped-root coverage regression.");
        string note = Path.Combine(nested, "note.txt");
        await File.WriteAllBytesAsync(note, bytes);
        RuleSet rules = new()
        {
            KnownHashes = [new HashRule { Id = "TEST-UNREAD-ROOT-INERT-HASH", Label = "Harmless root coverage fixture",
                Sha256 = Convert.ToHexString(SHA256.HashData(bytes)), Malware = true, Severity = FindingSeverity.High }]
        };
        static ScanOptions Options(params string[] roots) => new()
        {
            Mode = ScanMode.Custom,
            CustomRoots = roots.ToList(),
            IncludeSystem = false,
            IncludeSteam = false,
            IncludeWorkshop = false,
            InspectArchives = false,
            InspectDeepSignatures = false,
            HashEveryFile = true,
            UseAmsi = false
        };
        try
        {
            V020RecoverySetJunction(junction, physical);
            foreach (string root in new[] { junction, Path.Combine(junction, "nested") })
            {
                ScanReport blocked = await new ScanCoordinator(rules).RunAsync(Options(root));
                Check("显式目录检查：junction及其后代保留零读取与结构化UnsafePath", blocked.Coverage == ScanCoverage.Partial &&
                    blocked.Metrics.FilesVisited == 0 && blocked.RootSummaries is [{ Coverage: ScanCoverage.Partial, FilesVisited: 0 }] &&
                    blocked.Findings is [{ RuleId: "SCAN-PARTIAL", Category: FindingCategory.Coverage, ReasonCode: ReasonCodes.UnsafePath }] &&
                    CoveragePresentation.Groups(blocked) is [{ ReasonCode: ReasonCodes.UnsafePath, CanFullScan: false }] &&
                    MainWindow.ExplicitContentRootsUnchecked(blocked));
                string json = JsonSerializer.Serialize(blocked, JsonFile.Options);
                ScanReport restored = JsonSerializer.Deserialize<ScanReport>(json, JsonFile.Options)!;
                Check("显式目录检查：JSON往返保留未读取的路径与原因", MainWindow.ExplicitContentRootsUnchecked(restored) &&
                    restored.Findings.Single().ReasonCode == ReasonCodes.UnsafePath);
                await File.WriteAllTextAsync(Path.Combine(directory,
                    root == junction ? "junction-report.json" : "ancestor-junction-report.json"), json);
            }
            ScanReport allBlocked = await new ScanCoordinator(rules).RunAsync(Options(junction, Path.Combine(junction, "nested")));
            Check("显式目录检查：多个所选根全部被拒时明确标为未检查", allBlocked.RootSummaries.Count == 2 &&
                allBlocked.Metrics.FilesVisited == 0 && MainWindow.ExplicitContentRootsUnchecked(allBlocked));
            ScanReport emptyReport = await new ScanCoordinator(rules).RunAsync(Options(empty));
            Check("显式目录检查：正常空目录是完成检查而不是被跳过", emptyReport.Coverage == ScanCoverage.Complete &&
                emptyReport.RootSummaries is [{ Coverage: ScanCoverage.Complete, FilesVisited: 0 }] &&
                !MainWindow.ExplicitContentRootsUnchecked(emptyReport));
            ScanReport blockedAndEmpty = await new ScanCoordinator(rules).RunAsync(Options(junction, empty));
            Check("显式目录检查：部分根为空且已完成时不宣称所有根未检查", blockedAndEmpty.Coverage == ScanCoverage.Partial &&
                blockedAndEmpty.Metrics.FilesVisited == 0 && !MainWindow.ExplicitContentRootsUnchecked(blockedAndEmpty));
            ScanReport physicalReport = await new ScanCoordinator(rules).RunAsync(Options(nested));
            Check("显式目录检查：物理路径确实读取同一无害文本并命中测试专用精确规则", physicalReport.Metrics.FilesVisited == 1 &&
                physicalReport.Findings.Any(f => f.RuleId == "TEST-UNREAD-ROOT-INERT-HASH" && f.IsKnownMalware) &&
                !MainWindow.ExplicitContentRootsUnchecked(physicalReport));
            ScanReport mixedRoots = await new ScanCoordinator(rules).RunAsync(Options(junction, nested));
            Check("显式目录检查：存在真实读取时保留部分覆盖及发现", mixedRoots.Coverage == ScanCoverage.Partial &&
                mixedRoots.Metrics.FilesVisited == 1 && mixedRoots.Findings.Any(f => f.IsKnownMalware) &&
                !MainWindow.ExplicitContentRootsUnchecked(mixedRoots));
            ScanOptions excludedOptions = Options(nested);
            excludedOptions.ExcludedRoots.Add(nested);
            ScanReport excluded = await new ScanCoordinator(rules).RunAsync(excludedOptions);
            Check("显式目录检查：显式排除的根也不能得到已检查的结论", excluded.Metrics.FilesVisited == 0 &&
                excluded.Findings.Any(f => f.RuleId == "SCAN-EXCLUDED") && MainWindow.ExplicitContentRootsUnchecked(excluded));
        }
        finally
        {
            // Delete only the fixture link, never its target or the surrounding tree.
            Directory.Delete(junction, recursive: false);
        }
        Check("显式目录检查：拒绝链接和移除测试链接不改变真实文件", File.Exists(note) &&
            (await File.ReadAllBytesAsync(note)).AsSpan().SequenceEqual(bytes));
    }

    private static void TestExplicitRootCoverageUi(string? output)
    {
        foreach (var culture in new[] { DisplayText.Chinese, DisplayText.English })
        {
            using IDisposable language = DisplayText.UseCulture(culture);
            foreach ((int width, int height) in new[] { (1148, 780), (784, 460) })
            {
                string label = $"Explicit root coverage {culture.Name}/{width}x{height}";
                MainWindow window = new();
                try
                {
                    using UiLayoutHarness layout = new(window, width, height);
                    TabControl tabs = (TabControl)window.FindName("ResultTabs");
                    ScanReport blocked = CreateExplicitRootCoverageReport();
                    SetTrustProxyUiReport(window, blocked);
                    // Hidden windows never run Loaded or the scan's finally block.
                    // Enter the same idle, initialized state as a completed real scan.
                    UiPreview.ApplyAccessState(window, InstallationSecurityStatus.Protected, new(false, true));
                    layout.Refresh();
                    Check(label + " shows the uninspected content instead of a no-risk conclusion", window.Findings.Count == 0 &&
                        TrustProxyUiText(window, "HeaderStatusText").Text == DisplayText.Get("Coverage.ExplicitRootsUnchecked.Title") &&
                        TrustProxyUiText(window, "HeaderDetailText").Text == DisplayText.Get("Coverage.ExplicitRootsUnchecked.Detail") &&
                        tabs.SelectedItem == window.FindName("CoverageTab") &&
                        ((DataGrid)window.FindName("CoverageGrid")).SelectedItem is CoverageGroup { ReasonCode: ReasonCodes.UnsafePath } &&
                        TrustProxyUiText(window, "DetailEvidenceText").Text.Contains(blocked.Roots[0], StringComparison.Ordinal) &&
                        !TrustProxyUiButton(window, "CoverSelectedButton").IsEnabled);
                    Check(label + " keeps the title and rejected-path explanation visible",
                        layout.IsFullyVisible(TrustProxyUiText(window, "HeaderStatusText")) &&
                        layout.IsFullyVisible((DataGrid)window.FindName("CoverageGrid")));
                    if (output is not null) layout.Save($"unread-root-{culture.Name}-{width}x{height}", output);

                    ScanReport empty = CreateExplicitRootCoverageReport();
                    empty.Coverage = ScanCoverage.Complete;
                    empty.Findings.Clear();
                    empty.RootSummaries[0] = empty.RootSummaries[0] with { Coverage = ScanCoverage.Complete };
                    tabs.SelectedIndex = 0;
                    SetTrustProxyUiReport(window, empty);
                    Check(label + " keeps a completed empty directory distinct", tabs.SelectedIndex == 0 &&
                        TrustProxyUiText(window, "HeaderStatusText").Text == DisplayText.Get("Ui.xaml.UpdateSummary.14"));

                    ScanReport missingSummary = CreateExplicitRootCoverageReport();
                    missingSummary.RootSummaries.Clear();
                    Check(label + " does not infer a skipped root from zero counters or localized text alone",
                        !MainWindow.ExplicitContentRootsUnchecked(missingSummary));

                    ScanReport system = new()
                    {
                        Mode = ScanMode.Full,
                        Coverage = ScanCoverage.Complete,
                        CompletedAtUtc = DateTimeOffset.UtcNow,
                        StatusSchemaVersion = ScanExecution.SchemaVersion,
                        ExecutionState = ScanExecutionState.Completed,
                        Metrics = new() { FilesVisited = 5, ProcessesVisited = 7, PersistenceItemsVisited = 3 }
                    };
                    ScanReport merged = ScanReportMerger.Merge(system, blocked);
                    SetTrustProxyUiReport(window, merged);
                    Check(label + " scopes the unchecked message to content while retaining completed system counters",
                        TrustProxyUiText(window, "HeaderStatusText").Text == DisplayText.Get("Coverage.ExplicitRootsUnchecked.Title") &&
                        merged.ExecutionState == ScanExecutionState.Completed && merged.Metrics.FilesVisited == 5 && merged.Metrics.ProcessesVisited == 7 &&
                        merged.Metrics.PersistenceItemsVisited == 3);
                    system.Findings.Add(new Finding
                    {
                        RuleId = "TEST-INERT-SYSTEM-THREAT",
                        Category = FindingCategory.Process,
                        Severity = FindingSeverity.High,
                        IsKnownMalware = true,
                        Target = "Inert system observation; no process exists",
                        SuggestedActions = [SuggestedActionKind.ReviewOnly]
                    });
                    merged = ScanReportMerger.Merge(system, blocked);
                    tabs.SelectedIndex = 0;
                    SetTrustProxyUiReport(window, merged);
                    Check(label + " gives a system threat priority over unread content", tabs.SelectedIndex == 0 &&
                        TrustProxyUiText(window, "HeaderStatusText").Text == DisplayText.Get("Ui.xaml.UpdateSummary.01") &&
                        TrustProxyUiText(window, "HeaderDetailText").Text == DisplayText.Get("Coverage.ExplicitRootsUnchecked.Detail") &&
                        ((DataGrid)window.FindName("FindingsGrid")).Items.Count == 1);
                }
                finally { CloseSummaryFixture(window); }
            }
        }
    }

    private static ScanReport CreateExplicitRootCoverageReport()
    {
        const string root = @"C:\SteamSentinel-Inert-Coverage-Fixtures\junction\selected";
        return new()
        {
            Mode = ScanMode.Custom,
            Coverage = ScanCoverage.Partial,
            StatusSchemaVersion = ScanExecution.SchemaVersion,
            ExecutionState = ScanExecutionState.Completed,
            CompletedAtUtc = DateTimeOffset.UtcNow,
            Roots = [root],
            ContentScanSettings = new() { Mode = ScanMode.Custom, CustomRoots = [root], IncludeSystem = false, IncludeSteam = false, IncludeWorkshop = false },
            RootSummaries = [new(root, ScanCoverage.Partial, 0, 0, 0)],
            Findings = [new()
            {
                RuleId = "SCAN-PARTIAL", Category = FindingCategory.Coverage, ReasonCode = ReasonCodes.UnsafePath,
                Target = root, DescriptionText = MessageText.Create("Backend.Core.ContentScanner.ScanRootCoreAsync.02", root)
            }]
        };
    }
}
