using System.IO;
using System.Text.Json;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Media;
using SteamSentinel.App;
using SteamSentinel.App.Services;
using SteamSentinel.App.ViewModels;
using SteamSentinel.Core.Models;
using SteamSentinel.Core.Reporting;
using SteamSentinel.Core.Utilities;

namespace SteamSentinel.SelfTest;

internal static partial class Program
{
    private static int RunFindingPriorityUi(string output)
    {
        AppContext.SetSwitch("Switch.System.Windows.Media.ShouldRenderEvenWhenNoDisplayDevicesAreAvailable", true);
        output = Path.GetFullPath(output);
        Directory.CreateDirectory(output);
        Exception? error = null;
        Thread thread = new(() =>
        {
            SteamSentinel.App.App? app = null;
            try
            {
                RenderOptions.ProcessRenderMode = System.Windows.Interop.RenderMode.SoftwareOnly;
                app = UiFixtureApplication.Create();
                TestFindingPriorityUi(output);
            }
            catch (Exception ex) { error = ex; }
            finally { app?.Shutdown(); }
        });
        thread.SetApartmentState(ApartmentState.STA);
        thread.Start();
        thread.Join();
        if (error is not null) Failures.Add("Finding priority UI fixture error: " + error);
        File.WriteAllText(Path.Combine(output, "finding-priority-ui-results.json"), JsonSerializer.Serialize(new
        {
            passed = _passed,
            failed = Failures.Count,
            failures = Failures,
            skipped = _skipped,
            version = ProductInfo.Version,
            buildIdentity = ProductInfo.BuildIdentity,
            safety = "Hidden inert UI fixtures; no scanning, file execution, Broker execution, or remediation."
        }, new JsonSerializerOptions { WriteIndented = true }));
        foreach (string failure in Failures) Console.WriteLine("FAIL: " + failure);
        Console.WriteLine($"Finding priority UI: passed {_passed}; failed {Failures.Count}");
        return Failures.Count == 0 ? 0 : 1;
    }

    // Run with the existing isolated STA/Application, using only synthetic reports.
    private static void TestFindingPriorityUi(string? output = null)
    {
        foreach (var culture in new[] { DisplayText.Chinese, DisplayText.English })
        {
            using IDisposable language = DisplayText.UseCulture(culture);
            foreach ((int width, int height) in new[] { (1148, 780), (784, 460) })
            {
                string label = $"Finding priority {culture.Name}/{width}x{height}";
                MainWindow window = new();
                try
                {
                    using UiLayoutHarness layout = new(window, width, height);
                    ScanReport report = CreateFindingPriorityUiReport();
                    string original = JsonSerializer.Serialize(report, JsonFile.Options);
                    SetTrustProxyUiReport(window, report);
                    UiPreview.ApplyAccessState(window, InstallationSecurityStatus.Protected, new(false, true));
                    DataGrid priority = (DataGrid)window.FindName("FindingsGrid");
                    DataGrid reference = (DataGrid)window.FindName("ReferenceFindingsGrid");
                    Expander referenceGroup = (Expander)window.FindName("ReferenceFindingsExpander");
                    TextBlock detailScore = TrustProxyUiText(window, "DetailScoreText");
                    layout.Refresh();
                    string formatOnlyTitle = TrustProxyUiText(window, "HeaderStatusText").Text;
                    Check(label + " groups all 216 format findings without dropping the original evidence",
                        window.Findings.Count == 216 && priority.Items.Count == 0 && reference.Items.Count == 216 &&
                        !referenceGroup.IsExpanded && referenceGroup.Visibility == Visibility.Visible &&
                        original == JsonSerializer.Serialize(report, JsonFile.Options));
                    Check(label + " gives a compact format-only summary without explanatory boilerplate",
                        formatOnlyTitle.Contains(culture.Name == "zh-Hans" ? "格式" : "format", StringComparison.OrdinalIgnoreCase) &&
                        string.IsNullOrWhiteSpace(TrustProxyUiText(window, "HeaderDetailText").Text) &&
                        TrustProxyUiText(window, "FindingCountText").Text.Contains("216", StringComparison.Ordinal));
                    Check(label + " hides empty detail and routine explanation panels for completed reference-only results",
                        ((FrameworkElement)window.FindName("FindingDetailCard")).Visibility == Visibility.Collapsed &&
                        ((FrameworkElement)window.FindName("RemediationAvailabilityPanel")).Visibility == Visibility.Collapsed &&
                        string.IsNullOrWhiteSpace(TrustProxyUiText(window, "ProgressItemText").Text));
                    Check(label + " removes numeric scores from both result tables",
                        !HasFindingScoreColumn(priority) && !HasFindingScoreColumn(reference));
                    Check(label + " keeps the group header and main actions reachable",
                        layout.IsFullyVisible(referenceGroup) &&
                        layout.IsFullyVisible(TrustProxyUiButton(window, "SelectAllButton")) &&
                        layout.IsFullyVisible(TrustProxyUiButton(window, "RemediateButton")));
                    if (output is not null) layout.Save($"priority-collapsed-{culture.Name}-{width}x{height}", output);

                    referenceGroup.IsExpanded = true;
                    reference.SelectedIndex = 0;
                    layout.Refresh();
                    Check(label + " expands the first reference row and shows its score in details",
                        reference.ItemContainerGenerator.ContainerFromIndex(0) is DataGridRow first && layout.IsFullyVisible(first) &&
                        detailScore.Text.Contains("40", StringComparison.Ordinal) && priority.SelectedItem is null &&
                        ((FrameworkElement)window.FindName("RemediationAvailabilityPanel")).Visibility == Visibility.Collapsed &&
                        TrustProxyUiButton(window, "ReviewFindingButton").IsEnabled);
                    if (output is not null) layout.Save($"priority-expanded-{culture.Name}-{width}x{height}", output);
                    reference.SelectedIndex = reference.Items.Count - 1;
                    reference.ScrollIntoView(reference.SelectedItem);
                    layout.Refresh();
                    Check(label + " can reach the last of 216 reference rows",
                        reference.ItemContainerGenerator.ContainerFromIndex(215) is DataGridRow last && layout.IsFullyVisible(last) &&
                        reference.SelectedItem is FindingItemViewModel { Finding.Id: "format-215" });
                    TabControl resultTabs = (TabControl)window.FindName("ResultTabs");
                    resultTabs.SelectedIndex = 1;
                    layout.Refresh();
                    Check(label + " does not carry the selected finding score into coverage details", string.IsNullOrWhiteSpace(detailScore.Text));
                    resultTabs.SelectedIndex = 0;
                    layout.Refresh();
                    Check(label + " restores the selected finding score on returning to results", detailScore.Text.Contains("40", StringComparison.Ordinal));
                    referenceGroup.IsExpanded = false;

                    ScanReport mixed = CreateFindingPriorityUiReport();
                    mixed.Findings.Add(new Finding
                    {
                        Id = "strong-on-first",
                        RuleId = "INERT-KNOWN-PRIORITY",
                        Category = FindingCategory.File,
                        Severity = FindingSeverity.Critical,
                        Score = 100,
                        IsKnownMalware = true,
                        CanRemediate = true,
                        Target = mixed.Findings[0].Target,
                        Sha256 = new string('B', 64),
                        Title = "Inert known malware finding",
                        SuggestedActions = [SuggestedActionKind.QuarantineFile]
                    });
                    SetTrustProxyUiReport(window, mixed);
                    layout.Refresh();
                    Check(label + " promotes the matching file and its format evidence without hiding the strong result",
                        priority.Items.Count == 2 && reference.Items.Count == 215 && window.Findings.Count == 217 &&
                        priority.Items[0] is FindingItemViewModel { Finding.Id: "strong-on-first" } &&
                        priority.Items.Cast<FindingItemViewModel>().Any(item => item.Finding.Id == "format-0") &&
                        !referenceGroup.IsExpanded && TrustProxyUiText(window, "HeaderStatusText").Text != formatOnlyTitle);
                    Check(label + " keeps a priority row visible with the collapsed reference group",
                        priority.ItemContainerGenerator.ContainerFromIndex(0) is DataGridRow priorityRow && layout.IsFullyVisible(priorityRow));
                    if (output is not null) layout.Save($"priority-mixed-{culture.Name}-{width}x{height}", output);
                    ((ComboBox)window.FindName("RemediationModeComboBox")).SelectedIndex = 1;
                    layout.Refresh();
                    Button selectAll = TrustProxyUiButton(window, "SelectAllButton");
                    typeof(MainWindow).GetMethod("SelectAll_Click", TrustProxyUiPrivate)!.Invoke(window, [selectAll, new RoutedEventArgs()]);
                    Check(label + " select-all excludes collapsed references even in aggressive mode",
                        window.Findings.Any(item => item.IsSelected) &&
                        reference.Items.Cast<FindingItemViewModel>().All(item => !item.IsSelected));
                    referenceGroup.IsExpanded = true;
                    layout.Refresh();
                    FindingItemViewModel? referenceChoice = reference.Items.Cast<FindingItemViewModel>().FirstOrDefault(item => item.CanSelect);
                    if (referenceChoice is not null)
                    {
                        reference.SelectedItem = referenceChoice;
                        referenceChoice.IsSelected = true;
                    }
                    referenceGroup.IsExpanded = false;
                    layout.Refresh();
                    Check(label + " collapsing the reference group clears an explicitly selected risk and its detail selection",
                        referenceChoice is not null && !referenceChoice.IsSelected && reference.SelectedItem is null &&
                        reference.Items.Cast<FindingItemViewModel>().All(item => !item.IsSelected));
                    referenceGroup.IsExpanded = true;
                    if (referenceChoice is not null) referenceChoice.IsSelected = true;
                    ((ComboBox)window.FindName("RemediationModeComboBox")).SelectedIndex = 0;
                    layout.Refresh();
                    Check(label + " mode changes preserve the expanded view while clearing all remediation checkboxes",
                        referenceGroup.IsExpanded && window.Findings.All(item => !item.IsSelected));

                    ScanReport incomplete = CreateFindingPriorityUiReport();
                    incomplete.Coverage = ScanCoverage.Partial;
                    SetTrustProxyUiReport(window, incomplete);
                    layout.Refresh();
                    Check(label + " keeps incomplete coverage distinct from the completed format-only result",
                        TrustProxyUiText(window, "HeaderStatusText").Text != formatOnlyTitle &&
                        ((TabItem)window.FindName("CoverageTab")).Header?.ToString() == DisplayText.Get("Ui.xaml.PopulateFindings.04") &&
                        reference.Items.Count == 216);
                    foreach (bool cancelled in new[] { false, true })
                    {
                        ScanReport interrupted = CreateFindingPriorityUiReport();
                        typeof(MainWindow).GetMethod("PreserveScanFailure", TrustProxyUiPrivate)!.Invoke(window,
                            [interrupted, ScanMode.Custom, Array.Empty<string>(), new IOException("Inert priority UI interruption"), cancelled]);
                        layout.Refresh();
                        Check(label + $" {(cancelled ? "cancellation" : "failure")} is not replaced by a format-only conclusion",
                            TrustProxyUiText(window, "HeaderStatusText").Text == DisplayText.Get(cancelled
                                ? "Ui.xaml.PreserveScanFailure.01" : "Ui.xaml.PreserveScanFailure.02") &&
                            GetTrustProxyUiReport(window).Coverage == ScanCoverage.Partial && reference.Items.Count == 216 &&
                            TrustProxyUiButton(window, "ExportButton").IsEnabled);
                    }
                }
                finally { CloseSummaryFixture(window); }
            }
        }
    }

    private static bool HasFindingScoreColumn(DataGrid grid) => grid.Columns.OfType<DataGridBoundColumn>()
        .Any(column => column.Binding is Binding { Path.Path: "Score" });

    private static ScanReport CreateFindingPriorityUiReport()
    {
        ScanReport report = new()
        {
            Mode = ScanMode.Custom,
            Coverage = ScanCoverage.Complete,
            StatusSchemaVersion = 1,
            ExecutionState = ScanExecutionState.Completed,
            CompletedAtUtc = DateTimeOffset.UtcNow,
            Containers = new() { Complete = true }
        };
        string directory = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads");
        for (int i = 0; i < 216; i++)
        {
            string path = Path.Combine(directory, $"inert-format-{i:D3}.dat");
            report.Findings.Add(new Finding
            {
                Id = "format-" + i,
                RuleId = "CONTENT-EXTENSION-MISMATCH",
                Category = FindingCategory.Archive,
                Severity = FindingSeverity.Medium,
                Score = 40,
                Target = path,
                ContentPath = path,
                Sha256 = new string('A', 64),
                Title = "Inert file format finding",
                SuggestedActions = [SuggestedActionKind.ReviewOnly]
            });
            report.Containers.Nodes.Add(new ContainerScanNode
            {
                Kind = ContainerNodeKind.File,
                Format = "Zip",
                DisplayPath = path,
                OriginalTarget = path,
                Recognition = ContainerStageStatus.Complete,
                Integrity = ContainerStageStatus.Complete,
                ContentCheck = ContainerStageStatus.Complete,
                Overall = ContainerStageStatus.Complete
            });
        }
        return report;
    }
}
