using System.IO;
using System.Reflection;
using System.Text.Json;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using SteamSentinel.App;
using SteamSentinel.App.Dialogs;
using SteamSentinel.Core.Models;
using SteamSentinel.Core.Reporting;
using SteamSentinel.Core.Utilities;

namespace SteamSentinel.SelfTest;

internal static partial class Program
{
    private static int RunRemediationFailureDetailsTests(string output)
    {
        AppContext.SetSwitch("Switch.System.Windows.Media.ShouldRenderEvenWhenNoDisplayDevicesAreAvailable", true);
        output = Path.GetFullPath(output);
        Directory.CreateDirectory(output);
        TestRemediationFailureDetails();
        Exception? error = null;
        Thread thread = new(() =>
        {
            SteamSentinel.App.App? app = null;
            try
            {
                RenderOptions.ProcessRenderMode = System.Windows.Interop.RenderMode.SoftwareOnly;
                app = UiFixtureApplication.Create();
                TestRemediationFailureDetailsUi(output);
            }
            catch (Exception ex) { error = ex; }
            finally { app?.Shutdown(); }
        });
        thread.SetApartmentState(ApartmentState.STA);
        thread.Start();
        thread.Join();
        if (error is not null) Failures.Add("Remediation failure details fixture error: " + error);
        File.WriteAllText(Path.Combine(output, "remediation-result-details-results.json"), JsonSerializer.Serialize(new
        {
            passed = _passed,
            failed = Failures.Count,
            skipped = _skipped,
            failures = Failures,
            version = ProductInfo.Version,
            buildIdentity = ProductInfo.BuildIdentity,
            safety = "In-memory records and hidden WPF fixtures only; no samples, Broker execution, remediation, or clipboard writes."
        }, new JsonSerializerOptions { WriteIndented = true }));
        foreach (string failure in Failures) Console.WriteLine("FAIL: " + failure);
        Console.WriteLine($"Remediation result details: passed {_passed}; failed {Failures.Count}");
        return Failures.Count == 0 ? 0 : 1;
    }

    private static void TestRemediationFailureDetailsUi(string? output)
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
                    UiPreview.ApplyAccessState(window, InstallationSecurityStatus.Protected, new(false, true));
                    RemediationBatchSession batch = CreateRemediationFailureDetailsFixture();
                    typeof(MainWindow).GetField("_caseBatch", BindingFlags.Instance | BindingFlags.NonPublic)!.SetValue(window, batch);
                    typeof(MainWindow).GetMethod("UpdateBatchResults", BindingFlags.Instance | BindingFlags.NonPublic)!.Invoke(window, null);
                    ((Expander)window.FindName("ScanOptionsExpander")).IsExpanded = false;
                    ((TabControl)window.FindName("ResultTabs")).SelectedItem = window.FindName("BatchResultsTab");
                    DataGrid grid = (DataGrid)window.FindName("BatchResultsGrid");
                    Button open = (Button)window.FindName("BatchActionDetailsButton");
                    RemediationTargetOutcome target = batch.Targets.Single(item => item.Key == "executable");
                    grid.SelectedItem = target;
                    layout.Refresh();
                    string label = $"Remediation details UI {culture.Name}/{width}x{height}";
                    Check(label + " retains the result list and visible complete-record control",
                        grid.ActualHeight >= 48 && layout.HasReadableColumns(grid) && open.IsEnabled &&
                        layout.IsFullyVisible(open) && layout.DoNotOverlap([grid, open]));
                    DataGridRow? firstRow = grid.ItemContainerGenerator.ContainerFromIndex(0) as DataGridRow;
                    TextBlock? firstStatus = grid.Columns[0].GetCellContent(grid.Items[0]) as TextBlock;
                    TextBlock? firstTarget = grid.Columns[1].GetCellContent(grid.Items[0]) as TextBlock;
                    TextBlock? firstReason = grid.Columns[2].GetCellContent(grid.Items[0]) as TextBlock;
                    Check(label + " shows a complete first row with centered status and two-line previews backed by full tooltips",
                        firstRow is not null && firstRow.ActualHeight <= 40 && layout.IsFullyVisible(firstRow) &&
                        firstStatus?.VerticalAlignment == VerticalAlignment.Center &&
                        new[] { firstTarget, firstReason }.All(text => text is not null && text.MaxHeight == 32 &&
                            text.ActualHeight <= 32 && text.LineHeight == 16 && text.LineStackingStrategy == LineStackingStrategy.BlockLineHeight &&
                            text.TextTrimming == TextTrimming.CharacterEllipsis && string.Equals(text.ToolTip as string, text.Text, StringComparison.Ordinal)));
                    if (output is not null) layout.Save($"remediation-details-list-{culture.Name}-{width}x{height}", output);
                    TextDetailsWindow details = window.CreateBatchActionDetailsWindow()
                        ?? throw new InvalidOperationException("Selected target details window was not created.");
                    int detailWidth = width > 1000 ? 760 : 600, detailHeight = width > 1000 ? 520 : 420;
                    using (UiLayoutHarness detailLayout = new(details, detailWidth, detailHeight))
                    {
                        TextBox text = (TextBox)details.FindName("DetailsTextBox");
                        Button copy = (Button)details.FindName("CopyDetailsButton");
                        RemediationActionResult firewall = batch.Results.Single().Actions.Single(action => action.Type == RemediationActionType.AddProgramFirewallBlock);
                        Check(label + " exposes first-pass failure, later clear pass, and the dependent quarantine in read-only copyable text",
                            text.IsReadOnly && !text.IsUndoEnabled && text.AcceptsReturn && copy.IsEnabled &&
                            text.Text.Contains(firewall.Verifications[0].MessageText.Display, StringComparison.Ordinal) &&
                            text.Text.Contains("INERT_SECOND_PASS_CLEAR", StringComparison.Ordinal) &&
                            text.Text.Contains(RemediationResultPresentation.ExecutionLabel(RemediationExecutionStatus.SkippedDependency), StringComparison.Ordinal) &&
                            !text.Text.Contains("INERT_HOSTS_COMPLETED", StringComparison.Ordinal));
                        text.SelectAll();
                        Check(label + " allows selecting the full content without clipping the copy and close controls",
                            text.SelectedText == text.Text && text.ActualHeight >= 72 && detailLayout.IsFullyVisible(copy) &&
                            detailLayout.IsFullyVisible((Button)details.FindName("CloseDetailsButton")));
                        text.Select(text.Text.Length, 0);
                        text.ScrollToEnd();
                        detailLayout.Refresh();
                        Rect tail = text.GetRectFromCharacterIndex(Math.Max(0, text.Text.Length - 1));
                        Check(label + " keeps the final action and verification boundary reachable by scrolling",
                            !tail.IsEmpty && tail.Top >= 0 && tail.Bottom <= text.ActualHeight + 1);
                        if (output is not null) detailLayout.Save($"remediation-details-record-{culture.Name}-{width}x{height}", output);
                    }
                    details.Close();
                    grid.SelectedItem = null;
                    Check(label + " disables details when no target is selected", !open.IsEnabled && window.CreateBatchActionDetailsWindow() is null);
                }
                finally { CloseSummaryFixture(window); }
            }
        }
    }
}
