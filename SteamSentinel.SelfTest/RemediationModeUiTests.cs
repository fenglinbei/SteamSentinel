using System.IO;
using System.IO.Compression;
using System.Text.Json;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using SteamSentinel.App;
using SteamSentinel.App.Dialogs;
using SteamSentinel.App.Services;
using SteamSentinel.Broker;
using SteamSentinel.Core.Inspection;
using SteamSentinel.Core.Models;
using SteamSentinel.Core.Remediation;
using SteamSentinel.Core.Reporting;
using SteamSentinel.Core.Utilities;

namespace SteamSentinel.SelfTest;

internal static partial class Program
{
    private static int RunRemediationModeUi(string output)
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
                TestRemediationModeUi(output);
            }
            catch (Exception ex) { error = ex; }
            finally { app?.Shutdown(); }
        });
        thread.SetApartmentState(ApartmentState.STA);
        thread.Start();
        thread.Join();
        if (error is not null) Failures.Add("Remediation mode UI fixture error: " + error);
        File.WriteAllText(Path.Combine(output, "remediation-mode-ui-results.json"), JsonSerializer.Serialize(new
        {
            passed = _passed, failed = Failures.Count, failures = Failures,
            version = ProductInfo.Version, buildIdentity = ProductInfo.BuildIdentity,
            safety = "Hidden inert UI fixtures; no scan, process termination, Broker execution, or remediation."
        }, new JsonSerializerOptions { WriteIndented = true }));
        foreach (string failure in Failures) Console.WriteLine("FAIL: " + failure);
        Console.WriteLine($"Remediation mode UI: passed {_passed}; failed {Failures.Count}");
        return Failures.Count == 0 ? 0 : 1;
    }

    private static void TestRemediationModeUi(string output)
    {
        string target = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads", "inert-mode-risk.exe");
        Finding risk = new()
        {
            Id = "mode-risk", RuleId = "MANAGED-STEAM-CEF-HOST", Category = FindingCategory.File,
            Severity = FindingSeverity.High, Score = 90, Title = "Inert managed behavior finding",
            Target = target, Sha256 = new string('A', 64), SuggestedActions = [SuggestedActionKind.ReviewOnly]
        };
        Finding known = new()
        {
            Id = "mode-known", RuleId = "INERT-KNOWN", Category = FindingCategory.File,
            Severity = FindingSeverity.Critical, Score = 100, Title = "Inert known finding",
            Target = target + ".known", Sha256 = new string('B', 64), IsKnownMalware = true,
            CanRemediate = true, SuggestedActions = [SuggestedActionKind.QuarantineFile]
        };
        Finding unbound = new()
        {
            Id = "mode-unbound", RuleId = "INERT-UNBOUND", Category = FindingCategory.File,
            Severity = FindingSeverity.High, Score = 90, Title = "Inert unbound member",
            Target = target + ".zip", ContentPath = target + ".zip!/inner.exe",
            Sha256 = new string('C', 64), SuggestedActions = [SuggestedActionKind.ReviewOnly]
        };
        ScanReport report = new() { Findings = [known, risk, unbound], CompletedAtUtc = DateTimeOffset.UtcNow };
        string original = JsonSerializer.Serialize(report, JsonFile.Options);
        foreach (var culture in new[] { DisplayText.Chinese, DisplayText.English })
        {
            using IDisposable language = DisplayText.UseCulture(culture);
            Check($"Mode follow-up {culture.Name} unresolved source does not imply complete cleanup",
                MainWindow.HasUnresolvedSteamSource(report) &&
                MainWindow.SystemFollowUpSummary(report).Contains(DisplayText.Get("RemediationMode.UnresolvedSource"), StringComparison.Ordinal) &&
                !MainWindow.SystemFollowUpSummary(report).Contains(DisplayText.Get("Remediation.SystemFollowUpSummary.03"), StringComparison.Ordinal) &&
                MainWindow.ContentFollowUpSummary(report).Contains(DisplayText.Get("RemediationMode.UnresolvedSource"), StringComparison.Ordinal) &&
                !MainWindow.HasUnresolvedSteamSource(new ScanReport()));
            foreach ((int width, int height) in new[] { (1148, 780), (784, 460) })
            {
                MainWindow window = new();
                try
                {
                    using UiLayoutHarness layout = new(window, width, height);
                    SetTrustProxyUiReport(window, report);
                    UiPreview.ApplyAccessState(window, InstallationSecurityStatus.Protected, new(false, true));
                    ComboBox mode = (ComboBox)window.FindName("RemediationModeComboBox");
                    Button selectAll = TrustProxyUiButton(window, "SelectAllButton");
                    layout.Refresh();
                    Check($"Mode UI {culture.Name}/{width} defaults conservative without changing evidence",
                        window.CurrentRemediationMode == RemediationMode.Conservative && mode.SelectedIndex == 0 &&
                        window.Findings[0].IsSelected && !window.Findings[1].CanSelect && !window.Findings[2].CanSelect);
                    if (output is not null) layout.Save($"mode-conservative-{culture.Name}-{width}x{height}", output);
                    mode.SelectedIndex = 1;
                    layout.Refresh();
                    Check($"Mode UI {culture.Name}/{width} aggressive clears all selections and adds eligible risk only",
                        window.CurrentRemediationMode == RemediationMode.Aggressive && window.Findings.All(item => !item.IsSelected) &&
                        window.Findings[1].CanSelect && window.Findings[1].UserSelectedRisk && !window.Findings[2].CanSelect &&
                        window.Findings[1].Score == 90 && !window.Findings[1].Finding.IsKnownMalware &&
                        window.Findings[1].HandlingLabel.Contains(DisplayText.Get("RemediationMode.RiskLabel"), StringComparison.Ordinal) &&
                        original == JsonSerializer.Serialize(report, JsonFile.Options));
                    Check($"Mode UI {culture.Name}/{width} selector and actions fit viewport",
                        layout.IsFullyVisible(mode) && layout.IsFullyVisible(selectAll) &&
                        layout.IsFullyVisible(TrustProxyUiButton(window, "RemediateButton")));
                    DataGrid findings = (DataGrid)window.FindName("FindingsGrid");
                    DataGridRow? firstRow = findings.ItemContainerGenerator.ContainerFromIndex(0) as DataGridRow;
                    Check($"Mode UI {culture.Name}/{width} findings remain visible beside the new controls",
                        firstRow is not null && layout.IsFullyVisible(firstRow));
                    if (output is not null) layout.Save($"mode-aggressive-{culture.Name}-{width}x{height}", output);
                    typeof(MainWindow).GetMethod("SelectAll_Click", TrustProxyUiPrivate)!.Invoke(window, [selectAll, new RoutedEventArgs()]);
                    Check($"Mode UI {culture.Name}/{width} explicit select-all includes requested risk without changing finding",
                        window.Findings.Count(item => item.IsSelected) == 2 && !risk.CanRemediate && !risk.IsKnownMalware);
                    mode.SelectedIndex = 0;
                    layout.Refresh();
                    Check($"Mode UI {culture.Name}/{width} returning conservative clears selections and removes risk eligibility",
                        window.Findings.All(item => !item.IsSelected) && !window.Findings[1].CanSelect);
                }
                finally { CloseSummaryFixture(window); }
            }

            RemediationPlan plan = new()
            {
                Mode = RemediationMode.Aggressive, ExplicitFileTargetsRequested = true,
                Actions = new[] { RemediationActionType.StopProcess, RemediationActionType.RemoveRegistryValue, RemediationActionType.QuarantineFile }
                    .Select(type => new RemediationAction
                    {
                        Type = type, Target = target, DisplayName = "Inert user-selected risk action",
                        UserSelectedRisk = true, ConfidenceScore = 90, ExpectedSha256 = new string('A', 64)
                    }).ToList()
            };
            string originalPlan = JsonSerializer.Serialize(plan, JsonFile.Options);
            foreach ((int width, int height) in new[] { (860, 620), (600, 420) })
            {
                RemediationPreviewWindow preview = new(plan);
                try
                {
                    using UiLayoutHarness layout = new(preview, width, height);
                    CheckBox confirm = (CheckBox)preview.FindName("ConfirmCheckBox");
                    Button execute = (Button)preview.FindName("ExecuteButton");
                    layout.Refresh();
                    Check($"Mode preview {culture.Name}/{width} labels every risk action without confirmed-malware wording",
                        preview.ModeSummary == RemediationModePresentation.Summary(plan) &&
                        preview.Actions.All(action => action.Confidence == DisplayText.Get("RemediationMode.RiskLabel")) &&
                        preview.NoticeText.Contains(DisplayText.Get("RemediationMode.AggressiveNotice"), StringComparison.Ordinal) &&
                        preview.ConfirmationText == DisplayText.Get("RemediationMode.RiskConfirmation"));
                    Check($"Mode preview {culture.Name}/{width} one existing confirmation remains visible",
                        layout.IsFullyVisible((FrameworkElement)preview.FindName("PreviewModeSummary")) &&
                        layout.IsFullyVisible(confirm) && layout.IsFullyVisible(execute) && !execute.IsEnabled &&
                        UiLayoutHarness.Descendants<CheckBox>(layout.Root).Count() == 1);
                    confirm.IsChecked = true;
                    Check($"Mode preview {culture.Name}/{width} confirming changes no evidence or plan",
                        execute.IsEnabled && originalPlan == JsonSerializer.Serialize(plan, JsonFile.Options));
                    confirm.IsChecked = false;
                    layout.Refresh();
                    if (output is not null) layout.Save($"mode-preview-{culture.Name}-{width}x{height}", output);
                }
                finally { preview.Close(); }
            }
            BrokerConfirmationRow[] rows = BrokerConfirmationWindow.BuildRows(plan, null);
            Check($"Mode Broker {culture.Name} labels every requested action as unconfirmed",
                rows.Length == 3 && rows.All(row => row.Verification.Contains(DisplayText.Get("RemediationMode.BrokerRisk"), StringComparison.Ordinal)));
            RemediationAction cfgRepair = new()
            {
                Type = RemediationActionType.RepairSteamConfiguration, Target = @"C:\Steam\steam.cfg",
                ConfigurationKind = SteamConfigurationRepair.Cfg,
                ExpectedSha256 = new string('D', 64), RepairedSha256 = new string('E', 64)
            };
            const string originalRun = "\"C:\\Steam\\steam.exe\" -cef-enable-debugging -token=private-preview-secret -silent";
            const string repairedRun = "\"C:\\Steam\\steam.exe\" -token=private-preview-secret -silent";
            RemediationAction runRepair = new()
            {
                Type = RemediationActionType.RepairSteamConfiguration, Target = @"HKCU\Run\Steam",
                ConfigurationKind = SteamConfigurationRepair.Run, ExpectedValueData = originalRun,
                ConfigurationSnapshot = JsonSerializer.Serialize(new SteamConfigurationSnapshot(
                    SteamConfigurationRepair.Run, @"C:\Steam\steam.exe", originalRun, repairedRun))
            };
            RemediationPlan configPlan = new() { Actions = [cfgRepair, runRepair] };
            BrokerConfirmationRow[] configRows = BrokerConfirmationWindow.BuildRows(configPlan, null);
            RemediationPreviewWindow configPreview = new(configPlan);
            try
            {
                Check($"Mode configuration preview {culture.Name} shows exact file transformation and both hashes",
                    configRows[0].Verification == DisplayText.Format("SteamConfig.PreviewIntent", DisplayText.Get("SteamConfig.CfgDescription")) &&
                    configRows[0].Identity.Contains(cfgRepair.ExpectedSha256!, StringComparison.Ordinal) &&
                    configRows[0].Identity.Contains(cfgRepair.RepairedSha256!, StringComparison.Ordinal) &&
                    configPreview.Actions[0].ExpectedIdentity.Contains(cfgRepair.RepairedSha256!, StringComparison.Ordinal));
                string[] runIdentities = [configRows[1].Identity, configPreview.Actions[1].ExpectedIdentity];
                Check($"Mode configuration preview {culture.Name} shows Run intent and redacts both value snapshots",
                    configRows[1].Verification == DisplayText.Format("SteamConfig.PreviewIntent", DisplayText.Get("SteamConfig.ArgumentsDescription")) &&
                    runIdentities.All(identity => identity.Contains("-cef-enable-debugging", StringComparison.Ordinal) &&
                        identity.Contains(DisplayText.Format("SteamConfig.RepairedValue", ""), StringComparison.Ordinal) &&
                        identity.Contains("-silent", StringComparison.Ordinal) && !identity.Contains("private-preview-secret", StringComparison.Ordinal)));
            }
            finally { configPreview.Close(); }
            using (BrokerConfirmationWindow broker = new(plan, null))
            {
                foreach ((int width, int height) in new[] { (1080, 720), (800, 560) })
                {
                    broker.ConstrainToWorkingArea(new System.Drawing.Rectangle(0, 0, width, height));
                    CreateScopeControlHandles(broker);
                    using System.Drawing.Bitmap bitmap = new(broker.Width, broker.Height);
                    broker.DrawToBitmap(bitmap, new System.Drawing.Rectangle(System.Drawing.Point.Empty, bitmap.Size));
                    bitmap.Save(Path.Combine(output, $"mode-broker-{culture.Name}-{width}x{height}.png"), System.Drawing.Imaging.ImageFormat.Png);
                    System.Windows.Forms.Control container = broker.Controls[0];
                    System.Windows.Forms.DataGridView actionGrid = container.Controls.OfType<System.Windows.Forms.DataGridView>().Single();
                    Check($"Mode Broker {culture.Name}/{width} header and confirmation fit working area",
                        broker.Width <= width && broker.Height <= height &&
                        container.Controls.OfType<System.Windows.Forms.Label>().Any(label =>
                            label.Text.Contains(RemediationModePresentation.Summary(plan), StringComparison.Ordinal)) &&
                        container.Controls.Cast<System.Windows.Forms.Control>().All(control =>
                            control.Top >= 0 && control.Bottom <= container.ClientSize.Height));
                    Check($"Mode Broker {culture.Name}/{width} at least one complete action row remains visible",
                        actionGrid.ClientSize.Height >= actionGrid.ColumnHeadersHeight + actionGrid.Rows[0].Height + 2);
                }
            }
            RemediationCaseRecord record = new() { Plans = [plan] };
            string rendered = RemediationCasePresentation.Render(record);
            Check($"Mode case {culture.Name} retains mode and user-selection provenance",
                rendered.Contains(RemediationModePresentation.Summary(plan), StringComparison.Ordinal) &&
                rendered.Contains(DisplayText.Format("RemediationMode.RiskTarget", target), StringComparison.Ordinal));
            string exported = Path.Combine(output, "mode-case-" + culture.Name + ".zip");
            Task.Run(() => CaseBundleExporter.ExportAsync(exported, report, plan, null, null,
                persistedCase: record, culture: culture)).GetAwaiter().GetResult();
            using ZipArchive zip = ZipFile.OpenRead(exported);
            using StreamReader readme = new(zip.GetEntry("说明.txt")!.Open());
            Check($"Mode export {culture.Name} includes selected mode and unconfirmed-risk notice",
                readme.ReadToEnd().Contains(RemediationModePresentation.Summary(plan), StringComparison.Ordinal));
        }
    }
}
