using System.IO;
using System.Text.Json;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using SteamSentinel.App;
using SteamSentinel.App.Dialogs;
using SteamSentinel.App.Services;
using SteamSentinel.Core.Models;
using SteamSentinel.Core.Remediation;
using SteamSentinel.Core.Reporting;
using SteamSentinel.Core.Steam;
using SteamSentinel.Core.Utilities;

namespace SteamSentinel.SelfTest;

internal static partial class Program
{
    private static int RunV032ScopeUi(string output)
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
                TestV032ScopeUi(output);
            }
            catch (Exception ex) { error = ex; }
            finally { app?.Shutdown(); }
        });
        thread.SetApartmentState(ApartmentState.STA);
        thread.Start();
        thread.Join();
        if (error is not null) Failures.Add("v0.3.2 scope UI fixture error: " + error);
        File.WriteAllText(Path.Combine(output, "scope-ui-test-results.json"), JsonSerializer.Serialize(new
        {
            passed = _passed,
            failed = Failures.Count,
            failures = Failures,
            version = ProductInfo.Version,
            buildIdentity = ProductInfo.BuildIdentity,
            completedAtUtc = DateTimeOffset.UtcNow,
            safety = "Hidden inert WPF fixtures only; no Broker, target write, scan or installation."
        }, new JsonSerializerOptions { WriteIndented = true }));
        foreach (string failure in Failures) Console.WriteLine("FAIL: " + failure);
        Console.WriteLine($"v0.3.2 scope UI: passed {_passed}; failed {Failures.Count}");
        return Failures.Count == 0 ? 0 : 1;
    }

    // Hidden STA, inert paths only. No Broker launch, target write, scan or native identity lease.
    private static void TestV032ScopeUi(string? output)
    {
        string ordinary = Path.Combine(Path.GetPathRoot(Environment.SystemDirectory)!, "SteamSentinel-Scope-UI", "inert-pending.bin");
        string automatic = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads", "inert-automatic.bin");
        string sensitive = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "SteamSentinel-Scope-UI", "inert-sensitive.bin");
        string product = Path.Combine(AppContext.BaseDirectory, "inert-protected.bin");
        RuleSet rules = new();
        SteamLayout steam = new();
        foreach (var culture in new[] { DisplayText.Chinese, DisplayText.English })
        {
            using IDisposable language = DisplayText.UseCulture(culture);
            Finding[] findings =
            [
                ScopeUiFinding("automatic", automatic), ScopeUiFinding("pending", ordinary),
                ScopeUiFinding("sensitive", sensitive), ScopeUiFinding("product", product),
                ScopeUiFinding("network", @"\\scope-ui.invalid\share\inert.bin"),
                new() { Id = "retired", RuleId = "HEUR-SCRIPT-TOKEN-COOCCURRENCE", Target = ordinary,
                    Category = FindingCategory.File, IsKnownMalware = true, CanRemediate = true,
                    SuggestedActions = [SuggestedActionKind.QuarantineFile] }
            ];
            string original = JsonSerializer.Serialize(findings, JsonFile.Options);
            FindingHandlingInfo[] assessed = findings.Select(f => FindingHandlingPresentation.Get(f, rules, steam)).ToArray();
            FindingHandlingCounts counts = FindingHandlingPresentation.Count(assessed);
            Check($"v032 范围 UI {culture.Name} 待确认与需核验独立计数且不会当作已就绪",
                counts.Actionable == 1 && counts.PendingConfirmation == 1 && counts.NeedsVerification == 1 &&
                counts.Blocked == 2 && counts.NeedsReview == 1 && counts.SelectableCount == 3 &&
                counts.Summary == DisplayText.Format("Scope.Ui.Counts", 1, 1, 1, 1, 0, 2, 0));
            Check($"v032 范围 UI {culture.Name} 旧报告原值保留且旧入口兼容",
                original == JsonSerializer.Serialize(findings, JsonFile.Options) &&
                FindingHandlingPresentation.Get(findings[1]).CanSelect &&
                assessed[1].Label == DisplayText.Get("Scope.Ui.RequiresConsent.Label") &&
                assessed[2].Label == DisplayText.Get("Scope.Ui.Sensitive.Label") &&
                assessed[3].Label == DisplayText.Get("Scope.Ui.Blocked.Label") && !assessed[5].CanSelect);

            foreach ((int width, int height) in new[] { (1148, 780), (784, 460) })
            {
                MainWindow window = new();
                try
                {
                    using UiLayoutHarness layout = new(window, width, height);
                    SetTrustProxyUiReport(window, new() { Findings = [.. findings], CompletedAtUtc = DateTimeOffset.UtcNow });
                    UiPreview.ApplyAccessState(window, InstallationSecurityStatus.Protected, new(false, true));
                    Button selectAll = TrustProxyUiButton(window, "SelectAllButton");
                    Button remediate = TrustProxyUiButton(window, "RemediateButton");
                    layout.Refresh();
                    Check($"v032 范围 UI {culture.Name}/{width} 待确认可选可预览且默认不勾选",
                        window.Findings[0].IsSelected && !window.Findings[1].IsSelected && !window.Findings[2].IsSelected &&
                        window.Findings[1].CanSelect && window.Findings[2].CanSelect && !window.Findings[3].CanSelect &&
                        remediate.IsEnabled && selectAll.IsEnabled &&
                        TrustProxyUiText(window, "FindingHandlingSummaryText").Text == counts.Summary);
                    typeof(MainWindow).GetMethod("SelectAll_Click", TrustProxyUiPrivate)!.Invoke(window, [selectAll, new RoutedEventArgs()]);
                    window.Findings[3].IsSelected = true;
                    layout.Refresh();
                    Check($"v032 范围 UI {culture.Name}/{width} 全选包含待确认而阻断项目不能强选",
                        window.Findings.Count(item => item.IsSelected) == 3 && !window.Findings[3].IsSelected &&
                        layout.IsFullyVisible(remediate) && layout.IsFullyVisible(selectAll));
                    if (output is not null) layout.Save($"v032-scope-list-{culture.Name}-{width}x{height}", output);

                    SetTrustProxyUiReport(window, new() { Findings = [findings[1], findings[2]], CompletedAtUtc = DateTimeOffset.UtcNow });
                    layout.Refresh();
                    Check($"v032 范围 UI {culture.Name}/{width} 只有待确认项目仍可打开预览",
                        window.GetRemediationAvailability().CanRemediate && remediate.IsEnabled && selectAll.IsEnabled &&
                        FindingHandlingPresentation.Count(window.Findings.Select(item => item.Handling)).Actionable == 0);
                    SetTrustProxyUiReport(window, new() { Findings = [findings[3], findings[4]], CompletedAtUtc = DateTimeOffset.UtcNow });
                    layout.Refresh();
                    Check($"v032 范围 UI {culture.Name}/{width} 全部被阻断时没有可用处置入口",
                        !window.GetRemediationAvailability().CanRemediate && !remediate.IsEnabled && !selectAll.IsEnabled);
                }
                finally { CloseSummaryFixture(window); }
            }

            RemediationBatchSession batch = new();
            for (int batchIndex = 0; batchIndex < 3; batchIndex++)
                batch.Plans.Add(new()
                {
                    ExplicitFileTargetsRequested = true,
                    Actions = Enumerable.Range(batchIndex * 60, batchIndex == 2 ? 10 : 60).Select(index => new RemediationAction
                    {
                        Type = RemediationActionType.QuarantineFile,
                        Target = index == 1 ? sensitive : ordinary + "." + index,
                        ExpectedSha256 = new string('A', 64),
                        ConfidenceScore = 95,
                        DisplayName = "Inert exact file " + index
                    }).ToList()
                });
            string originalBatch = JsonSerializer.Serialize(batch, JsonFile.Options);
            foreach ((int width, int height) in new[] { (860, 620), (600, 420) })
            {
                RemediationPreviewWindow preview = new(batch, rules, steam);
                try
                {
                    using UiLayoutHarness layout = new(preview, width, height);
                    DataGrid grid = (DataGrid)preview.FindName("PreviewActionsGrid");
                    CheckBox confirm = (CheckBox)preview.FindName("ConfirmCheckBox");
                    Button execute = (Button)preview.FindName("ExecuteButton");
                    grid.SelectedIndex = 1;
                    layout.Refresh();
                    Check($"v032 范围预览 {culture.Name}/{width} 全量清单及敏感影响在原确认窗口可读",
                        preview.Plan.ExplicitFileTargetsRequested && preview.Actions.Count == 130 && grid.Items.Count == 130 &&
                        preview.Actions[^1].Batch == 3 && preview.Actions[^1].Target.EndsWith(".129", StringComparison.Ordinal) &&
                        preview.Actions[1].IsSensitive && preview.Actions[1].ScopeLabel == DisplayText.Get("Scope.Ui.Sensitive.Label") &&
                        preview.NoticeText.Contains(DisplayText.Get("Scope.Ui.PreviewNotice"), StringComparison.Ordinal) &&
                        preview.ConfirmationText == DisplayText.Get("Scope.Ui.PreviewConfirm") &&
                        layout.IsFullyVisible((FrameworkElement)preview.FindName("PreviewScopeNotice")) &&
                        layout.IsFullyVisible(confirm) && layout.IsFullyVisible(execute));
                    // The hidden harness moves Window.Content into its private presentation Root.
                    // Inspect that rendered tree, and require the sole checkbox to be the real
                    // confirmation control instead of counting the now-empty Window visual tree.
                    CheckBox[] confirmations = UiLayoutHarness.Descendants<CheckBox>(layout.Root).ToArray();
                    Check($"v032 范围预览 {culture.Name}/{width} 沿用唯一确认框且未确认不能继续",
                        confirmations.Length == 1 && ReferenceEquals(confirmations[0], confirm) &&
                        confirm.IsChecked == false && !execute.IsEnabled);
                    confirm.IsChecked = true;
                    Check($"v032 范围预览 {culture.Name}/{width} 一次原有确认即可继续但不修改计划授权",
                        execute.IsEnabled && originalBatch == JsonSerializer.Serialize(batch, JsonFile.Options));
                    confirm.IsChecked = false;
                    Check($"v032 范围预览 {culture.Name}/{width} 取消勾选立即禁止继续", !execute.IsEnabled);
                    if (output is not null) layout.Save($"v032-scope-preview-{culture.Name}-{width}x{height}", output);
                }
                finally { preview.Close(); }
            }
        }
    }

    private static Finding ScopeUiFinding(string id, string target) => new()
    {
        Id = id,
        RuleId = "UI-SCOPE-INERT",
        Title = "Inert scope fixture " + id,
        Target = target,
        Category = FindingCategory.File,
        Severity = FindingSeverity.High,
        IsKnownMalware = true,
        CanRemediate = true,
        Sha256 = new string('A', 64),
        SuggestedActions = [SuggestedActionKind.QuarantineFile]
    };
}
