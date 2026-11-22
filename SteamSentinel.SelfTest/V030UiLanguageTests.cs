using System.IO;
using System.Reflection;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Windows;
using System.Windows.Automation;
using System.Windows.Controls;
using System.Windows.Media;
using SteamSentinel.App;
using SteamSentinel.App.Dialogs;
using SteamSentinel.App.Localization;
using SteamSentinel.Core.Models;
using SteamSentinel.Core.Reporting;
using SteamSentinel.Core.Utilities;

namespace SteamSentinel.SelfTest;

internal static partial class Program
{
    private static bool IsEnglishUi => DisplayText.Culture.TwoLetterISOLanguageName == "en";
    private static string UiExpected(string chinese, string english) => IsEnglishUi ? english : chinese;

    private static void TestV030LanguageControls(string? output)
    {
        string directory = Path.Combine(output ?? Path.Combine(Path.GetTempPath(), "SteamSentinel-language-ui-" + Guid.NewGuid().ToString("N")), "language-controls");
        Directory.CreateDirectory(directory);
        var outerCulture = DisplayText.Culture;
        var previousAppCulture = DisplayText.ApplicationCulture;
        bool startsChinese = outerCulture.TwoLetterISOLanguageName == "zh";
        using (DisplayText.UseApplicationCulture())
        {
            try
            {
                foreach ((int width, int height) in new[] { (784, 460), (440, 340) })
                {
                    DisplayText.SetApplicationCulture(outerCulture);
                    string path = Path.Combine(directory, outerCulture.Name + "-" + width + ".json");
                    LanguageSettingsView view = new(path);
                    Window window = new() { Content = view, FontFamily = new("Microsoft YaHei UI, Segoe UI"), FontSize = 12 };
                    using (UiLayoutHarness layout = new(window, width, height))
                    {
                        ComboBox choice = UiLayoutHarness.Descendants<ComboBox>(layout.Root).Single(x => x.Name == "LanguagePreferenceComboBox");
                        Button save = UiLayoutHarness.Descendants<Button>(layout.Root).Single(x => x.Name == "SaveLanguageButton");
                        TextBlock status = UiLayoutHarness.Descendants<TextBlock>(layout.Root).Single(x => x.Name == "LanguageSaveStatus");
                        Check("语言UI 三个稳定选项和自动默认 " + width, choice.Items.Count == 3 && Equals(choice.SelectedValue, LanguagePreference.Automatic) && layout.IsFullyVisible(choice) && layout.IsFullyVisible(save));
                        LanguagePreference targetPreference = startsChinese ? LanguagePreference.English : LanguagePreference.SimplifiedChinese;
                        var targetCulture = startsChinese ? DisplayText.English : DisplayText.Chinese;
                        choice.SelectedValue = targetPreference;
                        save.RaiseEvent(new RoutedEventArgs(Button.ClickEvent)); layout.Refresh();
                        Check("语言UI 保存后立即热切换生效 " + width, LanguageSettings.Load(path) == targetPreference &&
                            DisplayText.Culture.Equals(targetCulture) && DisplayText.ApplicationCulture.Equals(targetCulture) &&
                            status.Text.Contains(startsChinese ? "immediately" : "立即", StringComparison.Ordinal) &&
                            Equals(save.Content, DisplayText.Get("Ui.Language.Save")));
                        using (FileStream held = new(path, FileMode.Open, FileAccess.Read, FileShare.Read))
                        {
                            choice.SelectedValue = startsChinese ? LanguagePreference.SimplifiedChinese : LanguagePreference.English;
                            save.RaiseEvent(new RoutedEventArgs(Button.ClickEvent)); layout.Refresh();
                            Check("语言UI 写入失败不宣称成功 " + width,
                                status.Text.Contains(startsChinese ? "were not saved" : "未保存", StringComparison.Ordinal) &&
                                LanguageSettings.Load(path) == targetPreference &&
                                DisplayText.Culture.Equals(targetCulture) && DisplayText.ApplicationCulture.Equals(targetCulture));
                        }
                        if (output is not null)
                        {
                            choice.SelectedValue = startsChinese ? LanguagePreference.SimplifiedChinese : LanguagePreference.English;
                            save.RaiseEvent(new RoutedEventArgs(Button.ClickEvent)); layout.Refresh();
                            layout.Save("language-settings-" + width + "x" + height, output);
                        }
                    }
                    window.Close();
                }
            }
            finally
            {
                DisplayText.SetApplicationCulture(previousAppCulture);
            }
        }
        TestLanguageHotSwitchOnMainWindow();
        foreach ((int width, int height) in new[] { (500, 310), (440, 280) })
        {
            ExportLanguageDialog dialog = new(DisplayText.Culture);
            using (UiLayoutHarness layout = new(dialog, width, height))
            {
                ComboBox choice = UiLayoutHarness.Descendants<ComboBox>(layout.Root).Single();
                Button cancel = UiLayoutHarness.Descendants<Button>(layout.Root).Single(x => x.Name == "CancelExportLanguageButton");
                Button confirm = UiLayoutHarness.Descendants<Button>(layout.Root).Single(x => x.Name == "ConfirmExportLanguageButton");
                Check("语言UI 导出默认当前界面且控件可见 " + width, dialog.SelectedCulture == DisplayText.Culture && layout.IsFullyVisible(choice) && layout.IsFullyVisible(cancel) && layout.IsFullyVisible(confirm) && cancel.IsCancel);
                choice.SelectedValue = ExportLanguageChoice.English;
                Check("语言UI 本次英文选择 " + width, dialog.SelectedCulture == DisplayText.English);
                choice.SelectedValue = ExportLanguageChoice.SimplifiedChinese;
                Check("语言UI 本次中文选择不修改界面 " + width, dialog.SelectedCulture == DisplayText.Chinese && confirm.IsEnabled);
                choice.SelectedValue = ExportLanguageChoice.CurrentInterface;
                if (output is not null) layout.Save("export-language-" + width + "x" + height, output);
            }
            dialog.Close();
        }
    }

    private static void TestLanguageHotSwitchOnMainWindow()
    {
        static bool HasChinese(string? value) => !string.IsNullOrEmpty(value) && Regex.IsMatch(value, "[\\p{IsCJKUnifiedIdeographs}]");
        var previousAppCulture = DisplayText.ApplicationCulture;
        using (DisplayText.UseApplicationCulture())
        {
            try
            {
                DisplayText.SetApplicationCulture(DisplayText.Chinese);
                MainWindow window = new();
                try
                {
                    using UiLayoutHarness layout = new(window, 1148, 780);
                    UiLayoutFixtures.PopulateThreatWindow(window);
                    window.PriorityFindings[0].IsSelected = true;
                    layout.Refresh();

                    Button quickScan = (Button)window.FindName("QuickScanButton");
                    TextBlock headerStatus = (TextBlock)window.FindName("HeaderStatusText");
                    TabItem coverageTab = (TabItem)window.FindName("CoverageTab");
                    TextBlock footer = (TextBlock)window.FindName("FooterText");
                    Check("语言热切换 初始中文静态与动态文本完整",
                        HasChinese(window.Title) && Equals(quickScan.Content, DisplayText.Get("Ui.Xaml.MainWindow.008")) &&
                        HasChinese(headerStatus.Text) && HasChinese(window.PriorityFindings[0].Severity));

                    Localizer.Instance.ApplyLanguage(DisplayText.English);
                    layout.Refresh();
                    Check("语言热切换 切英文即时刷新全部静态和动态文案并保留勾选",
                        !HasChinese(window.Title) && Equals(quickScan.Content, DisplayText.Get("Ui.Xaml.MainWindow.008")) &&
                        !HasChinese(headerStatus.Text) && !HasChinese(coverageTab.Header?.ToString()) &&
                        !HasChinese(window.PriorityFindings[0].Severity) && !HasChinese(window.PriorityFindings[0].HandlingLabel) &&
                        !HasChinese(window.QuarantineItems[0].Status) && !HasChinese(footer.Text) &&
                        window.PriorityFindings[0].IsSelected);

                    Localizer.Instance.ApplyLanguage(DisplayText.Chinese);
                    layout.Refresh();
                    Check("语言热切换 切回中文即时恢复并继续保留勾选",
                        HasChinese(window.Title) && Equals(quickScan.Content, DisplayText.Get("Ui.Xaml.MainWindow.008")) &&
                        HasChinese(headerStatus.Text) && HasChinese(coverageTab.Header?.ToString()) &&
                        HasChinese(window.PriorityFindings[0].Severity) && HasChinese(window.PriorityFindings[0].HandlingLabel) &&
                        HasChinese(window.QuarantineItems[0].Status) && HasChinese(footer.Text) &&
                        window.PriorityFindings[0].IsSelected);
                }
                finally { CloseSummaryFixture(window); }
            }
            finally
            {
                DisplayText.SetApplicationCulture(previousAppCulture);
            }
        }
    }

    private static void TestV030UiPresentation(string? output)
    {
        static bool Untranslated(string value) => Regex.IsMatch(value, "[\\p{IsCJKUnifiedIdeographs}]") ||
            value.Contains("Unrecognized display resource:", StringComparison.Ordinal);
        List<string> collected = [];
        List<string> selectedAutonyms = [];
        using (DisplayText.UseCulture(DisplayText.English))
        {
            MainWindow window = new();
            try
            {
                using UiLayoutHarness layout = new(window, 1148, 780);
                TabControl mainTabs = (TabControl)window.FindName("MainTabs");
                void Collect(ComboBox? languagePicker = null)
                {
                    collected.Add(window.Title);
                    // The language picker renders language names in their own language, including in the English UI.
                    var nativeLabels = languagePicker?.SelectedValue is LanguagePreference.SimplifiedChinese
                        ? UiLayoutHarness.Descendants<TextBlock>(languagePicker).Where(x => x.Text == LanguageSettings.ChineseAutonym).ToHashSet()
                        : [];
                    foreach (TextBlock text in UiLayoutHarness.Descendants<TextBlock>(layout.Root))
                    {
                        if (nativeLabels.Contains(text)) selectedAutonyms.Add(text.Text);
                        else collected.Add(text.Text);
                    }
                    collected.AddRange(UiLayoutHarness.Descendants<ContentControl>(layout.Root)
                        .Where(x => x.Content is string).Select(x => (string)x.Content));
                    collected.AddRange(UiLayoutHarness.Descendants<DataGrid>(layout.Root)
                        .SelectMany(x => x.Columns).Select(x => x.Header?.ToString() ?? ""));
                    collected.AddRange(UiLayoutHarness.Descendants<FrameworkElement>(layout.Root)
                        .SelectMany(x => new[] { AutomationProperties.GetName(x), AutomationProperties.GetHelpText(x) }));
                }
                Expander optionsExpander = (Expander)window.FindName("ScanOptionsExpander");
                CheckBox advancedTabsCheck = (CheckBox)window.FindName("ShowAdvancedTabsCheckBox");
                bool wasOptionsExpanded = optionsExpander.IsExpanded;
                optionsExpander.IsExpanded = true;
                advancedTabsCheck.IsChecked = true;
                layout.Refresh();
                for (int tab = 0; tab < mainTabs.Items.Count; tab++)
                {
                    mainTabs.SelectedIndex = tab; layout.Refresh();
                    if (((TabItem)mainTabs.Items[tab]).Content is LanguageSettingsView languageView)
                    {
                        ComboBox picker = UiLayoutHarness.Descendants<ComboBox>(languageView).Single(x => x.Name == "LanguagePreferenceComboBox");
                        foreach (LanguagePreference preference in Enum.GetValues<LanguagePreference>())
                        {
                            picker.SelectedValue = preference;
                            layout.Refresh();
                            Collect(picker);
                        }
                        continue;
                    }
                    Collect();
                    if (tab != 0) continue;
                    TabControl results = (TabControl)window.FindName("ResultTabs");
                    for (int page = 0; page < results.Items.Count; page++)
                    { results.SelectedIndex = page; layout.Refresh(); Collect(); }
                }
                advancedTabsCheck.IsChecked = false;
                optionsExpander.IsExpanded = wasOptionsExpanded;
                layout.Refresh();
                Check("双语UI 全部初始页签及辅助功能文案无遗漏资源或中文",
                    selectedAutonyms.Count > 0 && collected.Count > 150 && !collected.Any(Untranslated));
            }
            finally { CloseSummaryFixture(window); }
        }

        ScanReport report = new()
        {
            ExecutionState = ScanExecutionState.Completed,
            Coverage = ScanCoverage.Partial,
            CompletedAtUtc = DateTimeOffset.UtcNow,
            Findings =
            [
                new() { Id = "known", RuleId = "UI-INERT-FIXTURE", Title = "Inert known-match fixture", Description = "Original evidence 原始证据 {0}",
                    Category = FindingCategory.File, Severity = FindingSeverity.Critical, IsKnownMalware = true, CanRemediate = true,
                    Target = @"C:\Lab\synthetic-only\inert.txt", Sha256 = new string('A', 64) },
                new() { Id = "review", RuleId = "UI-INERT-REVIEW", Title = "Unconfirmed observation", Category = FindingCategory.Network,
                    HandlingReason = FindingHandlingReason.InsufficientEvidence, SuggestedActions = [SuggestedActionKind.ReviewOnly] },
                new() { Id = "gap", RuleId = "AMSI-UNAVAILABLE", ReasonCode = ReasonCodes.AmsiUnavailable, Category = FindingCategory.Coverage }
            ]
        };
        string original = JsonSerializer.Serialize(report, JsonFile.Options);
        List<string> selections = [];
        foreach (var culture in new[] { DisplayText.Chinese, DisplayText.English })
        {
            using IDisposable scope = DisplayText.UseCulture(culture);
            MainWindow window = new();
            try
            {
                using UiLayoutHarness layout = new(window, 1148, 780);
                ScanReport baseline = new()
                {
                    ExecutionState = ScanExecutionState.Completed,
                    CompletedAtUtc = DateTimeOffset.UtcNow,
                    Coverage = ScanCoverage.Complete,
                    ContentScanSettings = new() { UseAmsi = false }
                };
                SetTrustProxyUiReport(window, baseline);
                typeof(MainWindow).GetMethod("SetBusy", BindingFlags.Instance | BindingFlags.NonPublic)!.Invoke(window, [true]);
                typeof(MainWindow).GetMethod("SetBusy", BindingFlags.Instance | BindingFlags.NonPublic)!.Invoke(window, [false]);
                CheckBox enhancement = (CheckBox)window.FindName("AmsiCheckBox");
                Check("双语UI 温和启用AMSI复选框默认不勾选且空闲可用 " + culture.Name,
                    enhancement.Visibility == Visibility.Visible && enhancement.IsChecked == false && enhancement.IsEnabled);
                Check("双语UI 基础完成不因未调用增强显示不完整 " + culture.Name,
                    ((TextBlock)window.FindName("HeaderStatusText")).Text == DisplayText.Get("Ui.xaml.UpdateSummary.14") &&
                    StatusPresentation.ScanMessage(baseline).MessageId == "Scan.Completed" && CoveragePresentation.Groups(baseline).Count == 0);
                SetTrustProxyUiReport(window, report);
                UiPreview.ApplyAccessState(window, InstallationSecurityStatus.Protected, new(false, true));
                ((Expander)window.FindName("FindingDetailCard")).IsExpanded = true;
                typeof(MainWindow).GetMethod("SelectAll_Click", BindingFlags.Instance | BindingFlags.NonPublic)!
                    .Invoke(window, [window, new RoutedEventArgs()]);
                layout.Refresh();
                selections.Add(string.Join(",", window.Findings.Where(x => x.IsSelected).Select(x => x.Finding.Id).Order()));
                Check("双语UI 原始证据和机器报告未受显示或选择影响 " + culture.Name,
                    original == JsonSerializer.Serialize(report, JsonFile.Options) &&
                    ((TextBlock)window.FindName("DetailDescriptionText")).Text.Contains("Original evidence 原始证据 {0}", StringComparison.Ordinal));
                TextBlock description = (TextBlock)window.FindName("DetailDescriptionText");
                TextBlock label = ((Grid)description.Parent).Children.OfType<TextBlock>()
                    .Single(text => Grid.GetRow(text) == 0 && Grid.GetColumn(text) == 0);
                FormattedText labelText = new(label.Text, culture, label.FlowDirection,
                    new Typeface(label.FontFamily, label.FontStyle, label.FontWeight, label.FontStretch),
                    label.FontSize, Brushes.Black, VisualTreeHelper.GetDpi(label).PixelsPerDip);
                Check("双语UI 详情标签完整显示且不挤入选中说明 " + culture.Name,
                    label.ActualWidth + 1 >= labelText.WidthIncludingTrailingWhitespace &&
                    layout.Bounds(label).Left + labelText.WidthIncludingTrailingWhitespace + 10 <= layout.Bounds(description).Left);
                if (output is not null) layout.Save("bilingual-selection-" + culture.Name, output);
            }
            finally { CloseSummaryFixture(window); }
        }
        Check("双语UI 两种语言只选择同一个已核验目标", selections.SequenceEqual(new[] { "known", "known" }));
        if (output is not null) File.WriteAllText(Path.Combine(output, "english-interface-texts.json"),
            JsonSerializer.Serialize(collected.Concat(selectedAutonyms).Distinct().Order().ToArray(), new JsonSerializerOptions { WriteIndented = true }));
    }
}
