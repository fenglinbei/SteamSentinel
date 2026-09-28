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
        foreach ((int width, int height) in new[] { (784, 460), (440, 340) })
        {
            string path = Path.Combine(directory, DisplayText.Culture.Name + "-" + width + ".json");
            LanguageSettingsView view = new(path);
            Window window = new() { Content = view, FontFamily = new("Microsoft YaHei UI, Segoe UI"), FontSize = 12 };
            using (UiLayoutHarness layout = new(window, width, height))
            {
                ComboBox choice = UiLayoutHarness.Descendants<ComboBox>(layout.Root).Single(x => x.Name == "LanguagePreferenceComboBox");
                Button save = UiLayoutHarness.Descendants<Button>(layout.Root).Single(x => x.Name == "SaveLanguageButton");
                TextBlock status = UiLayoutHarness.Descendants<TextBlock>(layout.Root).Single(x => x.Name == "LanguageSaveStatus");
                var current = DisplayText.Culture; var application = DisplayText.ApplicationCulture;
                Check("语言UI 三个稳定选项和自动默认 " + width, choice.Items.Count == 3 && Equals(choice.SelectedValue, LanguagePreference.Automatic) && layout.IsFullyVisible(choice) && layout.IsFullyVisible(save));
                choice.SelectedValue = LanguagePreference.English;
                save.RaiseEvent(new RoutedEventArgs(Button.ClickEvent)); layout.Refresh();
                Check("语言UI 保存只影响下次启动 " + width, LanguageSettings.Load(path) == LanguagePreference.English &&
                    DisplayText.Culture == current && DisplayText.ApplicationCulture == application && status.Text.Contains(UiExpected("下次启动", "next time the app starts")));
                if (output is not null) layout.Save("language-settings-" + width + "x" + height, output);
                using (FileStream held = new(path, FileMode.Open, FileAccess.Read, FileShare.Read))
                {
                    choice.SelectedValue = LanguagePreference.SimplifiedChinese;
                    save.RaiseEvent(new RoutedEventArgs(Button.ClickEvent)); layout.Refresh();
                    Check("语言UI 写入失败不宣称成功 " + width, status.Text.Contains(UiExpected("未保存", "were not saved")) && LanguageSettings.Load(path) == LanguagePreference.English && DisplayText.Culture == current);
                }
            }
            window.Close();
        }
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

    private static void TestV030UiPresentation(string? output)
    {
        static bool Untranslated(string value) => Regex.IsMatch(value, "[\\p{IsCJKUnifiedIdeographs}]") ||
            value.Contains("Unrecognized display resource:", StringComparison.Ordinal);
        List<string> collected = [];
        using (DisplayText.UseCulture(DisplayText.English))
        {
            MainWindow window = new();
            try
            {
                using UiLayoutHarness layout = new(window, 1148, 780);
                TabControl mainTabs = (TabControl)window.FindName("MainTabs");
                void Collect()
                {
                    collected.Add(window.Title);
                    collected.AddRange(UiLayoutHarness.Descendants<TextBlock>(layout.Root).Select(x => x.Text));
                    collected.AddRange(UiLayoutHarness.Descendants<ContentControl>(layout.Root)
                        .Where(x => x.Content is string).Select(x => (string)x.Content));
                    collected.AddRange(UiLayoutHarness.Descendants<DataGrid>(layout.Root)
                        .SelectMany(x => x.Columns).Select(x => x.Header?.ToString() ?? ""));
                    collected.AddRange(UiLayoutHarness.Descendants<FrameworkElement>(layout.Root)
                        .SelectMany(x => new[] { AutomationProperties.GetName(x), AutomationProperties.GetHelpText(x) }));
                }
                for (int tab = 0; tab < mainTabs.Items.Count; tab++)
                {
                    mainTabs.SelectedIndex = tab; layout.Refresh(); Collect();
                    if (tab != 0) continue;
                    TabControl results = (TabControl)window.FindName("ResultTabs");
                    for (int page = 0; page < results.Items.Count; page++)
                    { results.SelectedIndex = page; layout.Refresh(); Collect(); }
                }
                Check("双语UI 全部初始页签及辅助功能文案无遗漏资源或中文", collected.Count > 150 && !collected.Any(Untranslated));
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
                Check("双语UI 暂停增强入口隐藏且忙碌结束不启用 " + culture.Name,
                    enhancement.Visibility == Visibility.Collapsed && enhancement.IsChecked == false && !enhancement.IsEnabled);
                Check("双语UI 基础完成不因未调用增强显示不完整 " + culture.Name,
                    ((TextBlock)window.FindName("HeaderStatusText")).Text == DisplayText.Get("Ui.xaml.UpdateSummary.14") &&
                    StatusPresentation.ScanMessage(baseline).MessageId == "Scan.Completed" && CoveragePresentation.Groups(baseline).Count == 0);
                SetTrustProxyUiReport(window, report);
                UiPreview.ApplyAccessState(window, InstallationSecurityStatus.Protected, new(false, true));
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
            JsonSerializer.Serialize(collected.Distinct().Order().ToArray(), new JsonSerializerOptions { WriteIndented = true }));
    }
}
