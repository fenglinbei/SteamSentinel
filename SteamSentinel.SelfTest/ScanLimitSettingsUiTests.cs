using System.IO;
using System.Windows;
using System.Windows.Controls;
using SteamSentinel.App.Dialogs;
using SteamSentinel.Core.Models;

namespace SteamSentinel.SelfTest;

internal static partial class Program
{
    private static void TestScanSettingsUi(string? output)
    {
        foreach ((int width, int height) in new[] { (820, 700), (520, 480) })
        {
            ScanLimitsDialog dialog = new(new());
            using UiLayoutHarness layout = new(dialog, width, height);
            ComboBox preset = UiLayoutHarness.Descendants<ComboBox>(layout.Root).Single(c => c.Items.Count == 6);
            ComboBox mode = UiLayoutHarness.Descendants<ComboBox>(layout.Root).Single(c => c.Items.Count == 2);
            Expander advanced = UiLayoutHarness.Descendants<Expander>(layout.Root).Single(e => e.Name == "AdvancedLimitsExpander");
            Check($"扫描设置UI {width} 默认中档并默认折叠32项高级预算",
                preset.SelectedIndex == 2 && preset.Items.Cast<string>().SequenceEqual(ScanLimitSettings.Presets) &&
                !advanced.IsExpanded && UiLayoutHarness.Descendants<TextBox>(layout.Root).All(tb => !tb.IsVisible));
            advanced.IsExpanded = true; layout.Refresh();
            Check($"扫描设置UI {width} 温和启用AMSI后展开展示全部额度项", ScanEnhancements.AmsiAvailable &&
                UiLayoutHarness.Descendants<TextBox>(layout.Root).Count() == ScanLimitSettings.Fields.Count);
            preset.SelectedIndex = 4; layout.Refresh();
            decimal highAmsiLimit = dialog.Settings.Quick[nameof(ScanOptions.MaximumAmsiBytes)];
            Check($"扫描设置UI {width} 选择极高会更新快速模式预算", dialog.Settings.Apply(new() { Mode = ScanMode.Quick }).ContainerLimits!.MaximumDepth == 16);
            TextBox input = UiLayoutHarness.Descendants<TextBox>(layout.Root).First();
            input.Text = "123";
            Check($"扫描设置UI {width} 手动修改自动转自定义", preset.SelectedIndex == 5);
            mode.SelectedIndex = 1; layout.Refresh();
            Check($"扫描设置UI {width} 模式切换保留自定义且完整仍为中", dialog.Settings.Quick["MaximumContentBytes"] == 123 && preset.SelectedIndex == 2);
            Check($"扫描设置UI {width} 模式切换后保留快速模式AMSI额度", dialog.Settings.Quick[nameof(ScanOptions.MaximumAmsiBytes)] == highAmsiLimit);
            preset.SelectedIndex = 3; layout.Refresh();
            if (output is not null) layout.Save($"scan-settings-{width}x{height}", output);
            ScrollViewer scroll = UiLayoutHarness.Descendants<ScrollViewer>(layout.Root).First(s => s.ScrollableHeight > 0);
            scroll.ScrollToEnd(); layout.Refresh();
            Button save = UiLayoutHarness.Descendants<Button>(layout.Root).Single(b => b.Name == "SaveLimitsButton");
            Rect bounds = layout.Bounds(save);
            Check($"扫描设置UI {width} 底部保存按钮保持可见可操作", bounds.Top >= 0 && bounds.Bottom <= height + 1 && bounds.Left >= 0 && bounds.Right <= width + 1);
            if (output is not null) layout.Save($"scan-settings-bottom-{width}x{height}", output);
            TextBox invalid = UiLayoutHarness.Descendants<TextBox>(layout.Root).First(); invalid.Text = "-1";
            mode.SelectedIndex = 0; layout.Refresh();
            Check($"扫描设置UI {width} 无效输入阻止模式切换", mode.SelectedIndex == 1);
            Button reset = UiLayoutHarness.Descendants<Button>(layout.Root).Single(b => b.Name == "ResetLimitsButton");
            reset.RaiseEvent(new RoutedEventArgs(Button.ClickEvent)); layout.Refresh();
            Check($"扫描设置UI {width} 恢复默认回中档", preset.SelectedIndex == 2 && dialog.Settings.Full.Count == 0);

            TextBox hiddenInvalid = UiLayoutHarness.Descendants<TextBox>(layout.Root).First();
            hiddenInvalid.Text = "bad";
            advanced = UiLayoutHarness.Descendants<Expander>(layout.Root).Single(e => e.Name == "AdvancedLimitsExpander");
            advanced.IsExpanded = false; layout.Refresh();
            save.RaiseEvent(new RoutedEventArgs(Button.ClickEvent)); layout.Refresh();
            Check($"扫描设置UI {width} 折叠状态下非法输入保存时自动展开定位错误",
                advanced.IsExpanded && dialog.DialogResult is not true &&
                UiLayoutHarness.Descendants<TextBox>(layout.Root).First().IsVisible);
        }
    }
}
