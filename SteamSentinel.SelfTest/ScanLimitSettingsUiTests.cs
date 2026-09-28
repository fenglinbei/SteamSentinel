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
            Check($"扫描设置UI {width} 默认中档并提供完整六项", preset.SelectedIndex == 2 && preset.Items.Cast<string>().SequenceEqual(ScanLimitSettings.Presets));
            Check($"扫描设置UI {width} 暂停的增强额度不展示", !ScanEnhancements.AmsiAvailable &&
                UiLayoutHarness.Descendants<TextBox>(layout.Root).Count() == ScanLimitSettings.Fields.Count - 1);
            preset.SelectedIndex = 4; layout.Refresh();
            decimal hiddenAmsiLimit = dialog.Settings.Quick[nameof(ScanOptions.MaximumAmsiBytes)];
            Check($"扫描设置UI {width} 选择极高会更新快速模式预算", dialog.Settings.Apply(new() { Mode = ScanMode.Quick }).ContainerLimits!.MaximumDepth == 16);
            TextBox input = UiLayoutHarness.Descendants<TextBox>(layout.Root).First();
            input.Text = "123";
            Check($"扫描设置UI {width} 手动修改自动转自定义", preset.SelectedIndex == 5);
            mode.SelectedIndex = 1; layout.Refresh();
            Check($"扫描设置UI {width} 模式切换保留自定义且完整仍为中", dialog.Settings.Quick["MaximumContentBytes"] == 123 && preset.SelectedIndex == 2);
            Check($"扫描设置UI {width} 保存可见字段保留隐藏增强额度", dialog.Settings.Quick[nameof(ScanOptions.MaximumAmsiBytes)] == hiddenAmsiLimit);
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
        }
    }
}
