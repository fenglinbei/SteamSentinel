using System.Globalization;
using System.Text.Json;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using SteamSentinel.App.Services;
using SteamSentinel.Core.Models;

namespace SteamSentinel.App.Dialogs;

internal sealed class ScanLimitsDialog : Window
{
    private readonly Dictionary<string, TextBox> _inputs = [];
    private readonly StackPanel _rows = new();
    private readonly TextBlock _error = new() { Foreground = Brushes.Firebrick, TextWrapping = TextWrapping.Wrap, Margin = new(0, 8, 0, 8) };
    private readonly ComboBox _mode = new() { ItemsSource = new[] { "快速扫描", "完整／文件／目录／补查" }, SelectedIndex = 0, MinWidth = 230 };
    private readonly ComboBox _preset = new() { ItemsSource = ScanLimitSettings.Presets, MinWidth = 130, Margin = new(12, 0, 0, 0) };
    private readonly TextBlock _presetHint = new() { TextWrapping = TextWrapping.Wrap, Foreground = Brushes.DarkSlateGray, Margin = new(0, 8, 0, 0) };
    private ScanMode _active = ScanMode.Quick;
    private bool _switching;
    private bool _rendering;
    internal ScanLimitSettings Settings { get; }

    internal ScanLimitsDialog(ScanLimitSettings current, string? loadError = null)
    {
        Settings = JsonSerializer.Deserialize<ScanLimitSettings>(JsonSerializer.Serialize(current))!;
        Title = "扫描限制设置";
        Width = 850; Height = 740; MinWidth = 520; MinHeight = 380;
        MaxWidth = SystemParameters.WorkArea.Width; MaxHeight = SystemParameters.WorkArea.Height;
        WindowStartupLocation = WindowStartupLocation.CenterOwner;
        FontFamily = new("Microsoft YaHei UI"); FontSize = 12;
        Background = Brushes.WhiteSmoke;
        DockPanel panel = new() { Margin = new(18) };
        Content = panel;
        StackPanel header = new(); DockPanel.SetDock(header, Dock.Top); panel.Children.Add(header);
        header.Children.Add(new TextBlock { Text = "由你决定扫描预算", FontSize = 20, FontWeight = FontWeights.SemiBold });
        header.Children.Add(new TextBlock
        {
            Text = "设置保存到当前 Windows 用户，下次扫描生效。两种扫描模式分别保存，可随时恢复默认。1 MiB = 1,048,576 字节。",
            TextWrapping = TextWrapping.Wrap,
            Margin = new(0, 6, 0, 6)
        });
        header.Children.Add(new TextBlock
        {
            Text = "调高预算会增加覆盖范围，也可能造成长时间扫描、磁盘占满或内存不足；调低会更早停止，并留下未检查内容。各预算同时生效，请结合报告中的停止原因调整。",
            TextWrapping = TextWrapping.Wrap,
            Foreground = Brushes.DarkSlateGray,
            Margin = new(0, 0, 0, 8)
        });
        WrapPanel selectors = new(); selectors.Children.Add(_mode); selectors.Children.Add(_preset);
        System.Windows.Automation.AutomationProperties.SetName(_mode, "扫描模式");
        System.Windows.Automation.AutomationProperties.SetName(_preset, "扫描预算预设");
        header.Children.Add(selectors); header.Children.Add(_presetHint);
        StackPanel footer = new(); DockPanel.SetDock(footer, Dock.Bottom); panel.Children.Add(footer);
        footer.Children.Add(_error);
        footer.Children.Add(new TextBlock
        {
            Text = "预算之外仍可能受到文件格式、密码、访问权限、系统资源和组件容量限制；报告会说明未完成原因。",
            TextWrapping = TextWrapping.Wrap,
            Foreground = Brushes.DimGray,
            Margin = new(0, 0, 0, 8)
        });
        WrapPanel actions = new() { HorizontalAlignment = HorizontalAlignment.Right };
        footer.Children.Add(actions);
        Button reset = new() { Content = "恢复当前模式默认", Padding = new(12, 6, 12, 6), Margin = new(4) };
        reset.Click += (_, _) => { Settings.For(_active).Clear(); RenderRows(); _error.Text = "已恢复当前模式默认值，点击保存后生效。"; };
        actions.Children.Add(reset);
        Button cancel = new() { Content = "取消", IsCancel = true, Padding = new(12, 6, 12, 6), Margin = new(4) };
        actions.Children.Add(cancel);
        Button save = new() { Content = "保存设置", IsDefault = true, Padding = new(12, 6, 12, 6), Margin = new(4) };
        save.Click += (_, _) =>
        {
            if (!Capture()) return;
            try { ScanSettingsStore.Save(ScanSettingsStore.DefaultPath, Settings); DialogResult = true; }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidDataException)
            { _error.Text = "设置未保存：" + ex.Message; }
        };
        actions.Children.Add(save);
        panel.Children.Add(new ScrollViewer { Content = _rows, VerticalScrollBarVisibility = ScrollBarVisibility.Auto, HorizontalScrollBarVisibility = ScrollBarVisibility.Disabled, Margin = new(0, 12, 0, 0) });
        _mode.SelectionChanged += (_, _) =>
        {
            if (_switching) return;
            if (!Capture())
            { _switching = true; _mode.SelectedIndex = _active == ScanMode.Quick ? 0 : 1; _switching = false; return; }
            _active = _mode.SelectedIndex == 0 ? ScanMode.Quick : ScanMode.Full;
            RenderRows();
        };
        _preset.SelectionChanged += (_, _) =>
        {
            if (_rendering) return;
            int index = _preset.SelectedIndex;
            _presetHint.Text = ScanLimitSettings.PresetDescription(index);
            if (index is >= 0 and < 5)
            {
                Settings.UsePreset(_active, index); RenderRows();
                _error.Text = "已载入“" + ScanLimitSettings.Presets[index] + "”预设，点击保存后生效。";
            }
        };
        RenderRows();
        if (loadError is not null) _error.Text = "已有设置读取失败，本次暂用默认值：" + loadError + "。保存将替换原设置文件。";
    }

    private void RenderRows()
    {
        _rendering = true;
        _rows.Children.Clear(); _inputs.Clear();
        foreach (ScanLimitDefinition field in ScanLimitSettings.Fields)
        {
            StackPanel row = new() { Margin = new(0, 0, 12, 12) };
            Grid line = new();
            line.ColumnDefinitions.Add(new() { Width = new(1, GridUnitType.Star) });
            line.ColumnDefinitions.Add(new() { Width = new(145) });
            line.ColumnDefinitions.Add(new() { Width = new(48) });
            line.Children.Add(new TextBlock { Text = field.Label, FontWeight = FontWeights.SemiBold, TextWrapping = TextWrapping.Wrap, VerticalAlignment = VerticalAlignment.Center });
            TextBox input = new() { Text = Settings.For(_active).GetValueOrDefault(field.Key, field.Default(_active)).ToString("0.############################", CultureInfo.InvariantCulture), Padding = new(5), MinWidth = 110 };
            System.Windows.Automation.AutomationProperties.SetName(input, field.Label + "（" + field.Unit + "）");
            Grid.SetColumn(input, 1); line.Children.Add(input); _inputs.Add(field.Key, input);
            input.TextChanged += (_, _) =>
            {
                if (_rendering) return;
                _preset.SelectedIndex = 5;
                _presetHint.Text = ScanLimitSettings.PresetDescription(5);
            };
            TextBlock unit = new() { Text = field.Unit, VerticalAlignment = VerticalAlignment.Center, Margin = new(8, 0, 0, 0) };
            Grid.SetColumn(unit, 2); line.Children.Add(unit); row.Children.Add(line);
            row.Children.Add(new TextBlock { Text = $"默认 {field.Default(_active):0.########} {field.Unit}。{field.Consequence}", TextWrapping = TextWrapping.Wrap, Foreground = Brushes.DimGray, Margin = new(0, 4, 0, 0) });
            _rows.Children.Add(row);
        }
        _preset.SelectedIndex = Settings.DetectPreset(_active);
        _presetHint.Text = ScanLimitSettings.PresetDescription(_preset.SelectedIndex);
        _rendering = false;
    }

    private bool Capture()
    {
        Dictionary<string, decimal> values = [];
        foreach (ScanLimitDefinition field in ScanLimitSettings.Fields)
        {
            TextBox input = _inputs[field.Key];
            try
            {
                if (!decimal.TryParse(input.Text.Trim(), NumberStyles.AllowDecimalPoint, CultureInfo.InvariantCulture, out decimal value))
                    throw new InvalidDataException(field.Label + "：请输入非负数字，小数点使用英文句点。");
                field.Validate(value);
                if (value != field.Default(_active)) values.Add(field.Key, value);
            }
            catch (InvalidDataException ex)
            { _error.Text = ex.Message; input.BringIntoView(); input.Focus(); input.SelectAll(); return false; }
        }
        if (_active == ScanMode.Quick) Settings.Quick = values; else Settings.Full = values;
        _error.Text = string.Empty;
        return true;
    }
}
