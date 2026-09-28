using SteamSentinel.Core.Reporting;
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
    private readonly ComboBox _mode = new() { ItemsSource = new[] { DisplayText.Get("Ui.ScanLimitsDialog._mode.01"), DisplayText.Get("Ui.ScanLimitsDialog._mode.02") }, SelectedIndex = 0, MinWidth = 230 };
    private readonly ComboBox _preset = new() { ItemsSource = ScanLimitSettings.Presets, MinWidth = 130, Margin = new(12, 0, 0, 0) };
    private readonly TextBlock _presetHint = new() { TextWrapping = TextWrapping.Wrap, Foreground = Brushes.DarkSlateGray, Margin = new(0, 8, 0, 0) };
    private ScanMode _active = ScanMode.Quick;
    private bool _switching;
    private bool _rendering;
    internal ScanLimitSettings Settings { get; }
    private static IEnumerable<ScanLimitDefinition> VisibleFields => ScanLimitSettings.Fields.Where(definition =>
        ScanEnhancements.AmsiAvailable || definition.Key != nameof(ScanOptions.MaximumAmsiBytes));

    internal ScanLimitsDialog(ScanLimitSettings current, string? loadError = null)
    {
        Settings = JsonSerializer.Deserialize<ScanLimitSettings>(JsonSerializer.Serialize(current))!;
        Title = DisplayText.Get("Ui.ScanLimitsDialog.Constructor.01");
        Width = 850; Height = 740; MinWidth = 520; MinHeight = 380;
        MaxWidth = SystemParameters.WorkArea.Width; MaxHeight = SystemParameters.WorkArea.Height;
        WindowStartupLocation = WindowStartupLocation.CenterOwner;
        FontFamily = new("Microsoft YaHei UI"); FontSize = 12;
        Background = Brushes.WhiteSmoke;
        DockPanel panel = new() { Margin = new(18) };
        Content = panel;
        StackPanel header = new(); DockPanel.SetDock(header, Dock.Top); panel.Children.Add(header);
        header.Children.Add(new TextBlock { Text = DisplayText.Get("Ui.ScanLimitsDialog.Constructor.02"), FontSize = 20, FontWeight = FontWeights.SemiBold });
        header.Children.Add(new TextBlock
        {
            Text = DisplayText.Get("Ui.ScanLimitsDialog.Constructor.03"),
            TextWrapping = TextWrapping.Wrap,
            Margin = new(0, 6, 0, 6)
        });
        header.Children.Add(new TextBlock
        {
            Text = DisplayText.Get("Ui.ScanLimitsDialog.Constructor.04"),
            TextWrapping = TextWrapping.Wrap,
            Foreground = Brushes.DarkSlateGray,
            Margin = new(0, 0, 0, 8)
        });
        WrapPanel selectors = new(); selectors.Children.Add(_mode); selectors.Children.Add(_preset);
        System.Windows.Automation.AutomationProperties.SetName(_mode, DisplayText.Get("Ui.ScanLimitsDialog.Constructor.05"));
        System.Windows.Automation.AutomationProperties.SetName(_preset, DisplayText.Get("Ui.ScanLimitsDialog.Constructor.06"));
        header.Children.Add(selectors); header.Children.Add(_presetHint);
        StackPanel footer = new(); DockPanel.SetDock(footer, Dock.Bottom); panel.Children.Add(footer);
        footer.Children.Add(_error);
        footer.Children.Add(new TextBlock
        {
            Text = DisplayText.Get("Ui.ScanLimitsDialog.Constructor.07"),
            TextWrapping = TextWrapping.Wrap,
            Foreground = Brushes.DimGray,
            Margin = new(0, 0, 0, 8)
        });
        WrapPanel actions = new() { HorizontalAlignment = HorizontalAlignment.Right };
        footer.Children.Add(actions);
        Button reset = new() { Name = "ResetLimitsButton", Content = DisplayText.Get("Ui.ScanLimitsDialog.Constructor.08"), Padding = new(12, 6, 12, 6), Margin = new(4) };
        reset.Click += (_, _) => { Settings.For(_active).Clear(); RenderRows(); _error.Text = DisplayText.Get("Ui.ScanLimitsDialog.Constructor.09"); };
        actions.Children.Add(reset);
        Button cancel = new() { Content = DisplayText.Get("Ui.ScanLimitsDialog.Constructor.10"), IsCancel = true, Padding = new(12, 6, 12, 6), Margin = new(4) };
        actions.Children.Add(cancel);
        Button save = new() { Name = "SaveLimitsButton", Content = DisplayText.Get("Ui.ScanLimitsDialog.Constructor.11"), IsDefault = true, Padding = new(12, 6, 12, 6), Margin = new(4) };
        save.Click += (_, _) =>
        {
            if (!Capture()) return;
            try { ScanSettingsStore.Save(ScanSettingsStore.DefaultPath, Settings); DialogResult = true; }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidDataException)
            { _error.Text = DisplayText.Get("Ui.ScanLimitsDialog.Constructor.12") + ex.Message; }
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
                _error.Text = DisplayText.Get("Ui.ScanLimitsDialog.Constructor.13") + ScanLimitSettings.Presets[index] + DisplayText.Get("Ui.ScanLimitsDialog.Constructor.14");
            }
        };
        RenderRows();
        if (loadError is not null) _error.Text = DisplayText.Get("Ui.ScanLimitsDialog.Constructor.15") + loadError + DisplayText.Get("Ui.ScanLimitsDialog.Constructor.16");
    }

    private void RenderRows()
    {
        _rendering = true;
        _rows.Children.Clear(); _inputs.Clear();
        CheckBox ask = new()
        {
            Name = "AskBeforeIncreasingCheckBox",
            IsChecked = Settings.AskBeforeIncreasing,
            Content = new TextBlock { Text = DisplayText.Get("Resource.AskBeforeIncreasing"), TextWrapping = TextWrapping.Wrap },
            Margin = new(0, 0, 0, 12)
        };
        ask.Checked += (_, _) => Settings.AskBeforeIncreasing = true;
        ask.Unchecked += (_, _) => Settings.AskBeforeIncreasing = false;
        _rows.Children.Add(ask);
        _rows.Children.Add(new TextBlock { Text = DisplayText.Get("Resource.PerformanceLabel"), FontWeight = FontWeights.SemiBold });
        ComboBox performance = new()
        {
            Name = "ScanPerformanceComboBox",
            HorizontalAlignment = HorizontalAlignment.Left,
            ItemsSource = Enum.GetValues<ScanPerformanceMode>().Select(value => DisplayText.Get("Resource.Performance." + value)).ToArray(),
            SelectedIndex = (int)Settings.PerformanceMode,
            Margin = new(0, 4, 0, 8),
            MinWidth = 230
        };
        performance.SelectionChanged += (_, _) => { if (performance.SelectedIndex >= 0) Settings.PerformanceMode = (ScanPerformanceMode)performance.SelectedIndex; };
        System.Windows.Automation.AutomationProperties.SetName(performance, DisplayText.Get("Resource.PerformanceLabel"));
        _rows.Children.Add(performance);
        _rows.Children.Add(new TextBlock { Text = DisplayText.Get("Resource.PerformanceHint"), TextWrapping = TextWrapping.Wrap, Margin = new(0, 0, 0, 16) });
        foreach (ScanLimitDefinition field in VisibleFields)
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
            row.Children.Add(new TextBlock { Text = DisplayText.Format("Ui.ScanLimitsDialog.RenderRows.01", (field.Default(_active)), (field.Unit), (field.Consequence)), TextWrapping = TextWrapping.Wrap, Foreground = Brushes.DimGray, Margin = new(0, 4, 0, 0) });
            _rows.Children.Add(row);
        }
        _preset.SelectedIndex = Settings.DetectPreset(_active);
        _presetHint.Text = ScanLimitSettings.PresetDescription(_preset.SelectedIndex);
        _rendering = false;
    }

    private bool Capture()
    {
        // Retain settings for temporarily hidden enhancements without offering them as
        // active baseline controls or discarding them when another field is saved.
        Dictionary<string, decimal> values = new(Settings.For(_active));
        foreach (ScanLimitDefinition field in VisibleFields)
        {
            TextBox input = _inputs[field.Key];
            try
            {
                if (!decimal.TryParse(input.Text.Trim(), NumberStyles.AllowDecimalPoint, CultureInfo.InvariantCulture, out decimal value))
                    throw new InvalidDataException(field.Label + DisplayText.Get("Ui.ScanLimitsDialog.Capture.01"));
                field.Validate(value);
                values.Remove(field.Key);
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
