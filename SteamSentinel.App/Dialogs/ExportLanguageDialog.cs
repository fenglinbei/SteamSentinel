using System.Globalization;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using SteamSentinel.App.Localization;
using SteamSentinel.Core.Reporting;

namespace SteamSentinel.App.Dialogs;

internal enum ExportLanguageChoice { CurrentInterface, SimplifiedChinese, English }
internal sealed record ExportLanguageOption(ExportLanguageChoice Value, string Label);

internal sealed class ExportLanguageDialog : Window
{
    private readonly CultureInfo _interfaceCulture;
    private readonly ComboBox _choice;

    internal ExportLanguageDialog(CultureInfo interfaceCulture)
    {
        _interfaceCulture = DisplayText.Resolve(interfaceCulture);
        Title = DisplayText.Get("Ui.ExportLanguage.Title");
        Width = 500; Height = 310; MinWidth = 400; MinHeight = 280;
        FontFamily = new("Microsoft YaHei UI, Segoe UI"); FontSize = 12;
        Background = new SolidColorBrush(Color.FromRgb(0xF4, 0xF6, 0xF9));
        WindowStartupLocation = WindowStartupLocation.CenterOwner;
        ShowInTaskbar = false; UseLayoutRounding = true;
        Grid layout = new() { Margin = new Thickness(14) };
        layout.RowDefinitions.Add(new() { Height = new GridLength(1, GridUnitType.Star) });
        layout.RowDefinitions.Add(new() { Height = GridLength.Auto });
        StackPanel body = new();
        body.Children.Add(new TextBlock { Text = Title, FontSize = 18, FontWeight = FontWeights.SemiBold, Foreground = new SolidColorBrush(Color.FromRgb(0x0F, 0x17, 0x2A)), TextWrapping = TextWrapping.Wrap });
        body.Children.Add(new TextBlock { Text = DisplayText.Get("Ui.ExportLanguage.Help"), Foreground = new SolidColorBrush(Color.FromRgb(0x47, 0x55, 0x69)), TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0, 6, 0, 10) });
        _choice = new()
        {
            Name = "ExportLanguageComboBox",
            DisplayMemberPath = nameof(ExportLanguageOption.Label),
            SelectedValuePath = nameof(ExportLanguageOption.Value),
            Padding = new Thickness(6),
            ItemsSource = new ExportLanguageOption[]
            {
                new(ExportLanguageChoice.CurrentInterface, DisplayText.Format("Ui.ExportLanguage.Current", LanguageSettings.CultureLabel(_interfaceCulture))),
                new(ExportLanguageChoice.SimplifiedChinese, LanguageSettings.ChineseAutonym),
                new(ExportLanguageChoice.English, LanguageSettings.EnglishAutonym)
            },
            SelectedValue = ExportLanguageChoice.CurrentInterface
        };
        System.Windows.Automation.AutomationProperties.SetName(_choice, Title);
        body.Children.Add(_choice);
        body.Children.Add(new TextBlock { Text = DisplayText.Get("Ui.ExportLanguage.Originals"), Foreground = new SolidColorBrush(Color.FromRgb(0x64, 0x74, 0x8B)), FontSize = 11.5, TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0, 8, 0, 0) });
        Border card = new()
        {
            Background = Brushes.White,
            BorderBrush = new SolidColorBrush(Color.FromRgb(0xE2, 0xE8, 0xF0)),
            BorderThickness = new Thickness(1),
            CornerRadius = new CornerRadius(10),
            Padding = new Thickness(14),
            Child = body
        };
        layout.Children.Add(new ScrollViewer { Content = card, VerticalScrollBarVisibility = ScrollBarVisibility.Auto, HorizontalScrollBarVisibility = ScrollBarVisibility.Disabled });
        WrapPanel actions = new() { HorizontalAlignment = HorizontalAlignment.Right, Margin = new Thickness(0, 10, 0, 0) };
        Button cancel = new() { Name = "CancelExportLanguageButton", Content = DisplayText.Get("Ui.ExportLanguage.Cancel"), IsCancel = true };
        Button confirm = new() { Name = "ConfirmExportLanguageButton", Content = DisplayText.Get("Ui.ExportLanguage.Confirm"), IsDefault = true, Margin = new Thickness(0) };
        if (TryFindResource("PrimaryButton") is Style primaryStyle) confirm.Style = primaryStyle;
        _choice.SelectionChanged += (_, _) => confirm.IsEnabled = _choice.SelectedItem is ExportLanguageOption;
        confirm.Click += (_, _) => { if (_choice.SelectedItem is ExportLanguageOption) DialogResult = true; };
        actions.Children.Add(cancel); actions.Children.Add(confirm);
        Grid.SetRow(actions, 1); layout.Children.Add(actions);
        Content = layout;
        DialogLayout.ConstrainToWorkArea(this);
    }

    internal CultureInfo SelectedCulture => _choice.SelectedValue switch
    {
        ExportLanguageChoice.CurrentInterface => _interfaceCulture,
        ExportLanguageChoice.SimplifiedChinese => DisplayText.Chinese,
        ExportLanguageChoice.English => DisplayText.English,
        _ => throw new InvalidOperationException("Select an export language before exporting.")
    };

    internal static bool RequiredForPath(string path) =>
        !Path.GetExtension(path).Equals(".json", StringComparison.OrdinalIgnoreCase);
}
