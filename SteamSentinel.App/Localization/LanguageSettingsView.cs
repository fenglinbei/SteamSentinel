using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using SteamSentinel.Core.Reporting;

namespace SteamSentinel.App.Localization;

public sealed class LanguageSettingsView : UserControl
{
    private readonly string _settingsPath;
    private readonly ComboBox _choice;
    private readonly TextBlock _status;

    public LanguageSettingsView() : this(LanguageSettings.DefaultPath) { }

    internal LanguageSettingsView(string settingsPath)
    {
        _settingsPath = settingsPath;
        LanguageSettingsRead saved = LanguageSettings.Read(settingsPath);
        StackPanel body = new() { Margin = new Thickness(18), MaxWidth = 720, HorizontalAlignment = HorizontalAlignment.Left };
        body.Children.Add(new TextBlock { Text = DisplayText.Get("Ui.Language.Title"), FontSize = 20, FontWeight = FontWeights.SemiBold });
        body.Children.Add(Paragraph(DisplayText.Format("Ui.Language.Current", LanguageSettings.CultureLabel(DisplayText.Culture))));
        body.Children.Add(Paragraph(DisplayText.Get("Ui.Language.StartupHelp")));
        TextBlock label = Paragraph(DisplayText.Get("Ui.Language.NextStartup"));
        label.FontWeight = FontWeights.SemiBold;
        body.Children.Add(label);
        _choice = new ComboBox
        {
            Name = "LanguagePreferenceComboBox",
            ItemsSource = LanguageSettings.Options(),
            DisplayMemberPath = nameof(LanguageOption.Label),
            SelectedValuePath = nameof(LanguageOption.Value),
            SelectedValue = saved.Preference,
            MinWidth = 240,
            HorizontalAlignment = HorizontalAlignment.Left,
            Padding = new Thickness(6)
        };
        System.Windows.Automation.AutomationProperties.SetName(_choice, DisplayText.Get("Ui.Language.NextStartup"));
        body.Children.Add(_choice);
        body.Children.Add(Paragraph(DisplayText.Get("Ui.Language.AutomaticHelp")));
        Button save = new() { Name = "SaveLanguageButton", Content = DisplayText.Get("Ui.Language.Save"), HorizontalAlignment = HorizontalAlignment.Left, Margin = new Thickness(0, 12, 0, 0) };
        save.Click += (_, _) => SavePreference();
        body.Children.Add(save);
        _status = Paragraph(LanguageSettings.ErrorText(saved.Error));
        _status.Name = "LanguageSaveStatus";
        _status.Foreground = saved.Error == LanguageSettingsError.None ? Brushes.DarkSlateGray : Brushes.Firebrick;
        System.Windows.Automation.AutomationProperties.SetLiveSetting(_status, System.Windows.Automation.AutomationLiveSetting.Polite);
        body.Children.Add(_status);
        Content = new ScrollViewer { Content = body, VerticalScrollBarVisibility = ScrollBarVisibility.Auto, HorizontalScrollBarVisibility = ScrollBarVisibility.Disabled };
    }

    internal bool SavePreference()
    {
        if (_choice.SelectedValue is not LanguagePreference preference) return false;
        try
        {
            LanguageSettings.Save(_settingsPath, preference);
            _status.Foreground = Brushes.DarkSlateGray;
            _status.Text = DisplayText.Get("Ui.Language.Saved");
            return true;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or System.Security.SecurityException)
        {
            _status.Foreground = Brushes.Firebrick;
            _status.Text = DisplayText.Format("Ui.Language.SaveFailed", ex.Message);
            return false;
        }
    }

    private static TextBlock Paragraph(string text) => new()
    { Text = text, TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0, 8, 0, 0) };
}
