using System.Globalization;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using SteamSentinel.Core.Reporting;

namespace SteamSentinel.App.Localization;

public sealed class LanguageSettingsView : UserControl
{
    private readonly string _settingsPath;
    private readonly TextBlock _title;
    private readonly TextBlock _current;
    private readonly TextBlock _startupHelp;
    private readonly TextBlock _label;
    private readonly TextBlock _automaticHelp;
    private readonly ComboBox _choice;
    private readonly Button _save;
    private readonly TextBlock _status;
    private LanguageSettingsError _lastReadError;
    private bool _hasSavedStatus;

    public LanguageSettingsView() : this(LanguageSettings.DefaultPath) { }

    internal LanguageSettingsView(string settingsPath)
    {
        _settingsPath = settingsPath;
        LanguageSettingsRead saved = LanguageSettings.Read(settingsPath);
        _lastReadError = saved.Error;
        Background = new SolidColorBrush(Color.FromRgb(0xF4, 0xF6, 0xF9));
        StackPanel body = new();
        _title = new TextBlock
        {
            Text = DisplayText.Get("Ui.Language.Title"),
            FontSize = 18,
            FontWeight = FontWeights.SemiBold,
            Foreground = new SolidColorBrush(Color.FromRgb(0x0F, 0x17, 0x2A))
        };
        body.Children.Add(_title);
        _current = Paragraph(DisplayText.Format("Ui.Language.Current", LanguageSettings.CultureLabel(DisplayText.Culture)));
        _current.Foreground = new SolidColorBrush(Color.FromRgb(0x33, 0x41, 0x55));
        body.Children.Add(_current);
        _startupHelp = Paragraph(DisplayText.Get("Ui.Language.StartupHelp"));
        _startupHelp.Foreground = new SolidColorBrush(Color.FromRgb(0x64, 0x74, 0x8B));
        body.Children.Add(_startupHelp);
        _label = Paragraph(DisplayText.Get("Ui.Language.NextStartup"));
        _label.FontWeight = FontWeights.SemiBold;
        _label.Foreground = new SolidColorBrush(Color.FromRgb(0x0F, 0x17, 0x2A));
        _label.Margin = new Thickness(0, 12, 0, 4);
        body.Children.Add(_label);
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
        _automaticHelp = Paragraph(DisplayText.Get("Ui.Language.AutomaticHelp"));
        _automaticHelp.Foreground = new SolidColorBrush(Color.FromRgb(0x64, 0x74, 0x8B));
        _automaticHelp.FontSize = 11.5;
        body.Children.Add(_automaticHelp);
        _save = new Button { Name = "SaveLanguageButton", Content = DisplayText.Get("Ui.Language.Save"), HorizontalAlignment = HorizontalAlignment.Left, Margin = new Thickness(0, 12, 0, 0) };
        if (TryFindResource("PrimaryButton") is Style primaryStyle) _save.Style = primaryStyle;
        _save.Click += (_, _) => SavePreference();
        body.Children.Add(_save);
        _status = Paragraph(LanguageSettings.ErrorText(saved.Error));
        _status.Name = "LanguageSaveStatus";
        _status.Foreground = saved.Error == LanguageSettingsError.None
            ? new SolidColorBrush(Color.FromRgb(0x47, 0x55, 0x69))
            : new SolidColorBrush(Color.FromRgb(0xB4, 0x23, 0x18));
        System.Windows.Automation.AutomationProperties.SetLiveSetting(_status, System.Windows.Automation.AutomationLiveSetting.Polite);
        body.Children.Add(_status);
        Border card = new()
        {
            Background = Brushes.White,
            BorderBrush = new SolidColorBrush(Color.FromRgb(0xE2, 0xE8, 0xF0)),
            BorderThickness = new Thickness(1),
            CornerRadius = new CornerRadius(10),
            Padding = new Thickness(18),
            Margin = new Thickness(14),
            MaxWidth = 620,
            HorizontalAlignment = HorizontalAlignment.Left,
            Child = body
        };
        Content = new ScrollViewer { Content = card, VerticalScrollBarVisibility = ScrollBarVisibility.Auto, HorizontalScrollBarVisibility = ScrollBarVisibility.Disabled };
        Loaded += (_, _) =>
        {
            Localizer.Instance.LanguageChanged -= OnLanguageChanged;
            Localizer.Instance.LanguageChanged += OnLanguageChanged;
            RefreshLocalizedTexts();
        };
        Unloaded += (_, _) => Localizer.Instance.LanguageChanged -= OnLanguageChanged;
    }

    private void OnLanguageChanged(object? sender, EventArgs e) => RefreshLocalizedTexts();

    /// <summary>按当前界面语言即时刷新语言设置卡片中的文本与自动选项标签。</summary>
    internal void RefreshLocalizedTexts()
    {
        _title.Text = DisplayText.Get("Ui.Language.Title");
        _current.Text = DisplayText.Format("Ui.Language.Current", LanguageSettings.CultureLabel(DisplayText.Culture));
        _startupHelp.Text = DisplayText.Get("Ui.Language.StartupHelp");
        _label.Text = DisplayText.Get("Ui.Language.NextStartup");
        _automaticHelp.Text = DisplayText.Get("Ui.Language.AutomaticHelp");
        _save.Content = DisplayText.Get("Ui.Language.Save");
        System.Windows.Automation.AutomationProperties.SetName(_choice, DisplayText.Get("Ui.Language.NextStartup"));
        object? selectedValue = _choice.SelectedValue;
        _choice.ItemsSource = LanguageSettings.Options();
        _choice.SelectedValue = selectedValue ?? LanguagePreference.Automatic;
        if (_hasSavedStatus)
        {
            _status.Foreground = new SolidColorBrush(Color.FromRgb(0x47, 0x55, 0x69));
            _status.Text = DisplayText.Get("Ui.Language.Saved");
        }
        else if (_lastReadError != LanguageSettingsError.None)
        {
            _status.Text = LanguageSettings.ErrorText(_lastReadError);
        }
    }

    internal bool SavePreference()
    {
        if (_choice.SelectedValue is not LanguagePreference preference) return false;
        try
        {
            LanguageSettings.Save(_settingsPath, preference);
            _lastReadError = LanguageSettingsError.None;
            _hasSavedStatus = true;
            CultureInfo target = LanguageSettings.Resolve(preference, CultureInfo.CurrentUICulture);
            Localizer.Instance.ApplyLanguage(target);
            RefreshLocalizedTexts();
            _status.Foreground = new SolidColorBrush(Color.FromRgb(0x47, 0x55, 0x69));
            _status.Text = DisplayText.Get("Ui.Language.Saved");
            return true;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or System.Security.SecurityException)
        {
            _hasSavedStatus = false;
            _status.Foreground = new SolidColorBrush(Color.FromRgb(0xB4, 0x23, 0x18));
            _status.Text = DisplayText.Format("Ui.Language.SaveFailed", ex.Message);
            return false;
        }
    }

    private static TextBlock Paragraph(string text) => new()
    { Text = text, TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0, 8, 0, 0) };
}
