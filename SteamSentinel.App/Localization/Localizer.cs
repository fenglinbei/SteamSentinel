using System.ComponentModel;
using System.Globalization;
using System.Windows;
using System.Windows.Threading;
using SteamSentinel.Core.Reporting;

namespace SteamSentinel.App.Localization;

/// <summary>提供 XAML 与界面层的动态多语言索引及即时切换通知。</summary>
public sealed class Localizer : INotifyPropertyChanged
{
    public static Localizer Instance { get; } = new();

    private Localizer() =>
        DisplayText.ApplicationCultureChanged += (_, _) => DispatchLanguageChanged();

    public string this[string key] => DisplayText.Get(key);

    public event PropertyChangedEventHandler? PropertyChanged;
    public event EventHandler? LanguageChanged;

    /// <summary>应用目标显示语言，确保静态绑定与运行时动态文案同时刷新。</summary>
    public void ApplyLanguage(CultureInfo culture)
    {
        CultureInfo previous = DisplayText.ApplicationCulture;
        DisplayText.SetApplicationCulture(culture);
        if (Equals(previous, DisplayText.ApplicationCulture)) DispatchLanguageChanged();
    }

    private void DispatchLanguageChanged()
    {
        Dispatcher? dispatcher = Application.Current?.Dispatcher;
        if (dispatcher is not null && !dispatcher.HasShutdownStarted && !dispatcher.HasShutdownFinished &&
            !dispatcher.CheckAccess())
        {
            dispatcher.BeginInvoke(RaiseNotifications);
            return;
        }
        RaiseNotifications();
    }

    private void RaiseNotifications()
    {
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs("Item[]"));
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(string.Empty));
        LanguageChanged?.Invoke(this, EventArgs.Empty);
    }
}
