using SteamSentinel.Core.Reporting;
using System.Windows;
using System.Windows.Interop;
using System.Windows.Media;
using SteamSentinel.App.Services;
using SteamSentinel.App.Localization;
using System.Globalization;

namespace SteamSentinel.App;

public partial class App : Application
{
    internal bool AdministratorWindowRequested { get; private set; }
    internal LanguageStartupState? LanguageStartup { get; private set; }

    internal void InitializeDisplayLanguage(IReadOnlyList<string> arguments, string? settingsPath = null, CultureInfo? windowsUiLanguage = null)
    {
        LanguageStartup = LanguageSettings.ResolveStartup(arguments, settingsPath ?? LanguageSettings.DefaultPath,
            windowsUiLanguage ?? CultureInfo.CurrentUICulture);
        DisplayText.InitializeApplicationCulture(LanguageStartup.Culture);
        AdministratorWindowRequested = LanguageStartup.AdministratorWindowRequested;
    }

    protected override void OnStartup(StartupEventArgs e)
    {
        // This security utility favors deterministic rendering and broad remote/VM compatibility.
        RenderOptions.ProcessRenderMode = RenderMode.SoftwareOnly;
        // Resolve the display language before StartupUri creates any views. No report,
        // plan, file path or credentials are transferred between accounts.
        InitializeDisplayLanguage(e.Args);
        DispatcherUnhandledException += (_, args) =>
        {
            AppErrorLog.Write("DispatcherUnhandledException", args.Exception);
            if (MainWindow is MainWindow window) window.EnterRecoveryMode();
            MessageBox.Show(
                DisplayText.Format("Ui.App.xaml.OnStartup.01", (args.Exception.Message)),
                "SteamSentinel",
                MessageBoxButton.OK,
                MessageBoxImage.Error);
            args.Handled = true;
        };
        AppDomain.CurrentDomain.UnhandledException += (_, args) =>
        {
            if (args.ExceptionObject is Exception error) AppErrorLog.Write("FatalUnhandledException", error);
        };
        TaskScheduler.UnobservedTaskException += (_, args) => AppErrorLog.Write("UnobservedTaskException", args.Exception);
        base.OnStartup(e);
    }
}
