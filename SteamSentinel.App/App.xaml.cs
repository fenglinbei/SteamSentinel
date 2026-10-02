using SteamSentinel.Core.Reporting;
using System.Windows;
using System.Windows.Interop;
using System.Windows.Media;
using SteamSentinel.App.Services;
using SteamSentinel.App.Localization;
using System.Globalization;
using System.Diagnostics;
using SteamSentinel.Core.Inspection;

namespace SteamSentinel.App;

public partial class App : Application
{
    internal bool AdministratorWindowRequested { get; private set; }
    internal LanguageStartupState? LanguageStartup { get; private set; }
    private bool _handlingUnhandledError;

    internal void InitializeDisplayLanguage(IReadOnlyList<string> arguments, string? settingsPath = null, CultureInfo? windowsUiLanguage = null)
    {
        LanguageStartup = LanguageSettings.ResolveStartup(arguments, settingsPath ?? LanguageSettings.DefaultPath,
            windowsUiLanguage ?? CultureInfo.CurrentUICulture);
        DisplayText.InitializeApplicationCulture(LanguageStartup.Culture);
        AdministratorWindowRequested = LanguageStartup.AdministratorWindowRequested;
    }

    protected override void OnStartup(StartupEventArgs e)
    {
        DispatcherUnhandledException += (_, args) =>
        {
            args.Handled = true;
            string? path = AppErrorLog.Write("DispatcherUnhandledException", args.Exception);
            if (_handlingUnhandledError) return;
            _handlingUnhandledError = true;
            try
            {
                try { if (MainWindow is MainWindow window) window.EnterRecoveryMode(); }
                catch (Exception recoveryError) { AppErrorLog.Write("UnhandledErrorRecovery", recoveryError); }
                ShowUnhandledError(args.Exception, path);
            }
            finally { _handlingUnhandledError = false; }
        };
        AppDomain.CurrentDomain.UnhandledException += (_, args) =>
        {
            if (args.ExceptionObject is Exception error) AppErrorLog.Write("FatalUnhandledException", error);
        };
        TaskScheduler.UnobservedTaskException += (_, args) => AppErrorLog.Write("UnobservedTaskException", args.Exception);
        // Resolve language before StartupUri creates views, after error reporting is installed.
        RenderOptions.ProcessRenderMode = RenderMode.SoftwareOnly;
        InitializeDisplayLanguage(e.Args);
        base.OnStartup(e);
    }

    internal static void ShowUnhandledError(Exception error, string? reportPath)
    {
        try
        {
            string message = DisplayText.Format("Ui.App.xaml.OnStartup.01", ScriptSignals.Redact(error.Message));
            message += "\n\n" + (reportPath is null ? DisplayText.Get("Ui.App.ErrorReport.Unavailable")
                : DisplayText.Format("Ui.App.ErrorReport.Saved", reportPath));
            MessageBoxResult choice = MessageBox.Show(message, "SteamSentinel",
                reportPath is null ? MessageBoxButton.OK : MessageBoxButton.YesNo, MessageBoxImage.Error);
            if (reportPath is not null && choice == MessageBoxResult.Yes)
                Process.Start(new ProcessStartInfo(reportPath) { UseShellExecute = true });
        }
        catch (Exception dialogError) { AppErrorLog.Write("ErrorReportDialog", dialogError); }
    }
}
