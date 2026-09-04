using System.Windows;
using System.Windows.Interop;
using System.Windows.Media;
using SteamSentinel.App.Services;

namespace SteamSentinel.App;

public partial class App : Application
{
    internal bool AdministratorWindowRequested { get; private set; }

    protected override void OnStartup(StartupEventArgs e)
    {
        // This security utility favors deterministic rendering and broad remote/VM compatibility.
        RenderOptions.ProcessRenderMode = RenderMode.SoftwareOnly;
        // A fixed UX marker only. No report, plan or credentials are transferred between accounts.
        AdministratorWindowRequested = e.Args.Length == 1 && e.Args[0] == ElevationService.WindowArgument;
        DispatcherUnhandledException += (_, args) =>
        {
            AppErrorLog.Write("DispatcherUnhandledException", args.Exception);
            MessageBox.Show(
                $"发生未处理错误：\n\n{args.Exception.Message}",
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
