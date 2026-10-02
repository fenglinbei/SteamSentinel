using System.Runtime.CompilerServices;
using SteamSentinel.Core.Utilities;
using SteamSentinel.App.Services;

namespace SteamSentinel.App;

internal static class StartupProgram
{
    [STAThread]
    private static int Main(string[] args)
    {
        if (StartupCompatibility.TryRunProbe(args, StartupRole.App, out int exitCode)) return exitCode;
        return RunApplication();
    }

    // Keep WPF construction/JIT and its settings, views and services out of the probe path.
    [MethodImpl(MethodImplOptions.NoInlining)]
    private static int RunApplication()
    {
        try
        {
            App application = new();
            application.InitializeComponent();
            return application.Run();
        }
        catch (Exception error)
        {
            string? reportPath = AppErrorLog.Write("ManagedStartup", error);
            App.ShowUnhandledError(error, reportPath);
            return 1;
        }
    }
}
