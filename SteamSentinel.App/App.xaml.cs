using System.Windows;
using System.Windows.Interop;
using System.Windows.Media;

namespace SteamSentinel.App;

public partial class App : Application
{
    protected override void OnStartup(StartupEventArgs e)
    {
        // This security utility favors deterministic rendering and broad remote/VM compatibility.
        RenderOptions.ProcessRenderMode = RenderMode.SoftwareOnly;
        DispatcherUnhandledException += (_, args) =>
        {
            MessageBox.Show(
                $"发生未处理错误：\n\n{args.Exception.Message}",
                "SteamSentinel",
                MessageBoxButton.OK,
                MessageBoxImage.Error);
            args.Handled = true;
        };
        base.OnStartup(e);
    }
}
