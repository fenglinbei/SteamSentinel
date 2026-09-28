using System.Windows;
using System.Windows.Threading;
using System.Reflection;

namespace SteamSentinel.SelfTest;

// Application schedules startup in its constructor even without Run(). Product
// resources must not also launch a real window when a layout test pumps messages.
internal static class UiFixtureApplication
{
    internal static SteamSentinel.App.App Create()
    {
        // .NET 10's public setter rejects null. This test-only reflection clears
        // the value installed by compiled App.xaml; fail before pumping if the
        // framework changes. No test bypass or startup switch ships in the app.
        FieldInfo startupUri = typeof(Application).GetField("_startupUri", BindingFlags.Instance | BindingFlags.NonPublic)
            ?? throw new InvalidOperationException("Cannot isolate WPF fixture startup on this runtime.");
        SteamSentinel.App.App app = new();
        app.InitializeComponent();
        startupUri.SetValue(app, null);
        if (app.StartupUri is not null)
            throw new InvalidOperationException("Cannot clear WPF fixture startup URI.");
        app.ShutdownMode = ShutdownMode.OnExplicitShutdown;
        app.Dispatcher.Invoke(() => { }, DispatcherPriority.ContextIdle);
        if (app.Windows.Count != 0)
            throw new InvalidOperationException("UI fixture startup created an unexpected window.");
        return app;
    }
}
