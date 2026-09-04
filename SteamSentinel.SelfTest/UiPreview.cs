using System.IO;
using System.Reflection;
using System.Windows;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using SteamSentinel.App;
using SteamSentinel.App.Dialogs;
using SteamSentinel.App.Services;
using SteamSentinel.Core.Models;
using SteamSentinel.Core.Utilities;

namespace SteamSentinel.SelfTest;

internal static class UiPreview
{
    public static int Render(string output)
    {
        Exception? failure = null;
        Thread thread = new(() =>
        {
            try
            {
                Directory.CreateDirectory(output);
                SteamSentinel.App.App app = new();
                app.InitializeComponent();
                ArchivePasswordRequest request = new("preview", "C:\\示例内容\\外层加密包.rar!/" +
                    string.Concat(Enumerable.Repeat("较长的成员目录/", 16)) + "内部加密包.zip",
                    new string('A', 64), "ZIP 压缩包", 2, null, "已尝试本次保存的密码，仍未解开这一层。内层可能使用不同密码，也不能排除内容损坏或格式兼容问题。",
                    ArchivePasswordReuseScope.Session, ArchivePasswordPromptKind.CachedPasswordFailed);
                foreach ((string name, int width, int height) in new[] { ("password-normal", 596, 554), ("password-small", 416, 274) })
                {
                    PasswordDialog dialog = new(request);
                    Capture(dialog, name, width, height, output);
                }
                MainWindow window = new();
                ScanReport report = new() { Coverage = ScanCoverage.Partial };
                report.Findings.Add(new Finding { IsKnownMalware = true, Severity = FindingSeverity.Critical });
                typeof(MainWindow).GetMethod("UpdateSummary", BindingFlags.Instance | BindingFlags.NonPublic)!.Invoke(window, [report]);
                Capture(window, "main-partial-threat", 980, 680, output);
                MainWindow failedWindow = new();
                typeof(MainWindow).GetMethod("PreserveScanFailure", BindingFlags.Instance | BindingFlags.NonPublic)!.Invoke(failedWindow,
                    [new ScanReport { Mode = ScanMode.Quick, Metrics = new ScanMetrics { ProcessesVisited = 7 } },
                     ScanMode.Quick, Array.Empty<string>(),
                     new WorkerFailureException(WorkerStage.Handshake, unchecked((int)0xC0000142), "扫描组件在安全握手前关闭了输出通道，未发送扫描路径。"), false]);
                ApplyAccessState(failedWindow, InstallationSecurityStatus.Protected, new ElevationContext(true, true));
                Capture(failedWindow, "main-worker-failed", 980, 680, output);
                foreach ((string name, InstallationSecurityStatus status, ElevationContext context) in new[]
                {
                    ("access-normal", InstallationSecurityStatus.Protected, new ElevationContext(false, true)),
                    ("access-standard", InstallationSecurityStatus.Protected, new ElevationContext(false, false)),
                    ("access-administrator", InstallationSecurityStatus.Protected, new ElevationContext(true, true)),
                    ("access-unsafe", new InstallationSecurityStatus(false, "安装对象允许非受信任账户写入：SteamSentinel.Core.dll"), new ElevationContext(false, true))
                })
                {
                    MainWindow accessWindow = new();
                    ScanReport accessReport = new() { Coverage = ScanCoverage.Partial };
                    accessReport.Findings.Add(new Finding
                    {
                        Title = "示例检测项（仅界面预览）",
                        Description = "这是用于核对布局的无害示例，不是实际扫描结果。",
                        Target = "C:\\示例内容\\样例.zip",
                        CanRemediate = true,
                        Severity = FindingSeverity.Critical,
                        IsKnownMalware = true,
                        Sha256 = new string('A', 64)
                    });
                    typeof(MainWindow).GetField("_lastReport", BindingFlags.Instance | BindingFlags.NonPublic)!.SetValue(accessWindow, accessReport);
                    typeof(MainWindow).GetMethod("PopulateFindings", BindingFlags.Instance | BindingFlags.NonPublic)!.Invoke(accessWindow, [accessReport]);
                    ApplyAccessState(accessWindow, status, context);
                    Capture(accessWindow, name, 980, 680, output);
                }
                app.Shutdown();
            }
            catch (Exception ex) { failure = ex; }
        });
        thread.SetApartmentState(ApartmentState.STA);
        thread.Start();
        thread.Join();
        if (failure is not null) throw new InvalidOperationException("UI preview failed", failure);
        Console.WriteLine("UI_PREVIEW_OK");
        return 0;
    }

    internal static void ApplyAccessState(MainWindow window, InstallationSecurityStatus status, ElevationContext context)
    {
        const BindingFlags flags = BindingFlags.Instance | BindingFlags.NonPublic;
        typeof(MainWindow).GetField("_installationSecurity", flags)!.SetValue(window, status);
        typeof(MainWindow).GetField("_elevationContext", flags)!.SetValue(window, context);
        typeof(MainWindow).GetMethod("SetBusy", flags)!.Invoke(window, [false]);
        typeof(MainWindow).GetMethod("ApplyInstallationSecurityStatus", flags)!.Invoke(window, null);
    }

    private static void Capture(Window window, string name, int width, int height, string output)
    {
        FrameworkElement content = (FrameworkElement)window.Content;
        content.DataContext = window.DataContext;
        window.Content = null;
        System.Windows.Controls.Border host = new()
        {
            Width = width,
            Height = height,
            Background = window.Background ?? Brushes.White,
            Child = content
        };
        host.Measure(new Size(width, height));
        host.Arrange(new Rect(0, 0, width, height));
        host.UpdateLayout();
        RenderTargetBitmap bitmap = new(width, height, 96, 96, PixelFormats.Pbgra32);
        bitmap.Render(host);
        PngBitmapEncoder encoder = new();
        encoder.Frames.Add(BitmapFrame.Create(bitmap));
        using FileStream stream = File.Create(Path.Combine(output, name + ".png"));
        encoder.Save(stream);
    }
}
