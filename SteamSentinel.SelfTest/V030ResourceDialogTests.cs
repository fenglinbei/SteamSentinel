using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Interop;
using System.IO;
using System.Text.Json;
using SteamSentinel.App.Dialogs;
using SteamSentinel.Core.Models;
using SteamSentinel.Core.Reporting;
using SteamSentinel.Core.Scanning;

namespace SteamSentinel.SelfTest;

internal static partial class Program
{
    private static async Task<int> RunV030ResourceUiAsync(string output, int dpiPercent)
    {
        output = Path.GetFullPath(output); Directory.CreateDirectory(output);
        UiLayoutHarness.RequestedDpi = new DpiScale(dpiPercent / 100d, dpiPercent / 100d);
        const long MiB = 1048576;
        ScanOptions options = new ScanLimitSettings().Apply(new() { Mode = ScanMode.Custom });
        ScanLimitRequest request = new(Guid.NewGuid().ToString("N"), "MaximumStringScanBytes", options.MaximumStringScanBytes,
            options.MaximumStringScanBytes + MiB, 0, true, "harmless-ui-fixture.txt", 256 * MiB, 0, 0);
        ScanMachineResources machine = new(8 * 1024 * MiB, 8 * 1024 * MiB, 16 * 1024 * MiB, 10 * 1024 * MiB, 8,
            DateTimeOffset.UtcNow, Path.GetPathRoot(output)!);
        try { await TestV030ResourceDialogAsync(output, ScanResourcePlanner.Propose(options, request, machine)); }
        catch (Exception exception) { Failures.Add(exception.ToString()); }
        await File.WriteAllTextAsync(Path.Combine(output, "resource-ui-results.json"), JsonSerializer.Serialize(new
        { passed = _passed, failures = Failures, dpiPercent, buildIdentity = ProductInfo.BuildIdentity,
            boundary = "Own hidden HWND DPI notification; not a physical display move." }, new JsonSerializerOptions { WriteIndented = true }));
        return Failures.Count == 0 ? 0 : 1;
    }

    private static Task TestV030ResourceDialogAsync(string output, ScanResourceProposal proposal)
    {
        TaskCompletionSource completion = new(TaskCreationOptions.RunContinuationsAsynchronously);
        Thread thread = new(() =>
        {
            try
            {
                AppContext.SetSwitch("Switch.System.Windows.Media.ShouldRenderEvenWhenNoDisplayDevicesAreAvailable", true);
                RenderOptions.ProcessRenderMode = RenderMode.SoftwareOnly;
                foreach (var culture in new[] { DisplayText.Chinese, DisplayText.English })
                using (DisplayText.UseCulture(culture))
                foreach ((int width, int height) in new[] { (700, 560), (440, 350) })
                {
                    ScanResourceDialog dialog = new(proposal with { Request = proposal.Request with { Target = new string('x', 1600) } });
                    using UiLayoutHarness layout = new(dialog, width, height);
                    var buttons = UiLayoutHarness.Descendants<Button>(layout.Root);
                    Button approve = buttons.Single(b => b.Name == "ApproveResourcesButton");
                    Button skip = buttons.Single(b => b.Name == "SkipResourcesButton");
                    Check($"自适应 UI {culture.Name} {width} 操作按钮可见且不默认批准", layout.IsFullyVisible(approve) && layout.IsFullyVisible(skip) && !approve.IsDefault && skip.IsCancel);
                    Check($"自适应 UI {culture.Name} {width} 保存未来默认不选", UiLayoutHarness.Descendants<CheckBox>(layout.Root).Single().IsChecked != true && !dialog.SaveForFuture);
                    ScrollViewer scroll = UiLayoutHarness.Descendants<ScrollViewer>(layout.Root).First(s => s.ScrollableHeight > 0);
                    scroll.ScrollToEnd(); layout.Refresh();
                    Check($"自适应 UI {culture.Name} {width} 长路径提示可滚动且固定操作区", scroll.VerticalOffset > 0 && layout.IsFullyVisible(approve));
                    layout.Save($"adaptive-dialog-{culture.Name}-{width}", output);
                }
                using (DisplayText.UseCulture(DisplayText.English))
                {
                    ScanResourceDialog denied = new(proposal with { Assessment = ResourceAssessmentKind.Unknown });
                    using UiLayoutHarness layout = new(denied, 700, 560);
                    Check("自适应 UI 容量未知保留按钮禁用批准", !UiLayoutHarness.Descendants<Button>(layout.Root).Single(b => b.Name == "ApproveResourcesButton").IsEnabled);
                }
                completion.SetResult();
            }
            catch (Exception error) { completion.SetException(error); }
        });
        thread.SetApartmentState(ApartmentState.STA); thread.Start();
        return completion.Task;
    }
}
