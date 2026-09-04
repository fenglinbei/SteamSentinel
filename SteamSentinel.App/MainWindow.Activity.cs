using System.ComponentModel;
using System.Diagnostics;
using System.Windows;
using System.Windows.Media.Animation;
using System.Windows.Threading;
using SteamSentinel.App.Services;
using SteamSentinel.Core.Models;

namespace SteamSentinel.App;

public partial class MainWindow
{
    private DispatcherTimer? _activityTimer;
    private readonly Stopwatch _activityClock = new();
    private bool _windowClosed, _closeWhenIdle, _operationCommitted;
    private ActivityPhase _activityPhase;
    private string _activityHint = "";

    internal enum ActivityPhase { Working, Scanning, Preparing, Confirmation, Applying, FollowUp, ContentFollowUp, Exporting, Inspecting, Cancelling }

    internal void ShowActivity(ActivityPhase phase, string? hint = null)
    {
        Dispatcher.VerifyAccess();
        if (_windowClosed) return;
        _activityPhase = phase;
        ActivityTitleText.Text = phase switch
        {
            ActivityPhase.Scanning => "正在扫描",
            ActivityPhase.Preparing => "正在生成处置方案",
            ActivityPhase.Confirmation => "请核对处置方案",
            ActivityPhase.Applying => "正在处置并验证",
            ActivityPhase.FollowUp => "正在复查系统与 Steam",
            ActivityPhase.ContentFollowUp => "正在复查原扫描范围",
            ActivityPhase.Exporting => "正在导出记录",
            ActivityPhase.Inspecting => "正在读取关联信息",
            ActivityPhase.Cancelling => "正在取消，请稍候",
            _ => "正在检查，请稍候"
        };
        _activityHint = hint ?? phase switch
        {
            ActivityPhase.Preparing => "核对文件、启动入口和关联进程，尚未修改文件，可取消。",
            ActivityPhase.Confirmation => "等待你在预览窗口确认，尚未开始处置。",
            ActivityPhase.Applying => "如出现 Windows 授权请确认，正在等待管理员组件完成操作与验证，请勿关闭窗口或重启。",
            ActivityPhase.FollowUp => "重新读取系统与 Steam 状态，不会再次隔离文件，最长等待约 2 分钟。",
            ActivityPhase.ContentFollowUp => "沿用原扫描范围和设置，只读检查，最长等待约 2 分钟，可取消，未完成部分可稍后手动复扫。加密内容可能需要重新输入密码。",
            ActivityPhase.Scanning => "范围或压缩内容较大时可能需要更久，可取消，已用时间不是剩余时间。",
            ActivityPhase.Exporting => "正在保存记录，完成后会显示保存位置。",
            ActivityPhase.Cancelling => "等待当前读取结束并释放临时文件，不会开始新的处置。",
            _ => "正在读取信息，请稍候，已用时间不是剩余时间。"
        };
        ActivityDetailText.Text = _activityHint;
        ActivityPanel.Visibility = Visibility.Visible;
        _activityClock.Restart();
        _activityTimer ??= new DispatcherTimer(TimeSpan.FromSeconds(1), DispatcherPriority.Background,
            (_, _) => RefreshActivityElapsed(), Dispatcher);
        _activityTimer.Stop();
        _activityTimer.Start();
        RefreshActivityElapsed();
        bool moving = phase != ActivityPhase.Confirmation && SystemParameters.ClientAreaAnimation;
        ActivitySpinner.Visibility = phase == ActivityPhase.Confirmation ? Visibility.Collapsed : Visibility.Visible;
        ActivityRotation.BeginAnimation(System.Windows.Media.RotateTransform.AngleProperty, null);
        if (moving) ActivityRotation.BeginAnimation(System.Windows.Media.RotateTransform.AngleProperty,
            new DoubleAnimation(0, 360, TimeSpan.FromSeconds(1.15)) { RepeatBehavior = RepeatBehavior.Forever });
        ActivityProgressBar.IsIndeterminate = moving;
        ActivityProgressBar.Visibility = phase == ActivityPhase.Confirmation ? Visibility.Collapsed : Visibility.Visible;
        ScanProgressBar.IsIndeterminate = moving && phase == ActivityPhase.Scanning;
        ScanProgressBar.Value = 0;
    }

    private void RefreshActivityElapsed()
    {
        TimeSpan elapsed = _activityClock.Elapsed;
        ActivityElapsedText.Text = "本阶段已用 " + (elapsed.TotalHours >= 1 ? elapsed.ToString(@"h\:mm\:ss") : elapsed.ToString(@"mm\:ss"));
        if (elapsed.TotalSeconds >= 20 && _activityPhase != ActivityPhase.Confirmation)
            ActivityDetailText.Text = _activityHint + "\n本阶段仍未返回结果，动画仅表示界面正在等待，不代表后台一定在持续推进。";
    }

    private void HideActivity()
    {
        _activityTimer?.Stop();
        _activityClock.Stop();
        ActivityRotation.BeginAnimation(System.Windows.Media.RotateTransform.AngleProperty, null);
        ActivityProgressBar.IsIndeterminate = false;
        ActivityPanel.Visibility = Visibility.Collapsed;
        ScanProgressBar.IsIndeterminate = false;
    }

    private DispatcherProgress<ScanProgress> CreateUiProgress(Action<ScanProgress> handler) => new(
        Dispatcher, handler, () => !_windowClosed && _busy && !_closeWhenIdle,
        error =>
        {
            AppErrorLog.Write("ProgressDisplay", error);
            ActivityDetailText.Text = "进度显示遇到问题，操作仍在等待结果，完成前请勿重启。错误已尝试保存在本地日志中。";
        });

    // The same production follow-up path is exercised under a real WPF dispatcher in tests.
    // The optional runner only substitutes read-only scanning, never grants remediation authority.
    internal async Task<ScanReport> RunPostRemediationCheckAsync(CancellationToken token,
        Func<ScanOptions, IProgress<ScanProgress>, CancellationToken, Task<ScanReport>>? runner = null)
    {
        Dispatcher.VerifyAccess();
        ShowActivity(ActivityPhase.FollowUp);
        using DispatcherProgress<ScanProgress> progress = CreateUiProgress(p =>
        {
            ProgressStageText.Text = "处置后复查 · " + p.Stage;
            ProgressItemText.Text = p.CurrentItem;
        });
        ScanOptions options = new()
        {
            Mode = ScanMode.Quick, IncludeSystem = true, IncludeSteam = true, IncludeWorkshop = false,
            IncludeRelatedContent = false, UseAmsi = false, InspectArchives = false
        };
        runner ??= (settings, reporter, cancellation) => _coordinator.RunAsync(settings, progress: reporter, cancellationToken: cancellation);
        return await Task.Run(() => runner(options, progress, token), token);
    }

    internal bool MustWaitBeforeClosing => _busy && _operationCommitted;

    private void MainWindow_Closing(object? sender, CancelEventArgs e)
    {
        if (!_busy) return;
        e.Cancel = true;
        if (MustWaitBeforeClosing || _scanCancellation is null)
        {
            MessageBox.Show(this, MustWaitBeforeClosing
                ? "处置或复查尚未结束，直接关闭会丢失界面中的后续记录。请等待本次返回结果后再关闭，不要重启电脑。"
                : "当前操作尚未结束，请等待完成后再关闭窗口。", "操作仍在进行", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }
        if (MessageBox.Show(this, "取消当前只读检查，并在取消完成后关闭窗口？已执行的处置不会因此回滚。",
            "取消后关闭", MessageBoxButton.YesNo, MessageBoxImage.Question) == MessageBoxResult.Yes)
        {
            _closeWhenIdle = true;
            _scanCancellation.Cancel();
            ShowActivity(ActivityPhase.Cancelling);
        }
    }

    private void MainWindow_Closed(object? sender, EventArgs e)
    {
        _windowClosed = true;
        _scanCancellation?.Cancel();
        HideActivity();
    }
}
