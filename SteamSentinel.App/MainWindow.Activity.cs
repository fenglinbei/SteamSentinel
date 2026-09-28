using SteamSentinel.Core.Reporting;
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
            ActivityPhase.Scanning => DisplayText.Get("Ui.Activity.ShowActivity.Scanning.01"),
            ActivityPhase.Preparing => DisplayText.Get("Ui.Activity.ShowActivity.Preparing.01"),
            ActivityPhase.Confirmation => DisplayText.Get("Ui.Activity.ShowActivity.Confirmation.01"),
            ActivityPhase.Applying => DisplayText.Get("Ui.Activity.ShowActivity.Applying.01"),
            ActivityPhase.FollowUp => DisplayText.Get("Ui.Activity.ShowActivity.FollowUp.01"),
            ActivityPhase.ContentFollowUp => DisplayText.Get("Ui.Activity.ShowActivity.ContentFollowUp.01"),
            ActivityPhase.Exporting => DisplayText.Get("Ui.Activity.ShowActivity.Exporting.01"),
            ActivityPhase.Inspecting => DisplayText.Get("Ui.Activity.ShowActivity.Inspecting.01"),
            ActivityPhase.Cancelling => DisplayText.Get("Ui.Activity.ShowActivity.Cancelling.01"),
            _ => DisplayText.Get("Ui.Activity.ShowActivity.01")
        };
        _activityHint = hint ?? phase switch
        {
            ActivityPhase.Preparing => DisplayText.Get("Ui.Activity.ShowActivity.Preparing.02"),
            ActivityPhase.Confirmation => DisplayText.Get("Ui.Activity.ShowActivity.Confirmation.02"),
            ActivityPhase.Applying => DisplayText.Get("Ui.Activity.ShowActivity.Applying.02"),
            ActivityPhase.FollowUp => DisplayText.Get("Ui.Activity.ShowActivity.FollowUp.02"),
            ActivityPhase.ContentFollowUp => DisplayText.Get("Ui.Activity.ShowActivity.ContentFollowUp.02"),
            ActivityPhase.Scanning => DisplayText.Get("Ui.Activity.ShowActivity.Scanning.02"),
            ActivityPhase.Exporting => DisplayText.Get("Ui.Activity.ShowActivity.Exporting.02"),
            ActivityPhase.Cancelling => DisplayText.Get("Ui.Activity.ShowActivity.Cancelling.02"),
            _ => DisplayText.Get("Ui.Activity.ShowActivity.02")
        };
        ActivityDetailText.Text = _activityHint;
        ActivityPanel.Visibility = Visibility.Visible;
        UpdateCompactHeader();
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
        ActivityElapsedText.Text = DisplayText.Get("Ui.Activity.RefreshActivityElapsed.01") + (elapsed.TotalHours >= 1 ? elapsed.ToString(@"h\:mm\:ss") : elapsed.ToString(@"mm\:ss"));
        if (elapsed.TotalSeconds >= 20 && _activityPhase != ActivityPhase.Confirmation)
            ActivityDetailText.Text = _activityHint + DisplayText.Get("Ui.Activity.RefreshActivityElapsed.02");
    }

    private void HideActivity()
    {
        _activityTimer?.Stop();
        _activityClock.Stop();
        ActivityRotation.BeginAnimation(System.Windows.Media.RotateTransform.AngleProperty, null);
        ActivityProgressBar.IsIndeterminate = false;
        ActivityPanel.Visibility = Visibility.Collapsed;
        UpdateCompactHeader();
        ScanProgressBar.IsIndeterminate = false;
    }

    private DispatcherProgress<ScanProgress> CreateUiProgress(Action<ScanProgress> handler) => new(
        Dispatcher, handler, () => !_windowClosed && _busy && !_closeWhenIdle,
        error =>
        {
            AppErrorLog.Write("ProgressDisplay", error);
            ActivityDetailText.Text = DisplayText.Get("Ui.Activity.CreateUiProgress.01");
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
            ProgressStageText.Text = DisplayText.Get("Ui.Activity.RunPostRemediationCheckAsync.01") + p.DisplayStage;
            ProgressItemText.Text = p.DisplayCurrentItem;
        });
        ScanOptions options = new()
        {
            Mode = ScanMode.Quick,
            IncludeSystem = true,
            IncludeSteam = true,
            IncludeWorkshop = false,
            IncludeRelatedContent = false,
            UseAmsi = false,
            InspectArchives = false
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
                ? DisplayText.Get("Ui.Activity.MainWindow_Closing.01")
                : DisplayText.Get("Ui.Activity.MainWindow_Closing.02"), DisplayText.Get("Ui.Activity.MainWindow_Closing.03"), MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }
        if (MessageBox.Show(this, DisplayText.Get("Ui.Activity.MainWindow_Closing.04"),
            DisplayText.Get("Ui.Activity.MainWindow_Closing.05"), MessageBoxButton.YesNo, MessageBoxImage.Question) == MessageBoxResult.Yes)
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
