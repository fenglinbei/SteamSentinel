using SteamSentinel.Core.Reporting;
using System.ComponentModel;
using System.Diagnostics;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Media.Animation;
using System.Windows.Threading;
using SteamSentinel.App.Services;
using SteamSentinel.Core.Models;

namespace SteamSentinel.App;

public partial class MainWindow
{
    private DispatcherTimer? _activityTimer;
    private readonly Stopwatch _activityClock = new();
    private bool _windowClosed, _closeWhenIdle, _operationCommitted, _hasCustomHint;
    private bool _scanStageAnimating;
    private string? _scanStageRawItem;
    private string? _scanStageRawDetail;
    private string? _scanStageCustomTitle;
    private ActivityPhase _activityPhase;
    private string _activityHint = "";
    private double _scanProgressMaxPercent;
    private double _scanStageStartPercent;
    private double _scanStageEndPercent = 100;
    private bool _repairStageActive;
    private string[] _repairStepLabels = [];
    private int _repairStepIndex;
    private double _repairStepPercent;
    private ActiveRepairFlow _activeRepairFlow;

    private static readonly Brush StepPendingBackground = FreezeBrush(0xF1, 0xF5, 0xF9);
    private static readonly Brush StepPendingForeground = FreezeBrush(0x64, 0x74, 0x8B);
    private static readonly Brush StepPendingBorder = FreezeBrush(0xE2, 0xE8, 0xF0);
    private static readonly Brush StepActiveBackground = FreezeBrush(0xEF, 0xF6, 0xFF);
    private static readonly Brush StepActiveForeground = FreezeBrush(0x1D, 0x4E, 0xD8);
    private static readonly Brush StepActiveBorder = FreezeBrush(0xBF, 0xDB, 0xFE);
    private static readonly Brush StepDoneBackground = FreezeBrush(0xEC, 0xFD, 0xF5);
    private static readonly Brush StepDoneForeground = FreezeBrush(0x04, 0x78, 0x57);
    private static readonly Brush StepDoneBorder = FreezeBrush(0xA7, 0xF3, 0xD0);

    internal enum ActiveRepairFlow { None, StandardRemediation, OfficialInstaller }

    private static readonly DependencyProperty ScanStageAnimatedProgressProperty =
        DependencyProperty.Register(
            nameof(ScanStageAnimatedProgress),
            typeof(double),
            typeof(MainWindow),
            new PropertyMetadata(0.0, OnScanStageAnimatedProgressChanged));

    private double ScanStageAnimatedProgress
    {
        get => (double)GetValue(ScanStageAnimatedProgressProperty);
        set => SetValue(ScanStageAnimatedProgressProperty, value);
    }

    private static void OnScanStageAnimatedProgressChanged(DependencyObject d, DependencyPropertyChangedEventArgs e)
    {
        if (d is MainWindow window) window.UpdateScanRingVisual((double)e.NewValue);
    }

    internal enum ActivityPhase { Working, Scanning, Preparing, Confirmation, Applying, FollowUp, ContentFollowUp, Exporting, Inspecting, Cancelling }

    private static string DefaultPhaseTitle(ActivityPhase phase) => phase switch
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

    private static string DefaultPhaseHint(ActivityPhase phase) => phase switch
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

    internal void ShowActivity(ActivityPhase phase, string? hint = null)
    {
        Dispatcher.VerifyAccess();
        if (_windowClosed) return;
        _activityPhase = phase;
        _hasCustomHint = hint is not null;
        ActivityTitleText.Text = DefaultPhaseTitle(phase);
        _activityHint = hint ?? DefaultPhaseHint(phase);
        ActivityDetailText.Text = _activityHint;
        UpdateActivityDetailVisibility();
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
            new DoubleAnimation(0, 360, TimeSpan.FromSeconds(0.85)) { RepeatBehavior = RepeatBehavior.Forever });
        ResetScanProgressPresentation();
        ActivityProgressBar.IsIndeterminate = moving;
        ActivityProgressBar.Visibility = phase == ActivityPhase.Confirmation ? Visibility.Collapsed : Visibility.Visible;
        ScanProgressBar.IsIndeterminate = false;
        ScanProgressBar.Value = 0;
        ScanProgressBar.Visibility = Visibility.Collapsed;
        _scanStageCustomTitle = null;
        _scanStageRawItem = null;
        _scanStageRawDetail = null;
        UpdateScanStageText(null, null, _activityHint);
        UpdateScanStageOverlayVisibility();
    }

    internal void BeginScanProgressStage(double startPercent, double endPercent, bool reset = false)
    {
        Dispatcher.VerifyAccess();
        if (_windowClosed) return;
        if (reset) ResetScanProgressPresentation();
        _scanStageStartPercent = Math.Clamp(startPercent, 0, 99);
        _scanStageEndPercent = Math.Clamp(Math.Max(_scanStageStartPercent, endPercent), 0, 99);
        if (!reset && _activityPhase == ActivityPhase.Scanning && _scanStageStartPercent > _scanProgressMaxPercent)
        {
            _scanProgressMaxPercent = _scanStageStartPercent;
            SetDeterminateActivityProgress(_scanProgressMaxPercent);
        }
    }

    /// <summary>
    /// 启动四步可视化修复进度舞台（显式激活，不影响常规 ShowActivity 的既有不确定进度契约）。
    /// </summary>
    internal void BeginRepairStage(IReadOnlyList<string> stepLabels) =>
        BeginRepairStageInternal(ActiveRepairFlow.None, stepLabels);

    private void BeginRepairStageInternal(ActiveRepairFlow flow, IReadOnlyList<string> stepLabels)
    {
        ArgumentNullException.ThrowIfNull(stepLabels);
        Dispatcher.VerifyAccess();
        if (_windowClosed) return;

        _activeRepairFlow = flow;
        _activityPhase = ActivityPhase.Applying;
        ActivityPanel.Visibility = Visibility.Visible;
        UpdateCompactHeader();
        if (!_activityClock.IsRunning) _activityClock.Restart();
        _activityTimer ??= new DispatcherTimer(TimeSpan.FromSeconds(1), DispatcherPriority.Background,
            (_, _) => RefreshActivityElapsed(), Dispatcher);
        if (!_activityTimer.IsEnabled) _activityTimer.Start();
        RefreshActivityElapsed();

        ActivitySpinner.Visibility = Visibility.Visible;
        ActivityRotation.BeginAnimation(RotateTransform.AngleProperty, null);
        if (SystemParameters.ClientAreaAnimation)
        {
            ActivityRotation.BeginAnimation(RotateTransform.AngleProperty,
                new DoubleAnimation(0, 360, TimeSpan.FromSeconds(0.85)) { RepeatBehavior = RepeatBehavior.Forever });
        }
        ActivityProgressBar.Visibility = Visibility.Visible;
        ScanProgressBar.IsIndeterminate = false;
        ScanProgressBar.Value = 0;
        ScanProgressBar.Visibility = Visibility.Collapsed;

        _repairStepLabels = stepLabels.ToArray();
        _repairStepIndex = 0;
        _repairStepPercent = 5;
        _repairStageActive = true;
        RenderRepairStepperPills();
        SetDeterminateActivityProgress(_repairStepPercent);
        UpdateScanStageOverlayVisibility();
    }

    internal static string[] GetStandardRemediationStepLabels() =>
    [
        DisplayText.Get("Ui.RepairStage.Std.Step0"),
        DisplayText.Get("Ui.RepairStage.Std.Step1"),
        DisplayText.Get("Ui.RepairStage.Std.Step2"),
        DisplayText.Get("Ui.RepairStage.Std.Step3")
    ];

    internal static string[] GetOfficialRepairStepLabels() =>
    [
        DisplayText.Get("Ui.RepairStage.Official.Step0"),
        DisplayText.Get("Ui.RepairStage.Official.Step1"),
        DisplayText.Get("Ui.RepairStage.Official.Step2"),
        DisplayText.Get("Ui.RepairStage.Official.Step3")
    ];

    /// <summary>
    /// 推进可视化修复舞台的当前步骤胶囊、主标题、当前条目及确定性百分比。
    /// </summary>
    internal void ReportRepairStep(int stepIndex, double percent, string stageTitle, string? currentItem = null, string? detailHint = null)
    {
        Dispatcher.VerifyAccess();
        if (_windowClosed || !_repairStageActive) return;

        int maxIndex = Math.Max(0, _repairStepLabels.Length - 1);
        _repairStepIndex = _repairStepLabels.Length == 0 ? 0 : Math.Clamp(stepIndex, 0, maxIndex);
        _repairStepPercent = Math.Clamp(percent, 1.0, 99.5);
        RenderRepairStepperPills();

        _hasCustomHint = !string.IsNullOrWhiteSpace(detailHint);
        ActivityTitleText.Text = stageTitle;
        if (!string.IsNullOrWhiteSpace(detailHint)) _activityHint = detailHint;
        ActivityDetailText.Text = _activityHint;
        UpdateActivityDetailVisibility();

        ProgressStageText.Text = stageTitle;
        ProgressItemText.Text = currentItem ?? string.Empty;

        UpdateScanStageText(stageTitle, currentItem, detailHint ?? _activityHint);
        SetDeterminateActivityProgress(_repairStepPercent);
        UpdateScanStageOverlayVisibility();
    }

    private void RenderRepairStepperPills()
    {
        if (RepairStepperPanel is null) return;
        RepairStepperPanel.Children.Clear();
        for (int i = 0; i < _repairStepLabels.Length; i++)
        {
            bool isDone = i < _repairStepIndex;
            bool isActive = i == _repairStepIndex;

            Brush bg = isDone ? StepDoneBackground : isActive ? StepActiveBackground : StepPendingBackground;
            Brush fg = isDone ? StepDoneForeground : isActive ? StepActiveForeground : StepPendingForeground;
            Brush borderBrush = isDone ? StepDoneBorder : isActive ? StepActiveBorder : StepPendingBorder;

            TextBlock text = new()
            {
                Text = isDone ? $"✓ {_repairStepLabels[i]}" : $"{i + 1}. {_repairStepLabels[i]}",
                FontSize = 11.5,
                FontWeight = isDone || isActive ? FontWeights.SemiBold : FontWeights.Normal,
                Foreground = fg,
                TextTrimming = TextTrimming.CharacterEllipsis
            };

            Border pill = new()
            {
                Background = bg,
                BorderBrush = borderBrush,
                BorderThickness = new Thickness(1),
                CornerRadius = new CornerRadius(12),
                Padding = new Thickness(9, 4, 9, 4),
                Margin = new Thickness(3, 0, 3, 0),
                Child = text
            };
            RepairStepperPanel.Children.Add(pill);
        }
    }

    internal void ReportScanProgressPercent(ScanProgress progress)
    {
        Dispatcher.VerifyAccess();
        if (_windowClosed || _activityPhase != ActivityPhase.Scanning) return;
        if (progress.Total is not (> 0 and long total)) return;
        double ratio = Math.Clamp((double)progress.Completed / total, 0.0, 1.0);
        double mapped = _scanStageStartPercent + (_scanStageEndPercent - _scanStageStartPercent) * ratio;
        mapped = Math.Clamp(Math.Max(_scanProgressMaxPercent, mapped), 1.0, 99.0);
        _scanProgressMaxPercent = mapped;
        SetDeterminateActivityProgress(mapped);
    }

    internal double CurrentScanProgressPercent => _scanProgressMaxPercent;

    private void SetDeterminateActivityProgress(double targetValue)
    {
        ActivityProgressBar.IsIndeterminate = false;
        // 分步修复阶段同步刷新圆环、进度条与百分比，避免短耗时回调读取到动画过渡前的旧数值。
        if (SystemParameters.ClientAreaAnimation && !_repairStageActive)
        {
            DoubleAnimation barAnim = new(targetValue, TimeSpan.FromMilliseconds(180))
            {
                EasingFunction = new CubicEase { EasingMode = EasingMode.EaseOut }
            };
            ActivityProgressBar.BeginAnimation(System.Windows.Controls.Primitives.RangeBase.ValueProperty, barAnim);

            DoubleAnimation ringAnim = new(targetValue, TimeSpan.FromMilliseconds(220))
            {
                EasingFunction = new CubicEase { EasingMode = EasingMode.EaseOut }
            };
            BeginAnimation(ScanStageAnimatedProgressProperty, ringAnim);
        }
        else
        {
            ActivityProgressBar.BeginAnimation(System.Windows.Controls.Primitives.RangeBase.ValueProperty, null);
            ActivityProgressBar.Value = targetValue;
            BeginAnimation(ScanStageAnimatedProgressProperty, null);
            ScanStageAnimatedProgress = targetValue;
        }
        ScanProgressBar.Value = targetValue;
        ActivityPercentText.Text = $"{(int)Math.Round(targetValue)}%";
        ActivityPercentText.Visibility = Visibility.Visible;
        ActivityPercentBadge.Visibility = Visibility.Visible;
    }

    private void ResetScanProgressPresentation()
    {
        _scanProgressMaxPercent = 0;
        _scanStageStartPercent = 0;
        _scanStageEndPercent = 100;
        _repairStageActive = false;
        _activeRepairFlow = ActiveRepairFlow.None;
        _repairStepLabels = [];
        _repairStepIndex = 0;
        _repairStepPercent = 0;
        if (RepairStepperPanel is not null)
        {
            RepairStepperPanel.Children.Clear();
            RepairStepperPanel.Visibility = Visibility.Collapsed;
        }
        ActivityProgressBar.BeginAnimation(System.Windows.Controls.Primitives.RangeBase.ValueProperty, null);
        ActivityProgressBar.Value = 0;
        BeginAnimation(ScanStageAnimatedProgressProperty, null);
        ScanStageAnimatedProgress = 0;
        UpdateScanRingVisual(0);
        ActivityPercentText.Text = string.Empty;
        ActivityPercentText.Visibility = Visibility.Collapsed;
        ActivityPercentBadge.Visibility = Visibility.Collapsed;
    }

    private void RefreshActivityElapsed()
    {
        TimeSpan elapsed = _activityClock.Elapsed;
        string elapsedText = DisplayText.Get("Ui.Activity.RefreshActivityElapsed.01") + (elapsed.TotalHours >= 1 ? elapsed.ToString(@"h\:mm\:ss") : elapsed.ToString(@"mm\:ss"));
        ActivityElapsedText.Text = elapsedText;
        if (ScanStageElapsedText is not null) ScanStageElapsedText.Text = elapsedText;
        if (elapsed.TotalSeconds >= 20 && _activityPhase != ActivityPhase.Confirmation)
        {
            ActivityDetailText.Text = _activityHint + DisplayText.Get("Ui.Activity.RefreshActivityElapsed.02");
            if (ScanStageHintText is not null && string.IsNullOrEmpty(_scanStageRawItem))
                ScanStageHintText.Text = DefaultPhaseHint(ActivityPhase.Scanning);
        }
    }

    /// <summary>在语言热切换期间，如果顶部活动栏处于可见状态，按当前语言同步刷新阶段文案、步骤胶囊与计时器。</summary>
    internal void RefreshActivityLocalizedText()
    {
        if (ActivityPanel.Visibility != Visibility.Visible) return;
        if (_repairStageActive && _activeRepairFlow != ActiveRepairFlow.None)
        {
            _repairStepLabels = _activeRepairFlow == ActiveRepairFlow.OfficialInstaller
                ? GetOfficialRepairStepLabels()
                : GetStandardRemediationStepLabels();
            RenderRepairStepperPills();
        }
        ActivityTitleText.Text = _repairStageActive && _scanStageCustomTitle is not null ? _scanStageCustomTitle : DefaultPhaseTitle(_activityPhase);
        if (!_hasCustomHint) _activityHint = DefaultPhaseHint(_activityPhase);
        ActivityDetailText.Text = _activityHint;
        UpdateActivityDetailVisibility();
        if (ScanStageHintText is not null)
            ScanStageHintText.Text = DefaultPhaseHint(ActivityPhase.Scanning);
        UpdateScanStageText(_scanStageCustomTitle, _scanStageRawItem, _scanStageRawDetail ?? _activityHint);
        RefreshActivityElapsed();
    }

    private void UpdateActivityDetailVisibility()
    {
        if (ActivityDetailText is null || ActivityDetailSeparator is null) return;
        bool showDetail = !(_compactLayout ?? false) && !string.IsNullOrWhiteSpace(ActivityDetailText.Text);
        Visibility visibility = showDetail ? Visibility.Visible : Visibility.Collapsed;
        ActivityDetailText.Visibility = visibility;
        ActivityDetailSeparator.Visibility = visibility;
    }

    private void HideActivity()
    {
        _activityTimer?.Stop();
        _activityClock.Stop();
        ActivityRotation.BeginAnimation(System.Windows.Media.RotateTransform.AngleProperty, null);
        StopScanStageAmbientAnimations();
        ResetScanProgressPresentation();
        ActivityProgressBar.IsIndeterminate = false;
        ActivityPanel.Visibility = Visibility.Collapsed;
        _scanStageCustomTitle = null;
        _scanStageRawItem = null;
        _scanStageRawDetail = null;
        UpdateScanStageOverlayVisibility();
        UpdateCompactHeader();
        ScanProgressBar.IsIndeterminate = false;
        ScanProgressBar.Visibility = Visibility.Collapsed;
    }

    private void UpdateScanRingVisual(double percent)
    {
        if (ScanRingIndeterminateHost is null || ScanRingProgressPath is null || ScanRingArcSegment is null ||
            ScanRingHeadDotHost is null || ScanRingHeadRotation is null || ScanStagePercentPanel is null ||
            ScanStagePercentNumber is null || ScanStagePendingDots is null || ScanStageBarFill is null ||
            ScanStageBarIndeterminate is null)
            return;

        if (percent < 0.5)
        {
            ScanRingIndeterminateHost.Visibility = Visibility.Visible;
            ScanStagePendingDots.Visibility = Visibility.Visible;
            ScanStageBarIndeterminate.Visibility = Visibility.Visible;
            ScanRingProgressPath.Visibility = Visibility.Collapsed;
            ScanRingHeadDotHost.Visibility = Visibility.Collapsed;
            ScanStagePercentPanel.Visibility = Visibility.Collapsed;
            ScanStageBarFill.Visibility = Visibility.Collapsed;
            ScanStageBarFill.Width = 0;
            return;
        }

        double clamped = Math.Clamp(percent, 0.5, 99.5);
        double angleRad = clamped / 100.0 * 2.0 * Math.PI;
        ScanRingArcSegment.Point = new Point(54.0 + 42.0 * Math.Sin(angleRad), 54.0 - 42.0 * Math.Cos(angleRad));
        ScanRingArcSegment.IsLargeArc = angleRad > Math.PI;
        ScanRingHeadRotation.Angle = clamped * 3.6;
        ScanStagePercentNumber.Text = ((int)Math.Round(clamped)).ToString(System.Globalization.CultureInfo.InvariantCulture);
        ScanStageBarFill.Width = 300.0 * (clamped / 100.0);

        ScanRingIndeterminateHost.Visibility = Visibility.Collapsed;
        ScanStagePendingDots.Visibility = Visibility.Collapsed;
        ScanStageBarIndeterminate.Visibility = Visibility.Collapsed;
        ScanRingProgressPath.Visibility = Visibility.Visible;
        ScanRingHeadDotHost.Visibility = Visibility.Visible;
        ScanStagePercentPanel.Visibility = Visibility.Visible;
        ScanStageBarFill.Visibility = Visibility.Visible;
    }

    private void StartScanStageAmbientAnimations()
    {
        if (!SystemParameters.ClientAreaAnimation || _scanStageAnimating || _windowClosed ||
            ScanPulseScale1 is null || ScanPulseScale2 is null || ScanPulseRing1 is null || ScanPulseRing2 is null ||
            ScanRingIndeterminateRotation is null || ScanStageBarShimmerTransform is null || ScanStageBarIndeterminateTransform is null)
            return;

        _scanStageAnimating = true;
        Duration pulseDuration = new(TimeSpan.FromSeconds(2.2));
        SineEase pulseEase = new() { EasingMode = EasingMode.EaseOut };

        void StartPulse(System.Windows.Media.ScaleTransform scale, System.Windows.Shapes.Ellipse ring, TimeSpan delay)
        {
            DoubleAnimation growX = new(1.0, 1.28, pulseDuration)
            {
                BeginTime = delay,
                RepeatBehavior = RepeatBehavior.Forever,
                EasingFunction = pulseEase
            };
            DoubleAnimation growY = growX.Clone();
            scale.BeginAnimation(System.Windows.Media.ScaleTransform.ScaleXProperty, growX);
            scale.BeginAnimation(System.Windows.Media.ScaleTransform.ScaleYProperty, growY);

            DoubleAnimationUsingKeyFrames fade = new()
            {
                BeginTime = delay,
                Duration = pulseDuration,
                RepeatBehavior = RepeatBehavior.Forever
            };
            fade.KeyFrames.Add(new LinearDoubleKeyFrame(0.42, KeyTime.FromTimeSpan(TimeSpan.FromSeconds(0.15))));
            fade.KeyFrames.Add(new LinearDoubleKeyFrame(0.28, KeyTime.FromTimeSpan(TimeSpan.FromSeconds(0.5))));
            fade.KeyFrames.Add(new LinearDoubleKeyFrame(0.0, KeyTime.FromTimeSpan(TimeSpan.FromSeconds(2.2))));
            ring.BeginAnimation(UIElement.OpacityProperty, fade);
        }

        StartPulse(ScanPulseScale1, ScanPulseRing1, TimeSpan.Zero);
        StartPulse(ScanPulseScale2, ScanPulseRing2, TimeSpan.FromSeconds(1.1));

        DoubleAnimation spin = new(0, 360, TimeSpan.FromSeconds(1.15)) { RepeatBehavior = RepeatBehavior.Forever };
        ScanRingIndeterminateRotation.BeginAnimation(System.Windows.Media.RotateTransform.AngleProperty, spin);

        SineEase sweepEase = new() { EasingMode = EasingMode.EaseInOut };
        DoubleAnimation shimmer = new(-100, 320, TimeSpan.FromSeconds(1.45))
        {
            RepeatBehavior = RepeatBehavior.Forever,
            EasingFunction = sweepEase
        };
        ScanStageBarShimmerTransform.BeginAnimation(System.Windows.Media.TranslateTransform.XProperty, shimmer);

        DoubleAnimation indeterminateSweep = new(-110, 300, TimeSpan.FromSeconds(1.2))
        {
            RepeatBehavior = RepeatBehavior.Forever,
            AutoReverse = true,
            EasingFunction = sweepEase
        };
        ScanStageBarIndeterminateTransform.BeginAnimation(System.Windows.Media.TranslateTransform.XProperty, indeterminateSweep);
    }

    private void StopScanStageAmbientAnimations()
    {
        if (ScanPulseScale1 is not null)
        {
            ScanPulseScale1.BeginAnimation(System.Windows.Media.ScaleTransform.ScaleXProperty, null);
            ScanPulseScale1.BeginAnimation(System.Windows.Media.ScaleTransform.ScaleYProperty, null);
            ScanPulseScale1.ScaleX = 1;
            ScanPulseScale1.ScaleY = 1;
        }
        if (ScanPulseScale2 is not null)
        {
            ScanPulseScale2.BeginAnimation(System.Windows.Media.ScaleTransform.ScaleXProperty, null);
            ScanPulseScale2.BeginAnimation(System.Windows.Media.ScaleTransform.ScaleYProperty, null);
            ScanPulseScale2.ScaleX = 1;
            ScanPulseScale2.ScaleY = 1;
        }
        if (ScanPulseRing1 is not null)
        {
            ScanPulseRing1.BeginAnimation(UIElement.OpacityProperty, null);
            ScanPulseRing1.Opacity = 0;
        }
        if (ScanPulseRing2 is not null)
        {
            ScanPulseRing2.BeginAnimation(UIElement.OpacityProperty, null);
            ScanPulseRing2.Opacity = 0;
        }
        if (ScanRingIndeterminateRotation is not null)
        {
            ScanRingIndeterminateRotation.BeginAnimation(System.Windows.Media.RotateTransform.AngleProperty, null);
            ScanRingIndeterminateRotation.Angle = 0;
        }
        if (ScanStageBarShimmerTransform is not null)
        {
            ScanStageBarShimmerTransform.BeginAnimation(System.Windows.Media.TranslateTransform.XProperty, null);
            ScanStageBarShimmerTransform.X = -100;
        }
        if (ScanStageBarIndeterminateTransform is not null)
        {
            ScanStageBarIndeterminateTransform.BeginAnimation(System.Windows.Media.TranslateTransform.XProperty, null);
            ScanStageBarIndeterminateTransform.X = -110;
        }
        _scanStageAnimating = false;
    }

    internal void UpdateScanStageOverlayVisibility()
    {
        if (ScanStageOverlay is null || ActivityPanel is null || FindingsAreaHost is null) return;
        bool repairVisible = _repairStageActive
            && ActivityPanel.Visibility == Visibility.Visible
            && _activityPhase != ActivityPhase.Confirmation
            && (ResultTabs is null || ResultTabs.SelectedIndex == 0)
            && FindingsAreaHost.ActualHeight >= 175;
        bool scanVisible = _activityPhase == ActivityPhase.Scanning
            && ActivityPanel.Visibility == Visibility.Visible
            && PriorityFindings.Count == 0
            && ReferenceFindings.Count == 0
            && (ResultTabs is null || ResultTabs.SelectedIndex == 0)
            && FindingsAreaHost.ActualHeight >= 175;
        bool visible = repairVisible || scanVisible;

        if (RepairStepperPanel is not null)
            RepairStepperPanel.Visibility = repairVisible && FindingsAreaHost.ActualHeight >= 255
                ? Visibility.Visible
                : Visibility.Collapsed;

        if (ScanStageMetaPanel is not null)
            ScanStageMetaPanel.Visibility = FindingsAreaHost.ActualHeight >= 245 ? Visibility.Visible : Visibility.Collapsed;

        ScanProgressBar.Visibility = Visibility.Collapsed;
        if (InlineProgressRow is not null)
            InlineProgressRow.Visibility = visible ? Visibility.Collapsed : Visibility.Visible;
        if (visible)
        {
            ScanStageOverlay.Visibility = Visibility.Visible;
            StartScanStageAmbientAnimations();
        }
        else
        {
            ScanStageOverlay.Visibility = Visibility.Collapsed;
            StopScanStageAmbientAnimations();
        }
    }

    internal static bool IsRawContainerDiagnosticDetail(string? text)
    {
        if (string.IsNullOrWhiteSpace(text)) return false;
        return (text.Contains("深度", StringComparison.Ordinal) && text.Contains("解码", StringComparison.Ordinal))
            || (text.Contains("Depth", StringComparison.Ordinal) && text.Contains("decoded", StringComparison.OrdinalIgnoreCase));
    }

    private string FormatFriendlyScanTarget(string? rawItem, string? rawDetail)
    {
        if (!string.IsNullOrWhiteSpace(rawItem))
        {
            string trimmed = rawItem.Trim();
            int lastSep = trimmed.LastIndexOfAny(['\\', '/']);
            if (lastSep > 0 && lastSep < trimmed.Length - 1)
            {
                int prevSep = trimmed.LastIndexOfAny(['\\', '/'], lastSep - 1);
                if (prevSep >= 0) return "…" + trimmed[prevSep..];
            }
            return trimmed;
        }
        if (!string.IsNullOrWhiteSpace(rawDetail) && !IsRawContainerDiagnosticDetail(rawDetail))
            return rawDetail.Trim();
        return DefaultPhaseHint(ActivityPhase.Scanning);
    }

    private void UpdateScanStageText(string? stage, string? item, string? detail)
    {
        if (ScanStageTitleText is null || ScanStageItemText is null) return;
        _scanStageCustomTitle = string.IsNullOrWhiteSpace(stage) ? null : stage.Trim();
        _scanStageRawItem = string.IsNullOrWhiteSpace(item) ? null : item.Trim();
        _scanStageRawDetail = string.IsNullOrWhiteSpace(detail) ? null : detail.Trim();

        ScanStageTitleText.Text = _scanStageCustomTitle ?? DefaultPhaseTitle(_activityPhase);
        ScanStageItemText.Text = FormatFriendlyScanTarget(_scanStageRawItem, _scanStageRawDetail);
        ScanStageItemText.ToolTip = _scanStageRawItem ?? (_scanStageRawDetail is { } d && !IsRawContainerDiagnosticDetail(d) ? d : ScanStageItemText.Text);
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
        if (_repairStageActive)
        {
            _activityPhase = ActivityPhase.FollowUp;
            ReportRepairStep(3, Math.Max(_repairStepPercent, 88),
                DisplayText.Get("Ui.RepairStage.Std.Step3Title"), null,
                DisplayText.Get("Ui.RepairStage.Std.Step3Hint"));
        }
        else
        {
            ShowActivity(ActivityPhase.FollowUp);
        }
        using DispatcherProgress<ScanProgress> progress = CreateUiProgress(p =>
        {
            ProgressStageText.Text = DisplayText.Get("Ui.Activity.RunPostRemediationCheckAsync.01") + p.DisplayStage;
            ProgressItemText.Text = p.DisplayCurrentItem;
            if (_repairStageActive)
            {
                double ratio = p.Total is > 0 and long total
                    ? Math.Clamp((double)p.Completed / total, 0.0, 1.0)
                    : 0.5;
                double mapped = Math.Max(_repairStepPercent, 88.0 + 10.0 * ratio);
                ReportRepairStep(3, mapped, DisplayText.Get("Ui.RepairStage.Std.Step3Title"),
                    p.DisplayCurrentItem, DisplayText.Get("Ui.RepairStage.Std.Step3Hint"));
            }
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
        Localization.Localizer.Instance.LanguageChanged -= OnLanguageChanged;
        _scanCancellation?.Cancel();
        HideActivity();
    }
}
