using System.Reflection;
using System.IO;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Threading;
using SteamSentinel.App;
using SteamSentinel.App.Services;
using SteamSentinel.Core.Models;

namespace SteamSentinel.SelfTest;

internal static partial class Program
{
    private static void TestV0115Window()
    {
        DispatcherFrame frame = new();
        Exception? failure = null;
        DispatcherTimer deadline = new() { Interval = TimeSpan.FromSeconds(30) };
        deadline.Tick += (_, _) => { failure = new TimeoutException("v0.1.15 dispatcher regression timed out"); frame.Continue = false; };
        deadline.Start();
        Dispatcher.CurrentDispatcher.BeginInvoke(new Action(async () =>
        {
            try { await TestV0115WindowAsync(); }
            catch (Exception ex) { failure = ex; }
            finally { frame.Continue = false; }
        }));
        Dispatcher.PushFrame(frame);
        deadline.Stop();
        if (failure is not null) throw failure;
    }

    private static async Task TestV0115WindowAsync()
    {
        Dispatcher ui = Dispatcher.CurrentDispatcher;
        int uiThread = Environment.CurrentManagedThreadId;
        Check("v0.1.15 在真实 WPF 消息循环与同步上下文中测试", SynchronizationContext.Current is DispatcherSynchronizationContext);

        TextBlock owned = new();
        TaskCompletionSource<Exception?> oldError = new(TaskCreationOptions.RunContinuationsAsynchronously);
        IProgress<int> oldProgress = await Task.Run(() => new Progress<int>(_ =>
        {
            try { owned.Text = "old invalid cross-thread update"; oldError.TrySetResult(null); }
            catch (Exception ex) { oldError.TrySetResult(ex); }
        }));
        oldProgress.Report(1);
        Check("v0.1.15 安全重现旧回调的跨线程异常，不崩溃测试进程",
            await oldError.Task.WaitAsync(TimeSpan.FromSeconds(3)) is InvalidOperationException);

        int callbackThread = 0, calls = 0, errors = 0;
        TaskCompletionSource<bool> received = new(TaskCreationOptions.RunContinuationsAsynchronously);
        using DispatcherProgress<int> fixedProgress = await Task.Run(() => new DispatcherProgress<int>(ui, value =>
        {
            owned.Text = value.ToString(); callbackThread = Environment.CurrentManagedThreadId; calls++;
            if (value == 9999) received.TrySetResult(true);
        }, () => true, _ => errors++));
        await Task.Run(() => { for (int i = 0; i < 10000; i++) fixedProgress.Report(i); });
        await received.Task.WaitAsync(TimeSpan.FromSeconds(3));
        Check("v0.1.15 后台创建和上报仍只在界面线程更新", callbackThread == uiThread && owned.Text == "9999" && errors == 0);
        Check("v0.1.15 密集进度合并，不堆积一万个界面回调", calls > 0 && calls < 10000);

        int late = 0;
        DispatcherProgress<int> disposed = new(ui, _ => late++, () => true, _ => errors++);
        disposed.Report(1); disposed.Dispose();
        await ui.InvokeAsync(() => { }, DispatcherPriority.ContextIdle);
        Check("v0.1.15 阶段结束后丢弃已排队的迟到更新", late == 0);
        using DispatcherProgress<int> inactive = new(ui, _ => late++, () => false, _ => errors++);
        inactive.Report(1);
        await ui.InvokeAsync(() => { }, DispatcherPriority.ContextIdle);
        Check("v0.1.15 已关闭或不活动的窗口不再接受回调", late == 0);
        using DispatcherProgress<int> brokenDisplay = new(ui, _ => throw new InvalidOperationException("inert display error"),
            () => true, _ => { errors++; callbackThread = Environment.CurrentManagedThreadId; });
        brokenDisplay.Report(1);
        await ui.InvokeAsync(() => { }, DispatcherPriority.ContextIdle);
        brokenDisplay.Report(2);
        await ui.InvokeAsync(() => { }, DispatcherPriority.ContextIdle);
        Check("v0.1.15 显示异常只报告一次且不逃逸到线程池", errors == 1 && callbackThread == uiThread);

        const BindingFlags flags = BindingFlags.NonPublic | BindingFlags.Instance;
        MainWindow window = new();
        void Busy(bool value) => typeof(MainWindow).GetMethod("SetBusy", flags)!.Invoke(window, [value]);
        T Control<T>(string name) => (T)window.FindName(name);
        FrameworkElement content = (FrameworkElement)window.Content;
        window.Content = null;
        // Off-screen inert host: does not raise MainWindow.Loaded or inspect this machine.
        Window host = new() { Content = content, Width = 980, Height = 720, Left = -20000, Top = -20000,
            ShowActivated = false, ShowInTaskbar = false, WindowStyle = WindowStyle.None };
        ShutdownMode previousShutdown = Application.Current.ShutdownMode;
        Application.Current.ShutdownMode = ShutdownMode.OnExplicitShutdown;
        host.Show();
        try
        {
            foreach (MainWindow.ActivityPhase phase in new[] { MainWindow.ActivityPhase.Preparing, MainWindow.ActivityPhase.Applying, MainWindow.ActivityPhase.FollowUp })
            {
                window.ShowActivity(phase);
                Check("v0.1.15 阶段可见并使用无百分比忙碌状态 " + phase,
                    Control<Border>("ActivityPanel").Visibility == Visibility.Visible &&
                    !Control<TextBlock>("ActivityElapsedText").Text.Contains('%') &&
                    Control<ProgressBar>("ActivityProgressBar").IsIndeterminate == SystemParameters.ClientAreaAnimation);
            }
            RotateTransform rotation = Control<RotateTransform>("ActivityRotation");
            double angle = rotation.Angle;
            int ticks = 0;
            DispatcherTimer heartbeat = new(TimeSpan.FromMilliseconds(20), DispatcherPriority.Background, (_, _) => ticks++, ui);
            heartbeat.Start();
            await Task.Delay(170);
            Check("v0.1.15 动画时钟实际推进或尊重系统关闭动画设置",
                !SystemParameters.ClientAreaAnimation || Math.Abs(rotation.Angle - angle) > 0.01);

            RemediationRunResult saved = new() { Success = true };
            typeof(MainWindow).GetField("_caseResult", flags)!.SetValue(window, saved);
            typeof(MainWindow).GetField("_operationCommitted", flags)!.SetValue(window, true);
            Check("v0.1.15 处置与复查期间阻止直接关闭窗口", window.MustWaitBeforeClosing);
            int runnerThread = uiThread;
            ScanReport followUp = await window.RunPostRemediationCheckAsync(CancellationToken.None, async (options, progress, token) =>
            {
                runnerThread = Environment.CurrentManagedThreadId;
                Check("v0.1.15 生产复查选项只读且不启动内容扫描", options.IncludeSystem && options.IncludeSteam &&
                    !options.IncludeWorkshop && !options.IncludeRelatedContent && !options.UseAmsi && !options.InspectArchives);
                progress.Report(new("fixture", "inert-follow-up", 1, null, "idle data"));
                await Task.Delay(2200, token);
                return new ScanReport { CompletedAtUtc = DateTimeOffset.UtcNow };
            });
            heartbeat.Stop();
            Check("v0.1.15 实际复查入口后台上报可安全更新界面", runnerThread != uiThread &&
                Control<TextBlock>("ProgressItemText").Text == "inert-follow-up" && followUp.CompletedAtUtc is not null);
            Check("v0.1.15 等待复查时界面持续响应且已用时间更新", ticks > 5 && !Control<TextBlock>("ActivityElapsedText").Text.EndsWith("00:00"));
            Check("v0.1.15 复查不覆盖已保存的处置结果", ReferenceEquals(typeof(MainWindow).GetField("_caseResult", flags)!.GetValue(window), saved));

            bool failed = false, cancelled = false;
            try { await window.RunPostRemediationCheckAsync(CancellationToken.None, (_, _, _) => throw new InvalidDataException("inert scan error")); }
            catch (InvalidDataException) { failed = true; }
            using (CancellationTokenSource cancellation = new(TimeSpan.FromMilliseconds(40)))
            {
                try { await window.RunPostRemediationCheckAsync(cancellation.Token, async (_, _, token) => { await Task.Delay(1000, token); return new(); }); }
                catch (OperationCanceledException) { cancelled = true; }
            }
            Check("v0.1.15 复查失败和取消回到等待调用方，不被进度层吞掉", failed && cancelled);
            ScanOptions originalOptions = new() { Mode = ScanMode.Custom, IncludeSystem = false, IncludeSteam = false,
                IncludeWorkshop = false, InspectArchives = true, CustomRoots = [@"C:\inert-original"] };
            int contentThread = uiThread;
            ScanReport originalScopeReport = await window.RunOriginalContentCheckAsync(originalOptions, CancellationToken.None, async (options, reporter, _) =>
            {
                contentThread = Environment.CurrentManagedThreadId;
                Check("0.1.16 原范围复查收到原压缩设置和原路径", options.InspectArchives && options.CustomRoots.Single() == @"C:\inert-original");
                reporter.Report(new("inert", "original scope", 1, 1, "read only"));
                await Task.Delay(30);
                return new();
            });
            Check("0.1.16 原范围复查在后台运行且界面独立显示阶段", contentThread != uiThread &&
                Control<TextBlock>("ActivityTitleText").Text.Contains("原扫描范围") && originalScopeReport is not null);
            var batchPreviewData = new RemediationBatchSession
            {
                Plans = [new() { Actions = [new() { Type = RemediationActionType.QuarantineFile, Target = @"C:\inert\a.zip" }] },
                    new() { Actions = [new() { Type = RemediationActionType.QuarantineFile, Target = @"C:\inert\b.zip" }] }],
                Targets = [new() { Target = @"C:\inert\changed.zip", MissingActions = ["inert"], Reason = "身份变化，未纳入" }]
            };
            SteamSentinel.App.Dialogs.RemediationPreviewWindow batchDialog = new(batchPreviewData);
            Check("0.1.16 批次预览列出所有批次且默认展示未纳入项", batchDialog.Actions.Select(a => a.Batch).SequenceEqual([1, 2]) &&
                ((TabControl)batchDialog.FindName("PreviewTabs")).SelectedIndex == 1 && batchDialog.OmittedTargets.Count == 1);
            Check("0.1.16 未勾选确认时不能开始全部批次", !((Button)batchDialog.FindName("ExecuteButton")).IsEnabled);
            batchDialog.Close();
            window.ShowActivity(MainWindow.ActivityPhase.Confirmation);
            Check("v0.1.15 等待人工确认时停止旋转和流动条", !rotation.HasAnimatedProperties &&
                !Control<ProgressBar>("ActivityProgressBar").IsIndeterminate && Control<TextBlock>("ActivityTitleText").Text.Contains("核对"));
            typeof(MainWindow).GetField("_operationCommitted", flags)!.SetValue(window, false);
            Busy(false);
            Check("v0.1.15 完成或失败后停止动画并解除关闭门禁", !window.MustWaitBeforeClosing &&
                Control<Border>("ActivityPanel").Visibility == Visibility.Collapsed && !rotation.HasAnimatedProperties &&
                !((DispatcherTimer)typeof(MainWindow).GetField("_activityTimer", flags)!.GetValue(window)!).IsEnabled);

            Busy(true);
            DispatcherProgress<ScanProgress> windowProgress = (DispatcherProgress<ScanProgress>)typeof(MainWindow)
                .GetMethod("CreateUiProgress", flags)!.Invoke(window, [new Action<ScanProgress>(_ => late++)])!;
            windowProgress.Report(new("late", "late", 1, null, "late"));
            Busy(false); window.Close();
            await ui.InvokeAsync(() => { }, DispatcherPriority.ContextIdle);
            windowProgress.Dispose();
            Check("v0.1.15 窗口关闭后排队的真实窗口进度被丢弃", late == 0);
        }
        finally
        {
            Busy(false); host.Content = null; host.Close(); window.Close();
            Application.Current.ShutdownMode = previousShutdown;
        }
        string log = AppErrorLog.Format("fixture", new InvalidOperationException("token=hidden-secret " + new string('x', 20000)));
        Check("v0.1.15 错误记录有界并过滤已识别凭据", log.Length <= 16384 && !log.Contains("hidden-secret"));
    }
}
