using System.Collections.Concurrent;
using System.Reflection;
using System.Runtime.ExceptionServices;
using System.Windows;
using System.Windows.Threading;

namespace SteamSentinel.SelfTest;

// Application schedules startup in its constructor even without Run(). Product
// resources must not also launch a real window when a layout test pumps messages.
internal static class UiFixtureApplication
{
    private static readonly object SyncRoot = new();
    private static Thread? _staThread;
    private static BlockingCollection<Action<SteamSentinel.App.App>?>? _workQueue;

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

    /// <summary>
    /// 在同一测试进程内复用单个 WPF Application 与 STA 线程执行同步 UI 测试。
    /// 不预置 DispatcherSynchronizationContext，以与原有独立 STA 夹具语义完全一致。
    /// </summary>
    internal static void RunOnStaApplication(Action<SteamSentinel.App.App> action)
    {
        BlockingCollection<Action<SteamSentinel.App.App>?> queue = EnsureSharedStaQueue();
        ExecutionContext? callerContext = ExecutionContext.Capture();
        using ManualResetEventSlim done = new(false);
        Exception? captured = null;
        queue.Add(app =>
        {
            void Execute()
            {
                SynchronizationContext? previous = SynchronizationContext.Current;
                SynchronizationContext.SetSynchronizationContext(null);
                try { action(app); }
                catch (Exception ex) { captured = ex; }
                finally { SynchronizationContext.SetSynchronizationContext(previous); }
            }

            try
            {
                if (callerContext is not null)
                    ExecutionContext.Run(callerContext, _ => Execute(), null);
                else
                    Execute();
            }
            finally
            {
                callerContext?.Dispose();
                done.Set();
            }
        });
        done.Wait();
        if (captured is not null)
            ExceptionDispatchInfo.Capture(captured).Throw();
    }

    /// <summary>
    /// 在共享 WPF STA 线程上通过 DispatcherFrame 执行异步 UI 测试，兼顾消息泵送与可重入等待。
    /// </summary>
    internal static Task RunOnStaApplicationAsync(Func<SteamSentinel.App.App, Task> actionAsync)
    {
        BlockingCollection<Action<SteamSentinel.App.App>?> queue = EnsureSharedStaQueue();
        ExecutionContext? callerContext = ExecutionContext.Capture();
        TaskCompletionSource completion = new(TaskCreationOptions.RunContinuationsAsynchronously);
        queue.Add(app =>
        {
            void Execute()
            {
                SynchronizationContext? previous = SynchronizationContext.Current;
                Dispatcher dispatcher = Dispatcher.CurrentDispatcher;
                SynchronizationContext.SetSynchronizationContext(new DispatcherSynchronizationContext(dispatcher));
                try
                {
                    DispatcherFrame frame = new();
                    Task innerTask = actionAsync(app);
                    _ = innerTask.ContinueWith(
                        _ => dispatcher.BeginInvoke(() => frame.Continue = false),
                        CancellationToken.None,
                        TaskContinuationOptions.ExecuteSynchronously,
                        TaskScheduler.Default);
                    if (!innerTask.IsCompleted)
                        Dispatcher.PushFrame(frame);
                    innerTask.GetAwaiter().GetResult();
                    completion.TrySetResult();
                }
                catch (Exception ex)
                {
                    completion.TrySetException(ex);
                }
                finally
                {
                    SynchronizationContext.SetSynchronizationContext(previous);
                }
            }

            try
            {
                if (callerContext is not null)
                    ExecutionContext.Run(callerContext, _ => Execute(), null);
                else
                    Execute();
            }
            finally
            {
                callerContext?.Dispose();
            }
        });
        return completion.Task;
    }

    /// <summary>
    /// 结束共享 WPF Application 与 STA 线程，防止阻塞测试进程退出。
    /// </summary>
    internal static void ShutdownShared()
    {
        Thread? thread;
        BlockingCollection<Action<SteamSentinel.App.App>?>? queue;
        lock (SyncRoot)
        {
            thread = _staThread;
            queue = _workQueue;
            _staThread = null;
            _workQueue = null;
        }
        if (queue is null) return;
        try
        {
            queue.Add(null);
            queue.CompleteAdding();
        }
        catch { }
        thread?.Join(TimeSpan.FromSeconds(5));
        queue.Dispose();
    }

    private static BlockingCollection<Action<SteamSentinel.App.App>?> EnsureSharedStaQueue()
    {
        ManualResetEventSlim? ready = null;
        Exception? initFailure = null;
        BlockingCollection<Action<SteamSentinel.App.App>?> queue;
        lock (SyncRoot)
        {
            if (_workQueue is not null) return _workQueue;
            queue = [];
            _workQueue = queue;
            ready = new ManualResetEventSlim(false);
            _staThread = new Thread(() =>
            {
                SteamSentinel.App.App? app = null;
                try
                {
                    app = Create();
                    ready.Set();
                    foreach (Action<SteamSentinel.App.App>? workItem in queue.GetConsumingEnumerable())
                    {
                        if (workItem is null) break;
                        workItem(app);
                    }
                }
                catch (Exception ex)
                {
                    initFailure = ex;
                    ready.Set();
                }
                finally
                {
                    try { app?.Shutdown(); }
                    catch { }
                }
            })
            {
                IsBackground = true
            };
            _staThread.SetApartmentState(ApartmentState.STA);
            _staThread.Start();
        }
        ready.Wait();
        ready.Dispose();
        if (initFailure is not null)
        {
            ShutdownShared();
            ExceptionDispatchInfo.Capture(initFailure).Throw();
        }
        return queue;
    }
}
