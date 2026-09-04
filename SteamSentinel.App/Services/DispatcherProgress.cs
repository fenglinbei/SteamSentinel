using System.Windows.Threading;

namespace SteamSentinel.App.Services;

// Always uses the window's dispatcher, never the context of the constructing thread.
// Coalesces bursts and drops queued updates when a phase ends or the window closes.
internal sealed class DispatcherProgress<T>(Dispatcher dispatcher, Action<T> handler,
    Func<bool> isActive, Action<Exception> onError) : IProgress<T>, IDisposable
{
    private readonly object _gate = new();
    private bool _disposed, _queued;
    private T? _latest;

    public void Report(T value)
    {
        lock (_gate)
        {
            if (_disposed || dispatcher.HasShutdownStarted || dispatcher.HasShutdownFinished) return;
            _latest = value;
            if (_queued) return;
            _queued = true;
        }
        try { dispatcher.BeginInvoke(DispatcherPriority.Background, new Action(Deliver)); }
        catch (InvalidOperationException) { Dispose(); }
    }

    private void Deliver()
    {
        T? value;
        lock (_gate)
        {
            if (_disposed) return;
            value = _latest;
            _latest = default;
            _queued = false;
        }
        try { if (isActive()) handler(value!); }
        catch (Exception ex)
        {
            Dispose();
            // Only a display callback is contained here, not scanning/remediation errors.
            try { onError(ex); } catch { /* Diagnostics must not crash a worker callback. */ }
        }
    }

    public void Dispose()
    {
        lock (_gate) { _disposed = true; _latest = default; }
    }
}
