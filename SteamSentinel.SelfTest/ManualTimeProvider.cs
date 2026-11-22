namespace SteamSentinel.SelfTest;

/// <summary>线程安全的可控虚拟时钟，用于替代真实长等待并确定性推进超时与计时器。</summary>
internal sealed class ManualTimeProvider : TimeProvider
{
    private readonly object _lock = new();
    private readonly object _advanceLock = new();
    private readonly List<ManualTimer> _timers = [];
    private DateTimeOffset _utcNow;
    private long _timestamp;
    private long _nextSequence;

    internal ManualTimeProvider(DateTimeOffset? startUtcNow = null)
    {
        _utcNow = (startUtcNow ?? DateTimeOffset.UtcNow).ToUniversalTime();
        _timestamp = TimeSpan.TicksPerSecond;
    }

    public override long TimestampFrequency => TimeSpan.TicksPerSecond;

    public override DateTimeOffset GetUtcNow()
    {
        lock (_lock)
        {
            return _utcNow;
        }
    }

    public override long GetTimestamp()
    {
        lock (_lock)
        {
            return _timestamp;
        }
    }

    public override ITimer CreateTimer(TimerCallback callback, object? state, TimeSpan dueTime, TimeSpan period)
    {
        ArgumentNullException.ThrowIfNull(callback);
        ValidateTimeout(dueTime, nameof(dueTime));
        ValidateTimeout(period, nameof(period));

        lock (_lock)
        {
            ManualTimer timer = new(this, callback, state);
            _timers.Add(timer);
            timer.ScheduleLocked(dueTime, period);
            return timer;
        }
    }

    /// <summary>按到期时间戳先后逐段推进虚拟时钟，并在锁外同步执行到期计时器回调。</summary>
    internal void Advance(TimeSpan delta)
    {
        if (delta < TimeSpan.Zero)
            throw new ArgumentOutOfRangeException(nameof(delta));

        lock (_advanceLock)
        {
            long targetTimestamp;
            lock (_lock)
            {
                long deltaTicks = delta.Ticks;
                targetTimestamp = deltaTicks > long.MaxValue - _timestamp
                    ? long.MaxValue
                    : _timestamp + deltaTicks;
            }

            while (true)
            {
                ManualTimer? nextTimer = null;
                TimerCallback? callback = null;
                object? state = null;

                lock (_lock)
                {
                    foreach (ManualTimer timer in _timers)
                    {
                        if (timer.Disposed || !timer.IsScheduled || timer.DueTimestamp > targetTimestamp)
                            continue;

                        if (nextTimer is null ||
                            timer.DueTimestamp < nextTimer.DueTimestamp ||
                            (timer.DueTimestamp == nextTimer.DueTimestamp && timer.Sequence < nextTimer.Sequence))
                        {
                            nextTimer = timer;
                        }
                    }

                    if (nextTimer is null)
                    {
                        AdvanceClockToLocked(targetTimestamp);
                        break;
                    }

                    AdvanceClockToLocked(nextTimer.DueTimestamp);
                    callback = nextTimer.Callback;
                    state = nextTimer.State;
                    nextTimer.ConsumeOrRescheduleLocked();
                }

                // 在锁外执行回调，避免回调内部再操作计时器、时钟或链接令牌时造成死锁。
                callback(state);
            }
        }
    }

    private void AdvanceClockToLocked(long targetTimestamp)
    {
        if (targetTimestamp > _timestamp)
        {
            long advanceTicks = targetTimestamp - _timestamp;
            _timestamp = targetTimestamp;
            _utcNow = _utcNow.AddTicks(advanceTicks);
        }
    }

    private static void ValidateTimeout(TimeSpan value, string parameterName)
    {
        if (value != Timeout.InfiniteTimeSpan && value < TimeSpan.Zero)
            throw new ArgumentOutOfRangeException(parameterName);
    }

    private sealed class ManualTimer(ManualTimeProvider provider, TimerCallback callback, object? state) : ITimer
    {
        public TimerCallback Callback { get; } = callback;
        public object? State { get; } = state;
        public bool Disposed { get; private set; }
        public bool IsScheduled { get; private set; }
        public long DueTimestamp { get; private set; }
        public long PeriodTicks { get; private set; } = -1;
        public long Sequence { get; private set; }

        public bool Change(TimeSpan dueTime, TimeSpan period)
        {
            ValidateTimeout(dueTime, nameof(dueTime));
            ValidateTimeout(period, nameof(period));

            lock (provider._lock)
            {
                if (Disposed) return false;
                ScheduleLocked(dueTime, period);
                return true;
            }
        }

        public void ScheduleLocked(TimeSpan dueTime, TimeSpan period)
        {
            // 与 System.Threading.Timer 语义一致：period 为 Infinite 或 Zero 时均为单次触发。
            PeriodTicks = period == Timeout.InfiniteTimeSpan || period == TimeSpan.Zero ? -1L : period.Ticks;
            if (dueTime == Timeout.InfiniteTimeSpan)
            {
                IsScheduled = false;
                DueTimestamp = 0;
                return;
            }

            long dueTicks = dueTime.Ticks;
            DueTimestamp = dueTicks > long.MaxValue - provider._timestamp
                ? long.MaxValue
                : provider._timestamp + dueTicks;
            Sequence = ++provider._nextSequence;
            IsScheduled = true;
        }

        public void ConsumeOrRescheduleLocked()
        {
            if (PeriodTicks > 0)
            {
                DueTimestamp = PeriodTicks > long.MaxValue - provider._timestamp
                    ? long.MaxValue
                    : provider._timestamp + PeriodTicks;
                Sequence = ++provider._nextSequence;
                IsScheduled = true;
            }
            else
            {
                IsScheduled = false;
            }
        }

        public void Dispose()
        {
            lock (provider._lock)
            {
                if (Disposed) return;
                Disposed = true;
                IsScheduled = false;
                provider._timers.Remove(this);
            }
        }

        public ValueTask DisposeAsync()
        {
            Dispose();
            return ValueTask.CompletedTask;
        }
    }
}
