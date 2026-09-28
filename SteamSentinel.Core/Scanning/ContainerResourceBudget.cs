using SteamSentinel.Core.Reporting;
using System.Diagnostics;
using SteamSentinel.Core.Models;

namespace SteamSentinel.Core.Scanning;

public sealed class ContainerResourceBudget
{
    private readonly Stopwatch _watch = Stopwatch.StartNew();
    private readonly CancellationToken _token;
    private readonly ScanResourceSession? _resourceSession = ScanResourceSession.Current;
    private long _read, _decoded, _accepted, _rangeCopy, _temporary, _peakTemporary, _peakMemory, _metadata;
    private long _lastMemoryCheck;
    private long _nativeReserved;
    private long _nativeDecodedReserved;
    private long _parallelReserved;
    private int _attempts;
    private readonly long _initialWait = ScanResourceSession.Current?.WaitingMilliseconds ?? 0;
    private long ActiveMilliseconds => Math.Max(0, _watch.ElapsedMilliseconds - ((ScanResourceSession.Current?.WaitingMilliseconds ?? 0) - _initialWait));
    public ContainerResourceLimits Limits { get; }
    public long EffectiveDiskReserve => _resourceSession?.RaisedResources == true ? Math.Max(1024L * 1024 * 1024, Limits.ReservedDiskBytes) : Limits.ReservedDiskBytes;
    public Action? Progress { get; set; }

    public ContainerResourceBudget(ContainerResourceLimits limits, CancellationToken token = default)
    {
        Validate(limits); Limits = limits; _token = token;
        ScanResourceSession.Current?.ObserveResources(Snapshot);
    }

    public static void Validate(ContainerResourceLimits limits)
    {
        ArgumentNullException.ThrowIfNull(limits);
        // Leave room for the final partial read in report accounting. Other ceilings are
        // representation/timer limits, not product policy limits.
        const long maximumBytes = long.MaxValue - 1048576;
        if (limits.MaximumEntryBytes is < 1 or > maximumBytes || limits.MaximumExpandedBytes is < 1 or > maximumBytes ||
            limits.MaximumWorkBytes is < 1 or > maximumBytes || limits.MaximumTemporaryBytes is < 1 or > maximumBytes ||
            limits.ReservedDiskBytes is < 0 or > maximumBytes || limits.MaximumDepth is < 1 or >= int.MaxValue ||
            limits.MaximumEntries is < 1 or >= int.MaxValue || limits.MaximumMetadataAttempts is < 1 or >= int.MaxValue ||
            limits.MaximumNodes is < 1 or > ContainerScanReport.MaximumNodes ||
            limits.MaximumPasswordAttempts is < 1 or >= int.MaxValue || limits.MaximumVolumes is < 1 or >= int.MaxValue ||
            limits.MaximumDirectoryCandidates is < 1 or >= int.MaxValue || limits.MaximumDurationSeconds is < 1 or > 4294960 ||
            !double.IsFinite(limits.MaximumCompressionRatio) || limits.MaximumCompressionRatio < 1)
            throw MessageExceptions.Create(MessageText.Create("Backend.Core.ContainerResourceBudget.Validate.01"), sourceText => new ArgumentOutOfRangeException(nameof(limits), sourceText));
    }

    public void Check()
    {
        _token.ThrowIfCancellationRequested();
        if (ActiveMilliseconds / 1000d >= Limits.MaximumDurationSeconds &&
            !ScanResourceSession.Allow("ContainerLimits.MaximumDurationSeconds", checked(Limits.MaximumDurationSeconds + 1L), ActiveMilliseconds / 1000, known: false))
            throw MessageExceptions.Create(MessageText.Create("Backend.Core.ContainerResourceBudget.Check.01"), sourceText => new ScanResourceLimitException(sourceText));
        if (_watch.ElapsedMilliseconds - _lastMemoryCheck >= 500)
        {
            _lastMemoryCheck = _watch.ElapsedMilliseconds;
            using Process process = Process.GetCurrentProcess();
            _peakMemory = Math.Max(_peakMemory, process.PrivateMemorySize64);
        }
        Progress?.Invoke();
    }

    public int ReadAllowance(int requested)
    {
        Check();
        if (requested < 0) throw new ArgumentOutOfRangeException(nameof(requested));
        if (requested == 0) return 0;
        long remaining = RemainingWorkBytes;
        if (remaining <= 0 && ScanResourceSession.Allow("ContainerLimits.MaximumWorkBytes", checked(Limits.MaximumWorkBytes + requested), Limits.MaximumWorkBytes, known: false))
            remaining = RemainingWorkBytes;
        if (requested > 0 && remaining <= 0) throw MessageExceptions.Create(MessageText.Create("Backend.Core.ContainerResourceBudget.ReadAllowance.01"), sourceText => new ScanResourceLimitException(sourceText));
        return (int)Math.Min(requested, remaining);
    }

    public void ChargeRead(long bytes)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(bytes); _read = checked(_read + bytes); EnsureWork(0);
    }
    public void ChargeDecoded(long bytes)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(bytes); _decoded = checked(_decoded + bytes); EnsureWork(0);
    }
    public void ReserveNativeRead(long bytes) { EnsureWork(bytes); _nativeReserved = checked(_nativeReserved + bytes); }
    public void ReserveNativeDecoded(long bytes) { EnsureWork(bytes); _nativeDecodedReserved = checked(_nativeDecodedReserved + bytes); }
    public void ChargeRangeCopy(long bytes)
    {
        if (bytes < 0) throw new ArgumentOutOfRangeException(nameof(bytes));
        _rangeCopy = checked(_rangeCopy + bytes);
    }
    private void EnsureWork(long bytes)
    {
        Check();
        long used = checked(_read + _decoded + _nativeReserved + _nativeDecodedReserved);
        if (bytes < 0 || bytes > Limits.MaximumWorkBytes - used &&
            !ScanResourceSession.Allow("ContainerLimits.MaximumWorkBytes", checked(used + bytes), used, known: false))
            throw MessageExceptions.Create(MessageText.Create("Backend.Core.ContainerResourceBudget.EnsureWork.01"), sourceText => new ScanResourceLimitException(sourceText));
    }
    public void AcceptExpansion(long bytes)
    {
        Check();
        if (bytes < 0 || bytes > Limits.MaximumExpandedBytes - _accepted &&
            !ScanResourceSession.Allow("ContainerLimits.MaximumExpandedBytes", checked(_accepted + bytes), _accepted, known: false))
            throw MessageExceptions.Create(MessageText.Create("Backend.Core.ContainerResourceBudget.AcceptExpansion.01"), sourceText => new ScanResourceLimitException(sourceText));
        _accepted = checked(_accepted + bytes);
    }
    public void RestoreLogicalExpansion(long checkpoint)
    {
        if (checkpoint < 0 || checkpoint > _accepted) throw new ArgumentOutOfRangeException(nameof(checkpoint));
        _accepted = checkpoint;
    }
    public long AcceptedExpandedBytes => _accepted;
    public long RemainingWorkBytes => Math.Max(0, Limits.MaximumWorkBytes - _read - _decoded - _nativeReserved - _nativeDecodedReserved - _parallelReserved);
    // The dispatcher owns these reservations. Tasks receive disjoint slices and never
    // mutate this ledger; settlement happens after all tasks have stopped.
    internal bool TryReserveParallelWork(long bytes)
    {
        Check();
        if (bytes < 0 || bytes > RemainingWorkBytes) return false;
        _parallelReserved = checked(_parallelReserved + bytes); return true;
    }
    internal void SettleParallelWork(long reserved, ContainerResourceSnapshot? actual)
    {
        if (reserved < 0 || reserved > _parallelReserved) throw new InvalidDataException("Invalid parallel reservation.");
        long read = actual?.ReadBytes ?? 0, decoded = actual?.DecodedBytes ?? 0;
        if (read < 0 || decoded != 0 || read > reserved || actual is { AcceptedExpandedBytes: not 0 } or
            { NativeReservedReadBytes: not 0 } or { NativeReservedDecodedBytes: not 0 } or { CurrentTemporaryBytes: not 0 })
            throw new InvalidDataException("A leaf task exceeded its reserved scope.");
        _read = checked(_read + read); _parallelReserved -= reserved;
        _peakMemory = Math.Max(_peakMemory, actual?.PeakPrivateMemoryBytes ?? 0);
    }
    public void ChargeMetadata()
    {
        Check();
        if (++_metadata > Limits.MaximumMetadataAttempts && !ScanResourceSession.Allow("ContainerLimits.MaximumMetadataAttempts", _metadata, _metadata - 1, known: false))
            throw MessageExceptions.Create(MessageText.Create("Backend.Core.ContainerResourceBudget.ChargeMetadata.01"), sourceText => new ScanResourceLimitException(sourceText));
    }
    public void ChargePasswordAttempt()
    {
        Check();
        if (++_attempts > Limits.MaximumPasswordAttempts && !ScanResourceSession.Allow("ContainerLimits.MaximumPasswordAttempts", _attempts, _attempts - 1, known: false))
            throw MessageExceptions.Create(MessageText.Create("Backend.Core.ContainerResourceBudget.ChargePasswordAttempt.01"), sourceText => new ScanResourceLimitException(sourceText));
    }
    public void ReserveTemporary(long bytes)
    {
        Check();
        if (bytes < 0 || bytes > Limits.MaximumTemporaryBytes - _temporary &&
            !ScanResourceSession.Allow("ContainerLimits.MaximumTemporaryBytes", checked(_temporary + bytes), _temporary, known: false))
            throw MessageExceptions.Create(MessageText.Create("Backend.Core.ContainerResourceBudget.ReserveTemporary.01"), sourceText => new ScanResourceLimitException(sourceText));
        _temporary = checked(_temporary + bytes); _peakTemporary = Math.Max(_peakTemporary, _temporary);
    }
    public void ReleaseTemporary(long bytes)
    {
        if (bytes < 0 || bytes > _temporary) throw MessageExceptions.Create(MessageText.Create("Backend.Core.ContainerResourceBudget.ReleaseTemporary.01"), sourceText => new InvalidOperationException(sourceText));
        _temporary -= bytes;
    }
    public ContainerResourceSnapshot Snapshot() => new()
    {
        ReadBytes = _read,
        DecodedBytes = _decoded,
        AcceptedExpandedBytes = _accepted,
        RangeCopyBytes = _rangeCopy,
        NativeReservedReadBytes = _nativeReserved,
        NativeReservedDecodedBytes = _nativeDecodedReserved,
        CurrentTemporaryBytes = _temporary,
        PeakTemporaryBytes = _peakTemporary,
        PeakPrivateMemoryBytes = _peakMemory,
        MetadataAttempts = _metadata,
        PasswordAttempts = _attempts,
        ElapsedMilliseconds = ActiveMilliseconds
    };
}
