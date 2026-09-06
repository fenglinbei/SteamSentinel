using System.Diagnostics;
using SteamSentinel.Core.Models;

namespace SteamSentinel.Core.Scanning;

public sealed class ContainerResourceBudget
{
    private readonly Stopwatch _watch = Stopwatch.StartNew();
    private readonly CancellationToken _token;
    private long _read, _decoded, _accepted, _rangeCopy, _temporary, _peakTemporary, _peakMemory, _metadata;
    private long _lastMemoryCheck;
    private long _nativeReserved;
    private long _nativeDecodedReserved;
    private int _attempts;
    public ContainerResourceLimits Limits { get; }
    public Action? Progress { get; set; }

    public ContainerResourceBudget(ContainerResourceLimits limits, CancellationToken token = default)
    {
        Validate(limits); Limits = limits; _token = token;
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
            throw new ArgumentOutOfRangeException(nameof(limits), "容器资源配置超出支持范围。");
    }

    public void Check()
    {
        _token.ThrowIfCancellationRequested();
        if (_watch.Elapsed.TotalSeconds >= Limits.MaximumDurationSeconds)
            throw new ScanResourceLimitException("容器处理达到时间上限；已保留完成的检查和未完成对象。");
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
        if (requested > 0 && remaining <= 0) throw new ScanResourceLimitException("读取与解码累计达到本轮预算，未继续读取内容。");
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
        if (bytes < 0 || bytes > Limits.MaximumWorkBytes - _read - _decoded - _nativeReserved - _nativeDecodedReserved)
            throw new ScanResourceLimitException("读取与解码累计达到本轮预算，未将未完成内容标为通过。");
    }
    public void AcceptExpansion(long bytes)
    {
        Check();
        if (bytes < 0 || bytes > Limits.MaximumExpandedBytes - _accepted)
            throw new ScanResourceLimitException("已接受成员的累计展开量达到上限。");
        _accepted = checked(_accepted + bytes);
    }
    public void RestoreLogicalExpansion(long checkpoint)
    {
        if (checkpoint < 0 || checkpoint > _accepted) throw new ArgumentOutOfRangeException(nameof(checkpoint));
        _accepted = checkpoint;
    }
    public long AcceptedExpandedBytes => _accepted;
    public long RemainingWorkBytes => Math.Max(0, Limits.MaximumWorkBytes - _read - _decoded - _nativeReserved - _nativeDecodedReserved);
    public void ChargeMetadata()
    {
        Check();
        if (++_metadata > Limits.MaximumMetadataAttempts) throw new ScanResourceLimitException("归档目录读取尝试达到本轮上限。");
    }
    public void ChargePasswordAttempt()
    {
        Check();
        if (++_attempts > Limits.MaximumPasswordAttempts) throw new ScanResourceLimitException("密码解码尝试达到本轮上限，已经发生的读取和解码消耗不会退还。");
    }
    public void ReserveTemporary(long bytes)
    {
        Check();
        if (bytes < 0 || bytes > Limits.MaximumTemporaryBytes - _temporary)
            throw new ScanResourceLimitException("临时内容占用达到上限，未继续展开。");
        _temporary = checked(_temporary + bytes); _peakTemporary = Math.Max(_peakTemporary, _temporary);
    }
    public void ReleaseTemporary(long bytes)
    {
        if (bytes < 0 || bytes > _temporary) throw new InvalidOperationException("临时空间计账不一致。");
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
        ElapsedMilliseconds = _watch.ElapsedMilliseconds
    };
}
