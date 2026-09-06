using System.Buffers;
using System.Diagnostics;
using System.IO;
using System.Security.Cryptography;
using System.Text.Json;
using SteamSentinel.Core.Models;
using SteamSentinel.Core.Reporting;
using SteamSentinel.Core.Scanning;

namespace SteamSentinel.App.Services;

internal static class ContainerRecoveryExporter
{
    internal static async Task CopyAsync(ScanReport report, string sourceDirectory, string destinationDirectory, CancellationToken token)
    {
        ContainerScanReport? containers = report.Containers;
        if (containers is null) return;
        ContainerScanNode[] nodes = containers.Nodes.Where(node => node.RecoveredContentAvailable).ToArray();
        // Worker staging is not a delivery. Clear these claims before any validation or I/O
        // can fail; only successfully committed destination files regain availability.
        foreach (ContainerScanNode node in nodes) { node.RecoveredContentAvailable = false; node.Revision++; }
        containers.RecoveryOutputDirectory = null;
        ContainerResourceBudget.Validate(containers.Limits);
        using ExportResourceAccounting accounting = new(containers);
        const string temporarySnapshot = "当前临时占用保留 Worker 结束时的暂存快照；本轮工作区最终会清理，不能视为导出后的持续占用。";
        if (!containers.Checks.Contains(temporarySnapshot)) containers.Checks.Add(temporarySnapshot);
        using RecoveryDirectoryLease source = RecoveryDirectoryLease.OpenExisting(sourceDirectory);
        using RecoveryDirectoryLease destination = RecoveryDirectoryLease.OpenExisting(destinationDirectory);
        if (nodes.Length > ContainerScanReport.MaximumNodes || nodes.Select(node => node.NodeId).Distinct().Count() != nodes.Length)
            throw new InvalidDataException("恢复节点数量或标识无效。");
        long expected = 0;
        foreach (ContainerScanNode node in nodes)
        {
            if (node.RecoveredContentName != node.NodeId.ToString("N") + ".scan" || node.Sha256 is not { Length: 64 } ||
                !node.Sha256.All(Uri.IsHexDigit) || node.Length < 0 || node.Length > containers.Limits.MaximumEntryBytes)
                throw new InvalidDataException("恢复文件映射或内容身份无效。");
            expected = checked(expected + node.Length);
        }
        if (expected > accounting.RemainingWorkBytes)
            throw new ScanResourceLimitException("恢复导出的额外读取超过本轮剩余工作预算，尚未创建输出目录。");
        if (expected > containers.Limits.MaximumTemporaryBytes ||
            new DriveInfo(Path.GetPathRoot(destination.Path)!).AvailableFreeSpace < checked(expected + containers.Limits.ReservedDiskBytes))
            throw new IOException("恢复输出空间不足，尚未开始复制。");
        token.ThrowIfCancellationRequested();
        using RecoveryDirectoryLease outputRoot = destination.CreateDirectory($"SteamSentinel-recovered-{report.ScanId:N}-{Guid.NewGuid():N}");
        containers.RecoveryOutputDirectory = outputRoot.Path;
        HashSet<Guid> delivered = [];
        try
        {
            foreach (ContainerScanNode node in nodes)
            {
                token.ThrowIfCancellationRequested();
                await using FileStream input = source.OpenRead(node.RecoveredContentName!);
                if (input.Length != node.Length) throw new InvalidDataException("恢复文件长度与报告不一致。");
                await using (RecoveryWriteFile output = outputRoot.CreateFile(node.RecoveredContentName!))
                {
                    using IncrementalHash hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
                    byte[] buffer = ArrayPool<byte>.Shared.Rent(128 * 1024);
                    try
                    {
                        long copied = 0;
                        while (copied < node.Length)
                        {
                            int allowance = (int)Math.Min(buffer.Length, Math.Min(node.Length - copied, accounting.RemainingWorkBytes));
                            if (allowance <= 0) throw new ScanResourceLimitException("恢复导出达到本轮工作预算，未继续读取内容。");
                            int read = await input.ReadAsync(buffer.AsMemory(0, allowance), token); if (read == 0) break;
                            // Charge bytes actually returned even when hash, disk or writes
                            // subsequently fail. RangeCopyBytes describes this copy attempt.
                            accounting.ChargeRead(read);
                            copied = checked(copied + read); if (copied > node.Length) throw new InvalidDataException("恢复文件增长。");
                            if (new DriveInfo(Path.GetPathRoot(destination.Path)!).AvailableFreeSpace < checked(containers.Limits.ReservedDiskBytes + read))
                                throw new IOException("恢复复制期间可用空间低于磁盘保留量，已停止保存。");
                            hash.AppendData(buffer, 0, read); await output.Stream.WriteAsync(buffer.AsMemory(0, read), token);
                        }
                        if (copied != node.Length || !Convert.ToHexString(hash.GetHashAndReset()).Equals(node.Sha256, StringComparison.OrdinalIgnoreCase))
                            throw new InvalidDataException("恢复文件 SHA-256 与检查结果不一致。");
                    }
                    finally { ArrayPool<byte>.Shared.Return(buffer, clearArray: true); }
                    await output.CommitAsync(token); delivered.Add(node.NodeId);
                }
            }
            containers.Checks.Add($"用户主动恢复导出：已交付 {delivered.Count} 个 .scan 文件；常规报告导出不附样本。");
        }
        finally
        {
            foreach (ContainerScanNode node in nodes)
            {
                node.RecoveredContentAvailable = delivered.Contains(node.NodeId);
                if (!node.RecoveredContentAvailable) node.RecoveredContentName = null;
                node.Revision++;
            }
            accounting.UpdateSnapshot();
            await using RecoveryWriteFile evidence = outputRoot.CreateFile("evidence.json");
            await JsonSerializer.SerializeAsync(evidence.Stream, new
            {
                SchemaVersion = 1,
                report.ScanId,
                report.BuildIdentity,
                CreatedAtUtc = DateTimeOffset.UtcNow,
                Description = "非可执行名称的已校验内容。文件名映射、每层 SHA-256、父层相对偏移与各检查阶段见 Nodes；未保存密码。",
                DeliveredFiles = delivered.Count,
                Nodes = containers.Nodes,
                containers.Limits,
                containers.Resources,
                containers.Checks
            }, ReportPrivacy.ExportOptions, CancellationToken.None);
            await evidence.CommitAsync(CancellationToken.None);
        }
    }

    private sealed class ExportResourceAccounting : IDisposable
    {
        private readonly ContainerScanReport _containers;
        private readonly ContainerResourceSnapshot _worker;
        private readonly Stopwatch _elapsed = Stopwatch.StartNew();
        private readonly long _workerWork;
        private long _read;

        internal ExportResourceAccounting(ContainerScanReport containers)
        {
            _containers = containers; _worker = containers.Resources;
            if (_worker.ReadBytes < 0 || _worker.DecodedBytes < 0 || _worker.NativeReservedReadBytes < 0 ||
                _worker.NativeReservedDecodedBytes < 0 || _worker.RangeCopyBytes < 0 || _worker.ElapsedMilliseconds < 0)
                throw new InvalidDataException("Worker 资源快照包含无效计量。");
            _workerWork = checked(_worker.ReadBytes + _worker.DecodedBytes + _worker.NativeReservedReadBytes + _worker.NativeReservedDecodedBytes);
            if (_workerWork > containers.Limits.MaximumWorkBytes)
                throw new ScanResourceLimitException("本轮已消耗的工作预算超过上限，尚未开始恢复导出。");
        }

        internal long RemainingWorkBytes => _containers.Limits.MaximumWorkBytes - _workerWork - _read;

        internal void ChargeRead(int bytes)
        {
            _read = checked(_read + bytes);
            UpdateSnapshot();
        }

        internal void UpdateSnapshot() => _containers.Resources = new()
        {
            ReadBytes = checked(_worker.ReadBytes + _read),
            DecodedBytes = _worker.DecodedBytes,
            AcceptedExpandedBytes = _worker.AcceptedExpandedBytes,
            RangeCopyBytes = checked(_worker.RangeCopyBytes + _read),
            NativeReservedReadBytes = _worker.NativeReservedReadBytes,
            NativeReservedDecodedBytes = _worker.NativeReservedDecodedBytes,
            CurrentTemporaryBytes = _worker.CurrentTemporaryBytes,
            PeakTemporaryBytes = _worker.PeakTemporaryBytes,
            PeakPrivateMemoryBytes = _worker.PeakPrivateMemoryBytes,
            MetadataAttempts = _worker.MetadataAttempts,
            PasswordAttempts = _worker.PasswordAttempts,
            ElapsedMilliseconds = checked(_worker.ElapsedMilliseconds + _elapsed.ElapsedMilliseconds)
        };

        public void Dispose() => UpdateSnapshot();
    }
}
