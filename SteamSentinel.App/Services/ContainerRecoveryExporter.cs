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
        MessageText temporarySnapshot = MessageText.Create("Backend.App.ContainerRecoveryExporter.CopyAsync.01");
        if (!containers.Checks.Contains(temporarySnapshot)) containers.AddCheck(temporarySnapshot);
        using RecoveryDirectoryLease source = RecoveryDirectoryLease.OpenExisting(sourceDirectory);
        using RecoveryDirectoryLease destination = RecoveryDirectoryLease.OpenExisting(destinationDirectory);
        if (nodes.Length > ContainerScanReport.MaximumNodes || nodes.Select(node => node.NodeId).Distinct().Count() != nodes.Length)
            throw MessageExceptions.Create(MessageText.Create("Backend.App.ContainerRecoveryExporter.CopyAsync.02"), sourceText => new InvalidDataException(sourceText));
        long expected = 0;
        foreach (ContainerScanNode node in nodes)
        {
            if (node.RecoveredContentName != node.NodeId.ToString("N") + ".scan" || node.Sha256 is not { Length: 64 } ||
                !node.Sha256.All(Uri.IsHexDigit) || node.Length < 0 || node.Length > containers.Limits.MaximumEntryBytes)
                throw MessageExceptions.Create(MessageText.Create("Backend.App.ContainerRecoveryExporter.CopyAsync.03"), sourceText => new InvalidDataException(sourceText));
            expected = checked(expected + node.Length);
        }
        if (expected > accounting.RemainingWorkBytes)
            throw MessageExceptions.Create(MessageText.Create("Backend.App.ContainerRecoveryExporter.CopyAsync.04"), sourceText => new ScanResourceLimitException(sourceText));
        if (expected > containers.Limits.MaximumTemporaryBytes ||
            new DriveInfo(Path.GetPathRoot(destination.Path)!).AvailableFreeSpace < checked(expected + containers.Limits.ReservedDiskBytes))
            throw MessageExceptions.Create(MessageText.Create("Backend.App.ContainerRecoveryExporter.CopyAsync.05"), sourceText => new IOException(sourceText));
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
                if (input.Length != node.Length) throw MessageExceptions.Create(MessageText.Create("Backend.App.ContainerRecoveryExporter.CopyAsync.06"), sourceText => new InvalidDataException(sourceText));
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
                            if (allowance <= 0) throw MessageExceptions.Create(MessageText.Create("Backend.App.ContainerRecoveryExporter.CopyAsync.07"), sourceText => new ScanResourceLimitException(sourceText));
                            int read = await input.ReadAsync(buffer.AsMemory(0, allowance), token); if (read == 0) break;
                            // Charge bytes actually returned even when hash, disk or writes
                            // subsequently fail. RangeCopyBytes describes this copy attempt.
                            accounting.ChargeRead(read);
                            copied = checked(copied + read); if (copied > node.Length) throw MessageExceptions.Create(MessageText.Create("Backend.App.ContainerRecoveryExporter.CopyAsync.08"), sourceText => new InvalidDataException(sourceText));
                            if (new DriveInfo(Path.GetPathRoot(destination.Path)!).AvailableFreeSpace < checked(containers.Limits.ReservedDiskBytes + read))
                                throw MessageExceptions.Create(MessageText.Create("Backend.App.ContainerRecoveryExporter.CopyAsync.09"), sourceText => new IOException(sourceText));
                            hash.AppendData(buffer, 0, read); await output.Stream.WriteAsync(buffer.AsMemory(0, read), token);
                        }
                        if (copied != node.Length || !Convert.ToHexString(hash.GetHashAndReset()).Equals(node.Sha256, StringComparison.OrdinalIgnoreCase))
                            throw MessageExceptions.Create(MessageText.Create("Backend.App.ContainerRecoveryExporter.CopyAsync.10"), sourceText => new InvalidDataException(sourceText));
                    }
                    finally { ArrayPool<byte>.Shared.Return(buffer, clearArray: true); }
                    await output.CommitAsync(token); delivered.Add(node.NodeId);
                }
            }
            containers.AddCheck(MessageText.Create("Backend.App.ContainerRecoveryExporter.CopyAsync.11", (delivered.Count)));
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
                Description = MessageText.Create("Backend.App.ContainerRecoveryExporter.CopyAsync.12").OriginalText,
                DescriptionMessage = MessageText.Create("Backend.App.ContainerRecoveryExporter.CopyAsync.12").Message,
                DeliveredFiles = delivered.Count,
                Nodes = containers.Nodes,
                containers.Limits,
                containers.Resources,
                containers.Checks,
                containers.CheckMessages
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
                throw MessageExceptions.Create(MessageText.Create("Backend.App.ContainerRecoveryExporter.Constructor.01"), sourceText => new InvalidDataException(sourceText));
            _workerWork = checked(_worker.ReadBytes + _worker.DecodedBytes + _worker.NativeReservedReadBytes + _worker.NativeReservedDecodedBytes);
            if (_workerWork > containers.Limits.MaximumWorkBytes)
                throw MessageExceptions.Create(MessageText.Create("Backend.App.ContainerRecoveryExporter.Constructor.02"), sourceText => new ScanResourceLimitException(sourceText));
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
