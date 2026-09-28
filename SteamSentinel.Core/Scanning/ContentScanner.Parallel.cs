using System.Diagnostics;
using System.Runtime.ExceptionServices;
using System.Text.Json;
using SteamSentinel.Core.Inspection;
using SteamSentinel.Core.Models;

namespace SteamSentinel.Core.Scanning;

public sealed partial class ContentScanner
{
    private PreparedLeaf? _preparedLeaf;
    private int _slowDiskBatches;
    private long _lastParallelCapacity;
    private int _parallelCapacity = 1;
    private readonly List<(ContentScanner Scanner, ScanOptions Options)> _leafWorkers = [];
    private string? _leafOptions;
    private sealed class PreparedLeaf(string path, FileStream stream) : IDisposable
    {
        public string Path { get; } = path;
        public FileStream Stream { get; } = stream;
        public FileTypeResult? Type { get; set; }
        public long Length => Stream.Length;
        public void Dispose() => Stream.Dispose();
    }

    private static bool ParallelExtension(string path) => Path.GetExtension(path).ToLowerInvariant() is
        ".txt" or ".md" or ".log" or ".lo" or ".json" or ".xml" or ".html" or ".htm" or
        ".js" or ".ps1" or ".bat" or ".cmd" or ".vbs" or ".lua" or ".py" or ".css" or ".ini";
    private static bool ParallelType(FileTypeResult type) => type.Type is DetectedFileType.Unknown or
        DetectedFileType.Empty or DetectedFileType.Json or DetectedFileType.Xml or DetectedFileType.Html or
        DetectedFileType.JavaScript or DetectedFileType.PowerShell or DetectedFileType.Batch;

    private int FileParallelism(ScanOptions options)
    {
        if (options.MaximumParallelFiles <= 1 || options.RecoveryOutputDirectory is not null) return 1;
        if (_slowDiskBatches > 0) { _slowDiskBatches--; return 1; }
        long now = Environment.TickCount64;
        if (now - _lastParallelCapacity < 500) return _parallelCapacity;
        _lastParallelCapacity = now;
        ScanMachineResources machine = ScanResourcePlanner.Capture(System.IO.Path.GetTempPath());
        int count = Math.Min(options.MaximumParallelFiles, ScanResourcePlanner.ParallelFiles(machine, options.PerformanceMode));
        using Process process = Process.GetCurrentProcess();
        long headroom = options.MaximumWorkerMemoryBytes / 4 * 3 - process.PrivateMemorySize64;
        int slots = Math.Max(1, Math.Min(count, (int)Math.Clamp(headroom / (128L * 1024 * 1024), 0, 4)));
        return _parallelCapacity = slots >= 4 ? 4 : slots >= 2 ? 2 : 1;
    }

    // Only bounded, recognized leaf files run together. Archives, native parsers,
    // volume/password groups and large files stay on the resumable serial path.
    private async Task<bool> TryScanParallelLeavesAsync(string[] paths, ScanReport report, ScanOptions options,
        IArchivePasswordProvider passwords, IProgress<ScanProgress>? progress, CancellationToken token,
        string? workshopId, string? projectType)
    {
        if (paths.Length < 2 || FileParallelism(options) < paths.Length || paths.Any(path => !ParallelExtension(path))) return false;
        ContainerResourceBudget ledger = ContainerBudget(report, options, token);
        if (paths.Length > options.MaximumFiles - report.Metrics.FilesVisited ||
            paths.Length > ledger.Limits.MaximumNodes - report.Containers!.Nodes.Count ||
            paths.Length * 16 > options.MaximumReportRecords - report.Findings.Count) return false;
        List<PreparedLeaf> prepared = [];
        bool preparedSuccessfully = false;
        Stopwatch preparation = Stopwatch.StartNew();
        try
        {
            foreach (string path in paths)
            {
                token.ThrowIfCancellationRequested();
                FileStream? file = null;
                try
                {
                    file = RelatedArtifactReader.Open(path);
                    if (file.Length > 8L * 1024 * 1024) { file.Dispose(); return false; }
                    prepared.Add(new(path, file)); file = null;
                }
                finally { file?.Dispose(); }
            }
            long total = prepared.Sum(item => item.Length);
            long charged = report.Metrics.BytesHashed - (options.Mode == ScanMode.Quick ? report.Metrics.QuickPriorityBytesHashed : 0);
            // Reserve enough headroom before reading ahead. Near any shared quota,
            // use serial order so speculative recognition cannot consume another
            // file's remaining work/hash allowance.
            if (checked(total * 4) > ledger.RemainingWorkBytes || total > options.MaximumContentBytes - charged) return false;
            bool recognized = true;
            foreach (PreparedLeaf item in prepared)
            {
                using BoundedReadOnlyStream view = new(item.Stream, 0, item.Length, budget: ledger);
                item.Type = await FileTypeDetector.DetectAsync(view, item.Path, token);
                if (!ParallelType(item.Type)) { recognized = false; break; }
            }
            preparedSuccessfully = true;
            bool eligible = recognized && prepared.All(item => item.Length <= options.MaximumStringScanBytes &&
                (!ScanEnhancements.UseAmsi(options) || item.Length <= options.MaximumAmsiBytes) &&
                (options.Mode != ScanMode.Quick || item.Length <= options.MaximumQuickFileBytes)) &&
                total <= options.MaximumContentBytes - charged;
            long reserved = checked(prepared.Sum(item => Math.Max(1, item.Length * 3)));
            if (!eligible || !ledger.TryReserveParallelWork(reserved))
            {
                // Classification used the held source handle. Reuse it on fallback;
                // do not reread or substitute a file between detection and scanning.
                foreach (PreparedLeaf item in prepared)
                {
                    _preparedLeaf = item;
                    try { await ScanFileAsync(item.Path, item.Path, item.Path, report, options, passwords, progress, token, 0, workshopId, projectType, GetArchiveBudget(report)); }
                    finally { _preparedLeaf = null; }
                    Checkpoint?.Invoke(report);
                }
                return true;
            }
            if (preparation.ElapsedMilliseconds / paths.Length > 40) _slowDiskBatches = 16;
            report.ResourceAudit ??= new() { Preflight = ScanResourcePlanner.Capture(System.IO.Path.GetTempPath()) };
            string serializedOptions = JsonSerializer.Serialize(options);
            if (_leafOptions != serializedOptions)
            {
                foreach (var worker in _leafWorkers) worker.Scanner.Dispose();
                _leafWorkers.Clear(); _leafOptions = serializedOptions;
            }
            while (_leafWorkers.Count < paths.Length)
            {
                ScanOptions settings = JsonSerializer.Deserialize<ScanOptions>(serializedOptions)!;
                typeof(ScanOptions).GetProperty(nameof(ScanOptions.AllowResourceDecisions))!.SetValue(settings, false);
                typeof(ScanOptions).GetProperty(nameof(ScanOptions.MaximumParallelFiles))!.SetValue(settings, 1);
                ContainerResourceLimits taskLimits = JsonSerializer.Deserialize<ContainerResourceLimits>(JsonSerializer.Serialize(ledger.Limits))!;
                typeof(ScanOptions).GetProperty(nameof(ScanOptions.ContainerLimits))!.SetValue(settings, taskLimits);
                _leafWorkers.Add((new(_rules, _amsiFactory), settings));
            }
            List<Task<(ContentScanner Scanner, ScanReport Report, Exception? Error, long Reservation)>> tasks = [];
            int activeTasks = 0, peakTasks = 0;
            for (int index = 0; index < prepared.Count; index++)
            {
                PreparedLeaf item = prepared[index];
                var worker = _leafWorkers[index];
                long slice = Math.Max(1, item.Length * 3);
                tasks.Add(Task.Run(async () =>
                {
                    int active = Interlocked.Increment(ref activeTasks);
                    int observed;
                    do { observed = Volatile.Read(ref peakTasks); }
                    while (active > observed && Interlocked.CompareExchange(ref peakTasks, active, observed) != observed);
                    using IDisposable suppressed = ScanResourceSession.Suppress();
                    ScanOptions settings = worker.Options;
                    typeof(ContainerResourceLimits).GetProperty(nameof(ContainerResourceLimits.MaximumWorkBytes))!.SetValue(settings.ContainerLimits, slice);
                    ScanReport part = new() { Mode = options.Mode, ContentScanSettings = ScanEnhancements.ForExecution(settings) };
                    ContentScanner scanner = worker.Scanner;
                    scanner._coverageRoot = _coverageRoot; scanner._preparedLeaf = item;
                    Exception? error = null;
                    try { await scanner.ScanFileAsync(item.Path, item.Path, item.Path, part, settings, passwords, null, token, 0, workshopId, projectType, scanner.GetArchiveBudget(part)); }
                    catch (Exception exception) { error = exception; }
                    finally { Interlocked.Decrement(ref activeTasks); }
                    return (scanner, part, error, slice);
                }, CancellationToken.None));
            }
            var results = await Task.WhenAll(tasks);
            report.ResourceAudit.PeakParallelFiles = Math.Max(report.ResourceAudit.PeakParallelFiles, peakTasks);
            Exception? firstError = null;
            foreach (var result in results)
            {
                try
                {
                    ledger.SettleParallelWork(result.Reservation, result.Report.Containers?.Resources);
                    MergeLeafResult(report, result.Report, result.Scanner);
                    firstError ??= result.Error;
                }
                finally { result.Scanner._preparedLeaf = null; }
            }
            report.Containers.Resources = ledger.Snapshot();
            report.Containers.Complete = _unfinishedContainers.Count == 0;
            _resources.Check(report); Checkpoint?.Invoke(report);
            if (firstError is not null) ExceptionDispatchInfo.Capture(firstError).Throw();
            return true;
        }
        catch (Exception ex) when (!preparedSuccessfully && ex is IOException or UnauthorizedAccessException)
        { return false; }
        finally { foreach (PreparedLeaf item in prepared) item.Dispose(); }
    }

    private void MergeLeafResult(ScanReport report, ScanReport part, ContentScanner scanner)
    {
        if (part.Coverage != ScanCoverage.Complete) report.Coverage = ScanCoverage.Partial;
        report.Findings.AddRange(part.Findings);
        foreach (var note in part.CoverageTexts) report.AddCoverageNote(note);
        report.CoverageNotices.AddRange(part.CoverageNotices.Where(n => n.ReasonCode != ReasonCodes.AmsiUnavailable));
        report.CoverageAggregates.AddRange(part.CoverageAggregates);
        report.Metrics.FilesVisited += part.Metrics.FilesVisited;
        report.Metrics.BytesHashed += part.Metrics.BytesHashed;
        report.Metrics.QuickPriorityBytesHashed += part.Metrics.QuickPriorityBytesHashed;
        if (scanner._amsiUnavailableCounts.GetValueOrDefault(part.ScanId) > 0)
            foreach (ContainerEngineObservation engine in part.Containers!.Nodes.SelectMany(n => n.Engines).Where(e => e.Engine == "AMSI" && e.Status == ContainerStageStatus.Failed))
                AddAmsiCoverage(report, engine.DetailText);
        if (part.Containers is null) return;
        foreach (ContainerScanNode node in part.Containers.Nodes) { report.Containers!.Nodes.Add(node); IndexContainer(node); }
    }
}
