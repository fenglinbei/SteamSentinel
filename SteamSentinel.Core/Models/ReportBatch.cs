using System.Diagnostics;
using SteamSentinel.Core.Scanning;

namespace SteamSentinel.Core.Models;

public sealed record WorkerDiagnostics(string Stage, string LastPath, string Operation,
    long PrivateBytes, long PeakPrivateBytes, long ManagedBytes, DateTimeOffset CapturedAtUtc,
    string? FailureType = null, string? FailureStack = null, string? LauncherIntegrity = null)
{
    public static WorkerDiagnostics Capture(ScanProgress? progress, Exception? error = null)
    {
        using Process process = Process.GetCurrentProcess();
        string? stack = error?.StackTrace;
        return new(progress?.Stage ?? "准备内容检查", progress?.CurrentItem ?? "", progress?.Message ?? "",
            process.PrivateMemorySize64, process.PeakPagedMemorySize64, GC.GetTotalMemory(false), DateTimeOffset.UtcNow,
            error?.GetType().Name, stack?[..Math.Min(stack.Length, 2048)]);
    }
}

public sealed record ReportOffsets(int Findings, int Notes, int Roots, int Sources, int Summaries, int Candidates, int Scope);
public sealed record ReportBatch(int Sequence, ReportOffsets Offsets, ScanReport Data)
{
    // Indexed replacements, not append-only offsets: a group's count changes after it was sent.
    public List<CoverageAggregateUpdate> CoverageUpdates { get; init; } = [];
}

/// <summary>Append-only findings are sent only after an outer file's hash binding is finalized.</summary>
public sealed class ReportBatchWriter(Action<ReportBatch> send)
{
    public const int BatchSize = 64;
    private int _findings, _notes, _roots, _sources, _summaries, _candidates, _scope;
    private readonly List<CoverageAggregate> _aggregates = [];
    public int Count { get; private set; }

    public void Send(ScanReport report, bool final = false)
    {
        // AMSI availability notes can be updated in place. Replay these bounded lists at completion.
        if (final) _notes = 0;
        List<CoverageAggregateUpdate> changes = [];
        for (int i = 0; i < report.CoverageAggregates.Count; i++)
            if (i >= _aggregates.Count || !ReferenceEquals(_aggregates[i], report.CoverageAggregates[i]))
                changes.Add(new(i, report.CoverageAggregates[i]));
        int changed = 0;
        do
        {
            ReportOffsets offsets = new(_findings, _notes, _roots, _sources, _summaries, _candidates, _scope);
            ScanReport data = new()
            {
                ProductVersion = report.ProductVersion,
                BuildIdentity = report.BuildIdentity,
                ScanId = report.ScanId,
                Mode = report.Mode,
                StartedAtUtc = report.StartedAtUtc,
                CompletedAtUtc = final ? report.CompletedAtUtc : null,
                RuleSetVersion = report.RuleSetVersion,
                Coverage = report.Coverage,
                Metrics = report.Metrics,
                ContentScanSettings = Count == 0 ? report.ContentScanSettings : null,
                WorkerDiagnostics = report.WorkerDiagnostics,
                Findings = Take(report.Findings, ref _findings),
                CoverageNotes = Take(report.CoverageNotes, ref _notes),
                Roots = Take(report.Roots, ref _roots),
                ContentSources = Take(report.ContentSources, ref _sources),
                RootSummaries = Take(report.RootSummaries, ref _summaries),
                CandidateRoots = Take(report.CandidateRoots, ref _candidates),
                ScopeNotes = Take(report.ScopeNotes, ref _scope)
            };
            List<CoverageAggregateUpdate> updates = [];
            long characters = 0;
            while (changed < changes.Count && updates.Count < BatchSize)
            {
                CoverageAggregateUpdate update = changes[changed];
                // Keep even heavily escaped example paths comfortably below the 1 MiB wire cap.
                if (updates.Count > 0 && characters + update.Value.TextCharacters > 32 * 1024) break;
                updates.Add(update);
                characters += update.Value.TextCharacters;
                changed++;
            }
            send(new(Count, offsets, data) { CoverageUpdates = updates });
            foreach (CoverageAggregateUpdate update in updates)
                if (update.Index < _aggregates.Count) _aggregates[update.Index] = update.Value;
                else _aggregates.Add(update.Value);
            Count++;
        } while (_findings < report.Findings.Count || _notes < report.CoverageNotes.Count || _roots < report.Roots.Count ||
            _sources < report.ContentSources.Count || _summaries < report.RootSummaries.Count ||
            _candidates < report.CandidateRoots.Count || _scope < report.ScopeNotes.Count || changed < changes.Count);
    }

    private static List<T> Take<T>(List<T> source, ref int offset)
    {
        List<T> result = source.GetRange(offset, Math.Min(BatchSize, source.Count - offset));
        offset += result.Count;
        return result;
    }
}

public sealed class ReportBatchReader
{
    public ScanReport? Report { get; private set; }
    public int Count { get; private set; }
    public void Apply(ReportBatch batch)
    {
        if (batch.Sequence != Count) throw new InvalidDataException("扫描结果批次不连续，不能作为完整结果。");
        ScanReport data = batch.Data;
        Report ??= new ScanReport
        {
            ProductVersion = data.ProductVersion,
            BuildIdentity = data.BuildIdentity,
            ScanId = data.ScanId,
            Mode = data.Mode,
            StartedAtUtc = data.StartedAtUtc,
            RuleSetVersion = data.RuleSetVersion,
            ContentScanSettings = data.ContentScanSettings
        };
        if (Report.ScanId != data.ScanId) throw new InvalidDataException("扫描结果标识不一致。");
        ReportOffsets o = batch.Offsets;
        // Validate every range before mutating, so a rejected batch cannot partially add findings.
        Validate(Report.Findings, data.Findings, o.Findings); Validate(Report.CoverageNotes, data.CoverageNotes, o.Notes);
        Validate(Report.Roots, data.Roots, o.Roots); Validate(Report.ContentSources, data.ContentSources, o.Sources);
        Validate(Report.RootSummaries, data.RootSummaries, o.Summaries); Validate(Report.CandidateRoots, data.CandidateRoots, o.Candidates);
        Validate(Report.ScopeNotes, data.ScopeNotes, o.Scope);
        ValidateCoverage(Report.CoverageAggregates, batch.CoverageUpdates);
        if (data.CoverageAggregates.Count != 0)
            throw new InvalidDataException("覆盖分组必须通过带索引的更新传输。");
        Put(Report.Findings, data.Findings, o.Findings); Put(Report.CoverageNotes, data.CoverageNotes, o.Notes);
        Put(Report.Roots, data.Roots, o.Roots); Put(Report.ContentSources, data.ContentSources, o.Sources);
        Put(Report.RootSummaries, data.RootSummaries, o.Summaries); Put(Report.CandidateRoots, data.CandidateRoots, o.Candidates);
        Put(Report.ScopeNotes, data.ScopeNotes, o.Scope);
        foreach (CoverageAggregateUpdate update in batch.CoverageUpdates)
            if (update.Index < Report.CoverageAggregates.Count) Report.CoverageAggregates[update.Index] = update.Value;
            else Report.CoverageAggregates.Add(update.Value);
        Report.CompletedAtUtc = data.CompletedAtUtc; Report.Coverage = data.Coverage;
        Report.WorkerDiagnostics = data.WorkerDiagnostics ?? Report.WorkerDiagnostics;
        CopyMetrics(data.Metrics, Report.Metrics);
        Count++;
    }

    private static void ValidateCoverage(List<CoverageAggregate> target, List<CoverageAggregateUpdate> values)
    {
        if (values.Count > ReportBatchWriter.BatchSize) throw new InvalidDataException("覆盖更新批次过大。");
        int expected = target.Count, previous = -1;
        foreach (CoverageAggregateUpdate update in values)
        {
            CoverageAggregate value = update.Value;
            if (update.Index <= previous || update.Index > expected || update.Index >= CoverageAggregate.MaximumGroups ||
                value is null || string.IsNullOrWhiteSpace(value.Root) || value.Root.Length > CoverageAggregate.MaximumRootCharacters ||
                string.IsNullOrWhiteSpace(value.RuleId) || value.RuleId.Length > 128 || value.Count <= 0 ||
                value.Examples is null || value.Examples.Count > CoverageAggregate.MaximumExamples ||
                value.Count < value.Examples.Count || value.Examples.Any(p => p is null || p.Length > CoverageAggregate.MaximumExampleCharacters))
                throw new InvalidDataException("覆盖分组更新超过安全范围。");
            if (update.Index < target.Count)
            {
                CoverageAggregate old = target[update.Index];
                if (old.RuleId != value.RuleId || !old.Root.Equals(value.Root, StringComparison.OrdinalIgnoreCase) || value.Count < old.Count)
                    throw new InvalidDataException("覆盖分组标识或累计计数不一致。");
            }
            else expected++;
            previous = update.Index;
        }
    }

    private static void Validate<T>(List<T> target, List<T> values, int offset)
    {
        if (offset < 0 || offset > target.Count || values.Count > ReportBatchWriter.BatchSize ||
            (long)offset + values.Count > ScanResourceGuard.MaximumRecords + 256)
            throw new InvalidDataException("扫描结果批次超过安全范围。");
    }
    private static void Put<T>(List<T> target, List<T> values, int offset)
    {
        foreach (T value in values) { if (offset < target.Count) target[offset] = value; else target.Add(value); offset++; }
    }
    private static void CopyMetrics(ScanMetrics from, ScanMetrics to)
    {
        to.FilesVisited = from.FilesVisited; to.BytesHashed = from.BytesHashed; to.ArchiveEntriesVisited = from.ArchiveEntriesVisited;
        to.ArchiveBytesExpanded = from.ArchiveBytesExpanded; to.WorkshopItemsVisited = from.WorkshopItemsVisited;
        to.ProcessesVisited = from.ProcessesVisited; to.PersistenceItemsVisited = from.PersistenceItemsVisited;
        to.QuickPriorityBytesHashed = from.QuickPriorityBytesHashed; to.MediaStructuresChecked = from.MediaStructuresChecked;
    }
}
