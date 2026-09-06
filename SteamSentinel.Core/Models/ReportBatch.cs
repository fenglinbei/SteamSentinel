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
    public TrustProxyDiagnosticFragment? TrustProxyFragment { get; init; }
    public RelatedComponentFragment? RelatedComponentFragment { get; init; }
    public ContainerScanFragment? ContainerFragment { get; init; }
}

/// <summary>Append-only findings are sent only after an outer file's hash binding is finalized.</summary>
public sealed class ReportBatchWriter(Action<ReportBatch> send)
{
    public const int BatchSize = 64;
    private int _findings, _notes, _roots, _sources, _summaries, _candidates, _scope;
    private readonly List<CoverageAggregate> _aggregates = [];
    private bool _diagnosticSent;
    private bool _relatedSent;
    private bool _containerEnded;
    private readonly List<(Guid Id, int Revision)> _containerVersions = [];
    public int Count { get; private set; }

    public void Send(ScanReport report, bool final = false)
    {
        IReadOnlyList<TrustProxyDiagnosticFragment>? diagnostic = final && !_diagnosticSent && report.TrustProxyDiagnostics is not null
            ? TrustProxyDiagnosticFragments.Create(report.TrustProxyDiagnostics) : null;
        IReadOnlyList<RelatedComponentFragment>? related = final && !_relatedSent && report.RelatedComponentDiagnostics is not null
            ? RelatedComponentFragments.Create(report.RelatedComponentDiagnostics) : null;
        List<ContainerScanFragment> containers = [];
        if (!_containerEnded && report.Containers is { } containerReport)
        {
            ContainerScanMetadata metadata = ContainerScanFragments.Metadata(containerReport);
            ContainerScanFragments.ValidateMetadata(metadata);
            for (int i = 0; i < containerReport.Nodes.Count; i++)
            {
                ContainerScanNode n = containerReport.Nodes[i];
                if (i < _containerVersions.Count && _containerVersions[i] == (n.NodeId, n.Revision)) continue;
                ContainerScanFragments.ValidateNode(n);
                containers.Add(new(metadata, i, n, false));
            }
            if (final) containers.Add(new(metadata, containerReport.Nodes.Count, null, true));
            foreach (ContainerScanFragment fragment in containers)
                TrustProxyDiagnosticFragments.ValidateWireFrame(new(Count,
                    new(report.Findings.Count, report.CoverageNotes.Count, report.Roots.Count, report.ContentSources.Count,
                        report.RootSummaries.Count, report.CandidateRoots.Count, report.ScopeNotes.Count), DiagnosticHeader(report, false))
                { ContainerFragment = fragment });
        }
        // Reject an invalid whole snapshot or oversized envelope before changing ordinary offsets.
        if (related is not null)
            foreach (RelatedComponentFragment fragment in related)
                TrustProxyDiagnosticFragments.ValidateWireFrame(new(Count,
                    new(report.Findings.Count, report.CoverageNotes.Count, report.Roots.Count, report.ContentSources.Count,
                        report.RootSummaries.Count, report.CandidateRoots.Count, report.ScopeNotes.Count), DiagnosticHeader(report, fragment.IsFinal))
                { RelatedComponentFragment = fragment });
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
                CompletedAtUtc = final && diagnostic is null && related is null && containers.Count == 0 ? report.CompletedAtUtc : null,
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
        if (diagnostic is not null)
        {
            foreach (TrustProxyDiagnosticFragment fragment in diagnostic)
            {
                ScanReport data = new()
                {
                    ProductVersion = report.ProductVersion,
                    BuildIdentity = report.BuildIdentity,
                    ScanId = report.ScanId,
                    Mode = report.Mode,
                    StartedAtUtc = report.StartedAtUtc,
                    RuleSetVersion = report.RuleSetVersion,
                    CompletedAtUtc = fragment.IsFinal && related is null && containers.Count == 0 ? report.CompletedAtUtc : null,
                    Coverage = report.Coverage,
                    Metrics = report.Metrics,
                    WorkerDiagnostics = report.WorkerDiagnostics
                };
                ReportBatch batch = new(Count, new(_findings, _notes, _roots, _sources, _summaries, _candidates, _scope), data)
                { TrustProxyFragment = fragment };
                TrustProxyDiagnosticFragments.ValidateWireFrame(batch);
                send(batch);
                Count++;
            }
            _diagnosticSent = true;
        }
        if (related is not null)
        {
            foreach (RelatedComponentFragment fragment in related)
            {
                ReportBatch batch = new(Count, new(_findings, _notes, _roots, _sources, _summaries, _candidates, _scope),
                    DiagnosticHeader(report, fragment.IsFinal && containers.Count == 0))
                { RelatedComponentFragment = fragment };
                TrustProxyDiagnosticFragments.ValidateWireFrame(batch);
                send(batch);
                Count++;
            }
            _relatedSent = true;
        }
        foreach (ContainerScanFragment fragment in containers)
        {
            ReportBatch batch = new(Count, new(_findings, _notes, _roots, _sources, _summaries, _candidates, _scope),
                DiagnosticHeader(report, final && fragment.IsFinal))
            { ContainerFragment = fragment };
            TrustProxyDiagnosticFragments.ValidateWireFrame(batch); send(batch); Count++;
            if (fragment.Node is { } n)
            {
                if (fragment.Index == _containerVersions.Count) _containerVersions.Add((n.NodeId, n.Revision));
                else _containerVersions[fragment.Index] = (n.NodeId, n.Revision);
            }
            _containerEnded |= fragment.IsFinal;
        }
    }

    private static ScanReport DiagnosticHeader(ScanReport report, bool complete) => new()
    {
        ProductVersion = report.ProductVersion,
        BuildIdentity = report.BuildIdentity,
        ScanId = report.ScanId,
        Mode = report.Mode,
        StartedAtUtc = report.StartedAtUtc,
        RuleSetVersion = report.RuleSetVersion,
        CompletedAtUtc = complete ? report.CompletedAtUtc : null,
        Coverage = report.Coverage,
        Metrics = report.Metrics,
        WorkerDiagnostics = report.WorkerDiagnostics
    };

    private static List<T> Take<T>(List<T> source, ref int offset)
    {
        List<T> result = source.GetRange(offset, Math.Min(BatchSize, source.Count - offset));
        offset += result.Count;
        return result;
    }
}

public sealed class ReportBatchReader(int maximumRecords = ScanResourceGuard.MaximumRecords)
{
    public ScanReport? Report { get; private set; }
    public int Count { get; private set; }
    private TrustProxyDiagnosticAssembly? _diagnostic;
    private RelatedComponentAssembly? _related;
    private ContainerScanAssembly? _container;
    public bool HasIncompleteTrustProxyDiagnostics => _diagnostic is { IsComplete: false };
    public bool HasIncompleteRelatedComponentDiagnostics => _related is { IsComplete: false };
    public bool HasIncompleteContainers => _container is { IsComplete: false };
    public void Apply(ReportBatch batch)
    {
        if (batch.Sequence != Count) throw new InvalidDataException("扫描结果批次不连续，不能作为完整结果。");
        ScanReport data = batch.Data;
        if (data is null || batch.Offsets is null || batch.CoverageUpdates is null || data.Metrics is null ||
            data.Findings is null || data.CoverageNotes is null || data.Roots is null || data.ContentSources is null ||
            data.RootSummaries is null || data.CandidateRoots is null || data.ScopeNotes is null || data.CoverageAggregates is null)
            throw new InvalidDataException("扫描结果批次结构缺失。");
        ScanReport target = Report ?? new ScanReport
        {
            ProductVersion = data.ProductVersion,
            BuildIdentity = data.BuildIdentity,
            ScanId = data.ScanId,
            Mode = data.Mode,
            StartedAtUtc = data.StartedAtUtc,
            RuleSetVersion = data.RuleSetVersion,
            ContentScanSettings = data.ContentScanSettings
        };
        if (target.ScanId != data.ScanId) throw new InvalidDataException("扫描结果标识不一致。");
        ReportOffsets o = batch.Offsets;
        // Validate every range before mutating, so a rejected batch cannot partially add findings.
        Validate(target.Findings, data.Findings, o.Findings); Validate(target.CoverageNotes, data.CoverageNotes, o.Notes);
        Validate(target.Roots, data.Roots, o.Roots); Validate(target.ContentSources, data.ContentSources, o.Sources);
        Validate(target.RootSummaries, data.RootSummaries, o.Summaries); Validate(target.CandidateRoots, data.CandidateRoots, o.Candidates);
        Validate(target.ScopeNotes, data.ScopeNotes, o.Scope);
        ValidateCoverage(target.CoverageAggregates, batch.CoverageUpdates);
        if (data.CoverageAggregates.Count != 0)
            throw new InvalidDataException("覆盖分组必须通过带索引的更新传输。");
        if (data.TrustProxyDiagnostics is not null || data.RelatedComponentDiagnostics is not null || data.Containers is not null)
            throw new InvalidDataException("诊断数据必须通过有界分片传输。");
        if ((batch.TrustProxyFragment is null ? 0 : 1) + (batch.RelatedComponentFragment is null ? 0 : 1) + (batch.ContainerFragment is null ? 0 : 1) > 1)
            throw new InvalidDataException("单个批次不得混装两种诊断分片。");
        TrustProxyDiagnosticAssembly? nextDiagnostic = null;
        PreparedTrustProxyFragment? prepared = null;
        if (batch.TrustProxyFragment is not null)
        {
            nextDiagnostic = _diagnostic ?? new TrustProxyDiagnosticAssembly();
            prepared = nextDiagnostic.Prepare(batch.TrustProxyFragment);
            TrustProxyDiagnosticFragments.ValidateWireFrame(batch);
        }
        RelatedComponentAssembly? nextRelated = null;
        PreparedRelatedComponentFragment? preparedRelated = null;
        if (batch.RelatedComponentFragment is not null)
        {
            nextRelated = _related ?? new RelatedComponentAssembly();
            preparedRelated = nextRelated.Prepare(batch.RelatedComponentFragment);
            TrustProxyDiagnosticFragments.ValidateWireFrame(batch);
        }
        ContainerScanAssembly? nextContainer = null;
        PreparedContainerFragment? preparedContainer = null;
        if (batch.ContainerFragment is not null)
        {
            nextContainer = _container ?? new();
            preparedContainer = nextContainer.Prepare(batch.ContainerFragment);
            TrustProxyDiagnosticFragments.ValidateWireFrame(batch);
        }
        // No report, finding, offset, or diagnostic state changes occur before all validation succeeds.
        Put(target.Findings, data.Findings, o.Findings); Put(target.CoverageNotes, data.CoverageNotes, o.Notes);
        Put(target.Roots, data.Roots, o.Roots); Put(target.ContentSources, data.ContentSources, o.Sources);
        Put(target.RootSummaries, data.RootSummaries, o.Summaries); Put(target.CandidateRoots, data.CandidateRoots, o.Candidates);
        Put(target.ScopeNotes, data.ScopeNotes, o.Scope);
        foreach (CoverageAggregateUpdate update in batch.CoverageUpdates)
            if (update.Index < target.CoverageAggregates.Count) target.CoverageAggregates[update.Index] = update.Value;
            else target.CoverageAggregates.Add(update.Value);
        if (prepared is not null)
        {
            nextDiagnostic!.Commit(prepared);
            _diagnostic = nextDiagnostic;
            target.TrustProxyDiagnostics = _diagnostic.Report;
        }
        if (preparedRelated is not null)
        {
            nextRelated!.Commit(preparedRelated);
            _related = nextRelated;
            target.RelatedComponentDiagnostics = _related.Report;
        }
        if (preparedContainer is not null)
        {
            nextContainer!.Commit(preparedContainer); _container = nextContainer; target.Containers = _container.Report;
        }
        bool incomplete = HasIncompleteTrustProxyDiagnostics || HasIncompleteRelatedComponentDiagnostics || HasIncompleteContainers;
        target.CompletedAtUtc = incomplete ? null : data.CompletedAtUtc;
        target.Coverage = incomplete || target.Containers is { Complete: false } ? ScanCoverage.Partial : data.Coverage;
        target.WorkerDiagnostics = data.WorkerDiagnostics ?? target.WorkerDiagnostics;
        CopyMetrics(data.Metrics, target.Metrics);
        Report = target;
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

    private void Validate<T>(List<T> target, List<T> values, int offset)
    {
        if (offset < 0 || offset > target.Count || values.Count > ReportBatchWriter.BatchSize ||
            (long)offset + values.Count > (long)maximumRecords + 256)
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
