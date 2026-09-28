using SteamSentinel.Core.Reporting;
using System.Diagnostics;
using SteamSentinel.Core.Scanning;

namespace SteamSentinel.Core.Models;

[method: System.Text.Json.Serialization.JsonConstructor]
public sealed record WorkerDiagnostics(string Stage, string LastPath, string Operation, long PrivateBytes, long PeakPrivateBytes, long ManagedBytes, DateTimeOffset CapturedAtUtc, string? FailureType = null, string? FailureStack = null, string? LauncherIntegrity = null)
{
    public long ValidateDisplayMessages() => (StageMessage?.Validate() ?? 0) + (LastPathMessage?.Validate() ?? 0) + (OperationMessage?.Validate() ?? 0);
    public static WorkerDiagnostics Capture(ScanProgress? progress, Exception? error = null)
    {
        using Process process = Process.GetCurrentProcess();
        string? stack = error?.StackTrace;
        return new(progress is null ? MessageText.Create("Backend.Core.ReportBatch.Capture.01") : new MessageText(progress.Stage, progress.StageMessage),
            new MessageText(progress?.CurrentItem ?? "", progress?.CurrentItemMessage), new MessageText(progress?.Message ?? "", progress?.DetailMessage), process.PrivateMemorySize64, process.PeakPagedMemorySize64, GC.GetTotalMemory(false), DateTimeOffset.UtcNow, error?.GetType().Name, stack?[..Math.Min(stack.Length, 2048)]);
    }
    [System.Text.Json.Serialization.JsonIgnore(Condition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull)]
    public SteamSentinel.Core.Models.DisplayMessage? StageMessage { get => SteamSentinel.Core.Reporting.MessageText.BoundDescriptor(field, Stage); init => field = value; }

    [System.Text.Json.Serialization.JsonIgnore]
    public SteamSentinel.Core.Reporting.MessageText StageText
    {
        get => new(Stage ?? string.Empty, StageMessage);
        init
        {
            Stage = value.OriginalText;
            StageMessage = value.Message;
        }
    }
    [System.Text.Json.Serialization.JsonIgnore(Condition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull)]
    public SteamSentinel.Core.Models.DisplayMessage? LastPathMessage { get => SteamSentinel.Core.Reporting.MessageText.BoundDescriptor(field, LastPath); init => field = value; }

    [System.Text.Json.Serialization.JsonIgnore]
    public SteamSentinel.Core.Reporting.MessageText LastPathText
    {
        get => new(LastPath ?? string.Empty, LastPathMessage);
        init
        {
            LastPath = value.OriginalText;
            LastPathMessage = value.Message;
        }
    }
    [System.Text.Json.Serialization.JsonIgnore(Condition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull)]
    public SteamSentinel.Core.Models.DisplayMessage? OperationMessage { get => SteamSentinel.Core.Reporting.MessageText.BoundDescriptor(field, Operation); init => field = value; }

    [System.Text.Json.Serialization.JsonIgnore]
    public SteamSentinel.Core.Reporting.MessageText OperationText
    {
        get => new(Operation ?? string.Empty, OperationMessage);
        init
        {
            Operation = value.OriginalText;
            OperationMessage = value.Message;
        }
    }

    public WorkerDiagnostics(SteamSentinel.Core.Reporting.MessageText Stage, SteamSentinel.Core.Reporting.MessageText LastPath, SteamSentinel.Core.Reporting.MessageText Operation, long PrivateBytes, long PeakPrivateBytes, long ManagedBytes, DateTimeOffset CapturedAtUtc, string? FailureType = null, string? FailureStack = null, string? LauncherIntegrity = null) : this(Stage.OriginalText, LastPath.OriginalText, Operation.OriginalText, PrivateBytes, PeakPrivateBytes, ManagedBytes, CapturedAtUtc, FailureType, FailureStack, LauncherIntegrity)
    {
        StageMessage = Stage.Message;
        LastPathMessage = LastPath.Message;
        OperationMessage = Operation.Message;
    }
}

public sealed record ReportOffsets(int Findings, int Notes, int Roots, int Sources, int Summaries, int Candidates, int Scope, int Notices = 0);
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
    private int _findings, _notes, _roots, _sources, _summaries, _candidates, _scope, _notices;
    private readonly List<CoverageAggregate> _aggregates = [];
    private bool _diagnosticSent;
    private bool _relatedSent;
    private bool _containerEnded;
    private int _resourceDecisionsSent = -1;
    private readonly List<(Guid Id, int Revision)> _containerVersions = [];
    public int Count { get; private set; }

    public void Send(ScanReport report, bool final = false)
    {
        report.ValidateTextMessages();
        report.ResourceAudit?.Validate();
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
                        report.RootSummaries.Count, report.CandidateRoots.Count, report.ScopeNotes.Count, report.CoverageNotices.Count), DiagnosticHeader(report, false))
                { ContainerFragment = fragment });
        }
        // Reject an invalid whole snapshot or oversized envelope before changing ordinary offsets.
        if (related is not null)
            foreach (RelatedComponentFragment fragment in related)
                TrustProxyDiagnosticFragments.ValidateWireFrame(new(Count,
                    new(report.Findings.Count, report.CoverageNotes.Count, report.Roots.Count, report.ContentSources.Count,
                        report.RootSummaries.Count, report.CandidateRoots.Count, report.ScopeNotes.Count, report.CoverageNotices.Count), DiagnosticHeader(report, fragment.IsFinal))
                { RelatedComponentFragment = fragment });
        // AMSI availability notes can be updated in place. Replay these bounded lists at completion.
        if (final) { _notes = 0; _notices = 0; }
        List<CoverageAggregateUpdate> changes = [];
        for (int i = 0; i < report.CoverageAggregates.Count; i++)
            if (i >= _aggregates.Count || !ReferenceEquals(_aggregates[i], report.CoverageAggregates[i]))
                changes.Add(new(i, report.CoverageAggregates[i]));
        int changed = 0;
        do
        {
            ReportOffsets offsets = new(_findings, _notes, _roots, _sources, _summaries, _candidates, _scope, _notices);
            ScanReport data = new()
            {
                ProductVersion = report.ProductVersion,
                StatusSchemaVersion = report.StatusSchemaVersion,
                ExecutionState = report.ExecutionState,
                ExecutionReasonCode = report.ExecutionReasonCode,
                LegacyExecutionStatus = report.LegacyExecutionStatus,
                BuildIdentity = report.BuildIdentity,
                ScanId = report.ScanId,
                Mode = report.Mode,
                StartedAtUtc = report.StartedAtUtc,
                CompletedAtUtc = final && diagnostic is null && related is null && containers.Count == 0 ? report.CompletedAtUtc : null,
                RuleSetVersion = report.RuleSetVersion,
                Coverage = report.Coverage,
                Metrics = report.Metrics,
                ContentScanSettings = Count == 0 ? report.ContentScanSettings : null,
                ResourceAudit = final || report.ResourceAudit?.Decisions.Count != _resourceDecisionsSent ? report.ResourceAudit : null,
                WorkerDiagnostics = report.WorkerDiagnostics,
                Findings = Take(report.Findings, ref _findings),
                CoverageNotes = Take(report.CoverageNotes, ref _notes),
                CoverageNotices = TakeNotices(report.CoverageNotices, ref _notices),
                Roots = Take(report.Roots, ref _roots),
                ContentSources = Take(report.ContentSources, ref _sources),
                RootSummaries = Take(report.RootSummaries, ref _summaries),
                CandidateRoots = Take(report.CandidateRoots, ref _candidates),
                ScopeNotes = Take(report.ScopeNotes, ref _scope)
            };
            data.CoverageNoteMessages = DisplayMessageMap.Slice(report.CoverageNoteMessages, offsets.Notes, data.CoverageNotes.Count);
            data.ScopeNoteMessages = DisplayMessageMap.Slice(report.ScopeNoteMessages, offsets.Scope, data.ScopeNotes.Count);
            data.ContentSourceMessages = DisplayMessageMap.Slice(report.ContentSourceMessages, offsets.Sources, data.ContentSources.Count);
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
            _resourceDecisionsSent = report.ResourceAudit?.Decisions.Count ?? -1;
            foreach (CoverageAggregateUpdate update in updates)
                if (update.Index < _aggregates.Count) _aggregates[update.Index] = update.Value;
                else _aggregates.Add(update.Value);
            Count++;
        } while (_findings < report.Findings.Count || _notes < report.CoverageNotes.Count || _roots < report.Roots.Count ||
            _sources < report.ContentSources.Count || _summaries < report.RootSummaries.Count ||
            _candidates < report.CandidateRoots.Count || _scope < report.ScopeNotes.Count || _notices < report.CoverageNotices.Count || changed < changes.Count);
        if (diagnostic is not null)
        {
            foreach (TrustProxyDiagnosticFragment fragment in diagnostic)
            {
                ScanReport data = new()
                {
                    ProductVersion = report.ProductVersion,
                    StatusSchemaVersion = report.StatusSchemaVersion,
                    ExecutionState = report.ExecutionState,
                    ExecutionReasonCode = report.ExecutionReasonCode,
                    LegacyExecutionStatus = report.LegacyExecutionStatus,
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
        StatusSchemaVersion = report.StatusSchemaVersion,
        ExecutionState = report.ExecutionState,
        ExecutionReasonCode = report.ExecutionReasonCode,
        LegacyExecutionStatus = report.LegacyExecutionStatus,
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

    private static List<CoverageNotice> TakeNotices(List<CoverageNotice> values, ref int offset)
    {
        List<CoverageNotice> result = [];
        long characters = 0;
        while (offset < values.Count && result.Count < BatchSize)
        {
            CoverageNotice notice = values[offset];
            notice.Validate();
            if (result.Count > 0 && characters + notice.TextCharacters > 32 * 1024) break;
            result.Add(notice); characters += notice.TextCharacters; offset++;
        }
        return result;
    }

    private static List<T> Take<T>(List<T> source, ref int offset)
    {
        List<T> result = source.GetRange(offset, Math.Min(BatchSize, source.Count - offset));
        offset += result.Count;
        return result;
    }
}

public sealed class ReportBatchReader(int maximumRecords = ScanResourceGuard.MaximumRecords)
{
    public void IncreaseRecordBudget(int records)
    {
        if (records < maximumRecords || records > int.MaxValue - 257) throw new InvalidDataException("Invalid report budget increase.");
        maximumRecords = records;
    }
    public ScanReport? Report { get; private set; }
    public int Count { get; private set; }
    private TrustProxyDiagnosticAssembly? _diagnostic;
    private RelatedComponentAssembly? _related;
    private ContainerScanAssembly? _container;
    private long _displayMessageCharacters;
    public bool HasIncompleteTrustProxyDiagnostics => _diagnostic is { IsComplete: false };
    public bool HasIncompleteRelatedComponentDiagnostics => _related is { IsComplete: false };
    public bool HasIncompleteContainers => _container is { IsComplete: false };
    public void Apply(ReportBatch batch)
    {
        if (batch.Sequence != Count) throw MessageExceptions.Create(MessageText.Create("Backend.Core.ReportBatch.Apply.01"), sourceText => new InvalidDataException(sourceText));
        ScanReport data = batch.Data;
        data?.ResourceAudit?.Validate();
        if (data?.ResourceAudit is { } audit && (audit.Decisions.Count > ScanResourceAudit.MaximumDecisions ||
            Report?.ResourceAudit is { } previous && (audit.Decisions.Count < previous.Decisions.Count ||
                audit.WaitingMilliseconds < previous.WaitingMilliseconds || audit.PeakParallelFiles < previous.PeakParallelFiles ||
                previous.Decisions.Where((d, i) => !ScanResourceAudit.SameDecision(d, audit.Decisions[i])).Any())))
            throw new InvalidDataException("Resource history cannot be rewritten.");
        if (data is null || batch.Offsets is null || batch.CoverageUpdates is null || data.Metrics is null ||
            data.Findings is null || data.CoverageNotes is null || data.Roots is null || data.ContentSources is null ||
            data.RootSummaries is null || data.CandidateRoots is null || data.ScopeNotes is null || data.CoverageAggregates is null || data.CoverageNotices is null)
            throw MessageExceptions.Create(MessageText.Create("Backend.Core.ReportBatch.Apply.02"), sourceText => new InvalidDataException(sourceText));
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
        if (target.ScanId != data.ScanId) throw MessageExceptions.Create(MessageText.Create("Backend.Core.ReportBatch.Apply.03"), sourceText => new InvalidDataException(sourceText));
        if (data.StatusSchemaVersion is < 0 or > ScanExecution.SchemaVersion || !Enum.IsDefined(data.ExecutionState) ||
            data.ExecutionReasonCode is not null && !ReasonCodes.IsValid(data.ExecutionReasonCode) || data.LegacyExecutionStatus?.Length > 4096)
            throw new InvalidDataException("Invalid scan execution metadata.");
        ReportOffsets o = batch.Offsets;
        // Validate every range before mutating, so a rejected batch cannot partially add findings.
        Validate(target.Findings, data.Findings, o.Findings); Validate(target.CoverageNotes, data.CoverageNotes, o.Notes);
        long displayCharacters = _displayMessageCharacters;
        foreach (Finding finding in data.Findings)
        {
            displayCharacters += finding.ValidateDisplayMessages();
            finding.SteamUiEvidence?.Validate();
            if (finding.ReasonCode is not null && !ReasonCodes.IsValid(finding.ReasonCode)) throw new InvalidDataException("Invalid finding reason code.");
        }
        foreach (Finding replaced in target.Findings.Skip(o.Findings).Take(data.Findings.Count))
            displayCharacters -= replaced.ValidateDisplayMessages();
        displayCharacters += data.ValidateTextMessages();
        displayCharacters += data.WorkerDiagnostics?.ValidateDisplayMessages() ?? 0;
        displayCharacters -= DisplayMessageMap.RangeCharacters(target.CoverageNoteMessages, o.Notes, data.CoverageNotes.Count) +
            DisplayMessageMap.RangeCharacters(target.ScopeNoteMessages, o.Scope, data.ScopeNotes.Count) +
            DisplayMessageMap.RangeCharacters(target.ContentSourceMessages, o.Sources, data.ContentSources.Count);
        if (displayCharacters > ScanResourceGuard.MaximumTextCharacters)
            throw new InvalidDataException("Display message aggregate limit exceeded.");
        Validate(target.Roots, data.Roots, o.Roots); Validate(target.ContentSources, data.ContentSources, o.Sources);
        Validate(target.RootSummaries, data.RootSummaries, o.Summaries); Validate(target.CandidateRoots, data.CandidateRoots, o.Candidates);
        Validate(target.ScopeNotes, data.ScopeNotes, o.Scope);
        Validate(target.CoverageNotices, data.CoverageNotices, o.Notices);
        foreach (CoverageNotice notice in data.CoverageNotices)
        { if (notice is null) throw new InvalidDataException("Missing coverage notice."); notice.Validate(); }
        ValidateCoverage(target.CoverageAggregates, batch.CoverageUpdates);
        if (data.CoverageAggregates.Count != 0)
            throw MessageExceptions.Create(MessageText.Create("Backend.Core.ReportBatch.Apply.04"), sourceText => new InvalidDataException(sourceText));
        if (data.TrustProxyDiagnostics is not null || data.RelatedComponentDiagnostics is not null || data.Containers is not null)
            throw MessageExceptions.Create(MessageText.Create("Backend.Core.ReportBatch.Apply.05"), sourceText => new InvalidDataException(sourceText));
        if ((batch.TrustProxyFragment is null ? 0 : 1) + (batch.RelatedComponentFragment is null ? 0 : 1) + (batch.ContainerFragment is null ? 0 : 1) > 1)
            throw MessageExceptions.Create(MessageText.Create("Backend.Core.ReportBatch.Apply.06"), sourceText => new InvalidDataException(sourceText));
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
        _displayMessageCharacters = displayCharacters;
        Put(target.Findings, data.Findings, o.Findings); Put(target.CoverageNotes, data.CoverageNotes, o.Notes);
        Put(target.Roots, data.Roots, o.Roots); Put(target.ContentSources, data.ContentSources, o.Sources);
        Put(target.RootSummaries, data.RootSummaries, o.Summaries); Put(target.CandidateRoots, data.CandidateRoots, o.Candidates);
        Put(target.ScopeNotes, data.ScopeNotes, o.Scope);
        Put(target.CoverageNotices, data.CoverageNotices, o.Notices);
        target.CoverageNoteMessages = DisplayMessageMap.Put(target.CoverageNoteMessages, data.CoverageNoteMessages, o.Notes, data.CoverageNotes.Count);
        target.ScopeNoteMessages = DisplayMessageMap.Put(target.ScopeNoteMessages, data.ScopeNoteMessages, o.Scope, data.ScopeNotes.Count);
        target.ContentSourceMessages = DisplayMessageMap.Put(target.ContentSourceMessages, data.ContentSourceMessages, o.Sources, data.ContentSources.Count);
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
        target.StatusSchemaVersion = data.StatusSchemaVersion;
        target.ExecutionState = (incomplete || data.CompletedAtUtc is null) && data.ExecutionState == ScanExecutionState.Completed ? ScanExecutionState.Running : data.ExecutionState;
        target.ExecutionReasonCode = data.ExecutionReasonCode;
        target.LegacyExecutionStatus = data.LegacyExecutionStatus;
        target.Coverage = incomplete || target.Containers is { Complete: false } ? ScanCoverage.Partial : data.Coverage;
        target.WorkerDiagnostics = data.WorkerDiagnostics ?? target.WorkerDiagnostics;
        if (data.ResourceAudit is not null) target.ResourceAudit = System.Text.Json.JsonSerializer.Deserialize<ScanResourceAudit>(System.Text.Json.JsonSerializer.Serialize(data.ResourceAudit));
        CopyMetrics(data.Metrics, target.Metrics);
        Report = target;
        Count++;
    }

    private static void ValidateCoverage(List<CoverageAggregate> target, List<CoverageAggregateUpdate> values)
    {
        if (values.Count > ReportBatchWriter.BatchSize) throw MessageExceptions.Create(MessageText.Create("Backend.Core.ReportBatch.ValidateCoverage.01"), sourceText => new InvalidDataException(sourceText));
        int expected = target.Count, previous = -1;
        foreach (CoverageAggregateUpdate update in values)
        {
            CoverageAggregate value = update.Value;
            if (update.Index <= previous || update.Index > expected || update.Index >= CoverageAggregate.MaximumGroups ||
                value is null || string.IsNullOrWhiteSpace(value.Root) || value.Root.Length > CoverageAggregate.MaximumRootCharacters ||
                string.IsNullOrWhiteSpace(value.RuleId) || value.RuleId.Length > 128 || value.Count <= 0 ||
                value.Examples is null || value.Examples.Count > CoverageAggregate.MaximumExamples ||
                value.Count < value.Examples.Count || value.Examples.Any(p => p is null || p.Length > CoverageAggregate.MaximumExampleCharacters))
                throw MessageExceptions.Create(MessageText.Create("Backend.Core.ReportBatch.ValidateCoverage.02"), sourceText => new InvalidDataException(sourceText));
            if (update.Index < target.Count)
            {
                CoverageAggregate old = target[update.Index];
                if (old.RuleId != value.RuleId || !old.Root.Equals(value.Root, StringComparison.OrdinalIgnoreCase) || value.Count < old.Count)
                    throw MessageExceptions.Create(MessageText.Create("Backend.Core.ReportBatch.ValidateCoverage.03"), sourceText => new InvalidDataException(sourceText));
            }
            else expected++;
            previous = update.Index;
        }
    }

    private void Validate<T>(List<T> target, List<T> values, int offset)
    {
        if (offset < 0 || offset > target.Count || values.Count > ReportBatchWriter.BatchSize ||
            (long)offset + values.Count > (long)maximumRecords + 256)
            throw MessageExceptions.Create(MessageText.Create("Backend.Core.ReportBatch.Validate.01"), sourceText => new InvalidDataException(sourceText));
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
