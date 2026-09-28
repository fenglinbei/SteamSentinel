using SteamSentinel.Core.Reporting;
using System.Diagnostics;
using SteamSentinel.Core.Models;

namespace SteamSentinel.Core.Scanning;

/// <summary>Stop honestly before report growth consumes the sandbox's emergency headroom.</summary>
public sealed class ScanResourceGuard(bool checkProcessMemory = false)
{
    public const int MaximumRecords = 20_000;
    public const long MaximumTextCharacters = 8 * 1024 * 1024;
    public const int MaximumFieldCharacters = 64 * 1024;
    private int _findings, _notes, _sources, _roots, _summaries;
    private long _characters;
    private long _lastMemoryCheck;
    private readonly MemoryReclaimPolicy _reclaim = new();
    private ScanReport? _report;
    private readonly List<CoverageAggregate> _aggregates = [];
    private readonly List<CoverageNotice> _notices = [];

    public void Check(ScanReport report)
    {
        if (!ReferenceEquals(_report, report))
        {
            _report = report;
            _findings = _notes = _sources = _roots = _summaries = 0;
            _characters = 0;
            _aggregates.Clear();
            _notices.Clear();
        }
        int records = report.ContentScanSettings?.MaximumReportRecords ?? MaximumRecords;
        long requiredRecords = new[] { report.Findings.Count, report.CoverageNotes.Count, report.CoverageNotices.Count,
            report.ContentSources.Count, report.RootSummaries.Count }.Max();
        if (requiredRecords > records && !ScanResourceSession.Allow("MaximumReportRecords", requiredRecords, records, known: false) ||
            report.CoverageAggregates.Count > CoverageAggregate.MaximumGroups)
            throw MessageExceptions.Create(MessageText.Create("Backend.Core.ScanResourceGuard.Check.01"), sourceText => new ScanResourceLimitException(sourceText));
        foreach (Finding f in report.Findings.Skip(_findings))
        {
            Count(f.Target, f.ContentPath, f.Title, f.Description, f.Evidence);
            _characters += f.ValidateDisplayMessages();
        }
        foreach (string s in report.CoverageNotes.Skip(_notes)) Count(s);
        foreach (string s in report.ContentSources.Skip(_sources)) Count(s);
        foreach (string s in report.Roots.Skip(_roots)) Count(s);
        foreach (ScanRootSummary s in report.RootSummaries.Skip(_summaries)) Count(s.Path);
        for (int i = 0; i < report.CoverageAggregates.Count; i++)
        {
            CoverageAggregate value = report.CoverageAggregates[i];
            if (i < _aggregates.Count && ReferenceEquals(value, _aggregates[i])) continue;
            if (value.Count <= 0 || value.Examples.Count > CoverageAggregate.MaximumExamples ||
                value.Root.Length > CoverageAggregate.MaximumRootCharacters ||
                value.Examples.Any(p => p.Length > CoverageAggregate.MaximumExampleCharacters))
                throw MessageExceptions.Create(MessageText.Create("Backend.Core.ScanResourceGuard.Check.02"), sourceText => new ScanResourceLimitException(sourceText));
            if (i < _aggregates.Count) _characters -= _aggregates[i].TextCharacters;
            Count(value.RuleId, value.Root);
            foreach (string example in value.Examples) Count(example);
            if (i < _aggregates.Count) _aggregates[i] = value;
            else _aggregates.Add(value);
        }
        for (int i = 0; i < report.CoverageNotices.Count; i++)
        {
            CoverageNotice value = report.CoverageNotices[i];
            if (i < _notices.Count && ReferenceEquals(value, _notices[i])) continue;
            value.Validate();
            if (i < _notices.Count) _characters -= _notices[i].TextCharacters;
            _characters += value.TextCharacters;
            if (i < _notices.Count) _notices[i] = value; else _notices.Add(value);
        }
        _findings = report.Findings.Count; _notes = report.CoverageNotes.Count;
        _sources = report.ContentSources.Count; _roots = report.Roots.Count; _summaries = report.RootSummaries.Count;
        long text = checked(_characters + report.ValidateTextMessages());
        long textLimit = report.ContentScanSettings?.MaximumReportTextCharacters ?? MaximumTextCharacters;
        if (text > textLimit && !ScanResourceSession.Allow("MaximumReportTextCharacters", text, textLimit, known: false))
            throw MessageExceptions.Create(MessageText.Create("Backend.Core.ScanResourceGuard.Check.03"), sourceText => new ScanResourceLimitException(sourceText));
        if (!checkProcessMemory || Environment.TickCount64 - _lastMemoryCheck < 500) return;
        _lastMemoryCheck = Environment.TickCount64;
        using Process process = Process.GetCurrentProcess();
        long memoryLimit = report.ContentScanSettings?.MaximumWorkerMemoryBytes ?? 1024L * 1024 * 1024;
        if (process.PrivateMemorySize64 < memoryLimit / 8 * 5) return;
        if (_reclaim.ShouldCollect(process.PrivateMemorySize64, memoryLimit, Environment.TickCount64))
        {
            GC.Collect(2, GCCollectionMode.Optimized, blocking: true, compacting: false);
            process.Refresh();
        }
        if (process.PrivateMemorySize64 >= memoryLimit / 4 * 3 &&
            !ScanResourceSession.Allow("MaximumWorkerMemoryBytes", checked(process.PrivateMemorySize64 / 3 * 4 + 64L * 1024 * 1024), process.PrivateMemorySize64, known: false))
            throw MessageExceptions.Create(MessageText.Create("Backend.Core.ScanResourceGuard.Check.04"), sourceText => new ScanResourceLimitException(sourceText));
    }

    private void Count(params string?[] values)
    {
        foreach (string? value in values)
        {
            if (value?.Length > MaximumFieldCharacters)
                throw MessageExceptions.Create(MessageText.Create("Backend.Core.ScanResourceGuard.Count.01"), sourceText => new ScanResourceLimitException(sourceText));
            _characters += value?.Length ?? 0;
        }
    }
}

public sealed class ScanResourceLimitException(string message) : Exception(message);
