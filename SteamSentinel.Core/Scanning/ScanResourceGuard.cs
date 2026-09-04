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
    private ScanReport? _report;
    private readonly List<CoverageAggregate> _aggregates = [];

    public void Check(ScanReport report)
    {
        if (!ReferenceEquals(_report, report))
        {
            _report = report;
            _findings = _notes = _sources = _roots = _summaries = 0;
            _characters = 0;
            _aggregates.Clear();
        }
        if (report.Findings.Count > MaximumRecords || report.CoverageNotes.Count > MaximumRecords ||
            report.ContentSources.Count > MaximumRecords || report.RootSummaries.Count > MaximumRecords ||
            report.CoverageAggregates.Count > CoverageAggregate.MaximumGroups)
            throw new ScanResourceLimitException("检查结果达到本轮记录上限，已保留此前结果。请缩小目录范围，分批检查剩余内容。");
        foreach (Finding f in report.Findings.Skip(_findings))
            Count(f.Target, f.ContentPath, f.Title, f.Description, f.Evidence);
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
                throw new ScanResourceLimitException("覆盖分组超过安全范围，已保留此前结果。");
            if (i < _aggregates.Count) _characters -= _aggregates[i].TextCharacters;
            Count(value.RuleId, value.Root);
            foreach (string example in value.Examples) Count(example);
            if (i < _aggregates.Count) _aggregates[i] = value;
            else _aggregates.Add(value);
        }
        _findings = report.Findings.Count; _notes = report.CoverageNotes.Count;
        _sources = report.ContentSources.Count; _roots = report.Roots.Count; _summaries = report.RootSummaries.Count;
        if (_characters > MaximumTextCharacters)
            throw new ScanResourceLimitException("检查结果的文本量达到本轮上限，已保留此前结果。请分批检查剩余目录。");
        if (!checkProcessMemory || Environment.TickCount64 - _lastMemoryCheck < 500) return;
        _lastMemoryCheck = Environment.TickCount64;
        using Process process = Process.GetCurrentProcess();
        if (process.PrivateMemorySize64 < 640L * 1024 * 1024) return;
        GC.Collect(2, GCCollectionMode.Aggressive, blocking: true, compacting: true);
        process.Refresh();
        if (process.PrivateMemorySize64 >= 768L * 1024 * 1024)
            throw new ScanResourceLimitException("扫描组件接近内存安全上限，已停止本轮内容检查并保留此前结果。请分批扫描，未完成的文件仍需检查。");
    }

    private void Count(params string?[] values)
    {
        foreach (string? value in values)
        {
            if (value?.Length > MaximumFieldCharacters)
                throw new ScanResourceLimitException("单条结果文本过长，已停止本轮内容检查，请单独检查该文件。");
            _characters += value?.Length ?? 0;
        }
    }
}

public sealed class ScanResourceLimitException(string message) : Exception(message);
