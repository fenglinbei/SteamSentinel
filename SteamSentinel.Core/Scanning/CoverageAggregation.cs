using System.Runtime.CompilerServices;
using SteamSentinel.Core.Models;

namespace SteamSentinel.Core.Scanning;

/// <summary>Bounded root/reason groups. Never silently discard a gap or claim samples are exhaustive.</summary>
public static class CoverageAggregation
{
    private sealed class Index
    {
        public Dictionary<string, int> Groups { get; } = new(StringComparer.OrdinalIgnoreCase);
        public int Indexed { get; set; }
    }
    private static readonly ConditionalWeakTable<ScanReport, Index> Indexes = new();

    public static void Add(ScanReport report, string ruleId, string root, string example)
    {
        report.Coverage = ScanCoverage.Partial;
        if (ruleId is not ("CONTENT-BYTE-BUDGET" or "QUICK-FILE-SIZE" or "QUICK-MEDIA-STRUCTURE" or
            "QUICK-CONTENT-NOT-HASHED"))
            throw new ArgumentException("This coverage reason requires an individual record.", nameof(ruleId));
        if (string.IsNullOrWhiteSpace(root) || root.Length > CoverageAggregate.MaximumRootCharacters)
            throw new ScanResourceLimitException("覆盖补查根路径超过安全长度，已保留此前结果，不能静默截断补查目标。");
        Index index = Indexes.GetOrCreateValue(report);
        while (index.Indexed < report.CoverageAggregates.Count)
        {
            CoverageAggregate value = report.CoverageAggregates[index.Indexed];
            index.Groups.TryAdd(value.RuleId + "\0" + value.Root, index.Indexed++);
        }
        string key = ruleId + "\0" + root;
        string sample = example.Length <= CoverageAggregate.MaximumExampleCharacters ? example :
            example[..(CoverageAggregate.MaximumExampleCharacters - 1)] + "…";
        if (index.Groups.TryGetValue(key, out int offset))
        {
            CoverageAggregate current = report.CoverageAggregates[offset];
            if (current.Count == long.MaxValue)
                throw new ScanResourceLimitException("覆盖计数达到安全上限，已保留此前结果。");
            IReadOnlyList<string> examples = current.Examples;
            if (examples.Count < CoverageAggregate.MaximumExamples && !examples.Contains(sample, StringComparer.OrdinalIgnoreCase))
                examples = [.. examples, sample];
            report.CoverageAggregates[offset] = current with { Count = current.Count + 1, Examples = examples };
        }
        else
        {
            if (report.CoverageAggregates.Count >= CoverageAggregate.MaximumGroups)
                throw new ScanResourceLimitException("不同根路径与原因的覆盖分组达到上限，已保留此前计数和补查根路径，请分批检查剩余目录。");
            index.Groups.Add(key, report.CoverageAggregates.Count);
            report.CoverageAggregates.Add(new(ruleId, root, 1, [sample]));
            index.Indexed++;
        }
    }

    public static long OccurrenceCount(ScanReport report) => report.CoverageAggregates.Sum(a => a.Count);
}
