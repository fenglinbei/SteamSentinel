using SteamSentinel.Core.Reporting;
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
            throw MessageExceptions.Create(MessageText.Create("Backend.Core.CoverageAggregation.Add.01"), sourceText => new ScanResourceLimitException(sourceText));
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
                throw MessageExceptions.Create(MessageText.Create("Backend.Core.CoverageAggregation.Add.02"), sourceText => new ScanResourceLimitException(sourceText));
            IReadOnlyList<string> examples = current.Examples;
            if (examples.Count < CoverageAggregate.MaximumExamples && !examples.Contains(sample, StringComparer.OrdinalIgnoreCase))
                examples = [.. examples, sample];
            report.CoverageAggregates[offset] = current with { Count = current.Count + 1, Examples = examples };
        }
        else
        {
            if (report.CoverageAggregates.Count >= CoverageAggregate.MaximumGroups)
                throw MessageExceptions.Create(MessageText.Create("Backend.Core.CoverageAggregation.Add.03"), sourceText => new ScanResourceLimitException(sourceText));
            index.Groups.Add(key, report.CoverageAggregates.Count);
            report.CoverageAggregates.Add(new(ruleId, root, 1, [sample]));
            index.Indexed++;
        }
    }

    public static long OccurrenceCount(ScanReport report) => report.CoverageAggregates.Sum(a => a.Count);
}
