namespace SteamSentinel.Core.Models;

/// <summary>
/// Exact number of coverage occurrences within a resumable root, not a distinct-file count.
/// Examples are bounded, may be shortened, and are never the complete retry target list.
/// Replace records when counts change so worker checkpoints can publish immutable upserts.
/// </summary>
public sealed record CoverageAggregate(string RuleId, string Root, long Count, IReadOnlyList<string> Examples)
{
    public const int MaximumGroups = 4096;
    public const int MaximumExamples = 4;
    public const int MaximumExampleCharacters = 1024;
    public const int MaximumRootCharacters = 32768;

    public long TextCharacters => (long)RuleId.Length + Root.Length + Examples.Sum(p => (long)p.Length);
}

public sealed record CoverageAggregateUpdate(int Index, CoverageAggregate Value);
