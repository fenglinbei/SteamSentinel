using System.Globalization;
using SteamSentinel.Core.Models;

namespace SteamSentinel.Core.Reporting;

public sealed record CoverageEntry(string Kind, string Target, string Detail, string NextStep, bool CanFullScan)
{
    public long Count { get; init; } = 1;
    public string ReasonCode { get; init; } = ReasonCodes.Unspecified;
    public string TargetDisplay { get; init; } = Target;
}
public sealed record CoverageGroup(string Kind, long Count, string NextStep, bool CanFullScan, IReadOnlyList<CoverageEntry> Entries)
{
    public string ReasonCode { get; init; } = ReasonCodes.Unspecified;
    public string Details => string.Join(Environment.NewLine + Environment.NewLine,
        Entries.Select(e => $"{e.TargetDisplay}\n{e.Detail}"));
}

/// <summary>Coverage is not a threat. Legacy coverage findings remain in JSON for worker and retry compatibility.</summary>
public static class CoveragePresentation
{
    public static string FullScanAction => DisplayText.Get("Coverage.FullScanAction.01");
    public static string QuickScope => DisplayText.Get("Coverage.QuickScope.01");
    public static string FullScope => DisplayText.Get("Coverage.FullScope.01");

    public static IReadOnlyList<CoverageGroup> Groups(ScanReport report, CultureInfo? culture = null)
    {
        using IDisposable scope = DisplayText.UseCulture(culture);
        List<CoverageEntry> entries = [];
        HashSet<string> described = new(StringComparer.Ordinal);
        foreach (Finding f in report.Findings.Where(f => f.Category == FindingCategory.Coverage))
        {
            described.Add(f.Description);
            entries.Add(Describe(f.RuleId, f.Target, f.DescriptionText.Display + (string.IsNullOrWhiteSpace(f.Evidence) ? "" : "\n" + f.EvidenceDisplay), f.ReasonCode, culture) with { TargetDisplay = f.TargetText.Display });
        }
        foreach (CoverageNotice notice in report.CoverageNotices)
        {
            described.Add(notice.Detail);
            entries.Add(Describe("", notice.Target ?? StatusPresentation.Text("Coverage.CurrentScan", culture),
                notice.DetailMessage is not null ? notice.DetailText.Display : notice.Message is null ? notice.Detail : StatusPresentation.Format(notice.Message, culture), notice.ReasonCode, culture));
        }
        foreach (MessageText note in report.CoverageTexts.DistinctBy(n => n.OriginalText).Where(n => !described.Contains(n.OriginalText)))
            entries.Add(Describe("", StatusPresentation.Text("Coverage.CurrentScan", culture), note.Display, ReasonCodes.Unspecified, culture));
        foreach (CoverageAggregate aggregate in report.CoverageAggregates)
        {
            string detail = StatusPresentation.Text("Coverage.Aggregate", culture,
                aggregate.Count.ToString("N0", culture ?? StatusPresentation.DefaultCulture)) +
                (aggregate.Examples.Count == 0 ? "" : "\n" + string.Join("\n", aggregate.Examples));
            entries.Add(Describe(aggregate.RuleId, aggregate.Root, detail, culture: culture) with { Count = aggregate.Count });
        }
        return entries.GroupBy(e => e.ReasonCode, StringComparer.Ordinal)
            .Select(g => new CoverageGroup(g.First().Kind, g.Sum(e => e.Count), g.First().NextStep, g.First().CanFullScan, g.ToArray())
            { ReasonCode = g.Key }).ToArray();
    }

    public static CoverageEntry Describe(string rule, string target, string detail, string? reasonCode = null, CultureInfo? culture = null)
    {
        string code = reasonCode ?? ReasonCodes.ForRule(rule);
        bool full = code is ReasonCodes.QuickMedia or ReasonCodes.QuickContent or ReasonCodes.ReadBudget
            or ReasonCodes.EngineSizeLimit or ReasonCodes.ArchiveNotExpanded or ReasonCodes.ArchiveEncrypted;
        string displayCode = code is ReasonCodes.TrustProxyIncomplete or ReasonCodes.SystemIncomplete or ReasonCodes.QuickMedia
            or ReasonCodes.QuickContent or ReasonCodes.ReadBudget or ReasonCodes.EngineSizeLimit or ReasonCodes.ArchiveNotExpanded
            or ReasonCodes.ArchiveEncrypted or ReasonCodes.ResourceLimit or ReasonCodes.AllocationFailed or ReasonCodes.WorkshopSelection
            or ReasonCodes.AmsiUnavailable or ReasonCodes.UnsafePath or ReasonCodes.AccessDenied ? code
            : code is ReasonCodes.ComponentFailed or ReasonCodes.UserCancelled or ReasonCodes.ContentNotStarted or ReasonCodes.WorkerStartFailed
                ? ReasonCodes.ContentNotStarted : ReasonCodes.ReadIncomplete;
        return new(StatusPresentation.Text(displayCode + ".title", culture), target, detail,
            StatusPresentation.Text(displayCode + ".next", culture), full)
        { ReasonCode = code };
    }
}
