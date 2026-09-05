namespace SteamSentinel.Core.Models;

public static class WorkerMessageTypes
{
    public const string Start = "start";
    public const string Ready = "ready";
    public const string Progress = "progress";
    public const string PasswordRequest = "password-request";
    public const string PasswordResponse = "password-response";
    public const string Completed = "completed";
    public const string Failed = "failed";
    public const string Cancel = "cancel";
    public const string Checkpoint = "checkpoint";
}

public sealed class WorkerMessage
{
    public string Type { get; init; } = string.Empty;
    public ScanOptions? Options { get; init; }
    public ScanProgress? Progress { get; init; }
    public ArchivePasswordRequest? PasswordRequest { get; init; }
    public ArchivePasswordResponse? PasswordResponse { get; init; }
    public ScanReport? Report { get; init; }
    public string? Error { get; init; }
    public string? Containment { get; init; }
    public ReportBatch? Batch { get; init; }
    public int? BatchCount { get; init; }
    public WorkerDiagnostics? Diagnostics { get; init; }
}

public static class ScanReportMerger
{
    public static ScanReport Merge(ScanReport first, ScanReport second)
    {
        ScanReport merged = new()
        {
            ProductVersion = first.ProductVersion,
            BuildIdentity = first.BuildIdentity,
            Mode = first.Mode,
            StartedAtUtc = first.StartedAtUtc < second.StartedAtUtc ? first.StartedAtUtc : second.StartedAtUtc,
            RuleSetVersion = first.RuleSetVersion,
            CompletedAtUtc = new[] { first.CompletedAtUtc, second.CompletedAtUtc }.Max(),
            Coverage = first.Coverage == ScanCoverage.Partial || second.Coverage == ScanCoverage.Partial
                ? ScanCoverage.Partial
                : first.Coverage == ScanCoverage.Skipped || second.Coverage == ScanCoverage.Skipped
                    ? ScanCoverage.Skipped
                    : ScanCoverage.Complete
        };
        merged.ContentScanSettings = second.ContentScanSettings ?? first.ContentScanSettings;
        merged.WorkerDiagnostics = second.WorkerDiagnostics ?? first.WorkerDiagnostics;
        merged.Roots.AddRange(first.Roots.Concat(second.Roots).Distinct(StringComparer.OrdinalIgnoreCase));
        merged.CandidateRoots.AddRange(first.CandidateRoots.Concat(second.CandidateRoots).Distinct(StringComparer.OrdinalIgnoreCase));
        merged.ContentSources.AddRange(first.ContentSources.Concat(second.ContentSources).Distinct(StringComparer.OrdinalIgnoreCase));
        merged.ScopeNotes.AddRange(first.ScopeNotes.Concat(second.ScopeNotes).Distinct(StringComparer.Ordinal));
        merged.CoverageNotes.AddRange(first.CoverageNotes.Concat(second.CoverageNotes).Distinct(StringComparer.Ordinal));
        // Preserve independently scanned occurrences; immutable groups cannot be changed by merging.
        merged.CoverageAggregates.AddRange(first.CoverageAggregates.Concat(second.CoverageAggregates));
        merged.Findings.AddRange(first.Findings.Concat(second.Findings));
        merged.RootSummaries.AddRange(first.RootSummaries.Concat(second.RootSummaries));
        merged.Metrics.QuickPriorityBytesHashed = first.Metrics.QuickPriorityBytesHashed + second.Metrics.QuickPriorityBytesHashed;
        merged.Metrics.MediaStructuresChecked = first.Metrics.MediaStructuresChecked + second.Metrics.MediaStructuresChecked;
        merged.Findings.Sort((left, right) =>
        {
            int severity = right.Severity.CompareTo(left.Severity);
            return severity != 0 ? severity : right.Score.CompareTo(left.Score);
        });
        merged.Metrics.FilesVisited = first.Metrics.FilesVisited + second.Metrics.FilesVisited;
        merged.Metrics.BytesHashed = first.Metrics.BytesHashed + second.Metrics.BytesHashed;
        merged.Metrics.ArchiveEntriesVisited = first.Metrics.ArchiveEntriesVisited + second.Metrics.ArchiveEntriesVisited;
        merged.Metrics.ArchiveBytesExpanded = first.Metrics.ArchiveBytesExpanded + second.Metrics.ArchiveBytesExpanded;
        merged.Metrics.ProcessesVisited = first.Metrics.ProcessesVisited + second.Metrics.ProcessesVisited;
        merged.Metrics.PersistenceItemsVisited = first.Metrics.PersistenceItemsVisited + second.Metrics.PersistenceItemsVisited;
        merged.Metrics.WorkshopItemsVisited = first.Metrics.WorkshopItemsVisited + second.Metrics.WorkshopItemsVisited;
        return merged;
    }
}
