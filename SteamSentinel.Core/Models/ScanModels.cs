using System.Text.Json.Serialization;

namespace SteamSentinel.Core.Models;

public enum FindingSeverity
{
    Information = 0,
    Low = 1,
    Medium = 2,
    High = 3,
    Critical = 4
}

public enum FindingCategory
{
    File,
    Archive,
    Process,
    Persistence,
    Steam,
    WallpaperEngine,
    Network,
    Certificate,
    SecurityControl,
    Coverage
}

public enum ScanCoverage
{
    Complete,
    Partial,
    Skipped
}

public enum ScanMode
{
    Quick,
    Full,
    Custom
}

public enum SuggestedActionKind
{
    None,
    StopProcess,
    RemoveRegistryValue,
    RemoveScheduledTask,
    RemoveDefenderExclusion,
    QuarantineFile,
    QuarantineDirectory,
    AddProgramFirewallBlock,
    BlockKnownDomains,
    RestoreSecurityControls,
    ReviewOnly
}

public sealed class Finding
{
    public string Id { get; init; } = Guid.NewGuid().ToString("N");
    public string RuleId { get; init; } = string.Empty;
    public FindingCategory Category { get; init; }
    public FindingSeverity Severity { get; init; }
    public int Score { get; init; }
    public string Title { get; init; } = string.Empty;
    public string Description { get; init; } = string.Empty;
    public string Target { get; init; } = string.Empty;
    public string Evidence { get; init; } = string.Empty;
    public string? Sha256 { get; init; }
    public string? ContentPath { get; set; }
    public string? TargetSha256 { get; set; }
    public int? ProcessId { get; init; }
    public string? RegistryHive { get; init; }
    public string? RegistryView { get; init; }
    public string? RegistryKey { get; init; }
    public string? RegistryValueName { get; init; }
    public string? WorkshopId { get; init; }
    public bool IsKnownMalware { get; init; }
    public bool CanRemediate { get; init; }
    public IReadOnlyList<SuggestedActionKind> SuggestedActions { get; init; } = [];
    public DateTimeOffset DetectedAtUtc { get; init; } = DateTimeOffset.UtcNow;
}

public sealed class ScanMetrics
{
    public long FilesVisited { get; set; }
    public long BytesHashed { get; set; }
    public long ArchiveEntriesVisited { get; set; }
    public long ArchiveBytesExpanded { get; set; }
    public long ProcessesVisited { get; set; }
    public long PersistenceItemsVisited { get; set; }
    public long WorkshopItemsVisited { get; set; }
}

public sealed class ScanReport
{
    public string ProductVersion { get; init; } = ProductInfo.Version;
    public string RuleSetVersion { get; set; } = string.Empty;
    public Guid ScanId { get; init; } = Guid.NewGuid();
    public DateTimeOffset StartedAtUtc { get; init; } = DateTimeOffset.UtcNow;
    public DateTimeOffset? CompletedAtUtc { get; set; }
    public string MachineName { get; init; } = Environment.MachineName;
    public string UserName { get; init; } = Environment.UserName;
    public ScanMode Mode { get; init; }
    public ScanCoverage Coverage { get; set; } = ScanCoverage.Complete;
    public List<string> Roots { get; init; } = [];
    public List<string> CoverageNotes { get; init; } = [];
    public List<Finding> Findings { get; init; } = [];
    public List<ScanRootSummary> RootSummaries { get; init; } = [];
    public ScanMetrics Metrics { get; init; } = new();

    [JsonIgnore]
    public FindingSeverity HighestSeverity => Findings.Count == 0
        ? FindingSeverity.Information
        : Findings.Max(f => f.Severity);
}

public sealed record ScanRootSummary(string Path, ScanCoverage Coverage, int KnownThreats, int ActionableFindings, long FilesVisited);

public sealed class ScanOptions
{
    public ScanMode Mode { get; init; } = ScanMode.Quick;
    public bool IncludeSystem { get; init; } = true;
    public bool IncludeSteam { get; init; } = true;
    public bool IncludeWorkshop { get; init; } = true;
    public bool InspectArchives { get; init; } = true;
    public bool UseAmsi { get; init; } = true;
    public bool HashEveryFile { get; init; }
    public int MaximumArchiveDepth { get; init; } = 4;
    public long MaximumEntryBytes { get; init; } = 256L * 1024 * 1024;
    public long MaximumExpandedBytes { get; init; } = 2L * 1024 * 1024 * 1024;
    public int MaximumArchiveEntries { get; init; } = 20_000;
    public double MaximumCompressionRatio { get; init; } = 500;
    public int MaximumFiles { get; init; } = 200_000;
    public List<string> CustomRoots { get; init; } = [];
    public List<string> ExcludedRoots { get; init; } = [];
}

public sealed record ScanProgress(
    string Stage,
    string CurrentItem,
    long Completed,
    long? Total,
    string Message);

public sealed record ArchivePasswordRequest(
    string RequestId,
    string ArchivePath,
    string ArchiveSha256,
    string Format,
    int Depth,
    string? WorkshopId,
    string Reason,
    ArchivePasswordReuseScope PreferredReuseScope = ArchivePasswordReuseScope.ArchiveTree,
    ArchivePasswordPromptKind PromptKind = ArchivePasswordPromptKind.Needed);

public sealed record ArchivePasswordResponse(
    string RequestId,
    bool Cancelled,
    string? Password,
    bool ReuseForSession,
    ArchivePasswordReuseScope ReuseScope = ArchivePasswordReuseScope.CurrentOnly);

public enum ArchivePasswordReuseScope { CurrentOnly, ArchiveTree, Session }

public enum ArchivePasswordPromptKind { Needed, CachedPasswordFailed, EnteredPasswordFailed, RepeatedPassword }

public interface IArchivePasswordProvider
{
    Task<ArchivePasswordResponse> RequestPasswordAsync(
        ArchivePasswordRequest request,
        CancellationToken cancellationToken);
}

public sealed class NullPasswordProvider : IArchivePasswordProvider
{
    public Task<ArchivePasswordResponse> RequestPasswordAsync(
        ArchivePasswordRequest request,
        CancellationToken cancellationToken) =>
        Task.FromResult(new ArchivePasswordResponse(request.RequestId, true, null, false));
}

public static class ProductInfo
{
    public const string Name = "SteamSentinel Steam 红信安全工具";
    public const string Version = "0.1.10";
}
