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
    ReviewOnly,
    StopHostProcess,
    DisableService,
    RemoveRelatedDefenderExclusion,
    DisableRelatedFirewallRule
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
    public DateTimeOffset? ProcessStartedAtUtc { get; init; }
    public string? RelatedFilePath { get; init; }
    public string? RelatedFileSha256 { get; init; }
    public string? ConfigurationKind { get; init; }
    public string? ConfigurationSnapshot { get; init; }
    public string? RegistryHive { get; init; }
    public string? RegistryView { get; init; }
    public string? RegistryKey { get; init; }
    public string? RegistryValueName { get; init; }
    public string? WorkshopId { get; init; }
    public string? AppId { get; set; }
    public string? SourceKind { get; set; }
    public bool IsKnownMalware { get; init; }
    public bool CanRemediate { get; init; }
    public IReadOnlyList<SuggestedActionKind> SuggestedActions { get; init; } = [];
    public DateTimeOffset DetectedAtUtc { get; init; } = DateTimeOffset.UtcNow;
}

public sealed class ScanMetrics
{
    public long FilesVisited { get; set; }
    public long BytesHashed { get; set; }
    public long QuickPriorityBytesHashed { get; set; }
    public long MediaStructuresChecked { get; set; }
    public long ArchiveEntriesVisited { get; set; }
    public long ArchiveBytesExpanded { get; set; }
    public long ProcessesVisited { get; set; }
    public long PersistenceItemsVisited { get; set; }
    public long WorkshopItemsVisited { get; set; }
}

public sealed class ScanReport
{
    public string ProductVersion { get; init; } = ProductInfo.Version;
    public string BuildIdentity { get; init; } = ProductInfo.BuildIdentity;
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
    public List<CoverageAggregate> CoverageAggregates { get; init; } = [];
    public List<Finding> Findings { get; init; } = [];
    public List<ScanRootSummary> RootSummaries { get; init; } = [];
    public List<string> CandidateRoots { get; init; } = [];
    public List<string> ContentSources { get; init; } = [];
    public ScanMetrics Metrics { get; init; } = new();
    public ScanOptions? ContentScanSettings { get; set; }
    public WorkerDiagnostics? WorkerDiagnostics { get; set; }

    [JsonIgnore]
    public FindingSeverity HighestSeverity => Findings.Where(f => f.Category != FindingCategory.Coverage)
        .Select(f => f.Severity).DefaultIfEmpty(FindingSeverity.Information).Max();

    public int RiskFindingCount => Findings.Count(f => f.Category != FindingCategory.Coverage);
    public string ExecutionStatus => Findings.Any(f => f.RuleId == "CONTENT-SCAN-FAILED") ? "内容检查失败，已保留可用结果" :
        CoverageNotes.Any(n => n.Contains("取消")) ? "扫描已取消，已保留可用结果" :
        CompletedAtUtc is null ? "尚未结束" :
        Coverage == ScanCoverage.Complete ? "本次扫描已完成" : "本次扫描已结束，仍有未检查内容";
    public List<string> ScopeNotes { get; init; } = [];
}

public sealed record ScanRootSummary(string Path, ScanCoverage Coverage, int KnownThreats, int ActionableFindings, long FilesVisited);

public sealed class ScanOptions
{
    public ScanMode Mode { get; init; } = ScanMode.Quick;
    public bool IncludeSystem { get; init; } = true;
    public bool IncludeSteam { get; init; } = true;
    public bool IncludeWorkshop { get; init; } = true;
    public bool IncludeRelatedContent { get; init; }
    public bool IncludeDownloadLocations { get; init; }
    public bool IncludeExecutionHistory { get; init; }
    public List<string> RelatedRoots { get; init; } = [];
    public List<string> WorkshopAppIds { get; init; } = [];
    public long MaximumContentBytes { get; init; } = long.MaxValue;
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
    ArchivePasswordReuseScope ReuseScope = ArchivePasswordReuseScope.CurrentOnly,
    IReadOnlyList<string>? Passwords = null,
    bool SkipAllEncrypted = false);

public static class ArchivePasswordInput
{
    public const int MaximumPasswords = 16;
    public const int MaximumPasswordCharacters = 1024;

    /// <summary>
    /// Validates an untrusted provider response and returns its effective password candidates.
    /// A non-empty ordered batch takes precedence over the legacy single-password field.
    /// Password text is never trimmed or included in validation errors.
    /// </summary>
    public static IReadOnlyList<string> ValidateAndGetPasswords(ArchivePasswordResponse response)
    {
        ArgumentNullException.ThrowIfNull(response);
        if (!Enum.IsDefined(response.ReuseScope))
            throw new ArgumentException("密码复用范围值无效。", nameof(response));
        if (response.Password is { Length: > MaximumPasswordCharacters })
            throw new ArgumentException($"单个密码不能超过 {MaximumPasswordCharacters} 个字符。", nameof(response));

        if (response.Passwords is { } supplied)
        {
            if (supplied.Count > MaximumPasswords)
                throw new ArgumentException($"一次最多可以提供 {MaximumPasswords} 个密码。", nameof(response));
            List<string> ordered = [];
            HashSet<string> seen = new(StringComparer.Ordinal);
            for (int index = 0; index < supplied.Count; index++)
            {
                string? value = supplied[index];
                if (string.IsNullOrEmpty(value)) continue;
                if (value.Length > MaximumPasswordCharacters)
                    throw new ArgumentException($"单个密码不能超过 {MaximumPasswordCharacters} 个字符。", nameof(response));
                if (seen.Add(value)) ordered.Add(value);
            }
            if (ordered.Count > 0) return ordered;
        }

        return string.IsNullOrEmpty(response.Password) ? [] : [response.Password];
    }
}

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
    public static string BuildIdentity { get; } = typeof(ProductInfo).Assembly
        .GetCustomAttributes(typeof(System.Reflection.AssemblyInformationalVersionAttribute), false)
        .OfType<System.Reflection.AssemblyInformationalVersionAttribute>().SingleOrDefault()?.InformationalVersion
        ?? "unknown";
    public static string Version { get; } = BuildIdentity.Split('+')[0];
}
