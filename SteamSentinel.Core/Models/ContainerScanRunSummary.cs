namespace SteamSentinel.Core.Models;

/// <summary>
/// Original scan-round identity and accounting retained when reports are combined.
/// A per-round limit is never a combined-report resource limit.
/// </summary>
public sealed class ContainerScanRunSummary
{
    public const int MaximumRuns = 64;
    public const int MaximumRoots = 512;
    public Guid ScanId { get; init; }
    public ScanMode Mode { get; init; }
    public DateTimeOffset StartedAtUtc { get; init; }
    public DateTimeOffset? CompletedAtUtc { get; init; }
    public bool Complete { get; init; }
    public List<string> Roots { get; init; } = [];
    public List<Guid> NodeIds { get; init; } = [];
    public ContainerResourceLimits Limits { get; init; } = new();
    public ContainerResourceSnapshot Resources { get; init; } = new();
    public string? RecoveryOutputDirectory { get; init; }
}
