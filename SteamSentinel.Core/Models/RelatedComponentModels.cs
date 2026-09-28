using SteamSentinel.Core.Reporting;
namespace SteamSentinel.Core.Models;

/// <summary>Read-only discovery and scan provenance; none of these records authorizes remediation.</summary>
public sealed class RelatedComponentDiagnosticReport
{
    public int SchemaVersion { get; init; } = 1;
    public DateTimeOffset StartedAtUtc { get; init; } = DateTimeOffset.UtcNow;
    public DateTimeOffset? CompletedAtUtc { get; set; }
    public string TargetUserSid { get; init; } = string.Empty;
    public RelatedComponentLimits? AppliedLimits { get; init; }
    public List<RelatedSourceObservation> Sources { get; init; } = [];
    public List<RelatedHostObservation> Hosts { get; init; } = [];
    public List<RelatedComponentCandidate> Candidates { get; init; } = [];
    public List<DiagnosticRelation> Relations { get; init; } = [];
    public List<DiagnosticCheck> Checks { get; init; } = [];
    public List<RelatedScanRound> Rounds { get; init; } = [];
}

public sealed partial class RelatedSourceObservation
{
    public string Id { get; init; } = Guid.NewGuid().ToString("N");
    public string Kind { get; init; } = string.Empty;
    public string Scope { get; init; } = string.Empty;
    public string Location { get; init; } = string.Empty;
    public string RawCommand { get; init; } = string.Empty;
    public string? WorkingDirectory { get; init; }
    public string? UserSid { get; init; }
    public DiagnosticReadStatus Status { get; set; }
    public string Detail { get; set; } = string.Empty;
    public List<string> ResolvedTargets { get; init; } = [];
}

public sealed partial class RelatedHostObservation
{
    public string Id { get; init; } = Guid.NewGuid().ToString("N");
    public int ProcessId { get; init; }
    public DateTimeOffset? StartedAtUtc { get; init; }
    public string ImagePath { get; init; } = string.Empty;
    public string? CommandLine { get; init; }
    public string? WorkingDirectory { get; init; }
    public string? ImageSha256 { get; set; }
    public string SignatureStatus { get; set; } = "NotChecked";
    public string SignatureDetail { get; set; } = MessageText.Create("Backend.Core.RelatedComponentModels.SignatureDetail.01");
    public DiagnosticReadStatus Status { get; set; }
    public string Detail { get; set; } = string.Empty;
    public List<string> SourceObservationIds { get; init; } = [];
}

public sealed partial class RelatedComponentCandidate
{
    public string Id { get; init; } = Guid.NewGuid().ToString("N");
    public string Path { get; init; } = string.Empty;
    public string Reason { get; set; } = string.Empty;
    public DiagnosticReadStatus Status { get; set; } = DiagnosticReadStatus.NotChecked;
    public string Detail { get; set; } = string.Empty;
    public string? Sha256 { get; set; }
    public long? Length { get; set; }
    public DateTimeOffset? VerifiedAtUtc { get; set; }
    public DiagnosticReadStatus ContentStatus { get; set; } = DiagnosticReadStatus.NotChecked;
    public string ContentDetail { get; set; } = MessageText.Create("Backend.Core.RelatedComponentModels.ContentDetail.01");
    public List<string> SourceObservationIds { get; init; } = [];
    public List<string> HostObservationIds { get; init; } = [];
    public List<string> EvidenceObservationIds { get; init; } = [];
}

public sealed partial class RelatedScanRound
{
    public int Number { get; init; }
    public DateTimeOffset StartedAtUtc { get; init; } = DateTimeOffset.UtcNow;
    public DateTimeOffset? CompletedAtUtc { get; set; }
    public DiagnosticReadStatus Status { get; set; }
    public long BytesRead { get; set; }
    public long? MaximumBytes { get; init; }
    public List<string> CandidateIds { get; init; } = [];
    public string Detail { get; set; } = string.Empty;
}

public sealed class RelatedComponentLimits
{
    public int MaximumRounds { get; init; } = 2;
    public int MaximumSources { get; init; } = 512;
    public int MaximumProcesses { get; init; } = 2048;
    public int MaximumHosts { get; init; } = 32;
    public int MaximumModulesPerHost { get; init; } = 256;
    public int MaximumCandidates { get; init; } = 128;
    public int MaximumScriptBytes { get; init; } = 256 * 1024;
    public long MaximumTotalScriptBytes { get; init; } = 8L * 1024 * 1024;
    public long MaximumFileBytes { get; init; } = 256L * 1024 * 1024;
    public long MaximumTotalBytes { get; init; } = 1024L * 1024 * 1024;
    public TimeSpan MaximumDiscoveryDuration { get; init; } = TimeSpan.FromSeconds(15);
    public TimeSpan MaximumDuration { get; init; } = TimeSpan.FromSeconds(90);
}

public sealed class RelatedComponentDiscoveryRequest
{
    public string TargetUserSid { get; init; } = string.Empty;
    public IReadOnlyList<string> SeedPaths { get; init; } = [];
    public IReadOnlyList<int> SeedProcessIds { get; init; } = [];
    public IReadOnlyList<string> ExcludedRoots { get; init; } = [];
}

public enum RelatedEvidenceTier { Observation, RelatedRisk, ConfirmedTarget }
