using System.Security.Principal;
using System.Text.Json.Serialization;

namespace SteamSentinel.Core.Models;

public enum RemediationActionType
{
    StopProcess,
    RemoveRegistryValue,
    RemoveScheduledTask,
    RemoveDefenderExclusion,
    QuarantineFile,
    QuarantineDirectory,
    AddProgramFirewallBlock,
    BlockKnownDomains,
    RestoreSecurityControls,
    RollbackIncident,
    DeleteIncident,
    StopHostProcess,
    DisableService,
    RemoveRelatedDefenderExclusion,
    DisableRelatedFirewallRule
}

public sealed class RemediationPlan
{
    [JsonRequired]
    public string SchemaVersion { get; init; } = "1";
    [JsonRequired]
    public Guid PlanId { get; init; } = Guid.NewGuid();
    [JsonRequired]
    public DateTimeOffset CreatedAtUtc { get; init; } = DateTimeOffset.UtcNow;
    [JsonRequired]
    public DateTimeOffset ExpiresAtUtc { get; init; } = DateTimeOffset.UtcNow.AddMinutes(15);
    [JsonRequired]
    public string RequestedBy { get; init; } = Environment.UserName;
    [JsonRequired]
    public string RequestedBySid { get; init; } = WindowsIdentity.GetCurrent().User?.Value ?? string.Empty;
    [JsonRequired]
    public List<RemediationAction> Actions { get; init; } = [];
}

public sealed class RemediationAction
{
    public Guid ActionId { get; init; } = Guid.NewGuid();
    public RemediationActionType Type { get; init; }
    public string DisplayName { get; init; } = string.Empty;
    public string Target { get; init; } = string.Empty;
    public string? ExpectedSha256 { get; init; }
    public string? ExpectedValueData { get; init; }
    public bool IsKnownMalware { get; init; }
    public int ConfidenceScore { get; init; }
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
    public List<string> Domains { get; init; } = [];
    public string? IncidentId { get; init; }
    public string? TaskName { get; init; }
}

public sealed class RemediationRunResult
{
    public Guid PlanId { get; init; }
    public Guid IncidentId { get; init; } = Guid.NewGuid();
    public DateTimeOffset StartedAtUtc { get; init; } = DateTimeOffset.UtcNow;
    public DateTimeOffset? CompletedAtUtc { get; set; }
    public bool Success { get; set; }
    public List<RemediationActionResult> Actions { get; init; } = [];
    public List<string> Errors { get; init; } = [];
    public string? ManifestPath { get; set; }
    // Success remains the legacy action-execution outcome, never a clean-machine assertion.
    public RemediationVerificationStatus VerificationStatus { get; set; }
    public string VerificationSummary { get; set; } = string.Empty;
    public DateTimeOffset? VerificationCompletedAtUtc { get; set; }
}

public sealed class RemediationActionResult
{
    public Guid ActionId { get; init; }
    public RemediationActionType Type { get; init; }
    public string Target { get; init; } = string.Empty;
    public bool Success { get; set; }
    public string Message { get; set; } = string.Empty;
    public RemediationVerificationStatus VerificationStatus { get; set; }
    public string VerificationSummary { get; set; } = string.Empty;
    public List<RemediationVerificationObservation> Verifications { get; init; } = [];
    public FileOccupancyResult? Occupancy { get; set; }
}

public enum RemediationVerificationStatus
{
    NotChecked, Verified, NoResidual, PendingReboot, Unknown, ResidualDetected, Reappeared
}

public sealed class RemediationVerificationObservation
{
    public int Pass { get; init; }
    public DateTimeOffset CheckedAtUtc { get; init; } = DateTimeOffset.UtcNow;
    public RemediationVerificationStatus Status { get; init; }
    public string Message { get; init; } = string.Empty;
}

public enum FileOccupancyStatus { Unknown, NoLocksReported, LocksReported }

public sealed class FileOccupancyResult
{
    public FileOccupancyStatus Status { get; init; }
    public List<FileOccupancyProcess> Processes { get; init; } = [];
    public string Diagnostic { get; init; } = string.Empty;
    public bool Truncated { get; init; }
}

public sealed class FileOccupancyProcess
{
    public int ProcessId { get; init; }
    public string ProcessName { get; init; } = string.Empty;
    public DateTimeOffset? StartedAtUtc { get; init; }
    public string? ServiceName { get; init; }
}

public sealed class QuarantineManifest
{
    public string SchemaVersion { get; init; } = "1";
    public Guid IncidentId { get; init; }
    public Guid PlanId { get; init; }
    public Guid TrustId { get; init; }
    public string RequestedBySid { get; init; } = string.Empty;
    public DateTimeOffset CreatedAtUtc { get; init; } = DateTimeOffset.UtcNow;
    public DateTimeOffset MachineBootTimeUtc { get; init; } = DateTimeOffset.UtcNow - TimeSpan.FromMilliseconds(Environment.TickCount64);
    public List<QuarantineRecord> Records { get; init; } = [];
}

public sealed class QuarantineRecord
{
    public Guid ActionId { get; init; }
    public RemediationActionType Type { get; init; }
    public string OriginalTarget { get; init; } = string.Empty;
    public string? QuarantinedPath { get; init; }
    public string? Sha256 { get; init; }
    public string? RegistryHive { get; init; }
    public string? RegistryView { get; init; }
    public string? RegistryKey { get; init; }
    public string? RegistryValueName { get; init; }
    public string? RegistryValueData { get; init; }
    public int? RegistryValueKind { get; init; }
    public string? FirewallRuleName { get; init; }
    public string? TaskName { get; init; }
    public string? DefenderExclusionPath { get; init; }
    public List<string> HostsDomains { get; init; } = [];
    public bool RolledBack { get; set; }
    public bool MutationConfirmed { get; set; }
    public string? RelatedFilePath { get; init; }
    public string? RelatedFileSha256 { get; init; }
    public string? ConfigurationKind { get; init; }
    public string? ConfigurationSnapshot { get; init; }
    // Broker-computed proof, never copied from request confidence or a finding label.
    public string? VerifiedContentRuleId { get; init; }
}
