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
    DeleteIncident
}

public sealed class RemediationPlan
{
    public string SchemaVersion { get; init; } = "1";
    public Guid PlanId { get; init; } = Guid.NewGuid();
    public DateTimeOffset CreatedAtUtc { get; init; } = DateTimeOffset.UtcNow;
    public DateTimeOffset ExpiresAtUtc { get; init; } = DateTimeOffset.UtcNow.AddMinutes(15);
    public string RequestedBy { get; init; } = Environment.UserName;
    public List<RemediationAction> Actions { get; init; } = [];
}

public sealed class RemediationAction
{
    public Guid ActionId { get; init; } = Guid.NewGuid();
    public RemediationActionType Type { get; init; }
    public string DisplayName { get; init; } = string.Empty;
    public string Target { get; init; } = string.Empty;
    public string? ExpectedSha256 { get; init; }
    public int? ProcessId { get; init; }
    public string? RegistryHive { get; init; }
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
}

public sealed class RemediationActionResult
{
    public Guid ActionId { get; init; }
    public RemediationActionType Type { get; init; }
    public string Target { get; init; } = string.Empty;
    public bool Success { get; set; }
    public string Message { get; set; } = string.Empty;
}

public sealed class QuarantineManifest
{
    public string SchemaVersion { get; init; } = "1";
    public Guid IncidentId { get; init; }
    public Guid PlanId { get; init; }
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
    public string? RegistryKey { get; init; }
    public string? RegistryValueName { get; init; }
    public string? RegistryValueData { get; init; }
    public int? RegistryValueKind { get; init; }
    public string? FirewallRuleName { get; init; }
    public string? TaskName { get; init; }
    public string? DefenderExclusionPath { get; init; }
    public List<string> HostsDomains { get; init; } = [];
    public bool RolledBack { get; set; }
}
