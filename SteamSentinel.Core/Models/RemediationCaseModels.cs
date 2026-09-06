namespace SteamSentinel.Core.Models;

public enum CaseSessionRequirement { NewBoot, NewInteractiveLogon, NewBootOrInteractiveLogon }
public enum CaseSessionTransition { Unknown, SameSession, NewBoot, NewInteractiveLogon }
public enum CaseReverificationState
{
    NotChecked, ExecutionUncertain, AwaitingSessionChange, SessionUnknown,
    Incomplete, ResidualDetected, Reappeared, SelectedTargetsVerified
}

/// <summary>A user-owned record for recovery and read-only review; never Broker authorization.</summary>
public sealed class RemediationCaseRecord
{
    public int SchemaVersion { get; init; } = 1;
    public Guid CaseId { get; init; } = Guid.NewGuid();
    public string UserSid { get; init; } = string.Empty;
    public DateTimeOffset CreatedAtUtc { get; init; } = DateTimeOffset.UtcNow;
    public DateTimeOffset UpdatedAtUtc { get; set; } = DateTimeOffset.UtcNow;
    public long Revision { get; set; }
    public ScanReport? OriginalScan { get; set; }
    public ScanOptions? OriginalContentSettings { get; set; }
    public RemediationBatchSession? BatchSession { get; set; }
    public List<RemediationPlan> Plans { get; init; } = [];
    public List<RemediationRunResult> ExecutionResults { get; init; } = [];
    public List<Guid> PendingPlanIds { get; init; } = [];
    public CaseSessionObservation? BaselineSession { get; set; }
    public CaseSessionRequirement SessionRequirement { get; set; } = CaseSessionRequirement.NewBootOrInteractiveLogon;
    public bool RequireContentFollowUp { get; set; } = true;
    public bool RequireRelatedFollowUp { get; set; } = true;
    public List<CaseVerificationEpisode> Episodes { get; init; } = [];
    public List<string> Notes { get; init; } = [];
    public bool IsWholeMachineClear => false;
    public bool WriterIdentified => false;
    public bool MayReplaySavedPlans => false;
    public string Authority => "UserOwnedReadOnlyRecordNotBrokerAuthorization";
    public string WriterSummary => "写入来源尚未证实；启动、加载、同路径和同机配置观察不能代替写入证据。";
}

public sealed class CaseSessionObservation
{
    public DateTimeOffset CapturedAtUtc { get; init; } = DateTimeOffset.UtcNow;
    public string UserSid { get; init; } = string.Empty;
    public string MachineName { get; init; } = Environment.MachineName;
    public DiagnosticReadStatus IdentityStatus { get; init; } = DiagnosticReadStatus.NotChecked;
    public DiagnosticReadStatus BootStatus { get; init; } = DiagnosticReadStatus.NotChecked;
    public string? BootIdentity { get; init; }
    public DateTimeOffset? BootStartedAtUtc { get; init; }
    public long? BootEventRecordId { get; init; }
    public DiagnosticReadStatus LogonStatus { get; init; } = DiagnosticReadStatus.NotChecked;
    public string? InteractiveLogonId { get; init; }
    public DateTimeOffset? InteractiveLogonStartedAtUtc { get; init; }
    public int? LogonType { get; init; }
    public int? SessionId { get; init; }
    public string Detail { get; init; } = string.Empty;
}

public sealed class CaseVerificationEpisode
{
    public Guid EpisodeId { get; init; } = Guid.NewGuid();
    public DateTimeOffset StartedAtUtc { get; init; } = DateTimeOffset.UtcNow;
    public DateTimeOffset? CompletedAtUtc { get; set; }
    public CaseSessionObservation? Session { get; set; }
    public CaseSessionTransition Transition { get; set; } = CaseSessionTransition.Unknown;
    public CaseReverificationState State { get; set; } = CaseReverificationState.NotChecked;
    public int SelectedActionCount { get; set; }
    public List<CaseActionVerification> Targets { get; init; } = [];
    public List<DiagnosticCheck> Checks { get; init; } = [];
    public ScanReport? ContentFollowUp { get; set; }
    public ScanReport? RelatedFollowUp { get; set; }
    public string Summary { get; set; } = string.Empty;
    public bool WriterIdentified => false;
    public bool IsWholeMachineClear => false;
}

public sealed class CaseActionVerification
{
    public Guid PlanId { get; init; }
    public Guid ActionId { get; init; }
    public Guid? IncidentId { get; init; }
    public RemediationActionType Type { get; init; }
    public string Target { get; init; } = string.Empty;
    public bool ExecutionSucceeded { get; init; }
    public DateTimeOffset CheckedAtUtc { get; init; } = DateTimeOffset.UtcNow;
    public RemediationVerificationStatus Status { get; init; } = RemediationVerificationStatus.Unknown;
    public string Message { get; init; } = string.Empty;
    public bool IsOriginalProcessIdentityOnly => Type is RemediationActionType.StopProcess or RemediationActionType.StopHostProcess;
}

public sealed class CaseFollowUpResult
{
    public ScanReport? ContentReport { get; init; }
    public ScanReport? RelatedReport { get; init; }
    public string Detail { get; init; } = string.Empty;
}

public sealed class CaseReverificationLimits
{
    public int MaximumActions { get; init; } = 256;
    public int MaximumEpisodes { get; init; } = 32;
    public TimeSpan ProbeTimeout { get; init; } = TimeSpan.FromSeconds(4);
    public TimeSpan SessionTimeout { get; init; } = TimeSpan.FromSeconds(6);
    public TimeSpan MaximumDuration { get; init; } = TimeSpan.FromMinutes(2);
}

public sealed class RemediationCaseSummary
{
    public Guid CaseId { get; init; }
    public string UserSid { get; init; } = string.Empty;
    public DateTimeOffset UpdatedAtUtc { get; init; }
    public long Revision { get; init; }
    public int PendingExecutionCount { get; init; }
    public int EpisodeCount { get; init; }
    public CaseReverificationState State { get; init; }
    public DiagnosticReadStatus ReadStatus { get; init; } = DiagnosticReadStatus.Complete;
    public string Detail { get; init; } = string.Empty;
}
