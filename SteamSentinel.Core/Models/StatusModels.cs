using System.Text.Json.Serialization;

namespace SteamSentinel.Core.Models;

// Values are append-only. Execution, coverage, severity and post-action verification
// are independent axes; a completed operation is never a clean-machine assertion.
public enum ScanExecutionState { Unknown = 0, NotStarted = 1, Running = 2, Completed = 3, Cancelled = 4, Failed = 5 }
public enum RemediationTargetState
{
    Unknown = 0, NotIncluded = 1, PartiallyIncluded = 2, Ready = 3,
    NotExecuted = 4, Failed = 5, ReviewRequired = 6, Completed = 7
}

/// <summary>Stable machine reasons. Never infer these from localized or OS error text.</summary>
public static class ReasonCodes
{
    public const string Unspecified = "legacy.unspecified";
    public const string UserCancelled = "execution.user_cancelled";
    public const string ComponentFailed = "execution.component_failed";
    public const string WorkerStartFailed = "execution.worker_start_failed";
    public const string ResourceLimit = "coverage.resource_limit";
    public const string AllocationFailed = "execution.allocation_failed";
    public const string SystemIncomplete = "coverage.system_incomplete";
    public const string TrustProxyIncomplete = "coverage.trust_proxy_incomplete";
    public const string ContentNotStarted = "coverage.content_not_started";
    public const string WorkshopSelection = "coverage.workshop_selection";
    public const string ReadBudget = "coverage.read_budget";
    public const string EngineSizeLimit = "coverage.engine_size_limit";
    public const string QuickMedia = "coverage.quick_media_structure";
    public const string QuickContent = "coverage.quick_content_not_hashed";
    public const string ArchiveNotExpanded = "coverage.archive_not_expanded";
    public const string ArchiveEncrypted = "coverage.archive_encrypted";
    public const string AmsiUnavailable = "coverage.amsi_unavailable";
    public const string ReadIncomplete = "coverage.read_incomplete";
    public const string UnsafePath = "coverage.unsafe_path";
    public const string AccessDenied = "coverage.access_denied";
    public const string PlanReady = "remediation.plan_ready";
    public const string ActionsNotIncluded = "remediation.actions_not_included";
    public const string EvidenceUnavailable = "remediation.evidence_unavailable";
    public const string TargetUnavailable = "remediation.target_unavailable";
    public const string ActionFailed = "remediation.action_failed";
    public const string WaitingBatches = "remediation.waiting_batches";
    public const string VerificationIncomplete = "remediation.verification_incomplete";
    public const string ActionsVerified = "remediation.actions_verified";
    public const string PlanExpired = "remediation.plan_expired";
    public const string BatchIncomplete = "remediation.batch_incomplete";
    public const string ExecutionInterrupted = "remediation.execution_interrupted";
    public const string ExecutionOutcomeUnknown = "remediation.outcome_unknown";

    public static string ForFailureType(string? type) => type switch
    {
        nameof(Scanning.ScanResourceLimitException) => ResourceLimit,
        nameof(OutOfMemoryException) => AllocationFailed,
        nameof(OperationCanceledException) or nameof(TaskCanceledException) => UserCancelled,
        nameof(UnauthorizedAccessException) => AccessDenied,
        _ => ComponentFailed
    };

    public static string ForReadStatus(DiagnosticReadStatus status) => status switch
    {
        DiagnosticReadStatus.Cancelled => UserCancelled,
        DiagnosticReadStatus.LimitReached => ResourceLimit,
        DiagnosticReadStatus.AccessDenied => AccessDenied,
        DiagnosticReadStatus.Failed => ComponentFailed,
        _ => ReadIncomplete
    };

    public static string ForRule(string? rule) => rule switch
    {
        "TRUST-PROXY-COVERAGE" or "TRUST-PROXY-DIAGNOSTIC-FAILED" => TrustProxyIncomplete,
        "SYSTEM-SCAN-INCOMPLETE" => SystemIncomplete,
        "QUICK-MEDIA-STRUCTURE" => QuickMedia,
        "QUICK-CONTENT-NOT-HASHED" => QuickContent,
        "QUICK-FILE-SIZE" or "CONTENT-BYTE-BUDGET" => ReadBudget,
        "STRING-ENGINE-SIZE-LIMIT" or "AMSI-ENGINE-SIZE-LIMIT" or "VPET-DECODED-STRING-LIMIT" => EngineSizeLimit,
        "ARCHIVE-NOT-REQUESTED" or "COMPOUND-CONTENT-NOT-EXPANDED" => ArchiveNotExpanded,
        "ARCHIVE-PASSWORD-FAILED" or "ARCHIVE-ENCRYPTED-NOT-SCANNED" or "ARCHIVE-ENCRYPTED-DEFERRED" => ArchiveEncrypted,
        "CONTENT-SCAN-CANCELLED" => UserCancelled,
        "CONTENT-SCAN-FAILED" => ComponentFailed,
        "ARCHIVE-RATIO-LIMIT" or "ARCHIVE-DEPTH-LIMIT" or "ARCHIVE-ENTRY-LIMIT" or "SCAN-COUNT-LIMIT"
            or "ARCHIVE-SIZE-LIMIT" or "ARCHIVE-ATTEMPT-LIMIT" => ResourceLimit,
        "AMSI-UNAVAILABLE" => AmsiUnavailable,
        _ => ReadIncomplete
    };

    public static bool IsValid(string? code) => code is { Length: > 0 and <= 96 } &&
        code.All(c => char.IsAsciiLetterOrDigit(c) || c is '.' or '_' or '-');
}

/// <summary>Display-only template and bounded arguments. Never grants an action.</summary>
public sealed record StatusMessage(string MessageId, IReadOnlyList<string> Arguments)
{
    public static StatusMessage Create(string id, params string[] arguments) => new(id, arguments);
    public void Validate()
    {
        if (!ReasonCodes.IsValid(MessageId) || Arguments is null || Arguments.Count > 8 ||
            Arguments.Any(a => a is null || a.Length > 4096))
            throw new InvalidDataException("Invalid status message descriptor.");
    }
}

[method: JsonConstructor]
public sealed record CoverageNotice(string ReasonCode, string Detail, string? Target = null, StatusMessage? Message = null)
{
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public DisplayMessage? DetailMessage { get => SteamSentinel.Core.Reporting.MessageText.BoundDescriptor(field, Detail); init => field = value; }
    public CoverageNotice(string reasonCode, Reporting.MessageText detail, string? target = null, StatusMessage? message = null)
        : this(reasonCode, detail.OriginalText, target, message) { DetailMessage = detail.Message; }
    [JsonIgnore] public Reporting.MessageText DetailText => new(Detail, DetailMessage);
    [JsonIgnore]
    public long TextCharacters => ReasonCode.Length + Detail.Length + (Target?.Length ?? 0) +
        (Message?.MessageId.Length ?? 0) + (Message?.Arguments.Sum(a => (long)a.Length) ?? 0) + (DetailMessage?.Validate() ?? 0);

    public void Validate()
    {
        if (!ReasonCodes.IsValid(ReasonCode) || Detail is null || Detail.Length > 65536 || Target?.Length > 32768)
            throw new InvalidDataException("Invalid coverage notice.");
        Message?.Validate();
        DetailMessage?.Validate();
    }
}

public static class ScanExecution
{
    public const int SchemaVersion = 1;
    public static ScanExecutionState Combine(ScanExecutionState first, ScanExecutionState second)
    {
        if (!Enum.IsDefined(first) || !Enum.IsDefined(second)) return ScanExecutionState.Unknown;
        foreach (ScanExecutionState state in new[] { ScanExecutionState.Failed, ScanExecutionState.Cancelled,
            ScanExecutionState.Unknown, ScanExecutionState.Running, ScanExecutionState.NotStarted })
            if (first == state || second == state) return state;
        return ScanExecutionState.Completed;
    }

    public static void Set(ScanReport report, ScanExecutionState state, string? reason = null)
    {
        if (!Enum.IsDefined(state) || reason is not null && !ReasonCodes.IsValid(reason))
            throw new ArgumentException("Invalid execution state or reason.");
        report.StatusSchemaVersion = SchemaVersion;
        report.ExecutionState = state;
        report.ExecutionReasonCode = reason;
    }

    public static void AddNotice(ScanReport report, string reason, Reporting.MessageText detail, string? target = null, StatusMessage? message = null)
    {
        CoverageNotice notice = new(reason, detail, target, message);
        notice.Validate();
        report.CoverageNotices.Add(notice);
        report.AddCoverageNote(detail); // Compatibility display only, never a decision input.
    }
}
