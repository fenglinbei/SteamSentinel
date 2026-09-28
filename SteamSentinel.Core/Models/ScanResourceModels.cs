using System.Text.Json.Serialization;

namespace SteamSentinel.Core.Models;

public enum ScanPerformanceMode { Automatic, LowImpact, HighThroughput }
public enum ResourceDecisionKind { Skip, Approve, Stop }
public enum ResourceAssessmentKind { EstimatedAvailable, Insufficient, Unknown }
public enum ScanResourcePhase { Running, AwaitingDecision, Finished }

public sealed record ScanMachineResources(long AvailableMemoryBytes, long CommitHeadroomBytes,
    long TotalMemoryBytes, long TemporaryFreeBytes, int LogicalProcessors, DateTimeOffset CapturedAtUtc, string TemporaryVolume = "")
{
    public bool IsUsable => AvailableMemoryBytes >= 0 && CommitHeadroomBytes >= 0 && TotalMemoryBytes > 0 && TemporaryFreeBytes >= 0;
}

public sealed record ScanLimitRequest(string RequestId, string LimitKey, long CurrentLimit, long RequiredMinimum,
    long Used, bool DemandKnown, string Target, long PrivateMemoryBytes, long TemporaryBytes, long WorkBytes, long ExpandedBytes = 0)
{
    public void Validate()
    {
        if (!Guid.TryParseExact(RequestId, "N", out _) || LimitKey is null || LimitKey.Length > 100 ||
            Target is null || Target.Length > 2048 || CurrentLimit < 0 || RequiredMinimum <= CurrentLimit ||
            Used < 0 || PrivateMemoryBytes < 0 || TemporaryBytes < 0 || WorkBytes < 0 || ExpandedBytes < 0)
            throw new InvalidDataException("Invalid resource request.");
        _ = Scanning.ScanLimitAccess.Definition(LimitKey);
    }
}

public sealed record ScanLimitChange(string LimitKey, long Before, long After);
public sealed record ScanLimitResponse(string RequestId, ResourceDecisionKind Decision, List<ScanLimitChange> Changes, string? ReasonCode = null);
public sealed record ScanResourceProposal(ScanLimitRequest Request, ScanMachineResources Machine,
    ResourceAssessmentKind Assessment, string ReasonCode, List<ScanLimitChange> Changes,
    long AdditionalTemporaryBytes, long EstimatedPrivateBytes, long ReservedDiskBytes = 1073741824);
public sealed record ScanResourceDecision(ScanLimitRequest Request, ResourceDecisionKind Decision,
    List<ScanLimitChange> Changes, DateTimeOffset DecidedAtUtc, string? ReasonCode = null);

public static class ResourceDecisionReasons
{
    public static bool IsValid(string? code) => code is null or "resource.user_approved" or "resource.user_kept_limits" or
        "resource.user_stopped" or "resource.capacity_changed" or "resource.no_callback";
    public static string For(ResourceDecisionKind decision) => decision switch
    { ResourceDecisionKind.Approve => "resource.user_approved", ResourceDecisionKind.Stop => "resource.user_stopped", _ => "resource.user_kept_limits" };
}

public sealed class ScanResourceAudit
{
    public const int MaximumDecisions = 64;
    public const int MaximumHistoryDecisions = 4096;
    public int SchemaVersion { get; init; } = 1;
    public ScanMachineResources? Preflight { get; set; }
    public ScanResourcePhase Phase { get; set; }
    public int PeakParallelFiles { get; set; } = 1;
    public long WaitingMilliseconds { get; set; }
    public List<ScanResourceDecision> Decisions { get; init; } = [];
    public void Validate()
    {
        if (SchemaVersion != 1 || !Enum.IsDefined(Phase) || PeakParallelFiles is < 1 or > 4 ||
            WaitingMilliseconds < 0 || Decisions is null || Decisions.Count > MaximumHistoryDecisions ||
            Decisions.Any(d => d is null || d.Request is null) ||
            Decisions.Select(d => d.Request.RequestId).Distinct().Count() != Decisions.Count ||
            Preflight is { } machine && (machine.AvailableMemoryBytes < -1 || machine.CommitHeadroomBytes < -1 ||
                machine.TotalMemoryBytes < -1 || machine.TemporaryFreeBytes < -1 || machine.LogicalProcessors is < 1 or > 65536 ||
                machine.TemporaryVolume is null || machine.TemporaryVolume.Length > 512))
            throw new InvalidDataException("Invalid resource audit.");
        foreach (ScanResourceDecision decision in Decisions)
        {
            decision.Request.Validate();
            if (!Enum.IsDefined(decision.Decision) || !ResourceDecisionReasons.IsValid(decision.ReasonCode) || decision.Changes is null || decision.Changes.Count > 8 ||
                decision.Changes.Any(c => c is null) || decision.Changes.Select(c => c.LimitKey).Distinct().Count() != decision.Changes.Count ||
                decision.Decision != ResourceDecisionKind.Approve && decision.Changes.Count != 0 ||
                decision.Decision == ResourceDecisionKind.Approve && !decision.Changes.Any(c =>
                    c.LimitKey == decision.Request.LimitKey && c.Before == decision.Request.CurrentLimit && c.After >= decision.Request.RequiredMinimum))
                throw new InvalidDataException("Invalid resource decision.");
            foreach (ScanLimitChange change in decision.Changes) Scanning.ScanLimitAccess.ValidateChange(change);
        }
    }
    public static ScanResourceAudit? Merge(ScanResourceAudit? first, ScanResourceAudit? second)
    {
        if (first is null) return second;
        if (second is null || ReferenceEquals(first, second)) return first;
        first.Validate(); second.Validate();
        ScanResourceAudit merged = new()
        {
            Preflight = second.Preflight ?? first.Preflight,
            Phase = second.Phase,
            PeakParallelFiles = Math.Max(first.PeakParallelFiles, second.PeakParallelFiles),
            WaitingMilliseconds = checked(first.WaitingMilliseconds + second.WaitingMilliseconds),
            Decisions = first.Decisions.Concat(second.Decisions).DistinctBy(d => d.Request.RequestId).ToList()
        };
        merged.Validate(); return merged;
    }
    public static bool SameDecision(ScanResourceDecision a, ScanResourceDecision b) => a.Request == b.Request &&
        a.Decision == b.Decision && a.DecidedAtUtc == b.DecidedAtUtc && a.ReasonCode == b.ReasonCode && a.Changes.SequenceEqual(b.Changes);
}

public sealed partial class ScanReport
{
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public ScanResourceAudit? ResourceAudit { get; set; }
}
