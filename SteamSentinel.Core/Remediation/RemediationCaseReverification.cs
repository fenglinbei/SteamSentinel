using SteamSentinel.Core.Reporting;
using System.Text.Json;
using SteamSentinel.Core.Models;
using SteamSentinel.Core.Utilities;

namespace SteamSentinel.Core.Remediation;

/// <summary>Independent, read-only post-session episodes. Saved plans are never executed or renewed.</summary>
public sealed class RemediationCaseReverification(
    IRemediationStateProbe probe,
    ICaseSessionReader sessionReader,
    TimeProvider? timeProvider = null,
    Func<Guid?, IRemediationStateProbe>? probeFactory = null)
{
    private readonly TimeProvider _time = timeProvider ?? TimeProvider.System;
    private readonly SemaphoreSlim _gate = new(1, 1);

    public RemediationCaseReverification() : this(new WindowsRemediationStateProbe(CaseReadOnlyScriptRunner.RunAsync),
        new WindowsCaseSessionReader(), probeFactory: incident => new WindowsRemediationStateProbe(CaseReadOnlyScriptRunner.RunAsync, incident))
    { }

    public async Task<CaseVerificationEpisode> RecheckAsync(RemediationCaseRecord record,
        Func<RemediationCaseRecord, CancellationToken, Task<CaseFollowUpResult>>? followUp = null,
        CancellationToken token = default, CaseReverificationLimits? limits = null)
    {
        ArgumentNullException.ThrowIfNull(record);
        limits ??= new();
        if (limits.MaximumActions is < 1 or > 256 || limits.MaximumEpisodes is < 1 or > RemediationCaseStore.MaximumEpisodes ||
            limits.ProbeTimeout <= TimeSpan.Zero || limits.ProbeTimeout > TimeSpan.FromSeconds(10) ||
            limits.SessionTimeout <= TimeSpan.Zero || limits.SessionTimeout > TimeSpan.FromSeconds(15) ||
            limits.MaximumDuration <= TimeSpan.Zero || limits.MaximumDuration > TimeSpan.FromMinutes(10))
            throw MessageExceptions.Create(MessageText.Create("Backend.Core.RemediationCaseReverification.RecheckAsync.01"), sourceText => new ArgumentOutOfRangeException(nameof(limits), sourceText));
        await _gate.WaitAsync(token).ConfigureAwait(false);
        try
        {
            RemediationCaseStore.ValidateRecord(record, record.UserSid);
            if (record.Episodes.Count >= limits.MaximumEpisodes) throw MessageExceptions.Create(MessageText.Create("Backend.Core.RemediationCaseReverification.RecheckAsync.02"), sourceText => new InvalidOperationException(sourceText));
            CaseVerificationEpisode episode = new() { StartedAtUtc = _time.GetUtcNow() };
            record.Episodes.Add(episode);
            using CancellationTokenSource budget = CancellationTokenSource.CreateLinkedTokenSource(token);
            budget.CancelAfter(limits.MaximumDuration);
            CancellationToken bounded = budget.Token;
            void Check(MessageText name, DiagnosticReadStatus state, MessageText detail, bool required = true) => episode.Checks.Add(new()
            { NameText = name, Status = state, DetailText = detail.Limit(2048), Required = required });
            try
            {
                RemediationPlan[] plans = RemediationCaseStore.AllPlans(record);
                RemediationRunResult[] results = RemediationCaseStore.AllResults(record);
                var actions = plans.SelectMany(plan => plan.Actions.Select(action => (Plan: plan, Action: action))).ToArray();
                episode.SelectedActionCount = actions.Length;
                if (record.PendingPlanIds.Count > 0 || results.Any(r => r.Disposition == RemediationRunDisposition.ExecutionUnknown ||
                        r.CompletedAtUtc is null && r.Disposition != RemediationRunDisposition.NotStarted ||
                        r.Actions.Any(a => a.ExecutionStatus == RemediationExecutionStatus.ExecutionUnknown)) ||
                    record.BatchSession is { ExecutionStarted: true, ExecutionFinished: false })
                {
                    episode.State = CaseReverificationState.ExecutionUncertain;
                    Check(MessageText.Create("Backend.Core.RemediationCaseReverification.RecheckAsync.03"), DiagnosticReadStatus.NotChecked, MessageText.Create("Backend.Core.RemediationCaseReverification.RecheckAsync.04"));
                    return Finish(record, episode);
                }
                using (CancellationTokenSource sessionBudget = CancellationTokenSource.CreateLinkedTokenSource(bounded))
                {
                    sessionBudget.CancelAfter(limits.SessionTimeout);
                    try { episode.Session = await sessionReader.ReadAsync(sessionBudget.Token).WaitAsync(sessionBudget.Token).ConfigureAwait(false); }
                    catch (Exception ex) when (ex is not OutOfMemoryException)
                    {
                        episode.State = CaseReverificationState.SessionUnknown;
                        Check(MessageText.Create("Backend.Core.RemediationCaseReverification.RecheckAsync.05"), ex is OperationCanceledException ? DiagnosticReadStatus.Cancelled : DiagnosticReadStatus.Failed,
                            MessageText.Create("Backend.Core.RemediationCaseReverification.RecheckAsync.06") + MessageExceptions.Describe(ex));
                        return Finish(record, episode);
                    }
                }
                if (episode.Session.IdentityStatus != DiagnosticReadStatus.Complete || episode.Session.UserSid != record.UserSid)
                {
                    episode.State = CaseReverificationState.SessionUnknown;
                    Check(MessageText.Create("Backend.Core.RemediationCaseReverification.RecheckAsync.07"), DiagnosticReadStatus.AccessDenied, MessageText.Create("Backend.Core.RemediationCaseReverification.RecheckAsync.08"));
                    return Finish(record, episode);
                }
                episode.Transition = CompareSessions(record.BaselineSession, episode.Session, record.UserSid);
                bool bootRequired = record.SessionRequirement == CaseSessionRequirement.NewBoot || results.Any(r =>
                    r.VerificationStatus == RemediationVerificationStatus.PendingReboot || r.Actions.Any(a => a.VerificationStatus == RemediationVerificationStatus.PendingReboot));
                bool eligible = bootRequired ? episode.Transition == CaseSessionTransition.NewBoot : record.SessionRequirement switch
                {
                    CaseSessionRequirement.NewInteractiveLogon => HasNewLogon(record.BaselineSession, episode.Session),
                    _ => episode.Transition is CaseSessionTransition.NewBoot or CaseSessionTransition.NewInteractiveLogon
                };
                DateTimeOffset executedThrough = results.Select(r => r.CompletedAtUtc ?? r.StartedAtUtc)
                    .Append(record.CreatedAtUtc).Append(record.BaselineSession?.CapturedAtUtc ?? record.CreatedAtUtc).Max();
                bool happenedAfterExecution = episode.Transition == CaseSessionTransition.NewBoot && record.SessionRequirement != CaseSessionRequirement.NewInteractiveLogon
                    ? episode.Session.BootStartedAtUtc > executedThrough : episode.Session.InteractiveLogonStartedAtUtc > executedThrough;
                eligible &= happenedAfterExecution;
                if (!eligible)
                {
                    episode.State = episode.Transition == CaseSessionTransition.Unknown ? CaseReverificationState.SessionUnknown : CaseReverificationState.AwaitingSessionChange;
                    Check(MessageText.Create("Backend.Core.RemediationCaseReverification.RecheckAsync.09"), DiagnosticReadStatus.NotChecked, bootRequired
                        ? MessageText.Create("Backend.Core.RemediationCaseReverification.RecheckAsync.10")
                        : MessageText.Create("Backend.Core.RemediationCaseReverification.RecheckAsync.11"));
                    return Finish(record, episode);
                }
                Check(MessageText.Create("Backend.Core.RemediationCaseReverification.RecheckAsync.12"), DiagnosticReadStatus.Complete, MessageText.Create("Backend.Core.RemediationCaseReverification.RecheckAsync.13"));
                if (actions.Length == 0) Check(MessageText.Create("Backend.Core.RemediationCaseReverification.RecheckAsync.14"), DiagnosticReadStatus.NotChecked, MessageText.Create("Backend.Core.RemediationCaseReverification.RecheckAsync.15"));
                if (actions.Length > limits.MaximumActions) Check(MessageText.Create("Backend.Core.RemediationCaseReverification.RecheckAsync.16"), DiagnosticReadStatus.LimitReached,
                    MessageText.Create("Backend.Core.RemediationCaseReverification.RecheckAsync.17", (actions.Length), (limits.MaximumActions)));
                if (record.BatchSession?.Targets.Any(t => t.MissingActions.Count > 0 || t.ActionIds.Count == 0) == true)
                    Check(MessageText.Create("Backend.Core.RemediationCaseReverification.RecheckAsync.18"), DiagnosticReadStatus.NotChecked, MessageText.Create("Backend.Core.RemediationCaseReverification.RecheckAsync.19"));
                foreach (RemediationRunResult run in results.Where(r => !r.Success || r.Errors.Count > 0))
                    Check(MessageText.Create("Backend.Core.RemediationCaseReverification.RecheckAsync.20"), DiagnosticReadStatus.NotChecked, MessageText.Create("Backend.Core.RemediationCaseReverification.RecheckAsync.21") + run.PlanId + MessageText.Create("Backend.Core.RemediationCaseReverification.RecheckAsync.22"));

                foreach (var item in actions.Take(limits.MaximumActions))
                {
                    RemediationRunResult? run = results.FirstOrDefault(r => r.PlanId == item.Plan.PlanId);
                    RemediationActionResult? executed = run?.Actions.FirstOrDefault(a => a.ActionId == item.Action.ActionId);
                    if (executed is null)
                    {
                        AddTarget(episode, item.Plan, item.Action, null, null, RemediationVerificationStatus.NotChecked,
                            MessageText.Create("Backend.Core.RemediationCaseReverification.RecheckAsync.23"));
                        continue;
                    }
                    if (item.Action.Type is RemediationActionType.RollbackIncident or RemediationActionType.DeleteIncident)
                    {
                        AddTarget(episode, item.Plan, item.Action, run, executed, RemediationVerificationStatus.Unknown,
                            MessageText.Create("Backend.Core.RemediationCaseReverification.RecheckAsync.24"));
                        continue;
                    }
                    RemediationVerificationObservation observation;
                    using CancellationTokenSource perTarget = CancellationTokenSource.CreateLinkedTokenSource(bounded);
                    perTarget.CancelAfter(limits.ProbeTimeout);
                    try
                    {
                        perTarget.Token.ThrowIfCancellationRequested();
                        IRemediationStateProbe targetProbe = probeFactory?.Invoke(run?.IncidentId) ?? probe;
                        observation = await targetProbe.ObserveAsync(item.Action, perTarget.Token).WaitAsync(perTarget.Token).ConfigureAwait(false);
                        if (observation is null || !Enum.IsDefined(observation.Status)) throw MessageExceptions.Create(MessageText.Create("Backend.Core.RemediationCaseReverification.RecheckAsync.25"), sourceText => new InvalidDataException(sourceText));
                    }
                    catch (Exception ex) when (ex is not OutOfMemoryException)
                    {
                        observation = new()
                        {
                            Status = RemediationVerificationStatus.Unknown,
                            MessageText = ex is OperationCanceledException ? MessageText.Create("Backend.Core.RemediationCaseReverification.RecheckAsync.26") : MessageText.Create("Backend.Core.RemediationCaseReverification.RecheckAsync.27") + MessageExceptions.Describe(ex)
                        };
                    }
                    RemediationVerificationStatus state = observation.Status == RemediationVerificationStatus.NotChecked
                        ? RemediationVerificationStatus.Unknown : observation.Status;
                    bool clearBefore = IsClear(executed.VerificationStatus) || record.Episodes.Where(e => e.EpisodeId != episode.EpisodeId)
                        .SelectMany(e => e.Targets).Any(t => t.ActionId == item.Action.ActionId && t.PlanId == item.Plan.PlanId && IsClear(t.Status));
                    if (clearBefore && state is RemediationVerificationStatus.ResidualDetected or RemediationVerificationStatus.PendingReboot)
                        state = RemediationVerificationStatus.Reappeared;
                    MessageText message = (state == RemediationVerificationStatus.Reappeared
                        ? MessageText.Create("Backend.Core.RemediationCaseReverification.RecheckAsync.28") : (MessageText)"") + observation.MessageText;
                    if (item.Action.Type is RemediationActionType.StopProcess or RemediationActionType.StopHostProcess)
                        message += MessageText.Create("Backend.Core.RemediationCaseReverification.RecheckAsync.29");
                    AddTarget(episode, item.Plan, item.Action, run, executed, state, message);
                }
                if (followUp is not null)
                {
                    try
                    {
                        bounded.ThrowIfCancellationRequested();
                        CaseFollowUpResult scanned = await followUp(record, bounded).WaitAsync(bounded).ConfigureAwait(false)
                            ?? throw MessageExceptions.Create(MessageText.Create("Backend.Core.RemediationCaseReverification.RecheckAsync.30"), sourceText => new InvalidDataException(sourceText));
                        episode.ContentFollowUp = scanned.ContentReport;
                        episode.RelatedFollowUp = scanned.RelatedReport;
                        if (!string.IsNullOrWhiteSpace(scanned.Detail)) Check(MessageText.Create("Backend.Core.RemediationCaseReverification.RecheckAsync.31"), DiagnosticReadStatus.Complete, scanned.DetailText, required: false);
                    }
                    catch (Exception ex) when (ex is not OutOfMemoryException)
                    { Check(MessageText.Create("Backend.Core.RemediationCaseReverification.RecheckAsync.32"), ex is OperationCanceledException ? DiagnosticReadStatus.Cancelled : DiagnosticReadStatus.Failed, MessageText.Create("Backend.Core.RemediationCaseReverification.RecheckAsync.33") + MessageExceptions.Describe(ex)); }
                }
                if (record.RequireContentFollowUp)
                {
                    bool complete = ContentFollowUpComplete(record, episode);
                    Check(MessageText.Create("Backend.Core.RemediationCaseReverification.RecheckAsync.34"), complete ? DiagnosticReadStatus.Complete : DiagnosticReadStatus.NotChecked, complete
                        ? MessageText.Create("Backend.Core.RemediationCaseReverification.RecheckAsync.35")
                        : MessageText.Create("Backend.Core.RemediationCaseReverification.RecheckAsync.36"));
                }
                if (record.RequireRelatedFollowUp)
                {
                    bool complete = RelatedFollowUpComplete(record, episode);
                    Check(MessageText.Create("Backend.Core.RemediationCaseReverification.RecheckAsync.37"), complete ? DiagnosticReadStatus.Complete : DiagnosticReadStatus.NotChecked, complete
                        ? MessageText.Create("Backend.Core.RemediationCaseReverification.RecheckAsync.38")
                        : MessageText.Create("Backend.Core.RemediationCaseReverification.RecheckAsync.39"));
                }
                // Re-read the same identity source before accepting observations. A user/session
                // switch while callbacks run must not turn another account's state into evidence.
                try
                {
                    using CancellationTokenSource endBudget = CancellationTokenSource.CreateLinkedTokenSource(bounded);
                    endBudget.CancelAfter(limits.SessionTimeout);
                    CaseSessionObservation after = await sessionReader.ReadAsync(endBudget.Token).WaitAsync(endBudget.Token).ConfigureAwait(false);
                    if (!SameCurrentSession(episode.Session, after))
                        Check(MessageText.Create("Backend.Core.RemediationCaseReverification.RecheckAsync.40"), DiagnosticReadStatus.NotChecked, MessageText.Create("Backend.Core.RemediationCaseReverification.RecheckAsync.41"));
                }
                catch (Exception ex) when (ex is not OutOfMemoryException)
                { Check(MessageText.Create("Backend.Core.RemediationCaseReverification.RecheckAsync.42"), DiagnosticReadStatus.NotChecked, MessageText.Create("Backend.Core.RemediationCaseReverification.RecheckAsync.43") + MessageExceptions.Describe(ex)); }
                episode.State = Evaluate(episode);
                return Finish(record, episode);
            }
            catch (Exception ex) when (ex is not OutOfMemoryException)
            {
                Check(MessageText.Create("Backend.Core.RemediationCaseReverification.RecheckAsync.44"), ex is OperationCanceledException ? DiagnosticReadStatus.Cancelled : DiagnosticReadStatus.Failed,
                    MessageText.Create("Backend.Core.RemediationCaseReverification.RecheckAsync.45") + MessageExceptions.Describe(ex));
                episode.State = Evaluate(episode);
                return Finish(record, episode);
            }
        }
        finally { _gate.Release(); }
    }

    public static CaseSessionTransition CompareSessions(CaseSessionObservation? baseline, CaseSessionObservation current, string userSid)
    {
        if (!ValidIdentity(baseline, userSid) || !ValidIdentity(current, userSid) ||
            !baseline!.MachineName.Equals(current.MachineName, StringComparison.OrdinalIgnoreCase) || current.CapturedAtUtc < baseline.CapturedAtUtc)
            return CaseSessionTransition.Unknown;
        bool bootReadable = baseline.BootStatus == DiagnosticReadStatus.Complete && current.BootStatus == DiagnosticReadStatus.Complete &&
            !string.IsNullOrWhiteSpace(baseline.BootIdentity) && !string.IsNullOrWhiteSpace(current.BootIdentity);
        if (bootReadable && baseline.BootIdentity != current.BootIdentity && baseline.BootEventRecordId is > 0 &&
            current.BootEventRecordId > baseline.BootEventRecordId && current.BootStartedAtUtc is { } boot &&
            boot > baseline.CapturedAtUtc && boot <= current.CapturedAtUtc)
            return CaseSessionTransition.NewBoot;
        if (HasNewLogon(baseline, current)) return CaseSessionTransition.NewInteractiveLogon;
        if (bootReadable && baseline.BootIdentity == current.BootIdentity && baseline.LogonStatus == DiagnosticReadStatus.Complete &&
            current.LogonStatus == DiagnosticReadStatus.Complete && !string.IsNullOrWhiteSpace(baseline.InteractiveLogonId) &&
            baseline.InteractiveLogonId == current.InteractiveLogonId && baseline.InteractiveLogonStartedAtUtc == current.InteractiveLogonStartedAtUtc)
            return CaseSessionTransition.SameSession;
        return CaseSessionTransition.Unknown;
    }

    private static bool HasNewLogon(CaseSessionObservation? baseline, CaseSessionObservation current) => baseline is not null &&
        ValidIdentity(baseline, current.UserSid) && ValidIdentity(current, baseline.UserSid) &&
        baseline.MachineName.Equals(current.MachineName, StringComparison.OrdinalIgnoreCase) &&
        baseline.LogonStatus == DiagnosticReadStatus.Complete && current.LogonStatus == DiagnosticReadStatus.Complete &&
        baseline.LogonType is 2 or 10 or 11 or 12 && current.LogonType is 2 or 10 or 11 or 12 &&
        !string.IsNullOrWhiteSpace(baseline.InteractiveLogonId) && !string.IsNullOrWhiteSpace(current.InteractiveLogonId) &&
        baseline.InteractiveLogonId != current.InteractiveLogonId && current.InteractiveLogonStartedAtUtc is { } started &&
        started > baseline.CapturedAtUtc && started <= current.CapturedAtUtc;

    private static bool ValidIdentity(CaseSessionObservation? observation, string sid) => observation is not null &&
        observation.IdentityStatus == DiagnosticReadStatus.Complete && observation.UserSid == sid && !string.IsNullOrWhiteSpace(sid) &&
        !string.IsNullOrWhiteSpace(observation.MachineName) && observation.CapturedAtUtc != default;
    private static bool SameCurrentSession(CaseSessionObservation before, CaseSessionObservation after) =>
        ValidIdentity(before, after.UserSid) && ValidIdentity(after, before.UserSid) && before.MachineName.Equals(after.MachineName, StringComparison.OrdinalIgnoreCase) &&
        (before.BootStatus != DiagnosticReadStatus.Complete || after.BootStatus == DiagnosticReadStatus.Complete && before.BootIdentity == after.BootIdentity) &&
        (before.LogonStatus != DiagnosticReadStatus.Complete || after.LogonStatus == DiagnosticReadStatus.Complete && before.InteractiveLogonId == after.InteractiveLogonId);

    private void AddTarget(CaseVerificationEpisode episode, RemediationPlan plan, RemediationAction action,
        RemediationRunResult? run, RemediationActionResult? result, RemediationVerificationStatus status, MessageText detail) => episode.Targets.Add(new()
        {
            PlanId = plan.PlanId,
            ActionId = action.ActionId,
            IncidentId = run?.IncidentId,
            Type = action.Type,
            Target = action.Target,
            ExecutionSucceeded = run?.Success == true &&
            run.Disposition is not (RemediationRunDisposition.NotStarted or RemediationRunDisposition.ExecutionUnknown) &&
            result?.Success == true && result.ExecutionStatus == RemediationExecutionStatus.Succeeded,
            Status = status,
            CheckedAtUtc = _time.GetUtcNow(),
            MessageText = detail.Limit(2048)
        });

    private static CaseReverificationState Evaluate(CaseVerificationEpisode episode)
    {
        if (episode.Targets.Any(t => t.Status == RemediationVerificationStatus.Reappeared)) return CaseReverificationState.Reappeared;
        if (episode.Targets.Any(t => t.Status == RemediationVerificationStatus.ResidualDetected) ||
            new[] { episode.ContentFollowUp, episode.RelatedFollowUp }.OfType<ScanReport>().Any(r => r.Findings.Any(f => f.IsKnownMalware || f.CanRemediate ||
                f.Category != FindingCategory.Coverage && f.Severity >= FindingSeverity.Medium))) return CaseReverificationState.ResidualDetected;
        bool incomplete = episode.SelectedActionCount == 0 || episode.Targets.Count != episode.SelectedActionCount ||
            episode.Targets.Any(t => !t.ExecutionSucceeded || !IsClear(t.Status)) ||
            episode.Checks.Any(c => c.Required && c.Status is not (DiagnosticReadStatus.Complete or DiagnosticReadStatus.NotPresent));
        return incomplete ? CaseReverificationState.Incomplete : CaseReverificationState.SelectedTargetsVerified;
    }

    private CaseVerificationEpisode Finish(RemediationCaseRecord record, CaseVerificationEpisode episode)
    {
        episode.CompletedAtUtc = _time.GetUtcNow();
        episode.SummaryText = LabelText(episode.State) + MessageText.Create("Backend.Core.RemediationCaseReverification.Finish.01", (episode.Targets.Count), (episode.SelectedActionCount)) +
            MessageText.Create("Backend.Core.RemediationCaseReverification.Finish.02");
        record.UpdatedAtUtc = episode.CompletedAtUtc.Value;
        return episode;
    }

    public static string Label(CaseReverificationState state) => LabelText(state).OriginalText;
    public static MessageText LabelText(CaseReverificationState state) => state switch
    {
        CaseReverificationState.ExecutionUncertain => MessageText.Create("Backend.Core.RemediationCaseReverification.Label.ExecutionUncertain.01"),
        CaseReverificationState.AwaitingSessionChange => MessageText.Create("Backend.Core.RemediationCaseReverification.Label.AwaitingSessionChange.01"),
        CaseReverificationState.SessionUnknown => MessageText.Create("Backend.Core.RemediationCaseReverification.Label.SessionUnknown.01"),
        CaseReverificationState.Incomplete => MessageText.Create("Backend.Core.RemediationCaseReverification.Label.Incomplete.01"),
        CaseReverificationState.ResidualDetected => MessageText.Create("Backend.Core.RemediationCaseReverification.Label.ResidualDetected.01"),
        CaseReverificationState.Reappeared => MessageText.Create("Backend.Core.RemediationCaseReverification.Label.Reappeared.01"),
        CaseReverificationState.SelectedTargetsVerified => MessageText.Create("Backend.Core.RemediationCaseReverification.Label.SelectedTargetsVerified.01"),
        _ => MessageText.Create("Backend.Core.RemediationCaseReverification.Label.01")
    };
    private static bool IsClear(RemediationVerificationStatus status) => status is RemediationVerificationStatus.NoResidual or RemediationVerificationStatus.Verified;
    private bool CurrentCompleteReport(ScanReport? report, CaseVerificationEpisode episode) => report is not null &&
        report.Coverage == ScanCoverage.Complete && report.CompletedAtUtc >= report.StartedAtUtc && report.StartedAtUtc >= episode.StartedAtUtc &&
        report.CompletedAtUtc <= _time.GetUtcNow() &&
        report.RootSummaries.All(r => r.Coverage == ScanCoverage.Complete);
    private bool ContentFollowUpComplete(RemediationCaseRecord record, CaseVerificationEpisode episode)
    {
        ScanOptions? original = record.OriginalContentSettings ?? record.BatchSession?.OriginalContentSettings ?? record.OriginalScan?.ContentScanSettings;
        return original is not null && CurrentCompleteReport(episode.ContentFollowUp, episode) && episode.ContentFollowUp!.ContentScanSettings is { } actual &&
            JsonSerializer.Serialize(original, JsonFile.Options) == JsonSerializer.Serialize(actual, JsonFile.Options);
    }
    private bool RelatedFollowUpComplete(RemediationCaseRecord record, CaseVerificationEpisode episode) =>
        CurrentCompleteReport(episode.RelatedFollowUp, episode) && episode.RelatedFollowUp!.RelatedComponentDiagnostics is { } diagnostic &&
        diagnostic.TargetUserSid == record.UserSid && diagnostic.CompletedAtUtc >= diagnostic.StartedAtUtc && diagnostic.StartedAtUtc >= episode.StartedAtUtc &&
        diagnostic.Checks.Count > 0 && diagnostic.Checks.All(c => !c.Required || c.Status is DiagnosticReadStatus.Complete or DiagnosticReadStatus.NotPresent);
}
