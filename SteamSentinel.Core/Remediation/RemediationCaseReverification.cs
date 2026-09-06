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
            throw new ArgumentOutOfRangeException(nameof(limits), "病例复验限额无效。");
        await _gate.WaitAsync(token).ConfigureAwait(false);
        try
        {
            RemediationCaseStore.ValidateRecord(record, record.UserSid);
            if (record.Episodes.Count >= limits.MaximumEpisodes) throw new InvalidOperationException("病例复验轮数达到保存上限；旧记录未覆盖或删除。");
            CaseVerificationEpisode episode = new() { StartedAtUtc = _time.GetUtcNow() };
            record.Episodes.Add(episode);
            using CancellationTokenSource budget = CancellationTokenSource.CreateLinkedTokenSource(token);
            budget.CancelAfter(limits.MaximumDuration);
            CancellationToken bounded = budget.Token;
            void Check(string name, DiagnosticReadStatus state, string detail, bool required = true) => episode.Checks.Add(new()
            { Name = name, Status = state, Detail = RemediationVerification.Limit(detail, 2048), Required = required });
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
                    Check("处置执行结果", DiagnosticReadStatus.NotChecked, "至少一个已开始执行的计划尚无确定结果；先恢复受保护结果或人工核对。此记录不能重复提交旧计划。");
                    return Finish(record, episode);
                }
                using (CancellationTokenSource sessionBudget = CancellationTokenSource.CreateLinkedTokenSource(bounded))
                {
                    sessionBudget.CancelAfter(limits.SessionTimeout);
                    try { episode.Session = await sessionReader.ReadAsync(sessionBudget.Token).WaitAsync(sessionBudget.Token).ConfigureAwait(false); }
                    catch (Exception ex) when (ex is not OutOfMemoryException)
                    {
                        episode.State = CaseReverificationState.SessionUnknown;
                        Check("当前会话身份", ex is OperationCanceledException ? DiagnosticReadStatus.Cancelled : DiagnosticReadStatus.Failed,
                            "未取得当前用户、启动或交互登录身份：" + ex.Message);
                        return Finish(record, episode);
                    }
                }
                if (episode.Session.IdentityStatus != DiagnosticReadStatus.Complete || episode.Session.UserSid != record.UserSid)
                {
                    episode.State = CaseReverificationState.SessionUnknown;
                    Check("病例用户身份", DiagnosticReadStatus.AccessDenied, "当前用户未核验或与病例 SID 不一致，未读取另一账户的当前用户配置，也未执行复验回调。");
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
                    Check("跨会话复验条件", DiagnosticReadStatus.NotChecked, bootRequired
                        ? "尚无本次处置后新系统启动的可核验证据；重新登录或打开窗口不能替代待重启目标复验。"
                        : "尚无要求的新启动或新交互登录证据；重开窗口、换 PID 或提权令牌不能代替。");
                    return Finish(record, episode);
                }
                Check("跨会话身份", DiagnosticReadStatus.Complete, "已核验同一用户的新会话条件；该条件本身不证明目标已消失。");
                if (actions.Length == 0) Check("复验目标", DiagnosticReadStatus.NotChecked, "没有保存明确的计划目标，未把空结果当作通过。");
                if (actions.Length > limits.MaximumActions) Check("复验目标数量", DiagnosticReadStatus.LimitReached,
                    $"共有 {actions.Length} 个计划动作，本轮最多读取 {limits.MaximumActions} 个，未读取部分仍待复核。");
                if (record.BatchSession?.Targets.Any(t => t.MissingActions.Count > 0 || t.ActionIds.Count == 0) == true)
                    Check("原始选择范围", DiagnosticReadStatus.NotChecked, "原选择含未纳入或无可执行证据的目标，所选动作通过不能覆盖这些未处理项。");
                foreach (RemediationRunResult run in results.Where(r => !r.Success || r.Errors.Count > 0))
                    Check("历史执行结果", DiagnosticReadStatus.NotChecked, "计划 " + run.PlanId + " 存在执行失败或未确定的错误；当前路径观察不会改写为执行成功。");

                foreach (var item in actions.Take(limits.MaximumActions))
                {
                    RemediationRunResult? run = results.FirstOrDefault(r => r.PlanId == item.Plan.PlanId);
                    RemediationActionResult? executed = run?.Actions.FirstOrDefault(a => a.ActionId == item.Action.ActionId);
                    if (executed is null)
                    {
                        AddTarget(episode, item.Plan, item.Action, null, null, RemediationVerificationStatus.NotChecked,
                            "此动作没有确定的执行记录；未重放计划，也不以当前目标恰好不存在补写执行成功。");
                        continue;
                    }
                    if (item.Action.Type is RemediationActionType.RollbackIncident or RemediationActionType.DeleteIncident)
                    {
                        AddTarget(episode, item.Plan, item.Action, run, executed, RemediationVerificationStatus.Unknown,
                            "病例核心不复验或重放隔离事件回滚/删除；需使用受保护事件的独立验证路径。");
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
                        if (observation is null || !Enum.IsDefined(observation.Status)) throw new InvalidDataException("探针没有返回有效目标状态。");
                    }
                    catch (Exception ex) when (ex is not OutOfMemoryException)
                    {
                        observation = new()
                        {
                            Status = RemediationVerificationStatus.Unknown,
                            Message = ex is OperationCanceledException ? "本目标复验超时或取消，未确认是否仍有残留。" : "本目标无法读取：" + ex.Message
                        };
                    }
                    RemediationVerificationStatus state = observation.Status == RemediationVerificationStatus.NotChecked
                        ? RemediationVerificationStatus.Unknown : observation.Status;
                    bool clearBefore = IsClear(executed.VerificationStatus) || record.Episodes.Where(e => e.EpisodeId != episode.EpisodeId)
                        .SelectMany(e => e.Targets).Any(t => t.ActionId == item.Action.ActionId && t.PlanId == item.Plan.PlanId && IsClear(t.Status));
                    if (clearBefore && state is RemediationVerificationStatus.ResidualDetected or RemediationVerificationStatus.PendingReboot)
                        state = RemediationVerificationStatus.Reappeared;
                    string message = (state == RemediationVerificationStatus.Reappeared
                        ? "此前目标复验通过后，相同定位再次出现或状态回退；这不单独证明同一恶意字节或写入者。 " : "") + observation.Message;
                    if (item.Action.Type is RemediationActionType.StopProcess or RemediationActionType.StopHostProcess)
                        message += " 这里只核对原 PID 和启动时间，不排除新的进程实例、磁盘组件或重新写入来源。";
                    AddTarget(episode, item.Plan, item.Action, run, executed, state, message);
                }
                if (followUp is not null)
                {
                    try
                    {
                        bounded.ThrowIfCancellationRequested();
                        CaseFollowUpResult scanned = await followUp(record, bounded).WaitAsync(bounded).ConfigureAwait(false)
                            ?? throw new InvalidDataException("复查回调未返回记录。");
                        episode.ContentFollowUp = scanned.ContentReport;
                        episode.RelatedFollowUp = scanned.RelatedReport;
                        if (!string.IsNullOrWhiteSpace(scanned.Detail)) Check("完整复查说明", DiagnosticReadStatus.Complete, scanned.Detail, required: false);
                    }
                    catch (Exception ex) when (ex is not OutOfMemoryException)
                    { Check("完整范围复查", ex is OperationCanceledException ? DiagnosticReadStatus.Cancelled : DiagnosticReadStatus.Failed, "完整复查未完成：" + ex.Message); }
                }
                if (record.RequireContentFollowUp)
                {
                    bool complete = ContentFollowUpComplete(record, episode);
                    Check("原内容范围复查", complete ? DiagnosticReadStatus.Complete : DiagnosticReadStatus.NotChecked, complete
                        ? "本次已重新完成保存的原内容范围及限制；没有发现不等于未知威胁已排除。"
                        : "缺少本次完成的原内容范围复查，或设置/覆盖不同；即时目标不存在不能代替内容复查。");
                }
                if (record.RequireRelatedFollowUp)
                {
                    bool complete = RelatedFollowUpComplete(record, episode);
                    Check("活动组件与来源复查", complete ? DiagnosticReadStatus.Complete : DiagnosticReadStatus.NotChecked, complete
                        ? "本次关联复查已完成其明确范围；路径关系不证明写入者。"
                        : "缺少本次完成的关联来源复查，或仍有必需来源不可读；旧 PID 消失不能排除新的宿主或来源。");
                }
                // Re-read the same identity source before accepting observations. A user/session
                // switch while callbacks run must not turn another account's state into evidence.
                try
                {
                    using CancellationTokenSource endBudget = CancellationTokenSource.CreateLinkedTokenSource(bounded);
                    endBudget.CancelAfter(limits.SessionTimeout);
                    CaseSessionObservation after = await sessionReader.ReadAsync(endBudget.Token).WaitAsync(endBudget.Token).ConfigureAwait(false);
                    if (!SameCurrentSession(episode.Session, after))
                        Check("复验结束身份", DiagnosticReadStatus.NotChecked, "复验期间用户、启动或已核验登录身份变化或不可读；不能将这些结果作为同一会话完成证明。");
                }
                catch (Exception ex) when (ex is not OutOfMemoryException)
                { Check("复验结束身份", DiagnosticReadStatus.NotChecked, "复验结束时无法重新核验会话：" + ex.Message); }
                episode.State = Evaluate(episode);
                return Finish(record, episode);
            }
            catch (Exception ex) when (ex is not OutOfMemoryException)
            {
                Check("病例复验", ex is OperationCanceledException ? DiagnosticReadStatus.Cancelled : DiagnosticReadStatus.Failed,
                    "复验未完成，保留此前独立观察：" + ex.Message);
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
        RemediationRunResult? run, RemediationActionResult? result, RemediationVerificationStatus status, string detail) => episode.Targets.Add(new()
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
            Message = RemediationVerification.Limit(detail, 2048)
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
        episode.Summary = Label(episode.State) + $"；本轮核对 {episode.Targets.Count}/{episode.SelectedActionCount} 个计划动作。" +
            "执行结果、即时目标状态和跨会话复验分别保留；写入来源尚未证实，不构成整案清除或整机安全结论，也不授权重放历史计划。";
        record.UpdatedAtUtc = episode.CompletedAtUtc.Value;
        return episode;
    }

    public static string Label(CaseReverificationState state) => state switch
    {
        CaseReverificationState.ExecutionUncertain => "执行结果未确定",
        CaseReverificationState.AwaitingSessionChange => "等待要求的新启动或新登录",
        CaseReverificationState.SessionUnknown => "会话变化尚未证实",
        CaseReverificationState.Incomplete => "病例复验未完成",
        CaseReverificationState.ResidualDetected => "复验仍有目标残留或风险",
        CaseReverificationState.Reappeared => "原目标定位再次出现或状态回退",
        CaseReverificationState.SelectedTargetsVerified => "本次所选目标复验通过，来源仍待调查",
        _ => "尚未进行病例复验"
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
