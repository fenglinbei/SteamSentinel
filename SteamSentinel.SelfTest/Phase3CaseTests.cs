using System.IO;
using System.Text.Json;
using SteamSentinel.Core.Models;
using SteamSentinel.Core.Remediation;
using SteamSentinel.Core.Utilities;

namespace SteamSentinel.SelfTest;

internal static partial class Program
{
    /// <summary>Inert records, injected sessions/probes, and files under the SelfTest fixture root only.</summary>
    private static async Task TestPhase3CasesAsync(string root)
    {
        const string sid = "S-1-5-21-123-456-789-1001", otherSid = "S-1-5-21-123-456-789-1002";
        DateTimeOffset epoch = DateTimeOffset.UtcNow.AddHours(-3);
        Phase3CaseClock clock = new(epoch.AddHours(2));
        CaseSessionObservation Session(string boot = "boot-A", long recordId = 100, string login = "login-A",
            DateTimeOffset? captured = null, DateTimeOffset? bootStarted = null, DateTimeOffset? loginStarted = null,
            string user = sid, DiagnosticReadStatus bootStatus = DiagnosticReadStatus.Complete,
            DiagnosticReadStatus loginStatus = DiagnosticReadStatus.Complete, DiagnosticReadStatus identityStatus = DiagnosticReadStatus.Complete) => new()
            {
                UserSid = user,
                MachineName = "INERT-CASE-FIXTURE",
                CapturedAtUtc = captured ?? clock.GetUtcNow(),
                IdentityStatus = identityStatus,
                BootStatus = bootStatus,
                BootIdentity = boot,
                BootEventRecordId = recordId,
                BootStartedAtUtc = bootStarted ?? epoch.AddHours(-1),
                LogonStatus = loginStatus,
                InteractiveLogonId = login,
                InteractiveLogonStartedAtUtc = loginStarted ?? epoch.AddMinutes(-50),
                LogonType = 2,
                SessionId = 1
            };
        CaseSessionObservation baseline = Session(captured: epoch);
        CaseSessionObservation newBoot = Session("boot-B", 200, "login-B", bootStarted: epoch.AddHours(1), loginStarted: epoch.AddHours(1).AddMinutes(1));
        CaseSessionObservation newLogin = Session(login: "login-B", loginStarted: epoch.AddHours(1));
        RemediationCaseRecord Case(int count = 1)
        {
            RemediationPlan plan = new() { RequestedBySid = sid, CreatedAtUtc = epoch, ExpiresAtUtc = epoch.AddMinutes(15) };
            RemediationRunResult result = new() { PlanId = plan.PlanId, StartedAtUtc = epoch.AddSeconds(1), CompletedAtUtc = epoch.AddMinutes(1), Success = true };
            for (int i = 0; i < count; i++)
            {
                RemediationAction action = new()
                {
                    Type = RemediationActionType.QuarantineFile,
                    Target = @"C:\InertCaseFixture\never-executed-" + i + ".bin",
                    ExpectedSha256 = new string('A', 64)
                };
                plan.Actions.Add(action);
                result.Actions.Add(new()
                {
                    ActionId = action.ActionId,
                    Type = action.Type,
                    Target = action.Target,
                    Success = true,
                    ExecutionStatus = RemediationExecutionStatus.Succeeded,
                    VerificationStatus = RemediationVerificationStatus.NoResidual,
                    Verifications = [new() { Pass = 1, Status = RemediationVerificationStatus.NoResidual }, new() { Pass = 2, Status = RemediationVerificationStatus.NoResidual }]
                });
            }
            return new()
            {
                UserSid = sid,
                CreatedAtUtc = epoch,
                UpdatedAtUtc = epoch,
                BaselineSession = baseline,
                Plans = [plan],
                ExecutionResults = [result],
                RequireContentFollowUp = false,
                RequireRelatedFollowUp = false
            };
        }
        static Phase3CaseProbe ClearProbe() => new((_, _) => Task.FromResult(new RemediationVerificationObservation
        { Status = RemediationVerificationStatus.NoResidual, Message = "Inert exact target absent." }));
        Check("第三批病例窗口重开但boot及登录不变不是跨会话", RemediationCaseReverification.CompareSessions(baseline, Session(), sid) == CaseSessionTransition.SameSession);
        Check("第三批病例完整新启动事件可建立新boot条件", RemediationCaseReverification.CompareSessions(baseline, newBoot, sid) == CaseSessionTransition.NewBoot);
        Check("第三批病例同boot的真实新交互登录独立识别", RemediationCaseReverification.CompareSessions(baseline, newLogin, sid) == CaseSessionTransition.NewInteractiveLogon);
        Check("第三批病例日志重置或较旧recordId不假定重启", RemediationCaseReverification.CompareSessions(baseline,
            Session("boot-reset", 1, bootStarted: epoch.AddHours(1)), sid) == CaseSessionTransition.Unknown);
        Check("第三批病例未来启动时间和只有时间漂移不建立新boot", RemediationCaseReverification.CompareSessions(baseline,
            Session("boot-future", 201, bootStarted: clock.GetUtcNow().AddHours(1)), sid) == CaseSessionTransition.Unknown &&
            RemediationCaseReverification.CompareSessions(baseline, Session(captured: clock.GetUtcNow().AddDays(1)), sid) == CaseSessionTransition.SameSession);
        Check("第三批病例UAC或非交互令牌未核验不能作为新登录", RemediationCaseReverification.CompareSessions(baseline,
            Session(login: "different-token", loginStarted: epoch.AddHours(1), loginStatus: DiagnosticReadStatus.NotChecked), sid) == CaseSessionTransition.Unknown);
        Check("第三批病例同名机器上的其他用户不能复用会话", RemediationCaseReverification.CompareSessions(baseline,
            Session("boot-B", 200, "login-B", user: otherSid, bootStarted: epoch.AddHours(1), loginStarted: epoch.AddHours(1)), sid) == CaseSessionTransition.Unknown);

        RemediationCaseRecord unchanged = Case();
        Phase3CaseProbe untouchedProbe = ClearProbe();
        CaseVerificationEpisode unchangedEpisode = await new RemediationCaseReverification(untouchedProbe, new Phase3CaseSessions(Session()), clock).RecheckAsync(unchanged);
        Check("第三批病例未跨会话时保留等待且不重放目标动作", unchangedEpisode.State == CaseReverificationState.AwaitingSessionChange && untouchedProbe.Calls == 0 &&
            unchanged.Plans[0].ExpiresAtUtc == epoch.AddMinutes(15) && unchanged.ExecutionResults[0].Actions[0].Verifications.Count == 2);

        RemediationCaseRecord passed = Case();
        string immediateBefore = JsonSerializer.Serialize(passed.ExecutionResults, JsonFile.Options);
        CaseVerificationEpisode passedEpisode = await new RemediationCaseReverification(ClearProbe(), new Phase3CaseSessions(newBoot), clock).RecheckAsync(passed);
        Check("第三批病例新boot后只读目标通过但整案及写入者保持未知", passedEpisode.State == CaseReverificationState.SelectedTargetsVerified &&
            !passedEpisode.IsWholeMachineClear && !passedEpisode.WriterIdentified && !passed.IsWholeMachineClear && !passed.WriterIdentified && !passed.MayReplaySavedPlans);
        Check("第三批病例独立episode不覆盖Broker即时两轮结果", passed.Episodes.Count == 1 && immediateBefore == JsonSerializer.Serialize(passed.ExecutionResults, JsonFile.Options));
        await new RemediationCaseReverification(ClearProbe(), new Phase3CaseSessions(newBoot), clock).RecheckAsync(passed);
        Check("第三批病例重复只读复验新增episode而不续期旧计划", passed.Episodes.Count == 2 && passed.Episodes[0].EpisodeId != passed.Episodes[1].EpisodeId &&
            passed.Plans[0].ExpiresAtUtc == epoch.AddMinutes(15));

        CaseVerificationEpisode loginEpisode = await new RemediationCaseReverification(ClearProbe(), new Phase3CaseSessions(newLogin), clock).RecheckAsync(Case());
        Check("第三批病例允许策略下真实新登录可完成目标复验", loginEpisode.State == CaseReverificationState.SelectedTargetsVerified && loginEpisode.Transition == CaseSessionTransition.NewInteractiveLogon);
        RemediationCaseRecord requiresBoot = Case(); requiresBoot.SessionRequirement = CaseSessionRequirement.NewBoot;
        CaseVerificationEpisode loginInsufficient = await new RemediationCaseReverification(ClearProbe(), new Phase3CaseSessions(newLogin), clock).RecheckAsync(requiresBoot);
        Check("第三批病例要求重启时新登录不能替代", loginInsufficient.State == CaseReverificationState.AwaitingSessionChange);
        RemediationCaseRecord pendingBoot = Case(); pendingBoot.ExecutionResults[0].Actions[0].VerificationStatus = RemediationVerificationStatus.PendingReboot;
        CaseVerificationEpisode pendingBootEpisode = await new RemediationCaseReverification(ClearProbe(), new Phase3CaseSessions(newLogin), clock).RecheckAsync(pendingBoot);
        Check("第三批病例即时PendingReboot强制真正的新boot条件", pendingBootEpisode.State == CaseReverificationState.AwaitingSessionChange);
        RemediationCaseRecord laterExecution = Case();
        laterExecution.ExecutionResults[0].CompletedAtUtc = epoch.AddMinutes(90);
        CaseVerificationEpisode tooEarly = await new RemediationCaseReverification(ClearProbe(), new Phase3CaseSessions(newBoot), clock).RecheckAsync(laterExecution);
        Check("第三批病例发生在动作完成前的新boot不冒充处置后复验", tooEarly.State == CaseReverificationState.AwaitingSessionChange);

        RemediationCaseRecord uncertain = Case(); uncertain.PendingPlanIds.Add(uncertain.Plans[0].PlanId);
        Phase3CaseProbe never = ClearProbe(); Phase3CaseSessions unusedSessions = new(newBoot);
        CaseVerificationEpisode uncertainEpisode = await new RemediationCaseReverification(never, unusedSessions, clock).RecheckAsync(uncertain);
        Check("第三批病例未确定执行保持锁定且不调用探针或会话复查", uncertainEpisode.State == CaseReverificationState.ExecutionUncertain && never.Calls == 0 && unusedSessions.Calls == 0 && uncertain.PendingPlanIds.Count == 1);
        RemediationCaseRecord actionUnknown = Case(); actionUnknown.ExecutionResults[0].Actions[0].ExecutionStatus = RemediationExecutionStatus.ExecutionUnknown;
        CaseVerificationEpisode actionUnknownEpisode = await new RemediationCaseReverification(ClearProbe(), new Phase3CaseSessions(newBoot), clock).RecheckAsync(actionUnknown);
        Check("第三批病例逐动作ExecutionUnknown不能被Success布尔覆盖", actionUnknownEpisode.State == CaseReverificationState.ExecutionUncertain);
        RemediationCaseRecord runUnknown = Case(); runUnknown.ExecutionResults[0].Disposition = RemediationRunDisposition.ExecutionUnknown;
        Phase3CaseProbe runUnknownProbe = ClearProbe();
        CaseVerificationEpisode runUnknownEpisode = await new RemediationCaseReverification(runUnknownProbe, new Phase3CaseSessions(newBoot), clock).RecheckAsync(runUnknown);
        Check("第三批病例运行级ExecutionUnknown即使旧Success与完成时间存在仍保持未确定", runUnknownEpisode.State == CaseReverificationState.ExecutionUncertain && runUnknownProbe.Calls == 0);
        RemediationCaseRecord neverStarted = Case(); neverStarted.ExecutionResults[0].Disposition = RemediationRunDisposition.NotStarted;
        neverStarted.ExecutionResults[0].CompletedAtUtc = null;
        CaseVerificationEpisode neverStartedEpisode = await new RemediationCaseReverification(ClearProbe(), new Phase3CaseSessions(newBoot), clock).RecheckAsync(neverStarted);
        Check("第三批病例确定未启动不误报执行中且矛盾Success不能变为通过", neverStartedEpisode.State == CaseReverificationState.Incomplete &&
            !neverStartedEpisode.Targets.Single().ExecutionSucceeded);
        RemediationCaseRecord inFlight = Case(); inFlight.BatchSession = new() { ExecutionStarted = true, ExecutionFinished = false };
        CaseVerificationEpisode inFlightEpisode = await new RemediationCaseReverification(ClearProbe(), new Phase3CaseSessions(newBoot), clock).RecheckAsync(inFlight);
        Check("第三批病例中断批次重开后不自动继续剩余动作", inFlightEpisode.State == CaseReverificationState.ExecutionUncertain);

        Phase3CaseProbe deniedProbe = new((_, _) => throw new UnauthorizedAccessException("Inert access denied."));
        CaseVerificationEpisode denied = await new RemediationCaseReverification(deniedProbe, new Phase3CaseSessions(newBoot), clock).RecheckAsync(Case());
        Check("第三批病例不可读目标保留Unknown而不是无残留", denied.State == CaseReverificationState.Incomplete && denied.Targets.Single().Status == RemediationVerificationStatus.Unknown);
        Phase3CaseProbe wrongUserProbe = ClearProbe(); int callbacks = 0;
        CaseVerificationEpisode wrongUser = await new RemediationCaseReverification(wrongUserProbe, new Phase3CaseSessions(Session(user: otherSid)), clock)
            .RecheckAsync(Case(), (_, _) => { callbacks++; return Task.FromResult(new CaseFollowUpResult()); });
        Check("第三批病例SID不符时不读取HKCU或调用后续扫描", wrongUser.State == CaseReverificationState.SessionUnknown && wrongUserProbe.Calls == 0 && callbacks == 0);
        CaseVerificationEpisode unavailableSession = await new RemediationCaseReverification(ClearProbe(), new Phase3CaseSessions(Session(
            bootStatus: DiagnosticReadStatus.AccessDenied, loginStatus: DiagnosticReadStatus.AccessDenied)), clock).RecheckAsync(Case());
        Check("第三批病例会话来源不可读不推断新启动", unavailableSession.State == CaseReverificationState.SessionUnknown);

        RemediationCaseRecord noResult = Case(); noResult.ExecutionResults.Clear();
        Phase3CaseProbe noResultProbe = ClearProbe();
        CaseVerificationEpisode noResultEpisode = await new RemediationCaseReverification(noResultProbe, new Phase3CaseSessions(newBoot), clock).RecheckAsync(noResult);
        Check("第三批病例缺执行结果不能由目标恰好不存在补成成功", noResultEpisode.State == CaseReverificationState.Incomplete && noResultProbe.Calls == 0 && noResultEpisode.Targets.Single().Status == RemediationVerificationStatus.NotChecked);
        RemediationCaseRecord failed = Case(); failed.ExecutionResults[0].Success = false; failed.ExecutionResults[0].Actions[0].Success = false;
        failed.ExecutionResults[0].Actions[0].ExecutionStatus = RemediationExecutionStatus.Failed;
        CaseVerificationEpisode failedEpisode = await new RemediationCaseReverification(ClearProbe(), new Phase3CaseSessions(newBoot), clock).RecheckAsync(failed);
        Check("第三批病例当前无残留不会改写历史执行失败", failedEpisode.State == CaseReverificationState.Incomplete && !failed.ExecutionResults[0].Success &&
            failedEpisode.Targets.Single().Status == RemediationVerificationStatus.NoResidual && !failedEpisode.Targets.Single().ExecutionSucceeded);
        foreach (RemediationExecutionStatus failedStatus in new[] { RemediationExecutionStatus.Failed, RemediationExecutionStatus.SkippedDependency, RemediationExecutionStatus.NotStarted })
        {
            RemediationCaseRecord contradictory = Case(); contradictory.ExecutionResults[0].Actions[0].ExecutionStatus = failedStatus;
            CaseVerificationEpisode contradictoryEpisode = await new RemediationCaseReverification(ClearProbe(), new Phase3CaseSessions(newBoot), clock).RecheckAsync(contradictory);
            Check("第三批病例逐动作" + failedStatus + "不能被矛盾Success覆盖", contradictoryEpisode.State == CaseReverificationState.Incomplete &&
                !contradictoryEpisode.Targets.Single().ExecutionSucceeded);
        }

        Phase3CaseProbe present = new((_, _) => Task.FromResult(new RemediationVerificationObservation { Status = RemediationVerificationStatus.ResidualDetected, Message = "Inert target present." }));
        CaseVerificationEpisode returned = await new RemediationCaseReverification(present, new Phase3CaseSessions(newBoot), clock).RecheckAsync(Case());
        Check("第三批病例即时无残留后相同定位再现单独标Reappeared", returned.State == CaseReverificationState.Reappeared && returned.Targets.Single().Message.Contains("不单独证明同一恶意字节"));
        RemediationCaseRecord neverClear = Case(); neverClear.ExecutionResults[0].Actions[0].VerificationStatus = RemediationVerificationStatus.Unknown;
        CaseVerificationEpisode remained = await new RemediationCaseReverification(present, new Phase3CaseSessions(newBoot), clock).RecheckAsync(neverClear);
        Check("第三批病例此前未知后发现目标只称残留不捏造复活", remained.State == CaseReverificationState.ResidualDetected);

        RemediationCaseRecord processCase = Case();
        RemediationAction oldFile = processCase.Plans[0].Actions[0];
        processCase.Plans[0].Actions[0] = new()
        {
            ActionId = oldFile.ActionId,
            Type = RemediationActionType.StopProcess,
            Target = oldFile.Target,
            ProcessId = 123,
            ProcessStartedAtUtc = epoch.AddMinutes(-1)
        };
        RemediationActionResult oldResult = processCase.ExecutionResults[0].Actions[0];
        processCase.ExecutionResults[0].Actions[0] = new()
        {
            ActionId = oldResult.ActionId,
            Type = RemediationActionType.StopProcess,
            Target = oldResult.Target,
            Success = true,
            ExecutionStatus = RemediationExecutionStatus.Succeeded,
            VerificationStatus = oldResult.VerificationStatus
        };
        processCase.RequireRelatedFollowUp = true;
        CaseVerificationEpisode stopped = await new RemediationCaseReverification(ClearProbe(), new Phase3CaseSessions(newBoot), clock).RecheckAsync(processCase);
        Check("第三批病例原PID消失不等于组件或新写入来源消失", stopped.State == CaseReverificationState.Incomplete && stopped.Targets.Single().IsOriginalProcessIdentityOnly &&
            stopped.Targets.Single().Message.Contains("不排除新的进程实例"));

        CaseVerificationEpisode capped = await new RemediationCaseReverification(ClearProbe(), new Phase3CaseSessions(newBoot), clock).RecheckAsync(Case(2), limits: new() { MaximumActions = 1 });
        Check("第三批病例目标限额保留未检查计数而不宣称全部通过", capped.State == CaseReverificationState.Incomplete && capped.Targets.Count == 1 && capped.SelectedActionCount == 2 &&
            capped.Checks.Any(c => c.Status == DiagnosticReadStatus.LimitReached));
        bool episodeLimit = false;
        try { await new RemediationCaseReverification(ClearProbe(), new Phase3CaseSessions(newBoot), clock).RecheckAsync(passed, limits: new() { MaximumEpisodes = 1 }); }
        catch (InvalidOperationException) { episodeLimit = true; }
        Check("第三批病例episode达到上限不覆盖旧观察", episodeLimit && passed.Episodes.Count == 2);
        CaseVerificationEpisode changedDuring = await new RemediationCaseReverification(ClearProbe(), new Phase3CaseSessions(newBoot, Session("boot-C", 300, "login-C",
            bootStarted: epoch.AddMinutes(110), loginStarted: epoch.AddMinutes(111))), clock).RecheckAsync(Case());
        Check("第三批病例复验期间会话改变使本轮保持未完成", changedDuring.State == CaseReverificationState.Incomplete && changedDuring.Checks.Any(c => c.Name == "复验结束身份"));

        RemediationCaseRecord full = Case(); full.RequireContentFollowUp = true; full.RequireRelatedFollowUp = true;
        full.OriginalContentSettings = new()
        {
            Mode = ScanMode.Custom,
            IncludeSystem = false,
            IncludeSteam = false,
            IncludeWorkshop = false,
            CustomRoots = [@"C:\InertCaseFixture"],
            UseAmsi = false,
            InspectArchives = true,
            HashEveryFile = true
        };
        CaseFollowUpResult CompleteReports(RemediationCaseRecord record, bool stale = false, bool incomplete = false)
        {
            DateTimeOffset now = stale ? epoch : clock.GetUtcNow();
            return new()
            {
                ContentReport = new()
                {
                    StartedAtUtc = now,
                    CompletedAtUtc = now,
                    ContentScanSettings = record.OriginalContentSettings,
                    Coverage = incomplete ? ScanCoverage.Partial : ScanCoverage.Complete
                },
                RelatedReport = new()
                {
                    StartedAtUtc = now,
                    CompletedAtUtc = now,
                    RelatedComponentDiagnostics = new()
                    {
                        TargetUserSid = sid,
                        StartedAtUtc = now,
                        CompletedAtUtc = now,
                        Checks = [new() { Name = "Inert completed source scope", Status = DiagnosticReadStatus.Complete }]
                    }
                }
            };
        }
        CaseVerificationEpisode fullEpisode = await new RemediationCaseReverification(ClearProbe(), new Phase3CaseSessions(newBoot), clock)
            .RecheckAsync(full, (record, _) => Task.FromResult(CompleteReports(record)));
        Check("第三批病例完整原范围和关联回调均通过仍仅给所选目标结论", fullEpisode.State == CaseReverificationState.SelectedTargetsVerified &&
            fullEpisode.ContentFollowUp is not null && fullEpisode.RelatedFollowUp is not null && !fullEpisode.WriterIdentified);
        RemediationCaseRecord missingFollow = Case(); missingFollow.RequireContentFollowUp = true; missingFollow.RequireRelatedFollowUp = true;
        CaseVerificationEpisode missingEpisode = await new RemediationCaseReverification(ClearProbe(), new Phase3CaseSessions(newBoot), clock).RecheckAsync(missingFollow);
        Check("第三批病例缺少完整复查回调不把空结果当完成", missingEpisode.State == CaseReverificationState.Incomplete);
        CaseVerificationEpisode staleFollow = await new RemediationCaseReverification(ClearProbe(), new Phase3CaseSessions(newBoot), clock)
            .RecheckAsync(full, (record, _) => Task.FromResult(CompleteReports(record, stale: true)));
        Check("第三批病例旧报告不能充当本次跨启动完整复查", staleFollow.State == CaseReverificationState.Incomplete);
        CaseVerificationEpisode partialFollow = await new RemediationCaseReverification(ClearProbe(), new Phase3CaseSessions(newBoot), clock)
            .RecheckAsync(full, (record, _) => Task.FromResult(CompleteReports(record, incomplete: true)));
        Check("第三批病例原范围覆盖不完整时不能整案完成", partialFollow.State == CaseReverificationState.Incomplete);
        CaseVerificationEpisode riskFollow = await new RemediationCaseReverification(ClearProbe(), new Phase3CaseSessions(newBoot), clock)
            .RecheckAsync(full, (record, _) =>
            {
                CaseFollowUpResult value = CompleteReports(record); value.ContentReport!.Findings.Add(new()
                { RuleId = "INERT-NEW-RISK", Target = @"C:\InertCaseFixture\new.bin", IsKnownMalware = true }); return Task.FromResult(value);
            });
        Check("第三批病例新内容风险不被旧目标无残留盖过", riskFollow.State == CaseReverificationState.ResidualDetected);
        CaseVerificationEpisode callbackFailed = await new RemediationCaseReverification(ClearProbe(), new Phase3CaseSessions(newBoot), clock)
            .RecheckAsync(full, (_, _) => throw new IOException("Inert callback failure."));
        Check("第三批病例完整扫描失败仍保存已完成的逐目标观察", callbackFailed.State == CaseReverificationState.Incomplete && callbackFailed.Targets.Count == 1 &&
            callbackFailed.CompletedAtUtc is not null && full.Episodes.Contains(callbackFailed));

        Phase3CaseProbe timeoutProbe = new(async (_, cancellation) =>
        { await Task.Delay(Timeout.InfiniteTimeSpan, cancellation); return new(); });
        CaseVerificationEpisode timedOut = await new RemediationCaseReverification(timeoutProbe, new Phase3CaseSessions(newBoot), clock)
            .RecheckAsync(Case(), limits: new() { ProbeTimeout = TimeSpan.FromMilliseconds(10) });
        Check("第三批病例有界超时保留Unknown及未完成状态", timedOut.State == CaseReverificationState.Incomplete && timedOut.Targets.Single().Status == RemediationVerificationStatus.Unknown);

        // Keep prior evidence while isolating every run from earlier case IDs and indices.
        string storeRoot = Path.Combine(root, "phase3-case-store-" + Guid.NewGuid().ToString("N"));
        RemediationCaseStore store = new(storeRoot, () => sid);
        RemediationCaseRecord durable = Case(); durable.OriginalScan = new() { ContentScanSettings = full.OriginalContentSettings };
        durable.OriginalContentSettings = full.OriginalContentSettings;
        durable.Notes.Add("Inert durable case: no sample or configuration is changed.");
        durable.PendingPlanIds.Add(durable.Plans[0].PlanId);
        await store.SaveAsync(durable);
        RemediationCaseRecord? loaded = await store.LoadAsync(durable.CaseId);
        Check("第三批病例原子落盘重开保留计划执行结果原设置及未确定状态", loaded is not null && loaded.Revision == 1 &&
            loaded.PendingPlanIds.SequenceEqual(durable.PendingPlanIds) && loaded.ExecutionResults[0].PlanId == durable.Plans[0].PlanId &&
            JsonSerializer.Serialize(loaded.OriginalContentSettings, JsonFile.Options) == JsonSerializer.Serialize(durable.OriginalContentSettings, JsonFile.Options));
        IReadOnlyList<RemediationCaseSummary> list = await store.ListAsync();
        Check("第三批病例列表显示执行未确定但索引不构成动作授权", list.Single().CaseId == durable.CaseId && list.Single().State == CaseReverificationState.ExecutionUncertain && !loaded!.MayReplaySavedPlans);
        RemediationCaseRecord staleCopy = loaded!;
        durable.PendingPlanIds.Clear();
        await store.SaveAsync(durable);
        bool staleRejected = false;
        try { await store.SaveAsync(staleCopy); } catch (InvalidDataException) { staleRejected = true; }
        Check("第三批病例多窗口旧revision不能覆盖更新后的病例", staleRejected && (await store.LoadAsync(durable.CaseId))!.Revision == 2);
        bool wrongOwner = false;
        try { await new RemediationCaseStore(storeRoot, () => otherSid).LoadAsync(durable.CaseId); } catch (InvalidDataException) { wrongOwner = true; }
        Check("第三批病例存储拒绝其他用户SID读取为自己的病例", wrongOwner);
        bool conflict = false;
        RemediationCaseRecord conflicting = Case();
        conflicting.BatchSession = new()
        {
            Plans = [new() { PlanId = conflicting.Plans[0].PlanId, RequestedBySid = sid,
            Actions = [new() { Type = RemediationActionType.QuarantineFile, Target = @"C:\InertCaseFixture\different.bin" }] }]
        };
        try { await store.SaveAsync(conflicting); } catch (InvalidDataException) { conflict = true; }
        Check("第三批病例相同计划ID的冲突快照拒绝落盘", conflict);
        bool nullRejected = false;
        RemediationCaseRecord nullPlan = Case(); nullPlan.Plans.Add(null!);
        try { await store.SaveAsync(nullPlan); } catch (InvalidDataException) { nullRejected = true; }
        Check("第三批病例空计划对象作为无效输入拒绝而非崩溃", nullRejected);
        bool nullResultRejected = false;
        RemediationCaseRecord nullActionResult = Case(); nullActionResult.ExecutionResults[0].Actions.Add(null!);
        try { await store.SaveAsync(nullActionResult); } catch (InvalidDataException) { nullResultRejected = true; }
        Check("第三批病例空动作执行结果作为无效输入拒绝", nullResultRejected);
        bool invalidDispositionRejected = false;
        RemediationCaseRecord invalidDisposition = Case(); invalidDisposition.ExecutionResults[0].Disposition = (RemediationRunDisposition)999;
        try { await store.SaveAsync(invalidDisposition); } catch (InvalidDataException) { invalidDispositionRejected = true; }
        Check("第三批病例未知运行结果枚举拒绝而不按成功历史加载", invalidDispositionRejected);

        string caseDirectory = Path.Combine(storeRoot, durable.CaseId.ToString("N"));
        File.Delete(Path.Combine(caseDirectory, "summary.json"));
        IReadOnlyList<RemediationCaseSummary> missingIndex = await store.ListAsync();
        Check("第三批病例显示索引丢失仍可恢复原记录且不显示完成", missingIndex.Single().ReadStatus == DiagnosticReadStatus.NotChecked &&
            (await store.LoadAsync(durable.CaseId))!.CaseId == durable.CaseId);
        await store.SaveAsync(durable);
        Check("第三批病例重试保存可重建丢失索引", (await store.ListAsync()).Single().Revision == durable.Revision);

        RemediationCaseRecord episodeRecord = Case();
        await new RemediationCaseReverification(ClearProbe(), new Phase3CaseSessions(newBoot), clock).RecheckAsync(episodeRecord);
        await store.SaveAsync(episodeRecord);
        RemediationCaseRecord restoredEpisode = (await store.LoadAsync(episodeRecord.CaseId))!;
        Check("第三批病例完整独立episode跨文件保存往返且保留未知来源", restoredEpisode.Episodes.Single().State == CaseReverificationState.SelectedTargetsVerified &&
            !restoredEpisode.WriterIdentified && restoredEpisode.ExecutionResults[0].Actions[0].Verifications.Count == 2);

        Guid oversizedId = Guid.NewGuid(); string oversizedDirectory = Path.Combine(storeRoot, oversizedId.ToString("N"));
        Directory.CreateDirectory(oversizedDirectory);
        using (FileStream sparse = new(Path.Combine(oversizedDirectory, "case.json"), FileMode.CreateNew, FileAccess.Write, FileShare.None))
            sparse.SetLength(RemediationCaseStore.MaximumCaseBytes + 1);
        bool oversizedRejected = false;
        try { await store.LoadAsync(oversizedId); } catch (InvalidDataException) { oversizedRejected = true; }
        Check("第三批病例文件超出字节上限时读取前拒绝", oversizedRejected);

        bool emptyIdRejected = false;
        try { await store.LoadAsync(Guid.Empty); } catch (ArgumentException) { emptyIdRejected = true; }
        Check("第三批病例目录仅接受非空GUID而不接收任意路径", emptyIdRejected);
    }

    private sealed class Phase3CaseClock(DateTimeOffset now) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => now;
    }

    private sealed class Phase3CaseSessions(params CaseSessionObservation[] observations) : ICaseSessionReader
    {
        public int Calls { get; private set; }
        public Task<CaseSessionObservation> ReadAsync(CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return Task.FromResult(observations[Math.Min(Calls++, observations.Length - 1)]);
        }
    }

    private sealed class Phase3CaseProbe(Func<RemediationAction, CancellationToken, Task<RemediationVerificationObservation>> read) : IRemediationStateProbe
    {
        public int Calls { get; private set; }
        public Task<RemediationVerificationObservation> ObserveAsync(RemediationAction action, CancellationToken cancellationToken)
        { Calls++; return read(action, cancellationToken); }
    }
}
