using System.IO;
using System.Text.Json;
using SteamSentinel.App.Services;
using SteamSentinel.Core.Models;
using SteamSentinel.Core.Remediation;
using SteamSentinel.Core.Reporting;
using SteamSentinel.Core.Utilities;

namespace SteamSentinel.SelfTest;

internal static partial class Program
{
    private static async Task TestV030RemediationRecoveryAsync(string root)
    {
        RemediationPlan plan = new()
        {
            Actions = [new() { Type = RemediationActionType.QuarantineFile, Target = @"C:\InertRecovery\never-execute.txt", ExpectedSha256 = new string('A', 64) }]
        };
        RemediationRunResult unknown = new()
        {
            PlanId = plan.PlanId,
            PlanIdentitySha256 = RemediationPlanIdentity.Fingerprint(plan),
            Disposition = RemediationRunDisposition.ExecutionUnknown,
            CompletedAtUtc = DateTimeOffset.UtcNow,
            Errors = ["inert legacy terminal receipt; outcome unknown"]
        };
        RemediationClient client = new((_, _) => Task.FromResult<RemediationRunResult?>(unknown));
        client.RestoreUnresolvedPlan(plan);
        RemediationRunResult? receipt = await client.TryRecoverResultAsync();
        Check("处置恢复 读到结束收据后仍等待持久保存", receipt == unknown && client.HasUnresolvedExecution);
        bool failedSave = false;
        try { await client.PersistResultAsync(unknown, () => throw new IOException("inert full disk")); }
        catch (IOException) { failedSave = true; }
        Check("处置恢复 保存失败不释放全局门槛", failedSave && client.HasUnresolvedExecution);
        bool noLaunch = false;
        try { await client.ExecuteAsync(new()); }
        catch (InvalidOperationException) { noLaunch = true; }
        Check("处置恢复 保存失败后新处置在启动管理员前被挡住", noLaunch);

        string caseRoot = Path.Combine(root, "v030-recovery-cases");
        RemediationCaseStore store = new(caseRoot);
        RemediationCaseRecord record = new()
        {
            UserSid = plan.RequestedBySid,
            BatchSession = new()
            {
                Plans = [plan],
                ExecutionStarted = true,
                ExecutionFinished = true,
                Targets = [new() { Key = "inert", Target = plan.Actions[0].Target, ActionIds = [plan.Actions[0].ActionId], RequiredActions = ["inert"] }]
            },
            PendingPlanIds = [plan.PlanId]
        };
        await store.SaveAsync(record);
        string receiptBefore = JsonSerializer.Serialize(unknown, JsonFile.Options);
        bool changed = false;
        await client.PersistResultAsync(unknown, async () =>
        {
            changed = RemediationCaseRecovery.ApplyFinishedResult(record, unknown);
            Check("处置恢复 保存回调期间仍然阻断", client.HasUnresolvedExecution);
            await store.SaveAsync(record);
        });
        Check("处置恢复 仅持久保存后解锁", changed && !client.HasUnresolvedExecution);
        RemediationCaseRecord loaded = (await store.LoadAsync(record.CaseId))!;
        Check("处置恢复 旧计划保留且不会重放", loaded.BatchSession!.Plans.Single().PlanId == plan.PlanId && !loaded.MayReplaySavedPlans);
        Check("处置恢复 结果未知不冒充未开始或成功", loaded.PendingPlanIds.Count == 0 &&
            loaded.ExecutionResults.Single().Disposition == RemediationRunDisposition.ExecutionUnknown && !loaded.ExecutionResults.Single().Success &&
            JsonSerializer.Serialize(loaded.ExecutionResults.Single(), JsonFile.Options) == receiptBefore);
        Check("处置恢复 目标为需复核而非尚未执行", loaded.BatchSession.Targets.Single().State == RemediationTargetState.ReviewRequired &&
            loaded.BatchSession.Targets.Single().ReasonCode == ReasonCodes.ExecutionOutcomeUnknown);
        Check("处置恢复 病例状态仍如实保留未知", (await store.ListAsync()).Single().State == CaseReverificationState.ExecutionUncertain);
        Check("处置恢复 重复读取收据不反复修改病例", !RemediationCaseRecovery.ApplyFinishedResult(loaded, unknown));

        RemediationClient reopened = new((_, _) => Task.FromResult<RemediationRunResult?>(unknown));
        reopened.RestoreUnresolvedPlan(loaded.BatchSession.Plans.Single());
        Check("处置恢复 重新打开不凭用户记录直接解锁", reopened.HasUnresolvedExecution);
        RemediationRunResult recoveredAgain = (await reopened.TryRecoverResultAsync())!;
        await reopened.PersistResultAsync(recoveredAgain, () => Task.CompletedTask);
        Check("处置恢复 重新核验关闭通道后可继续新处置", !reopened.HasUnresolvedExecution);

        foreach (Exception problem in new Exception[] { new InvalidDataException("inert malformed"), new UnauthorizedAccessException("inert ACL"), new IOException("inert active channel") })
        {
            RemediationClient blocked = new((_, _) => throw problem);
            blocked.RestoreUnresolvedPlan(plan);
            Check("处置恢复 " + problem.GetType().Name + " 不自动清除", await blocked.TryRecoverResultAsync() is null && blocked.HasUnresolvedExecution);
        }
        RemediationClient missing = new((_, _) => Task.FromResult<RemediationRunResult?>(null));
        missing.RestoreUnresolvedPlan(plan);
        Check("处置恢复 缺失收据不能由文件年龄或重启推断已完成", await missing.TryRecoverResultAsync() is null && missing.HasUnresolvedExecution);
        RemediationRunResult forged = new()
        {
            PlanId = plan.PlanId,
            PlanIdentitySha256 = new string('F', 64),
            Disposition = RemediationRunDisposition.ExecutionUnknown,
            CompletedAtUtc = DateTimeOffset.UtcNow,
            Errors = ["inert mismatch"]
        };
        RemediationClient mismatched = new((_, _) => Task.FromResult<RemediationRunResult?>(forged));
        mismatched.RestoreUnresolvedPlan(plan);
        Check("处置恢复 错误身份不能解除门槛", await mismatched.TryRecoverResultAsync() is null && mismatched.HasUnresolvedExecution);
        bool callbackCalled = false, wrongAck = false;
        try { await mismatched.PersistResultAsync(forged, () => { callbackCalled = true; return Task.CompletedTask; }); }
        catch (InvalidDataException) { wrongAck = true; }
        Check("处置恢复 伪造结果不进入写入回调", wrongAck && !callbackCalled && mismatched.HasUnresolvedExecution);

        RemediationPlan nextPlan = new()
        {
            Actions = [new() { Type = RemediationActionType.QuarantineFile, Target = @"C:\InertRecovery\next.txt", ExpectedSha256 = new string('B', 64) }]
        };
        RemediationBatchSession batch = new()
        {
            Plans = [plan, nextPlan],
            Targets = [new() { ActionIds = [plan.Actions[0].ActionId] }, new() { ActionIds = [nextPlan.Actions[0].ActionId] }]
        };
        int executeCalls = 0;
        await RemediationBatchPlanner.ExecuteAsync(batch, _ => { executeCalls++; return Task.FromResult(unknown); });
        Check("处置恢复 真正未知会中止原批次而非自动继续", executeCalls == 1 && batch.ExecutionFinished &&
            batch.Targets[0].State == RemediationTargetState.ReviewRequired && batch.Targets[1].State == RemediationTargetState.NotExecuted);
        Check("处置恢复 未知结果原始对象未改写", JsonSerializer.Serialize(unknown, JsonFile.Options) == receiptBefore);
    }
}
