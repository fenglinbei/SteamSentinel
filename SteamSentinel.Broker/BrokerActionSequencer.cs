using SteamSentinel.Core.Models;
using SteamSentinel.Core.Remediation;

namespace SteamSentinel.Broker;

/// <summary>The production action loop, with effects injected only by the already-validating BrokerEngine.</summary>
internal static class BrokerActionSequencer
{
    internal static async Task RunAsync(RemediationPlan plan, RemediationRunResult result,
        IReadOnlyDictionary<Guid, string> preparationFailures,
        Func<RemediationAction, CancellationToken, Task<string>> execute,
        Func<RemediationAction, RemediationActionResult, CancellationToken, Task> observe,
        Func<CancellationToken, Task> persist,
        Action<RemediationAction, RemediationActionResult, Exception>? describeFailure = null,
        CancellationToken token = default)
    {
        var dependencies = RemediationDependencies.Build(plan.Actions);
        Dictionary<Guid, string> blocks = [];
        foreach (List<RemediationAction> group in RemediationDependencies.Groups(plan.Actions))
        {
            string[] failures = group.Where(a => preparationFailures.ContainsKey(a.ActionId)).Select(a => preparationFailures[a.ActionId]).ToArray();
            if (failures.Length > 0)
                foreach (RemediationAction action in group) blocks[action.ActionId] = string.Join("；", failures);
        }
        foreach (RemediationAction action in plan.Actions)
        {
            token.ThrowIfCancellationRequested();
            RemediationActionResult actionResult = new() { ActionId = action.ActionId, Type = action.Type, Target = action.Target };
            if (blocks.TryGetValue(action.ActionId, out string? preparationFailure))
            {
                actionResult.ExecutionStatus = preparationFailures.ContainsKey(action.ActionId)
                    ? RemediationExecutionStatus.Failed : RemediationExecutionStatus.SkippedDependency;
                actionResult.Message = "关联配置的预先备份未完成，未执行本动作：" + preparationFailure;
                actionResult.VerificationSummary = "备份前置条件未满足，未开始本关联组的处置。";
            }
            else if (RemediationDependencies.Unmet(action.ActionId, dependencies, result.Actions) is { Count: > 0 } unmet)
            {
                actionResult.ExecutionStatus = RemediationExecutionStatus.SkippedDependency;
                actionResult.Message = "前置动作未成功或未通过即时复验，已跳过；动作 ID：" + string.Join(", ", unmet);
                actionResult.VerificationSummary = "前置处置未完成，不能据此声明关联目标已清除。";
            }
            else
            {
                try
                {
                    actionResult.Message = await execute(action, token).ConfigureAwait(false);
                    actionResult.Success = true;
                    actionResult.ExecutionStatus = RemediationExecutionStatus.Succeeded;
                }
                catch (Exception ex)
                {
                    actionResult.ExecutionStatus = ex is ConfigurationExecutionUncertainException
                        ? RemediationExecutionStatus.ExecutionUnknown : RemediationExecutionStatus.Failed;
                    actionResult.Message = RemediationVerification.Limit($"{ex.GetType().Name}: {ex.Message}", 700);
                    describeFailure?.Invoke(action, actionResult, ex);
                }
                await observe(action, actionResult, token).ConfigureAwait(false);
            }
            if (!actionResult.Success)
            {
                result.Errors.Add(RemediationVerification.Limit(action.DisplayName + ": " + actionResult.Message, 1700));
                if (actionResult.VerificationStatus == RemediationVerificationStatus.NotChecked)
                    actionResult.VerificationStatus = RemediationVerificationStatus.Unknown;
            }
            actionResult.Message = RemediationVerification.Limit(actionResult.Message, 1700);
            result.Actions.Add(actionResult);
            await persist(token).ConfigureAwait(false);
        }
    }
}
