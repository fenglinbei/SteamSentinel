using SteamSentinel.Core.Models;
using SteamSentinel.Core.Remediation;
using SteamSentinel.Core.Reporting;

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
        => await RunLocalizedAsync(plan, result, preparationFailures.ToDictionary(pair => pair.Key, pair => (MessageText)pair.Value),
            async (action, cancellationToken) => (MessageText)await execute(action, cancellationToken).ConfigureAwait(false),
            observe, persist, describeFailure, token).ConfigureAwait(false);

    internal static async Task RunLocalizedAsync(RemediationPlan plan, RemediationRunResult result,
        IReadOnlyDictionary<Guid, MessageText> preparationFailures,
        Func<RemediationAction, CancellationToken, Task<MessageText>> execute,
        Func<RemediationAction, RemediationActionResult, CancellationToken, Task> observe,
        Func<CancellationToken, Task> persist,
        Action<RemediationAction, RemediationActionResult, Exception>? describeFailure = null,
        CancellationToken token = default)
    {
        var dependencies = RemediationDependencies.Build(plan.Actions);
        Dictionary<Guid, MessageText> blocks = [];
        foreach (List<RemediationAction> group in RemediationDependencies.Groups(plan.Actions))
        {
            MessageText[] failures = group.Where(a => preparationFailures.ContainsKey(a.ActionId)).Select(a => preparationFailures[a.ActionId]).ToArray();
            if (failures.Length > 0)
                foreach (RemediationAction action in group) blocks[action.ActionId] = MessageText.List(failures);
        }
        foreach (RemediationAction action in plan.Actions)
        {
            token.ThrowIfCancellationRequested();
            RemediationActionResult actionResult = new() { ActionId = action.ActionId, Type = action.Type, Target = action.Target };
            if (blocks.TryGetValue(action.ActionId, out MessageText? preparationFailure))
            {
                actionResult.ExecutionStatus = preparationFailures.ContainsKey(action.ActionId)
                    ? RemediationExecutionStatus.Failed : RemediationExecutionStatus.SkippedDependency;
                actionResult.MessageText = MessageText.Create("Backend.Broker.PreparationBlocked", preparationFailure);
                actionResult.VerificationSummaryText = MessageText.Create("Backend.Broker.BackupPrerequisite");
            }
            else if (RemediationDependencies.Unmet(action.ActionId, dependencies, result.Actions) is { Count: > 0 } unmet)
            {
                actionResult.ExecutionStatus = RemediationExecutionStatus.SkippedDependency;
                actionResult.MessageText = MessageText.Create("Backend.Broker.DependencyBlocked", string.Join(", ", unmet));
                actionResult.VerificationSummaryText = MessageText.Create("Backend.Broker.RemediationPrerequisite");
            }
            else
            {
                try
                {
                    actionResult.MessageText = await execute(action, token).ConfigureAwait(false);
                    actionResult.Success = true;
                    actionResult.ExecutionStatus = RemediationExecutionStatus.Succeeded;
                }
                catch (Exception ex)
                {
                    actionResult.ExecutionStatus = ex is ConfigurationExecutionUncertainException
                        ? RemediationExecutionStatus.ExecutionUnknown : RemediationExecutionStatus.Failed;
                    actionResult.MessageText = MessageText.Create("Backend.Exception", ex.GetType().Name, MessageExceptions.Describe(ex)).Limit(700);
                    describeFailure?.Invoke(action, actionResult, ex);
                }
                await observe(action, actionResult, token).ConfigureAwait(false);
            }
            if (!actionResult.Success)
            {
                result.AddError(MessageText.Create("Backend.ActionError", action.DisplayNameText, actionResult.MessageText).Limit(1700));
                if (actionResult.VerificationStatus == RemediationVerificationStatus.NotChecked)
                    actionResult.VerificationStatus = RemediationVerificationStatus.Unknown;
            }
            actionResult.MessageText = actionResult.MessageText.Limit(1700);
            result.Actions.Add(actionResult);
            await persist(token).ConfigureAwait(false);
        }
    }
}
