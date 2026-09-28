using System.Text.Json;
using SteamSentinel.Core.Models;
using SteamSentinel.Core.Remediation;
using SteamSentinel.Core.Utilities;

namespace SteamSentinel.App.Services;

/// <summary>Records an authenticated closed-channel receipt, never replays or authorizes a saved plan.</summary>
internal static class RemediationCaseRecovery
{
    internal static bool ApplyFinishedResult(RemediationCaseRecord record, RemediationRunResult result)
    {
        RemediationPlan plan = record.Plans.Concat(record.BatchSession?.Plans ?? [])
            .First(p => p.PlanId == result.PlanId);
        ProtectedRemediationResultReader.ValidateFinished(plan, result);
        bool changed = ReplaceResult(record.ExecutionResults, result);
        changed |= record.PendingPlanIds.Remove(result.PlanId);
        if (record.BatchSession is { } batch)
        {
            changed |= ReplaceResult(batch.Results, result);
            if (record.PendingPlanIds.Count == 0 && batch.ExecutionStarted && !batch.ExecutionFinished)
            {
                batch.ExecutionFinished = true;
                changed = true;
            }
            string previousTargets = JsonSerializer.Serialize(batch.Targets, JsonFile.Options);
            RemediationBatchPlanner.RefreshOutcomes(batch);
            changed |= previousTargets != JsonSerializer.Serialize(batch.Targets, JsonFile.Options);
        }
        return changed;
    }

    private static bool ReplaceResult(List<RemediationRunResult> results, RemediationRunResult receipt)
    {
        RemediationRunResult[] matching = results.Where(r => r.PlanId == receipt.PlanId).ToArray();
        if (matching.Length == 1 && JsonSerializer.Serialize(matching[0], JsonFile.Options) ==
            JsonSerializer.Serialize(receipt, JsonFile.Options)) return false;
        results.RemoveAll(r => r.PlanId == receipt.PlanId);
        results.Add(receipt);
        return true;
    }
}
