using System.Globalization;
using System.Text;
using SteamSentinel.Core.Inspection;
using SteamSentinel.Core.Models;
using SteamSentinel.Core.Remediation;

namespace SteamSentinel.Core.Reporting;

/// <summary>Execution and verification remain independent; recorded free text is never parsed.</summary>
public static class RemediationResultPresentation
{
    public const int MaximumTargetDetailActions = 64;
    public const int MaximumTargetSummaryCharacters = 1700;

    public static string ExecutionLabel(RemediationExecutionStatus status, CultureInfo? culture = null)
    {
        using IDisposable scope = DisplayText.UseCulture(culture);
        return DisplayText.Get(Enum.IsDefined(status) ? "Execution." + status : "Common.Unknown");
    }
    public static string RunLabel(RemediationRunDisposition disposition, CultureInfo? culture = null)
    {
        using IDisposable scope = DisplayText.UseCulture(culture);
        return DisplayText.Get(Enum.IsDefined(disposition) ? "Run." + disposition : "Common.Unknown");
    }
    public static string SessionLabel(CaseSessionTransition transition, CultureInfo? culture = null)
    {
        using IDisposable scope = DisplayText.UseCulture(culture);
        return DisplayText.Get(Enum.IsDefined(transition) ? "Session." + transition : "Common.Unknown");
    }
    public static string Describe(RemediationActionResult result, CultureInfo? culture = null)
    {
        using IDisposable scope = DisplayText.UseCulture(culture);
        StringBuilder text = new(DisplayText.Format("Result.Action", ReportExporter.ActionLabel(result.Type), result.Target,
            ExecutionLabel(result.ExecutionStatus), RemediationVerification.Label(result.VerificationStatus)));
        text.AppendLine();
        text.AppendLine(DisplayText.Format(result.ResultMessage is null ? "Result.OriginalExecution" : "Result.ExecutionDetail", result.MessageText.Display));
        text.AppendLine(DisplayText.Format(result.VerificationSummaryMessage is null ? "Result.OriginalVerification" : "Result.VerificationDetail", result.VerificationSummaryText.Display));
        foreach (RemediationVerificationObservation observation in result.Verifications)
            text.AppendLine(DisplayText.Format("Result.VerificationPass", observation.Pass,
                RemediationVerification.Label(observation.Status), observation.MessageText.Display));
        text.AppendLine(DisplayText.Get("Result.Boundary"));
        return ScriptSignals.RedactSecrets(text.ToString());
    }
    public static string Describe(RemediationRunResult result, CultureInfo? culture = null)
    {
        using IDisposable scope = DisplayText.UseCulture(culture);
        StringBuilder text = new(DisplayText.Format("Result.Run", result.PlanId, result.IncidentId,
            RunLabel(result.Disposition), RemediationVerification.Label(result.VerificationStatus)));
        text.AppendLine();
        foreach (RemediationActionResult action in result.Actions) text.AppendLine(Describe(action));
        foreach (string error in result.DisplayErrors) text.AppendLine(error);
        return ScriptSignals.RedactSecrets(text.ToString());
    }

    /// <summary>
    /// Resolve only this target and its recorded prerequisites, in plan execution order.
    /// This read-only view never supplies dependencies or permissions to the Broker.
    /// </summary>
    public static IReadOnlyList<RemediationActionResult> TargetActions(RemediationBatchSession session,
        RemediationTargetOutcome target) => TargetActions(CreateTargetIndex(session), target);

    private static IReadOnlyList<RemediationActionResult> TargetActions(TargetPresentationIndex index,
        RemediationTargetOutcome target)
    {
        TargetSelection selection = SelectTarget(index, target);
        return selection.ActionIds.Where(index.Results.ContainsKey).Select(id => index.Results[id]).ToArray();
    }

    internal static TargetPresentationIndex CreateTargetIndex(RemediationBatchSession session,
        IReadOnlyDictionary<Guid, RemediationActionResult>? results = null)
    {
        Dictionary<Guid, IndexedAction> planned = [];
        int ordinal = 0;
        foreach (RemediationPlan plan in session.Plans)
            foreach (RemediationAction action in plan.Actions)
            {
                if (planned.TryGetValue(action.ActionId, out IndexedAction? existingAction))
                {
                    if (!existingAction.PlanIds.Contains(plan.PlanId))
                        planned[action.ActionId] = existingAction with { PlanIds = [.. existingAction.PlanIds, plan.PlanId] };
                }
                else planned.Add(action.ActionId, new(action, ordinal++, [plan.PlanId]));
            }
        Dictionary<Guid, IndexedRun> runs = [];
        foreach (RemediationRunResult run in session.Results)
            runs[run.PlanId] = new(run, runs.TryGetValue(run.PlanId, out IndexedRun? existingRun) ? existingRun.Ordinal : runs.Count);
        return new(planned, results ?? LatestResults(session), runs);
    }

    private static TargetSelection SelectTarget(TargetPresentationIndex index, RemediationTargetOutcome target)
    {
        Guid[] direct = target.ActionIds.Distinct().Take(MaximumTargetDetailActions + 1).ToArray();
        HashSet<Guid> selected = direct.Take(MaximumTargetDetailActions).ToHashSet();
        bool truncated = direct.Length > MaximumTargetDetailActions;
        Queue<Guid> pending = new(selected);
        while (pending.TryDequeue(out Guid id))
        {
            if (!index.Planned.TryGetValue(id, out IndexedAction? entry)) continue;
            foreach (Guid dependency in entry.Action.DependsOnActionIds)
            {
                if (!index.Planned.ContainsKey(dependency) || selected.Contains(dependency)) continue;
                if (selected.Count >= MaximumTargetDetailActions) { truncated = true; continue; }
                selected.Add(dependency);
                pending.Enqueue(dependency);
            }
        }
        // Legacy records may have results without their plan. Keep those direct results
        // visible after the planned actions instead of dropping their original evidence.
        Guid[] ordered = selected.Where(index.Planned.ContainsKey).OrderBy(id => index.Planned[id].Ordinal)
            .Concat(direct.Where(id => selected.Contains(id) && !index.Planned.ContainsKey(id))).ToArray();
        HashSet<Guid> plans = selected.Where(index.Planned.ContainsKey).SelectMany(id => index.Planned[id].PlanIds).ToHashSet();
        return new(ordered, plans, truncated);
    }

    public static string DescribeTarget(RemediationBatchSession session, RemediationTargetOutcome target,
        CultureInfo? culture = null)
    {
        using IDisposable scope = DisplayText.UseCulture(culture);
        TargetPresentationIndex index = CreateTargetIndex(session);
        TargetSelection selection = SelectTarget(index, target);
        StringBuilder text = new(DisplayText.Format("Result.TargetSummary", target.Target, target.Status, target.Reason));
        text.AppendLine();
        foreach (RemediationRunResult run in selection.PlanIds.Where(index.Runs.ContainsKey)
                     .Select(id => index.Runs[id]).OrderBy(item => item.Ordinal).Select(item => item.Run))
        {
            text.AppendLine(DisplayText.Format("Result.Run", run.PlanId, run.IncidentId,
                RunLabel(run.Disposition), RemediationVerification.Label(run.VerificationStatus)));
            foreach (string error in run.DisplayErrors) text.AppendLine(error);
        }
        foreach (Guid id in selection.ActionIds)
        {
            if (index.Results.TryGetValue(id, out RemediationActionResult? result)) text.AppendLine(Describe(result));
            else text.AppendLine(DisplayText.Format("Result.MissingAction", index.Planned.TryGetValue(id, out IndexedAction? entry)
                ? ReportExporter.ActionLabel(entry.Action.Type) : DisplayText.Get("Report.ActionLabel.01"), id));
        }
        if (selection.Truncated) text.AppendLine(DisplayText.Format("Result.TargetDetailsLimit", MaximumTargetDetailActions));
        return ScriptSignals.RedactSecrets(text.ToString());
    }

    /// <summary>
    /// Store one bounded cause per target. Complete action records remain in Results and
    /// are rendered on selection, avoiding repeated full chains in every target row.
    /// </summary>
    public static MessageText TargetFailureSummary(RemediationBatchSession session, RemediationTargetOutcome target) =>
        TargetFailureSummary(CreateTargetIndex(session), target);

    internal static MessageText TargetFailureSummary(TargetPresentationIndex index, RemediationTargetOutcome target)
    {
        IReadOnlyList<RemediationActionResult> actions = TargetActions(index, target);
        RemediationActionResult? failed = actions.FirstOrDefault(action => !action.Success &&
            action.ExecutionStatus != RemediationExecutionStatus.SkippedDependency);
        if (failed is not null) return Cause(failed, failed.MessageText);
        foreach (RemediationActionResult action in actions.Where(action => action.ExecutionStatus != RemediationExecutionStatus.SkippedDependency))
        {
            // A later clear pass must not hide the first observation that blocked an
            // already-skipped dependent action. Pass 2 is after execution and cannot be
            // promoted ahead of an actual execution failure as its presumed cause.
            RemediationVerificationObservation? firstUnclear = action.Verifications
                .FirstOrDefault(item => item.Pass == 1 && !IsClear(item.Status));
            if (firstUnclear is not null)
                return Cause(action, MessageText.Create("Result.VerificationPass", firstUnclear.Pass,
                    RemediationVerification.LabelText(firstUnclear.Status), firstUnclear.MessageText));
        }
        RemediationActionResult? unclear = actions.FirstOrDefault(action =>
            action.ExecutionStatus != RemediationExecutionStatus.SkippedDependency && !IsClear(action.VerificationStatus));
        if (unclear is not null) return Cause(unclear, unclear.VerificationSummaryText);
        RemediationActionResult? skipped = actions.FirstOrDefault(action => !action.Success);
        return skipped is null ? string.Empty : Cause(skipped, skipped.MessageText);
    }

    private static MessageText Cause(RemediationActionResult action, MessageText text) =>
        MessageText.Create("Common.LabelValue", ReportExporter.ActionLabelText(action.Type), text)
            .RedactSecrets().Limit(MaximumTargetSummaryCharacters);

    private static Dictionary<Guid, RemediationActionResult> LatestResults(RemediationBatchSession session) =>
        session.Results.SelectMany(result => result.Actions).GroupBy(result => result.ActionId)
            .ToDictionary(group => group.Key, group => group.Last());

    // One read-only lookup view per refresh. Each target traverses only its bounded
    // closure and sorts those IDs by the recorded ordinal, never the whole session.
    internal sealed record TargetPresentationIndex(IReadOnlyDictionary<Guid, IndexedAction> Planned,
        IReadOnlyDictionary<Guid, RemediationActionResult> Results, IReadOnlyDictionary<Guid, IndexedRun> Runs);
    internal sealed record IndexedAction(RemediationAction Action, int Ordinal, IReadOnlyList<Guid> PlanIds);
    internal sealed record IndexedRun(RemediationRunResult Run, int Ordinal);
    private sealed record TargetSelection(Guid[] ActionIds, HashSet<Guid> PlanIds, bool Truncated);

    private static bool IsClear(RemediationVerificationStatus status) =>
        status is RemediationVerificationStatus.Verified or RemediationVerificationStatus.NoResidual;
}
