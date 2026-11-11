using SteamSentinel.Core.Models;

namespace SteamSentinel.Core.Reporting;

/// <summary>Display the chosen policy without changing the original detection evidence.</summary>
public static class RemediationModePresentation
{
    public static string Label(RemediationMode mode) => DisplayText.Get(mode switch
    {
        RemediationMode.Conservative => "RemediationMode.Conservative",
        RemediationMode.Aggressive => "RemediationMode.Aggressive",
        _ => "Common.Unknown"
    });

    public static string Description(RemediationMode mode) => DisplayText.Get(mode == RemediationMode.Aggressive
        ? "RemediationMode.AggressiveDescription" : "RemediationMode.ConservativeDescription");

    public static string Summary(RemediationPlan plan) => DisplayText.Format("RemediationMode.PlanSummary",
        Label(plan.Mode), plan.Actions.Count(action => action.UserSelectedRisk));

    public static string Summary(IEnumerable<RemediationPlan> plans) => string.Join(Environment.NewLine,
        plans.GroupBy(plan => plan.Mode).Select(group => DisplayText.Format("RemediationMode.PlanSummary",
            Label(group.Key), group.SelectMany(plan => plan.Actions).DistinctBy(action => action.ActionId)
                .Count(action => action.UserSelectedRisk))));
}
