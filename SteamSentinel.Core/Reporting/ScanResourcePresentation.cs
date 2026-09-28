using SteamSentinel.Core.Models;
using SteamSentinel.Core.Scanning;

namespace SteamSentinel.Core.Reporting;

public static class ScanResourcePresentation
{
    public static string Summary(ScanResourceAudit audit) => DisplayText.Format("Resource.Summary", audit.PeakParallelFiles,
        audit.Decisions.Count(d => d.Decision == ResourceDecisionKind.Approve), audit.WaitingMilliseconds / 1000m);
    public static IEnumerable<string> Describe(ScanResourceAudit audit)
    {
        yield return Summary(audit);
        foreach (ScanResourceDecision decision in audit.Decisions)
        {
            yield return DisplayText.Format("Resource.History", decision.DecidedAtUtc.ToLocalTime(),
                DisplayText.Get("Resource.Reason." + (decision.ReasonCode ?? ResourceDecisionReasons.For(decision.Decision))), decision.Request.Target);
            foreach (ScanLimitChange change in decision.Changes)
            {
                ScanLimitDefinition field = ScanLimitAccess.Definition(change.LimitKey);
                yield return DisplayText.Format("Resource.Change", field.Label,
                    (change.Before / field.Scale).ToString("0.########", DisplayText.Culture),
                    (change.After / field.Scale).ToString("0.########", DisplayText.Culture), field.Unit);
            }
        }
    }
}
