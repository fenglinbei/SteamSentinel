using SteamSentinel.Core.Models;
using SteamSentinel.Core.Remediation;
using SteamSentinel.Core.Reporting;

namespace SteamSentinel.Broker;

internal static class BrokerExecutionBoundary
{
    internal static async Task<RemediationRunResult> RunAsync(RemediationPlan plan,
        Action validateBeforeExecution, Func<Task<RemediationRunResult>> execute)
    {
        string planIdentity = RemediationPlanIdentity.Fingerprint(plan);
        DateTimeOffset startedAtUtc = DateTimeOffset.UtcNow;
        try
        {
            validateBeforeExecution();
        }
        catch (Exception ex)
        {
            RemediationRunResult refused = new()
            {
                PlanId = plan.PlanId,
                PlanIdentitySha256 = planIdentity,
                StartedAtUtc = startedAtUtc,
                CompletedAtUtc = DateTimeOffset.UtcNow,
                Success = false,
                Disposition = RemediationRunDisposition.NotStarted
            };
            refused.AddError(MessageText.Create("Backend.Exception", ex.GetType().Name, MessageExceptions.Describe(ex)).Limit(1700));
            return refused;
        }

        // Initialization and execution may mutate machine state. Their failures must reach Program's
        // ExecutionUnknown handler even if their exception type or text matches a preflight refusal.
        return await execute();
    }
}
