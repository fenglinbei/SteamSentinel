using SteamSentinel.Core.Models;
using SteamSentinel.Core.Reporting;

namespace SteamSentinel.Core.Remediation;

/// <summary>
/// Retired token-only findings remain readable, but cannot authorize a new plan.
/// This client-side eligibility rule does not establish independent Broker content proof.
/// </summary>
public static class RemediationEvidencePolicy
{
    public const string ReviewOnlyReasonCode = "ScriptTokenCooccurrenceOnly";
    public const string ReviewOnlyMessageId = "Remediation.ScriptTokenEvidenceReviewOnly";

    public static bool IsReviewOnlyEvidence(Finding finding) =>
        finding.RuleId is "HEUR-STEAM-DEPLOYMENT-CHAIN" or "HEUR-SCRIPT-TOKEN-COOCCURRENCE" or
            "INSTALLER-STRUCTURE" or "SHORTCUT-EXECUTION-CHAIN" or "HISTORY-CLICKFIX" ||
        string.Equals(finding.ReasonCode, ReviewOnlyReasonCode, StringComparison.Ordinal);

    public static bool CanRemediate(Finding finding) => finding.CanRemediate && !IsReviewOnlyEvidence(finding);

    public static MessageText ReviewOnlyMessage(Finding finding)
    {
        // Only a bounded identifier is displayed; never copy source commands, paths or secrets.
        string rule = string.IsNullOrEmpty(finding.RuleId) ? ReasonCodes.Unspecified :
            new string(finding.RuleId.Take(96).Select(c => char.IsAsciiLetterOrDigit(c) || c is '.' or '_' or '-' ? c : '_').ToArray());
        return MessageText.Create(ReviewOnlyMessageId, rule);
    }

    public static void RequireActionableEvidence(Finding finding)
    {
        if (IsReviewOnlyEvidence(finding))
            throw MessageExceptions.Create(ReviewOnlyMessage(finding), text => new RemediationEvidenceException(text));
    }
}

internal sealed class RemediationEvidenceException(string message) : UnauthorizedAccessException(message)
{
    public string ReasonCode => RemediationEvidencePolicy.ReviewOnlyReasonCode;
}
