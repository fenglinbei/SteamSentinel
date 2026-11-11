using SteamSentinel.Core.Models;
using SteamSentinel.Core.Reporting;

namespace SteamSentinel.Core.Remediation;

/// <summary>
/// Review-only findings remain readable, but cannot authorize a new plan.
/// This client-side eligibility rule does not establish independent Broker content proof.
/// </summary>
public static class RemediationEvidencePolicy
{
    public const string ReviewOnlyReasonCode = "ScriptTokenCooccurrenceOnly";
    public const string ReviewOnlyMessageId = "Remediation.ScriptTokenEvidenceReviewOnly";
    internal const string BehaviorReviewReasonCode = "BehaviorEvidenceReviewOnly";

    internal static bool IsBehaviorObservation(string ruleId) => ruleId is
        "STEAM-UI-LOOPBACK-SCRIPT" or "MANAGED-MOD-DOWNLOAD-LAUNCH" or "MANAGED-STEAM-CEF-HOST" or "MANAGED-STEAM-CEF-CORE";

    public static bool IsReviewOnlyEvidence(Finding finding) =>
        IsBehaviorObservation(finding.RuleId) || finding.RuleId is "HEUR-STEAM-DEPLOYMENT-CHAIN" or "HEUR-SCRIPT-TOKEN-COOCCURRENCE" or
            "INSTALLER-STRUCTURE" or "SHORTCUT-EXECUTION-CHAIN" or "HISTORY-CLICKFIX" ||
        string.Equals(finding.ReasonCode, ReviewOnlyReasonCode, StringComparison.Ordinal);

    public static bool CanRemediate(Finding finding) => finding.CanRemediate && !IsReviewOnlyEvidence(finding);

    public static MessageText ReviewOnlyMessage(Finding finding)
    {
        if (finding.RuleId == "STEAM-UI-LOOPBACK-SCRIPT")
            return MessageText.Create(finding.ReasonCode == "SteamAlertResidentCorrelated" ? "Pawnshop.Ui.Repair" : "Pawnshop.Ui.Review");
        if (finding.RuleId == "MANAGED-MOD-DOWNLOAD-LAUNCH") return MessageText.Create("Scan.ManagedMod.Downloader.Description");
        if (finding.RuleId == "MANAGED-STEAM-CEF-HOST") return MessageText.Create("Scan.ManagedMod.Host.Description");
        if (finding.RuleId == "MANAGED-STEAM-CEF-CORE") return MessageText.Create("Scan.ManagedMod.Core.Description");
        // Only a bounded identifier is displayed; never copy source commands, paths or secrets.
        string rule = string.IsNullOrEmpty(finding.RuleId) ? ReasonCodes.Unspecified :
            new string(finding.RuleId.Take(96).Select(c => char.IsAsciiLetterOrDigit(c) || c is '.' or '_' or '-' ? c : '_').ToArray());
        return MessageText.Create(ReviewOnlyMessageId, rule);
    }

    public static void RequireActionableEvidence(Finding finding)
    {
        if (IsReviewOnlyEvidence(finding))
            throw MessageExceptions.Create(ReviewOnlyMessage(finding), text => new RemediationEvidenceException(text,
                IsBehaviorObservation(finding.RuleId) ? BehaviorReviewReasonCode : ReviewOnlyReasonCode));
    }
}

internal sealed class RemediationEvidenceException(string message, string reasonCode) : UnauthorizedAccessException(message)
{
    public string ReasonCode => reasonCode;
}
