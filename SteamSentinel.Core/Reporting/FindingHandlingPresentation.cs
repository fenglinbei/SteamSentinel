using SteamSentinel.Core.Models;

namespace SteamSentinel.Core.Reporting;

public sealed record FindingHandlingInfo(FindingDisposition Disposition, string Label, string Reason, string NextStep, bool CanSelect);
public sealed record FindingHandlingCounts(int Actionable, int NeedsReview, int Unsupported, int Blocked, int Informational)
{
    public int AttentionCount => NeedsReview + Unsupported + Blocked;
    public string Summary => DisplayText.Format("FindingHandling.Summary.01", (Actionable), (NeedsReview), (Unsupported), (Blocked), (Informational));
}

/// <summary>Eligibility only. Never infer execution failure/success from CanRemediate.</summary>
public static class FindingHandlingPresentation
{
    public static FindingHandlingInfo Get(Finding finding, System.Globalization.CultureInfo culture)
    {
        using IDisposable scope = DisplayText.UseCulture(culture);
        return Get(finding);
    }

    public static bool IsTrustProxyFinding(Finding finding) => finding.RuleId == "NETWORK-PROXY-PRESENT" ||
        finding.SourceKind == "trust-proxy-diagnostics" || finding.DiagnosticObservationIds.Count > 0;

    public static FindingHandlingInfo Get(Finding finding)
    {
        bool boundContainer = finding.ContentPath?.Contains("!/", StringComparison.Ordinal) != true ||
            !string.IsNullOrWhiteSpace(finding.TargetSha256);
        if (finding.CanRemediate && boundContainer)
            return new(FindingDisposition.Actionable, DisplayText.Get("FindingHandling.Get.01"), DisplayText.Get("FindingHandling.Get.02"), DisplayText.Get("FindingHandling.Get.03"), true);
        if (finding.CanRemediate && !boundContainer)
            return new(FindingDisposition.Blocked, DisplayText.Get("FindingHandling.Get.04"), DisplayText.Get("FindingHandling.Get.05"), DisplayText.Get("FindingHandling.Get.06"), false);
        if (finding.HandlingReason == FindingHandlingReason.UnsupportedAction)
            return new(FindingDisposition.Unsupported, DisplayText.Get("FindingHandling.Get.07"), Reason("FindingHandling.Get.08", finding.HandlingDetailsText.Display), DisplayText.Get("FindingHandling.Get.09"), false);
        if (finding.HandlingReason is FindingHandlingReason.IncompleteInspection or FindingHandlingReason.PrerequisiteNotMet)
            return new(FindingDisposition.Blocked, DisplayText.Get("FindingHandling.Get.10"), Reason("FindingHandling.Get.11", finding.HandlingDetailsText.Display), DisplayText.Get("FindingHandling.Get.12"), false);
        bool diagnostic = IsTrustProxyFinding(finding);
        if (finding.HandlingReason == FindingHandlingReason.InsufficientEvidence || diagnostic || finding.IsKnownMalware ||
            finding.Category != FindingCategory.Coverage && (finding.Severity >= FindingSeverity.Medium || finding.SuggestedActions.Contains(SuggestedActionKind.ReviewOnly)))
            return new(FindingDisposition.NeedsReview, DisplayText.Get("FindingHandling.Get.13"), Reason(diagnostic
                ? "FindingHandling.Get.14"
                : "FindingHandling.Get.15", finding.HandlingDetailsText.Display), diagnostic
                ? DisplayText.Get("FindingHandling.Get.16") : DisplayText.Get("FindingHandling.Get.17"), false);
        return new(FindingDisposition.Informational, DisplayText.Get("FindingHandling.Get.18"), DisplayText.Get("FindingHandling.Get.19"), DisplayText.Get("FindingHandling.Get.20"), false);
    }

    private static string Reason(string id, string? original) => DisplayText.Get(id) +
        (string.IsNullOrWhiteSpace(original) ? "" : Environment.NewLine + DisplayText.Format("Common.RawDetail", original));

    public static FindingHandlingCounts Count(IEnumerable<Finding> findings)
    {
        FindingDisposition[] states = findings.Where(f => f.Category != FindingCategory.Coverage).Select(f => Get(f).Disposition).ToArray();
        return new(states.Count(s => s == FindingDisposition.Actionable), states.Count(s => s == FindingDisposition.NeedsReview),
            states.Count(s => s == FindingDisposition.Unsupported), states.Count(s => s == FindingDisposition.Blocked),
            states.Count(s => s == FindingDisposition.Informational));
    }
}
