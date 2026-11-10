using SteamSentinel.Core.Models;
using SteamSentinel.Core.Remediation;
using SteamSentinel.Core.Steam;

namespace SteamSentinel.Core.Reporting;

public sealed record FindingHandlingInfo(FindingDisposition Disposition, string Label, string Reason, string NextStep, bool CanSelect,
    FileScopeStatus? ScopeStatus = null);
public sealed record FindingHandlingCounts(int Actionable, int NeedsReview, int Unsupported, int Blocked, int Informational,
    int PendingConfirmation = 0, int NeedsVerification = 0, bool HasFileScope = false)
{
    public int AttentionCount => NeedsReview + Unsupported + Blocked + NeedsVerification;
    public int SelectableCount => Actionable + PendingConfirmation + NeedsVerification;
    public string Summary => HasFileScope
        ? DisplayText.Format("Scope.Ui.Counts", Actionable, PendingConfirmation, NeedsVerification, NeedsReview, Unsupported, Blocked, Informational)
        : DisplayText.Format("FindingHandling.Summary.01", Actionable, NeedsReview, Unsupported, Blocked, Informational);
}

/// <summary>Eligibility only. Never infer execution failure/success from CanRemediate.</summary>
public static class FindingHandlingPresentation
{
    // Scope is a presentation-time assessment, never an execution authorization.
    // The caller supplies its cached Steam layout so rows do not repeat discovery.
    public static FileScopeAssessment? AssessFileScope(Finding finding, RuleSet rules, SteamLayout layout)
    {
        if (!Get(finding).CanSelect || !finding.SuggestedActions.Contains(SuggestedActionKind.QuarantineFile)) return null;
        string? hash = finding.TargetSha256 ?? (finding.ContentPath is null ||
            string.Equals(finding.Target, finding.ContentPath, StringComparison.OrdinalIgnoreCase) ? finding.Sha256 : null);
        return FileRemediationScope.Assess(finding.Target, hash, rules, layout);
    }

    public static FindingHandlingInfo Get(Finding finding, RuleSet rules, SteamLayout layout) =>
        Get(finding, AssessFileScope(finding, rules, layout));

    public static FindingHandlingInfo Get(Finding finding, FileScopeAssessment? scope)
    {
        FindingHandlingInfo original = Get(finding);
        if (!original.CanSelect || scope is null) return original;
        string? labelKey = scope.Status switch
        {
            FileScopeStatus.RequiresConsent => "Scope.Ui.RequiresConsent.Label",
            FileScopeStatus.SensitiveRequiresConsent => "Scope.Ui.Sensitive.Label",
            FileScopeStatus.NeedsVerification => scope.Sensitive ? "Scope.Ui.Sensitive.Label" : "Scope.Ui.NeedsVerification.Label",
            FileScopeStatus.Blocked => "Scope.Ui.Blocked.Label",
            _ => null
        };
        if (labelKey is null) return original with { ScopeStatus = scope.Status };
        return new(scope.CanRequest ? FindingDisposition.Actionable : FindingDisposition.Blocked,
            DisplayText.Get(labelKey), scope.Message.Display,
            DisplayText.Get(scope.CanRequest ? "Scope.Ui.Request.Next" : "Scope.Ui.Blocked.Next"), scope.CanRequest, scope.Status);
    }

    public static FindingHandlingInfo Get(Finding finding, System.Globalization.CultureInfo culture)
    {
        using IDisposable scope = DisplayText.UseCulture(culture);
        return Get(finding);
    }

    public static bool IsTrustProxyFinding(Finding finding) => finding.RuleId == "NETWORK-PROXY-PRESENT" ||
        finding.SourceKind == "trust-proxy-diagnostics" || finding.DiagnosticObservationIds.Count > 0;

    public static FindingHandlingInfo Get(Finding finding)
    {
        if (RemediationEvidencePolicy.IsReviewOnlyEvidence(finding))
            return new(FindingDisposition.NeedsReview, DisplayText.Get("FindingHandling.Get.13"),
                RemediationEvidencePolicy.ReviewOnlyMessage(finding).Display, DisplayText.Get("FindingHandling.Get.17"), false);
        bool boundContainer = finding.ContentPath?.Contains("!/", StringComparison.Ordinal) != true ||
            !string.IsNullOrWhiteSpace(finding.TargetSha256);
        if (RemediationEvidencePolicy.CanRemediate(finding) && boundContainer)
            return new(FindingDisposition.Actionable, DisplayText.Get("FindingHandling.Get.01"), DisplayText.Get("FindingHandling.Get.02"), DisplayText.Get("FindingHandling.Get.03"), true);
        if (RemediationEvidencePolicy.CanRemediate(finding) && !boundContainer)
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
        return Count(findings.Where(f => f.Category != FindingCategory.Coverage).Select(Get));
    }

    public static FindingHandlingCounts Count(IEnumerable<FindingHandlingInfo> handling)
    {
        FindingHandlingInfo[] items = handling.ToArray();
        return new(items.Count(i => i.Disposition == FindingDisposition.Actionable &&
                i.ScopeStatus is null or FileScopeStatus.Automatic),
            items.Count(i => i.Disposition == FindingDisposition.NeedsReview),
            items.Count(i => i.Disposition == FindingDisposition.Unsupported),
            items.Count(i => i.Disposition == FindingDisposition.Blocked),
            items.Count(i => i.Disposition == FindingDisposition.Informational),
            items.Count(i => i.CanSelect && i.ScopeStatus == FileScopeStatus.RequiresConsent),
            items.Count(i => i.CanSelect && i.ScopeStatus is FileScopeStatus.SensitiveRequiresConsent or FileScopeStatus.NeedsVerification),
            items.Any(i => i.ScopeStatus is not null));
    }
}
