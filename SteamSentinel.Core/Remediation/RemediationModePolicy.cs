using SteamSentinel.Core.Models;
using SteamSentinel.Core.Steam;
using SteamSentinel.Core.Scanning;
using SteamSentinel.Core.Utilities;

namespace SteamSentinel.Core.Remediation;

/// <summary>Separates evidence from an explicit request to quarantine a selected physical file.</summary>
public static class RemediationModePolicy
{
    public static bool IsValid(RemediationMode mode) => mode is RemediationMode.Conservative or RemediationMode.Aggressive;

    public static bool CanRequestQuarantine(Finding finding)
    {
        if (finding.Category is not (FindingCategory.File or FindingCategory.Archive or FindingCategory.Process or
                FindingCategory.Persistence or FindingCategory.Steam or FindingCategory.WallpaperEngine) ||
            finding.Severity < FindingSeverity.Medium && !finding.SuggestedActions.Contains(SuggestedActionKind.ReviewOnly) ||
            finding.HandlingReason is FindingHandlingReason.IncompleteInspection or FindingHandlingReason.PrerequisiteNotMet ||
            !ContentDiscovery.IsLocalSafePath(finding.Target) || Directory.Exists(finding.Target)) return false;
        string? hash = TargetHash(finding);
        return Validation.IsHexSha256(hash);
    }

    public static string? TargetHash(Finding finding) => finding.TargetSha256 ??
        (finding.ContentPath is null || RelatedArtifactRelations.SamePath(finding.Target, finding.ContentPath)
            ? finding.Sha256 : null);

    public static Finding ProjectFinding(Finding finding, RemediationMode mode)
    {
        if (!IsValid(mode)) throw new ArgumentOutOfRangeException(nameof(mode));
        if (mode != RemediationMode.Aggressive ||
            !finding.UserSelectedRisk && RemediationEvidencePolicy.CanRemediate(finding) || !CanRequestQuarantine(finding))
            return finding;
        // Keep the finding's rule, score, severity and provenance. This is a choice to remove
        // the reviewed physical target, not new malware evidence or permission to execute it.
        return new Finding
        {
            Id = finding.Id, RuleId = finding.RuleId, Category = finding.Category, Severity = finding.Severity,
            Score = finding.Score, TitleText = finding.TitleText, DescriptionText = finding.DescriptionText,
            Target = finding.Target, EvidenceText = finding.EvidenceText, ReasonCode = finding.ReasonCode,
            Sha256 = finding.Sha256, ContentPath = finding.ContentPath, TargetSha256 = finding.TargetSha256,
            WorkshopId = finding.WorkshopId, AppId = finding.AppId, SourceKind = finding.SourceKind,
            SteamUiEvidence = finding.SteamUiEvidence, IsKnownMalware = false, CanRemediate = true,
            UserSelectedRisk = true, HandlingReason = finding.HandlingReason, HandlingDetailsText = finding.HandlingDetailsText,
            DiagnosticObservationIds = [.. finding.DiagnosticObservationIds],
            AssociationObservationIds = [.. finding.AssociationObservationIds],
            AssociationEvidenceTier = finding.AssociationEvidenceTier,
            SuggestedActions = [SuggestedActionKind.QuarantineFile], DetectedAtUtc = finding.DetectedAtUtc
        };
    }
}
