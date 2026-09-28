using SteamSentinel.Core.Reporting;
using SteamSentinel.Core.Models;

namespace SteamSentinel.Core.Scanning;

/// <summary>Only links observed identity/containment. Coexistence never establishes interception or a writer.</summary>
public static class TrustProxyCorrelator
{
    public const string SourceKind = "trust-proxy-diagnostics";
    public const int MaximumRelations = 16384;

    public static void Apply(ScanReport report, TrustProxyDiagnosticReport diagnostic)
    {
        report.TrustProxyDiagnostics = diagnostic;
        diagnostic.Relations.Clear();
        HashSet<string> storeIds = diagnostic.CertificateStores.Select(s => s.Id).ToHashSet(StringComparer.Ordinal);
        ILookup<string, CertificateObservation> certificatesByHash = diagnostic.Certificates
            .Where(c => c.DerSha256.Length > 0).ToLookup(c => c.DerSha256, StringComparer.OrdinalIgnoreCase);
        bool truncated = false;
        bool AddRelation(DiagnosticRelation relation)
        {
            if (diagnostic.Relations.Count < MaximumRelations) { diagnostic.Relations.Add(relation); return true; }
            truncated = true;
            return false;
        }
        foreach (CertificateObservation certificate in diagnostic.Certificates)
        {
            if (storeIds.Contains(certificate.StoreObservationId))
                if (!AddRelation(new(certificate.StoreObservationId, certificate.Id, "StoreContainsCertificate", MessageText.Create("Backend.Core.TrustProxyCorrelator.Apply.01")))) break;
            foreach (string hash in certificate.ChainCertificateSha256.Distinct(StringComparer.OrdinalIgnoreCase))
            {
                foreach (CertificateObservation member in certificatesByHash[hash].Where(c => c.Id != certificate.Id))
                    if (!AddRelation(new(certificate.Id, member.Id, "OfflineChainCertificateMatch", MessageText.Create("Backend.Core.TrustProxyCorrelator.Apply.02")))) break;
                if (truncated) break;
            }
            if (truncated) break;
        }
        foreach (IGrouping<string, CertificateObservation> duplicates in certificatesByHash)
        {
            if (truncated) break;
            CertificateObservation[] occurrences = duplicates.ToArray();
            for (int i = 1; i < occurrences.Length; i++)
                if (!AddRelation(new(occurrences[0].Id, occurrences[i].Id, "SameCertificateDer", MessageText.Create("Backend.Core.TrustProxyCorrelator.Apply.03")))) break;
        }
        if (truncated) diagnostic.Checks.Add(new()
        {
            NameText = MessageText.Create("Backend.Core.TrustProxyCorrelator.Apply.04"),
            Status = DiagnosticReadStatus.LimitReached,
            DetailText = MessageText.Create("Backend.Core.TrustProxyCorrelator.Apply.05", (MaximumRelations))
        });

        foreach (ProxyConfigurationObservation proxy in diagnostic.Proxies)
            AddCheck(diagnostic, proxy.Id, proxy.Source, proxy.Status, proxy.DetailText);
        foreach (CertificateStoreObservation store in diagnostic.CertificateStores)
            AddCheck(diagnostic, store.Id, $"{store.Scope}/{store.StoreName}", store.Status, store.DetailText);
        foreach (CertificateObservation certificate in diagnostic.Certificates.Where(c => c.ChainStatus != DiagnosticReadStatus.Complete))
            AddCheck(diagnostic, certificate.Id, MessageText.Create("Backend.Core.TrustProxyCorrelator.Apply.06"), certificate.ChainStatus, certificate.ChainDetailText);

        IEnumerable<ProxyConfigurationObservation> configured = diagnostic.Proxies.Where(p =>
            !string.IsNullOrWhiteSpace(p.AutoConfigUrl) || p.ProxyEnabled == true ||
            p.Source == "WinINetCurrentConnection" && !string.IsNullOrWhiteSpace(p.ProxyServer));
        foreach (IGrouping<string, ProxyConfigurationObservation> group in configured.GroupBy(ProxyTarget, StringComparer.Ordinal))
        {
            ProxyConfigurationObservation[] sources = group.ToArray();
            report.Findings.Add(new()
            {
                RuleId = "NETWORK-PROXY-PRESENT",
                Category = FindingCategory.Network,
                Severity = FindingSeverity.Information,
                Score = 5,
                TitleText = MessageText.Create("Backend.Core.TrustProxyCorrelator.Apply.07"),
                Target = group.Key,
                DescriptionText = MessageText.Create("Backend.Core.TrustProxyCorrelator.Apply.08"),
                EvidenceLines = sources.Select(p => MessageText.Create("Backend.Core.TrustProxyCorrelator.ProxyEvidence", p.Source, p.Scope, p.Location,
                    p.ProxyEnabled.HasValue ? (MessageText)p.ProxyEnabled.Value.ToString() : MessageText.Create("Backend.Core.TrustProxyCorrelator.Apply.09"),
                    p.ProxyServer is null ? MessageText.Create("Backend.Core.TrustProxyCorrelator.Apply.10") : p.ProxyServerText,
                    p.AutoConfigUrl is null ? MessageText.Create("Backend.Core.TrustProxyCorrelator.Apply.11") : p.AutoConfigUrlText)),
                HandlingReason = FindingHandlingReason.InsufficientEvidence,
                HandlingDetailsText = MessageText.Create("Backend.Core.TrustProxyCorrelator.Apply.12"),
                CanRemediate = false,
                IsKnownMalware = false,
                SuggestedActions = [SuggestedActionKind.ReviewOnly],
                SourceKind = SourceKind,
                DiagnosticObservationIds = sources.Select(p => p.Id).ToList()
            });
        }

        // These names are review hints, not a malware rule or permission to remove a certificate.
        foreach (IGrouping<string, CertificateObservation> group in diagnostic.Certificates.Where(HasReviewName)
            .GroupBy(c => c.DerSha256, StringComparer.OrdinalIgnoreCase))
        {
            CertificateObservation[] certificates = group.ToArray();
            report.Findings.Add(new()
            {
                RuleId = "CERTIFICATE-NAME-REVIEW",
                Category = FindingCategory.Certificate,
                Severity = FindingSeverity.Information,
                Score = 5,
                TitleText = MessageText.Create("Backend.Core.TrustProxyCorrelator.Apply.13"),
                Target = certificates[0].Subject,
                Sha256 = certificates[0].DerSha256,
                DescriptionText = MessageText.Create("Backend.Core.TrustProxyCorrelator.Apply.14"),
                EvidenceLines = certificates.Select(c => MessageText.Create("Backend.Core.TrustProxyCorrelator.Apply.15", c.Id, c.StoreObservationId, c.DerSha256, c.Subject, c.Issuer)),
                HandlingReason = FindingHandlingReason.InsufficientEvidence,
                HandlingDetailsText = MessageText.Create("Backend.Core.TrustProxyCorrelator.Apply.16"),
                CanRemediate = false,
                IsKnownMalware = false,
                SuggestedActions = [SuggestedActionKind.ReviewOnly],
                SourceKind = SourceKind,
                DiagnosticObservationIds = certificates.Select(c => c.Id).ToList()
            });
        }

        foreach (DiagnosticCheck check in diagnostic.Checks.Where(IsIncomplete))
        {
            report.Coverage = ScanCoverage.Partial;
            report.Findings.Add(new()
            {
                RuleId = "TRUST-PROXY-COVERAGE",
                Category = FindingCategory.Coverage,
                Severity = FindingSeverity.Information,
                TitleText = MessageText.Create("Backend.Core.TrustProxyCorrelator.Apply.17"),
                Target = check.Name,
                DescriptionText = check.DetailText,
                Evidence = check.Status.ToString(),
                HandlingReason = FindingHandlingReason.IncompleteInspection,
                HandlingDetailsText = check.DetailText,
                SourceKind = SourceKind,
                DiagnosticObservationIds = [check.ObservationId ?? check.Id]
            });
        }
    }

    public static bool IsIncomplete(DiagnosticCheck check) => check.Required &&
        check.Status is not (DiagnosticReadStatus.Complete or DiagnosticReadStatus.NotPresent);

    private static void AddCheck(TrustProxyDiagnosticReport diagnostic, string id, MessageText name, DiagnosticReadStatus status, MessageText detail)
    {
        if (!diagnostic.Checks.Any(c => c.ObservationId == id))
            diagnostic.Checks.Add(new() { ObservationId = id, NameText = name, Status = status, DetailText = detail });
    }

    private static string ProxyTarget(ProxyConfigurationObservation proxy) => !string.IsNullOrWhiteSpace(proxy.AutoConfigUrl)
        ? proxy.AutoConfigUrl : !string.IsNullOrWhiteSpace(proxy.ProxyServer) ? proxy.ProxyServer : proxy.Location;

    private static bool HasReviewName(CertificateObservation certificate) => new[] { "mitmproxy", "help.steampowered.com", "store.steampowered.com" }
        .Any(name => certificate.Subject.Contains(name, StringComparison.OrdinalIgnoreCase) || certificate.Issuer.Contains(name, StringComparison.OrdinalIgnoreCase));
}
