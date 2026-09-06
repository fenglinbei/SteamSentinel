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
                if (!AddRelation(new(certificate.StoreObservationId, certificate.Id, "StoreContainsCertificate", "从该真实来源只读取得的公开证书。"))) break;
            foreach (string hash in certificate.ChainCertificateSha256.Distinct(StringComparer.OrdinalIgnoreCase))
            {
                foreach (CertificateObservation member in certificatesByHash[hash].Where(c => c.Id != certificate.Id))
                    if (!AddRelation(new(certificate.Id, member.Id, "OfflineChainCertificateMatch", "离线链中的 DER 哈希与该存储中的证书相同；不代表某网站的实际连接链。"))) break;
                if (truncated) break;
            }
            if (truncated) break;
        }
        foreach (IGrouping<string, CertificateObservation> duplicates in certificatesByHash)
        {
            if (truncated) break;
            CertificateObservation[] occurrences = duplicates.ToArray();
            for (int i = 1; i < occurrences.Length; i++)
                if (!AddRelation(new(occurrences[0].Id, occurrences[i].Id, "SameCertificateDer", "相同 DER 存在于不同采集记录，真实存储来源分别保留。"))) break;
        }
        if (truncated) diagnostic.Checks.Add(new()
        {
            Name = "诊断关联数量",
            Status = DiagnosticReadStatus.LimitReached,
            Detail = $"关联记录达到 {MaximumRelations} 条上限，已保留所采集的原始观察，关联分析未完成。"
        });

        foreach (ProxyConfigurationObservation proxy in diagnostic.Proxies)
            AddCheck(diagnostic, proxy.Id, proxy.Source, proxy.Status, proxy.Detail);
        foreach (CertificateStoreObservation store in diagnostic.CertificateStores)
            AddCheck(diagnostic, store.Id, $"{store.Scope}/{store.StoreName}", store.Status, store.Detail);
        foreach (CertificateObservation certificate in diagnostic.Certificates.Where(c => c.ChainStatus != DiagnosticReadStatus.Complete))
            AddCheck(diagnostic, certificate.Id, "证书离线链检查", certificate.ChainStatus, certificate.ChainDetail);

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
                Title = "检测到代理配置，需进一步确认",
                Target = group.Key,
                Description = "代理可能来自合法工具或企业网络。这里只记录配置，尚未确认来源、实际请求路径或是否恶意。",
                Evidence = string.Join("\n", sources.Select(p => $"{p.Source}；{p.Scope}；{p.Location}；ProxyEnabled={p.ProxyEnabled?.ToString() ?? "未取得"}；ProxyServer={p.ProxyServer ?? "未取得"}；AutoConfigURL={p.AutoConfigUrl ?? "未取得"}")),
                HandlingReason = FindingHandlingReason.InsufficientEvidence,
                HandlingDetails = "发现代理配置，但写入来源和实际连接链尚未确认，暂不能自动处理。本次未修改该配置。",
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
                Title = "检测到需确认用途的证书名称",
                Target = certificates[0].Subject,
                Sha256 = certificates[0].DerSha256,
                Description = "证书名称包含代理调试工具或 Steam 站点线索，合法调试也可能出现这些名称。名称、自签属性和同机代理不能单独证明恶意或拦截。",
                Evidence = string.Join("\n", certificates.Select(c => $"证书 {c.Id}；存储 {c.StoreObservationId}；DER SHA-256={c.DerSha256}；Subject={c.Subject}；Issuer={c.Issuer}")),
                HandlingReason = FindingHandlingReason.InsufficientEvidence,
                HandlingDetails = "尚未确认该证书的用途、安装来源或是否用于实际连接，本次未删除或修改证书。",
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
                Title = "证书与代理诊断未完成",
                Target = check.Name,
                Description = check.Detail,
                Evidence = check.Status.ToString(),
                HandlingReason = FindingHandlingReason.IncompleteInspection,
                HandlingDetails = check.Detail,
                SourceKind = SourceKind,
                DiagnosticObservationIds = [check.ObservationId ?? check.Id]
            });
        }
    }

    public static bool IsIncomplete(DiagnosticCheck check) => check.Required &&
        check.Status is not (DiagnosticReadStatus.Complete or DiagnosticReadStatus.NotPresent);

    private static void AddCheck(TrustProxyDiagnosticReport diagnostic, string id, string name, DiagnosticReadStatus status, string detail)
    {
        if (!diagnostic.Checks.Any(c => c.ObservationId == id))
            diagnostic.Checks.Add(new() { ObservationId = id, Name = name, Status = status, Detail = detail });
    }

    private static string ProxyTarget(ProxyConfigurationObservation proxy) => !string.IsNullOrWhiteSpace(proxy.AutoConfigUrl)
        ? proxy.AutoConfigUrl : !string.IsNullOrWhiteSpace(proxy.ProxyServer) ? proxy.ProxyServer : proxy.Location;

    private static bool HasReviewName(CertificateObservation certificate) => new[] { "mitmproxy", "help.steampowered.com", "store.steampowered.com" }
        .Any(name => certificate.Subject.Contains(name, StringComparison.OrdinalIgnoreCase) || certificate.Issuer.Contains(name, StringComparison.OrdinalIgnoreCase));
}
