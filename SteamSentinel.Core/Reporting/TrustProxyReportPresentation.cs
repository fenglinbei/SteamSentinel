using System.Text;
using SteamSentinel.Core.Inspection;
using SteamSentinel.Core.Models;
using SteamSentinel.Core.Scanning;

namespace SteamSentinel.Core.Reporting;

public static class TrustProxyReportPresentation
{
    public static string Describe(TrustProxyDiagnosticReport diagnostic, System.Globalization.CultureInfo culture)
    {
        using IDisposable scope = DisplayText.UseCulture(culture);
        return Describe(diagnostic);
    }

    public static string StatusLabel(DiagnosticReadStatus status, System.Globalization.CultureInfo culture)
    {
        using IDisposable scope = DisplayText.UseCulture(culture);
        return StatusLabel(status);
    }

    public static string StatusLabel(DiagnosticReadStatus status) => status switch
    {
        DiagnosticReadStatus.Complete => DisplayText.Get("TrustProxyReport.StatusLabel.Complete.01"),
        DiagnosticReadStatus.NotPresent => DisplayText.Get("TrustProxyReport.StatusLabel.NotPresent.01"),
        DiagnosticReadStatus.NotChecked => DisplayText.Get("TrustProxyReport.StatusLabel.NotChecked.01"),
        DiagnosticReadStatus.AccessDenied => DisplayText.Get("TrustProxyReport.StatusLabel.AccessDenied.01"),
        DiagnosticReadStatus.LimitReached => DisplayText.Get("TrustProxyReport.StatusLabel.LimitReached.01"),
        DiagnosticReadStatus.Cancelled => DisplayText.Get("TrustProxyReport.StatusLabel.Cancelled.01"),
        DiagnosticReadStatus.Failed => DisplayText.Get("TrustProxyReport.StatusLabel.01"),
        _ => DisplayText.Get("Common.Unknown")
    };

    public static string Describe(TrustProxyDiagnosticReport diagnostic)
    {
        StringBuilder text = new();
        text.AppendLine(DisplayText.Get("TrustProxyReport.Describe.01"));
        text.AppendLine(DisplayText.Format("TrustProxyReport.Describe.02", (Display(diagnostic.TargetUserSid))));
        text.AppendLine(DisplayText.Format("TrustProxyReport.Describe.03", (diagnostic.StartedAtUtc), (diagnostic.CompletedAtUtc)));
        text.AppendLine(DisplayText.Format("TrustProxyReport.Describe.04", (diagnostic.Proxies.Count), (diagnostic.CertificateStores.Count), (diagnostic.Certificates.Count), (diagnostic.Checks.Count(TrustProxyCorrelator.IsIncomplete))));
        text.AppendLine(DisplayText.Get("TrustProxyReport.Describe.05"));
        text.AppendLine();
        text.AppendLine(DisplayText.Get("TrustProxyReport.Describe.06"));
        foreach (ProxyConfigurationObservation proxy in diagnostic.Proxies)
        {
            text.AppendLine($"[{StatusLabel(proxy.Status)}] {Display(proxy.Source)} · {Display(proxy.Scope)} · ID {proxy.Id}");
            text.AppendLine(DisplayText.Format("TrustProxyReport.Describe.07", (Display(proxy.Location)), (Display(proxy.UserSid))));
            text.AppendLine(DisplayText.Format("TrustProxyReport.Describe.08", (Boolean(proxy.ProxyEnabled)), (Boolean(proxy.AutoDetect))));
            text.AppendLine(DisplayText.Format("TrustProxyReport.Describe.09", (Display(proxy.ProxyServerText.Display)), (Display(proxy.ProxyBypassText.Display))));
            text.AppendLine(DisplayText.Format("TrustProxyReport.Describe.10", (Display(proxy.AutoConfigUrlText.Display))));
            foreach (DiagnosticConfigurationValue value in proxy.Values)
                text.AppendLine("  " + DisplayText.Format("Common.LabelValue", $"{Display(value.Name)} ({Display(value.Kind)})",
                    (value.Present ? Display(value.ValueText.Display) : value.ReadStatus == DiagnosticReadStatus.NotPresent || value.Kind == "Missing" ? DisplayText.Get("TrustProxyReport.Describe.11") : DisplayText.Get("TrustProxyReport.Describe.12")) +
                    (value.Redacted ? DisplayText.Get("TrustProxyReport.Describe.13") : "")));
            text.AppendLine(DisplayText.Get("TrustProxyReport.Describe.14") + Display(proxy.DetailText.Display));
        }
        text.AppendLine();
        text.AppendLine(DisplayText.Get("TrustProxyReport.Describe.15"));
        foreach (CertificateStoreObservation store in diagnostic.CertificateStores)
        {
            text.AppendLine(DisplayText.Format("TrustProxyReport.Describe.16", (StatusLabel(store.Status)), (Display(store.Scope)), (Display(store.StoreName)), (Display(store.Provider)), (store.CertificatesRead), (store.Id)));
            text.AppendLine(DisplayText.Format("TrustProxyReport.Describe.17", (Display(store.UserSid)), (Display(store.DetailText.Display))));
            foreach (CertificateObservation certificate in diagnostic.Certificates.Where(c => c.StoreObservationId == store.Id))
            {
                text.AppendLine(DisplayText.Get("TrustProxyReport.Describe.18") + certificate.Id);
                text.AppendLine(DisplayText.Get("TrustProxyReport.Describe.19") + Display(certificate.Subject));
                text.AppendLine(DisplayText.Get("TrustProxyReport.Describe.20") + Display(certificate.Issuer));
                text.AppendLine("    " + DisplayText.Format("Common.LabelValue", "DER SHA-256", Display(certificate.DerSha256)));
                text.AppendLine(DisplayText.Get("TrustProxyReport.Describe.21") + Display(certificate.Sha1Thumbprint));
                text.AppendLine(DisplayText.Format("TrustProxyReport.Describe.22", (certificate.NotBeforeUtc), (certificate.NotAfterUtc)));
                text.AppendLine(DisplayText.Format("TrustProxyReport.Describe.23", (Boolean(certificate.IsCertificateAuthority)), ((certificate.HasPathLengthConstraint == true ? certificate.PathLengthConstraint?.ToString() ?? DisplayText.Get("TrustProxyReport.Describe.24") : certificate.HasPathLengthConstraint == false ? DisplayText.Get("TrustProxyReport.Describe.25") : DisplayText.Get("TrustProxyReport.Describe.26"))), (Display(certificate.KeyUsage))));
                text.AppendLine(DisplayText.Format("TrustProxyReport.Describe.27", (Display(string.Join(", ", certificate.EnhancedKeyUsages))), (certificate.SubjectEqualsIssuer), (Boolean(certificate.SelfSignatureVerified))));
                text.AppendLine(DisplayText.Format("TrustProxyReport.Describe.28", (StatusLabel(certificate.ChainStatus)), (Display(string.Join(", ", certificate.ChainFlags)))));
                text.AppendLine(DisplayText.Get("TrustProxyReport.Describe.29") + Display(certificate.ChainScope) + DisplayText.Get("Common.Semicolon") + Display(certificate.ChainDetailText.Display));
            }
        }
        text.AppendLine();
        text.AppendLine(DisplayText.Get("TrustProxyReport.Describe.30"));
        foreach (DiagnosticCheck check in diagnostic.Checks)
            text.AppendLine(DisplayText.Format("Common.LabelValue", $"[{StatusLabel(check.Status)}] {Display(check.NameText.Display)}{(check.Required ? "" : DisplayText.Get("TrustProxyReport.Describe.31"))}", Display(check.DetailText.Display)));
        text.AppendLine();
        text.AppendLine(DisplayText.Format("TrustProxyReport.Describe.32", (diagnostic.Relations.Count)));
        return text.ToString();
    }

    private static string Boolean(bool? value) => value.HasValue ? value.Value ? DisplayText.Get("TrustProxyReport.Boolean.01") : DisplayText.Get("TrustProxyReport.Boolean.02") : DisplayText.Get("TrustProxyReport.Boolean.03");
    private static string Display(string? value) => string.IsNullOrEmpty(value) ? DisplayText.Get("TrustProxyReport.Display.01") :
        ScriptSignals.RedactSecrets(value).Replace("\r", " ").Replace("\n", " ").Replace("\t", " ");
}
