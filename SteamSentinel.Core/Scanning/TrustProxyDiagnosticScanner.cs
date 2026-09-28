using SteamSentinel.Core.Reporting;
using System.Security.Principal;
using SteamSentinel.Core.Models;

namespace SteamSentinel.Core.Scanning;

public sealed class TrustProxyDiagnosticScanner
{
    private readonly Action<TrustProxyDiagnosticReport, DiagnosticScanLimits, CancellationToken> _proxies;
    private readonly Action<TrustProxyDiagnosticReport, DiagnosticScanLimits, CancellationToken> _certificates;
    private readonly Func<string> _userSid;

    public TrustProxyDiagnosticScanner() : this(new ProxyConfigurationScanner().Collect, new CertificateStoreScanner().Collect,
        CurrentUserSid)
    { }

    private static string CurrentUserSid()
    {
        using WindowsIdentity identity = WindowsIdentity.GetCurrent();
        return identity.User?.Value ?? string.Empty;
    }

    internal TrustProxyDiagnosticScanner(Action<TrustProxyDiagnosticReport, DiagnosticScanLimits, CancellationToken> proxies,
        Action<TrustProxyDiagnosticReport, DiagnosticScanLimits, CancellationToken> certificates, Func<string> userSid)
    { _proxies = proxies; _certificates = certificates; _userSid = userSid; }

    public void Collect(ScanReport report, IProgress<ScanProgress>? progress = null,
        CancellationToken cancellationToken = default, DiagnosticScanLimits? limits = null)
    {
        limits ??= new();
        string sid;
        try { sid = _userSid(); }
        catch (Exception ex) when (ex is System.Security.SecurityException or UnauthorizedAccessException or PlatformNotSupportedException)
        { sid = string.Empty; }
        TrustProxyDiagnosticReport diagnostic = new() { TargetUserSid = sid };
        report.AddScopeNote(MessageText.Create("Backend.Core.TrustProxyDiagnosticScanner.Collect.01"));
        report.AddScopeNote(MessageText.Create("Backend.Core.TrustProxyDiagnosticScanner.Collect.02"));
        try
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (string.IsNullOrWhiteSpace(sid))
                diagnostic.Checks.Add(new() { NameText = MessageText.Create("Backend.Core.TrustProxyDiagnosticScanner.Collect.03"), Status = DiagnosticReadStatus.Failed, DetailText = MessageText.Create("Backend.Core.TrustProxyDiagnosticScanner.Collect.04") });
            else
            {
                progress?.Report(new(MessageText.Create("Backend.Core.TrustProxyDiagnosticScanner.Collect.05"), MessageText.Create("Backend.Core.TrustProxyDiagnosticScanner.Collect.06"), 0, 2, MessageText.Create("Backend.Core.TrustProxyDiagnosticScanner.Collect.07")));
                RunCollector(_proxies, MessageText.Create("Backend.Core.TrustProxyDiagnosticScanner.Collect.08"), diagnostic, limits, cancellationToken);
                cancellationToken.ThrowIfCancellationRequested();
                progress?.Report(new(MessageText.Create("Backend.Core.TrustProxyDiagnosticScanner.Collect.09"), MessageText.Create("Backend.Core.TrustProxyDiagnosticScanner.Collect.10"), 1, 2, MessageText.Create("Backend.Core.TrustProxyDiagnosticScanner.Collect.11")));
                RunCollector(_certificates, MessageText.Create("Backend.Core.TrustProxyDiagnosticScanner.Collect.12"), diagnostic, limits, cancellationToken);
            }
        }
        catch (OperationCanceledException)
        { diagnostic.Checks.Add(new() { NameText = MessageText.Create("Backend.Core.TrustProxyDiagnosticScanner.Collect.13"), Status = DiagnosticReadStatus.Cancelled, DetailText = MessageText.Create("Backend.Core.TrustProxyDiagnosticScanner.Collect.14") }); }
        diagnostic.Checks.AddRange([
            new() { NameText = MessageText.Create("Backend.Core.TrustProxyDiagnosticScanner.Collect.15"), Status = DiagnosticReadStatus.NotChecked, Required = false, DetailText = MessageText.Create("Backend.Core.TrustProxyDiagnosticScanner.Collect.16") },
            new() { NameText = MessageText.Create("Backend.Core.TrustProxyDiagnosticScanner.Collect.17"), Status = DiagnosticReadStatus.NotChecked, Required = false, DetailText = MessageText.Create("Backend.Core.TrustProxyDiagnosticScanner.Collect.18") },
            new() { NameText = MessageText.Create("Backend.Core.TrustProxyDiagnosticScanner.Collect.19"), Status = DiagnosticReadStatus.NotChecked, Required = false, DetailText = MessageText.Create("Backend.Core.TrustProxyDiagnosticScanner.Collect.20") }
        ]);
        diagnostic.CompletedAtUtc = DateTimeOffset.UtcNow;
        TrustProxyCorrelator.Apply(report, diagnostic);
    }

    private static void RunCollector(Action<TrustProxyDiagnosticReport, DiagnosticScanLimits, CancellationToken> collector,
        MessageText name, TrustProxyDiagnosticReport diagnostic, DiagnosticScanLimits limits, CancellationToken token)
    {
        try { collector(diagnostic, limits, token); }
        catch (OperationCanceledException) { throw; }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            diagnostic.Checks.Add(new()
            {
                NameText = name,
                Status = ex is UnauthorizedAccessException or System.Security.SecurityException
            ? DiagnosticReadStatus.AccessDenied : DiagnosticReadStatus.Failed,
                DetailText = name + MessageText.Create("Backend.Core.TrustProxyDiagnosticScanner.RunCollector.01") + MessageExceptions.Describe(ex)
            });
        }
    }
}
