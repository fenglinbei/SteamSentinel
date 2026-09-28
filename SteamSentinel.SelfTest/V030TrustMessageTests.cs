using System.IO;
using System.Text.Json;
using System.Security.Cryptography.X509Certificates;
using SteamSentinel.Core.Models;
using SteamSentinel.Core.Reporting;
using SteamSentinel.Core.Scanning;
using SteamSentinel.Core.Utilities;

namespace SteamSentinel.SelfTest;

internal static partial class Program
{
    private static void TestV030TrustMessages()
    {
        const string sid = CertificateFixtureSid;
        ProxyTestReader reader = new(sid)
        {
            UserSettings = new(DiagnosticReadStatus.Complete,
                MessageText.Create("Backend.Core.ProxyConfigurationScanner.ReadRegistry.02"),
                [new("ProxyEnable", "REG_DWORD", "1", DiagnosticReadStatus.Complete),
                 new("ProxyServer", "REG_SZ", "user:secret@proxy.example.invalid:8080", DiagnosticReadStatus.Complete),
                 new("AutoConfigURL", "REG_SZ", "http://pac.example.invalid/config", DiagnosticReadStatus.Complete)])
        };
        TrustProxyDiagnosticReport diagnostic = new() { TargetUserSid = sid };
        new ProxyConfigurationScanner(reader).Collect(diagnostic, new());
        using X509Certificate2 cert = CreateTrustProxyRoot("CN=mitmproxy Inert Message Fixture");
        FakePhysicalCertificateReader certificates = new();
        certificates.Certificates[("CurrentUser", "Root")] = [cert.Export(X509ContentType.Cert)];
        new CertificateStoreScanner(certificates, () => sid).Collect(diagnostic, new());
        ScanReport report = new();
        TrustProxyCorrelator.Apply(report, diagnostic);
        string json = JsonSerializer.Serialize(report, JsonFile.Options);
        ScanReport copy = JsonSerializer.Deserialize<ScanReport>(json, JsonFile.Options)!;
        using (DisplayText.UseCulture(DisplayText.English))
        {
            ProxyConfigurationObservation proxy = copy.TrustProxyDiagnostics!.Proxies[0];
            Check("后台消息 代理脱敏值及详情为英文", !HasHan(proxy.DetailText.Display) &&
                !HasHan(proxy.ProxyServerText.Display) && proxy.Values.Single(v => v.Name == "ProxyServer").ValueMessage is not null);
            Check("后台消息 不保存代理凭据", !json.Contains("user:secret", StringComparison.Ordinal));
            Check("后台消息 证书存储及离线链为英文", copy.TrustProxyDiagnostics.CertificateStores.All(s => !HasHan(s.DetailText.Display)) &&
                copy.TrustProxyDiagnostics.Certificates.All(c => !HasHan(c.ChainDetailText.Display)));
            Check("后台消息 诊断发现标题理由及逐行证据为英文", copy.Findings.All(f => !HasHan(f.TitleText.Display) &&
                !HasHan(f.DescriptionText.Display) && !HasHan(f.EvidenceDisplay) && !HasHan(f.HandlingDetailsText.Display)));
            Check("后台消息 诊断显示不更改原记录或处置资格", json == JsonSerializer.Serialize(copy, JsonFile.Options) &&
                copy.Findings.All(f => !f.CanRemediate && !f.IsKnownMalware));
        }
        foreach (TrustProxyDiagnosticFragment fragment in TrustProxyDiagnosticFragments.Create(diagnostic))
            _ = JsonSerializer.Deserialize<TrustProxyDiagnosticFragment>(JsonSerializer.Serialize(fragment, JsonFile.Options), JsonFile.Options);
        ProxyConfigurationObservation invalid = new()
        {
            Source = "fixture",
            Scope = "LocalMachine",
            Location = "fixture",
            Status = DiagnosticReadStatus.Complete,
            Values = [new("ProxyServer", "REG_SZ", "raw", true) { ValueMessage = new("bad id", []) }]
        };
        TrustProxyDiagnosticReport malformed = new() { TargetUserSid = sid, Proxies = [invalid] };
        Check("后台消息 代理原值无效描述在分片边界被拒绝", V020Throws<InvalidDataException>(() => TrustProxyDiagnosticFragments.Create(malformed)));
        static bool HasHan(string value) => value.Any(c => c is >= '\u4e00' and <= '\u9fff');
    }
}
