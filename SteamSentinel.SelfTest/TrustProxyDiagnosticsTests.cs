using System.IO;
using System.IO.Compression;
using System.Text.Json;
using SteamSentinel.App.Services;
using SteamSentinel.Core.Models;
using SteamSentinel.Core.Reporting;
using SteamSentinel.Core.Scanning;
using SteamSentinel.Core.Utilities;

namespace SteamSentinel.SelfTest;

internal static partial class Program
{
    private static async Task TestTrustProxyDiagnosticsAsync(string root)
    {
        const string sid = "S-1-5-21-100-200-300-1001";
        TrustProxyDiagnosticReport diagnostic = new() { TargetUserSid = sid, CompletedAtUtc = DateTimeOffset.UtcNow };
        diagnostic.Proxies.AddRange([
            new() { Id = "pac-user", Source = "WinINetUserRegistry", Scope = "CurrentUser", UserSid = sid,
                Location = "HKU/fixture", Status = DiagnosticReadStatus.Failed, AutoConfigUrl = "http://127.0.0.1:8899/proxy.pac",
                Detail = "ProxyEnable 类型不符合预期；PAC 地址已读取。",
                Values = [new("ProxyEnable", "NotRead", null, false, ReadStatus: DiagnosticReadStatus.Failed)] },
            new() { Id = "pac-api", Source = "WinINetCurrentConnection", Scope = "CurrentUser", UserSid = sid,
                Status = DiagnosticReadStatus.Complete, ProxyEnabled = false, AutoConfigUrl = "http://127.0.0.1:8899/proxy.pac" },
            new() { Id = "disabled-manual", Source = "WinINetUserRegistry", ProxyEnabled = false,
                ProxyServer = "127.0.0.1:7890", Status = DiagnosticReadStatus.Complete }
        ]);
        diagnostic.CertificateStores.AddRange([
            new() { Id = "cu-root", Scope = "CurrentUser", StoreName = "Root", UserSid = sid, Status = DiagnosticReadStatus.Complete },
            new() { Id = "lm-ca", Scope = "LocalMachine", StoreName = "CA", Status = DiagnosticReadStatus.Complete }
        ]);
        diagnostic.Certificates.AddRange([
            new() { Id = "cert-a", StoreObservationId = "cu-root", Subject = "CN=mitmproxy", Issuer = "CN=mitmproxy",
                SubjectEqualsIssuer = true, DerSha256 = new('A', 64), DerBase64 = "AQID", ChainStatus = DiagnosticReadStatus.Complete },
            new() { Id = "cert-b", StoreObservationId = "lm-ca", Subject = "CN=mitmproxy", Issuer = "CN=mitmproxy",
                SubjectEqualsIssuer = true, DerSha256 = new('A', 64), DerBase64 = "AQID", ChainStatus = DiagnosticReadStatus.Complete },
            new() { Id = "different-key", StoreObservationId = "lm-ca", Subject = "CN=mitmproxy", Issuer = "CN=mitmproxy",
                DerSha256 = new('B', 64), DerBase64 = "BAUG", ChainStatus = DiagnosticReadStatus.Complete },
            new() { Id = "inert-dev", StoreObservationId = "cu-root", Subject = "CN=Inert Local Developer", Issuer = "CN=Inert Local Developer",
                DerSha256 = new('C', 64), DerBase64 = "BwgJ", SubjectEqualsIssuer = true, ChainStatus = DiagnosticReadStatus.Complete,
                ChainCertificateSha256 = [new('A', 64)] }
        ]);
        diagnostic.Checks.Add(new() { Name = "TLS", Status = DiagnosticReadStatus.NotChecked, Required = false });
        ScanReport report = new();
        TrustProxyCorrelator.Apply(report, diagnostic);
        Finding pac = report.Findings.Single(f => f.RuleId == "NETWORK-PROXY-PRESENT");
        Check("诊断 有效PAC在另一字段读取失败和手动代理关闭时仍保留并合并真实来源",
            pac.DiagnosticObservationIds.SequenceEqual(new[] { "pac-user", "pac-api" }) &&
            pac.Target.EndsWith("proxy.pac", StringComparison.Ordinal) && report.Coverage == ScanCoverage.Partial);
        Check("诊断 工具名称和自签属性不授权判恶或删除",
            report.Findings.All(f => !f.IsKnownMalware && !f.CanRemediate) &&
            report.Findings.Count(f => f.RuleId == "CERTIFICATE-NAME-REVIEW") == 2 &&
            report.Findings.All(f => !f.DiagnosticObservationIds.Contains("inert-dev")));
        Check("诊断 关联仅使用存储来源与相同DER而不连接同名不同证书或代理",
            diagnostic.Relations.Any(r => r.FromId == "cert-a" && r.ToId == "cert-b" && r.Kind == "SameCertificateDer") &&
            diagnostic.Relations.Any(r => r.FromId == "inert-dev" && r.ToId == "cert-a" && r.Kind == "OfflineChainCertificateMatch") &&
            diagnostic.Relations.All(r => !(r.FromId == "cert-a" && r.ToId == "different-key")) &&
            diagnostic.Relations.All(r => !r.FromId.StartsWith("pac-", StringComparison.Ordinal)));
        string display = TrustProxyReportPresentation.Describe(diagnostic);
        Check("诊断 未读值与不存在值区分且明确无安装时间和自签名结论",
            display.Contains("ProxyEnable (NotRead)：未读取／存在性未知", StringComparison.Ordinal) &&
            display.Contains("安装时间：未知", StringComparison.Ordinal) && display.Contains("自签名密码学校验：未检查／未取得", StringComparison.Ordinal));

        Finding ordinary = new() { Title = "普通网络信息", Severity = FindingSeverity.Information };
        Finding legacy = new() { RuleId = "NETWORK-PROXY-PRESENT", Severity = FindingSeverity.Information, SuggestedActions = [SuggestedActionKind.ReviewOnly] };
        Finding unsupported = new() { HandlingReason = FindingHandlingReason.UnsupportedAction, HandlingDetails = "未实现该动作" };
        Finding unbound = new() { CanRemediate = true, ContentPath = "inert.zip!/child.exe" };
        Finding actionable = new() { CanRemediate = true, Target = "inert.txt" };
        FindingHandlingCounts counts = FindingHandlingPresentation.Count([ordinary, legacy, unsupported, unbound, actionable]);
        Check("诊断 处理资格区分普通说明待确认不支持和阻塞而不误称执行失败",
            counts is { Actionable: 1, NeedsReview: 1, Unsupported: 1, Blocked: 1, Informational: 1 } &&
            counts.AttentionCount == 3 && !FindingHandlingPresentation.Get(unbound).CanSelect &&
            !FindingHandlingPresentation.Get(legacy).Label.Contains("失败", StringComparison.Ordinal));

        ScanReport scope = new();
        new TrustProxyDiagnosticScanner((_, _, _) => { }, (_, _, _) => { }, () => sid).Collect(scope);
        Check("诊断 本次范围外的PAC正文和TLS未检查不会冒充失败或实际已检查",
            scope.Coverage == ScanCoverage.Complete && scope.TrustProxyDiagnostics!.Checks.Count == 3 &&
            scope.TrustProxyDiagnostics.Checks.All(c => c.Status == DiagnosticReadStatus.NotChecked && !c.Required));
        int calls = 0;
        ScanReport missingIdentity = new();
        new TrustProxyDiagnosticScanner((_, _, _) => calls++, (_, _, _) => calls++, () => "").Collect(missingIdentity);
        Check("诊断 缺少目标SID不采集其他账户且保留部分检查说明",
            calls == 0 && missingIdentity.Coverage == ScanCoverage.Partial && missingIdentity.Findings.Any(f => f.RuleId == "TRUST-PROXY-COVERAGE"));
        ScanReport failure = new();
        new TrustProxyDiagnosticScanner((d, _, _) => { d.Proxies.Add(new() { Id = "kept", Status = DiagnosticReadStatus.Complete }); throw new UnauthorizedAccessException("fixture denied"); },
            (_, _, _) => calls++, () => sid).Collect(failure);
        Check("诊断 某采集器失败保留已取得数据且继续另一独立采集器",
            calls == 1 && failure.Coverage == ScanCoverage.Partial && failure.TrustProxyDiagnostics!.Proxies.Single().Id == "kept" &&
            failure.TrustProxyDiagnostics.Checks.Any(c => c.Status == DiagnosticReadStatus.AccessDenied));
        using CancellationTokenSource cancelled = new();
        cancelled.Cancel();
        ScanReport cancellation = new();
        new TrustProxyDiagnosticScanner((_, _, _) => calls++, (_, _, _) => calls++, () => sid).Collect(cancellation, cancellationToken: cancelled.Token);
        Check("诊断 预取消不会读系统或报告为完整",
            calls == 1 && cancellation.Coverage == ScanCoverage.Partial && cancellation.TrustProxyDiagnostics!.Checks.Any(c => c.Status == DiagnosticReadStatus.Cancelled));

        TrustProxyDiagnosticReport crowded = new();
        for (int i = 0; i < 140; i++) crowded.Certificates.Add(new()
        {
            Id = "dup-" + i,
            DerSha256 = new('A', 64),
            ChainStatus = DiagnosticReadStatus.Complete,
            ChainCertificateSha256 = [new('A', 64)]
        });
        ScanReport crowdedReport = new();
        TrustProxyCorrelator.Apply(crowdedReport, crowded);
        Check("诊断 重复证书关系在有界图内停止且原始观察保留并报告未完成",
            crowded.Relations.Count == TrustProxyCorrelator.MaximumRelations && crowded.Certificates.Count == 140 &&
            crowdedReport.Coverage == ScanCoverage.Partial && crowded.Checks.Any(c => c.Status == DiagnosticReadStatus.LimitReached));

        string dir = Path.Combine(root, "trust-proxy-reports");
        Directory.CreateDirectory(dir);
        string json = Path.Combine(dir, "scan.json"), markdown = Path.Combine(dir, "scan.md"), bundle = Path.Combine(dir, "case.zip");
        report.Findings.Add(unbound);
        await ReportExporter.ExportJsonAsync(report, json);
        await ReportExporter.ExportMarkdownAsync(report, markdown);
        ScanReport decoded = (await JsonFile.ReadAsync<ScanReport>(json))!;
        string md = await File.ReadAllTextAsync(markdown);
        Check("诊断 JSON往返保留来源ID字段状态DER与关系",
            decoded.TrustProxyDiagnostics!.Certificates[0].DerBase64 == "AQID" &&
            decoded.TrustProxyDiagnostics.Relations.Count == diagnostic.Relations.Count &&
            decoded.TrustProxyDiagnostics.Proxies[0].Values[0].ReadStatus == DiagnosticReadStatus.Failed &&
            decoded.Findings.Any(f => f.DiagnosticObservationIds.SequenceEqual(pac.DiagnosticObservationIds)));
        Check("诊断 Markdown解释资格和完整性且未绑定外层文件不宣称可选中处置",
            md.Contains("证书与代理只读诊断", StringComparison.Ordinal) && md.Contains("本扫描记录未执行该项修改", StringComparison.Ordinal) &&
            !md.Contains("可选中处置，仍需确认预览", StringComparison.Ordinal));
        ScanReport old = new(); old.Findings.Add(ordinary);
        await CaseBundleExporter.ExportAsync(bundle, old, null, null, null, latestDiagnostics: diagnostic);
        using (ZipArchive zip = ZipFile.OpenRead(bundle))
        {
            using Stream before = zip.GetEntry("scan.json")!.Open();
            ScanReport? original = await JsonSerializer.DeserializeAsync<ScanReport>(before, JsonFile.Options);
            using Stream latest = zip.GetEntry("trust-proxy-diagnostics.json")!.Open();
            TrustProxyDiagnosticReport? later = await JsonSerializer.DeserializeAsync<TrustProxyDiagnosticReport>(latest, JsonFile.Options);
            Check("诊断 证据ZIP独立保存最新诊断而不重写处置前报告或附带样本",
                original?.ScanId == old.ScanId && original.TrustProxyDiagnostics is null &&
                later?.TargetUserSid == sid && zip.Entries.Count == 3 && zip.Entries.All(e => !e.Name.EndsWith(".der", StringComparison.Ordinal)));
        }
        ScanReport merged = ScanReportMerger.Merge(report, old);
        Check("诊断 系统与内容报告合并保留系统诊断及原有结果",
            ReferenceEquals(merged.TrustProxyDiagnostics, diagnostic) && merged.Findings.Count == report.Findings.Count + old.Findings.Count &&
            merged.Coverage == ScanCoverage.Partial);

        using CancellationTokenSource stageCancellation = new();
        ScanReport? systemCheckpoint = null;
        bool stageCancelled = false;
        try
        {
            await new ScanCoordinator().RunAsync(new ScanOptions
            {
                Mode = ScanMode.Custom,
                IncludeSystem = false,
                IncludeSteam = false,
                IncludeWorkshop = false,
                IncludeRelatedContent = false,
                CustomRoots = [dir]
            }, cancellationToken: stageCancellation.Token,
                checkpoint: state => { systemCheckpoint = state; state.TrustProxyDiagnostics = diagnostic; stageCancellation.Cancel(); });
        }
        catch (OperationCanceledException) { stageCancelled = true; }
        ScanReport preserved = ScanFailureReports.PreserveSystemStage(systemCheckpoint, ScanMode.Quick, "inert",
            new OperationCanceledException("fixture cancellation"), true);
        Check("诊断 常规扫描取消后检查点仍能保存已读诊断且明确系统未完成",
            stageCancelled && ReferenceEquals(preserved.TrustProxyDiagnostics, diagnostic) && preserved.Coverage == ScanCoverage.Partial &&
            preserved.Findings.Any(f => f.RuleId == "SYSTEM-SCAN-INCOMPLETE") &&
            CoveragePresentation.Groups(preserved).Any(g => g.Kind == "系统检查未完成" && !g.CanFullScan));
    }
}
