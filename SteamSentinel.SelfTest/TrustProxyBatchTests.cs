using System.IO;
using System.Security.Cryptography;
using System.Text.Json;
using SteamSentinel.Core.Models;
using SteamSentinel.Core.Utilities;

namespace SteamSentinel.SelfTest;

internal static partial class Program
{
    private static void TestTrustProxyBatch()
    {
        JsonSerializerOptions wireOptions = new(JsonFile.Options) { WriteIndented = false };
        ScanReport source = TrustProxyBatchFixture(1, [48, 3, 2, 1, 0]);
        List<ReportBatch> frames = [];
        ReportBatchReader reader = new();
        int largest = 0;
        ReportBatchWriter writer = new(batch =>
        {
            string wire = JsonSerializer.Serialize(new WorkerMessage { Type = WorkerMessageTypes.Checkpoint, Batch = batch }, wireOptions);
            largest = Math.Max(largest, wire.Length);
            ReportBatch restored = JsonSerializer.Deserialize<WorkerMessage>(wire, JsonFile.Options)!.Batch!;
            frames.Add(restored);
            reader.Apply(restored);
        });
        writer.Send(source);
        Check("诊断批次仅在 final 传输快照", frames.All(f => f.TrustProxyFragment is null) && reader.Report!.TrustProxyDiagnostics is null);
        writer.Send(source, final: true);
        Check("诊断批次完整往返保留所有观察及关系", reader.Report is not null &&
            JsonSerializer.Serialize(source.TrustProxyDiagnostics, wireOptions) == JsonSerializer.Serialize(reader.Report.TrustProxyDiagnostics, wireOptions));
        Check("诊断批次兼容 scanid 序号及原范围偏移", reader.Count == writer.Count && reader.Report!.ScanId == source.ScanId &&
            reader.Report.Findings.Single().Id == source.Findings.Single().Id && reader.Report.CoverageNotes.SequenceEqual(source.CoverageNotes) &&
            reader.Report.CompletedAtUtc == source.CompletedAtUtc && !reader.HasIncompleteTrustProxyDiagnostics);
        Check("诊断批次不会把完整 DER 快照塞入 Data", frames.All(f => f.Data.TrustProxyDiagnostics is null) &&
            frames.Where(f => f.TrustProxyFragment is not null).All(f => f.TrustProxyFragment!.Certificates.Count <= 1 &&
                f.TrustProxyFragment.Proxies.Count <= 1 && f.TrustProxyFragment.Certificates.All(c => c.Data.DerBase64 == "")) && largest < 1024 * 1024);

        int first = frames.FindIndex(f => f.TrustProxyFragment is not null);
        int certificateFrame = frames.FindIndex(f => f.TrustProxyFragment?.Certificates.Count > 0);
        int proxyFrame = frames.FindIndex(f => f.TrustProxyFragment?.Proxies.Count > 0);
        int relationFrame = frames.FindIndex(f => f.TrustProxyFragment?.Relations.Count > 0);
        ReportBatchReader interrupted = new();
        foreach (ReportBatch batch in frames.Take(first + 1)) interrupted.Apply(batch);
        Check("诊断分片未齐不得显示为完整报告", interrupted.HasIncompleteTrustProxyDiagnostics && interrupted.Report is
        { Coverage: ScanCoverage.Partial, CompletedAtUtc: null, TrustProxyDiagnostics.CompletedAtUtc: null });

        bool RejectAt(int index, Func<ReportBatch, ReportBatch> change)
        {
            ReportBatchReader target = new();
            foreach (ReportBatch frame in frames.Take(index)) target.Apply(frame);
            string before = JsonSerializer.Serialize(target.Report, wireOptions);
            int count = target.Count;
            ReportBatch modified = change(frames[index]);
            modified = modified with
            {
                Data = new ScanReport
                {
                    ScanId = source.ScanId,
                    Findings = [new() { Title = "REJECTED-FINDING-MUST-NOT-APPEAR" }],
                    TrustProxyDiagnostics = modified.Data.TrustProxyDiagnostics
                }
            };
            try { target.Apply(modified); }
            catch (InvalidDataException)
            {
                return target.Count == count && JsonSerializer.Serialize(target.Report, wireOptions) == before;
            }
            return false;
        }

        Check("诊断错误偏移被拒绝且不部分提交发现或证书", RejectAt(certificateFrame, b => b with
        {
            TrustProxyFragment = b.TrustProxyFragment! with { Offsets = b.TrustProxyFragment.Offsets with { Certificates = 1 } }
        }));
        Check("诊断跨分片元数据变更被拒绝且不部分提交", RejectAt(certificateFrame, b => b with
        {
            TrustProxyFragment = b.TrustProxyFragment! with
            { Metadata = b.TrustProxyFragment.Metadata with { TargetUserSid = "S-1-5-21-10-20-30-1002" } }
        }));
        Check("诊断用户来源与元数据 SID 不符被拒绝", RejectAt(first, b => b with
        {
            TrustProxyFragment = b.TrustProxyFragment! with
            { Metadata = b.TrustProxyFragment.Metadata with { TargetUserSid = "S-1-5-21-10-20-30-1002" } }
        }));
        Check("诊断声明的累计证书数受限", RejectAt(first, b => b with
        {
            TrustProxyFragment = b.TrustProxyFragment! with
            { Metadata = b.TrustProxyFragment.Metadata with { Counts = b.TrustProxyFragment.Metadata.Counts with { Certificates = 8193 } } }
        }));
        Check("诊断声明的累计 DER 字节受限", RejectAt(first, b => b with
        {
            TrustProxyFragment = b.TrustProxyFragment! with
            { Metadata = b.TrustProxyFragment.Metadata with { Counts = b.TrustProxyFragment.Metadata.Counts with { DerBytes = 16L * 1024 * 1024 + 1 } } }
        }));
        Check("诊断单片不得混装多条代理", RejectAt(proxyFrame, b => b with
        {
            TrustProxyFragment = b.TrustProxyFragment! with { Proxies = [b.TrustProxyFragment.Proxies[0], b.TrustProxyFragment.Proxies[0]] }
        }));
        Check("诊断伪造结束标记被拒绝", RejectAt(first, b => b with { TrustProxyFragment = b.TrustProxyFragment! with { IsFinal = true } }));
        Check("诊断未知关系端点被拒绝且不部分提交", RejectAt(relationFrame, b => b with
        {
            TrustProxyFragment = b.TrustProxyFragment! with { Relations = [new("missing-observation", "fixture-certificate-0", "SameCertificateDer", "fixture")] }
        }));
        Check("诊断不规范 DER 编码被拒绝", RejectAt(certificateFrame, b => b with
        {
            TrustProxyFragment = b.TrustProxyFragment! with
            { Certificates = [b.TrustProxyFragment.Certificates[0] with { DerBase64Url = "not+base64url" }] }
        }));
        Check("诊断单 DER 大小受限", RejectAt(certificateFrame, b => b with
        {
            TrustProxyFragment = b.TrustProxyFragment! with
            { Certificates = [b.TrustProxyFragment.Certificates[0] with { DerBase64Url = new string('A', 180000) }] }
        }));
        Check("诊断 DER 与摘要不匹配被拒绝", RejectAt(certificateFrame, b => b with
        {
            TrustProxyFragment = b.TrustProxyFragment! with
            { Certificates = [b.TrustProxyFragment.Certificates[0] with { DerBase64Url = "AQIDBA" }] }
        }));
        Check("诊断完整 Data 旁路被拒绝且不部分提交", RejectAt(first, b => b with
        { Data = new ScanReport { ScanId = source.ScanId, TrustProxyDiagnostics = source.TrustProxyDiagnostics } }));

        ReportBatchReader fresh = new();
        bool firstRejected = false;
        try
        {
            fresh.Apply(new(0, new(0, 0, 0, 0, 0, 0, 0), new ScanReport { Findings = [new() { Title = "not committed" }] })
            {
                TrustProxyFragment = frames[first].TrustProxyFragment! with
                { Metadata = frames[first].TrustProxyFragment!.Metadata with { SchemaVersion = 99 } }
            });
        }
        catch (InvalidDataException) { firstRejected = true; }
        Check("首个异常诊断批次不创建半成品报告", firstRejected && fresh.Count == 0 && fresh.Report is null);

        byte[] extreme = new byte[128 * 1024];
        for (int i = 0; i < extreme.Length; i++) extreme[i] = (i % 3) switch { 0 => 0xfb, 1 => 0xef, _ => 0xbe };
        ScanReport maximum = TrustProxyBatchFixture(128, extreme);
        ReportBatchReader maximumReader = new();
        int maximumFrame = 0, certificateFrames = 0;
        new ReportBatchWriter(batch =>
        {
            string wire = JsonSerializer.Serialize(new WorkerMessage { Type = WorkerMessageTypes.Checkpoint, Batch = batch }, wireOptions);
            maximumFrame = Math.Max(maximumFrame, wire.Length);
            certificateFrames += batch.TrustProxyFragment?.Certificates.Count ?? 0;
            maximumReader.Apply(JsonSerializer.Deserialize<WorkerMessage>(wire, JsonFile.Options)!.Batch!);
        }).Send(maximum, final: true);
        Check("十六 MiB DER 通过单证书 Base64Url 分片往返且每帧小于一 MiB", certificateFrames == 128 && maximumFrame < 1024 * 1024 &&
            maximumReader.Report!.TrustProxyDiagnostics!.Certificates.Count == 128 &&
            maximumReader.Report.TrustProxyDiagnostics.Certificates.All(c => c.DerBase64 == Convert.ToBase64String(extreme)));
        Check("极端 Base64 加号不会经 JSON 转义膨胀传输", JsonSerializer.Serialize(Convert.ToBase64String(extreme), wireOptions).Length >= 1024 * 1024 &&
            maximumFrame < 512 * 1024);

        int sent = 0;
        bool overBudgetRejected = false;
        maximum.TrustProxyDiagnostics!.Certificates.Add(maximum.TrustProxyDiagnostics.Certificates[0]);
        try { new ReportBatchWriter(_ => sent++).Send(maximum, final: true); }
        catch (InvalidDataException) { overBudgetRejected = true; }
        Check("超累计 DER 预算在 final 发送任何范围前拒绝", overBudgetRejected && sent == 0);

        ScanReport unknownIdentity = new()
        {
            TrustProxyDiagnostics = new()
            {
                TargetUserSid = "",
                CompletedAtUtc = DateTimeOffset.UtcNow.AddSeconds(1),
                Checks = [new() { Name = "无法取得 SID", Status = DiagnosticReadStatus.Failed, Detail = "未执行用户采集" }]
            }
        };
        ReportBatchReader unknownReader = new();
        new ReportBatchWriter(unknownReader.Apply).Send(unknownIdentity, final: true);
        Check("身份未取得的失败诊断可完整传输且不捏造用户来源", unknownReader.Report!.TrustProxyDiagnostics is
        { TargetUserSid: "", Proxies.Count: 0, CertificateStores.Count: 0 } diagnostic && diagnostic.Checks.Single().Status == DiagnosticReadStatus.Failed);

        ScanReport empty = new() { TrustProxyDiagnostics = new() { TargetUserSid = "" } };
        ReportBatchReader emptyReader = new();
        new ReportBatchWriter(emptyReader.Apply).Send(empty, final: true);
        Check("空诊断快照以明确结束片保留", emptyReader.Report!.TrustProxyDiagnostics is not null && !emptyReader.HasIncompleteTrustProxyDiagnostics);
    }

    private static ScanReport TrustProxyBatchFixture(int count, byte[] bytes)
    {
        const string sid = "S-1-5-21-10-20-30-1001";
        DateTimeOffset started = DateTimeOffset.UtcNow.AddMinutes(-1);
        TrustProxyDiagnosticReport diagnostic = new()
        {
            TargetUserSid = sid,
            StartedAtUtc = started,
            CompletedAtUtc = started.AddSeconds(1),
            CertificateStores = [new()
            {
                Id = "fixture-store", Scope = "CurrentUser", UserSid = sid, StoreName = "Root", Provider = "fixture",
                Status = DiagnosticReadStatus.Complete, CertificatesRead = count
            }],
            Proxies = [new()
            {
                Id = "fixture-proxy", Source = "WinINetRegistry", Scope = "CurrentUser", UserSid = sid, Location = "fixture-key",
                ProxyEnabled = false, AutoConfigUrl = "http://pac.example.invalid/proxy.pac", Status = DiagnosticReadStatus.Complete,
                Values = [new("ProxyEnable", "REG_DWORD", "0", true), new("ProxyServer", "Missing", null, false, ReadStatus: DiagnosticReadStatus.NotPresent)]
            }],
            Checks = [new() { Id = "fixture-check", Name = "fixture read", ObservationId = "fixture-proxy", Status = DiagnosticReadStatus.Complete }]
        };
        string der = Convert.ToBase64String(bytes), sha256 = Convert.ToHexString(SHA256.HashData(bytes)), sha1 = Convert.ToHexString(SHA1.HashData(bytes));
        for (int i = 0; i < count; i++) diagnostic.Certificates.Add(new()
        {
            Id = "fixture-certificate-" + i,
            StoreObservationId = "fixture-store",
            DerBase64 = der,
            DerSha256 = sha256,
            Sha1Thumbprint = sha1,
            Subject = "CN=无害传输测试",
            Issuer = "CN=无害传输测试",
            ChainStatus = DiagnosticReadStatus.Complete,
            ChainScope = "fixture",
            ChainCertificateSha256 = [sha256],
            ChainFlags = ["fixture flag"],
            EnhancedKeyUsages = ["1.3.6.1.5.5.7.3.1"]
        });
        if (count > 0) diagnostic.Relations.Add(new("fixture-store", "fixture-certificate-0", "StoreContainsCertificate", "fixture observed DER"));
        return new ScanReport
        {
            StartedAtUtc = started,
            CompletedAtUtc = started.AddSeconds(2),
            TrustProxyDiagnostics = diagnostic,
            Findings = [new() { Id = "fixture-finding", Title = "harmless original finding" }],
            CoverageNotes = ["fixture note"]
        };
    }
}
