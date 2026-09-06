using System.ComponentModel;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using SteamSentinel.Core.Models;
using SteamSentinel.Core.Scanning;

namespace SteamSentinel.SelfTest;

internal static partial class Program
{
    private const string CertificateFixtureSid = "S-1-5-21-121-232-343-1001";

    private static void TestTrustProxyCertificates()
    {
        // All keys and certificate fixtures exist only in memory. No X509Store,
        // import, local store enumeration, or private-key persistence is used.
        using X509Certificate2 first = CreateTrustProxyRoot("CN=SteamSentinel Inert Same Name");
        using X509Certificate2 second = CreateTrustProxyRoot("CN=SteamSentinel Inert Same Name");
        byte[] firstDer = first.Export(X509ContentType.Cert), secondDer = second.Export(X509ContentType.Cert);
        string firstHash = Convert.ToHexString(SHA256.HashData(firstDer));

        FakePhysicalCertificateReader source = new();
        source.Certificates[("CurrentUser", "Root")] = [firstDer];
        source.Certificates[("LocalMachine", "Root")] = [firstDer, secondDer];
        TrustProxyDiagnosticReport report = CertificateDiagnostic();
        new CertificateStoreScanner(source, () => CertificateFixtureSid).Collect(report, new());
        Check("证书仅请求四个真实物理来源且保留目标用户SID", source.Requests.Count == 4 &&
            source.Requests.All(s => s.Scope == "CurrentUser" ? s.UserSid == CertificateFixtureSid : s.UserSid is null) &&
            report.CertificateStores.All(s => s.Provider == CertificateStoreScanner.PhysicalProvider));
        Check("机器证书不通过逻辑CU视图重复归属", report.CertificateStores.Single(s => s.Scope == "CurrentUser" && s.StoreName == "Root").CertificatesRead == 1 &&
            report.CertificateStores.Single(s => s.Scope == "LocalMachine" && s.StoreName == "Root").CertificatesRead == 2);
        Check("同名不同指纹证书分别保留", report.Certificates.Where(c => c.Subject == first.Subject).Select(c => c.DerSha256).Distinct().Count() == 2);
        Check("相同DER在CU与LM各自保存来源不互相覆盖", report.Certificates.Where(c => c.DerSha256 == firstHash).Select(c => c.StoreObservationId).Distinct().Count() == 2);
        CertificateObservation sample = report.Certificates.First(c => c.DerSha256 == firstHash);
        Check("证书公开DER与SHA256和SHA1对应同一字节", Convert.FromBase64String(sample.DerBase64).SequenceEqual(firstDer) &&
            sample.DerSha256 == firstHash && sample.Sha1Thumbprint == Convert.ToHexString(SHA1.HashData(firstDer)));
        using (X509Certificate2 publicCopy = X509CertificateLoader.LoadCertificate(Convert.FromBase64String(sample.DerBase64)))
            Check("采集结果仅含公开证书不含私钥", !publicCopy.HasPrivateKey);
        Check("BasicConstraints路径长度EKU与KeyUsage得到保留", sample.IsCertificateAuthority == true &&
            sample.HasPathLengthConstraint == true && sample.PathLengthConstraint == 1 && sample.BasicConstraintsCritical == true &&
            sample.KeyUsage?.Contains("KeyCertSign", StringComparison.Ordinal) == true && sample.EnhancedKeyUsages.Contains("1.3.6.1.5.5.7.3.1"));
        Check("同名主体与离线链成功不被伪造为自签名证明", sample.SubjectEqualsIssuer && sample.SelfSignatureVerified is null &&
            report.Certificates.All(c => c.SelfSignatureVerified is null));
        Check("有效期保存为UTC且不声称安装时间", sample.NotBeforeUtc.Offset == TimeSpan.Zero && sample.NotAfterUtc.Offset == TimeSpan.Zero &&
            sample.NotAfterUtc > sample.NotBeforeUtc && report.Checks.Any(c => c.Detail.Contains("有效期不代表安装时间", StringComparison.Ordinal)));
        Check("证书采集不创建风险关系或处置授权", report.Relations.Count == 0 && report.Certificates.All(c => c.SelfSignatureVerified is null));

        uint currentFlags = NativePhysicalCertificateStoreReader.FlagsFor(new("CurrentUser", "Root", CertificateFixtureSid));
        uint machineFlags = NativePhysicalCertificateStoreReader.FlagsFor(new("LocalMachine", "Root", null));
        Check("物理store始终只读且仅打开已存在项", (currentFlags & NativePhysicalCertificateStoreReader.ReadOnly) != 0 &&
            (currentFlags & NativePhysicalCertificateStoreReader.OpenExisting) != 0 &&
            (machineFlags & NativePhysicalCertificateStoreReader.ReadOnly) != 0 && (machineFlags & 0x00FF0000) == 0x00020000);
        Check("CU物理Root枚举不被保护根缓存过滤且没有机器继承标志", (currentFlags & 0x00FF0000) == 0x00010000 &&
            (currentFlags & NativePhysicalCertificateStoreReader.UnprotectedRootEnumeration) != 0);

        using (X509Certificate2 publicRoot = X509CertificateLoader.LoadCertificate(firstDer))
        {
            X509ChainPolicy policy = OfflineCertificateSnapshotChainBuilder.CreatePolicy([publicRoot], [], DateTimeOffset.UtcNow);
            Check("离线链只使用显式快照锚点并关闭下载撤销", policy.TrustMode == X509ChainTrustMode.CustomRootTrust &&
                policy.DisableCertificateDownloads && policy.RevocationMode == X509RevocationMode.NoCheck &&
                policy.CustomTrustStore.Count == 1 && policy.ExtraStore.Count == 0 && policy.VerificationFlags == X509VerificationFlags.NoFlag);
        }
        Check("完整的内存根快照可完成离线链检查", report.Certificates.All(c => c.ChainStatus == DiagnosticReadStatus.Complete &&
            c.ChainFlags.Count == 0 && c.ChainCertificateSha256.All(hash => report.Certificates.Any(other => other.DerSha256 == hash))));

        using X509Certificate2 intermediate = CreateTrustProxyIssuedCertificate("CN=SteamSentinel Inert Intermediate", first, true);
        using X509Certificate2 leaf = CreateTrustProxyIssuedCertificate("CN=SteamSentinel Inert Leaf", intermediate, false);
        byte[] intermediateDer = intermediate.Export(X509ContentType.Cert), leafDer = leaf.Export(X509ContentType.Cert);
        string intermediateHash = Convert.ToHexString(SHA256.HashData(intermediateDer));
        string leafHash = Convert.ToHexString(SHA256.HashData(leafDer));
        FakePhysicalCertificateReader chainedSource = new();
        chainedSource.Certificates[("LocalMachine", "Root")] = [firstDer];
        chainedSource.Certificates[("CurrentUser", "CA")] = [intermediateDer, leafDer];
        TrustProxyDiagnosticReport chained = CertificateDiagnostic();
        new CertificateStoreScanner(chainedSource, () => CertificateFixtureSid).Collect(chained, new());
        CertificateObservation leafObservation = chained.Certificates.Single(c => c.DerSha256 == leafHash);
        Check("内存ExtraStore把叶证书关联到已采集CA和Root", leafObservation.ChainStatus == DiagnosticReadStatus.Complete &&
            leafObservation.ChainFlags.Count == 0 && leafObservation.ChainCertificateSha256.SequenceEqual(new[] { leafHash, intermediateHash, firstHash }) &&
            !leafObservation.SubjectEqualsIssuer && leafObservation.IsCertificateAuthority == false);

        FakePhysicalCertificateReader noRootSource = new();
        noRootSource.Certificates[("CurrentUser", "CA")] = [firstDer];
        TrustProxyDiagnosticReport noRoot = CertificateDiagnostic();
        new CertificateStoreScanner(noRootSource, () => CertificateFixtureSid).Collect(noRoot, new());
        Check("离线快照缺少Root只记录链失败状态不判恶", noRoot.Certificates.Single().ChainStatus == DiagnosticReadStatus.Complete &&
            noRoot.Certificates.Single().ChainFlags.Count > 0 &&
            noRoot.Certificates.Single().ChainDetail.Contains("没有 Root", StringComparison.Ordinal) &&
            noRoot.Certificates.Single().ChainDetail.Contains("不等于恶意", StringComparison.Ordinal));

        FakePhysicalCertificateReader boundarySource = new();
        boundarySource.Certificates[("CurrentUser", "Root")] = [firstDer];
        TrustProxyDiagnosticReport boundary = CertificateDiagnostic();
        new CertificateStoreScanner(boundarySource, () => CertificateFixtureSid, chainBuilder: new CertificateFixtureChainBuilder(
            _ => new(true, [], [new string('F', 64)]))).Collect(boundary, new());
        Check("快照外缓存链元素使结果范围未知而非通过", boundary.Certificates.Single().ChainStatus == DiagnosticReadStatus.NotChecked &&
            boundary.Certificates.Single().ChainFlags.Contains("OutsideCapturedSnapshot") && boundary.Certificates.Single().ChainCertificateSha256.Count == 0);

        foreach (string target in new[] { "", "not-a-sid", "S-1-5-21-121-232-343-1002" })
        {
            FakePhysicalCertificateReader wrongIdentitySource = new();
            TrustProxyDiagnosticReport wrongIdentity = new() { TargetUserSid = target };
            new CertificateStoreScanner(wrongIdentitySource, () => CertificateFixtureSid).Collect(wrongIdentity, new());
            Check("缺失无效或异用户SID不打开任何证书存储", wrongIdentitySource.Requests.Count == 0 &&
                wrongIdentity.CertificateStores.All(s => s.Status == DiagnosticReadStatus.AccessDenied));
        }

        FakePhysicalCertificateReader changedIdentitySource = new();
        changedIdentitySource.Certificates[("CurrentUser", "Root")] = [firstDer];
        TrustProxyDiagnosticReport changedIdentity = CertificateDiagnostic();
        int identityChecks = 0;
        new CertificateStoreScanner(changedIdentitySource, () => identityChecks++ < 2 ? CertificateFixtureSid : "S-1-5-21-121-232-343-1002")
            .Collect(changedIdentity, new());
        Check("采集过程中SID变化停止打开后续物理来源", changedIdentitySource.Requests.Count == 1 && changedIdentity.Certificates.Count == 1 &&
            changedIdentity.CertificateStores.Skip(1).All(s => s.Status == DiagnosticReadStatus.AccessDenied));

        FakePhysicalCertificateReader errorSource = new();
        errorSource.Failures[("CurrentUser", "Root")] = new UnauthorizedAccessException("inert denied");
        errorSource.Failures[("CurrentUser", "CA")] = new Win32Exception(123, "inert failed");
        errorSource.Results[("LocalMachine", "Root")] = DiagnosticReadStatus.NotPresent;
        errorSource.Certificates[("LocalMachine", "CA")] = [firstDer];
        TrustProxyDiagnosticReport errors = CertificateDiagnostic();
        new CertificateStoreScanner(errorSource, () => CertificateFixtureSid).Collect(errors, new());
        Check("单store权限失败读取失败与不存在分别记录且继续其他来源", errors.CertificateStores[0].Status == DiagnosticReadStatus.AccessDenied &&
            errors.CertificateStores[1].Status == DiagnosticReadStatus.Failed && errors.CertificateStores[2].Status == DiagnosticReadStatus.NotPresent &&
            errors.CertificateStores[3].Status == DiagnosticReadStatus.Complete && errors.Certificates.Count == 1);
        FakePhysicalCertificateReader malformedSource = new();
        malformedSource.Certificates[("CurrentUser", "Root")] = [[1, 2, 3], firstDer];
        TrustProxyDiagnosticReport malformed = CertificateDiagnostic();
        new CertificateStoreScanner(malformedSource, () => CertificateFixtureSid).Collect(malformed, new());
        Check("损坏公开DER保留store失败并继续保存有效证书", malformed.CertificateStores[0].Status == DiagnosticReadStatus.Failed && malformed.Certificates.Count == 1);

        FakePhysicalCertificateReader perStoreSource = new();
        perStoreSource.Certificates[("CurrentUser", "Root")] = [firstDer, secondDer];
        perStoreSource.Certificates[("LocalMachine", "Root")] = [secondDer];
        TrustProxyDiagnosticReport perStore = CertificateDiagnostic();
        new CertificateStoreScanner(perStoreSource, () => CertificateFixtureSid).Collect(perStore, new() { MaximumCertificatesPerStore = 1 });
        Check("单store数量上限不吞掉另一实际来源", perStore.CertificateStores[0].Status == DiagnosticReadStatus.LimitReached &&
            perStore.CertificateStores[2].Status == DiagnosticReadStatus.Complete && perStore.Certificates.Count == 2);

        FakePhysicalCertificateReader sizeSource = new();
        sizeSource.Certificates[("CurrentUser", "Root")] = [firstDer];
        TrustProxyDiagnosticReport size = CertificateDiagnostic();
        new CertificateStoreScanner(sizeSource, () => CertificateFixtureSid).Collect(size, new() { MaximumCertificateBytes = 1 });
        Check("证书单项大小超限在复制DER前停止", sizeSource.AcceptedCount == 0 && size.Certificates.Count == 0 && size.CertificateStores[0].Status == DiagnosticReadStatus.LimitReached);

        FakePhysicalCertificateReader totalSource = new();
        totalSource.Certificates[("CurrentUser", "Root")] = [firstDer];
        totalSource.Certificates[("LocalMachine", "Root")] = [secondDer];
        TrustProxyDiagnosticReport total = CertificateDiagnostic();
        new CertificateStoreScanner(totalSource, () => CertificateFixtureSid).Collect(total, new() { MaximumTotalCertificateBytes = firstDer.Length });
        Check("证书字节总限额跨store累计", total.Certificates.Count == 1 && total.CertificateStores[2].Status == DiagnosticReadStatus.LimitReached &&
            total.CertificateStores[3].Status == DiagnosticReadStatus.LimitReached);

        FakePhysicalCertificateReader zeroSource = new();
        TrustProxyDiagnosticReport zero = CertificateDiagnostic();
        new CertificateStoreScanner(zeroSource, () => CertificateFixtureSid).Collect(zero, new() { MaximumCertificateBytes = 0 });
        Check("零字节预算不打开store并明确未检查", zeroSource.Requests.Count == 0 && zero.CertificateStores.All(s => s.Status == DiagnosticReadStatus.LimitReached));

        CertificateFixtureTimeProvider clock = new();
        FakePhysicalCertificateReader timedSource = new() { BeforeRead = _ => clock.Advance(TimeSpan.FromSeconds(2)) };
        timedSource.Certificates[("CurrentUser", "Root")] = [firstDer];
        TrustProxyDiagnosticReport timed = CertificateDiagnostic();
        new CertificateStoreScanner(timedSource, () => CertificateFixtureSid, clock).Collect(timed, new() { MaximumDuration = TimeSpan.FromSeconds(1) });
        Check("采集时间预算停止当前及后续store并标记限制", timedSource.AcceptedCount == 0 && timedSource.Requests.Count == 1 &&
            timed.CertificateStores.All(s => s.Status == DiagnosticReadStatus.LimitReached));

        FakePhysicalCertificateReader chainFailureSource = new();
        chainFailureSource.Certificates[("CurrentUser", "Root")] = [firstDer];
        TrustProxyDiagnosticReport chainFailure = CertificateDiagnostic();
        new CertificateStoreScanner(chainFailureSource, () => CertificateFixtureSid, chainBuilder: new CertificateFixtureChainBuilder(
            _ => throw new CryptographicException("inert chain failure"))).Collect(chainFailure, new());
        Check("链引擎失败不冒充通过或恶意", chainFailure.Certificates.Single().ChainStatus == DiagnosticReadStatus.Failed &&
            chainFailure.Certificates.Single().SelfSignatureVerified is null);

        using CancellationTokenSource beforeCancellation = new(); beforeCancellation.Cancel();
        FakePhysicalCertificateReader cancelledSource = new();
        TrustProxyDiagnosticReport cancelled = CertificateDiagnostic();
        bool cancelledThrown = false;
        try { new CertificateStoreScanner(cancelledSource, () => CertificateFixtureSid).Collect(cancelled, new(), beforeCancellation.Token); }
        catch (OperationCanceledException) { cancelledThrown = true; }
        Check("预取消不打开store并保留四来源取消状态", cancelledThrown && cancelledSource.Requests.Count == 0 &&
            cancelled.CertificateStores.All(s => s.Status == DiagnosticReadStatus.Cancelled));

        using CancellationTokenSource midwayCancellation = new();
        FakePhysicalCertificateReader midwaySource = new() { AfterAccepted = () => midwayCancellation.Cancel() };
        midwaySource.Certificates[("CurrentUser", "Root")] = [firstDer, secondDer];
        TrustProxyDiagnosticReport midway = CertificateDiagnostic();
        bool midwayThrown = false;
        try { new CertificateStoreScanner(midwaySource, () => CertificateFixtureSid).Collect(midway, new(), midwayCancellation.Token); }
        catch (OperationCanceledException) { midwayThrown = true; }
        Check("中途取消保留已读公开DER且结束reader和未完成链", midwayThrown && midwaySource.ReadExits == 1 && midway.Certificates.Count == 1 &&
            midway.CertificateStores.All(s => s.Status == DiagnosticReadStatus.Cancelled) && midway.Certificates[0].ChainStatus == DiagnosticReadStatus.Cancelled);
    }

    private static TrustProxyDiagnosticReport CertificateDiagnostic() => new() { TargetUserSid = CertificateFixtureSid };

    private static X509Certificate2 CreateTrustProxyRoot(string name)
    {
        using RSA rsa = RSA.Create(2048);
        CertificateRequest request = new(new X500DistinguishedName(name), rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, true, 1, true));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));
        request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(new OidCollection { new("1.3.6.1.5.5.7.3.1") }, false));
        return request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(7));
    }

    private static X509Certificate2 CreateTrustProxyIssuedCertificate(string name, X509Certificate2 issuer, bool authority)
    {
        using RSA rsa = RSA.Create(2048);
        CertificateRequest request = new(new X500DistinguishedName(name), rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(authority, authority, 0, true));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(authority ? X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign :
            X509KeyUsageFlags.DigitalSignature, true));
        request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(new OidCollection { new("1.3.6.1.5.5.7.3.1") }, false));
        using X509Certificate2 issued = request.Create(issuer, DateTimeOffset.UtcNow.AddMinutes(-1),
            new DateTimeOffset(issuer.NotAfter.ToUniversalTime()).AddHours(-1), RandomNumberGenerator.GetBytes(16));
        return issued.CopyWithPrivateKey(rsa);
    }

    private sealed class FakePhysicalCertificateReader : IPhysicalCertificateStoreReader
    {
        internal readonly Dictionary<(string Scope, string Name), byte[][]> Certificates = [];
        internal readonly Dictionary<(string Scope, string Name), Exception> Failures = [];
        internal readonly Dictionary<(string Scope, string Name), DiagnosticReadStatus> Results = [];
        internal readonly List<PhysicalCertificateStoreRequest> Requests = [];
        internal Action<PhysicalCertificateStoreRequest>? BeforeRead;
        internal Action? AfterAccepted;
        internal int AcceptedCount, ReadExits;

        public CertificateStoreReadResult Read(PhysicalCertificateStoreRequest store, Func<int, bool> reserveBytes,
            Action<byte[]> acceptCertificate, CancellationToken token)
        {
            Requests.Add(store);
            try
            {
                BeforeRead?.Invoke(store);
                var key = (store.Scope, store.StoreName);
                if (Failures.TryGetValue(key, out Exception? error)) throw error;
                if (Results.TryGetValue(key, out DiagnosticReadStatus status)) return new(status, "inert fixture status");
                foreach (byte[] der in Certificates.GetValueOrDefault(key) ?? [])
                {
                    token.ThrowIfCancellationRequested();
                    if (!reserveBytes(der.Length)) return new(DiagnosticReadStatus.LimitReached, "inert fixture budget reached");
                    AcceptedCount++;
                    acceptCertificate(der.ToArray());
                    AfterAccepted?.Invoke();
                }
                return new(DiagnosticReadStatus.Complete, "inert physical source completed");
            }
            finally { ReadExits++; }
        }
    }

    private sealed class CertificateFixtureTimeProvider : TimeProvider
    {
        private long _ticks;
        public override long TimestampFrequency => TimeSpan.TicksPerSecond;
        public override long GetTimestamp() => _ticks;
        public override DateTimeOffset GetUtcNow() => DateTimeOffset.UtcNow;
        internal void Advance(TimeSpan duration) => _ticks += duration.Ticks;
    }

    private sealed class CertificateFixtureChainBuilder(Func<X509Certificate2, CertificateSnapshotChainResult> build) : ICertificateSnapshotChainBuilder
    {
        public CertificateSnapshotChainResult Build(X509Certificate2 certificate, IReadOnlyList<X509Certificate2> roots,
            IReadOnlyList<X509Certificate2> intermediates, DateTimeOffset verificationTime) => build(certificate);
    }
}
