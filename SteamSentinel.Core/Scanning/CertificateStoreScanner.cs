using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Principal;
using Microsoft.Win32.SafeHandles;
using SteamSentinel.Core.Models;

namespace SteamSentinel.Core.Scanning;

/// <summary>
/// Reads public certificate bytes from four physical registry stores, never the
/// CurrentUser logical collection (which also contains LocalMachine entries).
/// No store writes, certificate/private-key imports, or private-key access occur.
/// </summary>
public sealed class CertificateStoreScanner
{
    internal const string PhysicalProvider = "CERT_STORE_PROV_SYSTEM_REGISTRY_W";
    internal const string SnapshotChainScope = "OfflineSnapshot:CustomRootTrust+ExtraStore;NoDownloads;NoRevocation";
    private readonly IPhysicalCertificateStoreReader _reader;
    private readonly Func<string?> _currentUserSid;
    private readonly TimeProvider _time;
    private readonly ICertificateSnapshotChainBuilder _chainBuilder;

    public CertificateStoreScanner() : this(new NativePhysicalCertificateStoreReader(), CurrentUserSid,
        TimeProvider.System, new OfflineCertificateSnapshotChainBuilder())
    { }

    internal CertificateStoreScanner(IPhysicalCertificateStoreReader reader, Func<string?> currentUserSid,
        TimeProvider? timeProvider = null, ICertificateSnapshotChainBuilder? chainBuilder = null)
    {
        _reader = reader;
        _currentUserSid = currentUserSid;
        _time = timeProvider ?? TimeProvider.System;
        _chainBuilder = chainBuilder ?? new OfflineCertificateSnapshotChainBuilder();
    }

    public void Collect(TrustProxyDiagnosticReport diagnostic, DiagnosticScanLimits limits, CancellationToken token = default)
    {
        ArgumentNullException.ThrowIfNull(diagnostic);
        ArgumentNullException.ThrowIfNull(limits);
        long started = _time.GetTimestamp();
        DateTimeOffset verificationTime = _time.GetUtcNow();
        List<CertificateStoreObservation> stores = [];
        foreach (string scope in new[] { "CurrentUser", "LocalMachine" })
            foreach (string name in new[] { "Root", "CA" })
            {
                CertificateStoreObservation store = new()
                {
                    Scope = scope,
                    StoreName = name,
                    Provider = PhysicalProvider,
                    UserSid = scope == "CurrentUser" ? diagnostic.TargetUserSid : null,
                    Status = DiagnosticReadStatus.NotChecked,
                    Detail = "仅物理注册表存储；不合并另一作用域或逻辑存储的继承证书。"
                };
                stores.Add(store);
                diagnostic.CertificateStores.Add(store);
            }
        List<CollectedCertificate> collected = [];
        try
        {
            token.ThrowIfCancellationRequested();
            if (limits.MaximumCertificatesPerStore < 0 || limits.MaximumCertificateBytes < 0 ||
                limits.MaximumTotalCertificateBytes < 0 || limits.MaximumDuration < TimeSpan.Zero)
            {
                FinishUnread(stores, DiagnosticReadStatus.Failed, "证书采集限额无效，未打开任何证书存储。");
                diagnostic.Checks.Add(new() { Name = "证书采集限额", Status = DiagnosticReadStatus.Failed, Detail = "限额不得为负数。" });
                return;
            }
            string? identityFailure = ValidateIdentity(diagnostic.TargetUserSid);
            if (identityFailure is not null)
            {
                FinishUnread(stores, DiagnosticReadStatus.AccessDenied, identityFailure);
                diagnostic.Checks.Add(new() { Name = "证书采集用户身份", Status = DiagnosticReadStatus.AccessDenied, Detail = identityFailure });
                return;
            }
            diagnostic.Checks.Add(new()
            {
                Name = "证书采集用户身份",
                Status = DiagnosticReadStatus.Complete,
                Detail = "发起扫描的目标 SID 与当前有效 Windows 用户 SID 完整匹配。"
            });
            diagnostic.Checks.Add(new()
            {
                Name = "证书物理来源范围",
                Status = DiagnosticReadStatus.Complete,
                Required = false,
                Detail = "仅当前用户和本机的物理注册表 Root/CA；包含注册表中可枚举的归档证书及未按保护根缓存过滤的条目。未合并组策略、企业、AuthRoot、其他用户或其他物理提供程序。这是注册快照，不是 Windows 实际有效信任列表；未读取私钥，证书有效期不代表安装时间。"
            });

            long totalBytes = 0;
            bool totalLimitReached = false;
            bool Expired() => _time.GetElapsedTime(started) >= limits.MaximumDuration;
            foreach (CertificateStoreObservation store in stores)
            {
                token.ThrowIfCancellationRequested();
                string? currentIdentityFailure = ValidateIdentity(diagnostic.TargetUserSid);
                if (currentIdentityFailure is not null)
                {
                    FinishUnread(stores, DiagnosticReadStatus.AccessDenied, currentIdentityFailure);
                    diagnostic.Checks.Add(new()
                    {
                        Name = "证书采集期间用户身份",
                        Status = DiagnosticReadStatus.AccessDenied,
                        Detail = "打开下一物理存储前重新核验失败：" + currentIdentityFailure
                    });
                    break;
                }
                if (Expired() || totalLimitReached || limits.MaximumCertificatesPerStore == 0 ||
                    limits.MaximumCertificateBytes == 0 || limits.MaximumTotalCertificateBytes == 0)
                {
                    store.Status = DiagnosticReadStatus.LimitReached;
                    store.Detail += " 读取前已达到证书时间、数量或字节限额，未打开此存储。";
                    continue;
                }
                int visited = 0, malformed = 0;
                string? localLimit = null;
                try
                {
                    CertificateStoreReadResult read = _reader.Read(new(store.Scope, store.StoreName, store.UserSid),
                        encodedBytes =>
                        {
                            token.ThrowIfCancellationRequested();
                            if (Expired()) localLimit = "证书采集时间预算已用尽。";
                            else if (visited >= limits.MaximumCertificatesPerStore) localLimit = "单存储证书数量达到上限。";
                            else if (encodedBytes > limits.MaximumCertificateBytes) localLimit = "证书 DER 超过单项字节上限，未复制该对象。";
                            else if (encodedBytes > limits.MaximumTotalCertificateBytes - totalBytes)
                            { totalLimitReached = true; localLimit = "证书 DER 总字节预算不足，未复制该对象。"; }
                            if (localLimit is not null) return false;
                            if (encodedBytes <= 0) throw new InvalidDataException("证书上下文没有有效公开 DER。");
                            visited++;
                            totalBytes += encodedBytes;
                            return true;
                        }, der =>
                        {
                            token.ThrowIfCancellationRequested();
                            X509Certificate2? certificate = null;
                            try
                            {
                                // LoadCertificate accepts public certificates only, unlike a PKCS#12 loader.
                                certificate = X509CertificateLoader.LoadCertificate(der);
                                CertificateObservation observation = Describe(certificate, der, store.Id);
                                diagnostic.Certificates.Add(observation);
                                collected.Add(new(certificate, observation, store.StoreName));
                                certificate = null; // Ownership is held until all snapshot chains are checked.
                                store.CertificatesRead++;
                            }
                            catch (Exception ex) when (ex is CryptographicException or ArgumentException or InvalidDataException)
                            { malformed++; }
                            finally { certificate?.Dispose(); }
                        }, token);
                    store.Status = localLimit is not null ? DiagnosticReadStatus.LimitReached : malformed > 0 ? DiagnosticReadStatus.Failed : read.Status;
                    store.Detail += " " + read.Detail;
                    if (localLimit is not null) store.Detail += " " + localLimit;
                    if (malformed > 0) store.Detail += $" {malformed} 个公开证书或扩展无法解析；未把这些对象视为已检查或恶意。";
                    if (Expired() && store.Status == DiagnosticReadStatus.Complete)
                    { store.Status = DiagnosticReadStatus.LimitReached; store.Detail += " 本次读取结束时已超过时间预算。"; }
                }
                catch (Exception ex) when (ex is UnauthorizedAccessException or System.Security.SecurityException)
                { store.Status = DiagnosticReadStatus.AccessDenied; store.Detail += " 读取权限不足：" + ex.Message; }
                catch (Exception ex) when (ex is Win32Exception or CryptographicException or IOException or ArgumentException or NotSupportedException)
                { store.Status = DiagnosticReadStatus.Failed; store.Detail += " 读取失败：" + ex.Message; }
            }
            VerifySnapshotChains(collected, limits, started, verificationTime, token);
        }
        catch (OperationCanceledException)
        {
            FinishUnread(stores, DiagnosticReadStatus.Cancelled, "证书采集已取消，尚未完成此物理存储。");
            foreach (CollectedCertificate item in collected.Where(c => c.Observation.ChainStatus == DiagnosticReadStatus.NotChecked))
            {
                item.Observation.ChainStatus = DiagnosticReadStatus.Cancelled;
                item.Observation.ChainDetail = "取消后未继续证书链检查。";
            }
            throw;
        }
        finally
        {
            foreach (CollectedCertificate item in collected) item.Certificate.Dispose();
        }
    }

    private string? ValidateIdentity(string targetSid)
    {
        try
        {
            if (string.IsNullOrWhiteSpace(targetSid)) return "缺少目标用户 SID；未打开证书存储。";
            SecurityIdentifier target = new(targetSid);
            string? effectiveValue = _currentUserSid();
            if (string.IsNullOrWhiteSpace(effectiveValue)) return "无法取得当前有效用户 SID；未打开证书存储。";
            SecurityIdentifier effective = new(effectiveValue);
            return target.Equals(effective) ? null : "当前有效用户 SID 与目标 SID 不匹配；未改用其他管理员的证书视图。";
        }
        catch (Exception ex) when (ex is ArgumentException or UnauthorizedAccessException or System.Security.SecurityException or Win32Exception)
        { return "用户 SID 无法核验，未打开证书存储：" + ex.Message; }
    }

    private static string? CurrentUserSid()
    {
        using WindowsIdentity identity = WindowsIdentity.GetCurrent();
        return identity.User?.Value;
    }

    private static CertificateObservation Describe(X509Certificate2 certificate, byte[] der, string storeId)
    {
        X509BasicConstraintsExtension? basic = null;
        X509KeyUsageExtension? usage = null;
        List<string> ekus = [];
        foreach (X509Extension extension in certificate.Extensions)
        {
            if (extension.Oid?.Value == "2.5.29.19")
            { basic = new(); basic.CopyFrom(extension); }
            else if (extension.Oid?.Value == "2.5.29.15")
            { usage = new(); usage.CopyFrom(extension); }
            else if (extension.Oid?.Value == "2.5.29.37")
            {
                X509EnhancedKeyUsageExtension enhanced = new(); enhanced.CopyFrom(extension);
                ekus.AddRange(enhanced.EnhancedKeyUsages.Cast<Oid>().Select(oid => oid.Value ?? ""));
            }
        }
        return new()
        {
            StoreObservationId = storeId,
            DerSha256 = Convert.ToHexString(SHA256.HashData(der)),
            Sha1Thumbprint = Convert.ToHexString(SHA1.HashData(der)),
            DerBase64 = Convert.ToBase64String(der),
            Subject = certificate.Subject,
            Issuer = certificate.Issuer,
            NotBeforeUtc = certificate.NotBefore.ToUniversalTime(),
            NotAfterUtc = certificate.NotAfter.ToUniversalTime(),
            SubjectEqualsIssuer = certificate.SubjectName.RawData.AsSpan().SequenceEqual(certificate.IssuerName.RawData),
            SelfSignatureVerified = null,
            IsCertificateAuthority = basic?.CertificateAuthority,
            HasPathLengthConstraint = basic?.HasPathLengthConstraint,
            PathLengthConstraint = basic?.HasPathLengthConstraint == true ? basic.PathLengthConstraint : null,
            BasicConstraintsCritical = basic?.Critical,
            KeyUsage = usage?.KeyUsages.ToString(),
            EnhancedKeyUsages = ekus.Distinct(StringComparer.Ordinal).ToList(),
            ChainScope = SnapshotChainScope,
            ChainDetail = "尚未进行离线快照链检查；主体与颁发者编码相同不等于自签名已验证。"
        };
    }

    private void VerifySnapshotChains(List<CollectedCertificate> collected, DiagnosticScanLimits limits,
        long started, DateTimeOffset verificationTime, CancellationToken token)
    {
        List<X509Certificate2> roots = collected.Where(c => c.StoreName == "Root")
            .DistinctBy(c => c.Observation.DerSha256).Select(c => c.Certificate).ToList();
        List<X509Certificate2> extras = collected.Where(c => c.StoreName == "CA")
            .DistinctBy(c => c.Observation.DerSha256).Select(c => c.Certificate).ToList();
        HashSet<string> capturedHashes = collected.Select(c => c.Observation.DerSha256).ToHashSet(StringComparer.OrdinalIgnoreCase);
        Dictionary<string, CertificateSnapshotChainResult> cache = new(StringComparer.OrdinalIgnoreCase);
        foreach (CollectedCertificate item in collected)
        {
            token.ThrowIfCancellationRequested();
            CertificateObservation observation = item.Observation;
            if (_time.GetElapsedTime(started) >= limits.MaximumDuration)
            {
                observation.ChainStatus = DiagnosticReadStatus.LimitReached;
                observation.ChainDetail = "时间预算不足，未完成此证书的离线链检查；不能据此判定信任或恶意。";
                continue;
            }
            try
            {
                if (!cache.TryGetValue(observation.DerSha256, out CertificateSnapshotChainResult? result))
                {
                    result = _chainBuilder.Build(item.Certificate, roots, extras, verificationTime);
                    cache.Add(observation.DerSha256, result);
                }
                if (_time.GetElapsedTime(started) >= limits.MaximumDuration)
                {
                    observation.ChainStatus = DiagnosticReadStatus.LimitReached;
                    observation.ChainDetail = "链构建返回时已超过时间预算，未将该次结果作为完整检查。时间预算在每个本机 API 调用前后检查。";
                    continue;
                }
                // Windows may consider cached intermediates even with CustomRootTrust.
                // Never report a snapshot result that used any uncaptured certificate.
                if (result.CertificateHashes.Any(hash => !capturedHashes.Contains(hash)))
                {
                    observation.ChainStatus = DiagnosticReadStatus.NotChecked;
                    observation.ChainFlags.Add("OutsideCapturedSnapshot");
                    observation.ChainDetail = "本机链引擎返回了采集快照之外的证书，已丢弃该链结论；离线快照范围未知，不代表证书恶意。";
                    continue;
                }
                observation.ChainStatus = DiagnosticReadStatus.Complete;
                observation.ChainFlags.AddRange(result.Flags);
                observation.ChainCertificateSha256.AddRange(result.CertificateHashes);
                observation.ChainDetail = (result.Valid ? "在已采集 Root 锚点和 CA 中间证书的范围内可构建链。" : "在已采集的证书范围内未通过链验证。") +
                    " 未下载证书，未检查撤销，也未评估 Windows 全部实际信任策略、站点身份或安装来源；未通过不等于恶意。" +
                    (roots.Count == 0 ? " 此快照没有 Root 信任锚点。" : "") +
                    " 未单独验证自签名，SelfSignatureVerified 保持未知。";
            }
            catch (Exception ex) when (ex is CryptographicException or ArgumentException or NotSupportedException)
            {
                observation.ChainStatus = DiagnosticReadStatus.Failed;
                observation.ChainDetail = "离线快照链检查失败，不能据此判恶：" + ex.Message;
            }
        }
    }

    private static void FinishUnread(IEnumerable<CertificateStoreObservation> stores, DiagnosticReadStatus status, string detail)
    {
        foreach (CertificateStoreObservation store in stores.Where(s => s.Status == DiagnosticReadStatus.NotChecked))
        { store.Status = status; store.Detail += " " + detail; }
    }

    private sealed record CollectedCertificate(X509Certificate2 Certificate, CertificateObservation Observation, string StoreName);
}

internal sealed record PhysicalCertificateStoreRequest(string Scope, string StoreName, string? UserSid);
internal sealed record CertificateStoreReadResult(DiagnosticReadStatus Status, string Detail);
internal interface IPhysicalCertificateStoreReader
{
    CertificateStoreReadResult Read(PhysicalCertificateStoreRequest store, Func<int, bool> reserveBytes,
        Action<byte[]> acceptCertificate, CancellationToken token);
}

internal sealed record CertificateSnapshotChainResult(bool Valid, IReadOnlyList<string> Flags, IReadOnlyList<string> CertificateHashes);
internal interface ICertificateSnapshotChainBuilder
{
    CertificateSnapshotChainResult Build(X509Certificate2 certificate, IReadOnlyList<X509Certificate2> roots,
        IReadOnlyList<X509Certificate2> intermediates, DateTimeOffset verificationTime);
}

internal sealed class OfflineCertificateSnapshotChainBuilder : ICertificateSnapshotChainBuilder
{
    internal static X509ChainPolicy CreatePolicy(IEnumerable<X509Certificate2> roots,
        IEnumerable<X509Certificate2> intermediates, DateTimeOffset verificationTime)
    {
        X509ChainPolicy policy = new()
        {
            TrustMode = X509ChainTrustMode.CustomRootTrust,
            RevocationMode = X509RevocationMode.NoCheck,
            DisableCertificateDownloads = true,
            VerificationFlags = X509VerificationFlags.NoFlag,
            VerificationTime = verificationTime.UtcDateTime,
            UrlRetrievalTimeout = TimeSpan.FromMilliseconds(1)
        };
        policy.CustomTrustStore.AddRange(roots.ToArray());
        policy.ExtraStore.AddRange(intermediates.ToArray());
        return policy;
    }

    public CertificateSnapshotChainResult Build(X509Certificate2 certificate, IReadOnlyList<X509Certificate2> roots,
        IReadOnlyList<X509Certificate2> intermediates, DateTimeOffset verificationTime)
    {
        using X509Chain chain = new();
        chain.ChainPolicy = CreatePolicy(roots, intermediates, verificationTime);
        bool valid = chain.Build(certificate);
        return new(valid, chain.ChainStatus.Select(s => s.Status.ToString()).ToArray(),
            chain.ChainElements.Cast<X509ChainElement>().Select(e => Convert.ToHexString(SHA256.HashData(e.Certificate.RawData))).ToArray());
    }
}

internal sealed class NativePhysicalCertificateStoreReader : IPhysicalCertificateStoreReader
{
    // Provider documentation: https://learn.microsoft.com/windows/win32/api/wincrypt/nf-wincrypt-certopenstore
    internal const uint ReadOnly = 0x00008000, OpenExisting = 0x00004000, EnumArchived = 0x00000200;
    internal const uint UnprotectedRootEnumeration = 0x40000000;
    internal static uint FlagsFor(PhysicalCertificateStoreRequest store) =>
        ReadOnly | OpenExisting | EnumArchived | (store.Scope == "CurrentUser" ? 0x00010000u : 0x00020000u) |
        (store.Scope == "CurrentUser" && store.StoreName == "Root" ? UnprotectedRootEnumeration : 0);

    public CertificateStoreReadResult Read(PhysicalCertificateStoreRequest store, Func<int, bool> reserveBytes,
        Action<byte[]> acceptCertificate, CancellationToken token)
    {
        if (store.Scope is not ("CurrentUser" or "LocalMachine") || store.StoreName is not ("Root" or "CA"))
            throw new ArgumentException("只允许本机的 CurrentUser/LocalMachine Root/CA 物理存储。");
        token.ThrowIfCancellationRequested();
        using SafeCertificateStoreHandle handle = CertOpenStore(new IntPtr(13), 0, IntPtr.Zero, FlagsFor(store), store.StoreName);
        if (handle.IsInvalid)
        {
            int error = Marshal.GetLastWin32Error();
            DiagnosticReadStatus status = error is 5 or unchecked((int)0x80070005) ? DiagnosticReadStatus.AccessDenied :
                error is 2 or 3 or unchecked((int)0x80092004) ? DiagnosticReadStatus.NotPresent : DiagnosticReadStatus.Failed;
            return new(status, $"物理注册表存储未打开；Windows 错误 0x{error:X8}。未创建存储，也不从逻辑视图补读。");
        }
        IntPtr context = IntPtr.Zero;
        try
        {
            while (true)
            {
                token.ThrowIfCancellationRequested();
                // CertEnumCertificatesInStore releases the previous context, including on failure.
                IntPtr previous = context;
                context = IntPtr.Zero;
                context = CertEnumCertificatesInStore(handle, previous);
                if (context == IntPtr.Zero)
                {
                    int error = Marshal.GetLastWin32Error();
                    return error == unchecked((int)0x80092004) ? new(DiagnosticReadStatus.Complete, "物理注册表证书枚举完成。") :
                        new(DiagnosticReadStatus.Failed, $"证书枚举未完整结束；Windows 错误 0x{error:X8}。");
                }
                NativeCertificateContext certificate = Marshal.PtrToStructure<NativeCertificateContext>(context);
                if (certificate.EncodedBytes > int.MaxValue) throw new InvalidDataException("证书公开 DER 长度无效。");
                int size = checked((int)certificate.EncodedBytes);
                if (!reserveBytes(size)) return new(DiagnosticReadStatus.LimitReached, "按调用方预算停止读取；未复制超限证书。");
                if (certificate.Encoded == IntPtr.Zero) throw new InvalidDataException("证书公开 DER 指针为空。");
                byte[] der = new byte[size];
                Marshal.Copy(certificate.Encoded, der, 0, size);
                acceptCertificate(der);
            }
        }
        finally { if (context != IntPtr.Zero) CertFreeCertificateContext(context); }
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct NativeCertificateContext
    {
        public uint Encoding;
        public IntPtr Encoded;
        public uint EncodedBytes;
        public IntPtr CertificateInfo;
        public IntPtr Store;
    }

    private sealed class SafeCertificateStoreHandle : SafeHandleZeroOrMinusOneIsInvalid
    {
        public SafeCertificateStoreHandle() : base(true) { }
        protected override bool ReleaseHandle() => CertCloseStore(handle, 0);
    }

    [DllImport("crypt32.dll", CharSet = CharSet.Unicode, ExactSpelling = true, SetLastError = true)]
    private static extern SafeCertificateStoreHandle CertOpenStore(IntPtr provider, uint encoding, IntPtr cryptProvider, uint flags, string storeName);
    [DllImport("crypt32.dll", SetLastError = true)]
    private static extern IntPtr CertEnumCertificatesInStore(SafeCertificateStoreHandle store, IntPtr previous);
    [DllImport("crypt32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CertFreeCertificateContext(IntPtr context);
    [DllImport("crypt32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CertCloseStore(IntPtr store, uint flags);
}
