using System.Security.Cryptography;
using System.Security.Principal;
using System.Text.Json;
using SteamSentinel.Core.Utilities;

namespace SteamSentinel.Core.Models;

public sealed record TrustProxyDiagnosticCounts(int Proxies, int Stores, int Certificates, int Checks, int Relations, long DerBytes);
public sealed record TrustProxyDiagnosticOffsets(int Proxies, int Stores, int Certificates, int Checks, int Relations);
public sealed record TrustProxyDiagnosticMetadata(int SchemaVersion, DateTimeOffset StartedAtUtc,
    DateTimeOffset? CompletedAtUtc, string TargetUserSid, TrustProxyDiagnosticCounts Counts);

/// <summary>Data never contains DER. Base64Url avoids the default JSON encoder's escaping of '+'.</summary>
public sealed record TrustProxyCertificateFragment(CertificateObservation Data, string DerBase64Url);

/// <summary>One bounded table slice. Offsets are append-only and metadata must be identical throughout.</summary>
public sealed record TrustProxyDiagnosticFragment(TrustProxyDiagnosticMetadata Metadata,
    TrustProxyDiagnosticOffsets Offsets, bool IsFinal)
{
    public List<ProxyConfigurationObservation> Proxies { get; init; } = [];
    public List<CertificateStoreObservation> Stores { get; init; } = [];
    public List<TrustProxyCertificateFragment> Certificates { get; init; } = [];
    public List<DiagnosticCheck> Checks { get; init; } = [];
    public List<DiagnosticRelation> Relations { get; init; } = [];
}

internal static class TrustProxyDiagnosticFragments
{
    internal const int MaximumProxies = 32, MaximumStores = 16, MaximumCertificates = 8192;
    internal const int MaximumChecks = 16384, MaximumRelations = 16384;
    internal const int MaximumCertificateBytes = 128 * 1024;
    internal const long MaximumDerBytes = 16L * 1024 * 1024;
    internal const long MaximumTextCharacters = 32L * 1024 * 1024;
    internal const int MaximumObservationTextCharacters = 96 * 1024;
    internal const int SmallBatchSize = 8, RelationBatchSize = 16;
    internal const int MaximumFrameCharacters = 1024 * 1024;
    private static readonly JsonSerializerOptions CompactJson = new(JsonFile.Options) { WriteIndented = false };

    internal static IReadOnlyList<TrustProxyDiagnosticFragment> Create(TrustProxyDiagnosticReport source)
    {
        if (source.Proxies is null || source.CertificateStores is null || source.Certificates is null || source.Checks is null || source.Relations is null)
            throw Invalid("诊断集合不能为空。");
        TrustProxyDiagnosticCounts counts = new(source.Proxies.Count, source.CertificateStores.Count,
            source.Certificates.Count, source.Checks.Count, source.Relations.Count, 0);
        ValidateCounts(counts);
        long bytes = 0;
        foreach (CertificateObservation certificate in source.Certificates)
        {
            if (certificate is null) throw Invalid("证书记录不能为空。");
            bytes += DecodeStandardDer(certificate.DerBase64).Length;
            if (bytes > MaximumDerBytes) throw Invalid("诊断 DER 累计字节超限。");
        }
        TrustProxyDiagnosticMetadata metadata = new(source.SchemaVersion, source.StartedAtUtc,
            source.CompletedAtUtc, source.TargetUserSid, counts with { DerBytes = bytes });
        ValidateMetadata(metadata);
        List<TrustProxyDiagnosticFragment> fragments = [];
        int proxies = 0, stores = 0, certificates = 0, checks = 0, relations = 0;
        bool Finished() => proxies == counts.Proxies && stores == counts.Stores && certificates == counts.Certificates &&
            checks == counts.Checks && relations == counts.Relations;
        TrustProxyDiagnosticOffsets Offset() => new(proxies, stores, certificates, checks, relations);
        do
        {
            TrustProxyDiagnosticOffsets offset = Offset();
            TrustProxyDiagnosticFragment fragment;
            if (stores < counts.Stores)
            {
                List<CertificateStoreObservation> slice = source.CertificateStores.GetRange(stores, Math.Min(SmallBatchSize, counts.Stores - stores));
                stores += slice.Count;
                fragment = new(metadata, offset, Finished()) { Stores = slice };
            }
            else if (proxies < counts.Proxies)
            {
                ProxyConfigurationObservation proxy = source.Proxies[proxies++];
                fragment = new(metadata, offset, Finished()) { Proxies = [proxy] };
            }
            else if (certificates < counts.Certificates)
            {
                CertificateObservation certificate = source.Certificates[certificates++];
                fragment = new(metadata, offset, Finished())
                {
                    Certificates = [new(CopyCertificate(certificate, ""),
                        certificate.DerBase64.TrimEnd('=').Replace('+', '-').Replace('/', '_'))]
                };
            }
            else if (checks < counts.Checks)
            {
                List<DiagnosticCheck> slice = source.Checks.GetRange(checks, Math.Min(SmallBatchSize, counts.Checks - checks));
                checks += slice.Count;
                fragment = new(metadata, offset, Finished()) { Checks = slice };
            }
            else
            {
                List<DiagnosticRelation> slice = source.Relations.GetRange(relations, Math.Min(RelationBatchSize, counts.Relations - relations));
                relations += slice.Count;
                fragment = new(metadata, offset, Finished()) { Relations = slice };
            }
            fragments.Add(fragment);
        } while (!Finished());

        // Preflight the whole snapshot before sending any final report ranges. This also verifies
        // references and the exact DER total, without putting the full payload in batch.Data.
        TrustProxyDiagnosticAssembly validation = new();
        foreach (TrustProxyDiagnosticFragment fragment in fragments)
            validation.Commit(validation.Prepare(fragment));
        return fragments;
    }

    internal static void ValidateWireFrame(ReportBatch batch)
    {
        // Match ArchiveWorker.Program.WriteAsync, including the WorkerMessage envelope. The default
        // encoder writes ASCII escapes; counting UTF-8 bytes is at least as strict as the line reader.
        using FrameLimitStream frame = new(MaximumFrameCharacters - 1);
        JsonSerializer.Serialize(frame, new WorkerMessage { Type = WorkerMessageTypes.Checkpoint, Batch = batch }, CompactJson);
    }

    private sealed class FrameLimitStream(long maximumBytes) : Stream
    {
        private long _length;
        public override bool CanRead => false;
        public override bool CanSeek => false;
        public override bool CanWrite => true;
        public override long Length => _length;
        public override long Position { get => _length; set => throw new NotSupportedException(); }
        public override void Flush() { }
        public override void Write(byte[] buffer, int offset, int count) => Write(buffer.AsSpan(offset, count));
        public override void Write(ReadOnlySpan<byte> buffer)
        {
            if (buffer.Length > maximumBytes - _length) throw Invalid("诊断结果帧超过 1 MiB 通信上限。");
            _length += buffer.Length;
        }
        public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
    }

    internal static void ValidateMetadata(TrustProxyDiagnosticMetadata metadata)
    {
        if (metadata is null || metadata.Counts is null || metadata.SchemaVersion != 1 || metadata.TargetUserSid is null ||
            metadata.StartedAtUtc == default || metadata.CompletedAtUtc < metadata.StartedAtUtc)
            throw Invalid("诊断元数据无效或版本不支持。");
        ValidateSid(metadata.TargetUserSid, allowEmpty: true);
        ValidateCounts(metadata.Counts);
    }

    private static void ValidateCounts(TrustProxyDiagnosticCounts counts)
    {
        if (counts.Proxies is < 0 or > MaximumProxies || counts.Stores is < 0 or > MaximumStores ||
            counts.Certificates is < 0 or > MaximumCertificates || counts.Checks is < 0 or > MaximumChecks ||
            counts.Relations is < 0 or > MaximumRelations || counts.DerBytes is < 0 or > MaximumDerBytes)
            throw Invalid("诊断累计数量或字节预算超限。");
    }

    internal static void ValidateSid(string? sid, bool allowEmpty = false)
    {
        if (allowEmpty && sid == "") return;
        if (string.IsNullOrWhiteSpace(sid) || sid.Length > 184) throw Invalid("诊断用户 SID 无效。");
        try { _ = new SecurityIdentifier(sid); }
        catch (ArgumentException) { throw Invalid("诊断用户 SID 无效。"); }
    }

    internal static byte[] DecodeStandardDer(string? encoded)
    {
        if (encoded is null || encoded.Length == 0 || encoded.Length > ((MaximumCertificateBytes + 2) / 3) * 4)
            throw Invalid("证书 DER 编码长度超限。");
        byte[] der;
        try { der = Convert.FromBase64String(encoded); }
        catch (FormatException) { throw Invalid("证书 DER Base64 编码无效。"); }
        if (der.Length == 0 || der.Length > MaximumCertificateBytes || Convert.ToBase64String(der) != encoded)
            throw Invalid("证书 DER 编码不规范或字节超限。");
        return der;
    }

    internal static byte[] DecodeUrlDer(string? encoded)
    {
        if (encoded is null || encoded.Length == 0 || encoded.Length > ((MaximumCertificateBytes + 2) / 3) * 4 ||
            encoded.Any(c => !(c is >= 'A' and <= 'Z' or >= 'a' and <= 'z' or >= '0' and <= '9' or '-' or '_')))
            throw Invalid("证书 DER Base64Url 编码无效或过长。");
        string standard = encoded.Replace('-', '+').Replace('_', '/');
        int padding = (4 - standard.Length % 4) % 4;
        if (padding == 3) throw Invalid("证书 DER Base64Url 编码长度无效。");
        byte[] der = DecodeStandardDer(standard + new string('=', padding));
        if (Convert.ToBase64String(der).TrimEnd('=').Replace('+', '-').Replace('/', '_') != encoded)
            throw Invalid("证书 DER Base64Url 编码不规范。");
        return der;
    }

    internal static CertificateObservation CopyCertificate(CertificateObservation value, string der) => new()
    {
        Id = value.Id,
        StoreObservationId = value.StoreObservationId,
        DerSha256 = value.DerSha256,
        Sha1Thumbprint = value.Sha1Thumbprint,
        DerBase64 = der,
        Subject = value.Subject,
        Issuer = value.Issuer,
        NotBeforeUtc = value.NotBeforeUtc,
        NotAfterUtc = value.NotAfterUtc,
        SubjectEqualsIssuer = value.SubjectEqualsIssuer,
        SelfSignatureVerified = value.SelfSignatureVerified,
        IsCertificateAuthority = value.IsCertificateAuthority,
        HasPathLengthConstraint = value.HasPathLengthConstraint,
        PathLengthConstraint = value.PathLengthConstraint,
        BasicConstraintsCritical = value.BasicConstraintsCritical,
        KeyUsage = value.KeyUsage,
        EnhancedKeyUsages = value.EnhancedKeyUsages is null ? null! : [.. value.EnhancedKeyUsages],
        ChainStatus = value.ChainStatus,
        ChainScope = value.ChainScope,
        ChainFlags = value.ChainFlags is null ? null! : [.. value.ChainFlags],
        ChainCertificateSha256 = value.ChainCertificateSha256 is null ? null! : [.. value.ChainCertificateSha256],
        ChainDetail = value.ChainDetail
    };

    internal static InvalidDataException Invalid(string reason) => new("诊断分片被拒绝：" + reason);
}

/// <summary>Prepare is read-only. Commit is called only after all ordinary batch ranges also validate.</summary>
internal sealed class TrustProxyDiagnosticAssembly
{
    private TrustProxyDiagnosticMetadata? _metadata;
    private readonly HashSet<string> _ids = new(StringComparer.Ordinal);
    private readonly Dictionary<string, int> _certificatesPerStore = new(StringComparer.Ordinal);
    private long _derBytes, _textCharacters;
    internal TrustProxyDiagnosticReport? Report { get; private set; }
    internal bool IsComplete { get; private set; }

    internal PreparedTrustProxyFragment Prepare(TrustProxyDiagnosticFragment fragment)
    {
        if (fragment is null || fragment.Offsets is null || fragment.Proxies is null || fragment.Stores is null ||
            fragment.Certificates is null || fragment.Checks is null || fragment.Relations is null)
            throw TrustProxyDiagnosticFragments.Invalid("分片结构缺失。");
        if (IsComplete) throw TrustProxyDiagnosticFragments.Invalid("完成后的诊断不能追加分片。");
        TrustProxyDiagnosticFragments.ValidateMetadata(fragment.Metadata);
        if (_metadata is not null && _metadata != fragment.Metadata)
            throw TrustProxyDiagnosticFragments.Invalid("分片元数据或总数量发生变化。");
        TrustProxyDiagnosticCounts totals = fragment.Metadata.Counts;
        TrustProxyDiagnosticOffsets offsets = fragment.Offsets;
        if (offsets.Proxies != (Report?.Proxies.Count ?? 0) || offsets.Stores != (Report?.CertificateStores.Count ?? 0) ||
            offsets.Certificates != (Report?.Certificates.Count ?? 0) || offsets.Checks != (Report?.Checks.Count ?? 0) || offsets.Relations != (Report?.Relations.Count ?? 0))
            throw TrustProxyDiagnosticFragments.Invalid("分片偏移不连续。");
        if (fragment.Proxies.Count > 1 || fragment.Certificates.Count > 1 || fragment.Stores.Count > TrustProxyDiagnosticFragments.SmallBatchSize ||
            fragment.Checks.Count > TrustProxyDiagnosticFragments.SmallBatchSize || fragment.Relations.Count > TrustProxyDiagnosticFragments.RelationBatchSize)
            throw TrustProxyDiagnosticFragments.Invalid("单片记录数量超限。");
        int tables = (fragment.Proxies.Count > 0 ? 1 : 0) + (fragment.Stores.Count > 0 ? 1 : 0) +
            (fragment.Certificates.Count > 0 ? 1 : 0) + (fragment.Checks.Count > 0 ? 1 : 0) + (fragment.Relations.Count > 0 ? 1 : 0);
        if (tables > 1) throw TrustProxyDiagnosticFragments.Invalid("单片只能携带一种诊断表。");
        int proxies = offsets.Proxies + fragment.Proxies.Count, stores = offsets.Stores + fragment.Stores.Count,
            certificates = offsets.Certificates + fragment.Certificates.Count, checks = offsets.Checks + fragment.Checks.Count,
            relations = offsets.Relations + fragment.Relations.Count;
        if (proxies > totals.Proxies || stores > totals.Stores || certificates > totals.Certificates || checks > totals.Checks || relations > totals.Relations)
            throw TrustProxyDiagnosticFragments.Invalid("分片超过声明的总数量。");
        bool allReceived = proxies == totals.Proxies && stores == totals.Stores && certificates == totals.Certificates && checks == totals.Checks && relations == totals.Relations;
        if (fragment.IsFinal != allReceived || tables == 0 && (!allReceived || Report is not null))
            throw TrustProxyDiagnosticFragments.Invalid("结束标记与声明的总数量不一致。");

        HashSet<string> newIds = new(StringComparer.Ordinal);
        long text = 0, derBytes = 0;
        void Id(string? id)
        {
            Field(id, 128, required: true);
            if (_ids.Contains(id!) || !newIds.Add(id!)) throw TrustProxyDiagnosticFragments.Invalid("观察或检查 ID 重复。");
        }
        void Reference(string? id)
        {
            Field(id, 128, required: true);
            if (!_ids.Contains(id!) && !newIds.Contains(id!)) throw TrustProxyDiagnosticFragments.Invalid("引用的观察 ID 尚未接收。");
        }
        void Field(string? value, int maximum, bool required = false)
        {
            if (required && string.IsNullOrWhiteSpace(value) || value?.Length > maximum)
                throw TrustProxyDiagnosticFragments.Invalid("诊断字段缺失或长度超限。");
            text += value?.Length ?? 0;
        }
        static void Status(DiagnosticReadStatus status)
        {
            if (!Enum.IsDefined(status)) throw TrustProxyDiagnosticFragments.Invalid("读取状态无效。");
        }
        void Scope(string scope, string? sid)
        {
            Field(scope, 32, required: true);
            if (scope == "CurrentUser")
            {
                TrustProxyDiagnosticFragments.ValidateSid(sid);
                if (sid != fragment.Metadata.TargetUserSid) throw TrustProxyDiagnosticFragments.Invalid("用户来源与目标 SID 不符。");
            }
            else if (scope != "LocalMachine" || !string.IsNullOrEmpty(sid))
                throw TrustProxyDiagnosticFragments.Invalid("诊断来源作用域无效。");
            Field(sid, 184);
        }
        void TextList(IReadOnlyList<string>? values, int maximumCount, int maximumCharacters, bool hashes = false)
        {
            if (values is null || values.Count > maximumCount) throw TrustProxyDiagnosticFragments.Invalid("证书字段列表超限。");
            foreach (string value in values) { Field(value, maximumCharacters, required: true); if (hashes) Hash(value, 64); }
        }

        foreach (CertificateStoreObservation store in fragment.Stores)
        {
            if (store is null) throw TrustProxyDiagnosticFragments.Invalid("存储记录为空。");
            Id(store.Id); Scope(store.Scope, store.UserSid); Field(store.StoreName, 128, required: true);
            Field(store.Provider, 256, required: true); Field(store.Detail, 8192); Status(store.Status);
            if (store.CertificatesRead is < 0 or > TrustProxyDiagnosticFragments.MaximumCertificates)
                throw TrustProxyDiagnosticFragments.Invalid("存储证书计数无效。");
        }
        foreach (ProxyConfigurationObservation proxy in fragment.Proxies)
        {
            if (proxy is null || proxy.Values is null || proxy.Values.Count > 16) throw TrustProxyDiagnosticFragments.Invalid("代理记录为空或字段数量超限。");
            long before = text;
            Id(proxy.Id); Scope(proxy.Scope, proxy.UserSid); Status(proxy.Status);
            Field(proxy.Source, 256, required: true); Field(proxy.Location, 4096, required: true); Field(proxy.Detail, 65536);
            Field(proxy.ProxyServer, 65536); Field(proxy.ProxyBypass, 65536); Field(proxy.AutoConfigUrl, 65536);
            HashSet<string> valueNames = new(StringComparer.OrdinalIgnoreCase);
            foreach (DiagnosticConfigurationValue value in proxy.Values)
            {
                if (value is null) throw TrustProxyDiagnosticFragments.Invalid("代理原值记录为空。");
                Field(value.Name, 128, required: true); Field(value.Kind, 128, required: true); Field(value.Value, 65536);
                if (!valueNames.Add(value.Name)) throw TrustProxyDiagnosticFragments.Invalid("代理原值名称重复。");
                Status(value.ReadStatus); if (value.Sha256 is not null) Hash(value.Sha256, 64);
                Field(value.Sha256, 64);
            }
            if (text - before > TrustProxyDiagnosticFragments.MaximumObservationTextCharacters)
                throw TrustProxyDiagnosticFragments.Invalid("代理记录文本总量超限。");
        }
        List<CertificateObservation> decoded = [];
        foreach (TrustProxyCertificateFragment wrapped in fragment.Certificates)
        {
            if (wrapped?.Data is not { } certificate || certificate.DerBase64 != "")
                throw TrustProxyDiagnosticFragments.Invalid("证书元数据不得嵌入完整 DER。");
            long before = text;
            Id(certificate.Id); Field(certificate.StoreObservationId, 128, required: true);
            if (Report?.CertificateStores.Any(s => s.Id == certificate.StoreObservationId) != true)
                throw TrustProxyDiagnosticFragments.Invalid("证书引用的真实存储尚未接收。");
            Hash(certificate.DerSha256, 64); Hash(certificate.Sha1Thumbprint, 40);
            Field(certificate.DerSha256, 64); Field(certificate.Sha1Thumbprint, 40);
            Field(certificate.Subject, 65536); Field(certificate.Issuer, 65536); Field(certificate.KeyUsage, 1024);
            Field(certificate.ChainScope, 1024, required: true); Field(certificate.ChainDetail, 8192); Status(certificate.ChainStatus);
            TextList(certificate.EnhancedKeyUsages, 256, 256); TextList(certificate.ChainFlags, 256, 256);
            TextList(certificate.ChainCertificateSha256, 256, 64, hashes: true);
            if (text - before > TrustProxyDiagnosticFragments.MaximumObservationTextCharacters)
                throw TrustProxyDiagnosticFragments.Invalid("证书元数据文本总量超限。");
            byte[] der = TrustProxyDiagnosticFragments.DecodeUrlDer(wrapped.DerBase64Url);
            if (!Convert.ToHexString(SHA256.HashData(der)).Equals(certificate.DerSha256, StringComparison.OrdinalIgnoreCase) ||
                !Convert.ToHexString(SHA1.HashData(der)).Equals(certificate.Sha1Thumbprint, StringComparison.OrdinalIgnoreCase))
                throw TrustProxyDiagnosticFragments.Invalid("证书 DER 与摘要不一致。");
            derBytes += der.Length;
            decoded.Add(TrustProxyDiagnosticFragments.CopyCertificate(certificate, Convert.ToBase64String(der)));
        }
        foreach (DiagnosticCheck check in fragment.Checks)
        {
            if (check is null) throw TrustProxyDiagnosticFragments.Invalid("检查记录为空。");
            Id(check.Id); Field(check.Name, 512, required: true); Field(check.Detail, 8192); Status(check.Status);
            if (check.ObservationId is not null) Reference(check.ObservationId);
        }
        foreach (DiagnosticRelation relation in fragment.Relations)
        {
            if (relation is null) throw TrustProxyDiagnosticFragments.Invalid("关系记录为空。");
            Reference(relation.FromId); Reference(relation.ToId); Field(relation.Kind, 128, required: true); Field(relation.Evidence, 4096);
        }
        if (_derBytes + derBytes > totals.DerBytes || _derBytes + derBytes > TrustProxyDiagnosticFragments.MaximumDerBytes ||
            _textCharacters + text > TrustProxyDiagnosticFragments.MaximumTextCharacters)
            throw TrustProxyDiagnosticFragments.Invalid("诊断累计 DER 或文本预算超限。");
        if (fragment.IsFinal)
        {
            if (_derBytes + derBytes != totals.DerBytes) throw TrustProxyDiagnosticFragments.Invalid("最终 DER 总量与声明不一致。");
            foreach (CertificateStoreObservation store in (Report?.CertificateStores ?? []).Concat(fragment.Stores))
            {
                int read = _certificatesPerStore.GetValueOrDefault(store.Id) + decoded.Count(c => c.StoreObservationId == store.Id);
                if (store.CertificatesRead != read) throw TrustProxyDiagnosticFragments.Invalid("存储声明计数与证书记录不一致。");
            }
        }
        return new(fragment, decoded, newIds, derBytes, text);
    }

    private static void Hash(string? value, int length)
    {
        if (value is null || value.Length != length || value.Any(c => !Uri.IsHexDigit(c)))
            throw TrustProxyDiagnosticFragments.Invalid("诊断摘要格式无效。");
    }

    internal void Commit(PreparedTrustProxyFragment prepared)
    {
        TrustProxyDiagnosticFragment fragment = prepared.Fragment;
        _metadata ??= fragment.Metadata;
        Report ??= new()
        {
            SchemaVersion = fragment.Metadata.SchemaVersion,
            StartedAtUtc = fragment.Metadata.StartedAtUtc,
            TargetUserSid = fragment.Metadata.TargetUserSid
        };
        Report.CertificateStores.AddRange(fragment.Stores);
        Report.Proxies.AddRange(fragment.Proxies);
        Report.Certificates.AddRange(prepared.Certificates);
        Report.Checks.AddRange(fragment.Checks);
        Report.Relations.AddRange(fragment.Relations);
        foreach (CertificateObservation certificate in prepared.Certificates)
            _certificatesPerStore[certificate.StoreObservationId] = _certificatesPerStore.GetValueOrDefault(certificate.StoreObservationId) + 1;
        _ids.UnionWith(prepared.Ids);
        _derBytes += prepared.DerBytes;
        _textCharacters += prepared.TextCharacters;
        IsComplete = fragment.IsFinal;
        Report.CompletedAtUtc = IsComplete ? fragment.Metadata.CompletedAtUtc : null;
    }
}

internal sealed record PreparedTrustProxyFragment(TrustProxyDiagnosticFragment Fragment,
    IReadOnlyList<CertificateObservation> Certificates, IReadOnlyCollection<string> Ids, long DerBytes, long TextCharacters);
