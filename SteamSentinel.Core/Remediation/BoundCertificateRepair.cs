using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using SteamSentinel.Core.Models;

namespace SteamSentinel.Core.Remediation;

/// <summary>
/// The store must enumerate all matching DER contexts in exactly one physical registry
/// Root/CA store. Mutating primitives recheck identity and metadata themselves. Neither
/// a context reference nor change notification is an atomic compare-and-delete lock.
/// </summary>
public interface IBoundCertificateStore
{
    IReadOnlyList<BoundCertificateBackup> ReadMatching(BoundCertificateTarget target);
    void RemoveExact(BoundCertificateBackup expected);
    void RestoreNew(BoundCertificateBackup backup);
}

public sealed class BoundCertificateRepairException(BoundCertificateProbeStatus status, string message) : InvalidOperationException(message)
{
    public BoundCertificateProbeStatus Status { get; } = status;
}

/// <summary>Identity and reversible-public-state checks only; the Broker independently authorizes removal.</summary>
public sealed class BoundCertificateRepair(IBoundCertificateStore store, Func<string> currentSid)
{
    public const int MaximumCertificateBytes = 128 * 1024;
    public const int MaximumPropertyBytes = 256 * 1024;
    public const int MaximumProperties = 32;
    // A deliberately narrow complete-state contract. All other properties, including
    // newer key/isolated-key properties, are rejected before their values are read.
    private static readonly HashSet<uint> PublicProperties = [3, 4, 9, 11, 13, 19, 20, 27, 107];

    public BoundCertificateBackup Capture(BoundCertificateTarget target)
    {
        BoundCertificateTarget requested = ValidateTarget(target, requireProperties: false);
        RequireCurrentSid(requested);
        IReadOnlyList<BoundCertificateBackup> matches = store.ReadMatching(requested);
        if (matches.Count == 0) throw Failure(BoundCertificateProbeStatus.Absent, "指定物理存储中已不存在此 DER 证书。");
        if (matches.Count != 1) throw Failure(BoundCertificateProbeStatus.Changed, "同一物理存储存在多个相同 DER 上下文，拒绝选择其中任意一个。");
        BoundCertificateBackup snapshot = ValidateBackup(matches[0]);
        RequireIdentity(requested, snapshot.Target, allowUnboundProperties: true);
        RequireCurrentSid(requested);
        return snapshot;
    }

    public void Remove(BoundCertificateTarget target, BoundCertificateBackup backup)
    {
        BoundCertificateTarget requested = ValidateTarget(target, requireProperties: true);
        BoundCertificateBackup expected = ValidateBackup(backup);
        RequireIdentity(requested, expected.Target);
        RequireSameState(expected, Capture(requested));
        RequireCurrentSid(requested);
        store.RemoveExact(expected);
        RequireCurrentSid(requested);
        if (store.ReadMatching(requested).Count != 0)
            throw Failure(BoundCertificateProbeStatus.Changed, "删除后的物理存储仍存在该 DER；可能出现并发变化，未继续删除，备份须保留。");
    }

    public void Restore(BoundCertificateBackup backup)
    {
        BoundCertificateBackup expected = ValidateBackup(backup);
        RequireCurrentSid(expected.Target);
        if (store.ReadMatching(expected.Target).Count != 0)
            throw Failure(BoundCertificateProbeStatus.Changed, "原物理存储已存在该 DER 上下文；不覆盖或合并之后的合法属性变化。");
        RequireCurrentSid(expected.Target);
        store.RestoreNew(expected);
        RequireSameState(expected, Capture(expected.Target));
    }

    public BoundCertificateProbe Probe(BoundCertificateTarget target)
    {
        try
        {
            _ = Capture(target);
            return new(BoundCertificateProbeStatus.Present, string.IsNullOrEmpty(target.PropertiesSha256)
                ? "指定物理存储中的 DER 存在，公开属性尚未绑定；需先取得完整备份，不能据此删除。"
                : "指定物理存储中的 DER 与已绑定公开属性相符；此结果不判断恶意或 Windows 实际信任策略。");
        }
        catch (BoundCertificateRepairException ex) { return new(ex.Status, ex.Message); }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        { return new(BoundCertificateProbeStatus.Unknown, "物理证书状态无法确认：" + ex.Message); }
    }

    private void RequireCurrentSid(BoundCertificateTarget target)
    {
        string actual;
        try { actual = new SecurityIdentifier(currentSid()).Value; }
        catch (Exception ex) when (ex is ArgumentException or System.Security.SecurityException or UnauthorizedAccessException)
        { throw Failure(BoundCertificateProbeStatus.Unknown, "无法核验当前证书操作用户身份：" + ex.Message); }
        if (!actual.Equals(target.TargetUserSid, StringComparison.Ordinal))
            throw Failure(BoundCertificateProbeStatus.Changed, "当前有效用户 SID 与证书目标不一致，未改用其他管理员的证书存储。");
    }

    public static BoundCertificateTarget ValidateTarget(BoundCertificateTarget target, bool requireProperties)
    {
        ArgumentNullException.ThrowIfNull(target);
        if (target.StoreLocation is not ("CurrentUser" or "LocalMachine") || target.StoreName is not ("Root" or "CA"))
            throw Failure(BoundCertificateProbeStatus.Unsupported, "只支持本机 CurrentUser/LocalMachine 的物理注册表 Root/CA，不接受逻辑、组策略、企业、其他用户或远程存储。");
        string sid;
        try
        {
            if (string.IsNullOrEmpty(target.TargetUserSid) || target.TargetUserSid.Length > 184) throw new ArgumentException();
            sid = new SecurityIdentifier(target.TargetUserSid).Value;
        }
        catch (ArgumentException) { throw Failure(BoundCertificateProbeStatus.Unsupported, "证书目标用户 SID 无效。"); }
        if (!IsHash(target.DerSha256) || (requireProperties || !string.IsNullOrEmpty(target.PropertiesSha256)) && !IsHash(target.PropertiesSha256))
            throw Failure(BoundCertificateProbeStatus.Unsupported, "证书目标缺少有效的 DER 或公开属性 SHA-256 绑定。");
        return new()
        {
            TargetUserSid = sid,
            StoreLocation = target.StoreLocation,
            StoreName = target.StoreName,
            DerSha256 = target.DerSha256.ToUpperInvariant(),
            PropertiesSha256 = (target.PropertiesSha256 ?? string.Empty).ToUpperInvariant()
        };
    }

    public static BoundCertificateBackup ValidateBackup(BoundCertificateBackup backup)
    {
        ArgumentNullException.ThrowIfNull(backup);
        BoundCertificateTarget target = ValidateTarget(backup.Target, requireProperties: true);
        byte[] der = Decode(backup.DerBase64, MaximumCertificateBytes, allowEmpty: false, "公开 DER");
        List<BoundCertificateProperty> properties = NormalizeProperties(backup.Properties, der);
        if (!Hash(der).Equals(target.DerSha256, StringComparison.Ordinal) ||
            !ComputePropertiesSha256(properties).Equals(target.PropertiesSha256, StringComparison.Ordinal))
            throw Failure(BoundCertificateProbeStatus.Changed, "证书备份的完整 DER 或公开属性与 SHA-256 绑定不一致。");
        return new() { Target = target, DerBase64 = Convert.ToBase64String(der), Properties = properties };
    }

    internal static BoundCertificateBackup CreateBackup(BoundCertificateTarget target, byte[] der, List<BoundCertificateProperty> properties)
    {
        BoundCertificateTarget source = ValidateTarget(target, requireProperties: false);
        if (der.Length is <= 0 or > MaximumCertificateBytes)
            throw Failure(BoundCertificateProbeStatus.Unsupported, "公开 DER 超过 128 KiB 或为空。");
        List<BoundCertificateProperty> normalized = NormalizeProperties(properties, der);
        return new()
        {
            Target = new()
            {
                TargetUserSid = source.TargetUserSid,
                StoreLocation = source.StoreLocation,
                StoreName = source.StoreName,
                DerSha256 = Hash(der),
                PropertiesSha256 = ComputePropertiesSha256(normalized)
            },
            DerBase64 = Convert.ToBase64String(der),
            Properties = normalized
        };
    }

    internal static List<BoundCertificateProperty> ReadPublicProperties(IReadOnlyList<uint> ids, Func<uint, int, byte[]> readValue)
    {
        ValidatePropertyIds(ids);
        List<BoundCertificateProperty> properties = [];
        int total = 0;
        foreach (uint id in ids.Order())
        {
            byte[] value = readValue(id, MaximumPropertyBytes - total);
            if (value.Length > MaximumPropertyBytes - total)
                throw Failure(BoundCertificateProbeStatus.Unsupported, "证书公开属性总量超过 256 KiB，未建立可恢复快照。");
            total += value.Length;
            properties.Add(new() { Id = id, ValueBase64 = Convert.ToBase64String(value) });
        }
        return properties;
    }

    internal static void ValidatePropertyIds(IReadOnlyList<uint> ids)
    {
        if (ids.Count > MaximumProperties || ids.Distinct().Count() != ids.Count || ids.Any(id => !PublicProperties.Contains(id)))
            throw Failure(BoundCertificateProbeStatus.Unsupported,
                "存在私钥相关、未知、重复或尚不支持恢复的证书属性；未读取这些属性值，也不执行删除或恢复。");
    }

    private static List<BoundCertificateProperty> NormalizeProperties(List<BoundCertificateProperty> properties, byte[] der)
    {
        if (properties is null || properties.Any(p => p is null))
            throw Failure(BoundCertificateProbeStatus.Unsupported, "证书属性列表无效。");
        ValidatePropertyIds(properties.Select(p => p.Id).ToArray());
        int total = 0;
        List<BoundCertificateProperty> result = [];
        foreach (BoundCertificateProperty property in properties.OrderBy(p => p.Id))
        {
            byte[] value = Decode(property.ValueBase64, MaximumPropertyBytes - total, allowEmpty: true, "公开属性");
            total += value.Length;
            if (property.Id == 19 && value.Length != 0 || property.Id == 27 && value.Length != 8 ||
                property.Id == 3 && !value.AsSpan().SequenceEqual(SHA1.HashData(der)) ||
                property.Id == 4 && !value.AsSpan().SequenceEqual(MD5.HashData(der)) ||
                property.Id == 107 && !value.AsSpan().SequenceEqual(SHA256.HashData(der)))
                throw Failure(BoundCertificateProbeStatus.Unsupported, "证书归档、时间或派生哈希属性格式不受支持，未建立可恢复快照。");
            result.Add(new() { Id = property.Id, ValueBase64 = Convert.ToBase64String(value) });
        }
        return result;
    }

    internal static string ComputePropertiesSha256(IReadOnlyList<BoundCertificateProperty> properties)
    {
        using MemoryStream stream = new();
        using (BinaryWriter writer = new(stream, Encoding.UTF8, leaveOpen: true))
        {
            writer.Write("SteamSentinel.PublicCertificateProperties/v1"); writer.Write(properties.Count);
            foreach (BoundCertificateProperty property in properties.OrderBy(p => p.Id))
            {
                byte[] value = Convert.FromBase64String(property.ValueBase64);
                writer.Write(property.Id); writer.Write(value.Length); writer.Write(value);
            }
        }
        return Hash(stream.ToArray());
    }

    internal static void RequireSameState(BoundCertificateBackup expected, BoundCertificateBackup actual)
    {
        RequireIdentity(expected.Target, actual.Target);
        if (expected.DerBase64 != actual.DerBase64 || expected.Properties.Count != actual.Properties.Count ||
            !expected.Properties.Zip(actual.Properties).All(pair => pair.First.Id == pair.Second.Id && pair.First.ValueBase64 == pair.Second.ValueBase64))
            throw Failure(BoundCertificateProbeStatus.Changed, "证书当前 DER 或公开属性已变化，拒绝沿用旧快照。");
    }

    private static void RequireIdentity(BoundCertificateTarget expected, BoundCertificateTarget actual, bool allowUnboundProperties = false)
    {
        if (expected.TargetUserSid != actual.TargetUserSid || expected.StoreLocation != actual.StoreLocation ||
            expected.StoreName != actual.StoreName || expected.DerSha256 != actual.DerSha256 ||
            (!allowUnboundProperties || expected.PropertiesSha256.Length > 0) && expected.PropertiesSha256 != actual.PropertiesSha256)
            throw Failure(BoundCertificateProbeStatus.Changed, "证书的物理来源、用户、DER 或公开属性绑定与当前状态不一致。");
    }

    private static byte[] Decode(string text, int maximum, bool allowEmpty, string label)
    {
        if (text is null || text.Length > ((long)maximum + 2) / 3 * 4)
            throw Failure(BoundCertificateProbeStatus.Unsupported, label + "编码超过允许字节上限。");
        byte[] result;
        try { result = Convert.FromBase64String(text); }
        catch (FormatException) { throw Failure(BoundCertificateProbeStatus.Unsupported, label + "不是有效 Base64。"); }
        if (result.Length > maximum || !allowEmpty && result.Length == 0)
            throw Failure(BoundCertificateProbeStatus.Unsupported, label + "字节数无效或超过上限。");
        return result;
    }

    private static bool IsHash(string? value) => value is { Length: 64 } && value.All(Uri.IsHexDigit);
    private static string Hash(byte[] data) => Convert.ToHexString(SHA256.HashData(data));
    internal static BoundCertificateRepairException Failure(BoundCertificateProbeStatus status, string message) => new(status, message);
}

/// <summary>The confirmation target is derived from the typed identity, never supplied as a separate friendly label.</summary>
public static class BoundConfigurationTargetNames
{
    public static string Certificate(BoundCertificateTarget target)
    {
        BoundCertificateTarget exact = BoundCertificateRepair.ValidateTarget(target, requireProperties: true);
        return exact.StoreLocation + "\\" + exact.StoreName + "\\" + exact.DerSha256;
    }

    public static string Proxy(BoundProxyTarget target)
    {
        BoundProxyRepair.ValidateTarget(target);
        return BoundProxyRepair.SupportedSource + "\\" + target.TargetUserSid;
    }
}
