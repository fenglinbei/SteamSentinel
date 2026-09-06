using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using SteamSentinel.Core.Models;
using SteamSentinel.Core.Remediation;

namespace SteamSentinel.SelfTest;

internal static partial class Program
{
    // Every mutation below targets this in-memory fake. No Windows certificate store
    // is opened; only an existing helper's self-generated public DER is used.
    private static void TestPhase3CertificateRepair()
    {
        using X509Certificate2 certificate = CreateTrustProxyRoot("CN=SteamSentinel inert certificate repair fixture");
        byte[] der = certificate.RawData;
        BoundCertificateTarget unbound = new()
        {
            TargetUserSid = CertificateFixtureSid,
            StoreLocation = "CurrentUser",
            StoreName = "Root",
            DerSha256 = Convert.ToHexString(SHA256.HashData(der))
        };
        BoundCertificateBackup original = BoundCertificateRepair.CreateBackup(unbound, der,
        [
            new() { Id = 3, ValueBase64 = Convert.ToBase64String(SHA1.HashData(der)) },
            new() { Id = 4, ValueBase64 = Convert.ToBase64String(MD5.HashData(der)) },
            new() { Id = 9, ValueBase64 = Convert.ToBase64String(new X509EnhancedKeyUsageExtension(
                new OidCollection { new("1.3.6.1.5.5.7.3.1") }, false).RawData) },
            new() { Id = 11, ValueBase64 = Convert.ToBase64String(Encoding.Unicode.GetBytes("inert original friendly name\0")) },
            new() { Id = 13, ValueBase64 = Convert.ToBase64String(Encoding.Unicode.GetBytes("inert original description\0")) },
            new() { Id = 19, ValueBase64 = "" },
            new() { Id = 20, ValueBase64 = Convert.ToBase64String(new byte[20]) },
            new() { Id = 27, ValueBase64 = Convert.ToBase64String(BitConverter.GetBytes(new DateTime(2026, 9, 6, 0, 0, 0, DateTimeKind.Utc).ToFileTimeUtc())) },
            new() { Id = 107, ValueBase64 = Convert.ToBase64String(SHA256.HashData(der)) }
        ]);
        FakeBoundCertificateStore store = new(original);
        BoundCertificateRepair repair = new(store, () => CertificateFixtureSid);
        BoundCertificateBackup captured = repair.Capture(unbound);
        Check("证书修复 完整公开DER和全部支持属性形成绑定", captured.DerBase64 == original.DerBase64 &&
            captured.Target.PropertiesSha256 == original.Target.PropertiesSha256 && captured.Properties.Count == 9 &&
            captured.Properties.Single(p => p.Id == 19).ValueBase64 == "" &&
            repair.Probe(unbound).Detail.Contains("尚未绑定", StringComparison.Ordinal));
        repair.Remove(captured.Target, captured);
        Check("证书修复 精确删除后确认不存在", store.DeleteMutations == 1 && store.Entries.Count == 0 &&
            repair.Probe(captured.Target).Status == BoundCertificateProbeStatus.Absent);
        repair.Restore(captured);
        Check("证书修复 ADD_NEW恢复保留EKU归档时间和公开属性", store.RestoreMutations == 1 &&
            repair.Probe(captured.Target).Status == BoundCertificateProbeStatus.Present &&
            store.Entries.Single().Properties.Select(p => p.ValueBase64).SequenceEqual(original.Properties.Select(p => p.ValueBase64)));
        Check("证书修复 再次恢复拒绝现有证书且不覆盖属性",
            RejectsCertificate(() => repair.Restore(captured), BoundCertificateProbeStatus.Changed) && store.RestoreMutations == 1);

        BoundCertificateBackup changed = CertificateWithFriendlyName(original, "inert later legitimate metadata");
        store = new(changed); repair = new(store, () => CertificateFixtureSid);
        Check("证书修复 同DER属性变化使旧删除计划失效",
            RejectsCertificate(() => repair.Remove(original.Target, original), BoundCertificateProbeStatus.Changed) && store.DeleteCalls == 0 &&
            repair.Probe(original.Target).Status == BoundCertificateProbeStatus.Changed);
        Check("证书修复 恢复不合并之后合法属性",
            RejectsCertificate(() => repair.Restore(original), BoundCertificateProbeStatus.Changed) && store.RestoreCalls == 0 &&
            store.Entries.Single().Target.PropertiesSha256 == changed.Target.PropertiesSha256);

        foreach (BoundCertificateBackup duplicate in new[] { original, changed })
        {
            store = new(original, duplicate); repair = new(store, () => CertificateFixtureSid);
            Check("证书修复 同DER多个上下文不任取其一 " + duplicate.Target.PropertiesSha256[..8],
                RejectsCertificate(() => repair.Capture(original.Target), BoundCertificateProbeStatus.Changed) &&
                RejectsCertificate(() => repair.Remove(original.Target, original), BoundCertificateProbeStatus.Changed) && store.DeleteCalls == 0);
        }
        byte[] sameIssuerSerialDifferentBytes = der.ToArray(); sameIssuerSerialDifferentBytes[^1] ^= 1;
        BoundCertificateBackup changedDer = BoundCertificateRepair.CreateBackup(unbound, sameIssuerSerialDifferentBytes, []);
        store = new(changedDer); repair = new(store, () => CertificateFixtureSid);
        Check("证书修复 同主体颁发者序列号但DER变化不误删",
            RejectsCertificate(() => repair.Remove(original.Target, original), BoundCertificateProbeStatus.Absent) && store.DeleteCalls == 0);

        foreach (string location in new[] { "CurrentUserGroupPolicy", "LocalMachineEnterprise", "Users", "\\\\host" })
        {
            BoundCertificateTarget invalid = CertificateTargetCopy(original.Target, location: location);
            store = new(original); repair = new(store, () => CertificateFixtureSid);
            Check("证书修复 拒绝未支持物理位置 " + location,
                RejectsCertificate(() => repair.Capture(invalid), BoundCertificateProbeStatus.Unsupported) && store.Reads == 0);
        }
        store = new(original); repair = new(store, () => "S-1-5-21-121-232-343-1002");
        Check("证书修复 用户SID不符时不读其他管理员存储",
            RejectsCertificate(() => repair.Capture(original.Target), BoundCertificateProbeStatus.Changed) && store.Reads == 0);
        store = new(original) { IgnorePhysicalScope = true }; repair = new(store, () => CertificateFixtureSid);
        Check("证书修复 适配器返回其他物理Root来源也会拒绝",
            RejectsCertificate(() => repair.Capture(CertificateTargetCopy(original.Target, location: "LocalMachine")), BoundCertificateProbeStatus.Changed));

        foreach (uint privateOrUnknown in new uint[] { 1, 2, 5, 6, 12, 65, 78, 79, 90, 91, 99, 100, 117, 118, 120, 125, 0x8001 })
        {
            int valueReads = 0;
            Check("证书修复 属性ID " + privateOrUnknown + " 拒绝且不读取任何值",
                RejectsCertificate(() => BoundCertificateRepair.ReadPublicProperties([3, privateOrUnknown], (_, _) =>
                    { valueReads++; return []; }), BoundCertificateProbeStatus.Unsupported) && valueReads == 0);
        }
        int remainingAfterFirst = -1;
        _ = BoundCertificateRepair.ReadPublicProperties([11, 13], (id, remaining) =>
        {
            if (id == 11) return new byte[remaining];
            remainingAfterFirst = remaining; return [];
        });
        Check("证书修复 属性总预算在读取回调前逐项收紧", remainingAfterFirst == 0 &&
            RejectsCertificate(() => BoundCertificateRepair.CreateBackup(unbound, new byte[128 * 1024 + 1], []), BoundCertificateProbeStatus.Unsupported));
        Check("证书修复 超限属性和未知备份属性拒绝",
            RejectsCertificate(() => BoundCertificateRepair.CreateBackup(unbound, der,
                [new() { Id = 11, ValueBase64 = Convert.ToBase64String(new byte[256 * 1024]) }, new() { Id = 13, ValueBase64 = "AA==" }]),
                BoundCertificateProbeStatus.Unsupported) &&
            RejectsCertificate(() => BoundCertificateRepair.ValidateBackup(new()
            {
                Target = original.Target,
                DerBase64 = original.DerBase64,
                Properties = [new() { Id = 117, ValueBase64 = "this value must never be decoded" }]
            }), BoundCertificateProbeStatus.Unsupported));
        Check("证书修复 伪造备份哈希不进入写原语",
            RejectsCertificate(() => new BoundCertificateRepair(new FakeBoundCertificateStore(original), () => CertificateFixtureSid)
                .Restore(new() { Target = original.Target, DerBase64 = original.DerBase64, Properties = [] }), BoundCertificateProbeStatus.Changed));

        store = new(original) { BeforeDelete = fake => { fake.Entries.Clear(); fake.Entries.Add(changed); } };
        repair = new(store, () => CertificateFixtureSid);
        Check("证书修复 原语最后复核拒绝预检后属性变化",
            RejectsCertificate(() => repair.Remove(original.Target, original), BoundCertificateProbeStatus.Changed) && store.DeleteMutations == 0);
        store = new() { BeforeRestore = fake => fake.Entries.Add(changed) }; repair = new(store, () => CertificateFixtureSid);
        Check("证书修复 ADD_NEW拒绝预检后新出现的合法上下文",
            RejectsCertificate(() => repair.Restore(original), BoundCertificateProbeStatus.Changed) && store.RestoreMutations == 0 &&
            store.Entries.Single().Target.PropertiesSha256 == changed.Target.PropertiesSha256);
        store = new(original) { AfterDelete = fake => fake.Entries.Add(changed) }; repair = new(store, () => CertificateFixtureSid);
        Check("证书修复 删除后重现只报告变化不再删",
            RejectsCertificate(() => repair.Remove(original.Target, original), BoundCertificateProbeStatus.Changed) && store.DeleteMutations == 1 &&
            store.Entries.Single().Target.PropertiesSha256 == changed.Target.PropertiesSha256);
        store = new() { AfterRestore = fake => { fake.Entries.Clear(); fake.Entries.Add(changed); } }; repair = new(store, () => CertificateFixtureSid);
        Check("证书修复 恢复后属性变化不补写或覆盖",
            RejectsCertificate(() => repair.Restore(original), BoundCertificateProbeStatus.Changed) && store.RestoreMutations == 1 &&
            store.Entries.Single().Target.PropertiesSha256 == changed.Target.PropertiesSha256);

        store = new(original) { FailRead = true }; repair = new(store, () => CertificateFixtureSid);
        Check("证书修复 不完整读取不视为不存在", repair.Probe(original.Target).Status == BoundCertificateProbeStatus.Unknown &&
            RejectsCertificate(() => repair.Restore(original), BoundCertificateProbeStatus.Unknown) && store.RestoreCalls == 0);
        uint userRead = WindowsBoundCertificateStore.FlagsFor(unbound, writable: false);
        uint userWrite = WindowsBoundCertificateStore.FlagsFor(unbound, writable: true);
        uint machineWrite = WindowsBoundCertificateStore.FlagsFor(CertificateTargetCopy(original.Target, location: "LocalMachine", name: "CA"), writable: true);
        Check("证书修复 原生标志限定既有物理区且包含归档不提升其他权限",
            userRead == (0x8000U | 0x4000U | 0x200U | 0x10000U | 0x40000000U) &&
            userWrite == (0x4000U | 0x200U | 0x10000U | 0x40000000U) && machineWrite == (0x4000U | 0x200U | 0x20000U));
    }

    private static bool RejectsCertificate(Action action, BoundCertificateProbeStatus status)
    {
        try { action(); return false; }
        catch (BoundCertificateRepairException ex) { return ex.Status == status; }
    }

    private static BoundCertificateTarget CertificateTargetCopy(BoundCertificateTarget target, string? location = null, string? name = null) => new()
    {
        TargetUserSid = target.TargetUserSid,
        StoreLocation = location ?? target.StoreLocation,
        StoreName = name ?? target.StoreName,
        DerSha256 = target.DerSha256,
        PropertiesSha256 = target.PropertiesSha256
    };

    private static BoundCertificateBackup CertificateWithFriendlyName(BoundCertificateBackup source, string friendly) =>
        BoundCertificateRepair.CreateBackup(source.Target, Convert.FromBase64String(source.DerBase64), source.Properties.Select(property =>
            new BoundCertificateProperty
            {
                Id = property.Id,
                ValueBase64 = property.Id == 11
                ? Convert.ToBase64String(Encoding.Unicode.GetBytes(friendly + "\0")) : property.ValueBase64
            }).ToList());

    private sealed class FakeBoundCertificateStore(params BoundCertificateBackup[] initial) : IBoundCertificateStore
    {
        public List<BoundCertificateBackup> Entries { get; } = [.. initial];
        public int Reads, DeleteCalls, DeleteMutations, RestoreCalls, RestoreMutations;
        public bool IgnorePhysicalScope, FailRead;
        public Action<FakeBoundCertificateStore>? BeforeDelete, AfterDelete, BeforeRestore, AfterRestore;
        public IReadOnlyList<BoundCertificateBackup> ReadMatching(BoundCertificateTarget target)
        {
            Reads++;
            if (FailRead) throw BoundCertificateRepair.Failure(BoundCertificateProbeStatus.Unknown, "无害测试：读取未完成");
            return Entries.Where(entry => SameSource(entry.Target, target) && entry.Target.DerSha256 == target.DerSha256).ToArray();
        }
        public void RemoveExact(BoundCertificateBackup expected)
        {
            DeleteCalls++; BeforeDelete?.Invoke(this);
            IReadOnlyList<BoundCertificateBackup> matches = ReadMatching(expected.Target);
            if (matches.Count != 1) throw BoundCertificateRepair.Failure(BoundCertificateProbeStatus.Changed, "无害测试：最终上下文数量变化");
            BoundCertificateRepair.RequireSameState(expected, matches[0]);
            Entries.Remove(matches[0]); DeleteMutations++; AfterDelete?.Invoke(this);
        }
        public void RestoreNew(BoundCertificateBackup backup)
        {
            RestoreCalls++; BeforeRestore?.Invoke(this);
            if (ReadMatching(backup.Target).Count != 0)
                throw BoundCertificateRepair.Failure(BoundCertificateProbeStatus.Changed, "无害测试：ADD_NEW拒绝现有上下文");
            Entries.Add(BoundCertificateRepair.ValidateBackup(backup)); RestoreMutations++; AfterRestore?.Invoke(this);
        }
        private bool SameSource(BoundCertificateTarget left, BoundCertificateTarget right) => IgnorePhysicalScope ||
            left.TargetUserSid == right.TargetUserSid && left.StoreLocation == right.StoreLocation && left.StoreName == right.StoreName;
    }
}
