using System.Globalization;
using System.Security.AccessControl;
using System.Security.Principal;
using Microsoft.Win32;
using SteamSentinel.Core.Models;
using SteamSentinel.Core.Utilities;

namespace SteamSentinel.Broker;

internal sealed record IncidentTrustRecord(
    Guid IncidentId,
    Guid PlanId,
    Guid TrustId,
    string RequestedBySid,
    DateTimeOffset CreatedAtUtc,
    string ManifestSha256,
    string? PendingManifestSha256)
{
    public bool MatchesIdentity(QuarantineManifest manifest) =>
        manifest.IncidentId == IncidentId &&
        manifest.PlanId == PlanId &&
        manifest.TrustId == TrustId &&
        manifest.CreatedAtUtc == CreatedAtUtc &&
        manifest.RequestedBySid.Equals(RequestedBySid, StringComparison.OrdinalIgnoreCase);

    public bool AcceptsManifestHash(string sha256) =>
        Validation.IsHexSha256(sha256) &&
        (sha256.Equals(ManifestSha256, StringComparison.OrdinalIgnoreCase) ||
         sha256.Equals(PendingManifestSha256, StringComparison.OrdinalIgnoreCase));
}

internal interface IIncidentTrustStore
{
    void RegisterPending(QuarantineManifest manifest, string pendingManifestSha256);
    IncidentTrustRecord GetRequired(Guid incidentId);
    void BeginManifestUpdate(Guid incidentId, string nextManifestSha256);
    void CommitManifestUpdate(Guid incidentId, string manifestSha256);
    void Delete(Guid incidentId);
}

internal sealed class RegistryIncidentTrustStore : IIncidentTrustStore
{
    private const RegistryRights DangerousRights =
        RegistryRights.SetValue |
        RegistryRights.CreateSubKey |
        RegistryRights.Delete |
        RegistryRights.ChangePermissions |
        RegistryRights.TakeOwnership;
    private const string PlanIdName = "PlanId";
    private const string TrustIdName = "TrustId";
    private const string RequestedBySidName = "RequestedBySid";
    private const string CreatedAtUtcName = "CreatedAtUtc";
    private const string ManifestSha256Name = "ManifestSha256";
    private const string PendingManifestSha256Name = "PendingManifestSha256";
    private static readonly HashSet<string> TrustedRegistryOwners = new(StringComparer.OrdinalIgnoreCase)
    {
        "S-1-5-18",
        "S-1-5-32-544",
        "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"
    };

    public void RegisterPending(QuarantineManifest manifest, string pendingManifestSha256)
    {
        RequireHash(pendingManifestSha256);
        if (manifest.IncidentId == Guid.Empty || manifest.PlanId == Guid.Empty || manifest.TrustId == Guid.Empty ||
            string.IsNullOrWhiteSpace(manifest.RequestedBySid))
        {
            throw new InvalidDataException("隔离事件缺少可信索引身份字段。");
        }

        using RegistryKey root = OpenRoot(writable: true, create: true);
        string name = manifest.IncidentId.ToString("D");
        using (RegistryKey? existing = root.OpenSubKey(name, writable: false))
        {
            if (existing is not null)
                throw new IOException("隔离事件可信索引已存在，拒绝复用事件 ID。");
        }

        using RegistryKey key = root.CreateSubKey(
            name,
            RegistryKeyPermissionCheck.ReadWriteSubTree,
            RegistryOptions.None,
            BuildProtectedKeySecurity());
        EnsureKeyProtected(key);
        key.SetValue(PlanIdName, manifest.PlanId.ToString("D"), RegistryValueKind.String);
        key.SetValue(TrustIdName, manifest.TrustId.ToString("D"), RegistryValueKind.String);
        key.SetValue(RequestedBySidName, manifest.RequestedBySid, RegistryValueKind.String);
        key.SetValue(CreatedAtUtcName, manifest.CreatedAtUtc.ToString("O", CultureInfo.InvariantCulture), RegistryValueKind.String);
        key.SetValue(ManifestSha256Name, string.Empty, RegistryValueKind.String);
        key.SetValue(PendingManifestSha256Name, pendingManifestSha256, RegistryValueKind.String);
        key.Flush();
    }

    public IncidentTrustRecord GetRequired(Guid incidentId)
    {
        if (incidentId == Guid.Empty) throw new InvalidDataException("隔离事件 ID 为空。");
        using RegistryKey root = OpenRoot(writable: false, create: false);
        using RegistryKey? key = root.OpenSubKey(incidentId.ToString("D"), writable: false);
        if (key is null)
        {
            throw new UnauthorizedAccessException(
                "该隔离事件缺少 Broker 受保护可信索引，可能来自旧版本或不可信目录；已拒绝自动回滚或删除，请保留隔离并人工核对。");
        }
        EnsureKeyProtected(key);

        string planText = ReadBoundedString(key, PlanIdName, 36);
        string trustText = ReadBoundedString(key, TrustIdName, 36);
        string sid = ReadBoundedString(key, RequestedBySidName, 184);
        string createdText = ReadBoundedString(key, CreatedAtUtcName, 64);
        string currentHash = ReadBoundedString(key, ManifestSha256Name, 64, allowEmpty: true);
        string pendingHash = ReadBoundedString(key, PendingManifestSha256Name, 64, allowEmpty: true);
        if (!Guid.TryParseExact(planText, "D", out Guid planId) || planId == Guid.Empty ||
            !Guid.TryParseExact(trustText, "D", out Guid trustId) || trustId == Guid.Empty ||
            !DateTimeOffset.TryParseExact(createdText, "O", CultureInfo.InvariantCulture,
                DateTimeStyles.RoundtripKind, out DateTimeOffset createdAtUtc) ||
            string.IsNullOrWhiteSpace(sid) ||
            currentHash.Length > 0 && !Validation.IsHexSha256(currentHash) ||
            pendingHash.Length > 0 && !Validation.IsHexSha256(pendingHash) ||
            currentHash.Length == 0 && pendingHash.Length == 0)
        {
            throw new InvalidDataException("隔离事件受保护可信索引格式无效。");
        }

        return new IncidentTrustRecord(
            incidentId,
            planId,
            trustId,
            sid,
            createdAtUtc,
            currentHash,
            pendingHash.Length == 0 ? null : pendingHash);
    }

    public void BeginManifestUpdate(Guid incidentId, string nextManifestSha256)
    {
        RequireHash(nextManifestSha256);
        using RegistryKey key = OpenIncident(incidentId, writable: true);
        key.SetValue(PendingManifestSha256Name, nextManifestSha256, RegistryValueKind.String);
        key.Flush();
    }

    public void CommitManifestUpdate(Guid incidentId, string manifestSha256)
    {
        RequireHash(manifestSha256);
        using RegistryKey key = OpenIncident(incidentId, writable: true);
        string current = ReadBoundedString(key, ManifestSha256Name, 64, allowEmpty: true);
        string pending = ReadBoundedString(key, PendingManifestSha256Name, 64, allowEmpty: true);
        if (!manifestSha256.Equals(current, StringComparison.OrdinalIgnoreCase) &&
            !manifestSha256.Equals(pending, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException("隔离清单哈希不对应可信索引中的待提交版本。");
        }
        key.SetValue(ManifestSha256Name, manifestSha256, RegistryValueKind.String);
        key.SetValue(PendingManifestSha256Name, string.Empty, RegistryValueKind.String);
        key.Flush();
    }

    public void Delete(Guid incidentId)
    {
        using RegistryKey root = OpenRoot(writable: true, create: false);
        root.DeleteSubKeyTree(incidentId.ToString("D"), throwOnMissingSubKey: true);
        root.Flush();
    }

    private static RegistryKey OpenIncident(Guid incidentId, bool writable)
    {
        using RegistryKey root = OpenRoot(writable, create: false);
        RegistryKey? key = root.OpenSubKey(incidentId.ToString("D"), writable);
        if (key is null)
            throw new UnauthorizedAccessException("隔离事件缺少 Broker 受保护可信索引。");
        EnsureKeyProtected(key);
        if (writable) ProtectKey(key);
        return key;
    }

    private static RegistryKey OpenRoot(bool writable, bool create)
    {
        RegistryKey machine = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
        try
        {
            using RegistryKey? software = machine.OpenSubKey("SOFTWARE", writable: true);
            if (software is null) throw new UnauthorizedAccessException("无法验证 HKLM\\SOFTWARE 可信根。");
            EnsureKeyProtected(software, allowCreatorOwnerForTrustedOwner: true);

            using RegistryKey steamSentinel = OpenOrCreateProtectedChild(
                software, "SteamSentinel", writable: true, create);
            return OpenOrCreateProtectedChild(
                steamSentinel, "TrustedIncidents", writable, create);
        }
        finally
        {
            machine.Dispose();
        }
    }

    private static RegistryKey OpenOrCreateProtectedChild(
        RegistryKey parent,
        string name,
        bool writable,
        bool create)
    {
        RegistryKey? existing = parent.OpenSubKey(name, writable);
        if (existing is not null)
        {
            try
            {
                // Validate provenance before any ACL rewrite. Otherwise an attacker-writable
                // pre-existing key could be made to look trusted after its values were planted.
                EnsureKeyProtected(existing);
                if (writable) ProtectKey(existing);
                return existing;
            }
            catch
            {
                existing.Dispose();
                throw;
            }
        }
        if (!create)
        {
            throw new UnauthorizedAccessException(
                "Broker 可信事件索引尚未初始化；旧版隔离事件不能自动回滚或删除，请保留隔离并人工核对。");
        }

        // The parent was already verified non-writable by untrusted identities. Creating and
        // immediately protecting this child therefore cannot bless an untrusted preplant.
        RegistryKey created = parent.CreateSubKey(
            name,
            RegistryKeyPermissionCheck.ReadWriteSubTree,
            RegistryOptions.None,
            BuildProtectedKeySecurity());
        try
        {
            EnsureKeyProtected(created);
            return created;
        }
        catch
        {
            created.Dispose();
            throw;
        }
    }

    private static void ProtectKey(RegistryKey key)
    {
        RegistryAclExtensions.SetAccessControl(key, BuildProtectedKeySecurity());
    }

    private static RegistrySecurity BuildProtectedKeySecurity()
    {
        RegistrySecurity security = new();
        security.SetOwner(new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null));
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        InheritanceFlags inheritance = InheritanceFlags.ContainerInherit;
        security.AddAccessRule(new RegistryAccessRule(
            new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null),
            RegistryRights.FullControl,
            inheritance,
            PropagationFlags.None,
            AccessControlType.Allow));
        security.AddAccessRule(new RegistryAccessRule(
            new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null),
            RegistryRights.FullControl,
            inheritance,
            PropagationFlags.None,
            AccessControlType.Allow));
        return security;
    }

    private static void EnsureKeyProtected(RegistryKey key, bool allowCreatorOwnerForTrustedOwner = false)
    {
        RegistrySecurity security = RegistryAclExtensions.GetAccessControl(
            key,
            AccessControlSections.Access | AccessControlSections.Owner);
        if (!IsRegistrySecurityDescriptorProtected(security, allowCreatorOwnerForTrustedOwner))
            throw new UnauthorizedAccessException("Broker 可信事件索引或其注册表祖先允许非受信任账户写入。");
    }

    internal static bool IsRegistrySecurityDescriptorProtected(
        RegistrySecurity security,
        bool allowCreatorOwnerForTrustedOwner)
    {
        if (security.GetOwner(typeof(SecurityIdentifier)) is not SecurityIdentifier owner ||
            !TrustedRegistryOwners.Contains(owner.Value))
        {
            return false;
        }
        if (new RawSecurityDescriptor(security.GetSecurityDescriptorBinaryForm(), 0).DiscretionaryAcl is null)
            return false;

        foreach (RegistryAccessRule rule in security.GetAccessRules(
                     includeExplicit: true,
                     includeInherited: true,
                     targetType: typeof(SecurityIdentifier)))
        {
            if (rule.AccessControlType != AccessControlType.Allow ||
                (rule.PropagationFlags & PropagationFlags.InheritOnly) != 0 ||
                (rule.RegistryRights & DangerousRights) == 0 ||
                rule.IdentityReference is not SecurityIdentifier identity)
            {
                continue;
            }
            if (TrustedRegistryOwners.Contains(identity.Value)) continue;
            // Windows' normal HKLM\SOFTWARE ACL carries a container-inheritable
            // CREATOR OWNER full-control placeholder. It maps to this already-trusted
            // key owner and is safe only for the verified ancestor, never for our index.
            if (allowCreatorOwnerForTrustedOwner &&
                identity.IsWellKnown(WellKnownSidType.CreatorOwnerSid)) continue;
            return false;
        }
        return true;
    }

    private static string ReadBoundedString(RegistryKey key, string name, int maximumLength, bool allowEmpty = false)
    {
        if (key.GetValue(name, null, RegistryValueOptions.DoNotExpandEnvironmentNames) is not string value ||
            value.Length > maximumLength || !allowEmpty && string.IsNullOrWhiteSpace(value))
        {
            throw new InvalidDataException($"隔离事件可信索引字段无效：{name}");
        }
        return value;
    }

    private static void RequireHash(string sha256)
    {
        if (!Validation.IsHexSha256(sha256)) throw new InvalidDataException("可信索引缺少有效的清单 SHA-256。");
    }
}
