using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;

namespace SteamSentinel.Core.Utilities;

public sealed record InstallationSecurityStatus(bool IsProtected, string Message)
{
    public static InstallationSecurityStatus Protected { get; } =
        new(true, "受保护安装与组件完整性校验已通过");
}

public static class InstallationSecurity
{
    private static readonly HashSet<string> TrustedOwners = new(StringComparer.OrdinalIgnoreCase)
    {
        "S-1-5-18",      // Local System
        "S-1-5-32-544",  // Builtin Administrators
        "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464" // TrustedInstaller
    };

    private const FileSystemRights DangerousRights =
        // Composite Modify/FullControl include read bits, so they cannot be used as a mask.
        FileSystemRights.WriteData |
        FileSystemRights.AppendData |
        FileSystemRights.WriteExtendedAttributes |
        FileSystemRights.WriteAttributes |
        FileSystemRights.Delete |
        FileSystemRights.DeleteSubdirectoriesAndFiles |
        FileSystemRights.ChangePermissions |
        FileSystemRights.TakeOwnership |
        (FileSystemRights)0x10000000 | // GENERIC_ALL
        (FileSystemRights)0x40000000;  // GENERIC_WRITE

    internal static bool GrantsWrite(FileSystemRights rights) => (rights & DangerousRights) != 0;

    private static readonly string[] RequiredComponents =
    [
        "SteamSentinel.exe",
        "SteamSentinel.Broker.exe",
        "SteamSentinel.ArchiveWorker.exe",
        "SteamSentinel.dll",
        "SteamSentinel.Core.dll",
        "SteamSentinel.Broker.dll",
        "SteamSentinel.ArchiveWorker.dll",
        "SteamSentinel.deps.json",
        "SteamSentinel.runtimeconfig.json",
        "SteamSentinel.Broker.deps.json",
        "SteamSentinel.Broker.runtimeconfig.json",
        "SteamSentinel.ArchiveWorker.deps.json",
        "SteamSentinel.ArchiveWorker.runtimeconfig.json"
    ];

    public static InstallationSecurityStatus Evaluate(string? baseDirectory = null)
    {
        try
        {
            string root = Path.TrimEndingDirectorySeparator(Path.GetFullPath(baseDirectory ?? AppContext.BaseDirectory));
            if (!IsUnderProgramFiles(root))
                return new(false, "当前不是 Program Files 受保护安装，扫描可用，管理员处置已关闭");
            if (Validation.ContainsReparsePoint(root))
                return new(false, "安装路径包含重解析点，管理员处置已关闭");

            InstallationSecurityStatus directoryAcl = CheckAcl(new DirectoryInfo(root));
            if (!directoryAcl.IsProtected) return directoryAcl;

            string sumsPath = Path.Combine(root, "SHA256SUMS.txt");
            if (!File.Exists(sumsPath) || (File.GetAttributes(sumsPath) & FileAttributes.ReparsePoint) != 0)
                return new(false, "安装包完整性清单缺失或不安全，管理员处置已关闭");
            InstallationSecurityStatus sumsAcl = CheckAcl(new FileInfo(sumsPath));
            if (!sumsAcl.IsProtected) return sumsAcl;

            Dictionary<string, string> expected = ReadChecksums(sumsPath);
            foreach (string component in RequiredComponents)
                if (!expected.ContainsKey(component)) return new(false, $"完整性清单缺少组件：{component}");

            // Apphosts load managed assemblies and bundled runtime files. Protect the payload,
            // not only the three EXEs, before either the broker or the UI can elevate.
            HashSet<string> checkedDirectories = new(StringComparer.OrdinalIgnoreCase) { root };
            foreach ((string component, string expectedHash) in expected)
            {
                string path = Path.Combine(root, component);
                if (!File.Exists(path) || Validation.ContainsReparsePoint(path))
                    return new(false, $"受保护组件缺失或被重定向：{component}");
                for (DirectoryInfo? parent = Directory.GetParent(path); parent is not null && checkedDirectories.Add(parent.FullName); parent = parent.Parent)
                {
                    InstallationSecurityStatus parentAcl = CheckAcl(parent);
                    if (!parentAcl.IsProtected) return parentAcl;
                }
                InstallationSecurityStatus fileAcl = CheckAcl(new FileInfo(path));
                if (!fileAcl.IsProtected) return fileAcl;
                string actualHash = ComputeSha256Exclusive(path);
                if (!actualHash.Equals(expectedHash, StringComparison.OrdinalIgnoreCase))
                    return new(false, $"组件完整性校验失败：{component}");
            }

            return InstallationSecurityStatus.Protected;
        }
        catch (Exception ex)
        {
            return new(false, $"无法验证安装安全性：{ex.Message}");
        }
    }

    private static bool IsUnderProgramFiles(string path)
    {
        string[] roots =
        [
            Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
            Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86)
        ];
        return roots.Where(root => !string.IsNullOrWhiteSpace(root)).Any(root => IsWithin(path, root));
    }

    internal static InstallationSecurityStatus CheckAcl(FileSystemInfo item)
    {
        FileSystemSecurity security = item switch
        {
            DirectoryInfo directory => FileSystemAclExtensions.GetAccessControl(
                directory, AccessControlSections.Access | AccessControlSections.Owner),
            FileInfo file => FileSystemAclExtensions.GetAccessControl(
                file, AccessControlSections.Access | AccessControlSections.Owner),
            _ => throw new NotSupportedException()
        };

        return CheckSecurityDescriptor(security, item.Name);
    }

    internal static InstallationSecurityStatus CheckSecurityDescriptor(FileSystemSecurity security, string name)
    {
        if (security.GetOwner(typeof(SecurityIdentifier)) is not SecurityIdentifier owner ||
            !TrustedOwners.Contains(owner.Value))
        {
            return new(false, $"安装对象所有者不受信任：{name}");
        }

        if (new RawSecurityDescriptor(security.GetSecurityDescriptorBinaryForm(), 0).DiscretionaryAcl is null)
            return new(false, $"安装对象没有访问限制：{name}");

        foreach (FileSystemAccessRule rule in security.GetAccessRules(
                     includeExplicit: true,
                     includeInherited: true,
                     targetType: typeof(SecurityIdentifier)))
        {
            if (rule.AccessControlType != AccessControlType.Allow ||
                (rule.PropagationFlags & PropagationFlags.InheritOnly) != 0 ||
                !GrantsWrite(rule.FileSystemRights) ||
                rule.IdentityReference is not SecurityIdentifier identity)
            {
                continue;
            }

            // Deny ACEs are deliberately not used to excuse an unsafe allow entry.
            // Also cover custom users/groups, including a filtered administrator's direct SID.
            if (!TrustedOwners.Contains(identity.Value))
            {
                return new(false, $"安装对象允许非受信任账户写入：{name}");
            }
        }

        return InstallationSecurityStatus.Protected;
    }

    internal static Dictionary<string, string> ReadChecksums(string path)
    {
        Dictionary<string, string> checksums = new(StringComparer.OrdinalIgnoreCase);
        foreach (string line in File.ReadLines(path))
        {
            if (string.IsNullOrWhiteSpace(line)) continue;
            if (line.Length < 67 || !Validation.IsHexSha256(line[..64]) || line[64] != ' ')
                throw new InvalidDataException("安装包完整性清单格式无效。");
            string relative = line[65..].TrimStart(' ', '*').Replace('/', Path.DirectorySeparatorChar);
            if (string.IsNullOrWhiteSpace(relative) || Path.IsPathRooted(relative) || relative.Contains(':') ||
                relative.Split(Path.DirectorySeparatorChar).Any(part => part is "" or "." or ".." ||
                    part.EndsWith(' ') || part.EndsWith('.') || part.IndexOfAny(Path.GetInvalidFileNameChars()) >= 0) ||
                !checksums.TryAdd(relative, line[..64]))
                throw new InvalidDataException("安装包完整性清单包含重复或不安全的路径。");
        }
        return checksums;
    }

    private static string ComputeSha256Exclusive(string path)
    {
        using FileStream stream = new(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        return Convert.ToHexString(SHA256.HashData(stream));
    }

    private static bool IsWithin(string candidate, string root)
    {
        string fullCandidate = Path.TrimEndingDirectorySeparator(Path.GetFullPath(candidate));
        string fullRoot = Path.TrimEndingDirectorySeparator(Path.GetFullPath(root));
        return fullCandidate.Equals(fullRoot, StringComparison.OrdinalIgnoreCase) ||
               fullCandidate.StartsWith(fullRoot + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase);
    }
}

public static class MachineStateSecurity
{
    public static void EnsureProtectedRoots()
    {
        string machineRoot = Path.GetFullPath(AppPaths.MachineStateRoot);
        if (Validation.ContainsReparsePoint(machineRoot))
            throw new UnauthorizedAccessException("机器状态目录包含重解析点，已拒绝管理员写入。");

        Directory.CreateDirectory(machineRoot);
        ApplyProtectedAcl(machineRoot, allowUsersRead: true);
        foreach (string child in new[] { AppPaths.QuarantineRoot, AppPaths.ResultsRoot, AppPaths.BrokerTemporaryRoot })
        {
            if (Validation.ContainsReparsePoint(child))
                throw new UnauthorizedAccessException("隔离或结果目录包含重解析点，已拒绝管理员写入。");
            Directory.CreateDirectory(child);
            ApplyProtectedAcl(
                child,
                allowUsersRead: !Path.GetFullPath(child).Equals(
                    Path.GetFullPath(AppPaths.BrokerTemporaryRoot),
                    StringComparison.OrdinalIgnoreCase));
        }
    }

    private static void ApplyProtectedAcl(string path, bool allowUsersRead)
    {
        DirectorySecurity security = new();
        security.SetOwner(new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null));
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        InheritanceFlags inheritance = InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit;
        security.AddAccessRule(new FileSystemAccessRule(
            new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null),
            FileSystemRights.FullControl,
            inheritance,
            PropagationFlags.None,
            AccessControlType.Allow));
        security.AddAccessRule(new FileSystemAccessRule(
            new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null),
            FileSystemRights.FullControl,
            inheritance,
            PropagationFlags.None,
            AccessControlType.Allow));
        if (allowUsersRead)
        {
            security.AddAccessRule(new FileSystemAccessRule(
                new SecurityIdentifier(WellKnownSidType.BuiltinUsersSid, null),
                FileSystemRights.ReadAndExecute | FileSystemRights.ListDirectory | FileSystemRights.Read,
                inheritance,
                PropagationFlags.None,
                AccessControlType.Allow));
        }
        FileSystemAclExtensions.SetAccessControl(new DirectoryInfo(path), security);
    }
}
