using SteamSentinel.Core.Reporting;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;

namespace SteamSentinel.Core.Utilities;

public enum InstallationTrustMode { Protected, Portable, Unsafe }

public enum InstallationVerificationDepth { Fast, Full }

[method: System.Text.Json.Serialization.JsonConstructor]
public sealed record InstallationSecurityStatus(bool IsProtected, string Message)
{
    public InstallationTrustMode Mode { get; init; } = IsProtected ? InstallationTrustMode.Protected : InstallationTrustMode.Unsafe;

    [System.Text.Json.Serialization.JsonIgnore]
    public bool CanRemediate => Mode is InstallationTrustMode.Protected or InstallationTrustMode.Portable;

    public static InstallationSecurityStatus Protected { get; } = new(true, MessageText.Create("Backend.Core.InstallationSecurity.Protected.01"));

    public static InstallationSecurityStatus Portable(SteamSentinel.Core.Reporting.MessageText message) =>
        new(false, message) { Mode = InstallationTrustMode.Portable };

    [System.Text.Json.Serialization.JsonIgnore(Condition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull)]
    public SteamSentinel.Core.Models.DisplayMessage? MessageMessage { get => SteamSentinel.Core.Reporting.MessageText.BoundDescriptor(field, Message); init => field = value; }

    [System.Text.Json.Serialization.JsonIgnore]
    public SteamSentinel.Core.Reporting.MessageText MessageText
    {
        get => new(Message ?? string.Empty, MessageMessage);
        init
        {
            Message = value.OriginalText;
            MessageMessage = value.Message;
        }
    }

    public InstallationSecurityStatus(bool IsProtected, SteamSentinel.Core.Reporting.MessageText Message) : this(IsProtected, Message.OriginalText)
    {
        MessageMessage = Message.Message;
    }
}

public static class InstallationSecurity
{
    private static readonly HashSet<string> TrustedOwners = new(StringComparer.OrdinalIgnoreCase)
    {
        "S-1-5-18",      // Local System
        "S-1-5-32-544",  // Builtin Administrators
        "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464" // TrustedInstaller
    };

    /// <summary>校验主体 SID 是否为受信任的系统/管理员身份，包括域与本机内置管理员 RID (-500/-512/-519)，绝不放行普通用户 RID。</summary>
    public static bool IsTrustedOwnerSid(string? sid)
    {
        if (string.IsNullOrWhiteSpace(sid)) return false;
        if (TrustedOwners.Contains(sid)) return true;
        if (!sid.StartsWith("S-1-5-21-", StringComparison.OrdinalIgnoreCase)) return false;
        string[] parts = sid.Split('-');
        if (parts.Length != 8) return false;
        for (int i = 4; i <= 6; i++)
        {
            if (!uint.TryParse(parts[i], System.Globalization.NumberStyles.None, System.Globalization.CultureInfo.InvariantCulture, out _))
                return false;
        }
        return parts[7] is "500" or "512" or "519";
    }

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

    private static readonly string[] CommonRequiredComponents =
    [
        "SteamSentinel.exe",
        "SteamSentinel.Broker.exe",
        "SteamSentinel.dll",
        "SteamSentinel.Core.dll",
        "SteamSentinel.Broker.dll",
        "SteamSentinel.ArchiveWorker.dll",
        "SteamSentinel.deps.json",
        "SteamSentinel.runtimeconfig.json",
        "SteamSentinel.Broker.deps.json",
        "SteamSentinel.Broker.runtimeconfig.json",
        "SteamSentinel.ArchiveWorker.deps.json",
        "SteamSentinel.ArchiveWorker.runtimeconfig.json",
        @"zh-Hans\SteamSentinel.Core.resources.dll"
    ];

    internal static IEnumerable<string> RequiredComponents(bool unified) => CommonRequiredComponents.Concat(unified
        ? Enum.GetValues<StartupRole>().SelectMany(role => Enum.GetValues<StartupMode>().Select(mode => StartupCompatibility.HostFileName(role, mode)))
        : ["SteamSentinel.ArchiveWorker.exe"]);

    internal static bool HasUnifiedPayload(string root, IReadOnlyDictionary<string, string> expected, string? processPath) =>
        StartupCompatibility.IsUnifiedHost(processPath) ||
        Enum.GetValues<StartupRole>().SelectMany(role => Enum.GetValues<StartupMode>().Select(mode => StartupCompatibility.HostFileName(role, mode)))
            .Any(name => expected.ContainsKey(name) || File.Exists(Path.Combine(root, name)));

    public static InstallationSecurityStatus Evaluate(
        string? baseDirectory = null,
        InstallationVerificationDepth depth = InstallationVerificationDepth.Full)
    {
        try
        {
            string root = Path.TrimEndingDirectorySeparator(Path.GetFullPath(baseDirectory ?? AppContext.BaseDirectory));
            if (Validation.ContainsReparsePoint(root))
                return new(false, MessageText.Create("Backend.Core.InstallationSecurity.Evaluate.02"));

            bool inProgramFiles = IsUnderProgramFiles(root);
            if (inProgramFiles)
            {
                InstallationSecurityStatus directoryAcl = CheckAcl(new DirectoryInfo(root));
                if (!directoryAcl.IsProtected) return directoryAcl;
            }

            string sumsPath = Path.Combine(root, "SHA256SUMS.txt");
            if (!File.Exists(sumsPath) || Validation.IsRedirectingReparsePoint(sumsPath))
                return new(false, MessageText.Create("Backend.Core.InstallationSecurity.Evaluate.03"));
            if (inProgramFiles)
            {
                InstallationSecurityStatus sumsAcl = CheckAcl(new FileInfo(sumsPath));
                if (!sumsAcl.IsProtected) return sumsAcl;
            }

            Dictionary<string, string> expected = ReadChecksums(sumsPath);
            bool unified = HasUnifiedPayload(root, expected, Environment.ProcessPath);
            string[] required = RequiredComponents(unified).ToArray();
            foreach (string component in required)
                if (!expected.ContainsKey(component)) return new(false, MessageText.Create("Backend.Core.InstallationSecurity.Evaluate.04", (component)));

            foreach (string file in EnumerateInstallFilesWithoutReparsePoints(root))
            {
                string relative = Path.GetRelativePath(root, file);
                if (!IsLoadablePayloadPath(relative) || expected.ContainsKey(relative)) continue;
                if (!IsAllowedUnlistedInstallFile(relative))
                    return new(false, MessageText.Create("Backend.Core.InstallationSecurity.Evaluate.05", (relative)));
                if (inProgramFiles)
                {
                    InstallationSecurityStatus uninstallerAcl = CheckAcl(new FileInfo(file));
                    if (!uninstallerAcl.IsProtected) return uninstallerAcl;
                }
            }

            // Apphosts load managed assemblies and bundled runtime files. Verify hashes under
            // exclusive read handles; Fast checks core launch targets while Full verifies all entries.
            HashSet<string> checkedDirectories = new(StringComparer.OrdinalIgnoreCase) { root };
            IEnumerable<KeyValuePair<string, string>> verificationTargets = depth == InstallationVerificationDepth.Full
                ? expected
                : required.Select(component => new KeyValuePair<string, string>(component, expected[component]));
            foreach ((string component, string expectedHash) in verificationTargets)
            {
                string path = Path.Combine(root, component);
                if (!File.Exists(path) || Validation.ContainsReparsePoint(path))
                    return new(false, MessageText.Create("Backend.Core.InstallationSecurity.Evaluate.06", (component)));
                if (inProgramFiles)
                {
                    for (DirectoryInfo? parent = Directory.GetParent(path); parent is not null && checkedDirectories.Add(parent.FullName); parent = parent.Parent)
                    {
                        InstallationSecurityStatus parentAcl = CheckAcl(parent);
                        if (!parentAcl.IsProtected) return parentAcl;
                    }
                    InstallationSecurityStatus fileAcl = CheckAcl(new FileInfo(path));
                    if (!fileAcl.IsProtected) return fileAcl;
                }
                string actualHash = ComputeSha256Exclusive(path);
                if (!actualHash.Equals(expectedHash, StringComparison.OrdinalIgnoreCase))
                    return new(false, MessageText.Create("Backend.Core.InstallationSecurity.Evaluate.07", (component)));
            }

            return inProgramFiles
                ? InstallationSecurityStatus.Protected
                : InstallationSecurityStatus.Portable(MessageText.Create("Backend.Core.InstallationSecurity.Portable.01"));
        }
        catch (Exception ex)
        {
            return new(false, MessageText.Create("Backend.Core.InstallationSecurity.Evaluate.08", (MessageExceptions.Describe(ex))));
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
            !IsTrustedOwnerSid(owner.Value))
        {
            return new(false, MessageText.Create("Backend.Core.InstallationSecurity.CheckSecurityDescriptor.01", (name)));
        }

        if (new RawSecurityDescriptor(security.GetSecurityDescriptorBinaryForm(), 0).DiscretionaryAcl is null)
            return new(false, MessageText.Create("Backend.Core.InstallationSecurity.CheckSecurityDescriptor.02", (name)));

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
            if (!IsTrustedOwnerSid(identity.Value))
            {
                return new(false, MessageText.Create("Backend.Core.InstallationSecurity.CheckSecurityDescriptor.03", (name)));
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
                throw MessageExceptions.Create(MessageText.Create("Backend.Core.InstallationSecurity.ReadChecksums.01"), sourceText => new InvalidDataException(sourceText));
            string relative = line[65..].TrimStart(' ', '*').Replace('/', Path.DirectorySeparatorChar);
            if (string.IsNullOrWhiteSpace(relative) || Path.IsPathRooted(relative) || relative.Contains(':') ||
                relative.Split(Path.DirectorySeparatorChar).Any(part => part is "" or "." or ".." ||
                    part.EndsWith(' ') || part.EndsWith('.') || part.IndexOfAny(Path.GetInvalidFileNameChars()) >= 0) ||
                !checksums.TryAdd(relative, line[..64]))
                throw MessageExceptions.Create(MessageText.Create("Backend.Core.InstallationSecurity.ReadChecksums.02"), sourceText => new InvalidDataException(sourceText));
        }
        return checksums;
    }

    internal static bool IsLoadablePayloadPath(string relativePath)
    {
        string name = Path.GetFileName(relativePath);
        string extension = Path.GetExtension(name);
        return extension.Equals(".exe", StringComparison.OrdinalIgnoreCase) ||
               extension.Equals(".dll", StringComparison.OrdinalIgnoreCase) ||
               extension.Equals(".com", StringComparison.OrdinalIgnoreCase) ||
               extension.Equals(".scr", StringComparison.OrdinalIgnoreCase) ||
               extension.Equals(".cpl", StringComparison.OrdinalIgnoreCase) ||
               extension.Equals(".ocx", StringComparison.OrdinalIgnoreCase) ||
               extension.Equals(".sys", StringComparison.OrdinalIgnoreCase) ||
               extension.Equals(".winmd", StringComparison.OrdinalIgnoreCase) ||
               extension.Equals(".config", StringComparison.OrdinalIgnoreCase) ||
               name.Contains(".deps.", StringComparison.OrdinalIgnoreCase) ||
               name.Contains(".runtimeconfig.", StringComparison.OrdinalIgnoreCase);
    }

    internal static bool IsAllowedUnlistedInstallFile(string relativePath) =>
        relativePath.Length == 12 &&
        relativePath.StartsWith("unins", StringComparison.OrdinalIgnoreCase) &&
        relativePath.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) &&
        char.IsAsciiDigit(relativePath[5]) &&
        char.IsAsciiDigit(relativePath[6]) &&
        char.IsAsciiDigit(relativePath[7]);

    private static IEnumerable<string> EnumerateInstallFilesWithoutReparsePoints(string root)
    {
        Stack<string> pending = new();
        pending.Push(root);
        while (pending.Count > 0)
        {
            string directory = pending.Pop();
            foreach (string entry in Directory.EnumerateFileSystemEntries(directory, "*", SearchOption.TopDirectoryOnly))
            {
                FileAttributes attributes = File.GetAttributes(entry);
                if ((attributes & FileAttributes.ReparsePoint) != 0 && Validation.IsRedirectingReparsePoint(entry))
                    throw MessageExceptions.Create(MessageText.Create("Backend.Core.InstallationSecurity.EnumerateInstallFilesWithoutReparsePoints.01", (Path.GetRelativePath(root, entry))), sourceText => new UnauthorizedAccessException(sourceText));
                if ((attributes & FileAttributes.Directory) != 0) pending.Push(entry);
                else yield return entry;
            }
        }
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
    private const int MaximumProtectedTreeEntries = 200_000;

    public static void EnsureProtectedRoots(bool createIfMissing = false)
    {
        string machineRoot = Path.GetFullPath(AppPaths.MachineStateRoot);
        if (Validation.ContainsReparsePoint(machineRoot))
            throw MessageExceptions.Create(MessageText.Create("Backend.Core.InstallationSecurity.EnsureProtectedRoots.01"), sourceText => new UnauthorizedAccessException(sourceText));

        EnsureProtectedOrCreateRootDirectory(machineRoot, createIfMissing, allowUsersBrowse: true);
        foreach (string child in new[] { AppPaths.QuarantineRoot, AppPaths.ResultsRoot, AppPaths.BrokerTemporaryRoot })
        {
            if (Validation.ContainsReparsePoint(child))
                throw MessageExceptions.Create(MessageText.Create("Backend.Core.InstallationSecurity.EnsureProtectedRoots.02"), sourceText => new UnauthorizedAccessException(sourceText));
            bool allowUsersBrowse = !Path.GetFullPath(child).Equals(
                Path.GetFullPath(AppPaths.BrokerTemporaryRoot),
                StringComparison.OrdinalIgnoreCase);
            EnsureProtectedOrCreateRootDirectory(child, createIfMissing, allowUsersBrowse);
        }
    }

    private static void EnsureProtectedOrCreateRootDirectory(string path, bool createIfMissing, bool allowUsersBrowse)
    {
        if (!File.Exists(path) && !Directory.Exists(path))
        {
            if (!createIfMissing)
                throw MessageExceptions.Create(MessageText.Create("Backend.Core.InstallationSecurity.EnsureExistingProtectedDirectory.01"), sourceText => new UnauthorizedAccessException(sourceText));

            string? parent = Path.GetDirectoryName(Path.TrimEndingDirectorySeparator(path));
            if (!string.IsNullOrEmpty(parent) && Validation.ContainsReparsePoint(parent))
                throw MessageExceptions.Create(MessageText.Create("Backend.Core.InstallationSecurity.EnsureProtectedRoots.01"), sourceText => new UnauthorizedAccessException(sourceText));

            Directory.CreateDirectory(path);
            ApplyProtectedDirectoryAcl(path, allowUsersBrowse);
            EnsureProtectedPath(path);
            return;
        }

        EnsureExistingProtectedDirectory(path);
        ApplyProtectedDirectoryAcl(path, allowUsersBrowse);
    }

    private static void EnsureExistingProtectedDirectory(string path)
    {
        if (File.Exists(path) || !Directory.Exists(path))
            throw MessageExceptions.Create(MessageText.Create("Backend.Core.InstallationSecurity.EnsureExistingProtectedDirectory.01"), sourceText => new UnauthorizedAccessException(sourceText));
        InstallationSecurityStatus status = InstallationSecurity.CheckAcl(new DirectoryInfo(path));
        if (!status.IsProtected)
            throw MessageExceptions.Create(MessageText.Create("Backend.Core.InstallationSecurity.EnsureExistingProtectedDirectory.02", (status.MessageText)), sourceText => new UnauthorizedAccessException(sourceText));
    }

    public static void PrepareIncidentDirectory(string path, string requestedBySid)
    {
        string fullPath = RequireWithin(path, AppPaths.QuarantineRoot);
        if (File.Exists(fullPath) || Directory.Exists(fullPath))
            throw MessageExceptions.Create(MessageText.Create("Backend.Core.InstallationSecurity.PrepareIncidentDirectory.01"), sourceText => new IOException(sourceText));
        if (Validation.ContainsReparsePoint(Path.GetDirectoryName(fullPath)!))
            throw MessageExceptions.Create(MessageText.Create("Backend.Core.InstallationSecurity.PrepareIncidentDirectory.02"), sourceText => new UnauthorizedAccessException(sourceText));

        Directory.CreateDirectory(fullPath);
        SecurityIdentifier requester = ParseRequester(requestedBySid);
        DirectorySecurity security = BuildProtectedDirectorySecurity(requester, allowUsersBrowse: false);
        FileSystemAclExtensions.SetAccessControl(new DirectoryInfo(fullPath), security);
        EnsureProtectedPath(fullPath);
    }

    public static void PreparePayloadDirectory(string path)
    {
        string fullPath = RequireWithin(path, AppPaths.QuarantineRoot);
        if (Validation.ContainsReparsePoint(Path.GetDirectoryName(fullPath)!))
            throw MessageExceptions.Create(MessageText.Create("Backend.Core.InstallationSecurity.PreparePayloadDirectory.01"), sourceText => new UnauthorizedAccessException(sourceText));
        List<string> missing = [];
        for (string? current = fullPath; current is not null && !Directory.Exists(current); current = Path.GetDirectoryName(current))
        {
            if (!current.StartsWith(
                    Path.TrimEndingDirectorySeparator(Path.GetFullPath(AppPaths.QuarantineRoot)) + Path.DirectorySeparatorChar,
                    StringComparison.OrdinalIgnoreCase))
            {
                throw MessageExceptions.Create(MessageText.Create("Backend.Core.InstallationSecurity.PreparePayloadDirectory.02"), sourceText => new UnauthorizedAccessException(sourceText));
            }
            missing.Add(current);
        }
        Directory.CreateDirectory(fullPath);
        foreach (string created in missing.AsEnumerable().Reverse())
            ApplyProtectedDirectoryAcl(created, allowUsersBrowse: false);
        // Reassert the exact leaf even when it pre-existed; only the elevated broker can
        // create it beneath a protected incident root.
        ApplyProtectedDirectoryAcl(fullPath, allowUsersBrowse: false);
        EnsureProtectedPath(fullPath);
    }

    public static void ProtectManifestFile(string path, string requestedBySid) =>
        ApplyProtectedFileAcl(RequireWithin(path, AppPaths.QuarantineRoot), ParseRequester(requestedBySid));

    public static void ProtectPayloadFile(string path) =>
        ApplyProtectedFileAcl(RequireWithin(path, AppPaths.QuarantineRoot), reader: null);

    public static void ProtectResultFile(string path, string requestedBySid) =>
        ApplyProtectedFileAcl(RequireWithin(path, AppPaths.ResultsRoot), ParseRequester(requestedBySid));

    public static void ProtectBrokerStateFile(string path) =>
        ApplyProtectedFileAcl(RequireWithin(path, AppPaths.BrokerTemporaryRoot), reader: null);

    public static void EnsureProtectedPath(string path)
    {
        string fullPath = Path.GetFullPath(path);
        if (Validation.ContainsReparsePoint(fullPath))
            throw MessageExceptions.Create(MessageText.Create("Backend.Core.InstallationSecurity.EnsureProtectedPath.01", (fullPath)), sourceText => new UnauthorizedAccessException(sourceText));

        FileSystemInfo item = Directory.Exists(fullPath)
            ? new DirectoryInfo(fullPath)
            : File.Exists(fullPath)
                ? new FileInfo(fullPath)
                : throw MessageExceptions.Create(MessageText.Create("Backend.Core.InstallationSecurity.EnsureProtectedPath.02"), sourceText => new FileNotFoundException(sourceText, fullPath));
        InstallationSecurityStatus status = InstallationSecurity.CheckAcl(item);
        if (!status.IsProtected)
            throw MessageExceptions.Create(MessageText.Create("Backend.Core.InstallationSecurity.EnsureProtectedPath.03", (status.MessageText)), sourceText => new UnauthorizedAccessException(sourceText));
    }

    public static void EnsureProtectedSubtree(string path)
    {
        string root = Path.TrimEndingDirectorySeparator(Path.GetFullPath(path));
        EnsureProtectedPath(root);
        Stack<string> pending = new();
        pending.Push(root);
        int count = 0;
        while (pending.Count > 0)
        {
            string directory = pending.Pop();
            foreach (string entry in Directory.EnumerateFileSystemEntries(directory, "*", SearchOption.TopDirectoryOnly))
            {
                if (++count > MaximumProtectedTreeEntries)
                    throw MessageExceptions.Create(MessageText.Create("Backend.Core.InstallationSecurity.EnsureProtectedSubtree.01"), sourceText => new InvalidDataException(sourceText));
                FileAttributes attributes = File.GetAttributes(entry);
                if ((attributes & FileAttributes.ReparsePoint) != 0 && Validation.IsRedirectingReparsePoint(entry))
                    throw MessageExceptions.Create(MessageText.Create("Backend.Core.InstallationSecurity.EnsureProtectedSubtree.02", (entry)), sourceText => new UnauthorizedAccessException(sourceText));
                EnsureProtectedPath(entry);
                if ((attributes & FileAttributes.Directory) != 0) pending.Push(entry);
            }
        }
    }

    internal static DirectorySecurity BuildProtectedDirectorySecurity(
        SecurityIdentifier? requester = null,
        bool allowUsersBrowse = false)
    {
        DirectorySecurity security = new();
        security.SetOwner(new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null));
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        InheritanceFlags inheritance = InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit;
        AddFullControlRules(security, inheritance);
        if (allowUsersBrowse)
        {
            security.AddAccessRule(new FileSystemAccessRule(
                new SecurityIdentifier(WellKnownSidType.BuiltinUsersSid, null),
                FileSystemRights.ReadAndExecute | FileSystemRights.ListDirectory | FileSystemRights.Read,
                InheritanceFlags.None,
                PropagationFlags.None,
                AccessControlType.Allow));
        }
        if (requester is not null)
        {
            security.AddAccessRule(new FileSystemAccessRule(
                requester,
                FileSystemRights.ReadAndExecute | FileSystemRights.ListDirectory | FileSystemRights.Read,
                InheritanceFlags.None,
                PropagationFlags.None,
                AccessControlType.Allow));
        }
        return security;
    }

    internal static FileSecurity BuildProtectedFileSecurity(SecurityIdentifier? reader = null)
    {
        FileSecurity security = new();
        security.SetOwner(new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null));
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        AddFullControlRules(security, InheritanceFlags.None);
        if (reader is not null)
        {
            security.AddAccessRule(new FileSystemAccessRule(
                reader,
                FileSystemRights.Read,
                InheritanceFlags.None,
                PropagationFlags.None,
                AccessControlType.Allow));
        }
        return security;
    }

    private static void ApplyProtectedDirectoryAcl(string path, bool allowUsersBrowse)
    {
        FileSystemAclExtensions.SetAccessControl(
            new DirectoryInfo(path),
            BuildProtectedDirectorySecurity(allowUsersBrowse: allowUsersBrowse));
    }

    private static void ApplyProtectedFileAcl(string path, SecurityIdentifier? reader)
    {
        if (!File.Exists(path) || Validation.ContainsReparsePoint(path))
            throw MessageExceptions.Create(MessageText.Create("Backend.Core.InstallationSecurity.ApplyProtectedFileAcl.01"), sourceText => new UnauthorizedAccessException(sourceText));
        FileSystemAclExtensions.SetAccessControl(new FileInfo(path), BuildProtectedFileSecurity(reader));
        EnsureProtectedPath(path);
    }

    private static void AddFullControlRules(FileSystemSecurity security, InheritanceFlags inheritance)
    {
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
    }

    private static SecurityIdentifier ParseRequester(string sid)
    {
        if (string.IsNullOrWhiteSpace(sid)) throw MessageExceptions.Create(MessageText.Create("Backend.Core.InstallationSecurity.ParseRequester.01"), sourceText => new InvalidDataException(sourceText));
        try { return new SecurityIdentifier(sid); }
        catch (ArgumentException ex) { throw MessageExceptions.Create(MessageText.Create("Backend.Core.InstallationSecurity.ParseRequester.02"), sourceText => new InvalidDataException(sourceText, ex)); }
    }

    private static string RequireWithin(string path, string root)
    {
        string fullPath = Path.GetFullPath(path);
        string fullRoot = Path.TrimEndingDirectorySeparator(Path.GetFullPath(root));
        if (!fullPath.StartsWith(fullRoot + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase))
            throw MessageExceptions.Create(MessageText.Create("Backend.Core.InstallationSecurity.RequireWithin.01"), sourceText => new UnauthorizedAccessException(sourceText));
        return fullPath;
    }
}
