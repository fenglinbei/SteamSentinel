using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using SteamSentinel.Core.Scanning;
using SteamSentinel.Core.Utilities;

namespace SteamSentinel.Core.Steam;

/// <summary>Steam 客户端官方分包清单条目（解析自 steam_client_*.manifest）。</summary>
/// <param name="Name">分包逻辑名称（如 steamui_websrc_all、steam_win64）。</param>
/// <param name="ZipFile">官方未加套壳的 ZIP 分包文件名。</param>
/// <param name="ZipSize">官方 ZIP 分包字节大小。</param>
/// <param name="Sha256">ZIP 分包的 64 位十六进制 SHA-256 摘要。</param>
/// <param name="ZipVzFile">可选的 Valve LZMA+ZIP 容器文件名（*.zip.vz.*）。</param>
/// <param name="Sha256Vz">可选的 .zip.vz 文件 64 位十六进制 SHA-256 摘要。</param>
/// <param name="IsBootstrapperPackage">是否为引导器核心分包（如 steam_win64）。</param>
public sealed record SteamPackageEntry(
    string Name,
    string ZipFile,
    long ZipSize,
    string Sha256,
    string? ZipVzFile,
    string? Sha256Vz,
    bool IsBootstrapperPackage);

/// <summary>Steam 客户端已安装清单中的官方文件/目录记录（解析自 steam_client_*.installed）。</summary>
/// <param name="RelativePath">相对于 Steam 根目录的归一化路径（统一使用 / 分隔）。</param>
/// <param name="Size">官方文件大小（目录项为 -1）。</param>
/// <param name="Timestamp">官方清单记录的 Unix 时间戳。</param>
/// <param name="Crc32">官方记录的 IEEE 802.3 CRC32 校验值（目录项通常为 0）。</param>
/// <param name="IsDirectory">是否为目录标记行（size == -1）。</param>
public sealed record SteamInstalledFileEntry(
    string RelativePath,
    long Size,
    long Timestamp,
    uint Crc32,
    bool IsDirectory = false);

/// <summary>Steam 官方 .installed 清单索引解析结果。</summary>
/// <param name="Entries">全部有效条目字典（文件与目录，目录以 / 结尾）。</param>
/// <param name="Files">仅包含文件条目的字典（不含目录项）。</param>
/// <param name="OsVersion">末尾 OSVER 字段值。</param>
/// <param name="FormatVersion">末尾 VERSION 字段值。</param>
/// <param name="ExpectedSha1">末尾 SHA1 校验字段值。</param>
/// <param name="IsSha1Verified">LF 归一化自校验 SHA-1 是否通过。</param>
public sealed record SteamInstalledIndex(
    IReadOnlyDictionary<string, SteamInstalledFileEntry> Entries,
    IReadOnlyDictionary<string, SteamInstalledFileEntry> Files,
    string? OsVersion,
    string? FormatVersion,
    string? ExpectedSha1,
    bool IsSha1Verified);

/// <summary>
/// Steam 客户端官方分包目录与已安装文件索引。
/// 负责安全解析 package\steam_client_*.manifest 与对应的 *.installed 文件并提供智能分包路由。
/// </summary>
public sealed class SteamPackageCatalog
{
    /// <summary>单个 manifest 文件最大允许读取字节数（8 MiB）。</summary>
    public const int MaximumManifestBytes = 8 * 1024 * 1024;

    /// <summary>单个 .installed 清单最大允许读取字节数（16 MiB）。</summary>
    public const int MaximumInstalledBytes = 16 * 1024 * 1024;

    private const int MaximumVdfDepth = 8;

    private static readonly string[] PriorityManifestNames =
    [
        "steam_client_win64.manifest",
        "steam_client_publicbeta_win64.manifest",
        "steam_client_win32.manifest"
    ];

    private static readonly Encoding StrictUtf8 = new UTF8Encoding(encoderShouldEmitUTF8Identifier: false, throwOnInvalidBytes: true);

    private readonly Dictionary<string, SteamPackageEntry> _packageMap;
    private readonly Dictionary<string, SteamInstalledFileEntry> _installedEntries;
    private readonly Dictionary<string, SteamInstalledFileEntry> _installedFiles;

    private SteamPackageCatalog(
        string steamRoot,
        string packageDirectory,
        string manifestPath,
        string? installedPath,
        string platformKey,
        string? clientVersion,
        string? osType,
        IReadOnlyList<SteamPackageEntry> packages,
        SteamInstalledIndex? installedIndex)
    {
        SteamRoot = steamRoot;
        PackageDirectory = packageDirectory;
        ManifestPath = manifestPath;
        InstalledPath = installedPath;
        PlatformKey = platformKey;
        ClientVersion = clientVersion;
        OsType = osType;
        Packages = packages;
        _packageMap = new Dictionary<string, SteamPackageEntry>(StringComparer.OrdinalIgnoreCase);
        foreach (SteamPackageEntry entry in packages)
        {
            _packageMap.TryAdd(entry.Name, entry);
        }

        if (installedIndex is { IsSha1Verified: true })
        {
            HasVerifiedInstalledIndex = true;
            InstalledOsVersion = installedIndex.OsVersion;
            InstalledFormatVersion = installedIndex.FormatVersion;
            InstalledSha1 = installedIndex.ExpectedSha1;
            _installedEntries = new Dictionary<string, SteamInstalledFileEntry>(installedIndex.Entries, StringComparer.OrdinalIgnoreCase);
            _installedFiles = new Dictionary<string, SteamInstalledFileEntry>(installedIndex.Files, StringComparer.OrdinalIgnoreCase);
        }
        else
        {
            HasVerifiedInstalledIndex = false;
            InstalledOsVersion = installedIndex?.OsVersion;
            InstalledFormatVersion = installedIndex?.FormatVersion;
            InstalledSha1 = installedIndex?.ExpectedSha1;
            _installedEntries = new Dictionary<string, SteamInstalledFileEntry>(StringComparer.OrdinalIgnoreCase);
            _installedFiles = new Dictionary<string, SteamInstalledFileEntry>(StringComparer.OrdinalIgnoreCase);
        }
    }

    /// <summary>归一化后的本地安全 Steam 根目录路径。</summary>
    public string SteamRoot { get; }

    /// <summary>Steam package 子目录完整路径。</summary>
    public string PackageDirectory { get; }

    /// <summary>当前生效的官方分包 manifest 完整路径。</summary>
    public string ManifestPath { get; }

    /// <summary>配对的 .installed 清单路径（若存在）。</summary>
    public string? InstalledPath { get; }

    /// <summary>manifest 根平台键（例如 win64、win32）。</summary>
    public string PlatformKey { get; }

    /// <summary>manifest 中记录的客户端版本号。</summary>
    public string? ClientVersion { get; }

    /// <summary>manifest 中记录的目标操作系统类型。</summary>
    public string? OsType { get; }

    /// <summary>按清单声明顺序排列的官方分包条目列表。</summary>
    public IReadOnlyList<SteamPackageEntry> Packages { get; }

    /// <summary>按分包名称索引的分包字典（忽略大小写）。</summary>
    public IReadOnlyDictionary<string, SteamPackageEntry> PackageMap => _packageMap;

    /// <summary>配对的 .installed 文件是否存在且通过 SHA-1 自校验。</summary>
    public bool HasVerifiedInstalledIndex { get; }

    /// <summary>.installed 末尾记录的 OSVER。</summary>
    public string? InstalledOsVersion { get; }

    /// <summary>.installed 末尾记录的 VERSION。</summary>
    public string? InstalledFormatVersion { get; }

    /// <summary>.installed 末尾记录的 SHA1 摘要。</summary>
    public string? InstalledSha1 { get; }

    /// <summary>已通过自校验的官方全部条目字典（含文件及以 / 结尾的目录项）。</summary>
    public IReadOnlyDictionary<string, SteamInstalledFileEntry> InstalledEntries => _installedEntries;

    /// <summary>已通过自校验的官方文件条目字典（不含目录项）。</summary>
    public IReadOnlyDictionary<string, SteamInstalledFileEntry> InstalledFiles => _installedFiles;

    /// <summary>尝试为指定的 Steam 根目录加载官方分包目录与已安装索引。</summary>
    public static bool TryLoadForSteamRoot(string? steamRoot, [NotNullWhen(true)] out SteamPackageCatalog? catalog)
    {
        catalog = null;
        if (string.IsNullOrWhiteSpace(steamRoot) || !ContentDiscovery.IsLocalSafePath(steamRoot))
        {
            return false;
        }

        string fullRoot;
        string packageDir;
        try
        {
            fullRoot = Path.TrimEndingDirectorySeparator(Path.GetFullPath(steamRoot));
            packageDir = Path.Combine(fullRoot, "package");
            if (!ContentDiscovery.IsLocalSafePath(fullRoot) ||
                !ContentDiscovery.IsLocalSafePath(packageDir) ||
                !Directory.Exists(packageDir))
            {
                return false;
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException)
        {
            return false;
        }

        List<string> candidateManifests = EnumerateCandidateManifests(packageDir);
        foreach (string manifestPath in candidateManifests)
        {
            if (!ContentDiscovery.IsLocalSafePath(manifestPath) || !File.Exists(manifestPath))
            {
                continue;
            }

            if (!TryReadAndParseManifest(manifestPath, out string? platformKey, out string? clientVersion, out string? osType, out List<SteamPackageEntry>? packages))
            {
                continue;
            }

            string installedPath = Path.ChangeExtension(manifestPath, ".installed");
            SteamInstalledIndex? installedIndex = null;
            string? resolvedInstalledPath = null;
            if (File.Exists(installedPath) && ContentDiscovery.IsLocalSafePath(installedPath))
            {
                resolvedInstalledPath = installedPath;
                TryParseInstalledFile(installedPath, out installedIndex);
            }

            catalog = new SteamPackageCatalog(
                fullRoot,
                packageDir,
                manifestPath,
                resolvedInstalledPath,
                platformKey,
                clientVersion,
                osType,
                packages,
                installedIndex);
            return true;
        }

        return false;
    }

    /// <summary>按分包名查询官方分包条目。</summary>
    public bool TryGetPackage(string packageName, [NotNullWhen(true)] out SteamPackageEntry? entry)
    {
        entry = null;
        if (string.IsNullOrWhiteSpace(packageName))
        {
            return false;
        }

        return _packageMap.TryGetValue(packageName, out entry);
    }

    /// <summary>判断相对路径是否属于已校验 .installed 清单中的官方文件。</summary>
    public bool IsKnownOfficialRelativePath(string? relativePath) =>
        HasVerifiedInstalledIndex &&
        TryNormalizeRelativePath(relativePath, out string normalized) &&
        _installedFiles.ContainsKey(normalized);

    /// <summary>查询已校验 .installed 清单中的官方文件（或带末尾分隔符的目录）条目。</summary>
    public bool TryGetInstalledEntry(string? relativePath, [NotNullWhen(true)] out SteamInstalledFileEntry? entry)
    {
        entry = null;
        if (!HasVerifiedInstalledIndex || string.IsNullOrWhiteSpace(relativePath))
        {
            return false;
        }

        string trimmed = relativePath.Trim();
        if (trimmed.EndsWith('/') || trimmed.EndsWith('\\'))
        {
            string withoutTrailing = trimmed.TrimEnd('/', '\\');
            if (!TryNormalizeRelativePath(withoutTrailing, out string dirNorm))
            {
                return false;
            }

            return _installedEntries.TryGetValue(dirNorm + "/", out entry);
        }

        return TryNormalizeRelativePath(trimmed, out string fileNorm) &&
               _installedFiles.TryGetValue(fileNorm, out entry);
    }

    /// <summary>
    /// 按目标相对路径智能排序候选分包，优先命中高频小包，将 bins_cef* 置后并排除纯媒体包以避免无效扫描。
    /// </summary>
    public IReadOnlyList<SteamPackageEntry> OrderCandidatePackages(string? relativePath)
    {
        if (!TryNormalizeRelativePath(relativePath, out string normalized))
        {
            return [];
        }

        List<(SteamPackageEntry Entry, int Priority, int Index)> scored = new(Packages.Count);
        for (int index = 0; index < Packages.Count; index++)
        {
            SteamPackageEntry entry = Packages[index];
            if (IsExcludedMediaPackage(entry.Name))
            {
                continue;
            }

            int priority = GetPackagePriority(entry.Name, normalized);
            scored.Add((entry, priority, index));
        }

        return scored
            .OrderBy(item => item.Priority)
            .ThenBy(item => item.Index)
            .Select(item => item.Entry)
            .ToArray();
    }

    /// <summary>校验分包文件名或条目名是否安全（严禁目录穿越、分隔符、冒号与控制字符）。</summary>
    public static bool IsSafePackageFileName([NotNullWhen(true)] string? fileName)
    {
        if (string.IsNullOrWhiteSpace(fileName) || fileName.Length > 255)
        {
            return false;
        }

        if (fileName is "." or ".." ||
            fileName.Contains("..", StringComparison.Ordinal) ||
            fileName.IndexOfAny(['/', '\\', ':', '\0']) >= 0 ||
            char.IsWhiteSpace(fileName[0]) ||
            char.IsWhiteSpace(fileName[^1]) ||
            fileName.Any(char.IsControl))
        {
            return false;
        }

        return string.Equals(Path.GetFileName(fileName), fileName, StringComparison.Ordinal);
    }

    /// <summary>归一化相对路径（将 \ 转为 /，拒绝盘符、绝对路径、空字节与 .. 段）。</summary>
    public static bool TryNormalizeRelativePath([NotNullWhen(true)] string? relativePath, out string normalized)
    {
        normalized = string.Empty;
        if (string.IsNullOrWhiteSpace(relativePath) || relativePath.Length > 1024)
        {
            return false;
        }

        if (relativePath.IndexOfAny(['\0', ':', '*', '?', '"', '<', '>', '|']) >= 0 ||
            relativePath.Any(char.IsControl))
        {
            return false;
        }

        if (relativePath.StartsWith('/') || relativePath.StartsWith('\\') || Path.IsPathRooted(relativePath))
        {
            return false;
        }

        string unified = relativePath.Replace('\\', '/');
        if (unified.Contains("..", StringComparison.Ordinal))
        {
            return false;
        }

        string[] segments = unified.Split('/');
        if (segments.Length == 0 || segments.Any(segment => segment is "" or "." or ".."))
        {
            return false;
        }

        normalized = string.Join('/', segments);
        return true;
    }

    /// <summary>解析并校验本地 steam_client_*.installed 文件（含末尾 SHA1 LF 归一化自校验）。</summary>
    public static bool TryParseInstalledFile(string installedPath, [NotNullWhen(true)] out SteamInstalledIndex? index)
    {
        index = null;
        if (string.IsNullOrWhiteSpace(installedPath) || !ContentDiscovery.IsLocalSafePath(installedPath))
        {
            return false;
        }

        try
        {
            using FileStream stream = RelatedArtifactReader.Open(installedPath);
            if (stream.Length <= 0 || stream.Length > MaximumInstalledBytes)
            {
                return false;
            }

            byte[] rawBytes = ReadBoundedBytes(stream, MaximumInstalledBytes);
            string text = DecodeStrictUtf8(rawBytes);
            return TryParseInstalledText(text, out index);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or DecoderFallbackException or System.ComponentModel.Win32Exception)
        {
            return false;
        }
    }

    /// <summary>从已解码的 .installed 文本中解析条目并执行末尾 SHA1 自校验。</summary>
    internal static bool TryParseInstalledText(string text, [NotNullWhen(true)] out SteamInstalledIndex? index)
    {
        index = null;
        if (string.IsNullOrWhiteSpace(text) || text.Contains('\0'))
        {
            return false;
        }

        // Steam 在 Windows 上将 .installed 写为 CRLF，但末尾 SHA1 是对 SHA1= 行之前全部文本做 LF(\n) 归一化后计算的。
        int shaLineIndex = text.LastIndexOf("SHA1=", StringComparison.Ordinal);
        if (shaLineIndex < 0)
        {
            return false;
        }

        if (shaLineIndex > 0 && text[shaLineIndex - 1] is not ('\n' or '\r'))
        {
            return false;
        }

        string shaRemainder = text[(shaLineIndex + 5)..].TrimEnd('\r', '\n');
        if (shaRemainder.Length != 40 || !shaRemainder.All(Uri.IsHexDigit))
        {
            return false;
        }

        string expectedSha1 = shaRemainder.ToUpperInvariant();
        string signedPrefix = text[..shaLineIndex].Replace("\r\n", "\n", StringComparison.Ordinal);
        byte[] signedBytes = StrictUtf8.GetBytes(signedPrefix);
        string actualSha1 = Convert.ToHexString(SHA1.HashData(signedBytes));
        bool sha1Verified = string.Equals(actualSha1, expectedSha1, StringComparison.OrdinalIgnoreCase);

        Dictionary<string, SteamInstalledFileEntry> entries = new(StringComparer.OrdinalIgnoreCase);
        Dictionary<string, SteamInstalledFileEntry> files = new(StringComparer.OrdinalIgnoreCase);
        string? osVersion = null;
        string? formatVersion = null;

        string[] lines = signedPrefix.Split('\n');
        foreach (string rawLine in lines)
        {
            string line = rawLine.TrimEnd('\r');
            if (line.Length == 0)
            {
                continue;
            }

            if (line.StartsWith("OSVER=", StringComparison.Ordinal))
            {
                osVersion = line[6..];
                continue;
            }

            if (line.StartsWith("VERSION=", StringComparison.Ordinal))
            {
                formatVersion = line[8..];
                continue;
            }

            int commaIndex = line.LastIndexOf(',');
            if (commaIndex <= 0 || commaIndex >= line.Length - 1)
            {
                return false;
            }

            string rawRelPath = line[..commaIndex];
            string metaPart = line[(commaIndex + 1)..];
            string[] metaTokens = metaPart.Split(';');
            if (metaTokens.Length != 3 ||
                !long.TryParse(metaTokens[0], NumberStyles.Integer, CultureInfo.InvariantCulture, out long size) ||
                !long.TryParse(metaTokens[1], NumberStyles.Integer, CultureInfo.InvariantCulture, out long timestamp) ||
                !uint.TryParse(metaTokens[2], NumberStyles.None, CultureInfo.InvariantCulture, out uint crc32))
            {
                return false;
            }

            bool isDirectory = size == -1;
            if (!isDirectory && size < 0)
            {
                return false;
            }

            if (isDirectory)
            {
                string trimmedDir = rawRelPath.TrimEnd('/', '\\');
                if (!TryNormalizeRelativePath(trimmedDir, out string normalizedDir))
                {
                    return false;
                }

                string dirKey = normalizedDir + "/";
                entries[dirKey] = new SteamInstalledFileEntry(dirKey, size, timestamp, crc32, IsDirectory: true);
            }
            else
            {
                if (!TryNormalizeRelativePath(rawRelPath, out string normalizedFile))
                {
                    return false;
                }

                SteamInstalledFileEntry entry = new(normalizedFile, size, timestamp, crc32, IsDirectory: false);
                entries[normalizedFile] = entry;
                files[normalizedFile] = entry;
            }
        }

        index = new SteamInstalledIndex(entries, files, osVersion, formatVersion, expectedSha1, sha1Verified);
        return sha1Verified;
    }

    /// <summary>尝试解析单个 manifest 文件的 VDF 文本并验证所有条目安全性。</summary>
    internal static bool TryParseManifestText(
        string text,
        [NotNullWhen(true)] out string? platformKey,
        out string? clientVersion,
        out string? osType,
        [NotNullWhen(true)] out List<SteamPackageEntry>? packages)
    {
        platformKey = null;
        clientVersion = null;
        osType = null;
        packages = null;

        if (string.IsNullOrWhiteSpace(text) || text.Contains('\0'))
        {
            return false;
        }

        if (!TryParseVdfDocument(text, out VdfObject? root))
        {
            return false;
        }

        foreach (VdfNode topNode in root.Children)
        {
            if (topNode.Object is null)
            {
                continue;
            }

            if (topNode.Key.Equals("kvsign2", StringComparison.OrdinalIgnoreCase) ||
                topNode.Key.Equals("kvsignatures", StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            platformKey = topNode.Key;
            VdfObject platformObj = topNode.Object;
            List<SteamPackageEntry> parsed = [];

            foreach (VdfNode child in platformObj.Children)
            {
                if (child.Value is not null)
                {
                    if (child.Key.Equals("version", StringComparison.OrdinalIgnoreCase))
                    {
                        clientVersion = child.Value;
                    }
                    else if (child.Key.Equals("ostype", StringComparison.OrdinalIgnoreCase))
                    {
                        osType = child.Value;
                    }

                    continue;
                }

                if (child.Object is null)
                {
                    continue;
                }

                if (!IsSafePackageFileName(child.Key))
                {
                    return false;
                }

                if (!TryExtractPackageEntries(child.Key, child.Object, parsed))
                {
                    return false;
                }
            }

            if (parsed.Count == 0)
            {
                return false;
            }

            packages = parsed;
            return true;
        }

        return false;
    }

    private static bool TryReadAndParseManifest(
        string manifestPath,
        [NotNullWhen(true)] out string? platformKey,
        out string? clientVersion,
        out string? osType,
        [NotNullWhen(true)] out List<SteamPackageEntry>? packages)
    {
        platformKey = null;
        clientVersion = null;
        osType = null;
        packages = null;

        try
        {
            using FileStream stream = RelatedArtifactReader.Open(manifestPath);
            if (stream.Length <= 0 || stream.Length > MaximumManifestBytes)
            {
                return false;
            }

            byte[] rawBytes = ReadBoundedBytes(stream, MaximumManifestBytes);
            string text = DecodeStrictUtf8(rawBytes);
            return TryParseManifestText(text, out platformKey, out clientVersion, out osType, out packages);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or DecoderFallbackException or InvalidDataException or System.ComponentModel.Win32Exception)
        {
            return false;
        }
    }

    private static bool TryExtractPackageEntries(string packageName, VdfObject node, List<SteamPackageEntry> output)
    {
        bool hasAnyOwnPackageKey = false;
        Dictionary<string, string> scalars = new(StringComparer.OrdinalIgnoreCase);

        foreach (VdfNode child in node.Children)
        {
            if (child.Value is not null)
            {
                scalars[child.Key] = child.Value;
                if (child.Key.Equals("file", StringComparison.OrdinalIgnoreCase) ||
                    child.Key.Equals("size", StringComparison.OrdinalIgnoreCase) ||
                    child.Key.Equals("sha2", StringComparison.OrdinalIgnoreCase) ||
                    child.Key.Equals("zipvz", StringComparison.OrdinalIgnoreCase) ||
                    child.Key.Equals("sha2vz", StringComparison.OrdinalIgnoreCase))
                {
                    hasAnyOwnPackageKey = true;
                }
            }
            else if (child.Object is not null)
            {
                if (!IsSafePackageFileName(child.Key))
                {
                    return false;
                }

                // 兼容 steam_win64 下的 steamrow / steamchina 及 win7-64 等子分包节点，使用拼接名避免被父节点覆盖或遗漏本地变体。
                string subName = $"{packageName}_{child.Key}";
                if (!IsSafePackageFileName(subName))
                {
                    return false;
                }

                if (!TryExtractPackageEntries(subName, child.Object, output))
                {
                    return false;
                }
            }
        }

        if (!hasAnyOwnPackageKey)
        {
            return true;
        }

        if (!TryBuildPackageEntry(packageName, scalars, out SteamPackageEntry? entry))
        {
            return false;
        }

        output.Add(entry);
        return true;
    }

    private static bool TryBuildPackageEntry(
        string name,
        IReadOnlyDictionary<string, string> scalars,
        [NotNullWhen(true)] out SteamPackageEntry? entry)
    {
        entry = null;
        if (!IsSafePackageFileName(name))
        {
            return false;
        }

        if (!scalars.TryGetValue("file", out string? zipFile) || !IsSafePackageFileName(zipFile))
        {
            return false;
        }

        if (!scalars.TryGetValue("size", out string? sizeRaw) ||
            !long.TryParse(sizeRaw, NumberStyles.None, CultureInfo.InvariantCulture, out long zipSize) ||
            zipSize <= 0)
        {
            return false;
        }

        if (!scalars.TryGetValue("sha2", out string? sha2Raw) || !Validation.IsHexSha256(sha2Raw))
        {
            return false;
        }

        string sha256 = sha2Raw.ToUpperInvariant();

        string? zipVzFile = null;
        string? sha256Vz = null;
        bool hasZipVz = scalars.TryGetValue("zipvz", out string? rawZipVz);
        bool hasSha2Vz = scalars.TryGetValue("sha2vz", out string? rawSha2Vz);
        if (hasZipVz || hasSha2Vz)
        {
            if (!hasZipVz || !hasSha2Vz || !IsSafePackageFileName(rawZipVz) || !Validation.IsHexSha256(rawSha2Vz))
            {
                return false;
            }

            zipVzFile = rawZipVz;
            sha256Vz = rawSha2Vz!.ToUpperInvariant();
        }

        bool isBootstrapper = scalars.TryGetValue("IsBootstrapperPackage", out string? bootRaw) &&
                              (bootRaw == "1" || bootRaw.Equals("true", StringComparison.OrdinalIgnoreCase));

        entry = new SteamPackageEntry(name, zipFile, zipSize, sha256, zipVzFile, sha256Vz, isBootstrapper);
        return true;
    }

    private static List<string> EnumerateCandidateManifests(string packageDir)
    {
        List<string> ordered = [];
        HashSet<string> seen = new(StringComparer.OrdinalIgnoreCase);

        foreach (string preferred in PriorityManifestNames)
        {
            string full = Path.Combine(packageDir, preferred);
            if (File.Exists(full) && seen.Add(full))
            {
                ordered.Add(full);
            }
        }

        try
        {
            foreach (string candidate in Directory.EnumerateFiles(packageDir, "steam_client_*.manifest")
                .OrderBy(path => path, StringComparer.OrdinalIgnoreCase))
            {
                if (seen.Add(candidate))
                {
                    ordered.Add(candidate);
                }
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            // 若无法枚举其余清单文件，仍保留已命中的高优先级候选清单。
        }

        return ordered;
    }

    private static bool IsExcludedMediaPackage(string packageName) =>
        packageName.Equals("steamui_websrc_movies_all", StringComparison.OrdinalIgnoreCase) ||
        packageName.Equals("steamui_websrc_sounds_all", StringComparison.OrdinalIgnoreCase) ||
        packageName.Equals("tenfoot_images_all", StringComparison.OrdinalIgnoreCase) ||
        packageName.Contains("_movies_", StringComparison.OrdinalIgnoreCase) ||
        packageName.Contains("_sounds_", StringComparison.OrdinalIgnoreCase) ||
        packageName.Equals("sounds", StringComparison.OrdinalIgnoreCase) ||
        packageName.StartsWith("tenfoot_images", StringComparison.OrdinalIgnoreCase);

    private static int GetPackagePriority(string packageName, string normalizedPath)
    {
        if (packageName.StartsWith("bins_cef", StringComparison.OrdinalIgnoreCase))
        {
            return 1000;
        }

        if (normalizedPath.StartsWith("steamui/", StringComparison.OrdinalIgnoreCase))
        {
            return packageName.ToLowerInvariant() switch
            {
                "steamui_websrc_all" => 0,
                "public_all" => 1,
                "resources_all" => 2,
                "strings_all" => 3,
                "strings_en_all" => 4,
                _ => 50
            };
        }

        if (normalizedPath.StartsWith("clientui/", StringComparison.OrdinalIgnoreCase))
        {
            return packageName.ToLowerInvariant() switch
            {
                "public_all" => 0,
                "steamui_websrc_all" => 1,
                "resources_all" => 2,
                "resources_misc_all" => 3,
                "resources_hidpi_all" => 4,
                _ => 50
            };
        }

        if (normalizedPath.StartsWith("resource/", StringComparison.OrdinalIgnoreCase))
        {
            return packageName.ToLowerInvariant() switch
            {
                "resources_all" => 0,
                "resources_misc_all" => 1,
                "resources_hidpi_all" => 2,
                "public_all" => 3,
                _ => 50
            };
        }

        if (normalizedPath.Equals("steam.exe", StringComparison.OrdinalIgnoreCase))
        {
            return packageName.ToLowerInvariant() switch
            {
                "steam_win64" => 0,
                "steam_win64_steamrow" => 1,
                "steam_win64_steamchina" => 2,
                "steam_win32" => 3,
                "steam_win32_steamrow" => 4,
                "steam_win32_steamchina" => 5,
                "bins_win64" => 6,
                "bins_win32" => 7,
                _ => 50
            };
        }

        if (normalizedPath.StartsWith("public/", StringComparison.OrdinalIgnoreCase))
        {
            return packageName.ToLowerInvariant() switch
            {
                "public_all" => 0,
                "resources_all" => 1,
                "resources_misc_all" => 2,
                _ => 50
            };
        }

        if (normalizedPath.StartsWith("bin/", StringComparison.OrdinalIgnoreCase) || !normalizedPath.Contains('/'))
        {
            if (packageName.StartsWith("bins_win64", StringComparison.OrdinalIgnoreCase)) return 0;
            if (packageName.StartsWith("bins_win32", StringComparison.OrdinalIgnoreCase)) return 1;
            if (packageName.StartsWith("bins_misc", StringComparison.OrdinalIgnoreCase)) return 2;
            if (packageName.StartsWith("bins_hardware", StringComparison.OrdinalIgnoreCase)) return 3;
            if (packageName.StartsWith("bins_webhelpers", StringComparison.OrdinalIgnoreCase)) return 4;
            if (packageName.StartsWith("bins_codecs", StringComparison.OrdinalIgnoreCase)) return 5;
            if (packageName.StartsWith("steam_win", StringComparison.OrdinalIgnoreCase)) return 6;
        }

        return 50;
    }

    private static byte[] ReadBoundedBytes(Stream stream, int maximumBytes)
    {
        if (stream.Length > maximumBytes)
        {
            throw new InvalidDataException($"文件大小超过上限 {maximumBytes} 字节。");
        }

        using MemoryStream ms = new(stream.Length is > 0 and <= 1024 * 1024 ? (int)stream.Length : 16 * 1024);
        byte[] buffer = new byte[16 * 1024];
        long total = 0;
        while (true)
        {
            int toRead = (int)Math.Min(buffer.Length, maximumBytes - total + 1);
            int read = stream.Read(buffer, 0, toRead);
            if (read == 0)
            {
                break;
            }

            total += read;
            if (total > maximumBytes)
            {
                throw new InvalidDataException($"读取字节超过上限 {maximumBytes} 字节。");
            }

            ms.Write(buffer, 0, read);
        }

        return ms.ToArray();
    }

    private static string DecodeStrictUtf8(ReadOnlySpan<byte> bytes)
    {
        if (bytes.Length >= 3 && bytes[0] == 0xEF && bytes[1] == 0xBB && bytes[2] == 0xBF)
        {
            bytes = bytes[3..];
        }

        return StrictUtf8.GetString(bytes);
    }

    private sealed class VdfObject
    {
        public List<VdfNode> Children { get; } = [];
    }

    private sealed record VdfNode(string Key, string? Value, VdfObject? Object);

    private static bool TryParseVdfDocument(string text, [NotNullWhen(true)] out VdfObject? root)
    {
        root = null;
        int cursor = 0;
        VdfObject parsed = new();
        if (!TryParseVdfBody(text, ref cursor, parsed, depth: 0, expectClosingBrace: false))
        {
            return false;
        }

        root = parsed;
        return true;
    }

    private static bool TryParseVdfBody(string text, ref int cursor, VdfObject target, int depth, bool expectClosingBrace)
    {
        if (depth > MaximumVdfDepth)
        {
            return false;
        }

        while (true)
        {
            if (!TryReadVdfToken(text, ref cursor, out VdfTokenKind kind, out string token))
            {
                return false;
            }

            if (kind == VdfTokenKind.EndOfFile)
            {
                return !expectClosingBrace;
            }

            if (kind == VdfTokenKind.CloseBrace)
            {
                return expectClosingBrace;
            }

            if (kind != VdfTokenKind.String)
            {
                return false;
            }

            string key = token;
            if (!TryReadVdfToken(text, ref cursor, out VdfTokenKind nextKind, out string nextToken))
            {
                return false;
            }

            if (nextKind == VdfTokenKind.String)
            {
                target.Children.Add(new VdfNode(key, nextToken, null));
            }
            else if (nextKind == VdfTokenKind.OpenBrace)
            {
                VdfObject child = new();
                if (!TryParseVdfBody(text, ref cursor, child, depth + 1, expectClosingBrace: true))
                {
                    return false;
                }

                target.Children.Add(new VdfNode(key, null, child));
            }
            else
            {
                return false;
            }
        }
    }

    private enum VdfTokenKind
    {
        EndOfFile,
        OpenBrace,
        CloseBrace,
        String
    }

    private static bool TryReadVdfToken(string text, ref int cursor, out VdfTokenKind kind, out string value)
    {
        kind = VdfTokenKind.EndOfFile;
        value = string.Empty;

        while (cursor < text.Length)
        {
            char ch = text[cursor];
            if (char.IsWhiteSpace(ch))
            {
                cursor++;
                continue;
            }

            if (ch == '/' && cursor + 1 < text.Length && text[cursor + 1] == '/')
            {
                cursor += 2;
                while (cursor < text.Length && text[cursor] is not ('\r' or '\n'))
                {
                    cursor++;
                }

                continue;
            }

            break;
        }

        if (cursor >= text.Length)
        {
            return true;
        }

        char first = text[cursor];
        if (first == '{')
        {
            cursor++;
            kind = VdfTokenKind.OpenBrace;
            return true;
        }

        if (first == '}')
        {
            cursor++;
            kind = VdfTokenKind.CloseBrace;
            return true;
        }

        if (first == '"')
        {
            cursor++;
            StringBuilder sb = new();
            while (cursor < text.Length)
            {
                char current = text[cursor++];
                if (current == '"')
                {
                    kind = VdfTokenKind.String;
                    value = sb.ToString();
                    return true;
                }

                if (current == '\\')
                {
                    if (cursor >= text.Length)
                    {
                        return false;
                    }

                    char escaped = text[cursor++];
                    switch (escaped)
                    {
                        case 'n':
                            sb.Append('\n');
                            break;
                        case 'r':
                            sb.Append('\r');
                            break;
                        case 't':
                            sb.Append('\t');
                            break;
                        case '\\':
                            sb.Append('\\');
                            break;
                        case '"':
                            sb.Append('"');
                            break;
                        default:
                            // 未知转义保留反斜杠原文（如未转义的 Windows 路径片段 sub\evil），防止消去斜杠绕过文件名校验。
                            sb.Append('\\');
                            sb.Append(escaped);
                            break;
                    }
                    continue;
                }

                sb.Append(current);
            }

            return false;
        }

        int start = cursor;
        while (cursor < text.Length && !char.IsWhiteSpace(text[cursor]) && text[cursor] is not ('{' or '}' or '"'))
        {
            cursor++;
        }

        kind = VdfTokenKind.String;
        value = text[start..cursor];
        return value.Length > 0;
    }
}
