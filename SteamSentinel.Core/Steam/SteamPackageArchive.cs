using System.Buffers;
using System.Buffers.Binary;
using System.IO.Compression;
using System.Net;
using System.Net.Http;
using System.Security.Cryptography;
using SharpCompress.Compressors.LZMA;
using SteamSentinel.Core.Inspection;
using SteamSentinel.Core.Scanning;
using SteamSentinel.Core.Utilities;

namespace SteamSentinel.Core.Steam;

/// <summary>从 Steam 官方分包中安全提取单个文件的结构化结果。</summary>
/// <param name="Content">提取出的官方文件原始字节。</param>
/// <param name="Sha256">提取结果的 64 位十六进制 SHA-256 摘要。</param>
/// <param name="SourcePackage">命中的官方分包条目。</param>
/// <param name="RelativePath">归一化后的相对路径（使用 / 分隔）。</param>
/// <param name="Downloaded">提取过程中是否通过官方 CDN 补拉下载了分包。</param>
public sealed record SteamPackageExtractResult(
    byte[] Content,
    string Sha256,
    SteamPackageEntry SourcePackage,
    string RelativePath,
    bool Downloaded);

/// <summary>
/// Steam 官方分包（.zip.vz 与 .zip）的校验、离线解压、受控 CDN 补拉与按路径提取引擎。
/// </summary>
public static class SteamPackageArchive
{
    /// <summary>.zip.vz 解压后内层 ZIP 最大允许大小（256 MiB）。</summary>
    public const int MaximumUncompressedZipBytes = 256 * 1024 * 1024;

    /// <summary>单个提取出的官方文件最大允许大小（64 MiB）。</summary>
    public const int MaximumExtractedFileBytes = 64 * 1024 * 1024;

    /// <summary>CDN 按需单分包流式下载上限（64 MiB）。</summary>
    public const int MaximumDownloadBytes = 64 * 1024 * 1024;

    /// <summary>本地已存在分包文件的最大允许读取大小（256 MiB）。</summary>
    public const int MaximumLocalPackageBytes = 256 * 1024 * 1024;

    /// <summary>LZMA 属性允许的最大字典大小上限（128 MiB，正版分包当前为 32 MiB）。</summary>
    public const int MaximumLzmaDictionaryBytes = 128 * 1024 * 1024;

    private const int MinimumVzLength = 22;
    private const uint Crc32Polynomial = 0xEDB88320u;

    private static readonly string[] OfficialCdnBases =
    [
        "https://steamcdn-a.akamaihd.net/client/",
        "https://cdn.akamai.steamstatic.com/client/"
    ];

    private static readonly string[] AllowedCdnHosts =
    [
        "steamcdn-a.akamaihd.net",
        "cdn.akamai.steamstatic.com"
    ];

    private static readonly uint[] Crc32Table = BuildCrc32Table();

    /// <summary>纯 C# 计算 IEEE 802.3 CRC32（多项式 0xEDB88320）。</summary>
    public static uint ComputeCrc32(ReadOnlySpan<byte> data) =>
        UpdateCrc32(0xFFFFFFFFu, data) ^ 0xFFFFFFFFu;

    /// <summary>流式增量更新 IEEE 802.3 CRC32 寄存器状态。</summary>
    internal static uint UpdateCrc32(uint currentCrc, ReadOnlySpan<byte> data)
    {
        uint crc = currentCrc;
        uint[] table = Crc32Table;
        foreach (byte b in data)
        {
            crc = (crc >> 8) ^ table[(crc ^ b) & 0xFF];
        }

        return crc;
    }

    /// <summary>
    /// 按优先路由从本地 package 目录（或按需从官方 CDN 补拉）安全提取指定相对路径的官方文件。
    /// </summary>
    public static Task<SteamPackageExtractResult?> TryExtractOfficialFileAsync(
        SteamPackageCatalog catalog,
        string relativePath,
        CancellationToken token = default) =>
        TryExtractOfficialFileAsync(catalog, relativePath, allowDownload: true, token, handler: null);

    /// <summary>
    /// 按优先路由从本地 package 目录（可选启用官方 CDN 补拉）安全提取指定相对路径的官方文件。
    /// </summary>
    public static async Task<SteamPackageExtractResult?> TryExtractOfficialFileAsync(
        SteamPackageCatalog catalog,
        string relativePath,
        bool allowDownload,
        CancellationToken token = default,
        HttpMessageHandler? handler = null)
    {
        ArgumentNullException.ThrowIfNull(catalog);
        token.ThrowIfCancellationRequested();

        if (!SteamPackageCatalog.TryNormalizeRelativePath(relativePath, out string normalizedPath) ||
            !ContentDiscovery.IsLocalSafePath(catalog.PackageDirectory))
        {
            return null;
        }

        IReadOnlyList<SteamPackageEntry> candidates = catalog.OrderCandidatePackages(normalizedPath);
        if (candidates.Count == 0)
        {
            return null;
        }

        HashSet<string> locallyVerifiedPackages = new(StringComparer.OrdinalIgnoreCase);

        // 第一阶段：优先复用本地已存在且校验通过的分包（零网络请求）。
        foreach (SteamPackageEntry candidate in candidates)
        {
            token.ThrowIfCancellationRequested();

            if (!string.IsNullOrEmpty(candidate.ZipVzFile) &&
                !string.IsNullOrEmpty(candidate.Sha256Vz) &&
                SteamPackageCatalog.IsSafePackageFileName(candidate.ZipVzFile))
            {
                string vzPath = Path.Combine(catalog.PackageDirectory, candidate.ZipVzFile);
                if (File.Exists(vzPath))
                {
                    try
                    {
                        SteamPackageExtractResult? extracted = await ExtractFromVzFileAsync(
                            vzPath, candidate, normalizedPath, candidate.Sha256Vz, downloaded: false, token).ConfigureAwait(false);
                        locallyVerifiedPackages.Add(candidate.Name);
                        if (extracted is not null)
                        {
                            return extracted;
                        }
                    }
                    catch (Exception ex) when (ex is IOException or InvalidDataException or UnauthorizedAccessException or System.ComponentModel.Win32Exception)
                    {
                        // 本地分包损坏或哈希失效时继续排查同分包 .zip 或在允许下载时按需补拉。
                    }
                }
            }

            if (SteamPackageCatalog.IsSafePackageFileName(candidate.ZipFile))
            {
                string zipPath = Path.Combine(catalog.PackageDirectory, candidate.ZipFile);
                if (File.Exists(zipPath))
                {
                    try
                    {
                        SteamPackageExtractResult? extracted = await ExtractFromZipFileAsync(
                            zipPath, candidate, normalizedPath, candidate.Sha256, downloaded: false, token).ConfigureAwait(false);
                        locallyVerifiedPackages.Add(candidate.Name);
                        if (extracted is not null)
                        {
                            return extracted;
                        }
                    }
                    catch (Exception ex) when (ex is IOException or InvalidDataException or UnauthorizedAccessException or System.ComponentModel.Win32Exception)
                    {
                        // 本地分包损坏时继续后续候选或补拉路径。
                    }
                }
            }
        }

        if (!allowDownload)
        {
            return null;
        }

        // 若已校验的 .installed 明确不包含该相对路径，则无需浪费流量从 CDN 补拉分包。
        if (catalog.HasVerifiedInstalledIndex && !catalog.IsKnownOfficialRelativePath(normalizedPath))
        {
            return null;
        }

        // 第二阶段：对本地缺失或损坏的候选分包按路由优先级执行受控 CDN 补拉并校验提取。
        foreach (SteamPackageEntry candidate in candidates)
        {
            token.ThrowIfCancellationRequested();
            if (locallyVerifiedPackages.Contains(candidate.Name))
            {
                continue;
            }

            string? downloadedPath = await TryDownloadPackageAsync(candidate, catalog.PackageDirectory, token, handler).ConfigureAwait(false);
            if (downloadedPath is null)
            {
                continue;
            }

            try
            {
                string downloadedName = Path.GetFileName(downloadedPath);
                if (!string.IsNullOrEmpty(candidate.ZipVzFile) &&
                    !string.IsNullOrEmpty(candidate.Sha256Vz) &&
                    downloadedName.Equals(candidate.ZipVzFile, StringComparison.OrdinalIgnoreCase))
                {
                    SteamPackageExtractResult? extracted = await ExtractFromVzFileAsync(
                        downloadedPath, candidate, normalizedPath, candidate.Sha256Vz, downloaded: true, token).ConfigureAwait(false);
                    if (extracted is not null)
                    {
                        return extracted;
                    }
                }
                else
                {
                    SteamPackageExtractResult? extracted = await ExtractFromZipFileAsync(
                        downloadedPath, candidate, normalizedPath, candidate.Sha256, downloaded: true, token).ConfigureAwait(false);
                    if (extracted is not null)
                    {
                        return extracted;
                    }
                }
            }
            catch (Exception ex) when (ex is IOException or InvalidDataException or UnauthorizedAccessException or System.ComponentModel.Win32Exception)
            {
                // 提取异常时继续排查其余候选分包。
            }
        }

        return null;
    }

    /// <summary>
    /// 校验 .zip.vz 文件整包 SHA-256、VZ 头尾标记、LZMA 属性与解压 CRC32/长度，并从中提取目标文件。
    /// </summary>
    public static async Task<SteamPackageExtractResult?> ExtractFromVzFileAsync(
        string vzFilePath,
        SteamPackageEntry sourcePackage,
        string relativePath,
        string expectedSha256Vz,
        bool downloaded = false,
        CancellationToken token = default)
    {
        ArgumentNullException.ThrowIfNull(sourcePackage);
        token.ThrowIfCancellationRequested();

        if (!SteamPackageCatalog.TryNormalizeRelativePath(relativePath, out string normalizedPath))
        {
            throw new InvalidDataException("拒绝不安全的目标相对路径。");
        }

        if (!Validation.IsHexSha256(expectedSha256Vz))
        {
            throw new InvalidDataException("无效的 .zip.vz 期望 SHA-256 摘要。");
        }

        if (!ContentDiscovery.IsLocalSafePath(vzFilePath))
        {
            throw new UnauthorizedAccessException("拒绝访问不安全的本地分包路径。");
        }

        await using FileStream fileStream = RelatedArtifactReader.Open(vzFilePath);
        if (fileStream.Length < MinimumVzLength || fileStream.Length > MaximumLocalPackageBytes)
        {
            throw new InvalidDataException($".zip.vz 文件长度越界（{fileStream.Length} 字节）。");
        }

        string actualSha256 = await Hashing.Sha256StreamAsync(fileStream, token, maximumBytes: MaximumLocalPackageBytes).ConfigureAwait(false);
        if (!actualSha256.Equals(expectedSha256Vz, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidDataException(".zip.vz 整文件 SHA-256 校验失败。");
        }

        fileStream.Seek(0, SeekOrigin.Begin);
        byte[] header = new byte[12];
        await fileStream.ReadExactlyAsync(header, token).ConfigureAwait(false);
        if (header[0] != (byte)'V' || header[1] != (byte)'Z')
        {
            throw new InvalidDataException(".zip.vz 头部魔数不是 VZ。");
        }

        byte[] lzmaProperties = header[7..12];
        uint dictionarySize = BinaryPrimitives.ReadUInt32LittleEndian(lzmaProperties.AsSpan(1, 4));
        if (lzmaProperties[0] >= 225 || dictionarySize > MaximumLzmaDictionaryBytes)
        {
            throw new InvalidDataException(".zip.vz LZMA 属性或字典大小超出安全限制。");
        }

        fileStream.Seek(-10, SeekOrigin.End);
        byte[] trailer = new byte[10];
        await fileStream.ReadExactlyAsync(trailer, token).ConfigureAwait(false);
        if (trailer[8] != (byte)'z' || trailer[9] != (byte)'v')
        {
            throw new InvalidDataException(".zip.vz 尾部魔数不是 zv。");
        }

        uint expectedZipCrc32 = BinaryPrimitives.ReadUInt32LittleEndian(trailer.AsSpan(0, 4));
        uint expectedUncompressedSize = BinaryPrimitives.ReadUInt32LittleEndian(trailer.AsSpan(4, 4));
        if (expectedUncompressedSize < 22 || expectedUncompressedSize > MaximumUncompressedZipBytes)
        {
            throw new InvalidDataException($".zip.vz 声明的解压大小超出限制（{expectedUncompressedSize} 字节）。");
        }

        long compressedLength = fileStream.Length - MinimumVzLength;
        using ArchiveVolumeSliceStream compressedSlice = new(fileStream, 12, compressedLength);
        using LzmaStream lzmaStream = LzmaStream.Create(
            lzmaProperties,
            compressedSlice,
            compressedLength,
            expectedUncompressedSize,
            leaveOpen: true);

        using MemoryStream zipStream = new();
        byte[] buffer = ArrayPool<byte>.Shared.Rent(64 * 1024);
        uint runningCrc = 0xFFFFFFFFu;
        long totalDecompressed = 0;
        try
        {
            while (true)
            {
                token.ThrowIfCancellationRequested();
                int requested = (int)Math.Min(buffer.Length, expectedUncompressedSize - totalDecompressed + 1);
                int read = await lzmaStream.ReadAsync(buffer.AsMemory(0, requested), token).ConfigureAwait(false);
                if (read == 0)
                {
                    break;
                }

                totalDecompressed += read;
                if (totalDecompressed > expectedUncompressedSize || totalDecompressed > MaximumUncompressedZipBytes)
                {
                    throw new InvalidDataException(".zip.vz 实际解压输出超过声明上限。");
                }

                runningCrc = UpdateCrc32(runningCrc, buffer.AsSpan(0, read));
                zipStream.Write(buffer, 0, read);
            }
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer, clearArray: true);
        }

        if (totalDecompressed != expectedUncompressedSize)
        {
            throw new InvalidDataException($".zip.vz 解压长度不匹配：期望 {expectedUncompressedSize}，实际 {totalDecompressed}。");
        }

        uint actualZipCrc32 = runningCrc ^ 0xFFFFFFFFu;
        if (actualZipCrc32 != expectedZipCrc32)
        {
            throw new InvalidDataException($".zip.vz 内层 ZIP CRC32 校验失败：期望 0x{expectedZipCrc32:X8}，实际 0x{actualZipCrc32:X8}。");
        }

        zipStream.Position = 0;
        return await ExtractEntryFromZipStreamAsync(zipStream, sourcePackage, normalizedPath, downloaded, token).ConfigureAwait(false);
    }

    /// <summary>校验普通 .zip 分包 SHA-256 并按归一化相对路径提取目标文件。</summary>
    public static async Task<SteamPackageExtractResult?> ExtractFromZipFileAsync(
        string zipFilePath,
        SteamPackageEntry sourcePackage,
        string relativePath,
        string expectedSha256,
        bool downloaded = false,
        CancellationToken token = default)
    {
        ArgumentNullException.ThrowIfNull(sourcePackage);
        token.ThrowIfCancellationRequested();

        if (!SteamPackageCatalog.TryNormalizeRelativePath(relativePath, out string normalizedPath))
        {
            throw new InvalidDataException("拒绝不安全的目标相对路径。");
        }

        if (!Validation.IsHexSha256(expectedSha256))
        {
            throw new InvalidDataException("无效的 .zip 期望 SHA-256 摘要。");
        }

        if (!ContentDiscovery.IsLocalSafePath(zipFilePath))
        {
            throw new UnauthorizedAccessException("拒绝访问不安全的本地分包路径。");
        }

        await using FileStream fileStream = RelatedArtifactReader.Open(zipFilePath);
        if (fileStream.Length < 22 || fileStream.Length > MaximumLocalPackageBytes)
        {
            throw new InvalidDataException($".zip 文件长度越界（{fileStream.Length} 字节）。");
        }

        string actualSha256 = await Hashing.Sha256StreamAsync(fileStream, token, maximumBytes: MaximumLocalPackageBytes).ConfigureAwait(false);
        if (!actualSha256.Equals(expectedSha256, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidDataException(".zip 整文件 SHA-256 校验失败。");
        }

        fileStream.Seek(0, SeekOrigin.Begin);
        return await ExtractEntryFromZipStreamAsync(fileStream, sourcePackage, normalizedPath, downloaded, token).ConfigureAwait(false);
    }

    /// <summary>
    /// 按需从 Steam 官方白名单 CDN 补拉单个分包（优先 .zip.vz，404 时可回退到未超限的 .zip），
    /// 禁止自动重定向，流式限制 64 MiB，核验 SHA-256 后原子落盘。
    /// </summary>
    public static async Task<string?> TryDownloadPackageAsync(
        SteamPackageEntry entry,
        string targetPackageDir,
        CancellationToken token,
        HttpMessageHandler? handler = null)
    {
        ArgumentNullException.ThrowIfNull(entry);
        token.ThrowIfCancellationRequested();

        if (string.IsNullOrWhiteSpace(targetPackageDir) ||
            !ContentDiscovery.IsLocalSafePath(targetPackageDir) ||
            !Validation.IsSafeExactTarget(targetPackageDir))
        {
            return null;
        }

        string fullTargetDir;
        try
        {
            fullTargetDir = Path.GetFullPath(targetPackageDir);
            Directory.CreateDirectory(fullTargetDir);
            if (!ContentDiscovery.IsLocalSafePath(fullTargetDir))
            {
                return null;
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException)
        {
            return null;
        }

        List<(string FileName, string ExpectedSha256)> artifacts = [];
        if (!string.IsNullOrEmpty(entry.ZipVzFile) && !string.IsNullOrEmpty(entry.Sha256Vz))
        {
            if (!SteamPackageCatalog.IsSafePackageFileName(entry.ZipVzFile) || !Validation.IsHexSha256(entry.Sha256Vz))
            {
                return null;
            }

            artifacts.Add((entry.ZipVzFile, entry.Sha256Vz));
        }

        if (!SteamPackageCatalog.IsSafePackageFileName(entry.ZipFile) || !Validation.IsHexSha256(entry.Sha256))
        {
            return null;
        }

        if (artifacts.Count == 0 || entry.ZipSize <= MaximumDownloadBytes)
        {
            artifacts.Add((entry.ZipFile, entry.Sha256));
        }

        SocketsHttpHandler? ownedHandler = null;
        HttpClient client;
        if (handler is null)
        {
            ownedHandler = new SocketsHttpHandler
            {
                AllowAutoRedirect = false,
                ConnectTimeout = TimeSpan.FromSeconds(15),
                PooledConnectionLifetime = TimeSpan.FromMinutes(2)
            };
            client = new HttpClient(ownedHandler, disposeHandler: true);
        }
        else
        {
            client = new HttpClient(handler, disposeHandler: false);
        }

        client.Timeout = TimeSpan.FromSeconds(60);

        using (client)
        {
            foreach ((string fileName, string expectedSha256) in artifacts)
            {
                bool allowFallbackToZip = false;
                bool hadSecurityOrHashFailure = false;

                foreach (string cdnBase in OfficialCdnBases)
                {
                    token.ThrowIfCancellationRequested();
                    Uri requestUri = new(cdnBase + Uri.EscapeDataString(fileName), UriKind.Absolute);
                    if (!IsAllowedCdnUri(requestUri))
                    {
                        return null;
                    }

                    DownloadOutcome outcome = await TryDownloadArtifactOnceAsync(
                        client,
                        requestUri,
                        fullTargetDir,
                        fileName,
                        expectedSha256,
                        token).ConfigureAwait(false);

                    if (outcome.SavedPath is not null)
                    {
                        return outcome.SavedPath;
                    }

                    if (outcome.SecurityOrIntegrityRejected)
                    {
                        hadSecurityOrHashFailure = true;
                    }
                    else if (outcome.NotFound)
                    {
                        allowFallbackToZip = true;
                    }
                }

                // 仅当 .zip.vz 在主备 CDN 均返回 404（且未触发安全或哈希异常）时才回退尝试普通 .zip。
                if (hadSecurityOrHashFailure || !allowFallbackToZip)
                {
                    break;
                }
            }
        }

        return null;
    }

    private sealed record DownloadOutcome(string? SavedPath, bool NotFound, bool SecurityOrIntegrityRejected);

    private static async Task<DownloadOutcome> TryDownloadArtifactOnceAsync(
        HttpClient client,
        Uri requestUri,
        string fullTargetDir,
        string fileName,
        string expectedSha256,
        CancellationToken token)
    {
        string destinationPath = Path.Combine(fullTargetDir, fileName);
        if (!ContentDiscovery.IsWithin(destinationPath, fullTargetDir))
        {
            return new DownloadOutcome(null, NotFound: false, SecurityOrIntegrityRejected: true);
        }

        string tempPath = Path.Combine(fullTargetDir, $".{fileName}.{Guid.NewGuid():N}.tmp");
        try
        {
            using HttpRequestMessage request = new(HttpMethod.Get, requestUri);
            using HttpResponseMessage response = await client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, token).ConfigureAwait(false);

            // 严格禁止任何自动或跨站重定向，防纵深二次核验最终响应 URI（允许测试桩未回填 RequestMessage 时回退校验原始请求 URI）。
            Uri effectiveUri = response.RequestMessage?.RequestUri ?? requestUri;
            if (!IsAllowedCdnUri(effectiveUri))
            {
                return new DownloadOutcome(null, NotFound: false, SecurityOrIntegrityRejected: true);
            }

            if ((int)response.StatusCode is >= 300 and < 400)
            {
                return new DownloadOutcome(null, NotFound: false, SecurityOrIntegrityRejected: true);
            }

            if (response.StatusCode == HttpStatusCode.NotFound)
            {
                return new DownloadOutcome(null, NotFound: true, SecurityOrIntegrityRejected: false);
            }

            if (response.StatusCode != HttpStatusCode.OK)
            {
                return new DownloadOutcome(null, NotFound: false, SecurityOrIntegrityRejected: false);
            }

            long? declaredLength = response.Content.Headers.ContentLength;
            if (declaredLength is < 0 or > MaximumDownloadBytes)
            {
                return new DownloadOutcome(null, NotFound: false, SecurityOrIntegrityRejected: true);
            }

            await using Stream bodyStream = await response.Content.ReadAsStreamAsync(token).ConfigureAwait(false);
            using IncrementalHash sha256 = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
            byte[] buffer = ArrayPool<byte>.Shared.Rent(64 * 1024);
            long totalRead = 0;

            try
            {
                await using (FileStream tempStream = new(
                    tempPath,
                    FileMode.CreateNew,
                    FileAccess.Write,
                    FileShare.None,
                    bufferSize: 64 * 1024,
                    FileOptions.Asynchronous | FileOptions.WriteThrough))
                {
                    while (true)
                    {
                        token.ThrowIfCancellationRequested();
                        int requested = (int)Math.Min(buffer.Length, MaximumDownloadBytes - totalRead + 1);
                        int read = await bodyStream.ReadAsync(buffer.AsMemory(0, requested), token).ConfigureAwait(false);
                        if (read == 0)
                        {
                            break;
                        }

                        totalRead += read;
                        if (totalRead > MaximumDownloadBytes)
                        {
                            return new DownloadOutcome(null, NotFound: false, SecurityOrIntegrityRejected: true);
                        }

                        sha256.AppendData(buffer, 0, read);
                        await tempStream.WriteAsync(buffer.AsMemory(0, read), token).ConfigureAwait(false);
                    }

                    if (declaredLength.HasValue && totalRead != declaredLength.Value)
                    {
                        return new DownloadOutcome(null, NotFound: false, SecurityOrIntegrityRejected: true);
                    }

                    string actualSha256 = Convert.ToHexString(sha256.GetHashAndReset());
                    if (!actualSha256.Equals(expectedSha256, StringComparison.OrdinalIgnoreCase))
                    {
                        return new DownloadOutcome(null, NotFound: false, SecurityOrIntegrityRejected: true);
                    }

                    await tempStream.FlushAsync(token).ConfigureAwait(false);
                    tempStream.Flush(flushToDisk: true);
                }

                if (!ContentDiscovery.IsLocalSafePath(destinationPath) || !ContentDiscovery.IsWithin(destinationPath, fullTargetDir))
                {
                    return new DownloadOutcome(null, NotFound: false, SecurityOrIntegrityRejected: true);
                }

                File.Move(tempPath, destinationPath, overwrite: true);
                return new DownloadOutcome(destinationPath, NotFound: false, SecurityOrIntegrityRejected: false);
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(buffer, clearArray: true);
            }
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception ex) when (ex is HttpRequestException or IOException or UnauthorizedAccessException or TaskCanceledException)
        {
            return new DownloadOutcome(null, NotFound: false, SecurityOrIntegrityRejected: false);
        }
        finally
        {
            try
            {
                if (File.Exists(tempPath))
                {
                    File.Delete(tempPath);
                }
            }
            catch
            {
                // 忽略临时文件清理异常。
            }
        }
    }

    private static async Task<SteamPackageExtractResult?> ExtractEntryFromZipStreamAsync(
        Stream zipStream,
        SteamPackageEntry sourcePackage,
        string normalizedRelPath,
        bool downloaded,
        CancellationToken token)
    {
        using ZipArchive archive = new(zipStream, ZipArchiveMode.Read, leaveOpen: true);
        foreach (ZipArchiveEntry zipEntry in archive.Entries)
        {
            token.ThrowIfCancellationRequested();

            if (string.IsNullOrEmpty(zipEntry.Name) ||
                zipEntry.FullName.EndsWith('/') ||
                zipEntry.FullName.EndsWith('\\'))
            {
                continue;
            }

            if (!SteamPackageCatalog.TryNormalizeRelativePath(zipEntry.FullName, out string normalizedEntryName))
            {
                continue;
            }

            if (!normalizedEntryName.Equals(normalizedRelPath, StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            if (zipEntry.Length < 0 || zipEntry.Length > MaximumExtractedFileBytes)
            {
                throw new InvalidDataException($"ZIP 条目 {normalizedRelPath} 声明长度超出上限（{zipEntry.Length} 字节）。");
            }

            await using Stream entryStream = zipEntry.Open();
            using MemoryStream output = new(zipEntry.Length <= 4 * 1024 * 1024 ? (int)zipEntry.Length : 64 * 1024);
            byte[] buffer = ArrayPool<byte>.Shared.Rent(64 * 1024);
            long totalRead = 0;

            try
            {
                while (true)
                {
                    token.ThrowIfCancellationRequested();
                    int requested = (int)Math.Min(buffer.Length, MaximumExtractedFileBytes - totalRead + 1);
                    int read = await entryStream.ReadAsync(buffer.AsMemory(0, requested), token).ConfigureAwait(false);
                    if (read == 0)
                    {
                        break;
                    }

                    totalRead += read;
                    if (totalRead > MaximumExtractedFileBytes)
                    {
                        throw new InvalidDataException($"ZIP 条目 {normalizedRelPath} 实际解压字节超出 {MaximumExtractedFileBytes} 上限。");
                    }

                    output.Write(buffer, 0, read);
                }
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(buffer, clearArray: true);
            }

            byte[] content = output.ToArray();
            string sha256 = Hashing.Sha256Bytes(content);
            return new SteamPackageExtractResult(content, sha256, sourcePackage, normalizedEntryName, downloaded);
        }

        return null;
    }

    private static bool IsAllowedCdnUri(Uri? uri) =>
        uri is { IsAbsoluteUri: true, UserInfo.Length: 0 } &&
        uri.Scheme.Equals(Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase) &&
        uri.IsDefaultPort &&
        AllowedCdnHosts.Any(host => uri.Host.Equals(host, StringComparison.OrdinalIgnoreCase)) &&
        uri.AbsolutePath.StartsWith("/client/", StringComparison.Ordinal);

    private static uint[] BuildCrc32Table()
    {
        uint[] table = new uint[256];
        for (uint i = 0; i < 256; i++)
        {
            uint crc = i;
            for (int bit = 0; bit < 8; bit++)
            {
                crc = (crc & 1) != 0 ? (crc >> 1) ^ Crc32Polynomial : crc >> 1;
            }

            table[i] = crc;
        }

        return table;
    }
}
