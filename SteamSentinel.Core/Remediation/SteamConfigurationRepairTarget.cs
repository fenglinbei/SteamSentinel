using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.Win32;
using Microsoft.Win32.SafeHandles;
using SteamSentinel.Core.Inspection;
using SteamSentinel.Core.Models;
using SteamSentinel.Core.Reporting;
using SteamSentinel.Core.Scanning;
using SteamSentinel.Core.Steam;
using SteamSentinel.Core.Utilities;

namespace SteamSentinel.Core.Remediation;

public sealed record SteamConfigurationSnapshot(
    string Kind,
    string? SteamExecutable = null,
    string? OriginalValue = null,
    string? RepairedValue = null,
    int? RegistryValueKind = null,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? PackageName = null,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? PackageRelativePath = null,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? PackageArchiveFile = null,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? PackageArchiveSha256 = null,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)] bool PackageIsVz = false);

public static class SteamConfigurationRepairTarget
{
    private static readonly Encoding StrictUtf8 = new UTF8Encoding(encoderShouldEmitUTF8Identifier: false, throwOnInvalidBytes: true);

    public static SteamConfigurationSnapshot ReadSnapshot(string? json)
    {
        if (json is null || json.Length > 140_000) throw Denied();
        try { return JsonSerializer.Deserialize<SteamConfigurationSnapshot>(json) ?? throw Denied(); }
        catch (JsonException) { throw Denied(); }
    }

    public static bool IsFileTarget(string path, string? kind, SteamLayout layout)
    {
        if (!ContentDiscovery.IsLocalSafePath(path)) return false;
        string full = Path.GetFullPath(path);
        return kind switch
        {
            SteamConfigurationRepair.Cfg => layout.SteamRoots.Any(root => full.Equals(Path.GetFullPath(Path.Combine(root, "steam.cfg")), StringComparison.OrdinalIgnoreCase)),
            SteamConfigurationRepair.Marker => layout.SteamRoots.Any(root => full.Equals(Path.GetFullPath(Path.Combine(root, ".cef-enable-remote-debugging")), StringComparison.OrdinalIgnoreCase)),
            SteamConfigurationRepair.Shortcut => Path.GetExtension(full).Equals(".lnk", StringComparison.OrdinalIgnoreCase),
            SteamConfigurationRepair.UiFile => IsUiFileTarget(full, layout),
            SteamConfigurationRepair.PackageRestore => TryResolvePackageRestoreRoot(full, layout, out _, out _),
            _ => false
        };
    }

    /// <summary>校验目标路径是否位于已知 Steam 根目录的受支持官方还原范围内并解析归一化相对路径。</summary>
    public static bool TryResolvePackageRestoreRoot(
        string path,
        SteamLayout layout,
        out string steamRoot,
        out string normalizedRelativePath)
    {
        steamRoot = string.Empty;
        normalizedRelativePath = string.Empty;
        if (!ContentDiscovery.IsLocalSafePath(path)) return false;

        string full = Path.GetFullPath(path);
        string? matchedRoot = null;
        string? matchedRelative = null;

        foreach (string candidateRoot in layout.SteamRoots.Where(ContentDiscovery.IsLocalSafePath))
        {
            string fullRoot = Path.TrimEndingDirectorySeparator(Path.GetFullPath(candidateRoot));
            string prefix = fullRoot + Path.DirectorySeparatorChar;
            if (!full.StartsWith(prefix, StringComparison.OrdinalIgnoreCase)) continue;

            string relative = full[prefix.Length..];
            if (!SteamPackageCatalog.TryNormalizeRelativePath(relative, out string normalized)) continue;

            bool allowed = normalized.StartsWith("steamui/", StringComparison.OrdinalIgnoreCase) ||
                           normalized.StartsWith("clientui/", StringComparison.OrdinalIgnoreCase) ||
                           normalized.Equals("resource/webkit.css", StringComparison.OrdinalIgnoreCase) ||
                           normalized.Equals("steam.exe", StringComparison.OrdinalIgnoreCase);
            if (!allowed) continue;

            if (matchedRoot is null || fullRoot.Length > matchedRoot.Length)
            {
                matchedRoot = fullRoot;
                matchedRelative = normalized;
            }
        }

        if (matchedRoot is null || matchedRelative is null) return false;
        steamRoot = matchedRoot;
        normalizedRelativePath = matchedRelative;
        return true;
    }

    private static bool IsUiFileTarget(string full, SteamLayout layout)
    {
        if (Path.GetExtension(full).ToLowerInvariant() is not (".js" or ".html" or ".htm" or ".css" or ".mjs" or ".cjs"))
            return false;
        return layout.SteamRoots.Any(root =>
            ContentDiscovery.IsWithin(full, Path.Combine(root, "steamui")) ||
            ContentDiscovery.IsWithin(full, Path.Combine(root, "clientui")));
    }

    public static bool IsRunTarget(string? hive, string? view, string? key, string? name) =>
        hive is "HKCU" or "HKLM" && view is "Default" or "Registry32" or "Registry64" &&
        key is @"Software\Microsoft\Windows\CurrentVersion\Run" or @"Software\Microsoft\Windows\CurrentVersion\RunOnce" &&
        name is { Length: > 0 and <= 16383 } && !name.Contains('\0');

    public static Task<RemediationAction> CaptureAsync(Finding finding, SteamLayout layout, CancellationToken token = default) =>
        CaptureAsync(finding, layout, allowPackageDownload: true, packageHttpMessageHandler: null, verifyExecutableSignature: null, token);

    /// <summary>捕获修复目标的当前身份与预期修复后摘要，支持官方分包按需 CDN 补拉开关与离线测试注入。</summary>
    public static Task<RemediationAction> CaptureAsync(
        Finding finding,
        SteamLayout layout,
        bool allowPackageDownload,
        HttpMessageHandler? packageHttpMessageHandler = null,
        CancellationToken token = default) =>
        CaptureAsync(finding, layout, allowPackageDownload, packageHttpMessageHandler, verifyExecutableSignature: null, token);

    internal static async Task<RemediationAction> CaptureAsync(
        Finding finding,
        SteamLayout layout,
        bool allowPackageDownload,
        HttpMessageHandler? packageHttpMessageHandler,
        Func<string, SafeFileHandle?, SignatureResult>? verifyExecutableSignature,
        CancellationToken token = default)
    {
        if (finding.ConfigurationKind == SteamConfigurationRepair.Run)
        {
            if (!IsRunTarget(finding.RegistryHive, finding.RegistryView, finding.RegistryKey, finding.RegistryValueName)) throw Denied();
            SteamConfigurationSnapshot observed = ReadSnapshot(finding.ConfigurationSnapshot);
            using RegistryKey baseKey = RegistryKey.OpenBaseKey(finding.RegistryHive == "HKCU" ? RegistryHive.CurrentUser : RegistryHive.LocalMachine,
                Enum.Parse<RegistryView>(finding.RegistryView!));
            using RegistryKey? key = baseKey.OpenSubKey(finding.RegistryKey!);
            if (key is null || key.GetValue(finding.RegistryValueName!, null, RegistryValueOptions.DoNotExpandEnvironmentNames) is not string value ||
                value != observed.OriginalValue || (int)key.GetValueKind(finding.RegistryValueName!) != observed.RegistryValueKind ||
                !SteamConfigurationRepair.TryRepairCommand(value, layout, out string repairedValue, out string executable)) throw Denied("SteamConfig.Changed");
            if (observed.Kind != SteamConfigurationRepair.Run || observed.SteamExecutable != executable || observed.RepairedValue != repairedValue) throw Denied();
            return new()
            {
                Type = RemediationActionType.RepairSteamConfiguration,
                Target = finding.Target,
                DisplayName = finding.Title,
                ConfigurationKind = SteamConfigurationRepair.Run,
                ConfigurationSnapshot = JsonSerializer.Serialize(observed),
                RegistryHive = finding.RegistryHive,
                RegistryView = finding.RegistryView,
                RegistryKey = finding.RegistryKey,
                RegistryValueName = finding.RegistryValueName,
                ExpectedValueData = value,
                RelatedFilePath = executable,
                RelatedFileSha256 = await CaptureExecutableHashAsync(executable, token),
                IsKnownMalware = false,
                ConfidenceScore = finding.Score
            };
        }
        if (!IsFileTarget(finding.Target, finding.ConfigurationKind, layout) || !FileScopeSafety.EvaluatePath(finding.Target).Allowed ||
            !Validation.IsHexSha256(finding.Sha256)) throw Denied();

        string fullTarget = Path.GetFullPath(finding.Target);
        string hash;
        string fileIdentity;
        string parentIdentity;
        if (finding.ConfigurationKind == SteamConfigurationRepair.PackageRestore)
        {
            await using FileStream input = RelatedArtifactReader.Open(fullTarget);
            if (input.Length < 0 || input.Length > SteamConfigurationRepair.MaximumPackageRestoreBytes) throw Denied();
            hash = await Hashing.Sha256StreamAsync(input, token, maximumBytes: SteamConfigurationRepair.MaximumPackageRestoreBytes);
            if (!hash.Equals(finding.Sha256, StringComparison.OrdinalIgnoreCase)) throw Denied("SteamConfig.Changed");
            RelatedArtifactReader.ValidatePath(input.SafeFileHandle, fullTarget);
            fileIdentity = FileScopeSafety.ReadIdentity(input.SafeFileHandle);
            parentIdentity = FileScopeSafety.CaptureIdentity(Path.GetDirectoryName(fullTarget)!, true);

            if (!TryResolvePackageRestoreRoot(fullTarget, layout, out string steamRoot, out string normalizedRelative) ||
                !SteamPackageCatalog.TryLoadForSteamRoot(steamRoot, out SteamPackageCatalog? catalog) ||
                (catalog.HasVerifiedInstalledIndex && !catalog.IsKnownOfficialRelativePath(normalizedRelative)))
                throw Denied();

            SteamPackageExtractResult? extracted = await SteamPackageArchive.TryExtractOfficialFileAsync(
                catalog,
                normalizedRelative,
                allowPackageDownload,
                token,
                packageHttpMessageHandler).ConfigureAwait(false);
            if (extracted is null)
                throw Denied("SteamConfig.PackageUnavailable");
            if (extracted.Sha256.Equals(hash, StringComparison.OrdinalIgnoreCase))
                throw Denied();

            await VerifyExtractedOfficialContentAsync(
                normalizedRelative,
                extracted.Content,
                AppPaths.TemporaryRoot,
                verifyExecutableSignature,
                token).ConfigureAwait(false);

            (string archiveFile, string archiveSha256, bool isVz) = await ResolveVerifiedSourceArchiveAsync(
                catalog.PackageDirectory, extracted.SourcePackage, token).ConfigureAwait(false);

            SteamConfigurationSnapshot snapshot = new(
                SteamConfigurationRepair.PackageRestore,
                PackageName: extracted.SourcePackage.Name,
                PackageRelativePath: extracted.RelativePath,
                PackageArchiveFile: archiveFile,
                PackageArchiveSha256: archiveSha256,
                PackageIsVz: isVz);

            return new()
            {
                Type = RemediationActionType.RepairSteamConfiguration,
                Target = fullTarget,
                DisplayName = finding.Title,
                ConfigurationKind = SteamConfigurationRepair.PackageRestore,
                ConfigurationSnapshot = JsonSerializer.Serialize(snapshot),
                ExpectedSha256 = hash,
                RepairedSha256 = extracted.Sha256,
                ExpectedFileIdentity = fileIdentity,
                ExpectedParentIdentity = parentIdentity,
                IsKnownMalware = false,
                ConfidenceScore = finding.Score
            };
        }

        {
            await using FileStream input = RelatedArtifactReader.Open(finding.Target);
            byte[] bytes = await ReadBytesAsync(input, token, SteamConfigurationRepair.MaximumBytesFor(finding.ConfigurationKind));
            hash = SteamConfigurationRepair.Hash(bytes);
            if (!hash.Equals(finding.Sha256, StringComparison.OrdinalIgnoreCase)) throw Denied("SteamConfig.Changed");
            string? repairedHash = null, target = null;
            if (!SteamConfigurationRepair.IsRemovedOnRepair(finding.ConfigurationKind))
            {
                if (!TryRepair(finding.ConfigurationKind!, bytes, layout, out byte[] repaired, out target)) throw Denied();
                repairedHash = SteamConfigurationRepair.Hash(repaired);
            }
            RelatedArtifactReader.ValidatePath(input.SafeFileHandle, fullTarget);
            return new()
            {
                Type = RemediationActionType.RepairSteamConfiguration,
                Target = fullTarget,
                DisplayName = finding.Title,
                ConfigurationKind = finding.ConfigurationKind,
                ConfigurationSnapshot = JsonSerializer.Serialize(new SteamConfigurationSnapshot(finding.ConfigurationKind!, target)),
                ExpectedSha256 = hash,
                RepairedSha256 = repairedHash,
                ExpectedFileIdentity = FileScopeSafety.ReadIdentity(input.SafeFileHandle),
                ExpectedParentIdentity = FileScopeSafety.CaptureIdentity(Path.GetDirectoryName(finding.Target)!, true),
                RelatedFilePath = target,
                RelatedFileSha256 = target is null ? null : await CaptureExecutableHashAsync(target, token),
                IsKnownMalware = false,
                ConfidenceScore = finding.Score
            };
        }
    }

    /// <summary>核验从官方分包中提取出的字节是否满足 UI 零异常门禁或 Valve PE 离线签名要求。</summary>
    public static Task VerifyExtractedOfficialContentAsync(
        string normalizedRelativePath,
        byte[] content,
        string temporaryVerificationRoot,
        CancellationToken token = default) =>
        VerifyExtractedOfficialContentAsync(normalizedRelativePath, content, temporaryVerificationRoot, verifyExecutableSignature: null, token);

    /// <summary>核验从官方分包中提取出的字节是否满足 UI 零异常门禁或 Valve PE 离线签名要求（支持签名测试注入）。</summary>
    public static async Task VerifyExtractedOfficialContentAsync(
        string normalizedRelativePath,
        byte[] content,
        string temporaryVerificationRoot,
        Func<string, SafeFileHandle?, SignatureResult>? verifyExecutableSignature,
        CancellationToken token)
    {
        if (content.Length is <= 0 or > SteamConfigurationRepair.MaximumPackageRestoreBytes)
            throw Denied();

        string extension = Path.GetExtension(normalizedRelativePath).ToLowerInvariant();
        if (extension is ".js" or ".mjs" or ".cjs" or ".html" or ".htm" or ".css")
        {
            string text;
            try { text = StrictUtf8.GetString(content); }
            catch (DecoderFallbackException) { throw Denied(); }

            if (extension is ".js" or ".mjs" or ".cjs" or ".html" or ".htm")
            {
                if (SteamSecurityScanner.AnalyzeSteamUiMessages(text).Count > 0 ||
                    SteamUiLoopbackInspector.Find(text) is not null ||
                    SteamUiLoopbackInspector.FindExternal(text) is not null)
                    throw Denied();
            }

            if (extension == ".css" && SteamSecurityScanner.HasCssSuppression(text))
                throw Denied();

            return;
        }

        if (extension is ".exe" or ".dll" or ".sys" or ".drv" or ".ocx" or ".cpl")
        {
            if (content.Length < 64) throw Denied();
            if (verifyExecutableSignature is null && (content[0] != (byte)'M' || content[1] != (byte)'Z'))
                throw Denied();

            if (!ContentDiscovery.IsLocalSafePath(temporaryVerificationRoot))
                throw Denied();

            string verifyDir = Path.Combine(Path.GetFullPath(temporaryVerificationRoot), "pkg-verify-" + Guid.NewGuid().ToString("N"));
            string tempFile = Path.Combine(verifyDir, Path.GetFileName(normalizedRelativePath));
            Directory.CreateDirectory(verifyDir);
            try
            {
                await using (FileStream writer = new(tempFile, FileMode.CreateNew, FileAccess.Write, FileShare.None, 64 * 1024, FileOptions.Asynchronous))
                {
                    await writer.WriteAsync(content, token).ConfigureAwait(false);
                    await writer.FlushAsync(token).ConfigureAwait(false);
                }

                await using FileStream reader = new(tempFile, FileMode.Open, FileAccess.Read, FileShare.Read, 64 * 1024, FileOptions.Asynchronous);
                if (Validation.IsRedirectingReparseHandle(reader.SafeFileHandle))
                    throw Denied();

                SignatureResult signature = verifyExecutableSignature is not null
                    ? verifyExecutableSignature(tempFile, reader.SafeFileHandle)
                    : AuthenticodeVerifier.VerifyOffline(tempFile, reader.SafeFileHandle);
                bool trustedValve = signature.Status == SignatureStatus.Valid &&
                    (signature.IsValveSigner || AuthenticodeVerifier.IsTrustedValveSigner(signature.Status, signature.SignerSubject));
                if (!trustedValve)
                    throw Denied();
            }
            finally
            {
                try { if (File.Exists(tempFile)) File.Delete(tempFile); } catch { }
                try { if (Directory.Exists(verifyDir)) Directory.Delete(verifyDir, recursive: false); } catch { }
            }
        }
    }

    private static async Task<(string ArchiveFile, string ArchiveSha256, bool IsVz)> ResolveVerifiedSourceArchiveAsync(
        string packageDirectory,
        SteamPackageEntry entry,
        CancellationToken token)
    {
        if (!string.IsNullOrEmpty(entry.ZipVzFile) &&
            !string.IsNullOrEmpty(entry.Sha256Vz) &&
            SteamPackageCatalog.IsSafePackageFileName(entry.ZipVzFile))
        {
            string vzPath = Path.Combine(packageDirectory, entry.ZipVzFile);
            if (File.Exists(vzPath) && ContentDiscovery.IsLocalSafePath(vzPath))
            {
                await using FileStream vzStream = RelatedArtifactReader.Open(vzPath);
                if (vzStream.Length <= SteamPackageArchive.MaximumLocalPackageBytes)
                {
                    string vzHash = await Hashing.Sha256StreamAsync(vzStream, token, maximumBytes: SteamPackageArchive.MaximumLocalPackageBytes).ConfigureAwait(false);
                    if (vzHash.Equals(entry.Sha256Vz, StringComparison.OrdinalIgnoreCase))
                        return (entry.ZipVzFile, entry.Sha256Vz, true);
                }
            }
        }

        if (SteamPackageCatalog.IsSafePackageFileName(entry.ZipFile))
        {
            string zipPath = Path.Combine(packageDirectory, entry.ZipFile);
            if (File.Exists(zipPath) && ContentDiscovery.IsLocalSafePath(zipPath))
            {
                await using FileStream zipStream = RelatedArtifactReader.Open(zipPath);
                if (zipStream.Length <= SteamPackageArchive.MaximumLocalPackageBytes)
                {
                    string zipHash = await Hashing.Sha256StreamAsync(zipStream, token, maximumBytes: SteamPackageArchive.MaximumLocalPackageBytes).ConfigureAwait(false);
                    if (zipHash.Equals(entry.Sha256, StringComparison.OrdinalIgnoreCase))
                        return (entry.ZipFile, entry.Sha256, false);
                }
            }
        }

        throw Denied();
    }

    public static bool TryRepair(string kind, byte[] original, SteamLayout layout, out byte[] repaired, out string? executable)
    {
        executable = null; repaired = [];
        if (kind == SteamConfigurationRepair.Cfg) return SteamConfigurationRepair.TryRepairCfg(original, out repaired, out _);
        if (kind != SteamConfigurationRepair.Shortcut) return false;
        bool changed = SteamConfigurationRepair.TryRepairShortcut(original, layout, out repaired, out string target);
        if (changed) executable = target;
        return changed;
    }

    public static async Task<string> CaptureExecutableHashAsync(string path, CancellationToken token)
    {
        if (!ContentDiscovery.IsLocalSafePath(path) || Validation.ContainsReparsePoint(path)) throw Denied();
        await using FileStream input = RelatedArtifactReader.Open(path);
        if (input.Length is <= 0 or > 64 * 1024 * 1024) throw Denied();
        string hash = await Hashing.Sha256StreamAsync(input, token);
        RelatedArtifactReader.ValidatePath(input.SafeFileHandle, Path.GetFullPath(path));
        return hash;
    }

    public static async Task<bool> IsRepairedAsync(RemediationAction action, SteamLayout layout, CancellationToken token = default)
    {
        if (action.Type != RemediationActionType.RepairSteamConfiguration) return false;
        if (action.ConfigurationKind == SteamConfigurationRepair.Run)
        {
            if (!IsRunTarget(action.RegistryHive, action.RegistryView, action.RegistryKey, action.RegistryValueName)) return false;
            SteamConfigurationSnapshot snapshot = ReadSnapshot(action.ConfigurationSnapshot);
            using RegistryKey baseKey = RegistryKey.OpenBaseKey(action.RegistryHive == "HKCU" ? RegistryHive.CurrentUser : RegistryHive.LocalMachine,
                Enum.Parse<RegistryView>(action.RegistryView!));
            using RegistryKey? key = baseKey.OpenSubKey(action.RegistryKey!);
            return snapshot.Kind == SteamConfigurationRepair.Run && snapshot.OriginalValue is not null &&
                SteamConfigurationRepair.TryRepairCommand(snapshot.OriginalValue, layout, out string repaired, out _) && repaired == snapshot.RepairedValue &&
                key is not null && key.GetValue(action.RegistryValueName!, null, RegistryValueOptions.DoNotExpandEnvironmentNames) is string current &&
                current == repaired && (int)key.GetValueKind(action.RegistryValueName!) == snapshot.RegistryValueKind;
        }
        if (!IsFileTarget(action.Target, action.ConfigurationKind, layout) ||
            FileScopeSafety.CaptureIdentity(Path.GetDirectoryName(action.Target)!, true) != action.ExpectedParentIdentity) return false;
        if (SteamConfigurationRepair.IsRemovedOnRepair(action.ConfigurationKind))
        {
            try { _ = File.GetAttributes(action.Target); return false; }
            catch (FileNotFoundException) { return true; }
            catch (DirectoryNotFoundException) { return false; }
        }
        if (action.ConfigurationKind == SteamConfigurationRepair.PackageRestore)
        {
            if (!Validation.IsHexSha256(action.RepairedSha256) || !FileScopeSafety.IsValidIdentity(action.ExpectedFileIdentity))
                return false;
            try
            {
                await using FileStream packageInput = RelatedArtifactReader.Open(action.Target);
                if (packageInput.Length <= 0 || packageInput.Length > SteamConfigurationRepair.MaximumPackageRestoreBytes)
                    return false;
                string actualHash = await Hashing.Sha256StreamAsync(packageInput, token, maximumBytes: SteamConfigurationRepair.MaximumPackageRestoreBytes).ConfigureAwait(false);
                RelatedArtifactReader.ValidatePath(packageInput.SafeFileHandle, Path.GetFullPath(action.Target));
                return FileScopeSafety.ReadIdentity(packageInput.SafeFileHandle) == action.ExpectedFileIdentity &&
                    actualHash.Equals(action.RepairedSha256, StringComparison.OrdinalIgnoreCase);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or System.ComponentModel.Win32Exception or InvalidDataException)
            {
                return false;
            }
        }
        await using FileStream input = RelatedArtifactReader.Open(action.Target);
        byte[] bytes = await ReadBytesAsync(input, token, SteamConfigurationRepair.MaximumBytesFor(action.ConfigurationKind));
        RelatedArtifactReader.ValidatePath(input.SafeFileHandle, Path.GetFullPath(action.Target));
        return FileScopeSafety.ReadIdentity(input.SafeFileHandle) == action.ExpectedFileIdentity &&
            SteamConfigurationRepair.Hash(bytes).Equals(action.RepairedSha256, StringComparison.OrdinalIgnoreCase) &&
            !TryRepair(action.ConfigurationKind!, bytes, layout, out _, out _);
    }

    internal static async Task<byte[]> ReadBytesAsync(FileStream input, CancellationToken token, int maximumBytes = SteamConfigurationRepair.MaximumBytes)
    {
        if (input.Length < 0 || input.Length > maximumBytes) throw Denied();
        byte[] bytes = new byte[checked((int)input.Length)];
        await input.ReadExactlyAsync(bytes, token);
        if (input.ReadByte() != -1) throw Denied("SteamConfig.Changed");
        return bytes;
    }

    private static Exception Denied(string id = "SteamConfig.InvalidTarget") =>
        MessageExceptions.Create(MessageText.Create(id), text => new InvalidDataException(text));
}
