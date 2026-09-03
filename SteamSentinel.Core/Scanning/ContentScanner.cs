using System.Buffers;
using System.Text;
using SharpCompress.Archives;
using SharpCompress.Common;
using SharpCompress.Readers;
using SteamSentinel.Core.Inspection;
using SteamSentinel.Core.Models;
using SteamSentinel.Core.Utilities;

namespace SteamSentinel.Core.Scanning;

public sealed class ContentScanner : IDisposable
{
    private const long MaximumStringScanBytes = 32L * 1024 * 1024;
    private readonly RuleSet _rules;
    private readonly Dictionary<string, string> _sessionPasswords = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<Guid, int> _amsiUnavailableCounts = [];
    private readonly AmsiScanner _amsi = new();
    private bool _disposed;

    public ContentScanner(RuleSet rules)
    {
        _rules = rules;
    }

    public async Task ScanRootAsync(
        string root,
        ScanReport report,
        ScanOptions options,
        IArchivePasswordProvider passwordProvider,
        IProgress<ScanProgress>? progress = null,
        CancellationToken cancellationToken = default,
        string? workshopId = null,
        string? projectType = null)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        string fullRoot = Path.GetFullPath(root);
        if (File.Exists(fullRoot))
        {
            await ScanFileAsync(fullRoot, fullRoot, fullRoot, report, options, passwordProvider, progress,
                cancellationToken, 0, workshopId, projectType, new ArchiveBudget(options));
            return;
        }

        if (!Directory.Exists(fullRoot))
        {
            AddCoverage(report, $"路径不存在：{fullRoot}", fullRoot, workshopId);
            return;
        }

        ArchiveBudget budget = new(options);
        Stack<string> pending = new();
        pending.Push(fullRoot);

        while (pending.Count > 0)
        {
            cancellationToken.ThrowIfCancellationRequested();
            string directory = pending.Pop();
            if (IsExcluded(directory, options.ExcludedRoots)) continue;

            try
            {
                FileAttributes attributes = File.GetAttributes(directory);
                if ((attributes & FileAttributes.ReparsePoint) != 0)
                {
                    AddCoverage(report, $"为防止越界，已跳过重解析目录：{directory}", directory, workshopId);
                    continue;
                }

                foreach (string child in Directory.EnumerateDirectories(directory)) pending.Push(child);
                foreach (string file in Directory.EnumerateFiles(directory))
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    if (++budget.FilesVisited > options.MaximumFiles)
                    {
                        AddCoverage(report, $"文件数量达到上限 {options.MaximumFiles}，剩余内容未扫描。", fullRoot, workshopId);
                        return;
                    }

                    await ScanFileAsync(file, file, file, report, options, passwordProvider, progress,
                        cancellationToken, 0, workshopId, projectType, budget);
                }
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                AddCoverage(report, $"无法读取目录：{directory}，原因：{ex.Message}", directory, workshopId);
            }
        }
    }

    private async Task ScanFileAsync(
        string physicalPath,
        string displayPath,
        string remediationTarget,
        ScanReport report,
        ScanOptions options,
        IArchivePasswordProvider passwordProvider,
        IProgress<ScanProgress>? progress,
        CancellationToken cancellationToken,
        int archiveDepth,
        string? workshopId,
        string? projectType,
        ArchiveBudget budget)
    {
        cancellationToken.ThrowIfCancellationRequested();
        progress?.Report(new ScanProgress("内容扫描", displayPath, report.Metrics.FilesVisited, null, "正在识别真实格式"));

        try
        {
            FileInfo info = new(physicalPath);
            if (!info.Exists) return;
            report.Metrics.FilesVisited++;

            FileTypeResult type = await FileTypeDetector.DetectAsync(physicalPath, cancellationToken);
            bool suspiciousExtension = _rules.DangerousExtensions.Contains(info.Extension, StringComparer.OrdinalIgnoreCase);
            bool shouldHash = options.HashEveryFile || options.Mode != ScanMode.Quick ||
                              info.Length <= 64L * 1024 * 1024 ||
                              suspiciousExtension || type.IsArchive || type.IsExecutableOrScript ||
                              type.Type == DetectedFileType.Mp4 ||
                              _rules.KnownProcessNames.Contains(info.Name, StringComparer.OrdinalIgnoreCase);

            string? sha256 = null;
            if (shouldHash)
            {
                sha256 = await Hashing.Sha256FileAsync(physicalPath, cancellationToken,
                    bytes => report.Metrics.BytesHashed += bytes);
                HashRule? hashRule = _rules.KnownHashes.FirstOrDefault(rule =>
                    rule.Sha256.Equals(sha256, StringComparison.OrdinalIgnoreCase));
                if (hashRule is not null)
                {
                    report.Findings.Add(new Finding
                    {
                        RuleId = hashRule.Id,
                        Category = type.IsArchive ? FindingCategory.Archive : FindingCategory.File,
                        Severity = hashRule.Severity,
                        Score = 100,
                        Title = hashRule.Label,
                        Description = "文件 SHA-256 与已确认规则完全一致。",
                        Target = remediationTarget,
                        Evidence = $"命中 {hashRule.Id}；内容位置：{displayPath}",
                        Sha256 = sha256,
                        WorkshopId = workshopId,
                        IsKnownMalware = hashRule.Malware,
                        CanRemediate = hashRule.Malware,
                        SuggestedActions = hashRule.Malware
                            ? [SuggestedActionKind.QuarantineFile, SuggestedActionKind.BlockKnownDomains]
                            : [SuggestedActionKind.ReviewOnly]
                    });
                }
            }

            if (type.ExtensionMismatch)
            {
                FindingSeverity severity = type.Type == DetectedFileType.PortableExecutable
                    ? FindingSeverity.High
                    : FindingSeverity.Medium;
                report.Findings.Add(new Finding
                {
                    RuleId = "CONTENT-EXTENSION-MISMATCH",
                    Category = type.IsArchive ? FindingCategory.Archive : FindingCategory.File,
                    Severity = severity,
                    Score = type.Type == DetectedFileType.PortableExecutable ? 65 : 40,
                    Title = "文件扩展名与真实格式不符",
                    Description = $"文件显示为 {info.Extension}，实际识别为 {type.Label}。",
                    Target = remediationTarget,
                    Evidence = $"内容位置：{displayPath}；建议扩展名：{type.ExpectedExtension}",
                    Sha256 = sha256,
                    WorkshopId = workshopId,
                    CanRemediate = false,
                    SuggestedActions = [SuggestedActionKind.ReviewOnly]
                });
            }

            if (workshopId is not null && IsUnexpectedExecutable(type, info.Extension, projectType))
            {
                report.Findings.Add(new Finding
                {
                    RuleId = "WORKSHOP-EXECUTABLE-CONTENT",
                    Category = FindingCategory.WallpaperEngine,
                    Severity = FindingSeverity.Medium,
                    Score = 40,
                    Title = "壁纸类型与可执行/启动型内容不一致",
                    Description = "视频或场景项目中出现启动型内容，需要核对来源。应用程序壁纸中的可执行文件不会仅凭类型报警。",
                    Target = remediationTarget,
                    Evidence = $"工坊 {workshopId}；内容位置：{displayPath}；真实格式：{type.Label}",
                    Sha256 = sha256,
                    WorkshopId = workshopId,
                    CanRemediate = false,
                    SuggestedActions = [SuggestedActionKind.ReviewOnly]
                });
            }

            if (info.Length <= MaximumStringScanBytes && (type.IsExecutableOrScript || suspiciousExtension || type.Type == DetectedFileType.Unknown))
            {
                await ScanStringsAsync(physicalPath, displayPath, remediationTarget, sha256, report, workshopId, projectType, cancellationToken);
            }

            if (options.UseAmsi && (type.IsExecutableOrScript || type.IsArchive || suspiciousExtension) && info.Length <= MaximumStringScanBytes)
            {
                AmsiScanResult amsiResult = await _amsi.ScanFileAsync(physicalPath, MaximumStringScanBytes, cancellationToken);
                if (amsiResult.Verdict is AmsiVerdict.Detected or AmsiVerdict.BlockedByPolicy)
                {
                    report.Findings.Add(new Finding
                    {
                        RuleId = "AMSI-DETECTED",
                        Category = FindingCategory.File,
                        Severity = FindingSeverity.Critical,
                        Score = 90,
                        Title = "本机反恶意软件接口判定为威胁",
                        Description = "AMSI 提供程序返回检测或阻止结果。",
                        Target = remediationTarget,
                        Evidence = $"{amsiResult.Detail}；内容位置：{displayPath}",
                        Sha256 = sha256,
                        WorkshopId = workshopId,
                        CanRemediate = true,
                        SuggestedActions = [SuggestedActionKind.QuarantineFile]
                    });
                }
                else if (amsiResult.Verdict is AmsiVerdict.Unavailable or AmsiVerdict.Error)
                {
                    AddAmsiCoverage(report, amsiResult.Detail);
                }
            }

            if (type.Type == DetectedFileType.Mp4)
            {
                Mp4InspectionResult mp4 = await Mp4Inspector.InspectAsync(physicalPath, cancellationToken);
                if (mp4.TrailingBytes > 0)
                {
                    report.Findings.Add(new Finding
                    {
                        RuleId = "MP4-TRAILING-DATA",
                        Category = FindingCategory.WallpaperEngine,
                        Severity = mp4.EmbeddedType is null ? FindingSeverity.Medium : FindingSeverity.High,
                        Score = mp4.EmbeddedType is null ? 45 : 75,
                        Title = "MP4 存在容器外尾随数据",
                        Description = mp4.EmbeddedType is null
                            ? "媒体结构结束后仍有额外数据，需要人工复核。"
                            : $"媒体尾部识别到 {mp4.EmbeddedType}。",
                        Target = remediationTarget,
                        Evidence = $"{mp4.Detail} 内容位置：{displayPath}",
                        Sha256 = sha256,
                        WorkshopId = workshopId,
                        CanRemediate = false,
                        SuggestedActions = [SuggestedActionKind.ReviewOnly]
                    });
                }
            }

            if (options.InspectArchives && type.IsArchive)
            {
                if (archiveDepth >= options.MaximumArchiveDepth)
                {
                    AddCoverage(report, $"压缩包达到最大嵌套深度 {options.MaximumArchiveDepth}：{displayPath}", remediationTarget, workshopId);
                }
                else
                {
                    await ScanArchiveAsync(physicalPath, displayPath, remediationTarget, sha256, report, options,
                        passwordProvider, progress, cancellationToken, archiveDepth, workshopId, projectType, budget, type.Label);
                }
            }
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidDataException)
        {
            AddCoverage(report, $"无法完整扫描文件 {displayPath}：{ex.Message}", remediationTarget, workshopId);
        }
    }

    private async Task ScanArchiveAsync(
        string physicalPath,
        string displayPath,
        string remediationTarget,
        string? sha256,
        ScanReport report,
        ScanOptions options,
        IArchivePasswordProvider passwordProvider,
        IProgress<ScanProgress>? progress,
        CancellationToken cancellationToken,
        int archiveDepth,
        string? workshopId,
        string? projectType,
        ArchiveBudget budget,
        string format)
    {
        sha256 ??= await Hashing.Sha256FileAsync(physicalPath, cancellationToken,
            bytes => report.Metrics.BytesHashed += bytes);
        string? password = _sessionPasswords.GetValueOrDefault(sha256);

        for (int attempt = 0; attempt < 3; attempt++)
        {
            cancellationToken.ThrowIfCancellationRequested();
            try
            {
                ReaderOptions readerOptions = new()
                {
                    Password = password,
                    LeaveStreamOpen = false,
                    LookForHeader = true
                };

                using IArchive archive = ArchiveFactory.OpenArchive(physicalPath, readerOptions);
                bool encrypted = archive.IsEncrypted || archive.Entries.Any(entry => entry.IsEncrypted);
                if (encrypted && string.IsNullOrEmpty(password))
                {
                    ArchivePasswordResponse response = await AskPasswordAsync(
                        displayPath, sha256, format, archiveDepth, workshopId, "压缩包内容已加密。", passwordProvider, cancellationToken);
                    if (response.Cancelled || string.IsNullOrEmpty(response.Password))
                    {
                        AddCoverage(report, $"加密包未解密：{displayPath}", remediationTarget, workshopId, "ARCHIVE-ENCRYPTED-NOT-SCANNED");
                        return;
                    }

                    password = response.Password;
                    if (response.ReuseForSession) _sessionPasswords[sha256] = password;
                    continue;
                }

                await ReadArchiveEntriesAsync(archive, physicalPath, displayPath, remediationTarget, report, options,
                    passwordProvider, progress, cancellationToken, archiveDepth, workshopId, projectType, budget);
                return;
            }
            catch (SharpCompress.Common.CryptographicException ex)
            {
                ArchivePasswordResponse response = await AskPasswordAsync(
                    displayPath, sha256, format, archiveDepth, workshopId,
                    string.IsNullOrEmpty(password) ? "压缩包需要密码。" : $"密码无法解密该压缩包：{ex.Message}",
                    passwordProvider, cancellationToken);
                if (response.Cancelled || string.IsNullOrEmpty(response.Password))
                {
                    AddCoverage(report, $"加密包未解密：{displayPath}", remediationTarget, workshopId, "ARCHIVE-ENCRYPTED-NOT-SCANNED");
                    return;
                }

                password = response.Password;
                if (response.ReuseForSession) _sessionPasswords[sha256] = password;
            }
            catch (Exception ex) when (LooksLikePasswordFailure(ex))
            {
                ArchivePasswordResponse response = await AskPasswordAsync(
                    displayPath, sha256, format, archiveDepth, workshopId, ex.Message, passwordProvider, cancellationToken);
                if (response.Cancelled || string.IsNullOrEmpty(response.Password))
                {
                    AddCoverage(report, $"加密包未解密：{displayPath}", remediationTarget, workshopId, "ARCHIVE-ENCRYPTED-NOT-SCANNED");
                    return;
                }

                password = response.Password;
                if (response.ReuseForSession) _sessionPasswords[sha256] = password;
            }
            catch (Exception ex) when (ex is ArchiveException or InvalidFormatException or NotSupportedException)
            {
                AddCoverage(report, $"压缩包格式损坏或不受支持：{displayPath}，原因：{ex.Message}", remediationTarget, workshopId,
                    "ARCHIVE-UNSUPPORTED");
                return;
            }
        }

        AddCoverage(report, $"加密包密码连续失败：{displayPath}", remediationTarget, workshopId, "ARCHIVE-PASSWORD-FAILED");
    }

    private async Task ReadArchiveEntriesAsync(
        IArchive archive,
        string physicalPath,
        string displayPath,
        string remediationTarget,
        ScanReport report,
        ScanOptions options,
        IArchivePasswordProvider passwordProvider,
        IProgress<ScanProgress>? progress,
        CancellationToken cancellationToken,
        int archiveDepth,
        string? workshopId,
        string? projectType,
        ArchiveBudget budget)
    {
        using TemporaryDirectory temporary = new();
        foreach (IArchiveEntry entry in archive.Entries)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (entry.IsDirectory) continue;

            report.Metrics.ArchiveEntriesVisited++;
            if (++budget.ArchiveEntries > options.MaximumArchiveEntries)
            {
                AddCoverage(report, $"压缩包条目数达到上限 {options.MaximumArchiveEntries}：{displayPath}", remediationTarget, workshopId);
                return;
            }

            string entryName = SanitizeEntryDisplayName(entry.Key);
            string virtualPath = $"{displayPath}!/{entryName}";
            progress?.Report(new ScanProgress("压缩包扫描", virtualPath, budget.ArchiveEntries,
                null, "正在受限读取压缩条目"));

            if (IsUnsafeArchiveName(entry.Key))
            {
                report.Findings.Add(new Finding
                {
                    RuleId = "ARCHIVE-PATH-TRAVERSAL",
                    Category = FindingCategory.Archive,
                    Severity = FindingSeverity.High,
                    Score = 80,
                    Title = "压缩包包含危险路径",
                    Description = "条目使用绝对路径、父目录、设备名或 NTFS ADS。本工具没有按该名称释放文件。",
                    Target = remediationTarget,
                    Evidence = $"条目：{virtualPath}",
                    WorkshopId = workshopId,
                    CanRemediate = true,
                    SuggestedActions = [SuggestedActionKind.QuarantineFile]
                });
            }

            if (entry.Size < 0 || entry.Size > options.MaximumEntryBytes)
            {
                AddCoverage(report, $"条目超过单文件上限：{virtualPath}（{entry.Size} 字节）", remediationTarget, workshopId);
                continue;
            }

            if (entry.CompressedSize > 0 && entry.Size / (double)entry.CompressedSize > options.MaximumCompressionRatio)
            {
                AddCoverage(report, $"条目压缩比超过上限：{virtualPath}", remediationTarget, workshopId, "ARCHIVE-RATIO-LIMIT");
                continue;
            }

            if (budget.ExpandedBytes + entry.Size > options.MaximumExpandedBytes)
            {
                AddCoverage(report, $"累计解压数据达到上限：{displayPath}", remediationTarget, workshopId, "ARCHIVE-SIZE-LIMIT");
                return;
            }

            string temporaryPath = temporary.CreateFilePath(entryName);
            await using (Stream input = entry.OpenEntryStream())
            await using (FileStream output = new(
                temporaryPath,
                FileMode.CreateNew,
                FileAccess.Write,
                FileShare.None,
                128 * 1024,
                FileOptions.Asynchronous | FileOptions.SequentialScan))
            {
                long copied = await CopyWithLimitAsync(input, output, options.MaximumEntryBytes, cancellationToken);
                budget.ExpandedBytes += copied;
                report.Metrics.ArchiveBytesExpanded += copied;
            }

            await ScanFileAsync(temporaryPath, virtualPath, remediationTarget, report, options, passwordProvider,
                progress, cancellationToken, archiveDepth + 1, workshopId, projectType, budget);
        }
    }

    private async Task ScanStringsAsync(
        string path,
        string displayPath,
        string remediationTarget,
        string? sha256,
        ScanReport report,
        string? workshopId,
        string? projectType,
        CancellationToken cancellationToken)
    {
        byte[] bytes = await File.ReadAllBytesAsync(path, cancellationToken);
        try
        {
            List<string> matches = [];
            int score = 0;
            bool trustedDefaultProject = string.Equals(projectType, "trusted-default", StringComparison.OrdinalIgnoreCase);
            foreach (StringRule rule in _rules.SuspiciousStrings)
            {
                if (trustedDefaultProject) continue;
                if (IndexOfAsciiIgnoreCase(bytes, rule.Value) >= 0)
                {
                    matches.Add($"{rule.Id}: {rule.Label}");
                    score += rule.Score;
                }
            }

            foreach (string domain in _rules.KnownDomains)
            {
                if (IndexOfAsciiIgnoreCase(bytes, domain) >= 0)
                {
                    matches.Add($"已知域名：{domain}");
                    score += 40;
                }
            }

            if (matches.Count == 0) return;
            score = Math.Min(100, score);
            FindingSeverity severity = score >= 100 ? FindingSeverity.Critical :
                score >= 60 ? FindingSeverity.High : score >= 30 ? FindingSeverity.Medium : FindingSeverity.Low;
            report.Findings.Add(new Finding
            {
                RuleId = "CONTENT-SUSPICIOUS-STRINGS",
                Category = FindingCategory.File,
                Severity = severity,
                Score = score,
                Title = "内容命中 Steam 假红信家族特征",
                Description = string.Join("；", matches),
                Target = remediationTarget,
                Evidence = $"内容位置：{displayPath}",
                Sha256 = sha256,
                WorkshopId = workshopId,
                IsKnownMalware = false,
                CanRemediate = false,
                SuggestedActions = [SuggestedActionKind.ReviewOnly]
            });
        }
        finally
        {
            Array.Clear(bytes);
        }
    }

    private static int IndexOfAsciiIgnoreCase(ReadOnlySpan<byte> data, string value)
    {
        byte[] needle = Encoding.ASCII.GetBytes(value.ToLowerInvariant());
        for (int i = 0; i <= data.Length - needle.Length; i++)
        {
            bool match = true;
            for (int j = 0; j < needle.Length; j++)
            {
                byte actual = data[i + j];
                if (actual is >= (byte)'A' and <= (byte)'Z') actual = (byte)(actual + 32);
                if (actual != needle[j])
                {
                    match = false;
                    break;
                }
            }

            if (match) return i;
        }

        return -1;
    }

    private static async Task<long> CopyWithLimitAsync(
        Stream input,
        Stream output,
        long limit,
        CancellationToken cancellationToken)
    {
        byte[] buffer = ArrayPool<byte>.Shared.Rent(128 * 1024);
        long total = 0;
        try
        {
            while (true)
            {
                int read = await input.ReadAsync(buffer.AsMemory(0, buffer.Length), cancellationToken);
                if (read == 0) break;
                total += read;
                if (total > limit) throw new InvalidDataException($"解压条目超过 {limit} 字节上限。");
                await output.WriteAsync(buffer.AsMemory(0, read), cancellationToken);
            }

            return total;
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer, clearArray: true);
        }
    }

    private static Task<ArchivePasswordResponse> AskPasswordAsync(
        string displayPath,
        string sha256,
        string format,
        int depth,
        string? workshopId,
        string reason,
        IArchivePasswordProvider provider,
        CancellationToken cancellationToken)
    {
        ArchivePasswordRequest request = new(
            Guid.NewGuid().ToString("N"), displayPath, sha256, format, depth, workshopId, reason);
        return provider.RequestPasswordAsync(request, cancellationToken);
    }

    private static bool LooksLikePasswordFailure(Exception ex)
    {
        string message = ex.ToString();
        return message.Contains("password", StringComparison.OrdinalIgnoreCase) ||
               message.Contains("encrypted", StringComparison.OrdinalIgnoreCase) ||
               message.Contains("crypto", StringComparison.OrdinalIgnoreCase) ||
               message.Contains("密码", StringComparison.OrdinalIgnoreCase) ||
               message.Contains("加密", StringComparison.OrdinalIgnoreCase);
    }

    private static bool IsUnexpectedExecutable(FileTypeResult type, string extension, string? projectType)
    {
        if (string.Equals(projectType, "trusted-default", StringComparison.OrdinalIgnoreCase)) return false;
        if (string.Equals(projectType, "application", StringComparison.OrdinalIgnoreCase) &&
            type.Type == DetectedFileType.PortableExecutable) return false;
        if (type.Type is DetectedFileType.PortableExecutable or DetectedFileType.Shortcut or
            DetectedFileType.PowerShell or DetectedFileType.Batch) return true;
        if (type.Type == DetectedFileType.JavaScript)
        {
            return !string.Equals(projectType, "web", StringComparison.OrdinalIgnoreCase);
        }

        return extension.Equals(".msi", StringComparison.OrdinalIgnoreCase) ||
               extension.Equals(".hta", StringComparison.OrdinalIgnoreCase) ||
               extension.Equals(".vbs", StringComparison.OrdinalIgnoreCase);
    }

    private static bool IsExcluded(string path, IEnumerable<string> excludedRoots)
    {
        string full = Path.GetFullPath(path);
        foreach (string excluded in excludedRoots)
        {
            try
            {
                string root = Path.TrimEndingDirectorySeparator(Path.GetFullPath(excluded));
                if (full.Equals(root, StringComparison.OrdinalIgnoreCase) ||
                    full.StartsWith(root + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase)) return true;
            }
            catch
            {
                // Ignore malformed exclusions.
            }
        }

        return false;
    }

    private static bool IsUnsafeArchiveName(string? name)
    {
        if (string.IsNullOrWhiteSpace(name)) return true;
        string normalized = name.Replace('/', '\\');
        if (string.IsNullOrWhiteSpace(normalized) || Path.IsPathFullyQualified(normalized) ||
            normalized.StartsWith("\\", StringComparison.Ordinal) ||
            normalized.Split('\\').Any(segment => segment is ".." or ".")) return true;
        if (normalized.Contains(':')) return true;
        string leaf = Path.GetFileNameWithoutExtension(normalized);
        return leaf.Equals("CON", StringComparison.OrdinalIgnoreCase) ||
               leaf.Equals("PRN", StringComparison.OrdinalIgnoreCase) ||
               leaf.Equals("AUX", StringComparison.OrdinalIgnoreCase) ||
               leaf.Equals("NUL", StringComparison.OrdinalIgnoreCase) ||
               (leaf.Length == 4 && (leaf.StartsWith("COM", StringComparison.OrdinalIgnoreCase) ||
                                     leaf.StartsWith("LPT", StringComparison.OrdinalIgnoreCase)) &&
                leaf[3] is >= '1' and <= '9');
    }

    private static string SanitizeEntryDisplayName(string? value)
    {
        if (string.IsNullOrEmpty(value)) return "<未命名条目>";
        string clean = value.Replace('\r', '_').Replace('\n', '_').Replace('\0', '_');
        return clean.Length <= 500 ? clean : clean[..500] + "…";
    }

    private static void AddCoverage(
        ScanReport report,
        string message,
        string target,
        string? workshopId,
        string ruleId = "SCAN-PARTIAL")
    {
        report.Coverage = ScanCoverage.Partial;
        if (!report.CoverageNotes.Contains(message, StringComparer.Ordinal)) report.CoverageNotes.Add(message);
        report.Findings.Add(new Finding
        {
            RuleId = ruleId,
            Category = FindingCategory.Coverage,
            Severity = FindingSeverity.Medium,
            Score = 30,
            Title = "未完整扫描",
            Description = message,
            Target = target,
            Evidence = workshopId is null ? string.Empty : $"工坊 {workshopId}",
            WorkshopId = workshopId,
            CanRemediate = false,
            SuggestedActions = [SuggestedActionKind.ReviewOnly]
        });
    }

    private void AddAmsiCoverage(ScanReport report, string detail)
    {
        report.Coverage = ScanCoverage.Partial;
        int count = _amsiUnavailableCounts.GetValueOrDefault(report.ScanId) + 1;
        _amsiUnavailableCounts[report.ScanId] = count;
        const string prefix = "AMSI/本机反恶意软件提供程序不可用：";
        string message = $"{prefix}{count:N0} 个候选文件未获得杀毒引擎判定。原因示例：{detail}";
        int existing = report.CoverageNotes.FindIndex(note => note.StartsWith(prefix, StringComparison.Ordinal));
        if (existing >= 0) report.CoverageNotes[existing] = message;
        else report.CoverageNotes.Add(message);
    }

    public void Dispose()
    {
        if (_disposed) return;
        _sessionPasswords.Clear();
        _amsiUnavailableCounts.Clear();
        _amsi.Dispose();
        _disposed = true;
        GC.SuppressFinalize(this);
    }

    private sealed class ArchiveBudget(ScanOptions options)
    {
        public long FilesVisited { get; set; }
        public long ArchiveEntries { get; set; }
        public long ExpandedBytes { get; set; }
        public ScanOptions Options { get; } = options;
    }
}
