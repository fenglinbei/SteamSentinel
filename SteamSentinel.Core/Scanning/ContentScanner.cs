using System.Buffers;
using System.Text;
using SharpCompress.Archives;
using SharpCompress.Common;
using SharpCompress.Readers;
using SteamSentinel.Core.Inspection;
using SteamSentinel.Core.Models;
using SteamSentinel.Core.Steam;
using SteamSentinel.Core.Utilities;

namespace SteamSentinel.Core.Scanning;

public sealed class ContentScanner : IDisposable
{
    private const long MaximumStringScanBytes = 32L * 1024 * 1024;
    private readonly RuleSet _rules;
    private readonly ArchivePasswordCache _passwords = new();
    private readonly Dictionary<Guid, int> _amsiUnavailableCounts = [];
    private readonly AmsiScanner _amsi = new();
    private bool _disposed;
    private readonly ScanResourceGuard _resources = new();
    private string? _coverageRoot;
    internal Action<ScanReport>? Checkpoint { get; set; }

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
        int first = report.Findings.Count;
        int notes = report.CoverageNotes.Count;
        long gaps = CoverageAggregation.OccurrenceCount(report);
        string? previousRoot = _coverageRoot;
        int amsiUnavailable = _amsiUnavailableCounts.GetValueOrDefault(report.ScanId);
        long files = report.Metrics.FilesVisited;
        bool completed = false;
        try
        {
            _coverageRoot = Path.GetFullPath(root);
            await ScanRootCoreAsync(root, report, options, passwordProvider, progress, cancellationToken, workshopId, projectType);
            completed = true;
        }
        finally
        {
            _coverageRoot = previousRoot;
            if (!completed) report.Coverage = ScanCoverage.Partial;
            Finding[] added = report.Findings.Skip(first).ToArray();
            report.RootSummaries.Add(new ScanRootSummary(root,
                !completed || report.CoverageNotes.Count > notes ||
                CoverageAggregation.OccurrenceCount(report) > gaps ||
                _amsiUnavailableCounts.GetValueOrDefault(report.ScanId) > amsiUnavailable ||
                added.Any(f => f.Category == FindingCategory.Coverage)
                    ? ScanCoverage.Partial : ScanCoverage.Complete,
                added.Count(f => f.IsKnownMalware), added.Count(f => f.CanRemediate), report.Metrics.FilesVisited - files));
            if (completed) Checkpoint?.Invoke(report);
        }
    }

    private async Task ScanRootCoreAsync(
        string root, ScanReport report, ScanOptions options, IArchivePasswordProvider passwordProvider,
        IProgress<ScanProgress>? progress, CancellationToken cancellationToken, string? workshopId, string? projectType)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        string fullRoot = Path.GetFullPath(root);
        if (IsExcluded(fullRoot, options.ExcludedRoots)) return;
        if (!ContentDiscovery.IsLocalSafePath(fullRoot))
        { AddCoverage(report, $"已跳过网络路径或重解析点：{fullRoot}", fullRoot, workshopId); return; }
        if (File.Exists(fullRoot))
        {
            await ScanFileAsync(fullRoot, fullRoot, fullRoot, report, options, passwordProvider, progress,
                cancellationToken, 0, workshopId, projectType, new ArchiveBudget(options));
            Checkpoint?.Invoke(report);
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

                foreach (string child in Directory.EnumerateDirectories(directory).Take(options.MaximumFiles + 1))
                {
                    if (++budget.DirectoryEntries > options.MaximumFiles) { AddCoverage(report, "目录数量达到扫描上限", fullRoot, workshopId); return; }
                    pending.Push(child);
                }
                foreach (string file in Directory.EnumerateFiles(directory).Take((int)Math.Clamp((long)options.MaximumFiles - budget.FilesVisited + 1, 0, int.MaxValue))
                    .Chunk(512).SelectMany(chunk => chunk.OrderBy(ContentPriority)))
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    if (IsExcluded(file, options.ExcludedRoots)) continue;
                    if (++budget.FilesVisited > options.MaximumFiles)
                    {
                        AddCoverage(report, $"文件数量达到上限 {options.MaximumFiles}，剩余内容未扫描。", fullRoot, workshopId);
                        return;
                    }

                    await ScanFileAsync(file, file, file, report, options, passwordProvider, progress,
                        cancellationToken, 0, workshopId, projectType, budget);
                    Checkpoint?.Invoke(report);
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
        _resources.Check(report);
        if (report.Metrics.FilesVisited >= options.MaximumFiles)
            throw new ScanResourceLimitException($"本轮文件数达到上限 {options.MaximumFiles}，已保留此前结果，请分批检查剩余目录。");
        int firstFinding = report.Findings.Count;
        string? scanIdentity = null;

        try
        {
            FileInfo info = new(physicalPath);
            if (!info.Exists) { AddCoverage(report, "扫描时文件已不存在或无法读取：" + displayPath, remediationTarget, workshopId); return; }
            report.Metrics.FilesVisited++;

            if ((info.Attributes & FileAttributes.ReparsePoint) != 0)
            {
                AddCoverage(report, $"已跳过重解析文件：{displayPath}", remediationTarget, workshopId);
                return;
            }
            string extension = Path.GetExtension(displayPath);
            FileTypeResult type = await FileTypeDetector.DetectAsync(physicalPath, cancellationToken, displayPath);
            bool suspiciousExtension = _rules.DangerousExtensions.Contains(extension, StringComparer.OrdinalIgnoreCase);
            // Format and MP4 structure checks do not require reading the whole media payload.
            // Never trust a .mp4 extension alone, and inspect overlays before applying hash budgets.
            Mp4InspectionResult? media = type.Type == DetectedFileType.Mp4
                ? await InspectMediaAsync(physicalPath, displayPath, remediationTarget, report, options, passwordProvider,
                    progress, cancellationToken, archiveDepth, workshopId, projectType, budget) : null;
            if (options.Mode == ScanMode.Quick && media?.IsStructurallyValid == true && !type.ExtensionMismatch)
            {
                CoverageAggregation.Add(report, "QUICK-MEDIA-STRUCTURE", _coverageRoot ?? remediationTarget, displayPath);
                return;
            }
            // long.MaxValue means no global hash-byte cap, not a larger allocation. Hashing remains streamed.
            long charged = Math.Max(0, report.Metrics.BytesHashed -
                (options.Mode == ScanMode.Quick ? report.Metrics.QuickPriorityBytesHashed : 0));
            long remaining = options.MaximumContentBytes == long.MaxValue ? long.MaxValue :
                Math.Max(0, Math.Max(0, options.MaximumContentBytes) - charged);
            bool priorityReserve = options.Mode == ScanMode.Quick && info.Length > remaining && info.Length <= 8L * 1024 * 1024 &&
                (type.IsExecutableOrScript || suspiciousExtension) && info.Length <= 128L * 1024 * 1024 - report.Metrics.QuickPriorityBytesHashed;
            bool tooLarge = options.Mode == ScanMode.Quick && info.Length > 256L * 1024 * 1024;
            bool deepReadAllowed = !tooLarge && (info.Length <= remaining || priorityReserve);
            bool shouldHash = options.HashEveryFile || options.Mode != ScanMode.Quick ||
                              info.Length <= 64L * 1024 * 1024 ||
                              suspiciousExtension || type.IsArchive || type.IsExecutableOrScript ||
                              type.Type == DetectedFileType.Mp4 ||
                              _rules.KnownProcessNames.Contains(info.Name, StringComparer.OrdinalIgnoreCase);

            string? sha256 = null;
            if (shouldHash && deepReadAllowed)
            {
                progress?.Report(new ScanProgress("文件哈希", displayPath, report.Metrics.FilesVisited, null, "正在分块计算文件哈希"));
                sha256 = await Hashing.Sha256FileAsync(physicalPath, cancellationToken,
                    bytes => { report.Metrics.BytesHashed += bytes; if (priorityReserve) report.Metrics.QuickPriorityBytesHashed += bytes; });
                if (archiveDepth == 0) scanIdentity = sha256;
                HashRule? hashRule = _rules.KnownHashes.FirstOrDefault(rule =>
                    rule.Sha256.Equals(sha256, StringComparison.OrdinalIgnoreCase));
                if (hashRule is not null)
                {
                    report.Findings.Add(new Finding
                    {
                        RuleId = hashRule.Id,
                        Category = type.IsArchive ? FindingCategory.Archive : FindingCategory.File,
                        Severity = hashRule.Severity,
                        Score = hashRule.Malware ? 100 : 80,
                        Title = hashRule.Label,
                        Description = hashRule.Evidence ?? "文件 SHA-256 与已确认规则完全一致。",
                        Target = remediationTarget,
                        Evidence = $"命中 {hashRule.Id}，内容位置：{displayPath}",
                        Sha256 = sha256,
                        WorkshopId = workshopId,
                        IsKnownMalware = hashRule.Malware,
                        CanRemediate = hashRule.Malware || hashRule.Remediable,
                        SuggestedActions = hashRule.Malware || hashRule.Remediable
                            ? [SuggestedActionKind.QuarantineFile]
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
                    Description = $"文件显示为 {extension}，实际识别为 {type.Label}。",
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

            if (!deepReadAllowed)
            {
                CoverageAggregation.Add(report, tooLarge ? "QUICK-FILE-SIZE" : "CONTENT-BYTE-BUDGET",
                    _coverageRoot ?? remediationTarget, displayPath);
                return;
            }

            if (info.Length <= MaximumStringScanBytes && (type.IsExecutableOrScript || suspiciousExtension ||
                type.Type is DetectedFileType.Unknown or DetectedFileType.Html or DetectedFileType.Json or DetectedFileType.Xml))
            {
                progress?.Report(new ScanProgress("内容特征", displayPath, report.Metrics.FilesVisited, null, "正在分块检查文本与行为特征"));
                await ScanStringsAsync(physicalPath, displayPath, remediationTarget, sha256, report, workshopId, projectType, cancellationToken);
            }

            if (options.UseAmsi && (type.IsExecutableOrScript || type.IsArchive || suspiciousExtension) && info.Length <= MaximumStringScanBytes)
            {
                progress?.Report(new ScanProgress("本机安全引擎", displayPath, report.Metrics.FilesVisited, null, "正在等待本机反恶意软件接口"));
                AmsiScanResult amsiResult = await _amsi.ScanFileAsync(physicalPath, MaximumStringScanBytes, cancellationToken);
                if (amsiResult.Verdict is AmsiVerdict.Detected or AmsiVerdict.BlockedByPolicy)
                {
                    report.Findings.Add(new Finding
                    {
                        RuleId = "AMSI-DETECTED",
                        Category = FindingCategory.File,
                        Severity = FindingSeverity.Critical,
                        Score = 90,
                        Title = amsiResult.Verdict == AmsiVerdict.Detected ? "本机反恶意软件接口检出威胁" : "本机安全策略阻止了该内容",
                        Description = amsiResult.Verdict == AmsiVerdict.Detected ? "AMSI 提供程序返回威胁检测结果。" : "策略阻止不等同于已确认病毒，请复核后决定是否隔离。",
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

            if (type.Type == DetectedFileType.Shortcut)
            {
                ShortcutInspection shortcut = info.Length <= 1024 * 1024
                    ? ShortcutInspector.Inspect(await File.ReadAllBytesAsync(physicalPath, cancellationToken))
                    : new(null, null, null, false, "快捷方式超过大小上限");
                string command = shortcut.Target + " " + shortcut.Arguments;
                IReadOnlyList<string> signals = ScriptSignals.Analyze(command);
                if (signals.Count > 0) report.Findings.Add(new Finding
                {
                    RuleId = "SHORTCUT-EXECUTION-CHAIN", Category = FindingCategory.File, Severity = FindingSeverity.High,
                    Score = 85, Title = "快捷方式包含可疑执行链", Description = string.Join("，", signals),
                    Target = remediationTarget, Sha256 = sha256, Evidence = ScriptSignals.Redact(command),
                    CanRemediate = true, SuggestedActions = [SuggestedActionKind.QuarantineFile]
                });
                if (!shortcut.Complete) AddCoverage(report, shortcut.Detail + "：" + displayPath, remediationTarget, workshopId, "SHORTCUT-PARTIAL");
            }

            if (type.Type is DetectedFileType.CompoundDocument or DetectedFileType.Cabinet)
            {
                if (options.InspectArchives && archiveDepth < options.MaximumArchiveDepth)
                    await ScanStructuredAsync(physicalPath, displayPath, remediationTarget, type.Type, sha256, report, options,
                        passwordProvider, progress, cancellationToken, archiveDepth, workshopId, projectType, budget);
                else AddCoverage(report, $"安装包内部未展开，已检查文件哈希：{displayPath}", remediationTarget,
                    workshopId, "COMPOUND-CONTENT-NOT-EXPANDED");
            }

            if (!options.InspectArchives && type.IsArchive)
                AddCoverage(report, $"本次未检查压缩包内部：{displayPath}", remediationTarget, workshopId, "ARCHIVE-NOT-REQUESTED");
            if (options.InspectArchives && type.IsArchive && type.Type != DetectedFileType.Cabinet)
            {
                if (archiveDepth >= options.MaximumArchiveDepth)
                {
                    AddCoverage(report, $"压缩包达到最大嵌套深度 {options.MaximumArchiveDepth}：{displayPath}", remediationTarget, workshopId);
                }
                else
                {
                    await ScanArchiveAsync(physicalPath, displayPath, remediationTarget, sha256, report, options,
                        passwordProvider, progress, cancellationToken, archiveDepth, workshopId, projectType, budget, type);
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
        finally
        {
            foreach (Finding finding in report.Findings.Skip(firstFinding))
            {
                finding.ContentPath ??= displayPath;
                if (archiveDepth == 0) finding.TargetSha256 = scanIdentity;
            }
        }
    }

    private static int ContentPriority(string path) => Path.GetExtension(path).ToLowerInvariant() switch
    {
        ".exe" or ".dll" or ".lnk" or ".ps1" or ".bat" or ".cmd" or ".vbs" or ".js" or ".lua" or ".py" => 0,
        ".zip" or ".rar" or ".7z" or ".msi" or ".cab" => 1,
        ".mp4" => 3,
        _ => 2
    };

    private async Task<Mp4InspectionResult> InspectMediaAsync(string physicalPath, string displayPath, string target,
        ScanReport report, ScanOptions options, IArchivePasswordProvider provider, IProgress<ScanProgress>? progress,
        CancellationToken token, int depth, string? workshopId, string? projectType, ArchiveBudget budget)
    {
        Mp4InspectionResult mp4 = await Mp4Inspector.InspectAsync(physicalPath, token);
        report.Metrics.MediaStructuresChecked++;
        if (mp4.TrailingBytes > 0)
        {
            report.Findings.Add(new Finding
            {
                RuleId = "MP4-TRAILING-DATA", Category = FindingCategory.WallpaperEngine,
                Severity = mp4.EmbeddedType is null ? FindingSeverity.Medium : FindingSeverity.High,
                Score = mp4.EmbeddedType is null ? 45 : 75, Title = "MP4 存在容器外尾随数据",
                Description = mp4.EmbeddedType is null ? "媒体结构结束后仍有额外数据，需要人工复核。" : $"媒体尾部识别到 {mp4.EmbeddedType}。",
                Target = target, Evidence = $"{mp4.Detail} 内容位置：{displayPath}", WorkshopId = workshopId,
                SuggestedActions = [SuggestedActionKind.ReviewOnly]
            });
            if (mp4.EmbeddedType is not null && options.InspectArchives && mp4.LastValidOffset > 0)
                await ScanOverlayAsync(physicalPath, displayPath, target, mp4.LastValidOffset, report,
                    options, provider, progress, token, depth, workshopId, projectType, budget);
            else AddCoverage(report, "媒体尾随内容未展开：" + displayPath, target, workshopId,
                options.InspectArchives ? "MP4-OVERLAY-UNSUPPORTED" : "ARCHIVE-NOT-REQUESTED");
        }
        else if (!mp4.IsStructurallyValid)
            AddCoverage(report, "媒体结构无法确认：" + displayPath, target, workshopId, "MP4-STRUCTURE-PARTIAL");
        return mp4;
    }

    private async Task ScanStructuredAsync(string physicalPath, string displayPath, string target, DetectedFileType type,
        string? sha256, ScanReport report, ScanOptions options, IArchivePasswordProvider passwords,
        IProgress<ScanProgress>? progress, CancellationToken token, int depth, string? workshopId, string? projectType, ArchiveBudget budget)
    {
        using TemporaryDirectory temp = new();
        long remaining = Math.Max(0, options.MaximumExpandedBytes - budget.ExpandedBytes);
        int entries = (int)Math.Max(0, options.MaximumArchiveEntries - budget.ArchiveEntries);
        StructuredInspection result = type == DetectedFileType.Cabinet
            ? StructuredContainerInspector.ReadCabinet(physicalPath, temp, options.MaximumEntryBytes, remaining, entries, token)
            : StructuredContainerInspector.ReadMsi(physicalPath, temp, options.MaximumEntryBytes, remaining, entries, token);
        budget.ExpandedBytes += result.ExpandedBytes;
        report.Metrics.ArchiveBytesExpanded += result.ExpandedBytes;
        foreach (string note in result.Notes.Distinct()) AddCoverage(report, ScriptSignals.Redact(note) + "：" + displayPath,
            target, workshopId, "INSTALLER-PARTIAL");
        if (result.Recognized && type == DetectedFileType.CompoundDocument)
        {
            string actions = string.Join("\n", result.Metadata.Where(line => line.StartsWith("CustomAction:", StringComparison.Ordinal)));
            IReadOnlyList<string> signals = ScriptSignals.Analyze(actions);
            report.Findings.Add(new Finding
            {
                RuleId = "INSTALLER-STRUCTURE", Category = FindingCategory.Archive,
                Severity = signals.Count > 0 ? FindingSeverity.High : FindingSeverity.Information,
                Score = signals.Count > 0 ? 85 : 5, Title = signals.Count > 0 ? "安装包自定义动作包含可疑执行链" : "已只读检查安装包结构",
                Description = $"读取 {result.Metadata.Count} 条安装表记录、{result.Members.Count} 个内嵌成员，未安装或执行自定义动作。" +
                    (signals.Count > 0 ? string.Join("，", signals) : "存在自定义动作本身不代表恶意。"),
                Target = target, Sha256 = sha256, Evidence = ScriptSignals.Redact(string.Join("\n", result.Metadata.Take(24))),
                CanRemediate = signals.Count > 0, SuggestedActions = signals.Count > 0 ? [SuggestedActionKind.QuarantineFile] : [SuggestedActionKind.ReviewOnly]
            });
        }
        foreach (StructuredMember member in result.Members)
        {
            token.ThrowIfCancellationRequested();
            if (!File.Exists(member.Path)) { AddCoverage(report, "安装包成员展开失败：" + member.Name, target, workshopId); continue; }
            if (++budget.ArchiveEntries > options.MaximumArchiveEntries) { AddCoverage(report, "安装包成员数量达到上限", target, workshopId); break; }
            report.Metrics.ArchiveEntriesVisited++;
            await ScanFileAsync(member.Path, displayPath + "!/" + SanitizeEntryDisplayName(member.Name), target, report,
                options, passwords, progress, token, depth + 1, workshopId, projectType, budget);
        }
    }

    private async Task ScanArchiveAsync(
        string physicalPath, string displayPath, string remediationTarget, string? sha256,
        ScanReport report, ScanOptions options, IArchivePasswordProvider passwordProvider,
        IProgress<ScanProgress>? progress, CancellationToken cancellationToken, int archiveDepth,
        string? workshopId, string? projectType, ArchiveBudget budget, FileTypeResult type)
    {
        sha256 ??= await Hashing.Sha256FileAsync(physicalPath, cancellationToken);
        Queue<string> candidates = new(_passwords.Candidates(remediationTarget));
        HashSet<string> tried = new(StringComparer.Ordinal);
        string? password = null;
        ArchivePasswordReuseScope scope = ArchivePasswordReuseScope.CurrentOnly;
        int manualAttempts = 0;
        int cachedFailures = 0;
        bool encrypted = false;
        bool usingCachedPassword = false;
        while (true)
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
                // Known formats must retain their decoder's password errors. Factory probing can
                // swallow ZIP AES "bad password" and replace it with "unknown archive format".
                progress?.Report(new ScanProgress("压缩包目录", displayPath, budget.ArchiveEntries, null, "正在读取压缩包目录与解码参数"));
                _resources.Check(report);
                using TemporaryDirectory temporary = new();
                List<(string Physical, string Virtual)> staged = [];
                ScanReport stageReport = new();
                bool validatedEncryptedEntry = false;
                using (IArchive archive = type.Type switch
                {
                    DetectedFileType.Zip => SharpCompress.Archives.Zip.ZipArchive.OpenArchive(physicalPath, readerOptions),
                    DetectedFileType.Rar => SharpCompress.Archives.Rar.RarArchive.OpenArchive(physicalPath, readerOptions),
                    DetectedFileType.SevenZip => SharpCompress.Archives.SevenZip.SevenZipArchive.OpenArchive(physicalPath, readerOptions),
                    _ => ArchiveFactory.OpenArchive(physicalPath, readerOptions)
                })
                {
                encrypted |= archive.IsEncrypted || archive.Entries.Any(entry => entry.IsEncrypted);
                if (encrypted && password is null) throw new PasswordNeededException();

                // Validate/decompress this level before scanning children. A bad password cannot
                // publish findings, cache entries or duplicate visible counters from a failed attempt.
                foreach (IArchiveEntry entry in archive.Entries)
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    _resources.Check(report);
                    if (entry.IsDirectory) continue;
                    if (++budget.ArchiveEntries > options.MaximumArchiveEntries)
                    {
                        AddCoverage(stageReport, $"压缩包条目数达到上限：{displayPath}", remediationTarget, workshopId);
                        break;
                    }
                    string virtualPath = $"{displayPath}!/{SanitizeEntryDisplayName(entry.Key)}";
                    progress?.Report(new ScanProgress("压缩包扫描", virtualPath, budget.ArchiveEntries, null, "正在受限读取压缩条目"));
                    if (IsUnsafeArchiveName(entry.Key))
                        stageReport.Findings.Add(new Finding
                        {
                            RuleId = "ARCHIVE-PATH-TRAVERSAL",
                            Category = FindingCategory.Archive,
                            Severity = FindingSeverity.High,
                            Score = 80,
                            Title = "压缩包包含危险路径",
                            Description = "未按压缩包中的路径写入文件，可在复核后隔离外层文件。",
                            Target = remediationTarget,
                            ContentPath = virtualPath,
                            Evidence = virtualPath,
                            WorkshopId = workshopId,
                            CanRemediate = true,
                            SuggestedActions = [SuggestedActionKind.QuarantineFile]
                        });
                    if (entry.Size < 0 || entry.Size > options.MaximumEntryBytes ||
                        (entry.CompressedSize > 0 && entry.Size / (double)entry.CompressedSize > options.MaximumCompressionRatio))
                    {
                        AddCoverage(stageReport, $"条目大小或压缩比超过上限：{virtualPath}", remediationTarget, workshopId,
                            entry.Size <= options.MaximumEntryBytes ? "ARCHIVE-RATIO-LIMIT" : "ARCHIVE-SIZE-LIMIT");
                        continue;
                    }
                    if (entry.Size > options.MaximumExpandedBytes - budget.ExpandedBytes)
                    {
                        AddCoverage(stageReport, $"累计解压数据达到上限：{virtualPath}", remediationTarget, workshopId);
                        break;
                    }
                    string temp = temporary.CreateFilePath();
                    try
                    {
                        long copied;
                        await using (Stream input = entry.OpenEntryStream())
                        await using (FileStream output = new(temp, FileMode.CreateNew, FileAccess.Write, FileShare.None,
                            128 * 1024, FileOptions.Asynchronous | FileOptions.SequentialScan))
                        {
                            using SharpCompress.Crypto.Crc32Stream? checksum = type.Type == DetectedFileType.Zip && entry.Crc != 0
                                ? new SharpCompress.Crypto.Crc32Stream(output) : null;
                            long available = Math.Min(options.MaximumEntryBytes, options.MaximumExpandedBytes - budget.ExpandedBytes);
                            copied = await CopyWithLimitAsync(input, (Stream?)checksum ?? output, available, cancellationToken,
                                bytes => budget.ExpandedBytes += bytes);
                            // ZIP has an exact uncompressed length. Stream formats may report an
                            // unknown length, and other decoders can include padding in their stream.
                            if (type.Type == DetectedFileType.Zip && copied != entry.Size)
                                throw new InvalidDataException("ZIP 解压长度与条目声明不一致。");
                            if (checksum is not null && checksum.Crc != (uint)entry.Crc)
                                throw new InvalidDataException("ZIP 内容校验失败，不能据此验证密码。");
                        }
                        // An unencrypted member is never proof that a supplied password works.
                        validatedEncryptedEntry |= entry.IsEncrypted && copied > 0 && copied == entry.Size;
                        stageReport.Metrics.ArchiveBytesExpanded += copied;
                        stageReport.Metrics.ArchiveEntriesVisited++;
                        staged.Add((temp, virtualPath));
                    }
                    catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidDataException &&
                                               !LooksLikePasswordFailure(ex))
                    {
                        AddCoverage(stageReport, $"条目无法读取或被安全软件处理：{virtualPath}，{ex.Message}", remediationTarget, workshopId);
                        // Solid streams may be unusable after an I/O failure, do not claim later entries were scanned.
                        break;
                    }
                }
                } // Release this decoder before recursively opening any child archive.
                if (password is not null && validatedEncryptedEntry)
                    _passwords.Remember(password, remediationTarget, scope);
                report.Findings.AddRange(stageReport.Findings);
                report.CoverageNotes.AddRange(stageReport.CoverageNotes);
                if (stageReport.Coverage == ScanCoverage.Partial) report.Coverage = ScanCoverage.Partial;
                report.Metrics.ArchiveEntriesVisited += stageReport.Metrics.ArchiveEntriesVisited;
                report.Metrics.ArchiveBytesExpanded += stageReport.Metrics.ArchiveBytesExpanded;
                foreach ((string physical, string virtualPath) in staged)
                    await ScanFileAsync(physical, virtualPath, remediationTarget, report, options, passwordProvider,
                        progress, cancellationToken, archiveDepth + 1, workshopId, projectType, budget);
                return;
            }
            catch (Exception ex) when (IsArchivePasswordFailure(ex, encrypted, password is not null))
            {
                encrypted = true;
                if (password is not null)
                {
                    tried.Add(password);
                    _passwords.RememberFailure(sha256, password);
                    if (usingCachedPassword) cachedFailures++;
                }
                string? next = null;
                while (candidates.TryDequeue(out string? candidate))
                {
                    if (_passwords.HasFailed(sha256, candidate)) { cachedFailures++; continue; }
                    if (!tried.Contains(candidate)) { next = candidate; break; }
                }
                if (next is not null)
                {
                    password = next;
                    scope = ArchivePasswordReuseScope.CurrentOnly;
                    usingCachedPassword = true;
                    continue;
                }
                if (_passwords.IsDeferred(sha256))
                {
                    AddCoverage(report, $"这份内容与本次此前未解开的内容相同（SHA-256 一致），未再次询问密码：{displayPath}。取得新密码后可点击“重试未解密内容”。",
                        remediationTarget, workshopId, "ARCHIVE-ENCRYPTED-DEFERRED");
                    return;
                }
                bool repeated = false;
                while (true)
                {
                    if (manualAttempts >= 3)
                    {
                        _passwords.Defer(sha256);
                        AddCoverage(report, $"已达到本次密码输入次数上限，未解开：{displayPath}。相同内容不再重复询问，可点击“重试未解密内容”补充密码。",
                            remediationTarget, workshopId, "ARCHIVE-PASSWORD-FAILED");
                        return;
                    }
                    ArchivePasswordPromptKind kind = repeated ? ArchivePasswordPromptKind.RepeatedPassword :
                        manualAttempts > 0 ? ArchivePasswordPromptKind.EnteredPasswordFailed :
                        cachedFailures > 0 ? ArchivePasswordPromptKind.CachedPasswordFailed : ArchivePasswordPromptKind.Needed;
                    string reason = kind switch
                    {
                        ArchivePasswordPromptKind.RepeatedPassword => "这个密码已经尝试过，未能解开这份内容。请换一个密码，也可以跳过，不会重复解包。",
                        ArchivePasswordPromptKind.EnteredPasswordFailed => "刚输入的密码未能解开这一层，没有因这次失败存为可复用密码。请核对内层是否使用其他密码，也不能排除内容损坏或格式兼容问题。",
                        ArchivePasswordPromptKind.CachedPasswordFailed => "已尝试本次保存的密码，仍未解开这一层。内层可能使用不同密码，也不能排除内容损坏或格式兼容问题。",
                        _ => "这一层内容需要密码，目前没有适用且已验证的密码可供复用。只有成功读取加密内容后，密码才会按所选范围复用。"
                    };
                    ArchivePasswordResponse response = await AskPasswordAsync(displayPath, sha256, type.Label, archiveDepth,
                        workshopId, reason, passwordProvider, cancellationToken, _passwords.PreferredScope, kind);
                    scope = response.ReuseForSession ? ArchivePasswordReuseScope.Session : response.ReuseScope;
                    _passwords.PreferredScope = scope;
                    if (response.Cancelled || string.IsNullOrEmpty(response.Password))
                    {
                        _passwords.Defer(sha256);
                        AddCoverage(report, $"已跳过未解密内容：{displayPath}。本次相同内容不再询问，取得新密码后可点击“重试未解密内容”。",
                            remediationTarget, workshopId, "ARCHIVE-ENCRYPTED-NOT-SCANNED");
                        return;
                    }
                    manualAttempts++;
                    if (tried.Contains(response.Password) || _passwords.HasFailed(sha256, response.Password))
                    {
                        repeated = true;
                        continue;
                    }
                    password = response.Password;
                    usingCachedPassword = false;
                    break;
                }
            }
            catch (Exception ex) when (ex is SharpCompressException or NotSupportedException or
                                       InvalidOperationException or ArgumentException or IOException or UnauthorizedAccessException or InvalidDataException or
                                       IndexOutOfRangeException or OverflowException)
            {
                AddCoverage(report, $"压缩包未完整读取，可能损坏、格式不支持、缺少分卷或读取受阻：{displayPath}（{ex.GetType().Name}）。已继续扫描其他文件。",
                    remediationTarget, workshopId, "ARCHIVE-UNSUPPORTED");
                return;
            }
        }
    }

    private sealed class PasswordNeededException : Exception;

    private static bool IsArchivePasswordFailure(Exception ex, bool encrypted, bool hasPassword) =>
        ex is PasswordNeededException or SharpCompress.Common.CryptographicException or System.Security.Cryptography.CryptographicException ||
        LooksLikePasswordFailure(ex) ||
        (encrypted && hasPassword && ex is SharpCompressException);

    private async Task ScanOverlayAsync(
        string physicalPath, string displayPath, string target, long offset, ScanReport report,
        ScanOptions options, IArchivePasswordProvider provider, IProgress<ScanProgress>? progress,
        CancellationToken token, int depth, string? workshopId, string? projectType, ArchiveBudget budget)
    {
        long size = new FileInfo(physicalPath).Length - offset;
        if (depth >= options.MaximumArchiveDepth || size > options.MaximumEntryBytes ||
            size > options.MaximumExpandedBytes - budget.ExpandedBytes)
        {
            AddCoverage(report, $"尾随内容超过扫描限制：{displayPath}", target, workshopId);
            return;
        }
        using TemporaryDirectory temporary = new();
        string overlay = temporary.CreateFilePath();
        await using (FileStream input = File.OpenRead(physicalPath))
        await using (FileStream output = new(overlay, FileMode.CreateNew))
        {
            input.Position = offset;
            budget.ExpandedBytes += await CopyWithLimitAsync(input, output, options.MaximumEntryBytes, token);
        }
        await ScanFileAsync(overlay, $"{displayPath}!/<尾随内容@{offset}>", target, report,
            options, provider, progress, token, depth + 1, workshopId, projectType, budget);
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
        var signals = await StreamingStringInspection.ReadAsync(path,
            _rules.SuspiciousStrings.Select(rule => rule.Value).Concat(_rules.KnownDomains),
            MaximumStringScanBytes, cancellationToken);
        {
            List<string> matches = [];
            bool Contains(string value) => signals.Raw.Contains(value);
            HeuristicMatch? combined = ContentHeuristics.Match(Contains, displayPath);
            if (combined is null && Path.GetExtension(displayPath).ToLowerInvariant() is not (".md" or ".log" or ".lo"))
            {
                IReadOnlyList<string> scriptSignals = ScriptSignals.Analyze(signals.Script.Contains);
                if (scriptSignals.Count > 0) combined = new HeuristicMatch("HEUR-STEAM-DEPLOYMENT-CHAIN",
                    "发现 Steam 插件部署或凭据收集链", string.Join("，", scriptSignals), 90);
            }
            if (combined is not null && !string.Equals(projectType, "trusted-default", StringComparison.OrdinalIgnoreCase))
                report.Findings.Add(new Finding
                {
                    RuleId = combined.Id,
                    Category = FindingCategory.File,
                    Severity = FindingSeverity.High,
                    Score = combined.Score,
                    Title = combined.Title,
                    Description = combined.Evidence,
                    Target = remediationTarget,
                    ContentPath = displayPath,
                    Evidence = $"内容位置：{displayPath}",
                    Sha256 = sha256,
                    WorkshopId = workshopId,
                    CanRemediate = true,
                    SuggestedActions = [SuggestedActionKind.QuarantineFile]
                });
            int score = 0;
            bool trustedDefaultProject = string.Equals(projectType, "trusted-default", StringComparison.OrdinalIgnoreCase);
            foreach (StringRule rule in _rules.SuspiciousStrings)
            {
                if (trustedDefaultProject) continue;
                if (Contains(rule.Value))
                {
                    matches.Add($"{rule.Id}: {rule.Label}");
                    score += rule.Score;
                }
            }

            foreach (string domain in _rules.KnownDomains)
            {
                if (Contains(domain))
                {
                    matches.Add($"已知域名：{domain}");
                    score += 40;
                }
            }

            if (matches.Count == 0 || combined is not null) return;
            score = Math.Min(100, score);
            bool documentation = Path.GetExtension(displayPath).ToLowerInvariant() is ".md" or ".log" or ".lo";
            FindingSeverity severity = documentation ? FindingSeverity.Information :
                score >= 60 ? FindingSeverity.High : score >= 30 ? FindingSeverity.Medium : FindingSeverity.Low;
            report.Findings.Add(new Finding
            {
                RuleId = "CONTENT-SUSPICIOUS-STRINGS",
                Category = FindingCategory.File,
                Severity = severity,
                Score = score,
                Title = documentation ? "说明或日志中引用了风险特征" : "内容命中 Steam 假红信家族特征",
                Description = string.Join("，", matches),
                Target = remediationTarget,
                Evidence = $"内容位置：{displayPath}",
                Sha256 = sha256,
                WorkshopId = workshopId,
                IsKnownMalware = false,
                CanRemediate = false,
                SuggestedActions = [SuggestedActionKind.ReviewOnly]
            });
        }
    }


    private static async Task<long> CopyWithLimitAsync(
        Stream input,
        Stream output,
        long limit,
        CancellationToken cancellationToken,
        Action<long>? onBytes = null)
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
                onBytes?.Invoke(read);
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
        CancellationToken cancellationToken,
        ArchivePasswordReuseScope preferredScope,
        ArchivePasswordPromptKind kind)
    {
        ArchivePasswordRequest request = new(
            Guid.NewGuid().ToString("N"), displayPath, sha256, format, depth, workshopId, reason, preferredScope, kind);
        return provider.RequestPasswordAsync(request, cancellationToken);
    }

    private static bool LooksLikePasswordFailure(Exception ex)
    {
        if (ex is OperationCanceledException) return false;
        if (ex is InvalidFormatException && ex.Message.Equals("bad password", StringComparison.OrdinalIgnoreCase)) return true;
        string message = ex.Message;
        // Never classify an I/O failure using a filename containing “密码” or “encrypted”.
        string[] phrases = ["wrong password", "invalid password", "password is required", "password required",
            "password must", "password verification", "password does not", "password did not", "password mismatch"];
        return phrases.Any(phrase => message.Contains(phrase, StringComparison.OrdinalIgnoreCase));
    }

    private static bool IsUnexpectedExecutable(FileTypeResult type, string extension, string? projectType)
    {
        if (string.Equals(projectType, "trusted-default", StringComparison.OrdinalIgnoreCase)) return false;
        if (projectType is "workshop" or "mod" or "plugin") return false;
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
        // Single-stream formats such as GZip may have no embedded filename.
        if (string.IsNullOrWhiteSpace(name)) return false;
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
        // Keep append O(1) for large libraries. Presentation/export deduplicates notes.
        report.CoverageNotes.Add(message);
        report.Findings.Add(new Finding
        {
            RuleId = ruleId,
            Category = FindingCategory.Coverage,
            Severity = FindingSeverity.Information,
            Score = 0,
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
        _passwords.Clear();
        _amsiUnavailableCounts.Clear();
        _amsi.Dispose();
        _disposed = true;
        GC.SuppressFinalize(this);
    }

    private sealed class ArchiveBudget(ScanOptions options)
    {
        public long FilesVisited { get; set; }
        public long DirectoryEntries { get; set; }
        public long ArchiveEntries { get; set; }
        public long ExpandedBytes { get; set; }
        public ScanOptions Options { get; } = options;
    }
}
