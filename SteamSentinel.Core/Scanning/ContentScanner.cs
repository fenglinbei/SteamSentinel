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

public sealed partial class ContentScanner : IDisposable
{
    private readonly RuleSet _rules;
    private readonly ArchivePasswordCache _passwords = new();
    private readonly Dictionary<Guid, int> _amsiUnavailableCounts = [];
    private readonly AmsiScanner _amsi = new();
    private readonly SemaphoreSlim _scanGate = new(1, 1);
    private bool _disposed;
    private readonly ScanResourceGuard _resources = new();
    private ScanReport? _archiveBudgetReport;
    private ArchiveBudget _archiveBudget = new();
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
        ObjectDisposedException.ThrowIf(_disposed, this);
        try
        {
            await _scanGate.WaitAsync(cancellationToken);
        }
        catch (OperationCanceledException)
        {
            report.Coverage = ScanCoverage.Partial;
            report.RootSummaries.Add(new ScanRootSummary(root, ScanCoverage.Partial, 0, 0, 0));
            throw;
        }
        try
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
        finally
        {
            _scanGate.Release();
        }
    }

    private async Task ScanRootCoreAsync(
        string root, ScanReport report, ScanOptions options, IArchivePasswordProvider passwordProvider,
        IProgress<ScanProgress>? progress, CancellationToken cancellationToken, string? workshopId, string? projectType)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        string fullRoot = Path.GetFullPath(root);
        if (IsExcluded(fullRoot, options.ExcludedRoots))
        {
            AddCoverage(report, $"所选根路径位于排除范围，未扫描：{fullRoot}", fullRoot, workshopId, "SCAN-EXCLUDED");
            return;
        }
        if (!ContentDiscovery.IsLocalSafePath(fullRoot))
        { AddCoverage(report, $"已跳过网络路径或重解析点：{fullRoot}", fullRoot, workshopId); return; }
        ArchiveBudget archiveBudget = GetArchiveBudget(report);
        if (File.Exists(fullRoot))
        {
            await ScanFileAsync(fullRoot, fullRoot, fullRoot, report, options, passwordProvider, progress,
                cancellationToken, 0, workshopId, projectType, archiveBudget);
            Checkpoint?.Invoke(report);
            return;
        }

        if (!Directory.Exists(fullRoot))
        {
            AddCoverage(report, $"路径不存在：{fullRoot}", fullRoot, workshopId);
            return;
        }

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

                int directoryLimit = (int)Math.Clamp((long)options.MaximumFiles - archiveBudget.DirectoryEntries + 1, 0, int.MaxValue);
                foreach (string child in Directory.EnumerateDirectories(directory).Take(directoryLimit))
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    if (++archiveBudget.DirectoryEntries > options.MaximumFiles) { AddCoverage(report, "目录数量达到扫描上限", fullRoot, workshopId); return; }
                    pending.Push(child);
                }
                foreach (string file in Directory.EnumerateFiles(directory).Take((int)Math.Clamp(
                             (long)options.MaximumFiles - report.Metrics.FilesVisited + 1, 0, int.MaxValue))
                    .Chunk(512).SelectMany(chunk => chunk.OrderBy(ContentPriority)))
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    if (IsExcluded(file, options.ExcludedRoots)) continue;
                    if (report.Metrics.FilesVisited >= options.MaximumFiles)
                    {
                        AddCoverage(report, $"文件数量达到上限 {options.MaximumFiles}，剩余内容未扫描。", fullRoot, workshopId);
                        return;
                    }
                    await ScanFileAsync(file, file, file, report, options, passwordProvider, progress,
                        cancellationToken, 0, workshopId, projectType, archiveBudget);
                    Checkpoint?.Invoke(report);
                }
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                AddCoverage(report, $"无法读取目录：{directory}，原因：{ex.Message}", directory, workshopId);
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

    private async Task ScanStructuredAsync(string physicalPath, string displayPath, string target, DetectedFileType type,
        string? sha256, ScanReport report, ScanOptions options, IArchivePasswordProvider passwords,
        IProgress<ScanProgress>? progress, CancellationToken token, int depth, string? workshopId, string? projectType, ArchiveBudget budget)
    {
        int checkpointFinding = report.Findings.Count;
        using TemporaryDirectory temp = new();
        ContainerResourceBudget sharedBudget = ContainerBudget(report, options, token);
        long actualLimit = ActualExpandedLimit(options);
        long remaining = Math.Min(Math.Max(0, options.MaximumExpandedBytes - budget.ExpandedBytes),
            Math.Max(0, actualLimit - budget.ActualExpandedBytes));
        int entries = (int)Math.Max(0, Math.Min(options.MaximumArchiveEntries - budget.ArchiveEntries, sharedBudget.Limits.MaximumEntries - report.Metrics.ArchiveEntriesVisited));
        long entryLimit = Math.Min(options.MaximumEntryBytes, sharedBudget.Limits.MaximumEntryBytes);
        StructuredInspection result = new(sharedBudget);
        bool metadataPublished = false;
        try
        {
            result = type == DetectedFileType.Cabinet
                ? StructuredContainerInspector.ReadCabinet(physicalPath, temp, entryLimit, remaining, entries, token, sharedBudget, result)
                : StructuredContainerInspector.ReadMsi(physicalPath, temp, entryLimit, remaining, entries, token, sharedBudget, result);
            budget.ExpandedBytes += result.ExpandedBytes;
            budget.ActualExpandedBytes += result.ExpandedBytes;
            budget.AttemptedArchiveEntries += result.Members.Count;
            report.Metrics.ArchiveBytesExpanded += result.ExpandedBytes;
            budget.ArchiveEntries += result.Members.Count;
            report.Metrics.ArchiveEntriesVisited += result.Members.Count;
            PublishMetadata();
            foreach (StructuredMember member in result.Members)
            {
                token.ThrowIfCancellationRequested();
                if (!File.Exists(member.Path)) { AddCoverage(report, "安装包成员展开失败：" + member.Name, target, workshopId); continue; }
                string virtualPath = displayPath + "!/" + SanitizeEntryDisplayName(member.Name);
                if (IsUnsafeArchiveName(member.Name))
                {
                    AddUnsafeArchiveFinding(report, target, virtualPath, workshopId);
                    report.Findings[^1].TargetSha256 = _structuredParent?.OriginalTargetSha256 ?? sha256;
                }
                await ScanFileAsync(member.Path, displayPath + "!/" + SanitizeEntryDisplayName(member.Name), target, report,
                    options, passwords, progress, token, depth + 1, workshopId, projectType, budget);
                if (depth == 0 && sha256 is not null)
                {
                    foreach (Finding finding in report.Findings.Skip(checkpointFinding))
                    {
                        finding.ContentPath ??= displayPath;
                        finding.TargetSha256 ??= sha256;
                    }
                    Checkpoint?.Invoke(report);
                    checkpointFinding = report.Findings.Count;
                }
            }
        }
        finally
        {
            try { PublishMetadata(); }
            finally
            {
                result.Dispose();
                temp.Dispose();
                result.ReconcileTemporary();
            }
        }

        void PublishMetadata()
        {
            if (metadataPublished) return;
            metadataPublished = true;
            if (report.Containers is { } containers)
                foreach (string note in result.AccountingNotes.Where(note => !containers.Checks.Contains(note)).Take(Math.Max(0, 512 - containers.Checks.Count)))
                    containers.Checks.Add(note);
            foreach (string note in result.Notes.Distinct()) AddCoverage(report, ScriptSignals.Redact(note) + "：" + displayPath,
                target, workshopId, "INSTALLER-PARTIAL");
            if (result.Recognized && type == DetectedFileType.CompoundDocument)
            {
                MsiActionAnalysis? semantics = result.MsiAnalysis;
                IReadOnlyList<string> signals = semantics?.ContentSignals ?? [];
                IReadOnlyList<string> linkedSignals = semantics?.LinkedSignals ?? [];
                bool suspicious = signals.Count > 0 || linkedSignals.Count > 0;
                report.Findings.Add(new Finding
                {
                    RuleId = "INSTALLER-STRUCTURE",
                    Category = FindingCategory.Archive,
                    Severity = suspicious ? FindingSeverity.High : FindingSeverity.Information,
                    Score = signals.Count > 0 ? 85 : linkedSignals.Count > 0 ? 65 : 5,
                    Title = suspicious ? "安装包自定义动作包含可疑内容或声明关联" : "已只读检查安装包结构",
                    Description = $"读取 {result.Msi?.ReadRows ?? 0} 条安装表记录、{result.Members.Count} 个内嵌成员，未安装或执行自定义动作。" +
                        (suspicious ? ScriptSignals.Redact(string.Join("，", signals.Concat(linkedSignals).Take(8))) : "存在自定义动作本身不代表恶意。") +
                        "属性/文件关联为静态声明；证书或 PAC 未在表中出现，不能排除程序运行后设置。",
                    Target = target,
                    Sha256 = sha256,
                    ContentPath = displayPath,
                    TargetSha256 = _structuredParent?.OriginalTargetSha256 ?? sha256,
                    Evidence = ScriptSignals.Redact(string.Join("\n", (signals.Concat(linkedSignals)).Concat(semantics?.Evidence ?? result.Metadata))),
                    AssociationEvidenceTier = suspicious ? RelatedEvidenceTier.RelatedRisk : RelatedEvidenceTier.Observation,
                    CanRemediate = signals.Count > 0,
                    SuggestedActions = signals.Count > 0 ? [SuggestedActionKind.QuarantineFile] : [SuggestedActionKind.ReviewOnly]
                });
            }
        }
    }

    private sealed class PasswordNeededException : Exception;

    private readonly record struct PasswordCandidate(
        string Value,
        bool FromPriorCache,
        ArchivePasswordReuseScope Scope);

    private static bool IsArchivePasswordFailure(Exception ex, bool encrypted, bool hasPassword) =>
        ex is PasswordNeededException or SharpCompress.Common.CryptographicException or System.Security.Cryptography.CryptographicException ||
        LooksLikePasswordFailure(ex) ||
        (encrypted && hasPassword && ex is SharpCompressException);

    private static long SaturatingMultiply(long value, int multiplier)
    {
        if (value <= 0) return 0;
        return value > long.MaxValue / multiplier ? long.MaxValue : value * multiplier;
    }

    private static long ActualExpandedLimit(ScanOptions options) =>
        options.MaximumExpandedBytes;

    private async Task ScanStringsStreamAsync(Stream stream, string displayPath, string remediationTarget, string? sha256,
        ScanReport report, string? workshopId, string? projectType, CancellationToken cancellationToken, long maximumBytes)
    {
        var signals = await StreamingStringInspection.ReadAsync(stream,
            _rules.SuspiciousStrings.Select(rule => rule.Value), _rules.KnownDomains,
            maximumBytes, cancellationToken);
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
            normalized.StartsWith("\\", StringComparison.Ordinal)) return true;
        foreach (string segment in normalized.Split('\\', StringSplitOptions.RemoveEmptyEntries))
        {
            // A single '.' is a harmless relative-path prefix such as ./readme.txt.
            if (segment == ".") continue;
            string windowsName = segment.TrimEnd(' ', '.');
            if (windowsName == ".." || windowsName.Length == 0) return true;
        }
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

    private static void AddUnsafeArchiveFinding(ScanReport report, string target, string virtualPath, string? workshopId) =>
        report.Findings.Add(new Finding
        {
            RuleId = "ARCHIVE-PATH-TRAVERSAL",
            Category = FindingCategory.Archive,
            Severity = FindingSeverity.High,
            Score = 80,
            Title = "压缩包包含危险路径",
            Description = "未按压缩包中的路径写入文件，可在复核后隔离外层文件。",
            Target = target,
            ContentPath = virtualPath,
            Evidence = virtualPath,
            WorkshopId = workshopId,
            CanRemediate = true,
            SuggestedActions = [SuggestedActionKind.QuarantineFile]
        });

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
        _archiveBudgetReport = null;
        _amsiUnavailableCounts.Clear();
        _amsi.Dispose();
        _disposed = true;
        GC.SuppressFinalize(this);
    }

    private ArchiveBudget GetArchiveBudget(ScanReport report)
    {
        if (ReferenceEquals(_archiveBudgetReport, report)) return _archiveBudget;
        _passwords.Clear();
        _archiveBudgetReport = report;
        _archiveBudget = new ArchiveBudget();
        return _archiveBudget;
    }

    private sealed class ArchiveBudget
    {
        public long DirectoryEntries { get; set; }
        public long ArchiveEntries { get; set; }
        public long ExpandedBytes { get; set; }
        public long AttemptedArchiveEntries { get; set; }
        public long ActualExpandedBytes { get; set; }
        public long PasswordDecodeAttempts { get; set; }
    }
}
