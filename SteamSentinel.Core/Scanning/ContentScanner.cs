using SteamSentinel.Core.Reporting;
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
    private readonly Func<AmsiScanner> _amsiFactory;
    private readonly Lazy<AmsiScanner> _amsi;
    private readonly SemaphoreSlim _scanGate = new(1, 1);
    private bool _disposed;
    private readonly ScanResourceGuard _resources = new();
    private ScanReport? _archiveBudgetReport;
    private ArchiveBudget _archiveBudget = new();
    private string? _coverageRoot;
    internal Action<ScanReport>? Checkpoint { get; set; }

    public ContentScanner(RuleSet rules) : this(rules, () => new AmsiScanner()) { }

    internal ContentScanner(RuleSet rules, Func<AmsiScanner> amsiFactory)
    {
        _rules = rules;
        _amsiFactory = amsiFactory;
        _amsi = new(amsiFactory);
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
        report.ContentScanSettings = ScanEnhancements.ForExecution(options);
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
            int firstNode = report.Containers?.Nodes.Count ?? 0;
            bool completed = false;
            try
            {
                _coverageRoot = Path.GetFullPath(root);
                await ScanRootCoreAsync(root, report, options, passwordProvider, progress, cancellationToken, workshopId, projectType);
                if (report.Containers is { } graph)
                    VPetComponentLinks.Link(graph.Nodes.Skip(firstNode).ToArray(), cancellationToken);
                completed = true;
            }
            finally
            {
                _coverageRoot = previousRoot;
                if (!completed) report.Coverage = ScanCoverage.Partial;
                report.ContentScanSettings = ScanEnhancements.ForExecution(options);
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
            AddCoverage(report, MessageText.Create("Backend.Core.ContentScanner.ScanRootCoreAsync.01", (fullRoot)), fullRoot, workshopId, "SCAN-EXCLUDED");
            return;
        }
        if (!ContentDiscovery.IsLocalSafePath(fullRoot))
        { AddCoverage(report, MessageText.Create("Backend.Core.ContentScanner.ScanRootCoreAsync.02", (fullRoot)), fullRoot, workshopId); return; }
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
            AddCoverage(report, MessageText.Create("Backend.Core.ContentScanner.ScanRootCoreAsync.03", (fullRoot)), fullRoot, workshopId);
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
                    AddCoverage(report, MessageText.Create("Backend.Core.ContentScanner.ScanRootCoreAsync.04", (directory)), directory, workshopId);
                    continue;
                }

                foreach (string child in Directory.EnumerateDirectories(directory))
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    if ((archiveBudget.DirectoryEntries & 255) == 0) _resources.Check(report);
                    if (++archiveBudget.DirectoryEntries > options.MaximumFiles &&
                        !ScanResourceSession.Allow("MaximumFiles", archiveBudget.DirectoryEntries, archiveBudget.DirectoryEntries - 1, known: false))
                    { AddCoverage(report, MessageText.Create("Backend.Core.ContentScanner.ScanRootCoreAsync.05"), fullRoot, workshopId, "SCAN-COUNT-LIMIT"); return; }
                    pending.Push(child);
                }
                int parallelism = FileParallelism(options);
                foreach (string[] group in Directory.EnumerateFiles(directory)
                    .Where(file => !IsExcluded(file, options.ExcludedRoots))
                    .Chunk(512).SelectMany(chunk => chunk.OrderBy(ContentPriority)).Chunk(parallelism))
                {
                    if (await TryScanParallelLeavesAsync(group, report, options, passwordProvider, progress, cancellationToken, workshopId, projectType)) continue;
                    foreach (string file in group)
                    {
                    cancellationToken.ThrowIfCancellationRequested();
                    if (IsExcluded(file, options.ExcludedRoots)) continue;
                    if (report.Metrics.FilesVisited >= options.MaximumFiles &&
                        !ScanResourceSession.Allow("MaximumFiles", report.Metrics.FilesVisited + 1, report.Metrics.FilesVisited, known: false))
                    {
                        AddCoverage(report, MessageText.Create("Backend.Core.ContentScanner.ScanRootCoreAsync.06", (options.MaximumFiles)), fullRoot, workshopId, "SCAN-COUNT-LIMIT");
                        return;
                    }
                    await ScanFileAsync(file, file, file, report, options, passwordProvider, progress,
                        cancellationToken, 0, workshopId, projectType, archiveBudget);
                    Checkpoint?.Invoke(report);
                    }
                }
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                AddCoverage(report, MessageText.Create("Backend.Core.ContentScanner.ScanRootCoreAsync.07", (directory), (ex.Message)), directory, workshopId);
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
                if (!File.Exists(member.Path)) { AddCoverage(report, MessageText.Create("Backend.Core.ContentScanner.ScanStructuredAsync.01") + member.Name, target, workshopId); continue; }
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
                foreach (MessageText note in result.AccountingNoteTexts.Where(note => !containers.Checks.Contains(note.OriginalText)).Take(Math.Max(0, 512 - containers.Checks.Count)))
                    containers.AddCheck(note);
            foreach (MessageText note in result.NoteTexts.DistinctBy(note => note.OriginalText)) AddCoverage(report, note.RedactSecrets() + "：" + displayPath,
                target, workshopId, "INSTALLER-PARTIAL");
            if (result.Recognized && type == DetectedFileType.CompoundDocument)
            {
                MsiActionAnalysis? semantics = result.MsiAnalysis;
                IReadOnlyList<MessageText> signals = semantics?.ContentSignals.Texts.ToArray() ?? [];
                IReadOnlyList<MessageText> linkedSignals = semantics?.LinkedSignals.Texts.ToArray() ?? [];
                bool suspicious = signals.Count > 0 || linkedSignals.Count > 0;
                report.Findings.Add(new Finding
                {
                    RuleId = "INSTALLER-STRUCTURE",
                    Category = FindingCategory.Archive,
                    Severity = suspicious ? FindingSeverity.High : FindingSeverity.Information,
                    Score = signals.Count > 0 ? 85 : linkedSignals.Count > 0 ? 65 : 5,
                    TitleText = suspicious ? MessageText.Create("Backend.Core.ContentScanner.ScanStructuredAsync.02") : MessageText.Create("Backend.Core.ContentScanner.ScanStructuredAsync.03"),
                    DescriptionText = MessageText.Create("Backend.Core.ContentScanner.ScanStructuredAsync.04", (result.Msi?.ReadRows ?? 0), (result.Members.Count)) +
                        (suspicious ? MessageText.List(signals.Concat(linkedSignals).Take(8)).RedactSecrets() : MessageText.Create("Backend.Core.ContentScanner.ScanStructuredAsync.05")) +
                        MessageText.Create("Backend.Core.ContentScanner.ScanStructuredAsync.06"),
                    Target = target,
                    Sha256 = sha256,
                    ContentPath = displayPath,
                    TargetSha256 = _structuredParent?.OriginalTargetSha256 ?? sha256,
                    EvidenceLines = signals.Concat(linkedSignals).Concat(semantics?.Evidence.Texts ?? result.Metadata.Select(value => (MessageText)value)).Select(value => value.RedactSecrets()),
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
            List<MessageText> matches = [];
            bool Contains(string value) => signals.Raw.Contains(value);
            HeuristicMatch? combined = ContentHeuristics.Match(Contains, displayPath);
            if (combined is null && Path.GetExtension(displayPath).ToLowerInvariant() is not (".md" or ".log" or ".lo"))
            {
                IReadOnlyList<MessageText> scriptSignals = ScriptSignals.AnalyzeMessages(signals.Script.Contains);
                if (scriptSignals.Count > 0) combined = new HeuristicMatch("HEUR-STEAM-DEPLOYMENT-CHAIN",
                    MessageText.Create("Backend.Core.ContentScanner.ScanStringsStreamAsync.01"), MessageText.List(scriptSignals), 90);
            }
            if (combined is not null && !string.Equals(projectType, "trusted-default", StringComparison.OrdinalIgnoreCase))
                report.Findings.Add(new Finding
                {
                    RuleId = combined.Id,
                    Category = FindingCategory.File,
                    Severity = FindingSeverity.High,
                    Score = combined.Score,
                    TitleText = combined.Title,
                    DescriptionText = combined.Evidence,
                    Target = remediationTarget,
                    ContentPath = displayPath,
                    EvidenceText = MessageText.Create("Backend.Core.ContentScanner.ScanStringsStreamAsync.02", (displayPath)),
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
                    matches.Add(MessageText.Create("Common.LabelValue", rule.Id, rule.LabelText));
                    score += rule.Score;
                }
            }

            foreach (string domain in _rules.KnownDomains)
            {
                if (Contains(domain))
                {
                    matches.Add(MessageText.Create("Backend.Core.ContentScanner.ScanStringsStreamAsync.03", (domain)));
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
                TitleText = documentation ? MessageText.Create("Backend.Core.ContentScanner.ScanStringsStreamAsync.04") : MessageText.Create("Backend.Core.ContentScanner.ScanStringsStreamAsync.05"),
                DescriptionText = MessageText.List(matches),
                Target = remediationTarget,
                EvidenceText = MessageText.Create("Backend.Core.ContentScanner.ScanStringsStreamAsync.06", (displayPath)),
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
        MessageText reason,
        IArchivePasswordProvider provider,
        CancellationToken cancellationToken,
        ArchivePasswordReuseScope preferredScope,
        ArchivePasswordPromptKind kind)
    {
        ArchivePasswordRequest request = new(
            Guid.NewGuid().ToString("N"), displayPath, sha256, format, depth, workshopId, reason.OriginalText, preferredScope, kind)
        { ReasonMessage = reason.Message };
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
            TitleText = MessageText.Create("Backend.Core.ContentScanner.AddUnsafeArchiveFinding.01"),
            DescriptionText = MessageText.Create("Backend.Core.ContentScanner.AddUnsafeArchiveFinding.02"),
            Target = target,
            ContentPath = virtualPath,
            EvidenceText = virtualPath,
            WorkshopId = workshopId,
            CanRemediate = true,
            SuggestedActions = [SuggestedActionKind.QuarantineFile]
        });

    private static string SanitizeEntryDisplayName(string? value)
    {
        if (string.IsNullOrEmpty(value)) return MessageText.Create("Backend.Core.ContentScanner.SanitizeEntryDisplayName.01");
        string clean = value.Replace('\r', '_').Replace('\n', '_').Replace('\0', '_');
        return clean.Length <= 500 ? clean : clean[..500] + "…";
    }

    private static void AddCoverage(
        ScanReport report,
        MessageText message,
        string target,
        string? workshopId,
        string ruleId = "SCAN-PARTIAL")
    {
        report.Coverage = ScanCoverage.Partial;
        // Keep append O(1) for large libraries. Presentation/export deduplicates notes.
        report.AddCoverageNote(message);
        report.Findings.Add(new Finding
        {
            RuleId = ruleId,
            ReasonCode = ReasonCodes.ForRule(ruleId),
            Category = FindingCategory.Coverage,
            Severity = FindingSeverity.Information,
            Score = 0,
            TitleText = MessageText.Create("Backend.Core.ContentScanner.AddCoverage.01"),
            DescriptionText = message,
            Target = target,
            EvidenceText = workshopId is null ? string.Empty : MessageText.Create("Backend.Core.ContentScanner.AddCoverage.02", (workshopId)),
            WorkshopId = workshopId,
            CanRemediate = false,
            SuggestedActions = [SuggestedActionKind.ReviewOnly]
        });
    }

    private void AddAmsiCoverage(ScanReport report, MessageText detail)
    {
        report.Coverage = ScanCoverage.Partial;
        int count = _amsiUnavailableCounts.GetValueOrDefault(report.ScanId) + 1;
        _amsiUnavailableCounts[report.ScanId] = count;
        MessageText prefix = MessageText.Create("Backend.Core.ContentScanner.AddAmsiCoverage.01");
        MessageText message = MessageText.Create("Backend.Core.ContentScanner.AddAmsiCoverage.02", (prefix), (System.FormattableString.Invariant($"{count:N0}")), (detail));
        int existing = report.CoverageNotices.FindIndex(note => note.ReasonCode == ReasonCodes.AmsiUnavailable);
        CoverageNotice notice = new(ReasonCodes.AmsiUnavailable, message);
        if (existing >= 0) report.CoverageNotices[existing] = notice;
        else report.CoverageNotices.Add(notice);
    }

    public void Dispose()
    {
        if (_disposed) return;
        _passwords.Clear();
        _archiveBudgetReport = null;
        _amsiUnavailableCounts.Clear();
        if (_amsi.IsValueCreated) _amsi.Value.Dispose();
        foreach (var worker in _leafWorkers) worker.Scanner.Dispose();
        _disposed = true;
        GC.SuppressFinalize(this);
    }

    private ArchiveBudget GetArchiveBudget(ScanReport report)
    {
        if (ReferenceEquals(_archiveBudgetReport, report)) return _archiveBudget;
        _passwords.Clear();
        foreach (Guid other in _amsiUnavailableCounts.Keys.Where(id => id != report.ScanId).ToArray())
            _amsiUnavailableCounts.Remove(other);
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
