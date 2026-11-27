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
    private long _lastProgressTick;
    internal Action<ScanReport>? Checkpoint { get; set; }
    internal Func<string, Microsoft.Win32.SafeHandles.SafeFileHandle, SignatureStatus> PeSignatureVerifier { get; init; } =
        static (path, handle) => AuthenticodeVerifier.VerifyOffline(path, handle).Status;

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
        { AddCoverage(report, MessageText.Create("Backend.Core.ContentScanner.ScanRootCoreAsync.02", (fullRoot)), fullRoot, workshopId, reasonCode: ReasonCodes.UnsafePath); return; }
        ArchiveBudget archiveBudget = GetArchiveBudget(report);
        _lastProgressTick = 0;
        if (File.Exists(fullRoot))
        {
            progress?.Report(new ScanProgress(
                MessageText.Create("Backend.Core.ContentScanner.ProgressStage"),
                fullRoot,
                0,
                1,
                MessageText.Create("Backend.Core.ContentScanner.ProgressDetail", report.Metrics.FilesVisited)));
            await ScanFileAsync(fullRoot, fullRoot, fullRoot, report, options, passwordProvider, progress,
                cancellationToken, 0, workshopId, projectType, archiveBudget);
            progress?.Report(new ScanProgress(
                MessageText.Create("Backend.Core.ContentScanner.ProgressStage"),
                fullRoot,
                1,
                1,
                MessageText.Create("Backend.Core.ContentScanner.ProgressDetail", report.Metrics.FilesVisited)));
            Checkpoint?.Invoke(report);
            return;
        }

        if (!Directory.Exists(fullRoot))
        {
            AddCoverage(report, MessageText.Create("Backend.Core.ContentScanner.ScanRootCoreAsync.03", (fullRoot)), fullRoot, workshopId);
            return;
        }

        Stack<(string Directory, string? TopBucket)> pending = new();
        pending.Push((fullRoot, null));
        Dictionary<string, int> bucketPendingCounts = new(StringComparer.OrdinalIgnoreCase);
        long topTotal = 0;
        long topDone = 0;
        long maxReportedUnits = 0;
        long rootFilesVisitedAtStart = report.Metrics.FilesVisited;
        bool initializedTopBuckets = false;

        void ReportProgressIfDue(string currentItem, bool force = false)
        {
            if (progress is null) return;
            long now = Environment.TickCount64;
            if (!force && _lastProgressTick != 0 && now - _lastProgressTick < 120) return;
            _lastProgressTick = now;
            if (topTotal > 0)
            {
                long deltaFiles = Math.Max(0, report.Metrics.FilesVisited - rootFilesVisitedAtStart);
                double subProgress = topDone < topTotal ? Math.Min(0.85, deltaFiles / 600.0) : 0;
                long raw = Math.Clamp((long)Math.Round(((topDone + subProgress) / topTotal) * 1000.0), 0, 1000);
                if (raw < maxReportedUnits) raw = maxReportedUnits;
                else maxReportedUnits = raw;
                progress.Report(new ScanProgress(
                    MessageText.Create("Backend.Core.ContentScanner.ProgressStage"),
                    currentItem,
                    raw,
                    1000,
                    MessageText.Create("Backend.Core.ContentScanner.ProgressDetail", report.Metrics.FilesVisited)));
            }
            else
            {
                progress.Report(new ScanProgress(
                    MessageText.Create("Backend.Core.ContentScanner.ProgressStage"),
                    currentItem,
                    report.Metrics.FilesVisited,
                    null,
                    MessageText.Create("Backend.Core.ContentScanner.ProgressDetail", report.Metrics.FilesVisited)));
            }
        }

        while (pending.Count > 0)
        {
            cancellationToken.ThrowIfCancellationRequested();
            (string directory, string? topBucket) = pending.Pop();
            if (IsExcluded(directory, options.ExcludedRoots))
            {
                CompleteBucketNode(topBucket);
                continue;
            }

            try
            {
                FileAttributes attributes = File.GetAttributes(directory);
                if ((attributes & FileAttributes.ReparsePoint) != 0 && Validation.IsRedirectingReparsePoint(directory))
                {
                    AddCoverage(report, MessageText.Create("Backend.Core.ContentScanner.ScanRootCoreAsync.04", (directory)), directory, workshopId);
                    CompleteBucketNode(topBucket);
                    continue;
                }

                List<string> immediateSubdirs = [];
                foreach (string child in Directory.EnumerateDirectories(directory))
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    if ((archiveBudget.DirectoryEntries & 255) == 0) _resources.Check(report);
                    if (++archiveBudget.DirectoryEntries > options.MaximumFiles &&
                        !ScanResourceSession.Allow("MaximumFiles", archiveBudget.DirectoryEntries, archiveBudget.DirectoryEntries - 1, known: false))
                    { AddCoverage(report, MessageText.Create("Backend.Core.ContentScanner.ScanRootCoreAsync.05"), fullRoot, workshopId, "SCAN-COUNT-LIMIT"); return; }
                    immediateSubdirs.Add(child);
                }

                bool collectingTop = !initializedTopBuckets && string.Equals(directory, fullRoot, StringComparison.OrdinalIgnoreCase);
                string[]? topFiles = null;
                if (collectingTop)
                {
                    initializedTopBuckets = true;
                    topFiles = Directory.EnumerateFiles(directory)
                        .Where(file => !IsExcluded(file, options.ExcludedRoots))
                        .ToArray();
                    topTotal = immediateSubdirs.Count + topFiles.Length;
                    ReportProgressIfDue(directory, force: true);
                }

                foreach (string child in immediateSubdirs)
                {
                    string bucketKey = collectingTop ? child : topBucket ?? child;
                    if (!IsExcluded(child, options.ExcludedRoots))
                    {
                        bucketPendingCounts[bucketKey] = bucketPendingCounts.GetValueOrDefault(bucketKey) + 1;
                        pending.Push((child, bucketKey));
                    }
                    else if (collectingTop)
                    {
                        topDone++;
                    }
                }

                int parallelism = FileParallelism(options);
                IEnumerable<string> fileSequence = topFiles is not null
                    ? topFiles
                    : Directory.EnumerateFiles(directory).Where(file => !IsExcluded(file, options.ExcludedRoots));
                foreach (string[] group in fileSequence
                    .Chunk(512).SelectMany(chunk => chunk.OrderBy(ContentPriority)).Chunk(parallelism))
                {
                    bool handledParallel = await TryScanParallelLeavesAsync(group, report, options, passwordProvider, progress, cancellationToken, workshopId, projectType);
                    if (handledParallel)
                    {
                        if (collectingTop) topDone += group.Length;
                        ReportProgressIfDue(group[^1]);
                        continue;
                    }
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
                        if (collectingTop) topDone++;
                        ReportProgressIfDue(file);
                        Checkpoint?.Invoke(report);
                    }
                }
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                AddCoverage(report, MessageText.Create("Backend.Core.ContentScanner.ScanRootCoreAsync.07", (directory), (ex.Message)), directory, workshopId);
            }
            finally
            {
                CompleteBucketNode(topBucket);
            }
        }

        if (topTotal > 0)
        {
            topDone = topTotal;
            maxReportedUnits = 1000;
            ReportProgressIfDue(fullRoot, force: true);
        }

        void CompleteBucketNode(string? bucketKey)
        {
            if (bucketKey is null) return;
            if (!bucketPendingCounts.TryGetValue(bucketKey, out int remaining)) return;
            if (remaining <= 1)
            {
                bucketPendingCounts.Remove(bucketKey);
                topDone++;
            }
            else
            {
                bucketPendingCounts[bucketKey] = remaining - 1;
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
                    Severity = suspicious ? FindingSeverity.Medium : FindingSeverity.Information,
                    Score = suspicious ? 40 : 5,
                    ReasonCode = suspicious ? "ScriptTokenCooccurrenceOnly" : null,
                    HandlingReason = suspicious ? FindingHandlingReason.InsufficientEvidence : FindingHandlingReason.None,
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
                    CanRemediate = false,
                    SuggestedActions = suspicious ? [SuggestedActionKind.ReviewOnly] : [SuggestedActionKind.None]
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
        ScanReport report, string? workshopId, string? projectType, CancellationToken cancellationToken, long maximumBytes,
        Func<bool>? hasValidOfflinePeSignature = null)
    {
        var signals = await StreamingStringInspection.ReadAsync(stream,
            _rules.SuspiciousStrings.Select(rule => rule.Value), _rules.KnownDomains,
            maximumBytes, cancellationToken);
        {
            List<MessageText> matches = [];
            bool Contains(string value) => signals.Raw.Contains(value);
            HeuristicMatch? combined = ContentHeuristics.Match(Contains, displayPath, workshopId);
            if (combined is null && !string.Equals(projectType, "trusted-default", StringComparison.OrdinalIgnoreCase) &&
                Path.GetExtension(displayPath).ToLowerInvariant() is not (".md" or ".log" or ".lo"))
            {
                IReadOnlyList<MessageText> scriptSignals = ScriptSignals.AnalyzeMessages(signals.Script.Contains);
                // 对具备有效离线 Authenticode 数字签名的合法 PE 二进制豁免纯脚本词语共现误报（仍保留强启发式、恶意哈希与域名规则）
                if (scriptSignals.Count > 0 && hasValidOfflinePeSignature?.Invoke() != true) report.Findings.Add(new Finding
                {
                    RuleId = "HEUR-SCRIPT-TOKEN-COOCCURRENCE",
                    Category = FindingCategory.File,
                    Severity = FindingSeverity.Medium,
                    Score = 40,
                    ReasonCode = "ScriptTokenCooccurrenceOnly",
                    HandlingReason = FindingHandlingReason.InsufficientEvidence,
                    TitleText = MessageText.Create("Backend.Core.ContentScanner.ScanStringsStreamAsync.01"),
                    DescriptionText = MessageText.Create("Scan.ScriptTokenCooccurrence.Description") + MessageText.List(scriptSignals),
                    Target = remediationTarget,
                    ContentPath = displayPath,
                    EvidenceLines = signals.Observations.Select(value => MessageText.Create(
                        "Scan.ScriptTokenCooccurrence.Window", value.Token, value.WindowByteOffset, value.Encoding,
                        MessageText.Create(value.Normalized ? "Scan.ScriptTokenCooccurrence.Normalized" : "Scan.ScriptTokenCooccurrence.Literal"))),
                    Sha256 = sha256,
                    WorkshopId = workshopId,
                    AssociationEvidenceTier = RelatedEvidenceTier.Observation,
                    CanRemediate = false,
                    SuggestedActions = [SuggestedActionKind.ReviewOnly]
                });
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
        string ruleId = "SCAN-PARTIAL",
        string? reasonCode = null)
    {
        report.Coverage = ScanCoverage.Partial;
        // Keep append O(1) for large libraries. Presentation/export deduplicates notes.
        report.AddCoverageNote(message);
        report.Findings.Add(new Finding
        {
            RuleId = ruleId,
            ReasonCode = reasonCode ?? ReasonCodes.ForRule(ruleId),
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
        // AMSI 为可选增强引擎：初始化失败或报错时仅记录诊断通知，绝不将扫描降级为 Partial
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
