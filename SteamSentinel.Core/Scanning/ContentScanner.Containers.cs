using System.Buffers;
using SteamSentinel.Core.Reporting;
using System.Security.Cryptography;
using SharpCompress.Common;
using SteamSentinel.Core.Inspection;
using SteamSentinel.Core.Models;
using SteamSentinel.Core.Steam;
using SteamSentinel.Core.Utilities;

namespace SteamSentinel.Core.Scanning;

public sealed partial class ContentScanner
{
    private ScanReport? _containerOwner;
    private ContainerResourceBudget? _containerBudget;
    private readonly Dictionary<string, ContainerScanNode> _decodedGroups = new(StringComparer.Ordinal);
    private readonly Dictionary<Guid, List<ContainerScanNode>> _containerChildren = [];
    private readonly HashSet<Guid> _unfinishedContainers = [];
    private ContainerScanNode? _structuredParent;
    private long _lastContainerProgress;

    private sealed record ContainerContext(ScanReport Report, ScanOptions Options, IArchivePasswordProvider Passwords,
        IProgress<ScanProgress>? Progress, CancellationToken Token, string? WorkshopId, string? ProjectType,
        ArchiveBudget LegacyBudget, ContainerResourceBudget Budget);

    private ContainerResourceBudget ContainerBudget(ScanReport report, ScanOptions options, CancellationToken token)
    {
        if (ReferenceEquals(_containerOwner, report)) return _containerBudget!;
        ContainerResourceLimits limits = options.ContainerLimits ?? new()
        {
            MaximumEntryBytes = options.MaximumEntryBytes,
            MaximumExpandedBytes = options.MaximumExpandedBytes,
            MaximumWorkBytes = options.Mode == ScanMode.Quick ? 4L * 1024 * 1024 * 1024 : 64L * 1024 * 1024 * 1024,
            MaximumTemporaryBytes = options.Mode == ScanMode.Quick ? 2L * 1024 * 1024 * 1024 : 16L * 1024 * 1024 * 1024,
            MaximumDepth = options.MaximumArchiveDepth,
            MaximumEntries = options.MaximumArchiveEntries,
            MaximumDurationSeconds = options.Mode == ScanMode.Quick ? 300 : 1800,
            MaximumCompressionRatio = options.MaximumCompressionRatio
        };
        _containerBudget = new(limits, token); _containerOwner = report; _decodedGroups.Clear();
        report.Containers ??= new(); report.Containers.Limits = limits;
        _containerChildren.Clear(); _unfinishedContainers.Clear();
        foreach (ContainerScanNode existing in report.Containers.Nodes) IndexContainer(existing);
        return _containerBudget;
    }

    private void IndexContainer(ContainerScanNode node)
    {
        if (node.ParentId is Guid parent)
        {
            if (!_containerChildren.TryGetValue(parent, out List<ContainerScanNode>? children))
                _containerChildren[parent] = children = [];
            children.Add(node);
        }
        if (node.Overall != ContainerStageStatus.Complete) _unfinishedContainers.Add(node.NodeId);
    }

    private IEnumerable<ContainerScanNode> ChildrenOf(ContainerScanNode node) =>
        _containerChildren.TryGetValue(node.NodeId, out List<ContainerScanNode>? children) ? children : [];

    private Task ScanFileAsync(string physicalPath, string displayPath, string remediationTarget, ScanReport report,
        ScanOptions options, IArchivePasswordProvider passwordProvider, IProgress<ScanProgress>? progress,
        CancellationToken cancellationToken, int archiveDepth, string? workshopId, string? projectType, ArchiveBudget budget)
    {
        ContainerContext context = new(report, options, passwordProvider, progress, cancellationToken,
            workshopId, projectType, budget, ContainerBudget(report, options, cancellationToken));
        return ScanContainerFileAsync(new(physicalPath, displayPath), remediationTarget, context, _structuredParent,
            archiveDepth, _structuredParent is null ? ContainerNodeKind.File : ContainerNodeKind.ArchiveMember, null);
    }

    private ContainerScanNode AddContainerNode(ContainerContext context, string display, string target,
        ContainerScanNode? parent, int depth, ContainerNodeKind kind, long length, long? offset = null)
    {
        ContainerScanReport containers = context.Report.Containers!;
        if (containers.Nodes.Count >= context.Budget.Limits.MaximumNodes &&
            !ScanResourceSession.Allow("ContainerLimits.MaximumNodes", (long)containers.Nodes.Count + 1, containers.Nodes.Count, known: false))
            throw MessageExceptions.Create(MessageText.Create("Backend.Core.ContentScanner.Containers.AddContainerNode.01"), sourceText => new ScanResourceLimitException(sourceText));
        ContainerScanNode node = new()
        {
            ParentId = parent?.NodeId,
            Kind = kind,
            DisplayPath = display,
            OriginalTarget = target,
            OriginalTargetSha256 = parent?.OriginalTargetSha256,
            Depth = depth,
            Length = length,
            ParentOffset = offset,
            ParentLength = offset.HasValue ? length : null
        };
        containers.Nodes.Add(node); IndexContainer(node); return node;
    }

    private static bool StageComplete(ContainerStageStatus value) => value is ContainerStageStatus.Complete or ContainerStageStatus.NotRequested;

    private void FinishContainer(ContainerContext context, ContainerScanNode node)
    {
        if (node.Overall == ContainerStageStatus.Pending)
            node.Overall = ContainerCompletionStatus(node, ChildrenOf(node));
        node.CompletedAtUtc = DateTimeOffset.UtcNow; node.Revision++;
        ContainerScanReport report = context.Report.Containers!;
        if (node.Overall == ContainerStageStatus.Complete) _unfinishedContainers.Remove(node.NodeId);
        else _unfinishedContainers.Add(node.NodeId);
        report.Resources = context.Budget.Snapshot(); report.Complete = _unfinishedContainers.Count == 0;
        if (node.Overall != ContainerStageStatus.Complete) context.Report.Coverage = ScanCoverage.Partial;
        Checkpoint?.Invoke(context.Report);
    }

    private void ContainerGap(ContainerContext context, ContainerScanNode node, ContainerStageStatus status, MessageText detail,
        string rule = "CONTAINER-PARTIAL")
    {
        node.Overall = status; if (node.Details.Count < 32) node.AddDetail(ShortContainerDetail(detail));
        if (rule is "CONTENT-BYTE-BUDGET" or "QUICK-FILE-SIZE")
        {
            CoverageAggregation.Add(context.Report, rule, _coverageRoot ?? node.OriginalTarget, node.DisplayPath);
            return;
        }
        AddCoverage(context.Report, detail + "：" + node.DisplayPath, node.OriginalTarget, context.WorkshopId, rule);
    }

    private static string ShortContainerDetail(string detail)
    {
        string redacted = ScriptSignals.RedactSecrets(detail); return redacted.Length > 2048 ? redacted[..2047] + "…" : redacted;
    }

    private static MessageText ShortContainerDetail(MessageText detail)
    {
        MessageText redacted = detail.RedactSecrets();
        return redacted.OriginalText.Length > 2048 ? new(redacted.OriginalText[..2047] + "…") : redacted;
    }

    private async Task ScanContainerFileAsync(ArchiveVolumeCandidate source, string target, ContainerContext context,
        ContainerScanNode? parent, int depth, ContainerNodeKind kind, IReadOnlyList<ArchiveVolumeCandidate>? siblings,
        long? parentOffset = null, string? verifiedHash = null)
    {
        using IDisposable resourceTarget = ScanResourceSession.EnterTarget(source.DisplayName);
        context.Token.ThrowIfCancellationRequested(); context.Budget.Check(); _resources.Check(context.Report);
        if (context.Report.Metrics.FilesVisited >= context.Options.MaximumFiles &&
            !ScanResourceSession.Allow("MaximumFiles", context.Report.Metrics.FilesVisited + 1, context.Report.Metrics.FilesVisited, known: false))
            throw MessageExceptions.Create(MessageText.Create("Backend.Core.ContentScanner.Containers.ScanContainerFileAsync.01"), sourceText => new ScanResourceLimitException(sourceText));
        ContainerScanNode node = AddContainerNode(context, source.DisplayName, target, parent, depth, kind, source.Length ?? 0, parentOffset);
        int firstFinding = context.Report.Findings.Count;
        try
        {
            context.Budget.Progress = () =>
            {
                long now = Environment.TickCount64;
                if (now - _lastContainerProgress < 250) return; _lastContainerProgress = now;
                ContainerResourceSnapshot resource = context.Budget.Snapshot();
                context.Progress?.Report(new(MessageText.Create("Backend.Core.ContentScanner.Containers.ScanContainerFileAsync.02"), source.DisplayName, resource.ReadBytes + resource.DecodedBytes, null,
                    MessageText.Create("Backend.Core.ContentScanner.Containers.ScanContainerFileAsync.03", (depth), (System.FormattableString.Invariant($"{resource.ReadBytes:N0}")), (System.FormattableString.Invariant($"{resource.DecodedBytes:N0}")), (System.FormattableString.Invariant($"{resource.CurrentTemporaryBytes:N0}")))));
            };
            PreparedLeaf? prepared = parent is null && _preparedLeaf?.Path == source.PhysicalPath ? _preparedLeaf : null;
            // Open performs the path/handle checks once; a prepared handle has already
            // passed the same checks and remains deny-write/delete. Revalidate at exit.
            await using FileStream file = prepared?.Stream ?? RelatedArtifactReader.Open(source.PhysicalPath);
            long length = source.Length ?? checked(file.Length - source.Offset); node.Length = length;
            using BoundedReadOnlyStream stream = new(file, source.Offset, length, budget: context.Budget);
            context.Report.Metrics.FilesVisited++;
            FileTypeResult type = prepared?.Type ?? await FileTypeDetector.DetectAsync(stream, source.DisplayName, context.Token);
            node.FormatText = type.LabelText; node.Recognition = ContainerStageStatus.Complete;
            node.Integrity = kind == ContainerNodeKind.ArchiveMember
                ? parent?.Integrity == ContainerStageStatus.UnsupportedIntegrity ? ContainerStageStatus.UnsupportedIntegrity : ContainerStageStatus.Complete
                : ContainerStageStatus.NotRequested;
            bool suspiciousExtension = _rules.DangerousExtensions.Contains(Path.GetExtension(source.DisplayName), StringComparer.OrdinalIgnoreCase);
            bool archiveCandidate = type.IsArchive || _rules.ArchiveExtensions.Contains(Path.GetExtension(source.DisplayName), StringComparer.OrdinalIgnoreCase);
            ContainerRangeInspection? ranges = null;
            if (type.Type is DetectedFileType.Mp4 or DetectedFileType.PortableExecutable)
            {
                stream.Position = 0;
                ranges = type.Type == DetectedFileType.Mp4 ? ContainerRangeInspector.InspectMp4(stream, context.Token, context.Options.RangeLimits) :
                    ContainerRangeInspector.InspectPeSfx(stream, context.Token, context.Options.RangeLimits);
                if (type.Type == DetectedFileType.Mp4) context.Report.Metrics.MediaStructuresChecked++;
                node.Engines.Add(new()
                {
                    EngineText = MessageText.Create("Backend.Core.ContentScanner.Containers.ScanContainerFileAsync.05"),
                    Status = ranges.Status == ContainerRangeStatus.Validated ? ContainerStageStatus.Complete : ContainerStageStatus.Partial,
                    Offset = 0,
                    Length = length,
                    DetailText = ranges.DetailText
                });
                foreach (ContainerRangeSfxDirective directive in ranges.SfxConfiguration.Take(24))
                    node.AddDetail(ShortContainerDetail(MessageText.Create("Backend.Core.ContentScanner.Containers.ScanContainerFileAsync.06", (directive.Name), (directive.Value))));
            }
            bool quickMedia = context.Options.Mode == ScanMode.Quick && type.Type == DetectedFileType.Mp4 &&
                ranges?.Status == ContainerRangeStatus.Validated && !type.ExtensionMismatch;
            long charged = Math.Max(0, context.Report.Metrics.BytesHashed -
                (context.Options.Mode == ScanMode.Quick ? context.Report.Metrics.QuickPriorityBytesHashed : 0));
            long remaining = context.Options.MaximumContentBytes == long.MaxValue ? long.MaxValue : Math.Max(0, context.Options.MaximumContentBytes - charged);
            bool priority = context.Options.Mode == ScanMode.Quick && length > remaining && length <= context.Options.MaximumQuickPriorityFileBytes &&
                (type.IsExecutableOrScript || suspiciousExtension) && length <= context.Options.MaximumQuickPriorityBytes - context.Report.Metrics.QuickPriorityBytesHashed;
            bool tooLarge = context.Options.Mode == ScanMode.Quick && length > context.Options.MaximumQuickFileBytes;
            if (tooLarge && ScanResourceSession.Allow("MaximumQuickFileBytes", length)) tooLarge = false;
            if (!tooLarge && length > remaining && !priority && context.Options.MaximumContentBytes != long.MaxValue &&
                length <= long.MaxValue - charged && ScanResourceSession.Allow("MaximumContentBytes", charged + length, charged))
                remaining = Math.Max(0, context.Options.MaximumContentBytes - charged);
            bool readAllowed = !tooLarge && (length <= remaining || priority);
            bool shouldHash = context.Options.HashEveryFile || context.Options.Mode != ScanMode.Quick || length <= 64L * 1024 * 1024 ||
                suspiciousExtension || archiveCandidate || type.IsExecutableOrScript || type.Type == DetectedFileType.Mp4;
            if (verifiedHash is not null || shouldHash && readAllowed && !quickMedia)
            {
                stream.Position = 0;
                node.Sha256 = await Hashing.Sha256StreamAsync(stream, context.Token, bytes =>
                {
                    context.Report.Metrics.BytesHashed += bytes;
                    if (priority) context.Report.Metrics.QuickPriorityBytesHashed += bytes;
                }, maximumBytes: length);
                if (verifiedHash is not null && !node.Sha256.Equals(verifiedHash, StringComparison.OrdinalIgnoreCase))
                {
                    node.Integrity = ContainerStageStatus.SourceChanged;
                    ContainerGap(context, node, ContainerStageStatus.SourceChanged, MessageText.Create("Backend.Core.ContentScanner.Containers.ScanContainerFileAsync.07")); return;
                }
            }
            if (parent is null) node.OriginalTargetSha256 = node.Sha256;
            node.Engines.Add(new()
            {
                Engine = "SHA-256",
                Status = node.Sha256 is null ? ContainerStageStatus.Skipped : ContainerStageStatus.Complete,
                Offset = 0,
                Length = node.Sha256 is null ? 0 : length,
                DetailText = node.Sha256 is null ? MessageText.Create("Backend.Core.ContentScanner.Containers.ScanContainerFileAsync.08") : MessageText.Create("Backend.Core.ContentScanner.Containers.ScanContainerFileAsync.09")
            });
            AddContainerFileFindings(context, node, type, suspiciousExtension);
            BindContainerFindings(context, node, firstFinding);
            if (readAllowed && node.Sha256 is not null && type.Type == DetectedFileType.PortableExecutable)
            {
                await ScanVPetFamilyAsync(stream, context, node);
                BindContainerFindings(context, node, firstFinding);
            }
            if (ranges is not null)
                await ScanContainerRangesAsync(source, context, node, ranges, siblings);
            if (quickMedia)
            {
                CoverageAggregation.Add(context.Report, "QUICK-MEDIA-STRUCTURE", _coverageRoot ?? target, source.DisplayName);
                node.ContentCheck = ContainerStageStatus.Skipped;
                node.AddDetail(MessageText.Create("Backend.Core.ContentScanner.Containers.ScanContainerFileAsync.10")); return;
            }
            if (!readAllowed)
            {
                ContainerGap(context, node, ContainerStageStatus.LimitReached, MessageText.Create("Backend.Core.ContentScanner.Containers.ScanContainerFileAsync.11"),
                    tooLarge ? "QUICK-FILE-SIZE" : "CONTENT-BYTE-BUDGET"); return;
            }
            if (context.Options.Mode == ScanMode.Quick && !shouldHash)
                CoverageAggregation.Add(context.Report, "QUICK-CONTENT-NOT-HASHED", _coverageRoot ?? target, source.DisplayName);
            await ScanContainerLeafAsync(file, stream, source, context, node, type, suspiciousExtension, archiveCandidate);
            BindContainerFindings(context, node, firstFinding);
            ArchiveVolumePlan? plan = ResolveContainerVolumes(source, type, siblings, context);
            if (plan is not null)
            {
                if (!context.Options.InspectArchives)
                    ContainerGap(context, node, ContainerStageStatus.NotRequested, MessageText.Create("Backend.Core.ContentScanner.Containers.ScanContainerFileAsync.12"), "ARCHIVE-NOT-REQUESTED");
                else if (depth >= context.Budget.Limits.MaximumDepth &&
                    !ScanResourceSession.Allow("ContainerLimits.MaximumDepth", (long)depth + 1, depth, known: false))
                    ContainerGap(context, node, ContainerStageStatus.LimitReached, MessageText.Create("Backend.Core.ContentScanner.Containers.ScanContainerFileAsync.13"));
                else await ScanContainerArchiveAsync(plan, context, node);
            }
            else if (type.Type is DetectedFileType.Cabinet or DetectedFileType.CompoundDocument)
            {
                if (context.Options.InspectArchives && depth < context.Budget.Limits.MaximumDepth && source.Offset == 0 && length == file.Length)
                {
                    node.Integrity = ContainerStageStatus.UnsupportedIntegrity;
                    ContainerScanNode? previous = _structuredParent; _structuredParent = node;
                    try
                    {
                        await ScanStructuredAsync(source.PhysicalPath, source.DisplayName, target, type.Type, node.Sha256,
                            context.Report, context.Options, context.Passwords, context.Progress, context.Token, depth,
                            context.WorkshopId, context.ProjectType, context.LegacyBudget);
                    }
                    finally { _structuredParent = previous; }
                    node.DirectoryRead = ContainerStageStatus.Partial;
                    node.Integrity = ContainerStageStatus.UnsupportedIntegrity;
                    node.AddDetail(MessageText.Create("Backend.Core.ContentScanner.Containers.ScanContainerFileAsync.14"));
                }
                else ContainerGap(context, node, ContainerStageStatus.Skipped, MessageText.Create("Backend.Core.ContentScanner.Containers.ScanContainerFileAsync.15"), "COMPOUND-CONTENT-NOT-EXPANDED");
            }
            else if (archiveCandidate)
            {
                // Additional stream formats use the same per-run accounting and owned temporary store.
                if (context.Options.InspectArchives && source.Offset == 0 && length == file.Length && depth < context.Budget.Limits.MaximumDepth)
                {
                    await ScanOtherContainerArchiveAsync(stream, context, node);
                }
                else ContainerGap(context, node, ContainerStageStatus.Unsupported, MessageText.Create("Backend.Core.ContentScanner.Containers.ScanContainerFileAsync.16"));
            }
            else if (ranges is null || !ranges.Ranges.Any(range => range.Type is ContainerRangeType.Zip or ContainerRangeType.Rar4 or ContainerRangeType.Rar5))
                await RecoverContainerLeafAsync(stream, context, node);
            RelatedArtifactReader.ValidatePath(file.SafeFileHandle, Path.GetFullPath(source.PhysicalPath));
        }
        catch (OperationCanceledException) { ContainerGap(context, node, ContainerStageStatus.Cancelled, MessageText.Create("Backend.Core.ContentScanner.Containers.ScanContainerFileAsync.17")); throw; }
        catch (ContainerEntryLimitException ex) { ContainerGap(context, node, ContainerStageStatus.LimitReached, MessageExceptions.Describe(ex), ex.RuleId); }
        catch (ScanResourceLimitException ex) { ContainerGap(context, node, ContainerStageStatus.LimitReached, MessageExceptions.Describe(ex)); throw; }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidDataException or NotSupportedException or ArgumentException or OverflowException or System.ComponentModel.Win32Exception or SharpCompressException)
        {
            ContainerGap(context, node, ex is UnauthorizedAccessException or System.ComponentModel.Win32Exception ? ContainerStageStatus.AccessDenied : ContainerStageStatus.Failed,
            MessageText.Create("Backend.Core.ContentScanner.Containers.ScanContainerFileAsync.18") + ex.GetType().Name + "）：" + MessageExceptions.Describe(ex));
        }
        finally
        {
            BindContainerFindings(context, node, firstFinding);
            FinishContainer(context, node);
        }
    }

    private static void BindContainerFindings(ContainerContext context, ContainerScanNode node, int firstFinding)
    {
        foreach (Finding finding in context.Report.Findings.Skip(firstFinding))
        {
            finding.ContentPath ??= node.DisplayPath;
            finding.TargetSha256 ??= node.OriginalTargetSha256;
        }
    }

    private void AddContainerFileFindings(ContainerContext context, ContainerScanNode node, FileTypeResult type, bool suspicious)
    {
        HashRule? rule = node.Sha256 is null ? null : _rules.KnownHashes.FirstOrDefault(value => value.Sha256.Equals(node.Sha256, StringComparison.OrdinalIgnoreCase));
        if (rule is not null) context.Report.Findings.Add(new()
        {
            RuleId = rule.Id,
            Category = type.IsArchive ? FindingCategory.Archive : FindingCategory.File,
            Severity = rule.Severity,
            Score = rule.Malware ? 100 : 80,
            TitleText = rule.LabelText,
            DescriptionText = rule.EvidenceText ?? MessageText.Create("Backend.Core.ContentScanner.Containers.AddContainerFileFindings.01"),
            Target = node.OriginalTarget,
            EvidenceText = MessageText.Create("Backend.Core.ContentScanner.Containers.AddContainerFileFindings.02", (rule.Id), (node.DisplayPath)),
            Sha256 = node.Sha256,
            WorkshopId = context.WorkshopId,
            IsKnownMalware = rule.Malware,
            CanRemediate = rule.Malware || rule.Remediable,
            SuggestedActions = rule.Malware || rule.Remediable ? [SuggestedActionKind.QuarantineFile] : [SuggestedActionKind.ReviewOnly]
        });
        if (type.ExtensionMismatch) context.Report.Findings.Add(new()
        {
            RuleId = "CONTENT-EXTENSION-MISMATCH",
            Category = type.IsArchive ? FindingCategory.Archive : FindingCategory.File,
            Severity = type.Type == DetectedFileType.PortableExecutable ? FindingSeverity.High : FindingSeverity.Medium,
            Score = type.Type == DetectedFileType.PortableExecutable ? 65 : 40,
            TitleText = MessageText.Create("Backend.Core.ContentScanner.Containers.AddContainerFileFindings.03"),
            DescriptionText = MessageText.Create("Backend.Core.ContentScanner.Containers.AddContainerFileFindings.04", (Path.GetExtension(node.DisplayPath)), (type.LabelText)),
            Target = node.OriginalTarget,
            EvidenceText = MessageText.Create("Backend.Core.ContentScanner.Containers.AddContainerFileFindings.05", (node.DisplayPath), (type.ExpectedExtensionText)),
            Sha256 = node.Sha256,
            WorkshopId = context.WorkshopId,
            SuggestedActions = [SuggestedActionKind.ReviewOnly]
        });
        if (context.WorkshopId is not null && IsUnexpectedExecutable(type, Path.GetExtension(node.DisplayPath), context.ProjectType))
            context.Report.Findings.Add(new()
            {
                RuleId = "WORKSHOP-EXECUTABLE-CONTENT",
                Category = FindingCategory.WallpaperEngine,
                Severity = FindingSeverity.Medium,
                Score = 40,
                TitleText = MessageText.Create("Backend.Core.ContentScanner.Containers.AddContainerFileFindings.06"),
                DescriptionText = MessageText.Create("Backend.Core.ContentScanner.Containers.AddContainerFileFindings.07"),
                Target = node.OriginalTarget,
                EvidenceText = MessageText.Create("Backend.Core.ContentScanner.Containers.AddContainerFileFindings.08", (context.WorkshopId), (node.DisplayPath), (type.LabelText)),
                Sha256 = node.Sha256,
                WorkshopId = context.WorkshopId,
                SuggestedActions = [SuggestedActionKind.ReviewOnly]
            });
    }

    private async Task ScanContainerLeafAsync(FileStream file, Stream stream, ArchiveVolumeCandidate source,
        ContainerContext context, ContainerScanNode node, FileTypeResult type, bool suspicious, bool archive)
    {
        bool strings = type.IsExecutableOrScript || suspicious || type.Type is DetectedFileType.Unknown or DetectedFileType.Html or DetectedFileType.Json or DetectedFileType.Xml;
        if (strings)
        {
            if (stream.Length <= context.Options.MaximumStringScanBytes || ScanResourceSession.Allow("MaximumStringScanBytes", stream.Length))
            {
                stream.Position = 0; await ScanStringsStreamAsync(stream, source.DisplayName, node.OriginalTarget, node.Sha256,
                    context.Report, context.WorkshopId, context.ProjectType, context.Token, context.Options.MaximumStringScanBytes);
                node.Engines.Add(new() { EngineText = MessageText.Create("Backend.Core.ContentScanner.Containers.ScanContainerLeafAsync.01"), Status = ContainerStageStatus.Complete, Offset = 0, Length = stream.Length });
            }
            else
            {
                node.Engines.Add(new() { EngineText = MessageText.Create("Backend.Core.ContentScanner.Containers.ScanContainerLeafAsync.02"), Status = ContainerStageStatus.LimitReached, Length = 0, DetailText = MessageText.Create("Backend.Core.ContentScanner.Containers.ScanContainerLeafAsync.03", (System.FormattableString.Invariant($"{context.Options.MaximumStringScanBytes:N0}"))) });
                AddCoverage(context.Report, MessageText.Create("Backend.Core.ContentScanner.Containers.ScanContainerLeafAsync.04") + node.DisplayPath, node.OriginalTarget, context.WorkshopId, "STRING-ENGINE-SIZE-LIMIT");
            }
        }
        if (ScanEnhancements.UseAmsi(context.Options) && (type.IsExecutableOrScript || archive || suspicious))
        {
            if (stream.Length > context.Options.MaximumAmsiBytes && !ScanResourceSession.Allow("MaximumAmsiBytes", stream.Length))
            {
                node.Engines.Add(new() { Engine = "AMSI", Status = ContainerStageStatus.LimitReached, Length = 0, DetailText = MessageText.Create("Backend.Core.ContentScanner.Containers.ScanContainerLeafAsync.05", (System.FormattableString.Invariant($"{context.Options.MaximumAmsiBytes:N0}"))) });
                AddCoverage(context.Report, MessageText.Create("Backend.Core.ContentScanner.Containers.ScanContainerLeafAsync.06") + node.DisplayPath, node.OriginalTarget, context.WorkshopId, "AMSI-ENGINE-SIZE-LIMIT");
            }
            else
            {
                stream.Position = 0;
                AmsiScanResult result = await _amsi.Value.ScanStreamAsync(stream, source.DisplayName, context.Options.MaximumAmsiBytes, context.Token);
                bool unavailable = result.Verdict is AmsiVerdict.Unavailable or AmsiVerdict.Error;
                node.Engines.Add(new()
                {
                    Engine = "AMSI",
                    Status = unavailable ? ContainerStageStatus.Failed : ContainerStageStatus.Complete,
                    Offset = 0,
                    Length = result.BytesSubmitted,
                    DetailText = result.DetailText,
                    AmsiDiagnostics = result.Diagnostics
                });
                if (unavailable) AddAmsiCoverage(context.Report, result.DetailText);
                if (result.Verdict is AmsiVerdict.Detected or AmsiVerdict.BlockedByPolicy)
                    context.Report.Findings.Add(new()
                    {
                        RuleId = "AMSI-DETECTED",
                        Category = FindingCategory.File,
                        Severity = FindingSeverity.Critical,
                        Score = 90,
                        TitleText = result.Verdict == AmsiVerdict.Detected ? MessageText.Create("Backend.Core.ContentScanner.Containers.ScanContainerLeafAsync.07") : MessageText.Create("Backend.Core.ContentScanner.Containers.ScanContainerLeafAsync.08"),
                        DescriptionText = result.Verdict == AmsiVerdict.Detected ? MessageText.Create("Backend.Core.ContentScanner.Containers.ScanContainerLeafAsync.09") : MessageText.Create("Backend.Core.ContentScanner.Containers.ScanContainerLeafAsync.10"),
                        Target = node.OriginalTarget,
                        EvidenceText = result.DetailText + MessageText.Create("Backend.Core.ContentScanner.Containers.ScanContainerLeafAsync.11") + node.DisplayPath,
                        Sha256 = node.Sha256,
                        WorkshopId = context.WorkshopId,
                        CanRemediate = true,
                        SuggestedActions = [SuggestedActionKind.QuarantineFile]
                    });
            }
        }
        if (type.Type == DetectedFileType.Shortcut)
        {
            ShortcutInspection shortcut;
            if (stream.Length <= 1024 * 1024)
            {
                stream.Position = 0; byte[] bytes = new byte[(int)stream.Length]; await stream.ReadExactlyAsync(bytes, context.Token);
                shortcut = ShortcutInspector.Inspect(bytes);
            }
            else shortcut = new(null, null, null, false, MessageText.Create("Backend.Core.ContentScanner.Containers.ScanContainerLeafAsync.12"));
            string command = shortcut.Target + " " + shortcut.Arguments;
            IReadOnlyList<string> signals = ScriptSignals.Analyze(command);
            if (signals.Count > 0) context.Report.Findings.Add(new()
            {
                RuleId = "SHORTCUT-EXECUTION-CHAIN",
                Category = FindingCategory.File,
                Severity = FindingSeverity.High,
                Score = 85,
                TitleText = MessageText.Create("Backend.Core.ContentScanner.Containers.ScanContainerLeafAsync.13"),
                DescriptionText = string.Join("，", signals),
                Target = node.OriginalTarget,
                Sha256 = node.Sha256,
                EvidenceText = ScriptSignals.Redact(command),
                CanRemediate = true,
                SuggestedActions = [SuggestedActionKind.QuarantineFile]
            });
            if (!shortcut.Complete) ContainerGap(context, node, ContainerStageStatus.Partial, shortcut.Detail, "SHORTCUT-PARTIAL");
        }
        if (type.Type == DetectedFileType.PortableExecutable && context.Options.InspectDeepSignatures)
            InspectContainerSignature(file, source, context, node);
        node.ContentCheck = node.Engines.Where(engine => engine.Engine != "SHA-256").All(engine => StageComplete(engine.Status))
            ? ContainerStageStatus.Complete : ContainerStageStatus.Partial;
    }
}
