using System.Buffers;
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
        return _containerBudget;
    }

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
        if (containers.Nodes.Count >= context.Budget.Limits.MaximumNodes)
            throw new ScanResourceLimitException("容器节点数量达到上限，剩余内容未检查。");
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
        containers.Nodes.Add(node); return node;
    }

    private static bool StageComplete(ContainerStageStatus value) => value is ContainerStageStatus.Complete or ContainerStageStatus.NotRequested;

    private void FinishContainer(ContainerContext context, ContainerScanNode node)
    {
        if (node.Overall == ContainerStageStatus.Pending)
            node.Overall = ContainerCompletionStatus(node, context.Report.Containers!.Nodes.Where(child => child.ParentId == node.NodeId));
        node.CompletedAtUtc = DateTimeOffset.UtcNow; node.Revision++;
        ContainerScanReport report = context.Report.Containers!;
        report.Resources = context.Budget.Snapshot(); report.Complete = report.Nodes.All(value => value.Overall == ContainerStageStatus.Complete);
        if (node.Overall != ContainerStageStatus.Complete) context.Report.Coverage = ScanCoverage.Partial;
        Checkpoint?.Invoke(context.Report);
    }

    private void ContainerGap(ContainerContext context, ContainerScanNode node, ContainerStageStatus status, string detail,
        string rule = "CONTAINER-PARTIAL")
    {
        node.Overall = status; if (node.Details.Count < 32) node.Details.Add(ShortContainerDetail(detail));
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

    private async Task ScanContainerFileAsync(ArchiveVolumeCandidate source, string target, ContainerContext context,
        ContainerScanNode? parent, int depth, ContainerNodeKind kind, IReadOnlyList<ArchiveVolumeCandidate>? siblings,
        long? parentOffset = null, string? verifiedHash = null)
    {
        context.Token.ThrowIfCancellationRequested(); context.Budget.Check(); _resources.Check(context.Report);
        if (context.Report.Metrics.FilesVisited >= context.Options.MaximumFiles)
            throw new ScanResourceLimitException("本轮文件数达到上限，已保留此前结果。");
        ContainerScanNode node = AddContainerNode(context, source.DisplayName, target, parent, depth, kind, source.Length ?? 0, parentOffset);
        int firstFinding = context.Report.Findings.Count;
        try
        {
            context.Budget.Progress = () =>
            {
                long now = Environment.TickCount64;
                if (now - _lastContainerProgress < 250) return; _lastContainerProgress = now;
                ContainerResourceSnapshot resource = context.Budget.Snapshot();
                context.Progress?.Report(new("容器内容", source.DisplayName, resource.ReadBytes + resource.DecodedBytes, null,
                    $"深度 {depth}；读取 {resource.ReadBytes:N0}，解码 {resource.DecodedBytes:N0} 字节；临时 {resource.CurrentTemporaryBytes:N0} 字节"));
            };
            if (!ContentDiscovery.IsLocalSafePath(source.PhysicalPath)) throw new IOException("源路径不是可读取的本地普通文件。");
            await using FileStream file = RelatedArtifactReader.Open(source.PhysicalPath);
            RelatedArtifactReader.ValidatePath(file.SafeFileHandle, Path.GetFullPath(source.PhysicalPath));
            long length = source.Length ?? checked(file.Length - source.Offset); node.Length = length;
            using BoundedReadOnlyStream stream = new(file, source.Offset, length, budget: context.Budget);
            context.Report.Metrics.FilesVisited++;
            FileTypeResult type = await FileTypeDetector.DetectAsync(stream, source.DisplayName, context.Token);
            node.Format = type.Label; node.Recognition = ContainerStageStatus.Complete;
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
                    Engine = "容器边界",
                    Status = ranges.Status == ContainerRangeStatus.Validated ? ContainerStageStatus.Complete : ContainerStageStatus.Partial,
                    Offset = 0,
                    Length = length,
                    Detail = ranges.Detail
                });
                foreach (ContainerRangeSfxDirective directive in ranges.SfxConfiguration.Take(24))
                    node.Details.Add(ShortContainerDetail($"静态 SFX {directive.Name}={directive.Value}"));
            }
            bool quickMedia = context.Options.Mode == ScanMode.Quick && type.Type == DetectedFileType.Mp4 &&
                ranges?.Status == ContainerRangeStatus.Validated && !type.ExtensionMismatch;
            long charged = Math.Max(0, context.Report.Metrics.BytesHashed -
                (context.Options.Mode == ScanMode.Quick ? context.Report.Metrics.QuickPriorityBytesHashed : 0));
            long remaining = context.Options.MaximumContentBytes == long.MaxValue ? long.MaxValue : Math.Max(0, context.Options.MaximumContentBytes - charged);
            bool priority = context.Options.Mode == ScanMode.Quick && length > remaining && length <= context.Options.MaximumQuickPriorityFileBytes &&
                (type.IsExecutableOrScript || suspiciousExtension) && length <= context.Options.MaximumQuickPriorityBytes - context.Report.Metrics.QuickPriorityBytesHashed;
            bool tooLarge = context.Options.Mode == ScanMode.Quick && length > context.Options.MaximumQuickFileBytes;
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
                    ContainerGap(context, node, ContainerStageStatus.SourceChanged, "临时成员与经归档校验的内容身份不一致。"); return;
                }
            }
            if (parent is null) node.OriginalTargetSha256 = node.Sha256;
            node.Engines.Add(new()
            {
                Engine = "SHA-256",
                Status = node.Sha256 is null ? ContainerStageStatus.Skipped : ContainerStageStatus.Complete,
                Offset = 0,
                Length = node.Sha256 is null ? 0 : length,
                Detail = node.Sha256 is null ? "快速或字节预算未安排完整哈希。" : "完整范围的流式 SHA-256。"
            });
            AddContainerFileFindings(context, node, type, suspiciousExtension);
            BindContainerFindings(context, node, firstFinding);
            if (ranges is not null)
                await ScanContainerRangesAsync(source, context, node, ranges, siblings);
            if (quickMedia)
            {
                CoverageAggregation.Add(context.Report, "QUICK-MEDIA-STRUCTURE", _coverageRoot ?? target, source.DisplayName);
                node.ContentCheck = ContainerStageStatus.Skipped;
                node.Details.Add("快速媒体扫描仅检查结构，未完成全部内容引擎。"); return;
            }
            if (!readAllowed)
            {
                ContainerGap(context, node, ContainerStageStatus.LimitReached, "快速文件大小或内容字节预算不足。",
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
                    ContainerGap(context, node, ContainerStageStatus.NotRequested, "本次未检查压缩包内部。", "ARCHIVE-NOT-REQUESTED");
                else if (depth >= context.Budget.Limits.MaximumDepth)
                    ContainerGap(context, node, ContainerStageStatus.LimitReached, "压缩包达到最大嵌套深度。");
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
                    node.Details.Add("MSI/CAB 沿用独立结构适配器，其原有限额和完整性边界保持有效。");
                }
                else ContainerGap(context, node, ContainerStageStatus.Skipped, "安装包内部未展开，已保留外层检查。", "COMPOUND-CONTENT-NOT-EXPANDED");
            }
            else if (archiveCandidate)
            {
                // Additional stream formats use the same per-run accounting and owned temporary store.
                if (context.Options.InspectArchives && source.Offset == 0 && length == file.Length && depth < context.Budget.Limits.MaximumDepth)
                {
                    await ScanOtherContainerArchiveAsync(stream, context, node);
                }
                else ContainerGap(context, node, ContainerStageStatus.Unsupported, "未展开此归档格式。");
            }
            else if (ranges is null || !ranges.Ranges.Any(range => range.Type is ContainerRangeType.Zip or ContainerRangeType.Rar4 or ContainerRangeType.Rar5))
                await RecoverContainerLeafAsync(stream, context, node);
            RelatedArtifactReader.ValidatePath(file.SafeFileHandle, Path.GetFullPath(source.PhysicalPath));
        }
        catch (OperationCanceledException) { ContainerGap(context, node, ContainerStageStatus.Cancelled, "内容检查已取消。"); throw; }
        catch (ContainerEntryLimitException ex) { ContainerGap(context, node, ContainerStageStatus.LimitReached, ex.Message, ex.RuleId); }
        catch (ScanResourceLimitException ex) { ContainerGap(context, node, ContainerStageStatus.LimitReached, ex.Message); throw; }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidDataException or NotSupportedException or ArgumentException or OverflowException or System.ComponentModel.Win32Exception or SharpCompressException)
        {
            ContainerGap(context, node, ex is UnauthorizedAccessException or System.ComponentModel.Win32Exception ? ContainerStageStatus.AccessDenied : ContainerStageStatus.Failed,
            "无法完整扫描内容（" + ex.GetType().Name + "）：" + ex.Message);
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
            Title = rule.Label,
            Description = rule.Evidence ?? "文件 SHA-256 与已确认规则完全一致。",
            Target = node.OriginalTarget,
            Evidence = $"命中 {rule.Id}，内容位置：{node.DisplayPath}",
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
            Title = "文件扩展名与真实格式不符",
            Description = $"文件显示为 {Path.GetExtension(node.DisplayPath)}，实际识别为 {type.Label}。",
            Target = node.OriginalTarget,
            Evidence = $"内容位置：{node.DisplayPath}；建议扩展名：{type.ExpectedExtension}",
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
                Title = "壁纸类型与可执行/启动型内容不一致",
                Description = "视频或场景项目中出现启动型内容，需要核对来源。",
                Target = node.OriginalTarget,
                Evidence = $"工坊 {context.WorkshopId}；内容位置：{node.DisplayPath}；真实格式：{type.Label}",
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
            if (stream.Length <= context.Options.MaximumStringScanBytes)
            {
                stream.Position = 0; await ScanStringsStreamAsync(stream, source.DisplayName, node.OriginalTarget, node.Sha256,
                    context.Report, context.WorkshopId, context.ProjectType, context.Token, context.Options.MaximumStringScanBytes);
                node.Engines.Add(new() { Engine = "字符串与行为特征", Status = ContainerStageStatus.Complete, Offset = 0, Length = stream.Length });
            }
            else
            {
                node.Engines.Add(new() { Engine = "字符串与行为特征", Status = ContainerStageStatus.LimitReached, Length = 0, Detail = $"超过字符串检查设置 {context.Options.MaximumStringScanBytes:N0} 字节，未读取正文；可在扫描限制设置中调整。" });
                AddCoverage(context.Report, "字符串引擎未检查大文件正文：" + node.DisplayPath, node.OriginalTarget, context.WorkshopId, "STRING-ENGINE-SIZE-LIMIT");
            }
        }
        if (context.Options.UseAmsi && (type.IsExecutableOrScript || archive || suspicious))
        {
            if (stream.Length > context.Options.MaximumAmsiBytes)
            {
                node.Engines.Add(new() { Engine = "AMSI", Status = ContainerStageStatus.LimitReached, Length = 0, Detail = $"超过 AMSI 设置 {context.Options.MaximumAmsiBytes:N0} 字节，未提交；可在扫描限制设置中调整。" });
                AddCoverage(context.Report, "AMSI 未检查大文件正文：" + node.DisplayPath, node.OriginalTarget, context.WorkshopId, "AMSI-ENGINE-SIZE-LIMIT");
            }
            else
            {
                stream.Position = 0;
                AmsiScanResult result = await _amsi.ScanStreamAsync(stream, source.DisplayName, context.Options.MaximumAmsiBytes, context.Token);
                bool unavailable = result.Verdict is AmsiVerdict.Unavailable or AmsiVerdict.Error;
                node.Engines.Add(new()
                {
                    Engine = "AMSI",
                    Status = unavailable ? ContainerStageStatus.Failed : ContainerStageStatus.Complete,
                    Offset = 0,
                    Length = stream.Length,
                    Detail = result.Detail
                });
                if (unavailable) AddAmsiCoverage(context.Report, result.Detail);
                if (result.Verdict is AmsiVerdict.Detected or AmsiVerdict.BlockedByPolicy)
                    context.Report.Findings.Add(new()
                    {
                        RuleId = "AMSI-DETECTED",
                        Category = FindingCategory.File,
                        Severity = FindingSeverity.Critical,
                        Score = 90,
                        Title = result.Verdict == AmsiVerdict.Detected ? "本机反恶意软件接口检出威胁" : "本机安全策略阻止了该内容",
                        Description = result.Verdict == AmsiVerdict.Detected ? "AMSI 提供程序返回威胁检测结果。" : "策略阻止不等同于已确认病毒，请复核后决定是否隔离。",
                        Target = node.OriginalTarget,
                        Evidence = result.Detail + "；内容位置：" + node.DisplayPath,
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
            else shortcut = new(null, null, null, false, "快捷方式超过大小上限");
            string command = shortcut.Target + " " + shortcut.Arguments;
            IReadOnlyList<string> signals = ScriptSignals.Analyze(command);
            if (signals.Count > 0) context.Report.Findings.Add(new()
            {
                RuleId = "SHORTCUT-EXECUTION-CHAIN",
                Category = FindingCategory.File,
                Severity = FindingSeverity.High,
                Score = 85,
                Title = "快捷方式包含可疑执行链",
                Description = string.Join("，", signals),
                Target = node.OriginalTarget,
                Sha256 = node.Sha256,
                Evidence = ScriptSignals.Redact(command),
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
