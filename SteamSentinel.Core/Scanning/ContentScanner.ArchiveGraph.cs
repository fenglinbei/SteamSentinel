using System.Buffers;
using System.Security.Cryptography;
using SharpCompress.Common;
using SharpCompress.Crypto;
using SharpCompress.Readers;
using SteamSentinel.Core.Inspection;
using SteamSentinel.Core.Models;
using SteamSentinel.Core.Steam;
using SteamSentinel.Core.Utilities;

namespace SteamSentinel.Core.Scanning;

public sealed partial class ContentScanner
{
    private async Task ScanContainerRangesAsync(ArchiveVolumeCandidate source, ContainerContext context, ContainerScanNode node,
        ContainerRangeInspection inspection, IReadOnlyList<ArchiveVolumeCandidate>? siblings)
    {
        ContainerRange[] archives = inspection.Ranges.Where(range => range.Type is ContainerRangeType.Zip or ContainerRangeType.Rar4 or ContainerRangeType.Rar5).ToArray();
        bool executableTail = false;
        try
        {
            if (node.Depth >= 32 && (archives.Length > 0 || inspection.UnknownRanges.Count > 0))
            {
                ContainerGap(context, node, ContainerStageStatus.LimitReached,
                    $"容器来源关系已达 32 层；本层另有 {archives.Length} 个已识别嵌入范围和 {inspection.UnknownRanges.Count} 个未知范围未建立子项。");
                return;
            }
            foreach (ContainerRange range in archives)
            {
                if (range.Offset == 0 && range.Length == node.Length && node.Kind == ContainerNodeKind.EmbeddedRange) continue;
                string suffix = range.Type == ContainerRangeType.Zip ? ".zip" : ".rar";
                string display = node.DisplayPath + $"!/@range-{range.Offset}-{range.Length}" + suffix;
                if (range.Status is not (ContainerRangeStatus.Validated or ContainerRangeStatus.ValidatedContainerHeader) ||
                    !context.Options.InspectArchives || node.Depth >= context.Budget.Limits.MaximumDepth)
                {
                    ContainerScanNode skipped = AddContainerNode(context, display, node.OriginalTarget, node, node.Depth + 1,
                        ContainerNodeKind.EmbeddedRange, range.Length, range.Offset);
                    skipped.Format = range.Type.ToString(); skipped.Recognition = ContainerStageStatus.Complete;
                    int firstFinding = context.Report.Findings.Count;
                    ContainerGap(context, skipped, !context.Options.InspectArchives ? ContainerStageStatus.NotRequested : ContainerStageStatus.LimitReached,
                        "已识别嵌入范围，本次未展开。");
                    BindContainerFindings(context, skipped, firstFinding);
                    FinishContainer(context, skipped); continue;
                }
                await ScanContainerFileAsync(new(source.PhysicalPath, display, checked(source.Offset + range.Offset), range.Length),
                    node.OriginalTarget, context, node, node.Depth + 1, ContainerNodeKind.EmbeddedRange, null, range.Offset);
            }
            foreach (ContainerRange range in inspection.UnknownRanges)
                await ScanUnknownContainerRangeAsync(source, context, node, range, () => executableTail = true);
            if (inspection.Status is ContainerRangeStatus.Malformed or ContainerRangeStatus.Unsupported or ContainerRangeStatus.LimitReached)
                ContainerGap(context, node, ContainerStageStatus.Partial, inspection.Detail, "CONTAINER-STRUCTURE-PARTIAL");
        }
        finally
        {
            if (inspection.ContainerType == ContainerRangeType.Mp4 && (archives.Length > 0 || inspection.UnknownRanges.Count > 0))
                context.Report.Findings.Add(new()
                {
                    RuleId = "MP4-TRAILING-DATA",
                    Category = FindingCategory.WallpaperEngine,
                    Severity = archives.Length > 0 || executableTail ? FindingSeverity.High : FindingSeverity.Medium,
                    Score = archives.Length > 0 || executableTail ? 75 : 45,
                    Title = "MP4 存在容器外尾随数据",
                    Description = "媒体结构之外存在内容，已按验证得到的范围分别记录。" +
                        (executableTail ? "尾部静态识别到启动型内容，未执行。" : ""),
                    Target = node.OriginalTarget,
                    TargetSha256 = node.OriginalTargetSha256,
                    ContentPath = node.DisplayPath,
                    Sha256 = node.Sha256,
                    Evidence = inspection.Detail + "；内容位置：" + node.DisplayPath,
                    WorkshopId = context.WorkshopId,
                    SuggestedActions = [SuggestedActionKind.ReviewOnly]
                });
        }
    }

    private async Task ScanUnknownContainerRangeAsync(ArchiveVolumeCandidate source, ContainerContext context,
        ContainerScanNode parent, ContainerRange range, Action executableFound)
    {
        ContainerScanNode node = AddContainerNode(context, parent.DisplayPath + $"!/@unknown-{range.Offset}-{range.Length}",
            parent.OriginalTarget, parent, parent.Depth + 1, ContainerNodeKind.UnknownRange, range.Length, range.Offset);
        node.Format = "未归属范围"; node.Recognition = ContainerStageStatus.Unsupported;
        node.Integrity = ContainerStageStatus.UnsupportedIntegrity;
        int firstFinding = context.Report.Findings.Count;
        ContainerGap(context, node, ContainerStageStatus.Unsupported, range.Detail, "CONTAINER-UNKNOWN-RANGE");
        try
        {
            context.Budget.Check(); _resources.Check(context.Report);
            if (context.Report.Metrics.FilesVisited >= context.Options.MaximumFiles)
                throw new ScanResourceLimitException("本轮文件数达到上限，未知范围尚未检查。");
            await using FileStream file = RelatedArtifactReader.Open(source.PhysicalPath);
            RelatedArtifactReader.ValidatePath(file.SafeFileHandle, Path.GetFullPath(source.PhysicalPath));
            ArchiveVolumeCandidate selected = new(source.PhysicalPath, node.DisplayPath, checked(source.Offset + range.Offset), range.Length);
            using BoundedReadOnlyStream stream = new(file, selected.Offset, range.Length, budget: context.Budget);
            context.Report.Metrics.FilesVisited++;
            // A bounded recognition head is still useful when full-content hashing is not scheduled.
            FileTypeResult type = await FileTypeDetector.DetectAsync(stream, node.DisplayPath, context.Token);
            node.Details.Add(ShortContainerDetail("内容魔数提示：" + type.Label + "；仅用于选择静态引擎，未取得完整容器边界。"));
            if (type.IsExecutableOrScript) executableFound();
            long charged = Math.Max(0, context.Report.Metrics.BytesHashed -
                (context.Options.Mode == ScanMode.Quick ? context.Report.Metrics.QuickPriorityBytesHashed : 0));
            long remaining = context.Options.MaximumContentBytes == long.MaxValue ? long.MaxValue :
                Math.Max(0, context.Options.MaximumContentBytes - charged);
            if (range.Length > remaining || context.Options.Mode == ScanMode.Quick && range.Length > context.Options.MaximumQuickFileBytes)
            {
                node.ContentCheck = ContainerStageStatus.LimitReached;
                node.Engines.Add(new()
                {
                    Engine = "SHA-256",
                    Status = ContainerStageStatus.Skipped,
                    Length = 0,
                    Detail = "未知范围超过快速大小或剩余内容读取预算。"
                });
                ContainerGap(context, node, ContainerStageStatus.LimitReached, "未知范围尚未完成独立哈希和内容检查。", "CONTENT-BYTE-BUDGET");
                return;
            }
            stream.Position = 0;
            node.Sha256 = await Hashing.Sha256StreamAsync(stream, context.Token,
                bytes => context.Report.Metrics.BytesHashed += bytes, maximumBytes: range.Length);
            node.Engines.Add(new()
            {
                Engine = "SHA-256",
                Status = ContainerStageStatus.Complete,
                Offset = 0,
                Length = range.Length,
                Detail = "仅此未知范围的完整流式 SHA-256；不代表格式完整性通过。"
            });
            bool suspicious = _rules.DangerousExtensions.Contains(Path.GetExtension(node.DisplayPath), StringComparer.OrdinalIgnoreCase);
            AddContainerFileFindings(context, node, type, suspicious);
            await ScanContainerLeafAsync(file, stream, selected, context, node, type, suspicious, archive: type.IsArchive);
            // Recognition and integrity remain unsupported even when all requested leaf engines ran.
            node.Overall = ContainerStageStatus.Unsupported;
            RelatedArtifactReader.ValidatePath(file.SafeFileHandle, Path.GetFullPath(source.PhysicalPath));
        }
        catch (OperationCanceledException)
        {
            node.ContentCheck = ContainerStageStatus.Cancelled;
            ContainerGap(context, node, ContainerStageStatus.Cancelled, "未知范围内容检查已取消。"); throw;
        }
        catch (ScanResourceLimitException ex)
        {
            node.ContentCheck = ContainerStageStatus.LimitReached;
            ContainerGap(context, node, ContainerStageStatus.LimitReached, ex.Message); throw;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidDataException or NotSupportedException or
            ArgumentException or OverflowException or System.ComponentModel.Win32Exception or SharpCompressException)
        {
            node.ContentCheck = ex is UnauthorizedAccessException or System.ComponentModel.Win32Exception
                ? ContainerStageStatus.AccessDenied : ContainerStageStatus.Failed;
            ContainerGap(context, node, node.ContentCheck, "未知范围未完整检查（" + ex.GetType().Name + "）：" + ex.Message);
        }
        finally
        {
            BindContainerFindings(context, node, firstFinding);
            FinishContainer(context, node);
        }
    }

    private ArchiveVolumePlan? ResolveContainerVolumes(ArchiveVolumeCandidate source, FileTypeResult type,
        IReadOnlyList<ArchiveVolumeCandidate>? siblings, ContainerContext context)
    {
        ArchiveVolumeLimits limits = new()
        {
            MaximumCandidates = context.Budget.Limits.MaximumDirectoryCandidates,
            MaximumVolumes = context.Budget.Limits.MaximumVolumes,
            MaximumTotalBytes = context.Budget.Limits.MaximumWorkBytes,
            MaximumEntries = context.Budget.Limits.MaximumMetadataAttempts
        };
        ArchiveVolumePlan nameProbe = ArchiveVolumeResolver.Resolve(source, [source], limits);
        ArchiveVolumeFormat? format = type.Type switch
        {
            DetectedFileType.Zip => ArchiveVolumeFormat.Zip,
            DetectedFileType.Rar => ArchiveVolumeFormat.Rar,
            DetectedFileType.SevenZip => ArchiveVolumeFormat.SevenZip,
            _ => null
        };
        if (nameProbe.Status == ArchiveVolumeStatus.NotArchive)
            return format.HasValue ? ArchiveVolumeResolver.Single(source, format.Value, limits) : null;
        if (source.Offset > 0 || source.Length.HasValue)
            return format.HasValue ? ArchiveVolumeResolver.Single(source, format.Value, limits) : nameProbe;
        if (siblings is not null) return ArchiveVolumeResolver.Resolve(source, siblings, limits);
        List<ArchiveVolumeCandidate> candidates = [];
        string originalDirectory = Path.GetDirectoryName(source.PhysicalPath)!;
        IEnumerable<string> directories = new[] { originalDirectory }.Concat(context.Options.SupplementalVolumeDirectories)
            .Distinct(StringComparer.OrdinalIgnoreCase);
        foreach (string directory in directories)
        {
            if (!ContentDiscovery.IsLocalSafePath(directory) || !Directory.Exists(directory)) continue;
            foreach (string path in Directory.EnumerateFiles(directory).Take(limits.MaximumCandidates + 1))
            {
                context.Budget.Check();
                if (IsExcluded(path, context.Options.ExcludedRoots)) continue;
                // Supplemental directories are explicitly selected. Project their leaf names into
                // this group, preserving physical identities; duplicate names are rejected by resolver.
                string display = Path.Combine(Path.GetDirectoryName(source.DisplayName) ?? "", Path.GetFileName(path));
                candidates.Add(new(path, display));
                if (candidates.Count > limits.MaximumCandidates)
                    return ArchiveVolumeResolver.Resolve(source, candidates, limits);
            }
        }
        ArchiveVolumePlan result = ArchiveVolumeResolver.Resolve(source, candidates, limits);
        // Content wins over a misleading single .zip/.rar suffix. Numbered volume families still
        // require the selected naming scheme to agree with their validated bytes.
        if (result.Layout == ArchiveVolumeLayout.Single && result.Members.Count == 1 && format.HasValue && result.Format != format.Value)
            return ArchiveVolumeResolver.Single(source, format.Value, limits);
        return result;
    }

    private sealed record DecodedContainerMember(ContainerTemporaryFile File, string Name, string Display, string Hash, long Length, bool IsEncrypted)
    {
        public bool MetricsRecorded { get; set; }
        public Guid? PublishedNodeId { get; set; }
    }
    private sealed class ContainerEntryLimitException(string ruleId, string detail) : IOException(detail)
    {
        public string RuleId { get; } = ruleId;
    }
    private sealed class ContainerGroupLease : IDisposable
    {
        private readonly List<FileStream> _locks = [];
        public string Identity { get; private set; } = string.Empty;
        public string PhysicalIdentity { get; private set; } = string.Empty;
        public List<ArchiveVolumeIdentity> Volumes { get; } = [];
        public static async Task<ContainerGroupLease> CaptureAsync(ArchiveVolumePlan plan, ContainerContext context)
        {
            ContainerGroupLease lease = new();
            try
            {
                using IncrementalHash hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
                using IncrementalHash physical = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
                HashSet<string> fileIds = new(StringComparer.Ordinal);
                hash.AppendData(System.Text.Encoding.UTF8.GetBytes($"SteamSentinel.PasswordGroup.v1\0{plan.Format}\0{plan.Layout}\0"));
                long total = 0;
                foreach (ArchiveVolumeCandidate member in plan.Members)
                {
                    context.Budget.Check();
                    FileStream file = RelatedArtifactReader.Open(member.PhysicalPath); lease._locks.Add(file);
                    string fileId = ArchiveVolumeSession.VerifyHandle(file, Path.GetFullPath(member.PhysicalPath));
                    if (!fileIds.Add(fileId)) throw new ArchiveVolumeException(ArchiveVolumeStatus.DuplicateVolume, "卷组引用了重复的物理文件身份。");
                    physical.AppendData(System.Text.Encoding.UTF8.GetBytes($"{fileId}\0{member.Offset}\0{member.Length}\0"));
                    total = checked(total + file.Length);
                    if (total > plan.Limits.MaximumTotalBytes) throw new ScanResourceLimitException("卷组总输入超过本轮限额。");
                    long length = member.Length ?? checked(file.Length - member.Offset);
                    using BoundedReadOnlyStream full = new(file, 0, file.Length, budget: context.Budget);
                    string fullHash = Convert.ToHexString(await SHA256.HashDataAsync(full, context.Token));
                    string rangeHash = fullHash;
                    if (member.Offset != 0 || length != file.Length)
                    {
                        using BoundedReadOnlyStream range = new(file, member.Offset, length, budget: context.Budget);
                        rangeHash = Convert.ToHexString(await SHA256.HashDataAsync(range, context.Token));
                    }
                    lease.Volumes.Add(new(member.PhysicalPath, member.DisplayName, length, fullHash, member.Offset, file.Length, rangeHash));
                    hash.AppendData(System.Text.Encoding.UTF8.GetBytes($"{file.Length}\0{member.Offset}\0{length}\0{fullHash}\0{rangeHash}\0"));
                }
                lease.Identity = plan.Members.Count == 1 ? lease.Volumes[0].RangeSha256 : Convert.ToHexString(hash.GetHashAndReset());
                lease.PhysicalIdentity = Convert.ToHexString(physical.GetHashAndReset());
                return lease;
            }
            catch { lease.Dispose(); throw; }
        }
        public void Dispose() { foreach (FileStream file in _locks) file.Dispose(); }
    }
    private sealed class ContainerDecodeAttempt(ContainerTemporaryStore store) : IDisposable
    {
        public ContainerTemporaryStore Store { get; } = store;
        public List<DecodedContainerMember> Members { get; } = [];
        public List<SkippedContainerMember> SkippedMembers { get; } = [];
        public int DirectoryEntries { get; set; }
        public List<ArchiveVolumeIdentity> Identities { get; } = [];
        public string? GroupHash { get; set; }
        public bool ValidatedPassword { get; set; }
        public bool HasEncryption { get; set; }
        public bool Complete { get; set; }
        public bool TraversalComplete { get; set; }
        public bool Reused { get; set; }
        public Exception? Failure { get; set; }
        public void Dispose() => Store.Dispose();
    }

    private sealed record SkippedContainerMember(string Display, long Length, bool IsEncrypted, string RuleId, string Detail);

    private async Task<ContainerDecodeAttempt> DecodeContainerAttemptAsync(ArchiveVolumePlan plan, string? password,
        ContainerContext context, ContainerScanNode node)
    {
        ContainerDecodeAttempt attempt = new(new(context.Budget));
        try
        {
            context.Progress?.Report(new("压缩包目录", node.DisplayPath, context.Report.Metrics.ArchiveEntriesVisited, null,
                $"正在核验 {plan.Members.Count} 个已限定输入与归档目录"));
            using ArchiveVolumeSession session = await ArchiveVolumeSession.OpenAsync(plan, password, context.Token,
                source => new BoundedReadOnlyStream(source, 0, source.Length, budget: context.Budget));
            attempt.Identities.AddRange(session.Identities); attempt.GroupHash = session.GroupSha256;
            using IReader reader = session.OpenReader();
            bool traversalComplete = false;
            try
            {
                while (true)
                {
                    context.Budget.Check(); context.Budget.ChargeMetadata();
                    if (!reader.MoveToNextEntry()) { traversalComplete = true; break; }
                    IEntry entry = reader.Entry;
                    attempt.HasEncryption |= entry.IsEncrypted && entry.Size > 0;
                    if (entry.IsEncrypted && entry.Size > 0 && password is null) throw new PasswordNeededException();
                    if (attempt.Members.Count + attempt.SkippedMembers.Count + attempt.DirectoryEntries + context.Report.Metrics.ArchiveEntriesVisited >= context.Budget.Limits.MaximumEntries)
                        throw new ScanResourceLimitException("归档成员数量达到上限。");
                    if (entry.IsDirectory) { attempt.DirectoryEntries++; continue; }
                    string name = entry.Key ?? "(unnamed)";
                    string display = node.DisplayPath + "!/" + SanitizeEntryDisplayName(name);
                    if (entry.Size < 0 || entry.Size > context.Budget.Limits.MaximumEntryBytes)
                    {
                        if (SkipLimitedZipMember("ARCHIVE-SIZE-LIMIT", "成员声明大小超过单成员上限；该成员未打开、未解码，继续检查后续 ZIP 成员。")) continue;
                        throw new ContainerEntryLimitException("ARCHIVE-SIZE-LIMIT", "成员声明大小超过单成员上限，当前格式不能安全跳过未解码成员，已停止本归档。");
                    }
                    if (entry.CompressedSize > 0 && entry.Size / (double)entry.CompressedSize > context.Budget.Limits.MaximumCompressionRatio)
                    {
                        if (SkipLimitedZipMember("ARCHIVE-RATIO-LIMIT", "成员声明压缩比超过安全上限；该成员未打开、未解码，继续检查后续 ZIP 成员。")) continue;
                        throw new ContainerEntryLimitException("ARCHIVE-RATIO-LIMIT", "成员压缩比超过安全上限，当前格式不能安全跳过未解码成员，已停止本归档。");
                    }
                    if (entry.Size > context.Budget.Limits.MaximumExpandedBytes - context.Budget.AcceptedExpandedBytes)
                        throw new ScanResourceLimitException("成员声明大小超过本轮剩余逻辑展开上限。");
                    using ArchiveIntegrityEntryVerifier verifier = ArchiveIntegrity.Begin(session, entry);
                    if (!verifier.Requirement.Supported)
                        throw new ArchiveVolumeException(ArchiveVolumeStatus.UnsupportedIntegrity, verifier.Requirement.Detail);
                    ContainerTemporaryFile output = attempt.Store.CreateFile();
                    using IncrementalHash hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
                    using Crc32Stream checksum = new(Stream.Null);
                    long copied = 0;
                    using (Stream input = reader.OpenEntryStream())
                    {
                        // EntryStream.Dispose would otherwise drain a failed solid entry outside
                        // our byte accounting. Cancel before any exceptional disposal.
                        try
                        {
                            byte[] buffer = ArrayPool<byte>.Shared.Rent(128 * 1024);
                            try
                            {
                                while (true)
                                {
                                    context.Budget.Check();
                                    int request = context.Budget.ReadAllowance(buffer.Length);
                                    int read = await input.ReadAsync(buffer.AsMemory(0, request), context.Token);
                                    if (read == 0) break;
                                    context.Budget.ChargeDecoded(read); copied = checked(copied + read);
                                    if (copied > context.Budget.Limits.MaximumEntryBytes)
                                        throw new ContainerEntryLimitException("ARCHIVE-SIZE-LIMIT", "成员实际展开长度超过单成员限额，已停止本归档。");
                                    if (copied > entry.Size)
                                        throw new ArchiveVolumeException(ArchiveVolumeStatus.InvalidMetadata, "成员实际展开长度超过声明大小。");
                                    hash.AppendData(buffer, 0, read); checksum.Write(buffer, 0, read);
                                    await output.WriteAsync(buffer.AsMemory(0, read), context.Token);
                                }
                            }
                            finally { ArrayPool<byte>.Shared.Return(buffer, clearArray: true); }
                            verifier.Complete(input, copied, checksum.Crc);
                        }
                        catch { reader.Cancel(); throw; }
                    }
                    await output.SealAsync(context.Token);
                    context.Budget.AcceptExpansion(copied);
                    attempt.ValidatedPassword |= verifier.CanValidatePassword;
                    attempt.Members.Add(new(output, name, display, Convert.ToHexString(hash.GetHashAndReset()), copied, entry.IsEncrypted));
                    context.Progress?.Report(new("归档成员已校验", display, attempt.Members.Count, null,
                        "已核对成员长度、归档完整性和内容 SHA-256；内容引擎尚未开始。"));

                    bool SkipLimitedZipMember(string ruleId, string detail)
                    {
                        if (!session.CanSkipCurrentUnopenedEntry) return false;
                        session.SkipCurrentUnopenedEntry(entry);
                        attempt.SkippedMembers.Add(new(display, Math.Max(0, entry.Size), entry.IsEncrypted, ruleId, detail));
                        return true;
                    }
                }
            }
            catch { reader.Cancel(); throw; }
            finally { if (!traversalComplete) reader.Cancel(); }
            session.VerifyTraversalCompleted(allowSkipped: session.SkippedEntries > 0);
            attempt.TraversalComplete = true;
            attempt.Complete = session.SkippedEntries == 0;
        }
        catch (Exception ex) when (ex is not OutOfMemoryException) { attempt.Failure = ex; }
        return attempt;
    }

    private async Task ScanContainerArchiveAsync(ArchiveVolumePlan plan, ContainerContext context, ContainerScanNode node)
    {
        if (plan.Status != ArchiveVolumeStatus.Ready)
        {
            node.DirectoryRead = VolumeStatus(plan.Status); ContainerGap(context, node, node.DirectoryRead, plan.Detail,
                plan.Status == ArchiveVolumeStatus.MissingVolume ? "ARCHIVE-MISSING-VOLUME" : "ARCHIVE-UNSUPPORTED"); return;
        }
        node.DirectoryRead = node.Integrity = ContainerStageStatus.Pending;
        if (plan.Layout != ArchiveVolumeLayout.Single) node.Kind = ContainerNodeKind.VolumeGroup;
        node.Format = plan.Format + (plan.Members.Count > 1 ? $" ({plan.Members.Count} 卷)" : "");
        using ContainerGroupLease lease = await ContainerGroupLease.CaptureAsync(plan, context);
        node.VolumeGroupSha256 = lease.Identity;
        node.Volumes.Clear();
        foreach (ArchiveVolumeIdentity volume in lease.Volumes)
            node.Volumes.Add(new()
            {
                OriginalPath = node.ParentId.HasValue ? node.OriginalTarget : volume.PhysicalPath,
                DisplayName = volume.DisplayName,
                Length = volume.SourceLength,
                Sha256 = volume.Sha256,
                IsTemporary = node.ParentId.HasValue
            });
        // Byte-identical copies are different remediation targets. Reuse only the same locked
        // physical group within the same scan root; nested groups also retain their outer target.
        string reuseKey = lease.Identity + "\0" + lease.PhysicalIdentity + "\0" +
            (_coverageRoot ?? node.OriginalTarget).ToUpperInvariant() + "\0" +
            (plan.Layout == ArchiveVolumeLayout.Single || node.ParentId.HasValue ? node.OriginalTarget.ToUpperInvariant() : "") + "\0" +
            context.WorkshopId + "\0" + context.ProjectType;
        if (_decodedGroups.TryGetValue(reuseKey, out ContainerScanNode? previous))
        {
            node.ReusedNodeId = previous.NodeId;
            node.Details.Add($"本轮同身份卷组的解码已经完成，内容范围引用节点 {previous.NodeId}；未再次尝试密码或解码。");
            node.DirectoryRead = previous.DirectoryRead; node.Decryption = previous.Decryption;
            node.Integrity = previous.Integrity; node.ContentCheck = previous.ContentCheck; node.Overall = previous.Overall;
            return;
        }
        Queue<PasswordCandidate> candidates = new(_passwords.CandidateEntries(node.OriginalTarget).Select(value =>
            new PasswordCandidate(value.Password, true, value.ValidationScope)));
        HashSet<string> tried = new(StringComparer.Ordinal);
        string? password = null;
        ArchivePasswordReuseScope scope = ArchivePasswordReuseScope.CurrentOnly;
        int manualAttempts = 0, cachedFailures = 0;
        bool fromCache = false, encrypted = false;
        string identity = lease.Identity;
        while (true)
        {
            context.Budget.Check();
            if (password is not null)
            {
                if (PasswordBudgetExhausted()) return;
                context.Budget.ChargePasswordAttempt();
            }
            long acceptedBefore = context.Budget.AcceptedExpandedBytes;
            using ContainerDecodeAttempt attempt = await DecodeContainerAttemptAsync(plan, password, context, node);
            encrypted |= attempt.HasEncryption;
            if (attempt.Failure is OperationCanceledException or ScanResourceLimitException)
            {
                context.Report.Metrics.ArchiveEntriesVisited += attempt.DirectoryEntries;
                ContainerStageStatus interrupted = attempt.Failure is OperationCanceledException
                    ? ContainerStageStatus.Cancelled : ContainerStageStatus.LimitReached;
                node.DirectoryRead = node.Integrity = ContainerStageStatus.Partial;
                node.Decryption = encrypted ? attempt.ValidatedPassword ? ContainerStageStatus.Complete : ContainerStageStatus.Partial
                    : ContainerStageStatus.NotRequested;
                PreserveSkippedContainerMembers(context, node, attempt.SkippedMembers);
                PreserveVerifiedContainerMembers(context, node, attempt.Members, interrupted);
                System.Runtime.ExceptionServices.ExceptionDispatchInfo.Capture(attempt.Failure).Throw();
            }
            bool passwordFailure = attempt.Failure is not null && attempt.Failure is not (ArchiveVolumeException or ContainerEntryLimitException or ScanResourceLimitException) &&
                IsArchivePasswordFailure(attempt.Failure, encrypted, password is not null);
            // Integrity mismatches may follow a weak password verifier collision. Permit a new
            // candidate, but never call them proof that the password alone is the cause.
            passwordFailure |= encrypted && password is not null && attempt.Failure is ArchiveVolumeException { Reason: ArchiveVolumeStatus.InvalidMetadata };
            if (!passwordFailure)
            {
                if (!attempt.Reused)
                {
                    context.Report.Metrics.ArchiveEntriesVisited += attempt.DirectoryEntries;
                    node.DirectoryRead = attempt.TraversalComplete ? ContainerStageStatus.Complete : ContainerStageStatus.Partial;
                    node.Integrity = attempt.Complete ? ContainerStageStatus.Complete : ContainerStageStatus.Partial;
                    node.Decryption = encrypted ? attempt.ValidatedPassword && !attempt.SkippedMembers.Any(member => member.IsEncrypted)
                        ? ContainerStageStatus.Complete : ContainerStageStatus.Partial : ContainerStageStatus.NotRequested;
                    if (password is not null && attempt.ValidatedPassword) _passwords.Remember(password, node.OriginalTarget, scope);
                    PreserveSkippedContainerMembers(context, node, attempt.SkippedMembers);
                    // All staged members already passed integrity. Reserve their global entry
                    // accounting before an inner archive can consume the remaining capacity.
                    foreach (DecodedContainerMember staged in attempt.Members) RecordDecodedMemberMetrics(context, staged);
                    IReadOnlyList<ArchiveVolumeCandidate> siblings = attempt.Members.Select(member => new ArchiveVolumeCandidate(member.File.Path, member.Display)).ToArray();
                    for (int memberIndex = 0; memberIndex < attempt.Members.Count; memberIndex++)
                    {
                        DecodedContainerMember member = attempt.Members[memberIndex];
                        try
                        {
                            context.Token.ThrowIfCancellationRequested();
                            RecordDecodedMemberMetrics(context, member);
                            if (IsUnsafeArchiveName(member.Name))
                            {
                                AddUnsafeArchiveFinding(context.Report, node.OriginalTarget, member.Display, context.WorkshopId);
                                // Child completion can publish an append-only checkpoint immediately.
                                context.Report.Findings[^1].TargetSha256 = node.OriginalTargetSha256;
                            }
                            int firstNode = context.Report.Containers!.Nodes.Count;
                            try
                            {
                                await ScanContainerFileAsync(new(member.File.Path, member.Display), node.OriginalTarget, context, node,
                                    node.Depth + 1, ContainerNodeKind.ArchiveMember, siblings, verifiedHash: member.Hash);
                            }
                            finally
                            {
                                member.PublishedNodeId = context.Report.Containers.Nodes.Skip(firstNode)
                                    .FirstOrDefault(child => child.ParentId == node.NodeId)?.NodeId;
                            }
                        }
                        catch (Exception ex) when (ex is OperationCanceledException or ScanResourceLimitException)
                        {
                            PreserveVerifiedContainerMembers(context, node, attempt.Members.Skip(memberIndex),
                                ex is OperationCanceledException ? ContainerStageStatus.Cancelled : ContainerStageStatus.LimitReached);
                            throw;
                        }
                    }
                    if (attempt.Failure is not null)
                    {
                        ContainerStageStatus status = attempt.Failure switch
                        {
                            ArchiveVolumeException ex => VolumeStatus(ex.Reason),
                            ContainerEntryLimitException or ScanResourceLimitException => ContainerStageStatus.LimitReached,
                            UnauthorizedAccessException => ContainerStageStatus.AccessDenied,
                            _ => ContainerStageStatus.Corrupt
                        };
                        node.Integrity = status;
                        ContainerGap(context, node, status, "归档未完整验证（" + attempt.Failure.GetType().Name + "）：" +
                            (attempt.Failure is ArchiveVolumeException or ContainerEntryLimitException or ScanResourceLimitException ? attempt.Failure.Message : "可能损坏、读取受阻或格式未支持。"),
                            attempt.Failure is ContainerEntryLimitException entryLimit ? entryLimit.RuleId :
                                attempt.Failure is ScanResourceLimitException ? "ARCHIVE-ATTEMPT-LIMIT" : "ARCHIVE-UNSUPPORTED");
                    }
                    // Only completed decoding is reusable; an incomplete group can receive a
                    // distinct later attempt after the user supplies missing input.
                    if (attempt.Complete && attempt.GroupHash is not null)
                    {
                        node.Overall = ContainerCompletionStatus(node, context.Report.Containers!.Nodes
                            .Where(child => child.ParentId == node.NodeId));
                        _decodedGroups.TryAdd(reuseKey, node);
                    }
                }
                return;
            }
            context.Budget.RestoreLogicalExpansion(acceptedBefore);
            encrypted = true; node.Decryption = password is null ? ContainerStageStatus.PasswordRequired : ContainerStageStatus.PasswordFailed;
            if (password is not null)
            {
                tried.Add(password); _passwords.RememberFailure(identity, password); if (fromCache) cachedFailures++;
            }
            if (NextCandidate()) continue;
            if (PasswordBudgetExhausted()) return;
            if (_passwords.IsDeferred(identity))
            {
                ContainerGap(context, node, ContainerStageStatus.Skipped,
                    "本轮已暂缓这份未解密内容；可补查原始内容后提供新密码。", "ARCHIVE-ENCRYPTED-DEFERRED"); return;
            }
            if (_passwords.SkipAllEncrypted)
            {
                _passwords.Defer(identity); ContainerGap(context, node, ContainerStageStatus.Skipped,
                    "本次已跳过这份未解密内容；可补查原始内容后提供新密码。", "ARCHIVE-ENCRYPTED-NOT-SCANNED"); return;
            }
            bool repeated = false;
            while (true)
            {
                if (PasswordBudgetExhausted()) return;
                if (manualAttempts >= 3)
                {
                    _passwords.Defer(identity); ContainerGap(context, node, ContainerStageStatus.PasswordFailed,
                        "已达到本次密码输入次数上限；可补查原始内容后提供新密码。", "ARCHIVE-PASSWORD-FAILED"); return;
                }
                ArchivePasswordPromptKind kind = repeated ? ArchivePasswordPromptKind.RepeatedPassword : manualAttempts > 0 ?
                    ArchivePasswordPromptKind.EnteredPasswordFailed : cachedFailures > 0 ? ArchivePasswordPromptKind.CachedPasswordFailed : ArchivePasswordPromptKind.Needed;
                string reason = kind switch
                {
                    ArchivePasswordPromptKind.CachedPasswordFailed => "已尝试本次暂存且适用的密码，仍未解开这一层。可能需要其他密码，也不能排除内容损坏或格式兼容问题。",
                    ArchivePasswordPromptKind.EnteredPasswordFailed => "刚才输入的密码未能通过这一层的解密与完整性校验。请提供其他密码；也不能排除内容损坏或格式兼容问题。",
                    ArchivePasswordPromptKind.RepeatedPassword => "这些密码在本轮已尝试且未通过这一层的校验，未重复解码。请提供其他密码，或暂缓这份内容。",
                    _ => "这一层包含加密内容，需要密码才能继续解密与完整性校验。外层密码不一定适用于内层。"
                };
                ArchivePasswordResponse response = await AskPasswordAsync(node.DisplayPath, identity, plan.Format.ToString(), node.Depth,
                    context.WorkshopId, reason,
                    context.Passwords, context.Token, _passwords.PreferredScope, kind);
                IReadOnlyList<string> supplied = ArchivePasswordInput.ValidateAndGetPasswords(response);
                scope = response.ReuseForSession ? ArchivePasswordReuseScope.Session : response.ReuseScope; _passwords.PreferredScope = scope;
                if (response.SkipAllEncrypted) _passwords.EnableSkipAllEncrypted();
                if (response.Cancelled || supplied.Count == 0)
                {
                    _passwords.Defer(identity); ContainerGap(context, node, ContainerStageStatus.Skipped,
                        "已跳过未解密内容，可补查原始内容后提供密码。", "ARCHIVE-ENCRYPTED-NOT-SCANNED"); return;
                }
                manualAttempts++;
                if (response.Passwords?.Any(value => !string.IsNullOrEmpty(value)) == true)
                    _passwords.SetUserCandidates(supplied, node.OriginalTarget, scope);
                foreach (string value in supplied)
                    if (!tried.Contains(value) && !_passwords.HasFailed(identity, value)) candidates.Enqueue(new(value, false, scope));
                if (NextCandidate()) break;
                if (_passwords.SkipAllEncrypted)
                {
                    _passwords.Defer(identity); ContainerGap(context, node, ContainerStageStatus.Skipped,
                        "已按本次设置跳过未解密内容。", "ARCHIVE-ENCRYPTED-NOT-SCANNED"); return;
                }
                repeated = true;
            }
        }
        bool NextCandidate()
        {
            while (candidates.TryDequeue(out PasswordCandidate candidate))
            {
                if (tried.Contains(candidate.Value) || _passwords.HasFailed(identity, candidate.Value))
                { if (candidate.FromPriorCache) cachedFailures++; continue; }
                password = candidate.Value; scope = candidate.Scope; fromCache = candidate.FromPriorCache; return true;
            }
            return false;
        }
        bool PasswordBudgetExhausted()
        {
            if (context.Budget.Snapshot().PasswordAttempts < context.Budget.Limits.MaximumPasswordAttempts) return false;
            node.Decryption = ContainerStageStatus.LimitReached;
            ContainerGap(context, node, ContainerStageStatus.LimitReached, "本轮密码解码尝试达到上限，未继续询问或解码。", "ARCHIVE-ATTEMPT-LIMIT");
            return true;
        }
    }

    private static void RecordDecodedMemberMetrics(ContainerContext context, DecodedContainerMember member)
    {
        if (member.MetricsRecorded) return;
        context.Report.Metrics.ArchiveEntriesVisited++;
        context.Report.Metrics.ArchiveBytesExpanded += member.Length;
        context.Report.Metrics.BytesHashed += member.Length;
        member.MetricsRecorded = true;
    }

    private void PreserveSkippedContainerMembers(ContainerContext context, ContainerScanNode parent,
        IReadOnlyList<SkippedContainerMember> members)
    {
        if (members.Count == 0) return;
        parent.Integrity = ContainerStageStatus.Partial;
        if (members.Any(member => member.IsEncrypted)) parent.Decryption = ContainerStageStatus.Partial;
        int firstFinding = context.Report.Findings.Count;
        foreach (SkippedContainerMember member in members)
        {
            context.Report.Metrics.ArchiveEntriesVisited++;
            if (context.Report.Containers!.Nodes.Count >= context.Budget.Limits.MaximumNodes)
            {
                ContainerGap(context, parent, ContainerStageStatus.LimitReached,
                    $"容器节点达到容量上限；{members.Count} 个声明超限成员的逐项记录可能不完整。", member.RuleId);
                break;
            }
            ContainerScanNode node = AddContainerNode(context, member.Display, parent.OriginalTarget, parent,
                parent.Depth + 1, ContainerNodeKind.ArchiveMember, member.Length);
            node.Format = "未打开归档成员（仅目录声明）";
            node.Recognition = ContainerStageStatus.Pending;
            node.Decryption = member.IsEncrypted ? ContainerStageStatus.Skipped : ContainerStageStatus.NotRequested;
            node.Integrity = node.ContentCheck = node.Overall = ContainerStageStatus.LimitReached;
            node.Engines.Add(new()
            {
                Engine = "SHA-256",
                Status = ContainerStageStatus.Skipped,
                Length = member.Length,
                Detail = "仅保留目录声明长度；未读取成员内容，没有可验证的内容 SHA-256。"
            });
            ContainerGap(context, node, ContainerStageStatus.LimitReached, member.Detail, member.RuleId);
            BindContainerFindings(context, node, firstFinding);
            node.CompletedAtUtc = DateTimeOffset.UtcNow; node.Revision++;
            firstFinding = context.Report.Findings.Count;
        }
        BindContainerFindings(context, parent, firstFinding);
        parent.Overall = ContainerStageStatus.Partial;
        context.Report.Containers!.Complete = false; context.Report.Coverage = ScanCoverage.Partial;
    }

    private void PreserveVerifiedContainerMembers(ContainerContext context, ContainerScanNode parent,
        IEnumerable<DecodedContainerMember> members, ContainerStageStatus interrupted)
    {
        // Only members added after verifier.Complete, Seal and accepted-length accounting enter
        // this list. Do not reopen payloads or call the exhausted/cancelled budget to retain facts.
        int omitted = 0;
        ContainerScanReport containers = context.Report.Containers!;
        foreach (DecodedContainerMember member in members)
        {
            RecordDecodedMemberMetrics(context, member);
            // Repeated names or hashes do not identify an archive entry. Only the exact node
            // created for this decode result may be updated after interrupted content checks.
            ContainerScanNode? node = member.PublishedNodeId is { } published
                ? containers.Nodes.SingleOrDefault(existing => existing.NodeId == published) : null;
            if (node is null)
            {
                if (containers.Nodes.Count >= context.Budget.Limits.MaximumNodes) { omitted++; continue; }
                node = AddContainerNode(context, member.Display, parent.OriginalTarget, parent, parent.Depth + 1,
                    ContainerNodeKind.ArchiveMember, member.Length);
                member.PublishedNodeId = node.NodeId;
                node.Format = "已校验归档成员（格式待检查）";
                node.Recognition = ContainerStageStatus.Pending;
                node.Integrity = ContainerStageStatus.Complete;
                node.Decryption = member.IsEncrypted ? ContainerStageStatus.Complete : ContainerStageStatus.NotRequested;
            }
            node.Sha256 ??= member.Hash;
            if (node.Length == 0) node.Length = member.Length;
            // Existing nodes may themselves be archives with incomplete inner integrity or
            // decryption. Preserve those outcomes; the upstream verified member is separate.
            if (node.ContentCheck != ContainerStageStatus.Complete) node.ContentCheck = interrupted;
            node.Overall = interrupted;
            if (node.Engines.Count < 16 && !node.Engines.Any(engine => engine.Engine == "SHA-256" && engine.Status == ContainerStageStatus.Complete))
                node.Engines.Add(new()
                {
                    Engine = "SHA-256",
                    Status = ContainerStageStatus.Complete,
                    Length = member.Length,
                    Detail = "上层解码完成时已计算并核对归档完整性；中止后只保留元数据，未重读临时内容。"
                });
            if (node.Details.Count < 32) node.Details.Add("归档成员身份已验证；后续格式识别或内容引擎未全部完成。未将临时文件声明为已交付恢复副本。");
            node.CompletedAtUtc = DateTimeOffset.UtcNow; node.Revision++;
        }
        if (omitted > 0 && parent.Details.Count < 32)
            parent.Details.Add($"容器节点已达容量上限，另有 {omitted} 个已校验成员未能登记；该部分证据仍有缺口。");
        context.Report.Containers!.Resources = context.Budget.Snapshot();
        context.Report.Containers.Complete = false; context.Report.Coverage = ScanCoverage.Partial;
        Checkpoint?.Invoke(context.Report);
    }

    internal static ContainerStageStatus ContainerCompletionStatus(ContainerScanNode node, IEnumerable<ContainerScanNode> children) =>
        new[] { node.Recognition, node.DirectoryRead, node.Decryption, node.Integrity, node.ContentCheck }.All(StageComplete) &&
        children.All(child => child.Overall == ContainerStageStatus.Complete)
            ? ContainerStageStatus.Complete : ContainerStageStatus.Partial;

    private static ContainerStageStatus VolumeStatus(ArchiveVolumeStatus status) => status switch
    {
        ArchiveVolumeStatus.MissingVolume => ContainerStageStatus.MissingVolume,
        ArchiveVolumeStatus.DuplicateVolume => ContainerStageStatus.DuplicateVolume,
        ArchiveVolumeStatus.MixedVolumes => ContainerStageStatus.MixedVolumes,
        ArchiveVolumeStatus.InvalidMetadata => ContainerStageStatus.Corrupt,
        ArchiveVolumeStatus.UnsupportedIntegrity => ContainerStageStatus.UnsupportedIntegrity,
        ArchiveVolumeStatus.LimitExceeded => ContainerStageStatus.LimitReached,
        ArchiveVolumeStatus.Unavailable => ContainerStageStatus.AccessDenied,
        _ => ContainerStageStatus.Unsupported
    };
}
