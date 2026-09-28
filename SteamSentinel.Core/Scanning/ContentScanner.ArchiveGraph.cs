using SteamSentinel.Core.Reporting;
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
                    MessageText.Create("Backend.Core.ContentScanner.ArchiveGraph.ScanContainerRangesAsync.01", (archives.Length), (inspection.UnknownRanges.Count)));
                return;
            }
            foreach (ContainerRange range in archives)
            {
                if (range.Offset == 0 && range.Length == node.Length && node.Kind == ContainerNodeKind.EmbeddedRange) continue;
                string suffix = range.Type == ContainerRangeType.Zip ? ".zip" : ".rar";
                string display = node.DisplayPath + $"!/@range-{range.Offset}-{range.Length}" + suffix;
                if (context.Options.InspectArchives && node.Depth >= context.Budget.Limits.MaximumDepth)
                    ScanResourceSession.Allow("ContainerLimits.MaximumDepth", node.Depth + 1L);
                if (range.Status is not (ContainerRangeStatus.Validated or ContainerRangeStatus.ValidatedContainerHeader) ||
                    !context.Options.InspectArchives || node.Depth >= context.Budget.Limits.MaximumDepth)
                {
                    ContainerScanNode skipped = AddContainerNode(context, display, node.OriginalTarget, node, node.Depth + 1,
                        ContainerNodeKind.EmbeddedRange, range.Length, range.Offset);
                    skipped.FormatText = range.Type.ToString(); skipped.Recognition = ContainerStageStatus.Complete;
                    int firstFinding = context.Report.Findings.Count;
                    ContainerGap(context, skipped, !context.Options.InspectArchives ? ContainerStageStatus.NotRequested : ContainerStageStatus.LimitReached,
                        MessageText.Create("Backend.Core.ContentScanner.ArchiveGraph.ScanContainerRangesAsync.02"));
                    BindContainerFindings(context, skipped, firstFinding);
                    FinishContainer(context, skipped); continue;
                }
                await ScanContainerFileAsync(new(source.PhysicalPath, display, checked(source.Offset + range.Offset), range.Length),
                    node.OriginalTarget, context, node, node.Depth + 1, ContainerNodeKind.EmbeddedRange, null, range.Offset);
            }
            foreach (ContainerRange range in inspection.UnknownRanges)
                await ScanUnknownContainerRangeAsync(source, context, node, range, () => executableTail = true);
            if (inspection.Status is ContainerRangeStatus.Malformed or ContainerRangeStatus.Unsupported or ContainerRangeStatus.LimitReached)
                ContainerGap(context, node, ContainerStageStatus.Partial, inspection.DetailText, "CONTAINER-STRUCTURE-PARTIAL");
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
                    TitleText = MessageText.Create("Backend.Core.ContentScanner.ArchiveGraph.ScanContainerRangesAsync.03"),
                    DescriptionText = MessageText.Create("Backend.Core.ContentScanner.ArchiveGraph.ScanContainerRangesAsync.04") +
                        (executableTail ? MessageText.Create("Backend.Core.ContentScanner.ArchiveGraph.ScanContainerRangesAsync.05") : (MessageText)""),
                    Target = node.OriginalTarget,
                    TargetSha256 = node.OriginalTargetSha256,
                    ContentPath = node.DisplayPath,
                    Sha256 = node.Sha256,
                    EvidenceText = inspection.DetailText + MessageText.Create("Backend.Core.ContentScanner.ArchiveGraph.ScanContainerRangesAsync.06") + node.DisplayPath,
                    WorkshopId = context.WorkshopId,
                    SuggestedActions = [SuggestedActionKind.ReviewOnly]
                });
        }
    }

    private async Task ScanUnknownContainerRangeAsync(ArchiveVolumeCandidate source, ContainerContext context,
        ContainerScanNode parent, ContainerRange range, Action executableFound)
    {
        bool familyMetadata = parent.VPetFamily is { EnvelopeValidated: true } family &&
            family.FooterOffset == range.Offset && family.FooterLength == range.Length;
        ContainerScanNode node = AddContainerNode(context, parent.DisplayPath + $"!/@{(familyMetadata ? "vpet-footer" : "unknown")}-{range.Offset}-{range.Length}",
            parent.OriginalTarget, parent, parent.Depth + 1, familyMetadata ? ContainerNodeKind.EmbeddedRange : ContainerNodeKind.UnknownRange, range.Length, range.Offset);
        node.FormatText = familyMetadata ? MessageText.Create("Backend.Core.ContentScanner.ArchiveGraph.ScanUnknownContainerRangeAsync.01") : MessageText.Create("Backend.Core.ContentScanner.ArchiveGraph.ScanUnknownContainerRangeAsync.02");
        node.Recognition = familyMetadata ? ContainerStageStatus.Complete : ContainerStageStatus.Unsupported;
        node.Integrity = familyMetadata ? ContainerStageStatus.NotRequested : ContainerStageStatus.UnsupportedIntegrity;
        int firstFinding = context.Report.Findings.Count;
        if (familyMetadata) node.AddDetail(MessageText.Create("Backend.Core.ContentScanner.ArchiveGraph.ScanUnknownContainerRangeAsync.03"));
        else ContainerGap(context, node, ContainerStageStatus.Unsupported, range.DetailText, "CONTAINER-UNKNOWN-RANGE");
        try
        {
            context.Budget.Check(); _resources.Check(context.Report);
            if (context.Report.Metrics.FilesVisited >= context.Options.MaximumFiles &&
                !ScanResourceSession.Allow("MaximumFiles", context.Report.Metrics.FilesVisited + 1, context.Report.Metrics.FilesVisited, known: false))
                throw MessageExceptions.Create(MessageText.Create("Backend.Core.ContentScanner.ArchiveGraph.ScanUnknownContainerRangeAsync.04"), sourceText => new ScanResourceLimitException(sourceText));
            await using FileStream file = RelatedArtifactReader.Open(source.PhysicalPath);
            RelatedArtifactReader.ValidatePath(file.SafeFileHandle, Path.GetFullPath(source.PhysicalPath));
            ArchiveVolumeCandidate selected = new(source.PhysicalPath, node.DisplayPath, checked(source.Offset + range.Offset), range.Length);
            using BoundedReadOnlyStream stream = new(file, selected.Offset, range.Length, budget: context.Budget);
            context.Report.Metrics.FilesVisited++;
            // A bounded recognition head is still useful when full-content hashing is not scheduled.
            FileTypeResult type = await FileTypeDetector.DetectAsync(stream, node.DisplayPath, context.Token);
            node.AddDetail(ShortContainerDetail(MessageText.Create("Backend.Core.ContentScanner.ArchiveGraph.ScanUnknownContainerRangeAsync.05") + type.LabelText + MessageText.Create("Backend.Core.ContentScanner.ArchiveGraph.ScanUnknownContainerRangeAsync.06")));
            if (type.IsExecutableOrScript) executableFound();
            long charged = Math.Max(0, context.Report.Metrics.BytesHashed -
                (context.Options.Mode == ScanMode.Quick ? context.Report.Metrics.QuickPriorityBytesHashed : 0));
            long remaining = context.Options.MaximumContentBytes == long.MaxValue ? long.MaxValue :
                Math.Max(0, context.Options.MaximumContentBytes - charged);
            if (range.Length > remaining && range.Length <= long.MaxValue - charged && ScanResourceSession.Allow("MaximumContentBytes", charged + range.Length, charged))
                remaining = context.Options.MaximumContentBytes - charged;
            if (context.Options.Mode == ScanMode.Quick && range.Length > context.Options.MaximumQuickFileBytes)
                ScanResourceSession.Allow("MaximumQuickFileBytes", range.Length);
            if (range.Length > remaining || context.Options.Mode == ScanMode.Quick && range.Length > context.Options.MaximumQuickFileBytes)
            {
                node.ContentCheck = ContainerStageStatus.LimitReached;
                node.Engines.Add(new()
                {
                    Engine = "SHA-256",
                    Status = ContainerStageStatus.Skipped,
                    Length = 0,
                    DetailText = MessageText.Create("Backend.Core.ContentScanner.ArchiveGraph.ScanUnknownContainerRangeAsync.07")
                });
                ContainerGap(context, node, ContainerStageStatus.LimitReached, MessageText.Create("Backend.Core.ContentScanner.ArchiveGraph.ScanUnknownContainerRangeAsync.08"), "CONTENT-BYTE-BUDGET");
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
                DetailText = MessageText.Create("Backend.Core.ContentScanner.ArchiveGraph.ScanUnknownContainerRangeAsync.09")
            });
            bool suspicious = _rules.DangerousExtensions.Contains(Path.GetExtension(node.DisplayPath), StringComparer.OrdinalIgnoreCase);
            AddContainerFileFindings(context, node, type, suspicious);
            await ScanContainerLeafAsync(file, stream, selected, context, node, type, suspicious, archive: type.IsArchive);
            // Recognition and integrity remain unsupported even when all requested leaf engines ran.
            if (!familyMetadata) node.Overall = ContainerStageStatus.Unsupported;
            RelatedArtifactReader.ValidatePath(file.SafeFileHandle, Path.GetFullPath(source.PhysicalPath));
        }
        catch (OperationCanceledException)
        {
            node.ContentCheck = ContainerStageStatus.Cancelled;
            ContainerGap(context, node, ContainerStageStatus.Cancelled, MessageText.Create("Backend.Core.ContentScanner.ArchiveGraph.ScanUnknownContainerRangeAsync.10")); throw;
        }
        catch (ScanResourceLimitException ex)
        {
            node.ContentCheck = ContainerStageStatus.LimitReached;
            ContainerGap(context, node, ContainerStageStatus.LimitReached, MessageExceptions.Describe(ex)); throw;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidDataException or NotSupportedException or
            ArgumentException or OverflowException or System.ComponentModel.Win32Exception or SharpCompressException)
        {
            node.ContentCheck = ex is UnauthorizedAccessException or System.ComponentModel.Win32Exception
                ? ContainerStageStatus.AccessDenied : ContainerStageStatus.Failed;
            ContainerGap(context, node, node.ContentCheck, MessageText.Create("Backend.Core.ContentScanner.ArchiveGraph.ScanUnknownContainerRangeAsync.11") + ex.GetType().Name + "）：" + MessageExceptions.Describe(ex));
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
            foreach (string path in Directory.EnumerateFiles(directory))
            {
                context.Budget.Check();
                if (IsExcluded(path, context.Options.ExcludedRoots)) continue;
                // Supplemental directories are explicitly selected. Project their leaf names into
                // this group, preserving physical identities; duplicate names are rejected by resolver.
                string display = Path.Combine(Path.GetDirectoryName(source.DisplayName) ?? "", Path.GetFileName(path));
                candidates.Add(new(path, display));
                if (candidates.Count > limits.MaximumCandidates)
                {
                    if (!ScanResourceSession.Allow("ContainerLimits.MaximumDirectoryCandidates", candidates.Count, candidates.Count - 1, known: false))
                        return ArchiveVolumeResolver.Resolve(source, candidates, limits);
                    limits = limits with { MaximumCandidates = context.Budget.Limits.MaximumDirectoryCandidates };
                }
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
    private sealed class ContainerEntryLimitException : IOException
    {
        public string RuleId { get; }
        public ContainerEntryLimitException(string ruleId, MessageText detail) : base(detail.OriginalText)
        { RuleId = ruleId; MessageExceptions.Attach(this, detail); }
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
                    if (!fileIds.Add(fileId)) throw new ArchiveVolumeException(ArchiveVolumeStatus.DuplicateVolume, MessageText.Create("Backend.Core.ContentScanner.ArchiveGraph.CaptureAsync.01"));
                    physical.AppendData(System.Text.Encoding.UTF8.GetBytes($"{fileId}\0{member.Offset}\0{member.Length}\0"));
                    total = checked(total + file.Length);
                    if (total > plan.Limits.MaximumTotalBytes) throw MessageExceptions.Create(MessageText.Create("Backend.Core.ContentScanner.ArchiveGraph.CaptureAsync.02"), sourceText => new ScanResourceLimitException(sourceText));
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

    private sealed record SkippedContainerMember(string Display, long Length, bool IsEncrypted, string RuleId, MessageText Detail);

    private async Task<ContainerDecodeAttempt> DecodeContainerAttemptAsync(ArchiveVolumePlan plan, string? password,
        ContainerContext context, ContainerScanNode node)
    {
        ContainerDecodeAttempt attempt = new(new(context.Budget));
        try
        {
            context.Progress?.Report(new(MessageText.Create("Backend.Core.ContentScanner.ArchiveGraph.DecodeContainerAttemptAsync.01"), node.DisplayPath, context.Report.Metrics.ArchiveEntriesVisited, null,
                MessageText.Create("Backend.Core.ContentScanner.ArchiveGraph.DecodeContainerAttemptAsync.02", (plan.Members.Count))));
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
                    long visitedEntries = (long)attempt.Members.Count + attempt.SkippedMembers.Count + attempt.DirectoryEntries + context.Report.Metrics.ArchiveEntriesVisited;
                    if (visitedEntries >= context.Budget.Limits.MaximumEntries &&
                        !ScanResourceSession.Allow("ContainerLimits.MaximumEntries", visitedEntries + 1, visitedEntries, known: false))
                        throw MessageExceptions.Create(MessageText.Create("Backend.Core.ContentScanner.ArchiveGraph.DecodeContainerAttemptAsync.03"), sourceText => new ScanResourceLimitException(sourceText));
                    if (entry.IsDirectory) { attempt.DirectoryEntries++; continue; }
                    string name = entry.Key ?? "(unnamed)";
                    string display = node.DisplayPath + "!/" + SanitizeEntryDisplayName(name);
                    using IDisposable resourceTarget = ScanResourceSession.EnterTarget(display);
                    if (entry.Size < 0 || entry.Size > context.Budget.Limits.MaximumEntryBytes &&
                        !ScanResourceSession.Allow("ContainerLimits.MaximumEntryBytes", entry.Size))
                    {
                        if (SkipLimitedZipMember("ARCHIVE-SIZE-LIMIT", MessageText.Create("Backend.Core.ContentScanner.ArchiveGraph.DecodeContainerAttemptAsync.04"))) continue;
                        throw new ContainerEntryLimitException("ARCHIVE-SIZE-LIMIT", MessageText.Create("Backend.Core.ContentScanner.ArchiveGraph.DecodeContainerAttemptAsync.05"));
                    }
                    if (entry.CompressedSize > 0 && entry.Size / (double)entry.CompressedSize > context.Budget.Limits.MaximumCompressionRatio &&
                        !ScanResourceSession.Allow("ContainerLimits.MaximumCompressionRatio", checked((long)Math.Ceiling(entry.Size / (double)entry.CompressedSize))))
                    {
                        if (SkipLimitedZipMember("ARCHIVE-RATIO-LIMIT", MessageText.Create("Backend.Core.ContentScanner.ArchiveGraph.DecodeContainerAttemptAsync.06"))) continue;
                        throw new ContainerEntryLimitException("ARCHIVE-RATIO-LIMIT", MessageText.Create("Backend.Core.ContentScanner.ArchiveGraph.DecodeContainerAttemptAsync.07"));
                    }
                    if (entry.Size > context.Budget.Limits.MaximumExpandedBytes - context.Budget.AcceptedExpandedBytes &&
                        !ScanResourceSession.Allow("ContainerLimits.MaximumExpandedBytes", checked(context.Budget.AcceptedExpandedBytes + entry.Size), context.Budget.AcceptedExpandedBytes))
                        throw MessageExceptions.Create(MessageText.Create("Backend.Core.ContentScanner.ArchiveGraph.DecodeContainerAttemptAsync.08"), sourceText => new ScanResourceLimitException(sourceText));
                    using ArchiveIntegrityEntryVerifier verifier = ArchiveIntegrity.Begin(session, entry);
                    if (!verifier.Requirement.Supported)
                        throw new ArchiveVolumeException(ArchiveVolumeStatus.UnsupportedIntegrity, verifier.Requirement.DetailText);
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
                                    if (copied > context.Budget.Limits.MaximumEntryBytes &&
                                        !ScanResourceSession.Allow("ContainerLimits.MaximumEntryBytes", copied, known: false))
                                        throw new ContainerEntryLimitException("ARCHIVE-SIZE-LIMIT", MessageText.Create("Backend.Core.ContentScanner.ArchiveGraph.DecodeContainerAttemptAsync.09"));
                                    if (copied > entry.Size)
                                        throw new ArchiveVolumeException(ArchiveVolumeStatus.InvalidMetadata, MessageText.Create("Backend.Core.ContentScanner.ArchiveGraph.DecodeContainerAttemptAsync.10"));
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
                    context.Progress?.Report(new(MessageText.Create("Backend.Core.ContentScanner.ArchiveGraph.DecodeContainerAttemptAsync.11"), display, attempt.Members.Count, null,
                        MessageText.Create("Backend.Core.ContentScanner.ArchiveGraph.DecodeContainerAttemptAsync.12")));

                    bool SkipLimitedZipMember(string ruleId, MessageText detail)
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
            node.DirectoryRead = VolumeStatus(plan.Status); ContainerGap(context, node, node.DirectoryRead, plan.DetailText,
                plan.Status == ArchiveVolumeStatus.MissingVolume ? "ARCHIVE-MISSING-VOLUME" : "ARCHIVE-UNSUPPORTED"); return;
        }
        node.DirectoryRead = node.Integrity = ContainerStageStatus.Pending;
        if (plan.Layout != ArchiveVolumeLayout.Single) node.Kind = ContainerNodeKind.VolumeGroup;
        node.FormatText = plan.Format.ToString() + (plan.Members.Count > 1 ? MessageText.Create("Backend.Core.ContentScanner.ArchiveGraph.ScanContainerArchiveAsync.01", (plan.Members.Count)) : (MessageText)"");
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
            node.AddDetail(MessageText.Create("Backend.Core.ContentScanner.ArchiveGraph.ScanContainerArchiveAsync.02", (previous.NodeId)));
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
                        ContainerGap(context, node, status, MessageText.Create("Backend.Core.ContentScanner.ArchiveGraph.ScanContainerArchiveAsync.03") + attempt.Failure.GetType().Name + "）：" +
                            (attempt.Failure is ArchiveVolumeException or ContainerEntryLimitException or ScanResourceLimitException ? MessageExceptions.Describe(attempt.Failure) : MessageText.Create("Backend.Core.ContentScanner.ArchiveGraph.ScanContainerArchiveAsync.04")),
                            attempt.Failure is ContainerEntryLimitException entryLimit ? entryLimit.RuleId :
                                attempt.Failure is ScanResourceLimitException ? "ARCHIVE-ATTEMPT-LIMIT" : "ARCHIVE-UNSUPPORTED");
                    }
                    // Only completed decoding is reusable; an incomplete group can receive a
                    // distinct later attempt after the user supplies missing input.
                    if (attempt.Complete && attempt.GroupHash is not null)
                    {
                        node.Overall = ContainerCompletionStatus(node, ChildrenOf(node));
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
                    MessageText.Create("Backend.Core.ContentScanner.ArchiveGraph.ScanContainerArchiveAsync.05"), "ARCHIVE-ENCRYPTED-DEFERRED"); return;
            }
            if (_passwords.SkipAllEncrypted)
            {
                _passwords.Defer(identity); ContainerGap(context, node, ContainerStageStatus.Skipped,
                    MessageText.Create("Backend.Core.ContentScanner.ArchiveGraph.ScanContainerArchiveAsync.06"), "ARCHIVE-ENCRYPTED-NOT-SCANNED"); return;
            }
            bool repeated = false;
            while (true)
            {
                if (PasswordBudgetExhausted()) return;
                if (manualAttempts >= 3)
                {
                    _passwords.Defer(identity); ContainerGap(context, node, ContainerStageStatus.PasswordFailed,
                        MessageText.Create("Backend.Core.ContentScanner.ArchiveGraph.ScanContainerArchiveAsync.07"), "ARCHIVE-PASSWORD-FAILED"); return;
                }
                ArchivePasswordPromptKind kind = repeated ? ArchivePasswordPromptKind.RepeatedPassword : manualAttempts > 0 ?
                    ArchivePasswordPromptKind.EnteredPasswordFailed : cachedFailures > 0 ? ArchivePasswordPromptKind.CachedPasswordFailed : ArchivePasswordPromptKind.Needed;
                MessageText reason = kind switch
                {
                    ArchivePasswordPromptKind.CachedPasswordFailed => MessageText.Create("Backend.Core.ContentScanner.ArchiveGraph.ScanContainerArchiveAsync.CachedPasswordFailed.01"),
                    ArchivePasswordPromptKind.EnteredPasswordFailed => MessageText.Create("Backend.Core.ContentScanner.ArchiveGraph.ScanContainerArchiveAsync.EnteredPasswordFailed.01"),
                    ArchivePasswordPromptKind.RepeatedPassword => MessageText.Create("Backend.Core.ContentScanner.ArchiveGraph.ScanContainerArchiveAsync.RepeatedPassword.01"),
                    _ => MessageText.Create("Backend.Core.ContentScanner.ArchiveGraph.ScanContainerArchiveAsync.08")
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
                        MessageText.Create("Backend.Core.ContentScanner.ArchiveGraph.ScanContainerArchiveAsync.09"), "ARCHIVE-ENCRYPTED-NOT-SCANNED"); return;
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
                        MessageText.Create("Backend.Core.ContentScanner.ArchiveGraph.ScanContainerArchiveAsync.10"), "ARCHIVE-ENCRYPTED-NOT-SCANNED"); return;
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
            ContainerGap(context, node, ContainerStageStatus.LimitReached, MessageText.Create("Backend.Core.ContentScanner.ArchiveGraph.ScanContainerArchiveAsync.11"), "ARCHIVE-ATTEMPT-LIMIT");
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
                    MessageText.Create("Backend.Core.ContentScanner.ArchiveGraph.PreserveSkippedContainerMembers.01", (members.Count)), member.RuleId);
                break;
            }
            ContainerScanNode node = AddContainerNode(context, member.Display, parent.OriginalTarget, parent,
                parent.Depth + 1, ContainerNodeKind.ArchiveMember, member.Length);
            node.FormatText = MessageText.Create("Backend.Core.ContentScanner.ArchiveGraph.PreserveSkippedContainerMembers.02");
            node.Recognition = ContainerStageStatus.Pending;
            node.Decryption = member.IsEncrypted ? ContainerStageStatus.Skipped : ContainerStageStatus.NotRequested;
            node.Integrity = node.ContentCheck = node.Overall = ContainerStageStatus.LimitReached;
            node.Engines.Add(new()
            {
                Engine = "SHA-256",
                Status = ContainerStageStatus.Skipped,
                Length = member.Length,
                DetailText = MessageText.Create("Backend.Core.ContentScanner.ArchiveGraph.PreserveSkippedContainerMembers.03")
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
                node.FormatText = MessageText.Create("Backend.Core.ContentScanner.ArchiveGraph.PreserveVerifiedContainerMembers.01");
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
                    DetailText = MessageText.Create("Backend.Core.ContentScanner.ArchiveGraph.PreserveVerifiedContainerMembers.02")
                });
            if (node.Details.Count < 32) node.AddDetail(MessageText.Create("Backend.Core.ContentScanner.ArchiveGraph.PreserveVerifiedContainerMembers.03"));
            node.CompletedAtUtc = DateTimeOffset.UtcNow; node.Revision++;
        }
        if (omitted > 0 && parent.Details.Count < 32)
            parent.AddDetail(MessageText.Create("Backend.Core.ContentScanner.ArchiveGraph.PreserveVerifiedContainerMembers.04", (omitted)));
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
