using System.Buffers;
using System.Security.Cryptography;
using SharpCompress.Common;
using SharpCompress.Readers;
using SteamSentinel.Core.Inspection;
using SteamSentinel.Core.Models;
using SteamSentinel.Core.Utilities;

namespace SteamSentinel.Core.Scanning;

public sealed partial class ContentScanner
{
    // Legacy stream formats share the same work, disk, depth and entry budgets. Their
    // decoder output is useful for static inspection, but is not a verified archive proof.
    private async Task ScanOtherContainerArchiveAsync(Stream source, ContainerContext context, ContainerScanNode node)
    {
        node.Integrity = ContainerStageStatus.UnsupportedIntegrity;
        node.DirectoryRead = ContainerStageStatus.Pending;
        node.Details.Add("此单流格式可以受限展开，但尚无独立完整性验证，结果保留为部分完成。");
        using ContainerTemporaryStore temporary = new(context.Budget);
        List<(ContainerTemporaryFile File, string Display, string Hash)> staged = [];
        source.Position = 0;
        using (IReader reader = ReaderFactory.OpenReader(source, new ReaderOptions { LeaveStreamOpen = true, LookForHeader = false }))
        {
            try
            {
                while (true)
                {
                    context.Budget.ChargeMetadata();
                    if (!reader.MoveToNextEntry()) break;
                    if (context.Report.Metrics.ArchiveEntriesVisited >= context.Budget.Limits.MaximumEntries)
                        throw new ScanResourceLimitException("归档条目数量达到本轮上限。");
                    context.Report.Metrics.ArchiveEntriesVisited++;
                    IEntry entry = reader.Entry;
                    if (entry.IsEncrypted) throw new NotSupportedException("此单流格式的加密方案尚不支持。");
                    if (entry.IsDirectory) continue;
                    if (entry.Size < 0 || entry.Size > context.Budget.Limits.MaximumEntryBytes ||
                        entry.CompressedSize > 0 && entry.Size / (double)entry.CompressedSize > context.Budget.Limits.MaximumCompressionRatio)
                        throw new ContainerEntryLimitException("ARCHIVE-SIZE-LIMIT", "单流成员声明大小或压缩比超过单项上限，已停止此归档。");
                    string display = node.DisplayPath + "!/" + SanitizeEntryDisplayName(entry.Key);
                    if (IsUnsafeArchiveName(entry.Key))
                    {
                        AddUnsafeArchiveFinding(context.Report, node.OriginalTarget, display, context.WorkshopId);
                        context.Report.Findings[^1].TargetSha256 = node.OriginalTargetSha256;
                    }
                    ContainerTemporaryFile output = temporary.CreateFile();
                    using IncrementalHash hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
                    long copied = 0;
                    using (Stream input = reader.OpenEntryStream())
                    {
                        try
                        {
                            byte[] buffer = ArrayPool<byte>.Shared.Rent(128 * 1024);
                            try
                            {
                                while (true)
                                {
                                    int requested = context.Budget.ReadAllowance(buffer.Length);
                                    int count = await input.ReadAsync(buffer.AsMemory(0, requested), context.Token);
                                    if (count == 0) break;
                                    context.Budget.ChargeDecoded(count); copied = checked(copied + count);
                                    if (copied > context.Budget.Limits.MaximumEntryBytes || entry.Size > 0 && copied > entry.Size ||
                                        entry.CompressedSize > 0 && copied / (double)entry.CompressedSize > context.Budget.Limits.MaximumCompressionRatio)
                                        throw new ContainerEntryLimitException("ARCHIVE-SIZE-LIMIT", "单流成员实际展开大小或压缩比超过单项上限，已停止此归档。");
                                    context.Budget.AcceptExpansion(count);
                                    hash.AppendData(buffer, 0, count);
                                    await output.WriteAsync(buffer.AsMemory(0, count), context.Token);
                                }
                            }
                            finally { ArrayPool<byte>.Shared.Return(buffer, clearArray: true); }
                        }
                        catch { reader.Cancel(); throw; }
                    }
                    if (entry.Size > 0 && copied != entry.Size) throw new InvalidDataException("单流成员实际长度与声明不一致。");
                    await output.SealAsync(context.Token);
                    context.Report.Metrics.ArchiveBytesExpanded += copied;
                    staged.Add((output, display, Convert.ToHexString(hash.GetHashAndReset())));
                }
            }
            catch { reader.Cancel(); throw; }
        }
        node.DirectoryRead = ContainerStageStatus.Complete;
        ArchiveVolumeCandidate[] siblings = staged.Select(member => new ArchiveVolumeCandidate(member.File.Path, member.Display)).ToArray();
        foreach (var member in staged)
            await ScanContainerFileAsync(new(member.File.Path, member.Display), node.OriginalTarget, context, node,
                node.Depth + 1, ContainerNodeKind.ArchiveMember, siblings, verifiedHash: member.Hash);
    }
}
