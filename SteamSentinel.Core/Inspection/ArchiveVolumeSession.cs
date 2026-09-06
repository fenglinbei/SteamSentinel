using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Win32.SafeHandles;
using SharpCompress.Archives;
using SharpCompress.Readers;
using SteamSentinel.Core.Utilities;

namespace SteamSentinel.Core.Inspection;

/// <summary>Owns read locks for every supplied physical volume for its complete lifetime. Never discovers paths.</summary>
public sealed class ArchiveVolumeSession : IDisposable
{
    private readonly List<(FileStream File, Stream Decorated, Stream Range)> _owned;
    private readonly CancellationToken _cancellationToken;
    private bool _readerOpened;
    private bool _disposed;
    private ArchiveVolumeTraversal? _traversal;
    private readonly Dictionary<(string Key, long Size, uint Crc, bool Encrypted), ArchiveIntegrityZipMember?> _zipIndex = [];
    public ArchiveVolumePlan Plan { get; }
    public IArchive Archive { get; }
    public IReadOnlyList<ArchiveVolumeIdentity> Identities { get; }
    public string GroupSha256 { get; }
    internal string? Password { get; }
    internal IReadOnlyList<ArchiveIntegrityZipMember> ZipMembers { get; }
    internal ArchiveRarIntegrityIndex? RarIntegrity { get; }

    private ArchiveVolumeSession(ArchiveVolumePlan plan, IArchive archive,
        List<(FileStream File, Stream Decorated, Stream Range)> owned,
        List<ArchiveVolumeIdentity> identities, string? password,
        IReadOnlyList<ArchiveIntegrityZipMember> zipMembers, ArchiveRarIntegrityIndex? rarIntegrity, CancellationToken cancellationToken)
    {
        Plan = plan; Archive = archive; _owned = owned; Password = password; ZipMembers = zipMembers;
        _cancellationToken = cancellationToken;
        RarIntegrity = rarIntegrity; Identities = Array.AsReadOnly(identities.ToArray());
        foreach (ArchiveIntegrityZipMember member in zipMembers)
        {
            var key = (member.Key, member.Size, member.Crc, member.Encrypted);
            if (!_zipIndex.TryAdd(key, member)) _zipIndex[key] = null;
        }
        using IncrementalHash hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        hash.AppendData("SteamSentinel.ArchiveVolumes.v1\0"u8);
        hash.AppendData(Encoding.UTF8.GetBytes($"{plan.Format}\0{plan.Layout}\0"));
        foreach (ArchiveVolumeIdentity identity in identities)
            hash.AppendData(Encoding.UTF8.GetBytes($"{identity.SourceLength}\0{identity.Offset}\0{identity.Length}\0{identity.Sha256}\0{identity.RangeSha256}\0"));
        GroupSha256 = Convert.ToHexString(hash.GetHashAndReset());
    }

    public static async Task<ArchiveVolumeSession> OpenAsync(ArchiveVolumePlan plan, string? password = null,
        CancellationToken cancellationToken = default, Func<Stream, Stream>? readDecorator = null)
    {
        ArgumentNullException.ThrowIfNull(plan); plan.Limits.Validate();
        if (plan.Status != ArchiveVolumeStatus.Ready) throw new ArchiveVolumeException(plan.Status, plan.Detail);
        if (plan.Members.Count == 0 || plan.Members.Count > plan.Limits.MaximumVolumes)
            throw new ArchiveVolumeException(ArchiveVolumeStatus.LimitExceeded, "卷组数量无效。");
        if (password is { Length: > 4096 }) throw new ArgumentOutOfRangeException(nameof(password));
        List<(FileStream File, Stream Decorated, Stream Range)> owned = [];
        List<ArchiveVolumeIdentity> identities = [];
        HashSet<string> fileIds = new(StringComparer.Ordinal);
        IArchive? archive = null;
        try
        {
            long total = 0;
            foreach (ArchiveVolumeCandidate member in plan.Members)
            {
                cancellationToken.ThrowIfCancellationRequested();
                string path = Path.GetFullPath(member.PhysicalPath);
                if (!Path.IsPathFullyQualified(path) || path.StartsWith("\\\\", StringComparison.Ordinal) ||
                    Validation.ContainsReparsePoint(path))
                    throw new ArchiveVolumeException(ArchiveVolumeStatus.Unavailable, "分卷必须是明确的本地普通文件。");
                FileStream file = new(path, FileMode.Open, FileAccess.Read, FileShare.Read, 128 * 1024, FileOptions.Asynchronous);
                Stream decorated = file;
                // Register the lock immediately so every validation/decorator failure releases it.
                owned.Add((file, file, file));
                string fileId = VerifyHandle(file, path);
                if (!fileIds.Add(fileId)) throw new ArchiveVolumeException(ArchiveVolumeStatus.DuplicateVolume, "分卷引用了同一文件身份。");
                long sourceLength = file.Length;
                total = checked(total + sourceLength);
                if (sourceLength <= 0 || total > plan.Limits.MaximumTotalBytes)
                    throw new ArchiveVolumeException(ArchiveVolumeStatus.LimitExceeded, "分卷实际输入字节数超过限额或存在空卷。");
                long rangeLength = member.Length ?? (sourceLength - member.Offset);
                if (member.Offset < 0 || member.Offset > sourceLength || rangeLength <= 0 || rangeLength > sourceLength - member.Offset)
                    throw new ArchiveVolumeException(ArchiveVolumeStatus.InvalidMetadata, "归档输入切片超出已锁定文件。");
                if (readDecorator is not null)
                {
                    decorated = readDecorator(file) ?? throw new ArgumentException("读取计量包装器返回空值。", nameof(readDecorator));
                    owned[^1] = (file, decorated, decorated);
                    if (!decorated.CanRead || !decorated.CanSeek || decorated.CanWrite || decorated.Length != sourceLength)
                        throw new ArgumentException("读取计量包装器必须保留只读可定位视图与原始长度。", nameof(readDecorator));
                }
                decorated.Position = 0;
                string fullHash = Convert.ToHexString(await SHA256.HashDataAsync(decorated, cancellationToken).ConfigureAwait(false));
                Stream range = new ArchiveVolumeSliceStream(decorated, member.Offset, rangeLength);
                owned[^1] = (file, decorated, range);
                string rangeHash = member.Offset == 0 && rangeLength == sourceLength ? fullHash :
                    Convert.ToHexString(await SHA256.HashDataAsync(range, cancellationToken).ConfigureAwait(false));
                range.Position = 0;
                identities.Add(new(path, member.DisplayName, rangeLength, fullHash, member.Offset, sourceLength, rangeHash));
            }
            IReadOnlyList<Stream> ranges = owned.Select(item => item.Range).ToArray();
            using ArchiveVolumeJoinedStream joined = new(ranges);
            IReadOnlyList<ArchiveIntegrityZipMember> zipMembers = [];
            ArchiveRarIntegrityIndex? rar = null;
            switch (plan.Format)
            {
                case ArchiveVolumeFormat.Zip:
                    zipMembers = ArchiveIntegrityZip.Read(joined, plan, password, cancellationToken);
                    break;
                case ArchiveVolumeFormat.SevenZip:
                    ValidateSevenZip(joined, plan, cancellationToken);
                    break;
                case ArchiveVolumeFormat.Rar:
                    rar = ArchiveIntegrity.InspectRarHeaders(ranges, password, plan.Limits, cancellationToken);
                    break;
                default: throw new ArchiveVolumeException(ArchiveVolumeStatus.UnsupportedLayout, "未知归档格式。");
            }
            foreach (Stream range in ranges) range.Position = 0;
            IReadOnlyList<Stream> libraryOrder = ranges;
            if (plan.Layout == ArchiveVolumeLayout.ZipSpanned)
            {
                // 0.50.4 tests localOffset + compressedSize when deciding whether to
                // join disks, omitting the local header length. A short member can
                // therefore cross a disk boundary without activating that branch.
                // Give every disk a bounded continuation view, still rooted at that
                // disk's offset zero; all local metadata was checked against physical
                // disk boundaries above. No view can reach outside admitted volumes.
                Stream[] continuations = Enumerable.Range(0, ranges.Count)
                    .Select(index => (Stream)new ArchiveVolumeJoinedStream(ranges.Skip(index).ToArray())).ToArray();
                libraryOrder = new[] { continuations[^1] }.Concat(continuations.Take(continuations.Length - 1)).ToArray();
            }
            ReaderOptions readerOptions = new() { Password = password, LeaveStreamOpen = true, LookForHeader = false };
            archive = plan.Format switch
            {
                ArchiveVolumeFormat.Zip => SharpCompress.Archives.Zip.ZipArchive.OpenArchive(libraryOrder, readerOptions),
                ArchiveVolumeFormat.Rar => SharpCompress.Archives.Rar.RarArchive.OpenArchive(libraryOrder, readerOptions),
                ArchiveVolumeFormat.SevenZip => SharpCompress.Archives.SevenZip.SevenZipArchive.OpenArchive(libraryOrder, readerOptions),
                _ => throw new InvalidOperationException()
            };
            return new(plan, archive, owned, identities, password, zipMembers, rar, cancellationToken);
        }
        catch
        {
            archive?.Dispose(); DisposeOwned(owned); throw;
        }
    }

    /// <summary>Only one ordered traversal is allowed. Abort it rather than skipping an oversized solid member.</summary>
    public IReader OpenReader()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (_readerOpened) throw new InvalidOperationException("卷组只能进行一次顺序解码；密码重试必须重新打开会话。");
        _readerOpened = true;
        (int entries, int files) = Plan.Format switch
        {
            ArchiveVolumeFormat.Zip => (ZipMembers.Count, ZipMembers.Count(member => !member.IsDirectory)),
            ArchiveVolumeFormat.Rar => (RarIntegrity!.Entries.Count, RarIntegrity.Entries.Count(member => !member.IsDirectory)),
            _ => SevenZipInventory()
        };
        IReader reader = Plan.Format switch
        {
            ArchiveVolumeFormat.Zip => new ArchiveVolumeEntryReader(Archive),
            ArchiveVolumeFormat.Rar => (RarIntegrity ?? throw new InvalidOperationException("RAR 校验索引缺失。"))
                .OpenReader(Password, _cancellationToken),
            _ => Archive.ExtractAllEntries()
        };
        return _traversal = new(reader, entries, files);
    }

    private (int Entries, int Files) SevenZipInventory()
    {
        // This is the initial 7z directory load. ExtractAllEntries reuses these cached
        // records, and final completion checks never re-open or re-decode the archive.
        var entries = Archive.Entries.Take(Plan.Limits.MaximumEntries + 1).ToList();
        if (entries.Count > Plan.Limits.MaximumEntries)
            throw new ArchiveVolumeException(ArchiveVolumeStatus.LimitExceeded, "7z 目录条目超过元数据限额。");
        return (entries.Count, entries.Count(entry => !entry.IsDirectory));
    }

    internal void RequireCurrentEntry(SharpCompress.Common.IEntry entry) =>
        (_traversal ?? throw new InvalidOperationException("完整性校验必须通过会话读取器。")).RequireCurrent(entry);
    internal void MarkEntryVerified(SharpCompress.Common.IEntry entry) =>
        (_traversal ?? throw new InvalidOperationException("完整性校验必须通过会话读取器。")).MarkVerified(entry);

    /// <summary>Only ZIP can move past an unopened file without decoding or automatic skipping.</summary>
    public bool CanSkipCurrentUnopenedEntry => !_disposed && (_traversal?.CanSkipCurrentUnopenedEntry ?? false);
    public int SkippedEntries => _traversal?.SkippedEntries ?? 0;
    /// <summary>Marks the current unopened ZIP file as unverified; the caller still advances its reader.</summary>
    public void SkipCurrentUnopenedEntry(SharpCompress.Common.IEntry entry)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        (_traversal ?? throw new InvalidOperationException("归档遍历尚未开始。")).SkipCurrentUnopenedEntry(entry);
    }
    /// <summary>
    /// Requires actual EOF and one successful content check per file. Allowing an
    /// explicit skip proves traversal accounting only; the archive remains incomplete.
    /// </summary>
    public void VerifyTraversalCompleted(bool allowSkipped = false) =>
        (_traversal ?? throw new InvalidOperationException("归档遍历尚未开始。")).VerifyCompleted(allowSkipped);

    internal ArchiveIntegrityZipMember? FindZipMember(string key, long size, uint crc, bool encrypted) =>
        _zipIndex.GetValueOrDefault((key, size, crc, encrypted));

    private static void ValidateSevenZip(Stream source, ArchiveVolumePlan plan, CancellationToken token)
    {
        byte[] header = ArchiveIntegrityZip.At(source, 0, 32);
        if (!header.AsSpan(0, 6).SequenceEqual(new byte[] { 0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c }))
            throw new ArchiveVolumeException(ArchiveVolumeStatus.MixedVolumes, "7z 首卷签名不匹配。");
        if (header[6] != 0) throw new ArchiveVolumeException(ArchiveVolumeStatus.UnsupportedLayout, "7z 主版本不受支持。");
        uint startCrc = System.Buffers.Binary.BinaryPrimitives.ReadUInt32LittleEndian(header.AsSpan(8));
        if (ArchiveIntegrity.Crc32(header.AsSpan(12, 20)) != startCrc)
            throw new ArchiveVolumeException(ArchiveVolumeStatus.InvalidMetadata, "7z 起始头 CRC 不匹配。");
        ulong nextOffset = System.Buffers.Binary.BinaryPrimitives.ReadUInt64LittleEndian(header.AsSpan(12));
        ulong nextSize = System.Buffers.Binary.BinaryPrimitives.ReadUInt64LittleEndian(header.AsSpan(20));
        if (nextOffset > long.MaxValue - 32 || nextSize > (ulong)plan.Limits.MaximumMetadataBytes)
            throw new ArchiveVolumeException(ArchiveVolumeStatus.LimitExceeded, "7z 下一头范围超过限额。");
        long start = 32 + (long)nextOffset;
        if (start > source.Length || nextSize > (ulong)(source.Length - start))
            throw new ArchiveVolumeException(ArchiveVolumeStatus.MissingVolume, "7z 下一头缺失，卷组可能不完整。");
        if ((long)nextSize != source.Length - start)
            throw new ArchiveVolumeException(ArchiveVolumeStatus.MixedVolumes, "7z 结束范围与输入卷组不一致。");
        token.ThrowIfCancellationRequested();
        byte[] next = ArchiveIntegrityZip.At(source, start, (int)nextSize);
        uint expected = System.Buffers.Binary.BinaryPrimitives.ReadUInt32LittleEndian(header.AsSpan(28));
        if (ArchiveIntegrity.Crc32(next) != expected)
            throw new ArchiveVolumeException(ArchiveVolumeStatus.InvalidMetadata, "7z 下一头 CRC 不匹配。");
    }

    internal static string VerifyHandle(FileStream file, string expectedPath)
    {
        if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException("卷组文件锁身份校验需要 Windows。");
        StringBuilder buffer = new(32768);
        uint count = GetFinalPathNameByHandle(file.SafeFileHandle, buffer, (uint)buffer.Capacity, 0);
        if (count == 0 || count >= buffer.Capacity || !GetFileInformationByHandle(file.SafeFileHandle, out FileInformation information))
            throw new ArchiveVolumeException(ArchiveVolumeStatus.Unavailable, "无法核验已打开分卷的文件身份。");
        string final = buffer.ToString();
        if (final.StartsWith("\\\\?\\", StringComparison.Ordinal)) final = final[4..];
        if (!string.Equals(final, expectedPath, StringComparison.OrdinalIgnoreCase) ||
            (information.Attributes & (uint)(FileAttributes.Directory | FileAttributes.ReparsePoint)) != 0 ||
            Validation.ContainsReparsePoint(expectedPath))
            throw new ArchiveVolumeException(ArchiveVolumeStatus.Unavailable, "分卷文件身份或路径在打开时发生变化。");
        return $"{information.VolumeSerial:X8}:{information.FileIndexHigh:X8}{information.FileIndexLow:X8}";
    }

    public void Dispose()
    {
        if (_disposed) return; _disposed = true;
        try { Archive.Dispose(); } finally { DisposeOwned(_owned); }
    }
    private static void DisposeOwned(List<(FileStream File, Stream Decorated, Stream Range)> owned)
    {
        foreach (var item in owned.AsEnumerable().Reverse())
        {
            try { if (!ReferenceEquals(item.Range, item.Decorated)) item.Range.Dispose(); }
            finally { try { if (!ReferenceEquals(item.Decorated, item.File)) item.Decorated.Dispose(); } finally { item.File.Dispose(); } }
        }
    }
    [StructLayout(LayoutKind.Sequential)]
    private struct FileInformation
    {
        public uint Attributes;
        public System.Runtime.InteropServices.ComTypes.FILETIME Created, Accessed, Written;
        public uint VolumeSerial, SizeHigh, SizeLow, LinkCount, FileIndexHigh, FileIndexLow;
    }
    [DllImport("kernel32.dll", EntryPoint = "GetFinalPathNameByHandleW", CharSet = CharSet.Unicode, SetLastError = true, ExactSpelling = true)]
    private static extern uint GetFinalPathNameByHandle(SafeFileHandle handle, StringBuilder path, uint length, uint flags);
    [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetFileInformationByHandle(SafeFileHandle handle, out FileInformation information);
}
