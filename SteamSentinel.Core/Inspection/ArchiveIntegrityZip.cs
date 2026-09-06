using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;

namespace SteamSentinel.Core.Inspection;

internal sealed record ArchiveIntegrityZipMember(string Key, long Size, uint Crc, bool Encrypted,
    ushort AesVersion, byte AesStrength, long DataOffset, long PackedSize, bool IsDirectory);

internal static class ArchiveIntegrityZip
{
    internal static IReadOnlyList<ArchiveIntegrityZipMember> Read(ArchiveVolumeJoinedStream source,
        ArchiveVolumePlan plan, string? password, CancellationToken token)
    {
        long length = source.Length;
        if (length < 22)
        {
            if (plan.Layout is ArchiveVolumeLayout.NumericSplit or ArchiveVolumeLayout.ZipSpanned) Missing("ZIP 分卷缺少完整结束目录，可能缺卷或被截断。");
            Fail("ZIP 结束目录缺失。");
        }
        byte[] tail = At(source, Math.Max(0, length - 65557), (int)Math.Min(length, 65557));
        int end = -1;
        for (int i = tail.Length - 22; i >= 0; i--)
            if (U32(tail, i) == 0x06054b50 && i + 22 + U16(tail, i + 20) == tail.Length) { end = i; break; }
        if (end < 0)
        {
            if (plan.Layout is ArchiveVolumeLayout.NumericSplit or ArchiveVolumeLayout.ZipSpanned) Missing("ZIP 分卷缺少完整结束目录，可能缺卷或被截断。");
            Fail("ZIP 缺少完整结束目录或存在范围外尾随数据。");
        }
        long endPosition = length - tail.Length + end;
        long disk = U16(tail, end + 4), centralDisk = U16(tail, end + 6);
        long diskEntries = U16(tail, end + 8), entries = U16(tail, end + 10);
        long centralSize = U32(tail, end + 12), centralOffset = U32(tail, end + 16);
        bool spanned = plan.Layout == ArchiveVolumeLayout.ZipSpanned;
        int disks = spanned ? plan.Members.Count : 1;
        if (disk == ushort.MaxValue || centralDisk == ushort.MaxValue || entries == ushort.MaxValue ||
            diskEntries == ushort.MaxValue || centralSize == uint.MaxValue || centralOffset == uint.MaxValue)
        {
            if (endPosition < 20) Fail("ZIP64 定位记录缺失。");
            byte[] locator = At(source, endPosition - 20, 20);
            if (U32(locator, 0) != 0x07064b50) Fail("ZIP64 定位记录无效。");
            int locatorDisk = CheckedInt(U32(locator, 4));
            if (U32(locator, 16) != disks) Missing("ZIP64 声明卷数与输入卷组不一致。");
            long recordOffset = spanned ? source.DiskOffset(locatorDisk, L64(locator, 8)) : L64(locator, 8);
            byte[] record = At(source, recordOffset, 56);
            if (U32(record, 0) != 0x06064b50 || L64(record, 4) < 44 ||
                L64(record, 4) > plan.Limits.MaximumMetadataBytes || recordOffset + 12 + L64(record, 4) != endPosition - 20)
                Fail("ZIP64 结束记录范围无效。");
            disk = U32(record, 16); centralDisk = U32(record, 20);
            diskEntries = L64(record, 24); entries = L64(record, 32);
            centralSize = L64(record, 40); centralOffset = L64(record, 48);
            endPosition = recordOffset;
        }
        if (disk != disks - 1 || centralDisk < 0 || centralDisk >= disks) Missing("ZIP 结束目录声明的卷号与实际卷组不一致。");
        if (!spanned && (diskEntries != entries || centralDisk != 0)) Missing("ZIP 声明了未提供的分盘结构。");
        if (entries > plan.Limits.MaximumEntries || centralSize > plan.Limits.MaximumMetadataBytes)
            throw new ArchiveVolumeException(ArchiveVolumeStatus.LimitExceeded, "ZIP 中央目录超过元数据限额。");
        long centralStart = spanned ? source.DiskOffset((int)centralDisk, centralOffset) : centralOffset;
        if (centralStart < 0 || centralSize < 0 || centralStart > endPosition || centralSize > endPosition - centralStart)
            Fail("ZIP 中央目录越过归档范围。");
        if (spanned)
        {
            byte[] prefix = At(source, 0, 8);
            if (U32(prefix, 0) != 0x08074b50 || U32(prefix, 4) != 0x04034b50)
                throw new ArchiveVolumeException(ArchiveVolumeStatus.UnsupportedLayout, "ZIP 分盘首卷没有受支持的分盘标记与本地头。");
        }
        List<ArchiveIntegrityZipMember> members = [];
        List<(long Start, long End)> extents = [];
        long position = centralStart;
        long metadata = centralSize;
        for (long index = 0; index < entries; index++)
        {
            token.ThrowIfCancellationRequested();
            if (position > centralStart + centralSize - 46) Fail("ZIP 中央目录条目被截断。");
            byte[] header = At(source, position, 46);
            if (U32(header, 0) != 0x02014b50) Fail("ZIP 中央目录条目签名无效。");
            ushort flags = U16(header, 8), method = U16(header, 10);
            uint crc = U32(header, 16);
            long packed = U32(header, 20), size = U32(header, 24), localOffset = U32(header, 42);
            long localDisk = U16(header, 34);
            int nameLength = U16(header, 28), extraLength = U16(header, 30), commentLength = U16(header, 32);
            int variableLength = nameLength + extraLength + commentLength;
            if (variableLength > centralStart + centralSize - position - 46) Fail("ZIP 中央目录字段越界。");
            byte[] variable = At(source, position + 46, variableLength);
            byte[] rawName = variable.AsSpan(0, nameLength).ToArray();
            ReadOnlySpan<byte> extra = variable.AsSpan(nameLength, extraLength);
            bool needSize = size == uint.MaxValue, needPacked = packed == uint.MaxValue,
                needOffset = localOffset == uint.MaxValue, needDisk = localDisk == ushort.MaxValue;
            ushort aesVersion = 0; byte strength = 0; bool sawZip64 = false, sawAes = false;
            for (int cursor = 0; cursor < extra.Length;)
            {
                if (extra.Length - cursor < 4) Fail("ZIP 扩展字段被截断。");
                ushort id = U16(extra, cursor), bytes = U16(extra, cursor + 2); cursor += 4;
                if (bytes > extra.Length - cursor) Fail("ZIP 扩展字段长度无效。");
                ReadOnlySpan<byte> value = extra.Slice(cursor, bytes); cursor += bytes;
                if (id == 1)
                {
                    if (sawZip64) Fail("ZIP64 扩展字段重复。"); sawZip64 = true;
                    int at = 0;
                    if (needSize) size = Take64(value, ref at);
                    if (needPacked) packed = Take64(value, ref at);
                    if (needOffset) localOffset = Take64(value, ref at);
                    if (needDisk) { if (value.Length - at < 4) Fail("ZIP64 卷号缺失。"); localDisk = U32(value, at); }
                }
                if (id == 0x9901)
                {
                    if (sawAes || bytes != 7 || value[2] != (byte)'A' || value[3] != (byte)'E') Fail("ZIP AES 扩展字段无效。");
                    sawAes = true; aesVersion = U16(value, 0); strength = value[4];
                    if (aesVersion is not (1 or 2) || strength is < 1 or > 3 || method != 99 || (flags & 1) == 0)
                        throw new ArchiveVolumeException(ArchiveVolumeStatus.UnsupportedIntegrity, "ZIP AES 版本或加密参数不受支持。");
                }
            }
            if ((needSize || needPacked || needOffset || needDisk) && !sawZip64) Fail("ZIP64 必需字段缺失。");
            if (method == 99 && !sawAes || (flags & 0x2040) != 0)
                throw new ArchiveVolumeException(ArchiveVolumeStatus.UnsupportedIntegrity, "ZIP 使用未支持的加密完整性方案。");
            if (aesVersion == 2 && crc != 0) Fail("ZIP AES AE-2 的 CRC 字段必须为零。");
            long local = spanned ? source.DiskOffset(CheckedInt(localDisk), localOffset) : localOffset;
            if (!spanned && localDisk != 0) Missing("ZIP 条目引用了未提供的卷。");
            if (local < 0 || local > centralStart - 30) Fail("ZIP 本地头位置越界。");
            byte[] localHeader = At(source, local, 30);
            int localNameLength = U16(localHeader, 26), localExtraLength = U16(localHeader, 28);
            if (U32(localHeader, 0) != 0x04034b50 || U16(localHeader, 6) != flags || U16(localHeader, 8) != method || localNameLength != nameLength)
                Fail("ZIP 本地头与中央目录不一致。");
            metadata = checked(metadata + 30 + localNameLength + localExtraLength);
            if (metadata > plan.Limits.MaximumMetadataBytes)
                throw new ArchiveVolumeException(ArchiveVolumeStatus.LimitExceeded, "ZIP 本地头元数据超过限额。");
            byte[] localVariable = At(source, local + 30, localNameLength + localExtraLength);
            if (!localVariable.AsSpan(0, localNameLength).SequenceEqual(rawName)) Fail("ZIP 条目名称在本地头与中央目录间不一致。");
            if ((flags & 8) == 0 && (U32(localHeader, 14) != crc ||
                U32(localHeader, 18) != uint.MaxValue && U32(localHeader, 18) != packed ||
                U32(localHeader, 22) != uint.MaxValue && U32(localHeader, 22) != size)) Fail("ZIP 条目长度或 CRC 元数据冲突。");
            if (sawAes) ValidateLocalAes(localVariable.AsSpan(localNameLength), extra);
            long data = checked(local + 30 + localNameLength + localExtraLength);
            if (data > centralStart || packed > centralStart - data) Fail("ZIP 压缩数据越过中央目录。");
            extents.Add((local, checked(data + packed)));
            string decodedName = Encoding.UTF8.GetString(rawName);
            string key = decodedName.Replace('\\', '/');
            bool directory = decodedName.EndsWith('/') || packed == 0 && size == 0 && decodedName.EndsWith('\\');
            ArchiveIntegrityZipMember member = new(key, size, crc, (flags & 1) != 0, aesVersion, strength, data, packed, directory);
            if (sawAes && password is not null) Authenticate(source, member, password, token);
            members.Add(member); position += 46 + variableLength;
        }
        if (position != centralStart + centralSize) Fail("ZIP 中央目录大小与条目范围不一致。");
        extents.Sort((a, b) => a.Start.CompareTo(b.Start));
        for (int i = 1; i < extents.Count; i++) if (extents[i].Start < extents[i - 1].End) Fail("ZIP 成员数据范围重叠或重复。");
        return members;
    }

    private static void ValidateLocalAes(ReadOnlySpan<byte> local, ReadOnlySpan<byte> central)
    {
        static byte[] Find(ReadOnlySpan<byte> extra)
        {
            byte[]? found = null;
            for (int i = 0; i < extra.Length;)
            {
                if (extra.Length - i < 4) Fail("ZIP 本地扩展字段截断。");
                ushort id = U16(extra, i), size = U16(extra, i + 2); i += 4;
                if (size > extra.Length - i) Fail("ZIP 本地扩展字段越界。");
                if (id == 0x9901) { if (found is not null) Fail("ZIP AES 字段重复。"); found = extra.Slice(i, size).ToArray(); }
                i += size;
            }
            return found ?? [];
        }
        if (!Find(local).AsSpan().SequenceEqual(Find(central))) Fail("ZIP AES 本地参数与中央目录不一致。");
    }

    private static void Authenticate(Stream source, ArchiveIntegrityZipMember member, string password, CancellationToken token)
    {
        int keyBytes = member.AesStrength switch { 1 => 16, 2 => 24, 3 => 32, _ => throw new InvalidDataException() };
        int saltBytes = keyBytes / 2;
        if (member.PackedSize < saltBytes + 12) Fail("ZIP AES 认证结构被截断。");
        byte[] prefix = At(source, member.DataOffset, saltBytes + 2);
        byte[] passwordBytes = Encoding.UTF8.GetBytes(password);
        byte[] derived = Rfc2898DeriveBytes.Pbkdf2(passwordBytes, prefix.AsSpan(0, saltBytes), 1000, HashAlgorithmName.SHA1, keyBytes * 2 + 2);
        try
        {
            if (!CryptographicOperations.FixedTimeEquals(prefix.AsSpan(saltBytes, 2), derived.AsSpan(keyBytes * 2, 2)))
                throw new CryptographicException("ZIP AES 密码校验失败。");
            using IncrementalHash hmac = IncrementalHash.CreateHMAC(HashAlgorithmName.SHA1, derived.AsSpan(keyBytes, keyBytes));
            long remaining = member.PackedSize - saltBytes - 12;
            source.Position = member.DataOffset + saltBytes + 2;
            byte[] buffer = new byte[128 * 1024];
            while (remaining > 0)
            {
                token.ThrowIfCancellationRequested();
                int count = (int)Math.Min(remaining, buffer.Length); source.ReadExactly(buffer.AsSpan(0, count));
                hmac.AppendData(buffer.AsSpan(0, count)); remaining -= count;
            }
            byte[] stored = new byte[10]; source.ReadExactly(stored);
            if (!CryptographicOperations.FixedTimeEquals(stored, hmac.GetHashAndReset().AsSpan(0, 10)))
                Fail("ZIP AES 认证码不匹配，内容可能损坏或被修改。");
        }
        finally { CryptographicOperations.ZeroMemory(passwordBytes); CryptographicOperations.ZeroMemory(derived); }
    }

    internal static byte[] At(Stream stream, long offset, int count)
    {
        if (offset < 0 || count < 0 || offset > stream.Length || count > stream.Length - offset) Fail("归档元数据读取越界。");
        byte[] result = new byte[count]; stream.Position = offset; stream.ReadExactly(result); return result;
    }
    private static ushort U16(ReadOnlySpan<byte> bytes, int offset) => BinaryPrimitives.ReadUInt16LittleEndian(bytes[offset..]);
    private static uint U32(ReadOnlySpan<byte> bytes, int offset) => BinaryPrimitives.ReadUInt32LittleEndian(bytes[offset..]);
    private static long L64(ReadOnlySpan<byte> bytes, int offset)
    {
        ulong value = BinaryPrimitives.ReadUInt64LittleEndian(bytes[offset..]);
        if (value > long.MaxValue) Fail("归档声明长度超过支持范围。"); return (long)value;
    }
    private static long Take64(ReadOnlySpan<byte> bytes, ref int offset)
    {
        if (bytes.Length - offset < 8) Fail("ZIP64 扩展字段被截断。");
        long value = L64(bytes, offset); offset += 8; return value;
    }
    private static int CheckedInt(long value)
    {
        if (value > int.MaxValue || value < 0) Missing("ZIP 卷号超过输入范围。"); return (int)value;
    }
    private static void Fail(string detail) => throw new ArchiveVolumeException(ArchiveVolumeStatus.InvalidMetadata, detail);
    private static void Missing(string detail) => throw new ArchiveVolumeException(ArchiveVolumeStatus.MissingVolume, detail);
}
