using System.Buffers.Binary;
using System.IO;
using System.IO.Compression;
using System.Text;
using SteamSentinel.Core.Inspection;
using SteamSentinel.Core.Models;

namespace SteamSentinel.SelfTest;

internal static partial class Program
{
    // Entirely inert byte fixtures. No SFX executable is started, no archive member
    // is written to disk, and directives are only strings in checked comments.
    private static void TestV020ContainerRanges()
    {
        byte[] ftyp = V020RangeBox("ftyp", "isom\0\0\0\0isom"u8.ToArray());
        byte[] rar5 = V020RangeRar5();
        byte[] zip = V020RangeZip();
        byte[] mp4 = [.. ftyp, .. V020RangeBox("mdat", "inert media"u8.ToArray())];
        ContainerRangeInspection normal = V020RangeInspect(mp4, ContainerRangeInspector.InspectMp4);
        Check("0.2容器 普通MP4顶层盒覆盖完整流", normal.Status == ContainerRangeStatus.Validated && normal.UnknownRanges.Count == 0 && normal.Ranges.Single().Length == mp4.Length);
        byte[] inside = [.. ftyp, .. V020RangeBox("mdat", rar5)];
        Check("0.2容器 mdat内RAR魔数不产生尾部候选", V020RangeInspect(inside).Ranges.All(x => x.Type == ContainerRangeType.Mp4));
        byte[] zeroMdat = [.. ftyp, 0, 0, 0, 0, (byte)'m', (byte)'d', (byte)'a', (byte)'t', .. rar5];
        ContainerRangeInspection zero = V020RangeInspect(zeroMdat);
        Check("0.2容器 size0媒体盒占有EOF且不剥离内部魔数", zero.UnknownRanges.Count == 0 && zero.Ranges.Count == 1 && zero.Ranges[0].Length == zeroMdat.Length);
        ContainerRangeInspection appended = V020RangeInspect([.. mp4, .. zip]);
        Check("0.2容器 MP4后ZIP仅由本地头中央目录EOCD一致性建立范围", appended.Ranges.Count == 2 && appended.Ranges[1].Type == ContainerRangeType.Zip && appended.Ranges[1].Offset == mp4.Length && appended.Ranges[1].Length == zip.Length && appended.UnknownRanges.Count == 0);
        ContainerRangeInspection trailing = V020RangeInspect([.. mp4, .. rar5, 0xde, 0xad, 0xbe, 0xef]);
        Check("0.2容器 RAR END之外额外尾字节保留未知范围", trailing.Ranges.Any(x => x.Type == ContainerRangeType.Rar5 && x.Length == rar5.Length) && trailing.UnknownRanges.Single().Offset == mp4.Length + rar5.Length && trailing.UnknownRanges[0].Length == 4);
        ContainerRangeInspection unrecognized = V020RangeInspect([.. mp4, 0x50, 0x4b, 0x03, 0x04, .. new byte[40]]);
        Check("0.2容器 单独ZIP魔数不冒充有效压缩包", unrecognized.Ranges.All(x => x.Type != ContainerRangeType.Zip) && unrecognized.UnknownRanges.Single().Length == 44 && unrecognized.Checks.Any(x => x.Status == ContainerRangeStatus.Malformed));
        byte[] oversized = [.. ftyp, 0, 0, 0, 1, (byte)'m', (byte)'d', (byte)'a', (byte)'t', .. Enumerable.Repeat((byte)0xff, 8)];
        Check("0.2容器 MP4无符号64位超界长度仍为未知尾部", V020RangeInspect(oversized).UnknownRanges.Single().Length == 16);
        Check("0.2容器 截断ftyp不建立媒体容器身份", V020RangeInspect([0, 0, 0, 16, (byte)'f', (byte)'t', (byte)'y', (byte)'p']).Status == ContainerRangeStatus.Malformed);
        byte[] largeHeader = new byte[16]; V020RangePut32Be(largeHeader, 0, 1); "mdat"u8.CopyTo(largeHeader.AsSpan(4));
        long largeLength = (long)uint.MaxValue + 4096;
        BinaryPrimitives.WriteUInt64BigEndian(largeHeader.AsSpan(8), (ulong)(largeLength - ftyp.Length));
        using (V020RangeSparseStream sparse = new(largeLength, (0, ftyp), (ftyp.Length, largeHeader)))
        {
            ContainerRangeInspection huge = ContainerRangeInspector.InspectMp4(sparse);
            Check("0.2容器 超4GiB MP4扩展盒使用64位边界且无需读取payload", huge.Ranges.Single().Length == largeLength && huge.BytesRead < 128 && huge.UnknownRanges.Count == 0);
        }

        ContainerRangeInspection directZip = V020RangeInspect(zip);
        Check("0.2容器 普通ZIP范围可验证且不声称成员完整性", directZip.Status == ContainerRangeStatus.Validated && directZip.Ranges.Single().LengthIsExact && directZip.Detail.Contains("成员 CRC"));
        byte[] zipTail = [.. zip, .. "unexplained"u8];
        Check("0.2容器 ZIP EOCD后额外数据被保留", V020RangeInspect(zipTail).UnknownRanges.Single().Length == 11);
        byte[] fakeEocd = [.. zip, 0x50, 0x4b, 0x05, 0x06, .. new byte[18]];
        ContainerRangeInspection fake = V020RangeInspect(fakeEocd);
        Check("0.2容器 尾部伪空EOCD不能吞并前一个ZIP", fake.Ranges.First().Length == zip.Length && fake.Ranges.Count == 2 && fake.Ranges[1].Offset == zip.Length);
        byte[] wrongLocal = zip.ToArray(); wrongLocal[8] ^= 1;
        Check("0.2容器 ZIP本地头和目录方法不一致拒绝范围", V020RangeInspect(wrongLocal).Ranges.Count == 0);
        byte[] missingEnd = zip[..^10];
        Check("0.2容器 ZIP截断EOCD不返回精确范围", V020RangeInspect(missingEnd).Ranges.Count == 0);
        byte[] zip64 = V020RangeZip64();
        Check("0.2容器 ZIP64 locator和64位字段建立精确范围", V020RangeInspect(zip64).Ranges.Single().Length == zip64.Length && V020RangeInspect(zip64).Detail.Contains("ZIP64"));
        byte[] corruptLocator = zip64.ToArray(); corruptLocator[corruptLocator.Length - 42 + 8] = 0xff;
        Check("0.2容器 ZIP64越界locator不截断成32位", V020RangeInspect(corruptLocator).Ranges.Count == 0);
        byte[] descriptor = V020RangeZip(descriptor: true);
        Check("0.2容器 ZIP数据描述符必须匹配CRC和长度", V020RangeInspect(descriptor).Ranges.Count == 1);
        int descriptorAt = V020RangeFind(descriptor, [0x50, 0x4b, 0x07, 0x08]);
        descriptor[descriptorAt + 4] ^= 1;
        Check("0.2容器 ZIP数据描述符CRC冲突拒绝范围", V020RangeInspect(descriptor).Ranges.Count == 0);

        ContainerRangeRarInspection rar = V020RangeRarInspect(rar5);
        Check("0.2容器 RAR5读取主头及END并给出精确尾界", rar.Status == ContainerRangeStatus.Validated && rar.HeaderIntegrityVerified && rar.HasEndMarker && rar.Length == rar5.Length && rar.Version == 5);
        byte[] rar4 = V020RangeRar4();
        ContainerRangeRarInspection old = V020RangeRarInspect(rar4);
        Check("0.2容器 RAR4 CRC及END尾界有效", old.Status == ContainerRangeStatus.Validated && old.Version == 4 && old.Length == rar4.Length);
        byte[] wrongCrc = rar5.ToArray(); wrongCrc[8] ^= 1;
        Check("0.2容器 RAR5坏头CRC不能以魔数通过", V020RangeRarInspect(wrongCrc).Status == ContainerRangeStatus.Malformed && !V020RangeRarInspect(wrongCrc).HeaderIntegrityVerified);
        byte[] wrong4 = rar4.ToArray(); wrong4[7] ^= 1;
        Check("0.2容器 RAR4坏头CRC不能通过", V020RangeRarInspect(wrong4).Status == ContainerRangeStatus.Malformed);
        Check("0.2容器 RAR5缺少END明确截断", V020RangeRarInspect(rar5[..^8]).Status == ContainerRangeStatus.Malformed);
        ContainerRangeRarInspection noEnd4 = V020RangeRarInspect(rar4[..^7]);
        Check("0.2容器 旧RAR缺END保留可读头但未知尾界", noEnd4.Status == ContainerRangeStatus.ValidatedContainerHeader && !noEnd4.Length.HasValue && !noEnd4.HasEndMarker);
        byte[] encrypted5 = V020RangeRar5(encryptedHeader: true);
        ContainerRangeRarInspection encrypted = V020RangeRarInspect(encrypted5);
        Check("0.2容器 加密RAR5允许密码继续且不虚构尾界", encrypted.Status == ContainerRangeStatus.ValidatedContainerHeader && encrypted.NeedsPassword && encrypted.HeaderIntegrityVerified && encrypted.Length is null && encrypted.EndOffset is null);
        ContainerRangeInspection encryptedRange = V020RangeInspect([.. mp4, .. encrypted5]);
        Check("0.2容器 加密RAR候选带硬范围但LengthIsExact为false", encryptedRange.Ranges.Any(x => x.Type == ContainerRangeType.Rar5 && x.NeedsPassword && !x.LengthIsExact && x.Length == encrypted5.Length) && encryptedRange.UnknownRanges.Any(x => x.Offset == mp4.Length));
        ContainerRangeRarInspection encrypted4 = V020RangeRarInspect(V020RangeRar4(encryptedHeader: true));
        Check("0.2容器 加密RAR4主头CRC与未知尾界分离", encrypted4.HeaderEncrypted && encrypted4.Status == ContainerRangeStatus.ValidatedContainerHeader && encrypted4.Length is null);
        ContainerRangeRarInspection volume = V020RangeRarInspect(V020RangeRar5(volume: 2, splitBefore: true, splitAfter: true, nextVolume: true));
        Check("0.2容器 RAR5原生卷号与文件拆分位分别保留", volume.IsMultiVolume && volume.VolumeNumber == 2 && volume.IsFirstVolume == false && volume.FirstFileSplitBefore == true && volume.LastFileSplitAfter == true && volume.ExpectsNextVolume == true);
        ContainerRangeRarInspection volume4 = V020RangeRarInspect(V020RangeRar4(volume: 3));
        Check("0.2容器 RAR4卷号来自END而非文件名猜测", volume4.IsMultiVolume && volume4.VolumeNumber == 3 && volume4.IsFirstVolume == false);
        string directives = "; inert configuration\r\nSetup=never-executed.exe /inert\r\nPath=%TEMP%\\inert\r\nSilent=1\r\nOverwrite=1\r\nTempMode\r\n";
        ContainerRangeRarInspection comment = V020RangeRarInspect(V020RangeRar5(comment: directives));
        Check("0.2容器 SFX配置只取已校验CMT而非任意PE字符串", comment.SfxConfiguration.Count == 5 && comment.SfxConfiguration.Any(x => x.Name == "Setup" && x.Value == "never-executed.exe /inert") && comment.SfxConfiguration.All(x => x.Source.Contains("已校验")));
        byte[] corruptComment = V020RangeRar5(comment: directives);
        int commentAt = V020RangeFind(corruptComment, "never-executed"u8.ToArray()); corruptComment[commentAt] ^= 1;
        Check("0.2容器 CMT数据CRC冲突不显示可信配置", V020RangeRarInspect(corruptComment).Status == ContainerRangeStatus.Malformed && V020RangeRarInspect(corruptComment).SfxConfiguration.Count == 0);
        ContainerRangeRarInspection hashMac = V020RangeRarInspect(V020RangeRar5(hashMac: true));
        Check("0.2容器 可读RAR5文件头保留HashMAC标志", hashMac.HasEncryptedFileHeaders && hashMac.HasHashMacFileHeaders && hashMac.HeaderIntegrityVerified);

        byte[] pe = V020RangePe(rar5, certificateAfterOverlay: true);
        ContainerRangeInspection sfx = V020RangeInspect(pe);
        Check("0.2容器 PE节边界后且证书表之前RAR仍被找到", sfx.Status == ContainerRangeStatus.Validated && sfx.Ranges.Any(x => x.Type == ContainerRangeType.Rar5 && x.Offset == 0x400 && x.Length == rar5.Length) && sfx.Ranges.Any(x => x.Type == ContainerRangeType.PeCertificateTable));
        byte[] afterCertificate = V020RangePe(rar5, certificateAfterOverlay: false);
        ContainerRangeInspection after = V020RangeInspect(afterCertificate);
        Check("0.2容器 PE证书表之后overlay继续独立检测", after.Ranges.Any(x => x.Type == ContainerRangeType.Rar5 && x.Offset == 0x408));
        byte[] peJunk = V020RangePe([.. "SFX Setup=never-run.exe\0"u8, .. rar5], certificateAfterOverlay: true);
        ContainerRangeInspection junk = V020RangeInspect(peJunk);
        Check("0.2容器 PE前导overlay未知字节保留且不当作SFX配置", junk.Ranges.Any(x => x.Type == ContainerRangeType.Rar5) && junk.UnknownRanges.Any(x => x.Offset == 0x400) && junk.SfxConfiguration.Count == 0);
        byte[] invalidPe = pe.ToArray(); V020RangePut32(invalidPe, 0x98 + 96 + 32, 0x200);
        Check("0.2容器 PE证书表与映像重叠拒绝", V020RangeInspect(invalidPe).Status == ContainerRangeStatus.Malformed);
        byte[] sectionOverflow = pe.ToArray(); V020RangePut32(sectionOverflow, 0x178 + 16, uint.MaxValue);
        Check("0.2容器 PE节大小溢出不产生overlay", V020RangeInspect(sectionOverflow).Ranges.Count == 0);
        byte[] badCertificate = pe.ToArray(); int certStart = (int)BinaryPrimitives.ReadUInt32LittleEndian(pe.AsSpan(0x98 + 96 + 32)); V020RangePut32(badCertificate, certStart, 7);
        Check("0.2容器 WIN_CERTIFICATE长度小于8拒绝", V020RangeInspect(badCertificate).Status == ContainerRangeStatus.Malformed);

        using (MemoryStream positioned = new(rar5))
        {
            positioned.Position = 3;
            _ = ContainerRangeInspector.Inspect(positioned);
            Check("0.2容器 检查后恢复调用方流位置", positioned.Position == 3);
            _ = ContainerRangeInspector.InspectRar(positioned, long.MaxValue, 8);
            Check("0.2容器 越界偏移返回状态且恢复流位置", positioned.Position == 3);
        }
        using (MemoryStream limited = new(rar5))
        {
            ContainerRangeInspection budget = ContainerRangeInspector.Inspect(limited, limits: new() { MaximumReadBytes = 8 });
            Check("0.2容器 全局读预算精确限制且未覆盖部分未知", budget.Status == ContainerRangeStatus.LimitReached && budget.BytesRead <= 8 && budget.UnknownRanges.Count == 1);
        }
        using (MemoryStream limited = new(rar5)) Check("0.2容器 头记录上限产生LimitReached", ContainerRangeInspector.InspectRar(limited, limits: new() { MaximumRecords = 1 }).Status == ContainerRangeStatus.LimitReached);
        using (MemoryStream limited = new(zip)) Check("0.2容器 ZIP条目上限独立生效", ContainerRangeInspector.Inspect(limited, limits: new() { MaximumZipEntries = 0 }).Status == ContainerRangeStatus.LimitReached);
        using (MemoryStream limited = new(rar5)) Check("0.2容器 零时间预算立即停止", ContainerRangeInspector.InspectRar(limited, limits: new() { MaximumDuration = TimeSpan.Zero }).Status == ContainerRangeStatus.LimitReached);
        using (MemoryStream cancelled = new(rar5)) Check("0.2容器 已取消token保留取消状态", ContainerRangeInspector.Inspect(cancelled, new CancellationToken(true)).Status == ContainerRangeStatus.Cancelled);
        using (V020RangeSparseStream shortRead = new(rar5.Length, (0, rar5)) { MaximumReadSize = 1 })
            Check("0.2容器 短读流循环精确读取完整头", ContainerRangeInspector.InspectRar(shortRead).Status == ContainerRangeStatus.Validated);
    }

    private static ContainerRangeInspection V020RangeInspect(byte[] bytes, Func<Stream, CancellationToken, ContainerRangeLimits?, ContainerRangeInspection>? inspect = null)
    { using MemoryStream stream = new(bytes); return (inspect ?? ContainerRangeInspector.Inspect)(stream, default, null); }
    private static ContainerRangeRarInspection V020RangeRarInspect(byte[] bytes)
    { using MemoryStream stream = new(bytes); return ContainerRangeInspector.InspectRar(stream); }

    private static byte[] V020RangeBox(string type, byte[] data)
    {
        byte[] result = new byte[data.Length + 8]; V020RangePut32Be(result, 0, (uint)result.Length);
        Encoding.ASCII.GetBytes(type).CopyTo(result, 4); data.CopyTo(result, 8); return result;
    }

    private static byte[] V020RangeZip(bool descriptor = false)
    {
        // A non-seekable writer forces the standard data-descriptor variant.
        using MemoryStream output = new();
        Stream target = descriptor ? new V020RangeNonSeekWriteStream(output) : output;
        using (ZipArchive archive = new(target, ZipArchiveMode.Create, leaveOpen: true))
        {
            ZipArchiveEntry entry = archive.CreateEntry("inert.txt", CompressionLevel.NoCompression);
            using Stream content = entry.Open(); content.Write("inert fixture bytes"u8);
        }
        return output.ToArray();
    }

    private static byte[] V020RangeZip64()
    {
        using MemoryStream output = new(); using BinaryWriter writer = new(output, Encoding.UTF8, leaveOpen: true);
        byte[] name = "empty.txt"u8.ToArray();
        writer.Write(0x04034b50u); writer.Write((ushort)45); writer.Write((ushort)0); writer.Write((ushort)0); writer.Write(0u); writer.Write(0u);
        writer.Write(uint.MaxValue); writer.Write(uint.MaxValue); writer.Write((ushort)name.Length); writer.Write((ushort)20); writer.Write(name);
        writer.Write((ushort)1); writer.Write((ushort)16); writer.Write(0UL); writer.Write(0UL);
        long central = output.Position;
        writer.Write(0x02014b50u); writer.Write((ushort)45); writer.Write((ushort)45); writer.Write((ushort)0); writer.Write((ushort)0); writer.Write(0u); writer.Write(0u);
        writer.Write(uint.MaxValue); writer.Write(uint.MaxValue); writer.Write((ushort)name.Length); writer.Write((ushort)28); writer.Write((ushort)0); writer.Write((ushort)0); writer.Write((ushort)0); writer.Write(0u); writer.Write(uint.MaxValue); writer.Write(name);
        writer.Write((ushort)1); writer.Write((ushort)24); writer.Write(0UL); writer.Write(0UL); writer.Write(0UL);
        long centralSize = output.Position - central, zip64 = output.Position;
        writer.Write(0x06064b50u); writer.Write(44UL); writer.Write((ushort)45); writer.Write((ushort)45); writer.Write(0u); writer.Write(0u); writer.Write(1UL); writer.Write(1UL); writer.Write((ulong)centralSize); writer.Write((ulong)central);
        writer.Write(0x07064b50u); writer.Write(0u); writer.Write((ulong)zip64); writer.Write(1u);
        writer.Write(0x06054b50u); writer.Write((ushort)0); writer.Write((ushort)0); writer.Write(ushort.MaxValue); writer.Write(ushort.MaxValue); writer.Write(uint.MaxValue); writer.Write(uint.MaxValue); writer.Write((ushort)0);
        return output.ToArray();
    }

    private static byte[] V020RangeRar4(bool encryptedHeader = false, int? volume = null)
    {
        List<byte> result = [0x52, 0x61, 0x72, 0x21, 0x1a, 7, 0];
        result.AddRange(V020RangeRar4Block(0x73, (ushort)((encryptedHeader ? 0x80 : 0) | (volume.HasValue ? 1 : 0)), new byte[6]));
        if (encryptedHeader) result.AddRange(new byte[48]);
        else result.AddRange(V020RangeRar4Block(0x7b, (ushort)(volume.HasValue ? 8 : 0), volume.HasValue ? BitConverter.GetBytes((ushort)volume.Value) : []));
        return result.ToArray();
    }
    private static byte[] V020RangeRar4Block(byte type, ushort flags, byte[] body)
    {
        byte[] header = new byte[7 + body.Length]; header[2] = type; BinaryPrimitives.WriteUInt16LittleEndian(header.AsSpan(3), flags);
        BinaryPrimitives.WriteUInt16LittleEndian(header.AsSpan(5), (ushort)header.Length); body.CopyTo(header, 7);
        BinaryPrimitives.WriteUInt16LittleEndian(header, (ushort)V020RangeCrc(header.AsSpan(2))); return header;
    }
    private static byte[] V020RangeRar5(bool encryptedHeader = false, int? volume = null, bool splitBefore = false, bool splitAfter = false, bool nextVolume = false, string? comment = null, bool hashMac = false)
    {
        List<byte> output = [0x52, 0x61, 0x72, 0x21, 0x1a, 7, 1, 0];
        if (encryptedHeader)
        {
            output.AddRange(V020RangeRar5Block(4, 0, [0, 0, 10, .. new byte[16]])); output.AddRange(new byte[48]); return output.ToArray();
        }
        output.AddRange(V020RangeRar5Block(1, 0, volume.HasValue ? [3, .. V020RangeVint((ulong)volume.Value)] : [0]));
        if (comment is not null)
        {
            byte[] text = Encoding.UTF8.GetBytes(comment);
            byte[] fields = [4, .. V020RangeVint((ulong)text.Length), 0, .. BitConverter.GetBytes(V020RangeCrc(text)), 0, 0, 3, .. "CMT"u8];
            output.AddRange(V020RangeRar5Block(3, 2, fields, text));
        }
        if (splitBefore || splitAfter || hashMac)
        {
            byte[] fields = [4, 0, 0, 0, 0, 0, 0, 0, 0, 9, .. "inert.txt"u8];
            byte[] extra = hashMac ? [36, 1, 0, 2, 10, .. new byte[32]] : [];
            output.AddRange(V020RangeRar5Block(2, (ulong)((splitBefore ? 8 : 0) | (splitAfter ? 16 : 0)), fields, extra: extra));
        }
        output.AddRange(V020RangeRar5Block(5, 0, [nextVolume ? (byte)1 : (byte)0]));
        return output.ToArray();
    }
    private static byte[] V020RangeRar5Block(ulong type, ulong flags, byte[] fields, byte[]? data = null, byte[]? extra = null)
    {
        extra ??= []; data ??= [];
        if (extra.Length > 0) flags |= 1;
        if (data.Length > 0) flags |= 2;
        List<byte> body = [.. V020RangeVint(type), .. V020RangeVint(flags)];
        if ((flags & 1) != 0) body.AddRange(V020RangeVint((ulong)extra.Length));
        if ((flags & 2) != 0) body.AddRange(V020RangeVint((ulong)data.Length));
        body.AddRange(fields); body.AddRange(extra);
        byte[] sizeAndBody = [.. V020RangeVint((ulong)body.Count), .. body];
        return [.. BitConverter.GetBytes(V020RangeCrc(sizeAndBody)), .. sizeAndBody, .. data];
    }
    private static byte[] V020RangeVint(ulong value)
    {
        List<byte> result = [];
        do { byte b = (byte)(value & 127); value >>= 7; result.Add(value == 0 ? b : (byte)(b | 128)); } while (value != 0);
        return result.ToArray();
    }

    private static byte[] V020RangePe(byte[] overlay, bool certificateAfterOverlay)
    {
        int cert = certificateAfterOverlay ? (0x400 + overlay.Length + 7) & ~7 : 0x400;
        int overlayStart = certificateAfterOverlay ? 0x400 : 0x408;
        byte[] image = new byte[Math.Max(cert + 8, overlayStart + overlay.Length)];
        image[0] = (byte)'M'; image[1] = (byte)'Z'; V020RangePut32(image, 60, 0x80);
        V020RangePut32(image, 0x80, 0x4550); BinaryPrimitives.WriteUInt16LittleEndian(image.AsSpan(0x84), 0x14c);
        BinaryPrimitives.WriteUInt16LittleEndian(image.AsSpan(0x86), 1); BinaryPrimitives.WriteUInt16LittleEndian(image.AsSpan(0x94), 224);
        BinaryPrimitives.WriteUInt16LittleEndian(image.AsSpan(0x98), 0x10b); V020RangePut32(image, 0x98 + 60, 0x200); V020RangePut32(image, 0x98 + 92, 16);
        V020RangePut32(image, 0x98 + 96 + 32, (uint)cert); V020RangePut32(image, 0x98 + 96 + 36, 8);
        ".inert"u8.CopyTo(image.AsSpan(0x178)); V020RangePut32(image, 0x178 + 16, 0x200); V020RangePut32(image, 0x178 + 20, 0x200);
        overlay.CopyTo(image, overlayStart); V020RangePut32(image, cert, 8); BinaryPrimitives.WriteUInt16LittleEndian(image.AsSpan(cert + 4), 0x200); BinaryPrimitives.WriteUInt16LittleEndian(image.AsSpan(cert + 6), 2);
        return image;
    }
    private static uint V020RangeCrc(ReadOnlySpan<byte> bytes)
    {
        uint crc = 0xffffffff;
        foreach (byte b in bytes) { crc ^= b; for (int i = 0; i < 8; i++) crc = (crc & 1) != 0 ? (crc >> 1) ^ 0xedb88320u : crc >> 1; }
        return crc ^ 0xffffffff;
    }
    private static void V020RangePut32(byte[] data, int offset, uint value) => BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(offset), value);
    private static void V020RangePut32Be(byte[] data, int offset, uint value) => BinaryPrimitives.WriteUInt32BigEndian(data.AsSpan(offset), value);
    private static int V020RangeFind(byte[] data, byte[] wanted)
    { for (int i = 0; i <= data.Length - wanted.Length; i++) if (data.AsSpan(i, wanted.Length).SequenceEqual(wanted)) return i; return -1; }

    private sealed class V020RangeSparseStream(long length, params (long Offset, byte[] Bytes)[] segments) : Stream
    {
        public int MaximumReadSize { get; init; } = int.MaxValue;
        public override bool CanRead => true; public override bool CanSeek => true; public override bool CanWrite => false;
        public override long Length => length; public override long Position { get; set; }
        public override int Read(byte[] buffer, int offset, int count)
        {
            int read = (int)Math.Min(Math.Min(count, MaximumReadSize), Math.Max(0, length - Position));
            Array.Clear(buffer, offset, read);
            foreach ((long start, byte[] bytes) in segments)
            {
                long from = Math.Max(start, Position), until = Math.Min(start + bytes.Length, Position + read);
                if (until > from) bytes.AsSpan((int)(from - start), (int)(until - from)).CopyTo(buffer.AsSpan(offset + (int)(from - Position)));
            }
            Position += read; return read;
        }
        public override long Seek(long offset, SeekOrigin origin) => Position = origin switch { SeekOrigin.Begin => offset, SeekOrigin.Current => Position + offset, _ => length + offset };
        public override void Flush() { }
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }
    private sealed class V020RangeNonSeekWriteStream(Stream target) : Stream
    {
        public override bool CanRead => false; public override bool CanSeek => false; public override bool CanWrite => true;
        public override long Length => throw new NotSupportedException(); public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
        public override void Flush() => target.Flush(); public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException(); public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => target.Write(buffer, offset, count);
    }
}
