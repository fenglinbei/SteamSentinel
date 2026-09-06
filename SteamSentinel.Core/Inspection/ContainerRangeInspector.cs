using System.Buffers.Binary;
using System.Diagnostics;
using System.Text;
using SteamSentinel.Core.Models;

namespace SteamSentinel.Core.Inspection;

/// <summary>
/// Bounded, read-only structural inspection. A validated range is an extent established by
/// container headers, not a verdict about decoded media, archive members, signatures or safety.
/// Does not extract files, decrypt headers, start an SFX, or follow configuration directives.
/// </summary>
public static class ContainerRangeInspector
{
    private static ReadOnlySpan<byte> Rar4Magic => [0x52, 0x61, 0x72, 0x21, 0x1a, 0x07, 0x00];
    private static ReadOnlySpan<byte> Rar5Magic => [0x52, 0x61, 0x72, 0x21, 0x1a, 0x07, 0x01, 0x00];

    public static ContainerRangeInspection Inspect(Stream stream, CancellationToken token = default, ContainerRangeLimits? limits = null)
        => InspectWith(stream, token, limits, (reader, result) =>
        {
            byte[] prefix = reader.Read(0, (int)Math.Min(16, reader.Length));
            if (prefix.Length >= 2 && prefix[0] == 'M' && prefix[1] == 'Z') InspectPe(reader, result);
            else if (prefix.Length >= 8 && FourCc(prefix.AsSpan(4, 4)) == "ftyp") InspectMp4Core(reader, result);
            else InspectArchiveCore(reader, result, 0, reader.Length, search: false);
        });

    public static ContainerRangeInspection InspectMp4(Stream stream, CancellationToken token = default, ContainerRangeLimits? limits = null)
        => InspectWith(stream, token, limits, InspectMp4Core);

    public static ContainerRangeInspection InspectPeSfx(Stream stream, CancellationToken token = default, ContainerRangeLimits? limits = null)
        => InspectWith(stream, token, limits, InspectPe);

    public static ContainerRangeInspection InspectArchiveAt(Stream stream, long offset, long length,
        CancellationToken token = default, ContainerRangeLimits? limits = null)
        => InspectWith(stream, token, limits, (reader, result) =>
        {
            RequireRange(offset, length, reader.Length);
            InspectArchiveCore(reader, result, offset, length, search: false);
        });

    public static ContainerRangeRarInspection InspectRar(Stream stream, long offset = 0, long? length = null,
        CancellationToken token = default, ContainerRangeLimits? limits = null)
    {
        ArgumentNullException.ThrowIfNull(stream);
        if (!stream.CanRead || !stream.CanSeek) return new() { Offset = offset, Status = ContainerRangeStatus.Unsupported, Detail = "RAR 结构检查需要可读且可定位的流。" };
        long saved = stream.Position;
        Reader? reader = null;
        ContainerRangeRarInspection result = new() { Offset = offset, AvailableLength = length ?? Math.Max(0, stream.Length - Math.Max(0, offset)) };
        try
        {
            reader = new(stream, token, limits ?? new());
            RequireRange(offset, result.AvailableLength, reader.Length);
            ParseRar(reader, result);
        }
        catch (RangeInspectionException ex) { result.Status = ex.Status; result.Detail = ex.Message; result.HeaderIntegrityVerified = false; }
        catch (OperationCanceledException) { result.Status = ContainerRangeStatus.Cancelled; result.Detail = "RAR 头结构检查已取消；成员与尾界未完成验证。"; result.HeaderIntegrityVerified = false; }
        catch (Exception ex) when (ex is IOException or NotSupportedException or ArgumentException or OverflowException)
        { result.Status = ContainerRangeStatus.Malformed; result.Detail = $"RAR 范围不可验证：{ex.GetType().Name}。"; result.HeaderIntegrityVerified = false; }
        finally { if (reader is not null) result.BytesRead = reader.BytesRead; stream.Position = saved; }
        return result;
    }

    private static ContainerRangeInspection InspectWith(Stream stream, CancellationToken token, ContainerRangeLimits? limits,
        Action<Reader, ContainerRangeInspection> inspect)
    {
        ArgumentNullException.ThrowIfNull(stream);
        if (!stream.CanRead || !stream.CanSeek) return new() { Status = ContainerRangeStatus.Unsupported, Detail = "容器范围检查需要可读且可定位的流。" };
        long saved = stream.Position;
        Reader? reader = null;
        ContainerRangeInspection result = new() { FileLength = stream.Length };
        try { reader = new(stream, token, limits ?? new()); inspect(reader, result); reader.Check(); }
        catch (RangeInspectionException ex) { result.Status = ex.Status; result.Detail = ex.Message; result.Checks.Add(new() { Offset = Math.Min(result.FileLength, Math.Max(0, result.LastContainerBoundary)), Status = ex.Status, Detail = ex.Message }); }
        catch (OperationCanceledException) { result.Status = ContainerRangeStatus.Cancelled; result.Detail = "容器范围检查已取消；未检查部分仍未知。"; }
        catch (Exception ex) when (ex is IOException or NotSupportedException or ArgumentException or OverflowException)
        { result.Status = ContainerRangeStatus.Malformed; result.Detail = $"容器范围不可验证：{ex.GetType().Name}。"; }
        finally
        {
            if (reader is not null) result.BytesRead = reader.BytesRead;
            stream.Position = saved;
        }
        // Do not silently omit bytes after an interrupted/failed parser. Existing precise
        // ranges remain useful, but unverified portions are explicitly represented.
        CompleteUnknownRanges(result);
        return result;
    }

    private static void InspectMp4Core(Reader reader, ContainerRangeInspection result)
    {
        result.ContainerType = ContainerRangeType.Mp4;
        long cursor = 0;
        bool ftyp = false;
        int boxes = 0;
        while (cursor < reader.Length)
        {
            reader.Record(ref boxes);
            if (reader.Length - cursor < 8) break;
            byte[] header = reader.Read(cursor, 8);
            string type = FourCc(header.AsSpan(4));
            if (!PlausibleFourCc(header.AsSpan(4))) break;
            uint size32 = U32Be(header, 0);
            long headerLength = 8;
            ulong size = size32;
            if (size32 == 1)
            {
                if (reader.Length - cursor < 16) break;
                size = BinaryPrimitives.ReadUInt64BigEndian(reader.Read(cursor + 8, 8));
                headerLength = 16;
            }
            else if (size32 == 0) size = (ulong)(reader.Length - cursor);
            if (type == "uuid") headerLength += 16;
            if (size > long.MaxValue || size < (ulong)headerLength || size > (ulong)(reader.Length - cursor)) break;
            if (type == "ftyp")
            {
                if (ftyp || size < (ulong)(headerLength + 8) || ((long)size - headerLength - 8) % 4 != 0)
                    throw Bad("MP4 ftyp 头长度或重复出现不符合所支持的顶层结构。");
                ftyp = true;
            }
            else if (!ftyp && type is not ("free" or "skip" or "wide"))
                throw Bad("MP4 未在媒体盒前建立 ftyp 容器身份。");
            cursor += (long)size;
            result.LastContainerBoundary = cursor;
            if (size32 == 0) break; // A size-zero box owns the complete remaining stream.
        }
        if (!ftyp) throw Bad("未验证 MP4 ftyp 与顶层盒范围。");
        result.Ranges.Add(Range(0, cursor, ContainerRangeType.Mp4, "已验证 MP4 顶层盒长度和范围；未解码媒体内容。"));
        result.Status = ContainerRangeStatus.Validated;
        result.Detail = cursor == reader.Length ? "MP4 顶层结构覆盖完整流。" : "MP4 顶层结构后存在额外字节，分别验证其容器结构。";
        if (cursor < reader.Length) InspectArchiveCore(reader, result, cursor, reader.Length - cursor, search: false, preserveType: true);
    }

    private static void InspectPe(Reader reader, ContainerRangeInspection result)
    {
        result.ContainerType = ContainerRangeType.PeImage;
        byte[] dos = reader.Read(0, 64);
        if (dos[0] != 'M' || dos[1] != 'Z') throw Bad("缺少有效 DOS MZ 头。");
        long pe = U32(dos, 60);
        if (pe < 64 || pe > reader.Length - 24) throw Bad("PE e_lfanew 超出流或重叠 DOS 头。");
        byte[] coff = reader.Read(pe, 24);
        if (U32(coff, 0) != 0x00004550) throw Bad("PE 签名无效。");
        int sections = U16(coff, 6), optionalSize = U16(coff, 20);
        if (sections is < 1 or > 96 || optionalSize < 96) throw Bad("PE 节数或可选头长度不在支持范围。");
        long optionalStart = pe + 24, table = optionalStart + optionalSize;
        RequireRange(table, sections * 40L, reader.Length);
        byte[] optional = reader.Read(optionalStart, optionalSize);
        int magic = U16(optional, 0), directoriesStart, directoryCountOffset;
        if (magic == 0x10b) { directoriesStart = 96; directoryCountOffset = 92; }
        else if (magic == 0x20b) { directoriesStart = 112; directoryCountOffset = 108; }
        else throw Unsupported("PE 可选头 magic 不属于 PE32/PE32+。");
        if (optional.Length < directoriesStart) throw Bad("PE 可选头被截断。");
        long imageEnd = U32(optional, 60);
        if (imageEnd < table + sections * 40L || imageEnd > reader.Length) throw Bad("PE SizeOfHeaders 没有覆盖节表或超出流。");
        List<(long Start, long End)> occupied = [(0, imageEnd)];
        for (int i = 0; i < sections; i++)
        {
            byte[] section = reader.Read(table + i * 40L, 40);
            long size = U32(section, 16), start = U32(section, 20);
            if (size == 0) continue;
            RequireRange(start, size, reader.Length);
            long end = start + size;
            if (occupied.Any(x => start < x.End && end > x.Start)) throw Bad("PE 节的原始数据与头或另一节重叠。");
            occupied.Add((start, end));
            imageEnd = Math.Max(imageEnd, end);
        }
        long certificateStart = 0, certificateLength = 0;
        uint directoryCount = U32(optional, directoryCountOffset);
        if (directoryCount > (optional.Length - directoriesStart) / 8) throw Bad("PE NumberOfRvaAndSizes 超出可选头。");
        if (directoryCount > 4)
        {
            certificateStart = U32(optional, directoriesStart + 32);
            certificateLength = U32(optional, directoriesStart + 36);
            if ((certificateStart == 0) != (certificateLength == 0)) throw Bad("PE 证书表地址与大小必须同时为零或同时存在。");
        }
        if (certificateLength != 0)
        {
            RequireRange(certificateStart, certificateLength, reader.Length);
            if ((certificateStart & 7) != 0 || certificateStart < imageEnd) throw Bad("PE 证书表未按 8 字节对齐或落在映像范围内。");
            long current = certificateStart, end = certificateStart + certificateLength;
            int certificates = 0;
            while (current < end)
            {
                reader.Record(ref certificates);
                if (end - current < 8) throw Bad("PE WIN_CERTIFICATE 头被截断。");
                byte[] certificate = reader.Read(current, 8);
                long length = U32(certificate, 0);
                if (length < 8 || length > end - current) throw Bad("PE WIN_CERTIFICATE 长度越界。");
                long padded = checked((length + 7) & ~7L);
                if (padded > end - current) throw Bad("PE WIN_CERTIFICATE 对齐填充越界。");
                current += padded;
            }
        }
        result.Ranges.Add(Range(0, imageEnd, ContainerRangeType.PeImage, "已验证 DOS/PE 头、节表和原始节范围；未启动映像。"));
        result.LastContainerBoundary = imageEnd;
        result.Status = ContainerRangeStatus.Validated;
        result.Detail = "已建立 PE 映像范围；证书表使用文件偏移并独立于 overlay 检查。";
        if (certificateLength > 0)
        {
            result.Ranges.Add(Range(certificateStart, certificateLength, ContainerRangeType.PeCertificateTable, "已验证 WIN_CERTIFICATE 表长度和对齐；未验证 Authenticode 信任。"));
            if (certificateStart > imageEnd) InspectArchiveCore(reader, result, imageEnd, certificateStart - imageEnd, search: true, preserveType: true);
            long afterCertificate = certificateStart + certificateLength;
            if (afterCertificate < reader.Length) InspectArchiveCore(reader, result, afterCertificate, reader.Length - afterCertificate, search: true, preserveType: true);
        }
        else if (imageEnd < reader.Length) InspectArchiveCore(reader, result, imageEnd, reader.Length - imageEnd, search: true, preserveType: true);
    }

    private static void InspectArchiveCore(Reader reader, ContainerRangeInspection result, long offset, long length, bool search, bool preserveType = false)
    {
        long end = checked(offset + length), cursor = offset;
        int candidates = 0;
        while (cursor < end)
        {
            reader.Check();
            long candidate = search ? FindSignature(reader, cursor, end) : cursor;
            if (candidate < 0) break;
            if (++candidates > reader.Limits.MaximumCandidates) throw Limited("容器候选数量达到限制。");
            byte[] signature = reader.Read(candidate, (int)Math.Min(8, end - candidate));
            bool rar4 = signature.AsSpan().StartsWith(Rar4Magic), rar5 = signature.AsSpan().StartsWith(Rar5Magic);
            bool zip = signature.Length >= 4 && U32(signature, 0) is 0x04034b50 or 0x06054b50;
            if (!rar4 && !rar5 && !zip) break;
            ContainerRange? range = null;
            try
            {
                if (rar4 || rar5)
                {
                    ContainerRangeRarInspection rar = new() { Offset = candidate, AvailableLength = end - candidate };
                    ParseRar(reader, rar);
                    range = new()
                    {
                        Offset = candidate,
                        Length = rar.Length ?? end - candidate,
                        LengthIsExact = rar.Length.HasValue,
                        Type = rar5 ? ContainerRangeType.Rar5 : ContainerRangeType.Rar4,
                        Status = rar.Status,
                        NeedsPassword = rar.NeedsPassword,
                        Detail = rar.Detail
                    };
                    result.SfxConfiguration.AddRange(rar.SfxConfiguration);
                }
                else range = ParseZip(reader, candidate, end - candidate);
            }
            catch (RangeInspectionException ex) when (ex.Status is ContainerRangeStatus.Malformed or ContainerRangeStatus.Unsupported)
            {
                result.Checks.Add(new() { Offset = candidate, Status = ex.Status, Detail = ex.Message });
                if (!search) { if (!preserveType) result.Status = ex.Status; result.Detail = ex.Message; break; }
                cursor = candidate + 1;
                continue;
            }
            if (range is not null)
            {
                result.Ranges.Add(range);
                if (!preserveType) { result.ContainerType = range.Type; result.Status = range.Status; result.Detail = range.Detail; }
                result.LastContainerBoundary = Math.Max(result.LastContainerBoundary, range.Offset + (range.LengthIsExact ? range.Length : 0));
                if (!range.LengthIsExact) break;
                cursor = range.Offset + range.Length;
                // Contiguous following containers can be established without searching
                // inside bytes already owned by a validated archive.
                if (!search && cursor < end) continue;
            }
            else break;
        }
    }

    private static long FindSignature(Reader reader, long start, long end)
    {
        int count = (int)Math.Min(end - start, reader.Limits.MaximumSignatureSearchBytes);
        if (count <= 0) throw Limited("SFX 签名搜索预算为零。");
        byte[] data = reader.Read(start, count);
        for (int i = 0; i <= data.Length - 4; i++)
        {
            if ((i & 4095) == 0) reader.Check();
            ReadOnlySpan<byte> current = data.AsSpan(i);
            if (current.StartsWith(Rar4Magic) || current.StartsWith(Rar5Magic) || U32(current, 0) is 0x04034b50 or 0x06054b50) return start + i;
        }
        if (end - start > count) throw Limited("SFX overlay 的签名搜索达到字节限制；后部仍未知。");
        return -1;
    }

    private static void ParseRar(Reader reader, ContainerRangeRarInspection result)
    {
        long end = checked(result.Offset + result.AvailableLength);
        byte[] signature = reader.Read(result.Offset, (int)Math.Min(8, result.AvailableLength));
        if (signature.AsSpan().StartsWith(Rar5Magic)) { result.Version = 5; ParseRar5(reader, result, result.Offset + 8, end); }
        else if (signature.AsSpan().StartsWith(Rar4Magic)) { result.Version = 4; ParseRar4(reader, result, result.Offset + 7, end); }
        else throw Bad("指定范围开头不是 RAR4/RAR5 标记。");
    }

    private static void ParseRar4(Reader reader, ContainerRangeRarInspection result, long cursor, long end)
    {
        bool main = false;
        int records = 0;
        while (cursor < end)
        {
            reader.Record(ref records);
            if (end - cursor < 7) throw Bad("RAR4 尾部头被截断。");
            byte[] prefix = reader.Read(cursor, 7);
            int type = prefix[2], flags = U16(prefix, 3), headerSize = U16(prefix, 5);
            if (headerSize < 7 || headerSize > end - cursor) throw Bad("RAR4 头长度越界。");
            if (headerSize > reader.Limits.MaximumHeaderBytes) throw Limited("RAR4 头长度达到限制。");
            byte[] header = reader.Read(cursor, headerSize);
            // Old nested comments have a separately checked payload. Their parent CRC
            // excludes that comment; classify this legacy shape as unsupported instead
            // of claiming CRC failure from the generic modern-header calculation.
            if ((type == 0x73 && (flags & 2) != 0) || (type == 0x74 && (flags & 8) != 0) || type is 0x75 or 0x76 or 0x79)
                throw Unsupported("RAR4 旧式嵌套注释/签名头需要专用解码；当前不能建立精确尾界。");
            if ((Crc32(header.AsSpan(2)) & 0xffff) != U16(header, 0)) throw Bad("RAR4 头 CRC16 校验不一致。");
            long dataLength = 0;
            if ((flags & 0x8000) != 0)
            {
                if (headerSize < 11) throw Bad("RAR4 LONG_BLOCK 缺少数据长度。");
                dataLength = U32(header, 7);
            }
            if (type == 0x73)
            {
                if (main || records != 1 || headerSize < 13) throw Bad("RAR4 主头顺序或长度无效。");
                main = true;
                result.IsMultiVolume = (flags & 1) != 0;
                result.IsFirstVolume = !result.IsMultiVolume || (flags & 0x100) != 0 ? true : null;
                result.HeaderEncrypted = (flags & 0x80) != 0;
                if (result.HeaderEncrypted) { HeaderOnly(result); return; }
            }
            else if (!main) throw Bad("RAR4 缺少先行主头。");
            else if (type is 0x74 or 0x7a)
            {
                if (headerSize < 32) throw Bad("RAR4 文件/服务头短于固定部分。");
                dataLength = U32(header, 7);
                int nameStart = 32;
                if ((flags & 0x100) != 0)
                {
                    if (headerSize < 40) throw Bad("RAR4 大文件头缺少高位长度。");
                    ulong combined = U32(header, 7) | ((ulong)U32(header, 32) << 32);
                    if (combined > long.MaxValue) throw Bad("RAR4 压缩长度超过可定位范围。");
                    dataLength = (long)combined; nameStart = 40;
                }
                int nameSize = U16(header, 26);
                if (nameSize > headerSize - nameStart) throw Bad("RAR4 文件名长度超出头。");
                if (type == 0x74)
                {
                    if (result.FileHeaderCount++ == 0) result.FirstFileSplitBefore = (flags & 1) != 0;
                    result.LastFileSplitAfter = (flags & 2) != 0;
                    result.HasEncryptedFileHeaders |= (flags & 4) != 0;
                }
                else if (header.AsSpan(nameStart, nameSize).SequenceEqual("CMT"u8) && header[25] == 0x30 && (flags & 4) == 0)
                {
                    if (dataLength > end - cursor - headerSize) throw Bad("RAR4 注释数据越界。");
                    CaptureSfxComment(reader, result, cursor + headerSize, dataLength, U32(header, 16), "RAR4 已校验的未压缩 CMT 服务数据");
                }
            }
            else if (type == 0x7b)
            {
                int required = 7 + ((flags & 2) != 0 ? 4 : 0) + ((flags & 8) != 0 ? 2 : 0);
                if (headerSize < required || dataLength != 0) throw Bad("RAR4 END 头字段被截断或带未知数据。");
                result.ExpectsNextVolume = (flags & 1) != 0;
                if ((flags & 8) != 0) result.VolumeNumber = U16(header, 7 + ((flags & 2) != 0 ? 4 : 0));
                if (result.VolumeNumber.HasValue) result.IsFirstVolume = result.VolumeNumber == 0;
                FinishRar(result, cursor + headerSize); return;
            }
            else if (type is not (0x77 or 0x78) && (flags & 0x4000) == 0)
                throw Unsupported("RAR4 遇到不能安全跳过的未知头类型。");
            if (dataLength > end - cursor - headerSize) throw Bad("RAR4 压缩数据长度超出给定范围。");
            cursor += headerSize + dataLength;
        }
        if (main)
        {
            // RAR 1.5/2.x can legitimately omit END. It still cannot establish a
            // format-authenticated tail boundary in an outer carrier.
            result.Status = ContainerRangeStatus.ValidatedContainerHeader;
            result.HeaderIntegrityVerified = true;
            result.Detail = "RAR4 已读取头 CRC 合格，但未找到 END 标记；可能为旧格式，精确尾界与完整性仍未知。";
            return;
        }
        throw Bad("RAR4 主头缺失。");
    }

    private static void ParseRar5(Reader reader, ContainerRangeRarInspection result, long cursor, long end)
    {
        bool main = false;
        int records = 0;
        while (cursor < end)
        {
            reader.Record(ref records);
            if (end - cursor < 7) throw Bad("RAR5 头被截断。");
            byte[] prefix = reader.Read(cursor, 7);
            int sizeCursor = 4;
            ulong size = Vint(prefix, ref sizeCursor, 7, 3);
            if (size < 2 || size > (ulong)reader.Limits.MaximumHeaderBytes) throw size < 2 ? Bad("RAR5 头长度过小。") : Limited("RAR5 头长度达到限制。");
            long total = sizeCursor + (long)size;
            if (total > end - cursor) throw Bad("RAR5 头长度超出给定范围。");
            byte[] header = reader.Read(cursor, checked((int)total));
            if (Crc32(header.AsSpan(4)) != U32(header, 0)) throw Bad("RAR5 头 CRC32 校验不一致。");
            int p = sizeCursor;
            ulong type = Vint(header, ref p, header.Length), flags = Vint(header, ref p, header.Length);
            ulong extraSize = (flags & 1) != 0 ? Vint(header, ref p, header.Length) : 0;
            ulong dataSize = (flags & 2) != 0 ? Vint(header, ref p, header.Length) : 0;
            if (extraSize > (ulong)(header.Length - p)) throw Bad("RAR5 extra 区域越过头字段。");
            int fieldsEnd = header.Length - (int)extraSize;
            if (dataSize > (ulong)(end - cursor - total)) throw Bad("RAR5 数据长度超出给定范围。");
            if (type == 4)
            {
                if (main || records != 1) throw Bad("RAR5 archive-encryption 头顺序无效。");
                ulong version = Vint(header, ref p, fieldsEnd), encryptionFlags = Vint(header, ref p, fieldsEnd);
                if (version != 0 || (encryptionFlags & ~1UL) != 0) throw Unsupported("RAR5 archive-encryption 版本或标志不受支持。");
                int required = 17 + ((encryptionFlags & 1) != 0 ? 12 : 0);
                if (required > fieldsEnd - p || dataSize != 0) throw Bad("RAR5 archive-encryption 头缺少 KDF/salt/check 字段。");
                result.HeaderEncrypted = true; HeaderOnly(result); return;
            }
            if (type == 1)
            {
                if (main || records != 1) throw Bad("RAR5 主头顺序无效。");
                main = true;
                ulong archiveFlags = Vint(header, ref p, fieldsEnd);
                result.IsMultiVolume = (archiveFlags & 1) != 0;
                if ((archiveFlags & 2) != 0)
                {
                    ulong number = Vint(header, ref p, fieldsEnd);
                    if (number > long.MaxValue) throw Bad("RAR5 分卷编号超出范围。");
                    result.VolumeNumber = (long)number;
                }
                else result.VolumeNumber = result.IsMultiVolume ? 0 : null;
                result.IsFirstVolume = !result.IsMultiVolume || (result.VolumeNumber ?? 0) == 0;
                if (dataSize != 0) throw Bad("RAR5 主头包含未支持的数据段。");
            }
            else if (!main) throw Bad("RAR5 缺少先行主头。");
            else if (type is 2 or 3)
            {
                ulong fileFlags = Vint(header, ref p, fieldsEnd), unpacked = Vint(header, ref p, fieldsEnd);
                _ = Vint(header, ref p, fieldsEnd); // attributes
                if ((fileFlags & 2) != 0) Skip(ref p, 4, fieldsEnd);
                uint? dataCrc = null;
                if ((fileFlags & 4) != 0) { RequireField(p, 4, fieldsEnd); dataCrc = U32(header, p); p += 4; }
                ulong compression = Vint(header, ref p, fieldsEnd);
                _ = Vint(header, ref p, fieldsEnd); // host OS
                ulong nameLength = Vint(header, ref p, fieldsEnd);
                if (nameLength > (ulong)(fieldsEnd - p)) throw Bad("RAR5 文件名越过头字段。");
                ReadOnlySpan<byte> name = header.AsSpan(p, (int)nameLength); p += (int)nameLength;
                bool encrypted = ParseRar5Extra(header, fieldsEnd, result);
                if (type == 2)
                {
                    if (result.FileHeaderCount++ == 0) result.FirstFileSplitBefore = (flags & 8) != 0;
                    result.LastFileSplitAfter = (flags & 16) != 0;
                }
                else if (name.SequenceEqual("CMT"u8) && ((compression >> 7) & 7) == 0 && (compression & 0x40) == 0 && !encrypted && (fileFlags & 8) == 0 && unpacked == dataSize && dataCrc.HasValue)
                    CaptureSfxComment(reader, result, cursor + total, (long)dataSize, dataCrc.Value, "RAR5 已校验的未压缩 CMT 服务数据");
            }
            else if (type == 5)
            {
                ulong endFlags = Vint(header, ref p, fieldsEnd);
                if ((endFlags & ~1UL) != 0 || dataSize != 0) throw Unsupported("RAR5 END 头包含未知标志或数据。");
                result.ExpectsNextVolume = (endFlags & 1) != 0;
                FinishRar(result, cursor + total); return;
            }
            else if ((flags & 4) == 0) throw Unsupported("RAR5 遇到不能安全跳过的未知头类型。");
            cursor += total + (long)dataSize;
        }
        throw Bad("RAR5 未找到 END 标记，尾界可能被截断。");
    }

    private static bool ParseRar5Extra(byte[] header, int start, ContainerRangeRarInspection result)
    {
        int p = start;
        bool encrypted = false;
        while (p < header.Length)
        {
            ulong length = Vint(header, ref p, header.Length);
            if (length == 0 || length > (ulong)(header.Length - p)) throw Bad("RAR5 extra 记录长度越界。");
            int end = p + (int)length;
            ulong type = Vint(header, ref p, end);
            if (type == 1)
            {
                encrypted = true;
                ulong version = Vint(header, ref p, end);
                ulong flags = Vint(header, ref p, end);
                if (version != 0 || (flags & ~3UL) != 0) throw Unsupported("RAR5 file-encryption 版本或标志不受支持。");
                RequireField(p, 33 + ((flags & 1) != 0 ? 12 : 0), end);
                result.HasEncryptedFileHeaders = true;
                if ((flags & 2) != 0) result.HasHashMacFileHeaders = true;
            }
            p = end;
        }
        return encrypted;
    }

    private static void HeaderOnly(ContainerRangeRarInspection result)
    {
        result.Status = ContainerRangeStatus.ValidatedContainerHeader;
        result.HeaderIntegrityVerified = true;
        result.Detail = $"RAR{result.Version} 加密头标记及其公开头 CRC 已验证；需要密码继续，精确尾界和成员完整性仍未知。";
    }

    private static void FinishRar(ContainerRangeRarInspection result, long end)
    {
        result.EndOffset = end; result.Length = end - result.Offset; result.HasEndMarker = true;
        result.HeaderIntegrityVerified = true; result.Status = ContainerRangeStatus.Validated;
        result.Detail = $"RAR{result.Version} 各已读取头 CRC、数据跨度及 END 尾界已验证；成员解压完整性须另行检查。";
    }

    private static void CaptureSfxComment(Reader reader, ContainerRangeRarInspection result, long offset, long size, uint crc, string source)
    {
        if (size > reader.Limits.MaximumSfxConfigurationBytes) throw Limited("SFX 静态注释读取达到限制。");
        byte[] comment = reader.Read(offset, checked((int)size));
        if (Crc32(comment) != crc) throw Bad("RAR 未压缩 CMT 注释数据 CRC32 不一致。");
        string text = comment.AsSpan().StartsWith(new byte[] { 0xff, 0xfe }) ? Encoding.Unicode.GetString(comment, 2, comment.Length - 2) : Encoding.UTF8.GetString(comment);
        foreach (string line in text.Split(['\r', '\n'], StringSplitOptions.RemoveEmptyEntries))
        {
            string trimmed = line.Trim().TrimStart('\ufeff');
            if (trimmed.StartsWith(';')) continue;
            int equals = trimmed.IndexOf('=');
            string name = equals >= 0 ? trimmed[..equals].Trim() : trimmed;
            if (!SfxDirectiveNames.Contains(name)) continue;
            result.SfxConfiguration.Add(new() { Name = name, Value = equals < 0 ? string.Empty : trimmed[(equals + 1)..].Trim(), Offset = offset, Source = source });
        }
    }

    private static readonly HashSet<string> SfxDirectiveNames = new(StringComparer.OrdinalIgnoreCase)
        { "Setup", "Presetup", "Path", "Silent", "Overwrite", "TempMode", "Title", "Shortcut", "SavePath", "SetupCode", "Delete", "Update", "Lock" };

    private static ContainerRange ParseZip(Reader reader, long offset, long length)
    {
        if (length < 22) throw Bad("ZIP 缺少完整 EOCD。");
        long end = checked(offset + length);
        // EOCD may precede a carrier trailer. Search only a bounded suffix, then verify
        // all central/local references; a magic match alone never defines a range.
        int suffixLength = (int)Math.Min(length, reader.Limits.MaximumSignatureSearchBytes);
        if (suffixLength < 22) throw Limited("ZIP EOCD 搜索预算不足。");
        long suffixStart = end - suffixLength;
        byte[] suffix = reader.Read(suffixStart, suffixLength);
        int candidates = 0;
        RangeInspectionException? last = null;
        for (int i = suffix.Length - 22; i >= 0; i--)
        {
            if ((i & 4095) == 0) reader.Check();
            if (U32(suffix, i) != 0x06054b50) continue;
            if (++candidates > reader.Limits.MaximumCandidates) throw Limited("ZIP EOCD 候选数量达到限制。");
            try { return ValidateZipEnd(reader, offset, end, suffixStart + i); }
            catch (RangeInspectionException ex) when (ex.Status is ContainerRangeStatus.Malformed or ContainerRangeStatus.Unsupported) { last = ex; }
        }
        if (last is not null) throw last;
        if (length > suffixLength) throw Limited("ZIP 在受限尾部搜索中未找到可验证 EOCD；更早位置未扫描。");
        throw Bad("ZIP 未找到与中央目录及本地头一致的 EOCD。");
    }

    private static ContainerRange ValidateZipEnd(Reader reader, long offset, long availableEnd, long eocd)
    {
        byte[] end = reader.Read(eocd, 22);
        long archiveEnd = eocd + 22L + U16(end, 20);
        if (archiveEnd > availableEnd) throw Bad("ZIP EOCD 注释越界。");
        if (U16(end, 4) != 0 || U16(end, 6) != 0 || U16(end, 8) != U16(end, 10)) throw Unsupported("ZIP 分卷中央目录需由分卷适配器读取。");
        ulong count = U16(end, 10), directorySize = U32(end, 12), directoryOffset = U32(end, 16);
        long directoryEnd = eocd;
        bool zip64 = count == ushort.MaxValue || directorySize == uint.MaxValue || directoryOffset == uint.MaxValue;
        if (zip64)
        {
            if (eocd - offset < 20) throw Bad("ZIP64 locator 缺失。");
            byte[] locator = reader.Read(eocd - 20, 20);
            if (U32(locator, 0) != 0x07064b50 || U32(locator, 4) != 0 || U32(locator, 16) != 1) throw Unsupported("ZIP64 locator 无效或指向多卷。");
            ulong relative = U64(locator, 8);
            long zip64Start = Relative(offset, relative, eocd - 20);
            byte[] record = reader.Read(zip64Start, 56);
            ulong recordSize = U64(record, 4);
            if (U32(record, 0) != 0x06064b50 || recordSize < 44 || recordSize > long.MaxValue || recordSize != (ulong)(eocd - 20 - zip64Start - 12)) throw Bad("ZIP64 EOCD 长度或相邻关系无效。");
            if (U32(record, 16) != 0 || U32(record, 20) != 0 || U64(record, 24) != U64(record, 32)) throw Unsupported("ZIP64 中央目录跨卷。");
            count = U64(record, 32); directorySize = U64(record, 40); directoryOffset = U64(record, 48); directoryEnd = zip64Start;
        }
        if (count > (ulong)reader.Limits.MaximumZipEntries) throw Limited("ZIP 条目数量达到限制。");
        long central = Relative(offset, directoryOffset, directoryEnd);
        if (directorySize > long.MaxValue || directorySize != (ulong)(directoryEnd - central)) throw Bad("ZIP 中央目录大小与 EOCD 位置不一致。");
        if (count == 0 && (central != offset || directorySize != 0)) throw Bad("空 ZIP 的中央目录范围不一致。");
        long cursor = central;
        List<(long Start, long End)> localRanges = [];
        bool encrypted = false;
        for (ulong entry = 0; entry < count; entry++)
        {
            reader.Check();
            if (directoryEnd - cursor < 46) throw Bad("ZIP 中央目录条目被截断。");
            byte[] header = reader.Read(cursor, 46);
            if (U32(header, 0) != 0x02014b50) throw Bad("ZIP 中央目录条目标记不一致。");
            int nameLength = U16(header, 28), extraLength = U16(header, 30), commentLength = U16(header, 32);
            long recordLength = 46L + nameLength + extraLength + commentLength;
            if (recordLength > directoryEnd - cursor || recordLength > reader.Limits.MaximumHeaderBytes) throw Bad("ZIP 中央目录变长字段越界。");
            byte[] variable = reader.Read(cursor + 46, nameLength + extraLength);
            ulong packed = U32(header, 20), unpacked = U32(header, 24), localOffset = U32(header, 42), disk = U16(header, 34);
            bool packed64 = packed == uint.MaxValue, unpacked64 = unpacked == uint.MaxValue;
            ReadZip64Extra(variable.AsSpan(nameLength), ref unpacked, ref packed, ref localOffset, ref disk);
            if (disk != 0) throw Unsupported("ZIP 本地条目位于其它分卷。");
            ushort flags = U16(header, 8), method = U16(header, 10);
            encrypted |= (flags & 1) != 0;
            long local = Relative(offset, localOffset, central);
            if (central - local < 30) throw Bad("ZIP 本地头与中央目录重叠。");
            byte[] localHeader = reader.Read(local, 30);
            if (U32(localHeader, 0) != 0x04034b50 || U16(localHeader, 6) != flags || U16(localHeader, 8) != method) throw Bad("ZIP 本地头签名/标志/压缩方法与目录不一致。");
            int localNameLength = U16(localHeader, 26), localExtraLength = U16(localHeader, 28);
            if (localNameLength != nameLength) throw Bad("ZIP 本地文件名长度与目录不一致。");
            long dataStart = checked(local + 30L + localNameLength + localExtraLength);
            if (dataStart > central || packed > (ulong)(central - dataStart)) throw Bad("ZIP 压缩数据范围越过中央目录。");
            byte[] localVariable = reader.Read(local + 30, localNameLength + localExtraLength);
            if (!localVariable.AsSpan(0, nameLength).SequenceEqual(variable.AsSpan(0, nameLength))) throw Bad("ZIP 本地文件名与目录不一致。");
            if ((flags & 8) == 0)
            {
                ulong localPacked = U32(localHeader, 18), localUnpacked = U32(localHeader, 22), unusedOffset = 0, unusedDisk = 0;
                ReadZip64Extra(localVariable.AsSpan(localNameLength), ref localUnpacked, ref localPacked, ref unusedOffset, ref unusedDisk);
                if (localPacked != packed || localUnpacked != unpacked || U32(localHeader, 14) != U32(header, 16)) throw Bad("ZIP 本地长度/CRC 与中央目录不一致。");
            }
            long localEnd = dataStart + (long)packed;
            if ((flags & 8) != 0) localEnd = ReadZipDescriptor(reader, localEnd, central, U32(header, 16), packed, unpacked, packed64 || unpacked64);
            localRanges.Add((local, localEnd));
            cursor += recordLength;
        }
        if (cursor != directoryEnd) throw Bad("ZIP 中央目录条目数量与目录大小不一致。");
        localRanges.Sort((a, b) => a.Start.CompareTo(b.Start));
        long expected = offset;
        foreach ((long start, long finish) in localRanges)
        {
            if (start != expected) throw Bad("ZIP 本地条目之间有重叠或未解释间隙，不能建立完整范围。");
            expected = finish;
        }
        if (expected != central) throw Bad("ZIP 本地条目与中央目录之间存在未解释字节。");
        return new()
        {
            Offset = offset,
            Length = archiveEnd - offset,
            LengthIsExact = true,
            Type = ContainerRangeType.Zip,
            Status = ContainerRangeStatus.Validated,
            NeedsPassword = encrypted,
            Detail = $"ZIP{(zip64 ? "64" : string.Empty)} 本地头、数据跨度、中央目录和 EOCD 已相互验证；未以此代替成员 CRC/解压完整性检查。"
        };
    }

    private static long ReadZipDescriptor(Reader reader, long start, long limit, uint crc, ulong packed, ulong unpacked, bool zip64)
    {
        int size = zip64 ? 20 : 12;
        if (limit - start < size) throw Bad("ZIP data descriptor 被截断。");
        byte[] first = reader.Read(start, 4);
        bool signature = U32(first, 0) == 0x08074b50;
        // CRC can itself equal the optional signature. Try both interpretations.
        foreach (int prefix in signature ? new[] { 4, 0 } : new[] { 0 })
        {
            if (limit - start < size + prefix) continue;
            byte[] descriptor = reader.Read(start + prefix, size);
            ulong descriptorPacked = zip64 ? U64(descriptor, 4) : U32(descriptor, 4);
            ulong descriptorUnpacked = zip64 ? U64(descriptor, 12) : U32(descriptor, 8);
            if (U32(descriptor, 0) == crc && descriptorPacked == packed && descriptorUnpacked == unpacked) return start + prefix + size;
        }
        throw Bad("ZIP data descriptor 的 CRC/长度与目录不一致。");
    }

    private static void ReadZip64Extra(ReadOnlySpan<byte> extra, ref ulong unpacked, ref ulong packed, ref ulong offset, ref ulong disk)
    {
        bool need = unpacked == uint.MaxValue || packed == uint.MaxValue || offset == uint.MaxValue || disk == ushort.MaxValue;
        bool found = false;
        int cursor = 0;
        while (cursor < extra.Length)
        {
            if (extra.Length - cursor < 4) throw Bad("ZIP extra 头被截断。");
            int id = U16(extra, cursor), length = U16(extra, cursor + 2); cursor += 4;
            if (length > extra.Length - cursor) throw Bad("ZIP extra 字段长度越界。");
            if (id == 1)
            {
                if (found) throw Bad("ZIP64 extra 字段重复。");
                found = true;
                ReadOnlySpan<byte> value = extra.Slice(cursor, length);
                int p = 0;
                if (unpacked == uint.MaxValue) { RequireField(p, 8, length); unpacked = U64(value, p); p += 8; }
                if (packed == uint.MaxValue) { RequireField(p, 8, length); packed = U64(value, p); p += 8; }
                if (offset == uint.MaxValue) { RequireField(p, 8, length); offset = U64(value, p); p += 8; }
                if (disk == ushort.MaxValue) { RequireField(p, 4, length); disk = U32(value, p); }
            }
            cursor += length;
        }
        if (need && !found) throw Bad("ZIP64 sentinel 缺少对应 extra 字段。");
    }

    private static void CompleteUnknownRanges(ContainerRangeInspection result)
    {
        // Non-exact encrypted ranges are candidates, not coverage of known bytes.
        List<(long Start, long End)> known = result.Ranges.Where(x => x.LengthIsExact && x.Offset >= 0 && x.Length >= 0 && x.Offset <= result.FileLength && x.Length <= result.FileLength - x.Offset)
            .Select(x => (x.Offset, x.Offset + x.Length)).OrderBy(x => x.Offset).ToList();
        result.UnknownRanges.Clear();
        long cursor = 0;
        foreach ((long start, long end) in known)
        {
            if (start > cursor) result.UnknownRanges.Add(Unknown(cursor, start - cursor));
            cursor = Math.Max(cursor, end);
        }
        if (cursor < result.FileLength) result.UnknownRanges.Add(Unknown(cursor, result.FileLength - cursor));
    }

    private static ContainerRange Range(long offset, long length, ContainerRangeType type, string detail) => new()
    { Offset = offset, Length = length, Type = type, Status = ContainerRangeStatus.Validated, LengthIsExact = true, Detail = detail };
    private static ContainerRange Unknown(long offset, long length) => new()
    { Offset = offset, Length = length, Type = ContainerRangeType.Unknown, Status = ContainerRangeStatus.Unknown, LengthIsExact = true, Detail = "此字节范围尚未由所支持的容器结构建立归属；不是恶意性判断。" };
    private static void RequireRange(long offset, long length, long bound)
    { if (offset < 0 || length < 0 || offset > bound || length > bound - offset) throw Bad("请求的字节范围越界或发生长度溢出。"); }
    private static long Relative(long offset, ulong relative, long end)
    { if (offset < 0 || end < offset || relative > (ulong)(end - offset)) throw Bad("容器相对偏移超出父范围。"); return offset + (long)relative; }
    private static void RequireField(int offset, int length, int bound)
    { if (offset < 0 || length < 0 || offset > bound || length > bound - offset) throw Bad("容器头字段被截断。"); }
    private static void Skip(ref int offset, int length, int bound) { RequireField(offset, length, bound); offset += length; }
    private static ushort U16(ReadOnlySpan<byte> data, int at) => BinaryPrimitives.ReadUInt16LittleEndian(data.Slice(at, 2));
    private static uint U32(ReadOnlySpan<byte> data, int at) => BinaryPrimitives.ReadUInt32LittleEndian(data.Slice(at, 4));
    private static ulong U64(ReadOnlySpan<byte> data, int at) => BinaryPrimitives.ReadUInt64LittleEndian(data.Slice(at, 8));
    private static uint U32Be(ReadOnlySpan<byte> data, int at) => BinaryPrimitives.ReadUInt32BigEndian(data.Slice(at, 4));
    private static string FourCc(ReadOnlySpan<byte> data) => Encoding.ASCII.GetString(data[..4]);
    private static bool PlausibleFourCc(ReadOnlySpan<byte> data)
    { for (int i = 0; i < 4; i++) if (data[i] < 0x20 || data[i] > 0x7e) return false; return true; }
    private static ulong Vint(ReadOnlySpan<byte> data, ref int offset, int bound, int maximumBytes = 10)
    {
        ulong value = 0;
        for (int i = 0; i < maximumBytes; i++)
        {
            RequireField(offset, 1, bound);
            byte b = data[offset++];
            if (i == 9 && (b & 0xfe) != 0) throw Bad("RAR vint 超过 64 位。");
            value |= (ulong)(b & 0x7f) << (7 * i);
            if ((b & 0x80) == 0) return value;
        }
        throw Bad("RAR vint 连续字节超出允许长度。");
    }
    private static uint Crc32(ReadOnlySpan<byte> data)
    {
        uint value = uint.MaxValue;
        foreach (byte b in data) { value ^= b; for (int i = 0; i < 8; i++) value = (value >> 1) ^ (0xedb88320u & (uint)-(int)(value & 1)); }
        return ~value;
    }
    private static RangeInspectionException Bad(string message) => new(ContainerRangeStatus.Malformed, message);
    private static RangeInspectionException Unsupported(string message) => new(ContainerRangeStatus.Unsupported, message);
    private static RangeInspectionException Limited(string message) => new(ContainerRangeStatus.LimitReached, message);
    private sealed class RangeInspectionException(ContainerRangeStatus status, string message) : Exception(message)
    { public ContainerRangeStatus Status { get; } = status; }

    private sealed class Reader
    {
        private readonly Stream _stream;
        private readonly CancellationToken _token;
        private readonly Stopwatch _elapsed = Stopwatch.StartNew();
        public ContainerRangeLimits Limits { get; }
        public long Length { get; }
        public long BytesRead { get; private set; }
        public Reader(Stream stream, CancellationToken token, ContainerRangeLimits limits)
        {
            _stream = stream; _token = token; Limits = limits; Length = stream.Length;
            if (limits.MaximumReadBytes < 0 || limits.MaximumSignatureSearchBytes < 0 || limits.MaximumCandidates < 0 || limits.MaximumRecords < 0 || limits.MaximumZipEntries < 0 || limits.MaximumHeaderBytes < 0 || limits.MaximumSfxConfigurationBytes < 0 || limits.MaximumDuration < TimeSpan.Zero)
                throw Limited("容器检查预算不能为负数。");
            Check();
        }
        public void Check()
        {
            _token.ThrowIfCancellationRequested();
            if (_elapsed.Elapsed >= Limits.MaximumDuration) throw Limited("容器结构检查达到时间限制。");
        }
        public void Record(ref int records) { Check(); if (++records > Limits.MaximumRecords) throw Limited("容器头/盒数量达到限制。"); }
        public byte[] Read(long offset, int count)
        {
            Check(); RequireRange(offset, count, Length);
            if (count > Limits.MaximumReadBytes - BytesRead) throw Limited("容器结构读取达到字节限制。");
            byte[] data = new byte[count];
            _stream.Position = offset;
            int read = 0;
            while (read < count)
            {
                Check();
                int current = _stream.Read(data, read, count - read);
                if (current == 0) throw Bad("底层流在声明长度之前结束。");
                read += current; BytesRead += current;
            }
            Check(); return data;
        }
    }
}
