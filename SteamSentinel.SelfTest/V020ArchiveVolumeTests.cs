using System.Buffers.Binary;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using SharpCompress.Common;
using SharpCompress.Readers;
using SteamSentinel.Core.Inspection;

namespace SteamSentinel.SelfTest;

internal static partial class Program
{
    private static async Task TestV020ArchiveVolumesAsync(string root)
    {
        await TestV020ZipSkippingAsync(root);
        TestV020RarIntegrityPrimitives();
        string directory = Path.Combine(root, "v020-volumes"); Directory.CreateDirectory(directory);
        ArchiveVolumeCandidate Candidate(string name, string? logical = null) => new(Path.Combine(directory, name), logical ?? name);
        byte[] rar4HeaderPlaintext = Encoding.UTF8.GetBytes("SteamSentinel RAR4 KDF fixture: inert text only.\r\n");
        foreach ((string name, string password, string archive) in V020Rar4HeaderVectors())
        {
            ArchiveVolumeCandidate headerEncrypted = Candidate($"rar4-header-{name}.rar");
            await File.WriteAllBytesAsync(headerEncrypted.PhysicalPath, Convert.FromBase64String(archive));
            using ArchiveVolumeSession session = await ArchiveVolumeSession.OpenAsync(
                ArchiveVolumeResolver.Single(headerEncrypted, ArchiveVolumeFormat.Rar), password);
            var decoded = await V020Decode(session);
            Check($"0.2.0 RAR4加密文件名{name}通过完整受控会话",
                decoded.Count == 1 && decoded.PasswordVerified && decoded.Bytes.SequenceEqual(rar4HeaderPlaintext));
        }
        var rar4HeaderSplit = V020Rar4HeaderSplitVector();
        ArchiveVolumeCandidate[] rar4HeaderParts = [Candidate("rar4-hp-split.rar"), Candidate("rar4-hp-split.r00")];
        for (int i = 0; i < rar4HeaderParts.Length; i++)
            await File.WriteAllBytesAsync(rar4HeaderParts[i].PhysicalPath, rar4HeaderSplit.Volumes[i]);
        using (ArchiveVolumeSession session = await ArchiveVolumeSession.OpenAsync(
            ArchiveVolumeResolver.Resolve(rar4HeaderParts[1], rar4HeaderParts), rar4HeaderSplit.Password))
        {
            var decoded = await V020Decode(session);
            Check("0.2.0 RAR4长Unicode密码加密文件名旧二卷通过完整会话",
                decoded.Count == 1 && decoded.PasswordVerified && session.Identities.Count == 2 &&
                decoded.Bytes.SequenceEqual(rar4HeaderSplit.Plaintext));
        }
        ArchiveVolumeCandidate[] rarNames = [Candidate("group.part1.rar"), Candidate("group.part2.rar"), Candidate("group.part3.rar")];
        ArchiveVolumePlan numbered = ArchiveVolumeResolver.Resolve(rarNames[2], rarNames.Reverse());
        Check("0.2.0 从任一RAR卷映射到有序组", numbered.Status == ArchiveVolumeStatus.Ready && numbered.Layout == ArchiveVolumeLayout.RarNumbered && numbered.Members.SequenceEqual(rarNames));
        Check("0.2.0 分卷缺失中间编号明确拒绝", ArchiveVolumeResolver.Resolve(rarNames[2], [rarNames[0], rarNames[2]]).Status == ArchiveVolumeStatus.MissingVolume);
        Check("0.2.0 分卷重复数字序号拒绝", ArchiveVolumeResolver.Resolve(rarNames[0], [rarNames[0], Candidate("group.part01.rar")]).Status == ArchiveVolumeStatus.DuplicateVolume);
        Check("0.2.0 新旧分卷混用拒绝", ArchiveVolumeResolver.Resolve(rarNames[0], [rarNames[0], Candidate("group.rar")]).Status == ArchiveVolumeStatus.MixedVolumes);
        Check("0.2.0 不跨逻辑目录寻找兄弟卷", ArchiveVolumeResolver.Resolve(Candidate("group.part3.rar", "one/group.part3.rar"),
            [Candidate("group.part1.rar", "two/group.part1.rar"), Candidate("group.part2.rar", "two/group.part2.rar"), Candidate("group.part3.rar", "one/group.part3.rar")]).Status == ArchiveVolumeStatus.MissingVolume);
        Check("0.2.0 分卷候选收集先应用限额", ArchiveVolumeResolver.Resolve(rarNames[0], rarNames,
            new() { MaximumCandidates = 2 }).Status == ArchiveVolumeStatus.LimitExceeded);
        ArchiveVolumeCandidate[] oldNames = [Candidate("legacy.rar"), Candidate("legacy.r00"), Candidate("legacy.r01")];
        Check("0.2.0 旧r00分卷顺序与首卷映射", ArchiveVolumeResolver.Resolve(oldNames[1], oldNames).Members.SequenceEqual(oldNames));
        ArchiveVolumeCandidate[] zipNames = [Candidate("spanned.z01"), Candidate("spanned.zip")];
        Check("0.2.0 z01按ZIP而非RAR旧卷解释", ArchiveVolumeResolver.Resolve(zipNames[0], zipNames).Layout == ArchiveVolumeLayout.ZipSpanned);
        Check("0.2.0 ZIP分盘最终zip卷缺失明确拒绝", ArchiveVolumeResolver.Resolve(zipNames[0], [zipNames[0]]).Status == ArchiveVolumeStatus.MissingVolume);
        ArchiveVolumeCandidate[] numeric = [Candidate("numeric.zip.001"), Candidate("numeric.zip.002")];
        Check("0.2.0 数字切分由第二卷回溯组", ArchiveVolumeResolver.Resolve(numeric[1], numeric).Members.SequenceEqual(numeric));
        Check("0.2.0 数字切分不混入同名完整包", ArchiveVolumeResolver.Resolve(numeric[0], [numeric[0], Candidate("numeric.zip")]).Status == ArchiveVolumeStatus.MixedVolumes);

        byte[] payload = Encoding.UTF8.GetBytes("SteamSentinel inert member. No executable content.");
        byte[] zip = V020StoredZip(payload);
        ArchiveVolumeCandidate ordinary = Candidate("ordinary.zip"); await File.WriteAllBytesAsync(ordinary.PhysicalPath, zip);
        long sourceReads = 0;
        using (ArchiveVolumeSession session = await ArchiveVolumeSession.OpenAsync(ArchiveVolumeResolver.Resolve(ordinary, [ordinary]),
            readDecorator: source => new V020CountedSource(source, count => sourceReads += count)))
        {
            var decoded = await V020Decode(session);
            Check("0.2.0 受控ZIP读取与成员CRC校验", decoded.Bytes.SequenceEqual(payload) && decoded.Count == 1 && !decoded.PasswordVerified);
            Check("0.2.0 源哈希与解码读取均经过计量装饰器", sourceReads > zip.Length && session.Identities.Single().Sha256 == Convert.ToHexString(SHA256.HashData(zip)));
            bool locked = false;
            try { using FileStream mutation = new(ordinary.PhysicalPath, FileMode.Open, FileAccess.Write, FileShare.ReadWrite); }
            catch (IOException) { locked = true; }
            Check("0.2.0 扫描生命周期锁定实际输入文件", locked);
        }
        using (FileStream writable = new(ordinary.PhysicalPath, FileMode.Open, FileAccess.Write, FileShare.ReadWrite))
            Check("0.2.0 会话释放后解除只读源锁", writable.CanWrite);
        using (ArchiveVolumeSession incomplete = await ArchiveVolumeSession.OpenAsync(ArchiveVolumeResolver.Single(ordinary, ArchiveVolumeFormat.Zip)))
        {
            bool unopened = false;
            try { incomplete.VerifyTraversalCompleted(); } catch (InvalidOperationException) { unopened = true; }
            Check("0.2.0 未开始遍历不能声称完成", unopened);
            using IReader skipped = incomplete.OpenReader();
            bool reached = skipped.MoveToNextEntry() && !skipped.MoveToNextEntry();
            bool unverified = false;
            try { incomplete.VerifyTraversalCompleted(); } catch (ArchiveVolumeException) { unverified = true; }
            Check("0.2.0 目录已到EOF但漏校验ZIP成员仍拒绝完成", reached && unverified);
        }

        await File.WriteAllBytesAsync(numeric[0].PhysicalPath, zip[..(zip.Length / 2)]);
        await File.WriteAllBytesAsync(numeric[1].PhysicalPath, zip[(zip.Length / 2)..]);
        using (ArchiveVolumeSession session = await ArchiveVolumeSession.OpenAsync(ArchiveVolumeResolver.Resolve(numeric[1], numeric)))
        {
            var decoded = await V020Decode(session);
            Check("0.2.0 ZIP001只用明确流列表跨卷解码", decoded.Bytes.SequenceEqual(payload) && session.Identities.Count == 2);
        }
        Check("0.2.0 缺尾ZIP001不借助库自动打开相邻002", await V020Rejects(ArchiveVolumeResolver.Resolve(numeric[0], [numeric[0]]), ArchiveVolumeStatus.MissingVolume));

        byte[][] spanned = V020SpannedZip(payload);
        for (int i = 0; i < spanned.Length; i++) await File.WriteAllBytesAsync(zipNames[i].PhysicalPath, spanned[i]);
        using (ArchiveVolumeSession session = await ArchiveVolumeSession.OpenAsync(ArchiveVolumeResolver.Resolve(zipNames[1], zipNames)))
            Check("0.2.0 ZIP z01分盘按元数据卷号解码", (await V020Decode(session)).Bytes.SequenceEqual(payload));
        byte[] wrongDisk = spanned[1].ToArray(); BinaryPrimitives.WriteUInt16LittleEndian(wrongDisk.AsSpan(wrongDisk.Length - 18), 2);
        ArchiveVolumeCandidate wrongDiskCandidate = Candidate("wrong-disk.zip"); await File.WriteAllBytesAsync(wrongDiskCandidate.PhysicalPath, wrongDisk);
        Check("0.2.0 ZIP结束记录不可伪称卷组完整", await V020Rejects(ArchiveVolumeResolver.Single(wrongDiskCandidate, ArchiveVolumeFormat.Zip), ArchiveVolumeStatus.MissingVolume));

        byte[] zeroPayload = V020ZeroCrcPayload();
        Check("0.2.0 测试夹具包含真实合法CRC零值", ArchiveIntegrity.Crc32(zeroPayload) == 0 && zeroPayload.Length > 0);
        ArchiveVolumeCandidate zero = Candidate("zero.zip"); await File.WriteAllBytesAsync(zero.PhysicalPath, V020StoredZip(zeroPayload));
        using (ArchiveVolumeSession session = await ArchiveVolumeSession.OpenAsync(ArchiveVolumeResolver.Single(zero, ArchiveVolumeFormat.Zip)))
            Check("0.2.0 普通ZIP零CRC仍经校验后通过", (await V020Decode(session)).Bytes.SequenceEqual(zeroPayload));
        byte[] damagedZero = V020StoredZip(zeroPayload); damagedZero[30 + Encoding.UTF8.GetByteCount("inert.txt")] ^= 1;
        ArchiveVolumeCandidate corrupt = Candidate("zero-corrupt.zip"); await File.WriteAllBytesAsync(corrupt.PhysicalPath, damagedZero);
        Check("0.2.0 普通ZIP零CRC篡改不会跳过校验", await V020Rejects(ArchiveVolumeResolver.Single(corrupt, ArchiveVolumeFormat.Zip), ArchiveVolumeStatus.InvalidMetadata, decode: true));

        const string secret = "SteamSentinel-Inert-723";
        ArchiveVolumeCandidate traditional = Candidate("traditional.zip");
        await File.WriteAllBytesAsync(traditional.PhysicalPath, Convert.FromBase64String("UEsDBBQAAQAIADKkJl27vthzTAAAAEMAAAASAAAAaW5lcnQtcmVhZGFibGUudHh0BWRRFD4Gpdq3jq1DttMKsG5AHun+VIAgH6vXHFwAr1KWb+/heg0aH9HVLT4GpXyxwNWZaM+2l2rvEbmCkb0WJ1hkiXKa1MfSUciSLVBLAQI/ABQAAQAIADKkJl27vthzTAAAAEMAAAASACQAAAAAAAAAIAAAAAAAAABpbmVydC1yZWFkYWJsZS50eHQKACAAAAAAAAEAGAAoql3v+z3dAW2lZ+/7Pd0BKKpd7/s93QFQSwUGAAAAAAEAAQBkAAAAfAAAAAAA"));
        using (ArchiveVolumeSession session = await ArchiveVolumeSession.OpenAsync(ArchiveVolumeResolver.Single(traditional, ArchiveVolumeFormat.Zip), secret))
        {
            var decoded = await V020Decode(session);
            Check("0.2.0 传统ZipCrypto依赖真实CRC验证密码", decoded.Bytes.Length == 67 && decoded.PasswordVerified);
        }
        foreach (ushort version in new ushort[] { 1, 2 })
        {
            ArchiveVolumeCandidate aes = Candidate($"aes{version}.zip");
            byte[] encrypted = V020AesZip(payload, secret, version); await File.WriteAllBytesAsync(aes.PhysicalPath, encrypted);
            using (ArchiveVolumeSession session = await ArchiveVolumeSession.OpenAsync(ArchiveVolumeResolver.Single(aes, ArchiveVolumeFormat.Zip), secret))
            {
                var decoded = await V020Decode(session);
                Check($"0.2.0 ZIP AES AE{version}独立认证且密码可验证", decoded.Bytes.SequenceEqual(payload) && decoded.PasswordVerified);
            }
            byte[] badTag = encrypted.ToArray(); int tag = 30 + 9 + 11 + 16 + 2 + payload.Length; badTag[tag] ^= 1;
            ArchiveVolumeCandidate tampered = Candidate($"aes{version}-tag.zip"); await File.WriteAllBytesAsync(tampered.PhysicalPath, badTag);
            Check($"0.2.0 ZIP AES AE{version}认证码篡改被拒绝", await V020Rejects(ArchiveVolumeResolver.Single(tampered, ArchiveVolumeFormat.Zip), ArchiveVolumeStatus.InvalidMetadata, secret));
        }
        ArchiveVolumeCandidate aesZero = Candidate("aes1-zero.zip");
        await File.WriteAllBytesAsync(aesZero.PhysicalPath, V020AesZip(zeroPayload, secret, 1));
        using (ArchiveVolumeSession session = await ArchiveVolumeSession.OpenAsync(ArchiveVolumeResolver.Single(aesZero, ArchiveVolumeFormat.Zip), secret))
            Check("0.2.0 AES AE1的合法零CRC与AE2明确区分", (await V020Decode(session)).Bytes.SequenceEqual(zeroPayload));

        ArchiveVolumeCandidate wrapped = Candidate("wrapped.bin", "payload.zip");
        byte[] prefix = Encoding.ASCII.GetBytes("INERT WRAPPER PREFIX");
        byte[] wrapper = prefix.Concat(zip).Concat(Encoding.ASCII.GetBytes("INERT TAIL")).ToArray();
        await File.WriteAllBytesAsync(wrapped.PhysicalPath, wrapper);
        wrapped = wrapped with { Offset = prefix.Length, Length = zip.Length };
        using (ArchiveVolumeSession session = await ArchiveVolumeSession.OpenAsync(ArchiveVolumeResolver.Single(wrapped, ArchiveVolumeFormat.Zip)))
        {
            var decoded = await V020Decode(session); ArchiveVolumeIdentity identity = session.Identities.Single();
            Check("0.2.0 内部范围不复制且绑定完整外层与切片哈希", decoded.Bytes.SequenceEqual(payload) &&
                identity.Sha256 == Convert.ToHexString(SHA256.HashData(wrapper)) && identity.RangeSha256 == Convert.ToHexString(SHA256.HashData(zip)) &&
                identity.Offset == prefix.Length && identity.Length == zip.Length && identity.SourceLength == wrapper.Length);
        }

        foreach (string fixedName in new[] { "seven-stored.7z", "seven-encrypted.7z" })
        {
            byte[] bytes = V020FixedArchive(fixedName);
            ArchiveVolumeCandidate[] parts = [Candidate(fixedName + ".001"), Candidate(fixedName + ".002"), Candidate(fixedName + ".003")];
            int width = bytes.Length / 3;
            await File.WriteAllBytesAsync(parts[0].PhysicalPath, bytes[..width]);
            await File.WriteAllBytesAsync(parts[1].PhysicalPath, bytes[width..(width * 2)]);
            await File.WriteAllBytesAsync(parts[2].PhysicalPath, bytes[(width * 2)..]);
            string? password = fixedName.Contains("encrypted", StringComparison.Ordinal) ? secret : null;
            using (ArchiveVolumeSession session = await ArchiveVolumeSession.OpenAsync(ArchiveVolumeResolver.Resolve(parts[2], parts), password))
            {
                var decoded = await V020Decode(session);
                Check($"0.2.0 {fixedName}受控跨卷及CRC验证", decoded.Count == 1 && decoded.Bytes.Length == 67 && decoded.PasswordVerified == (password is not null));
            }
            Check($"0.2.0 {fixedName}缺最后卷独立识别", await V020Rejects(ArchiveVolumeResolver.Resolve(parts[0], parts.Take(2)), ArchiveVolumeStatus.MissingVolume, password));
        }
        byte[] corruptSeven = V020FixedArchive("seven-stored.7z"); corruptSeven[32] ^= 1;
        ArchiveVolumeCandidate sevenCorrupt = Candidate("seven-corrupt.7z"); await File.WriteAllBytesAsync(sevenCorrupt.PhysicalPath, corruptSeven);
        Check("0.2.0 7z头完整也不能替代成员CRC校验", await V020Rejects(ArchiveVolumeResolver.Single(sevenCorrupt, ArchiveVolumeFormat.SevenZip), ArchiveVolumeStatus.InvalidMetadata, decode: true));

        byte[] rarExpected = new byte[6600]; Random rarRandom = new(723);
        for (int i = 0; i < 3; i++) { byte[] item = new byte[2200]; rarRandom.NextBytes(item); item.CopyTo(rarExpected, i * 2200); }
        foreach (string family in new[] { "rar5-hp-solid", "rar5-p-solid", "rar5-blake-hp-solid" })
        {
            ArchiveVolumeCandidate[] parts = Enumerable.Range(1, 3).Select(i => Candidate($"{family}.part{i}.rar")).ToArray();
            foreach (ArchiveVolumeCandidate part in parts) await File.WriteAllBytesAsync(part.PhysicalPath, V020FixedArchive(part.DisplayName));
            using (ArchiveVolumeSession session = await ArchiveVolumeSession.OpenAsync(ArchiveVolumeResolver.Resolve(parts[2], parts), secret))
            {
                var decoded = await V020Decode(session);
                Check($"0.2.0 {family}三卷固实成员完整校验", decoded.Count == 3 && decoded.Bytes.SequenceEqual(rarExpected) && decoded.PasswordVerified);
            }
            Check($"0.2.0 {family}缺尾不自动读取现存相邻卷", await V020Rejects(ArchiveVolumeResolver.Resolve(parts[0], parts.Take(2)), ArchiveVolumeStatus.MissingVolume, secret));
        }

        ArchiveVolumeCandidate[] legacy = [Candidate("legacy-read.rar"), Candidate("legacy-read.r00")];
        byte[][] legacyBytes = V020LegacyRar(payload);
        for (int i = 0; i < legacy.Length; i++) await File.WriteAllBytesAsync(legacy[i].PhysicalPath, legacyBytes[i]);
        using (ArchiveVolumeSession session = await ArchiveVolumeSession.OpenAsync(ArchiveVolumeResolver.Resolve(legacy[1], legacy)))
            Check("0.2.0 惰性RAR4旧r00分卷端到端读取", (await V020Decode(session)).Bytes.SequenceEqual(payload));
        Check("0.2.0 实际总源字节预算在解码前执行", await V020Rejects(ArchiveVolumeResolver.Single(ordinary, ArchiveVolumeFormat.Zip,
            new() { MaximumTotalBytes = 32 }), ArchiveVolumeStatus.LimitExceeded));
    }

    private static async Task<(byte[] Bytes, int Count, bool PasswordVerified)> V020Decode(ArchiveVolumeSession session)
    {
        using IReader reader = session.OpenReader(); using MemoryStream all = new();
        int count = 0; bool password = false;
        try
        {
            while (reader.MoveToNextEntry())
            {
                if (reader.Entry.IsDirectory) continue;
                using ArchiveIntegrityEntryVerifier verifier = ArchiveIntegrity.Begin(session, reader.Entry);
                if (!verifier.Requirement.Supported) throw new ArchiveVolumeException(ArchiveVolumeStatus.UnsupportedIntegrity, verifier.Requirement.Detail);
                using Stream input = reader.OpenEntryStream();
                try
                {
                    using MemoryStream output = new();
                    using SharpCompress.Crypto.Crc32Stream crc = new(output);
                    await input.CopyToAsync(crc); verifier.Complete(input, output.Length, crc.Crc);
                    password |= verifier.CanValidatePassword; count++; all.Write(output.ToArray());
                }
                catch { reader.Cancel(); throw; }
            }
        }
        catch { reader.Cancel(); throw; }
        session.VerifyTraversalCompleted();
        return (all.ToArray(), count, password);
    }

    private static async Task<bool> V020Rejects(ArchiveVolumePlan plan, ArchiveVolumeStatus status, string? password = null, bool decode = false)
    {
        try { using ArchiveVolumeSession session = await ArchiveVolumeSession.OpenAsync(plan, password); if (decode) await V020Decode(session); return false; }
        catch (ArchiveVolumeException exception) { return exception.Reason == status; }
    }

    private static byte[] V020StoredZip(byte[] payload, byte[]? extra = null, ushort method = 0, ushort flags = 0,
        uint? crcOverride = null, byte[]? packed = null)
    {
        byte[] name = Encoding.UTF8.GetBytes("inert.txt"); extra ??= []; packed ??= payload;
        uint crc = crcOverride ?? ArchiveIntegrity.Crc32(payload);
        using MemoryStream stream = new(); using BinaryWriter writer = new(stream, Encoding.UTF8, true);
        writer.Write(0x04034b50u); writer.Write((ushort)20); writer.Write(flags); writer.Write(method); writer.Write(0u);
        writer.Write(crc); writer.Write((uint)packed.Length); writer.Write((uint)payload.Length); writer.Write((ushort)name.Length); writer.Write((ushort)extra.Length);
        writer.Write(name); writer.Write(extra); writer.Write(packed);
        long central = stream.Position;
        writer.Write(0x02014b50u); writer.Write((ushort)20); writer.Write((ushort)20); writer.Write(flags); writer.Write(method); writer.Write(0u);
        writer.Write(crc); writer.Write((uint)packed.Length); writer.Write((uint)payload.Length); writer.Write((ushort)name.Length); writer.Write((ushort)extra.Length);
        writer.Write((ushort)0); writer.Write((ushort)0); writer.Write((ushort)0); writer.Write(0u); writer.Write(0u); writer.Write(name); writer.Write(extra);
        uint centralLength = checked((uint)(stream.Position - central));
        writer.Write(0x06054b50u); writer.Write((ushort)0); writer.Write((ushort)0); writer.Write((ushort)1); writer.Write((ushort)1);
        writer.Write(centralLength); writer.Write((uint)central); writer.Write((ushort)0); writer.Flush(); return stream.ToArray();
    }

    private static byte[][] V020SpannedZip(byte[] payload)
    {
        byte[] zip = V020StoredZip(payload); int localLength = 30 + 9;
        int cut = localLength + payload.Length / 2;
        byte[] first = new byte[cut + 4]; BinaryPrimitives.WriteUInt32LittleEndian(first, 0x08074b50); zip.AsSpan(0, cut).CopyTo(first.AsSpan(4));
        byte[] last = zip[cut..]; int central = localLength + payload.Length - cut; int end = last.Length - 22;
        BinaryPrimitives.WriteUInt32LittleEndian(last.AsSpan(central + 42), 4);
        BinaryPrimitives.WriteUInt16LittleEndian(last.AsSpan(end + 4), 1); BinaryPrimitives.WriteUInt16LittleEndian(last.AsSpan(end + 6), 1);
        BinaryPrimitives.WriteUInt32LittleEndian(last.AsSpan(end + 16), (uint)central); return [first, last];
    }

    private static byte[] V020ZeroCrcPayload()
    {
        // Solve the 32-bit affine CRC mapping for a four-byte nonempty payload whose CRC is zero.
        byte[] bytes = new byte[4]; uint initial = ArchiveIntegrity.Crc32(bytes);
        uint[] values = new uint[32], masks = new uint[32];
        for (int i = 0; i < 32; i++)
        {
            byte[] bit = new byte[4]; bit[i / 8] = (byte)(1 << (i % 8));
            uint value = ArchiveIntegrity.Crc32(bit) ^ initial, mask = 1u << i;
            for (int b = 31; b >= 0; b--) if ((value & (1u << b)) != 0)
            {
                if (values[b] == 0) { values[b] = value; masks[b] = mask; break; }
                value ^= values[b]; mask ^= masks[b];
            }
        }
        uint answer = 0;
        for (int b = 31; b >= 0; b--) if ((initial & (1u << b)) != 0) { initial ^= values[b]; answer ^= masks[b]; }
        BinaryPrimitives.WriteUInt32LittleEndian(bytes, answer); return bytes;
    }

    private static byte[] V020AesZip(byte[] payload, string password, ushort version)
    {
        byte[] salt = Enumerable.Range(1, 16).Select(i => (byte)i).ToArray();
        byte[] derived = Rfc2898DeriveBytes.Pbkdf2(Encoding.UTF8.GetBytes(password), salt, 1000, HashAlgorithmName.SHA1, 66);
        byte[] cipher = new byte[payload.Length]; using Aes aes = Aes.Create(); aes.Key = derived[..32]; aes.Mode = CipherMode.ECB; aes.Padding = PaddingMode.None;
        using ICryptoTransform encrypt = aes.CreateEncryptor(); byte[] counter = new byte[16], keyStream = new byte[16];
        for (int position = 0; position < payload.Length; position += 16)
        {
            BinaryPrimitives.WriteUInt32LittleEndian(counter, (uint)(position / 16 + 1)); encrypt.TransformBlock(counter, 0, 16, keyStream, 0);
            for (int i = 0; i < Math.Min(16, payload.Length - position); i++) cipher[position + i] = (byte)(payload[position + i] ^ keyStream[i]);
        }
        byte[] authentication = HMACSHA1.HashData(derived.AsSpan(32, 32), cipher);
        byte[] packed = salt.Concat(derived.AsSpan(64, 2).ToArray()).Concat(cipher).Concat(authentication[..10]).ToArray();
        byte[] extra = [0x01, 0x99, 0x07, 0x00, (byte)version, 0x00, (byte)'A', (byte)'E', 0x03, 0x00, 0x00];
        byte[] result = V020StoredZip(payload, extra, 99, 1, version == 2 ? 0 : ArchiveIntegrity.Crc32(payload), packed);
        CryptographicOperations.ZeroMemory(derived); return result;
    }

    private static byte[][] V020LegacyRar(byte[] payload)
    {
        byte[] name = Encoding.ASCII.GetBytes("inert.txt"); uint crc = ArchiveIntegrity.Crc32(payload);
        byte[] Header(byte type, ushort flags, byte[] body)
        {
            byte[] header = new byte[7 + body.Length]; header[2] = type;
            BinaryPrimitives.WriteUInt16LittleEndian(header.AsSpan(3), flags); BinaryPrimitives.WriteUInt16LittleEndian(header.AsSpan(5), (ushort)header.Length);
            body.CopyTo(header, 7); BinaryPrimitives.WriteUInt16LittleEndian(header, (ushort)ArchiveIntegrity.Crc32(header.AsSpan(2))); return header;
        }
        byte[] Volume(int index)
        {
            byte[] data = index == 0 ? payload[..(payload.Length / 2)] : payload[(payload.Length / 2)..];
            using MemoryStream body = new(); using (BinaryWriter writer = new(body, Encoding.UTF8, true))
            {
                writer.Write((uint)data.Length); writer.Write((uint)payload.Length); writer.Write((byte)2); writer.Write(crc); writer.Write(0u);
                writer.Write((byte)20); writer.Write((byte)0x30); writer.Write((ushort)name.Length); writer.Write(0x20u); writer.Write(name);
            }
            return new byte[] { 0x52, 0x61, 0x72, 0x21, 0x1a, 0x07, 0x00 }
                .Concat(Header(0x73, (ushort)(index == 0 ? 0x101 : 1), new byte[6]))
                .Concat(Header(0x74, (ushort)(0x8000 | (index == 0 ? 2 : 1)), body.ToArray())).Concat(data)
                .Concat(Header(0x7b, (ushort)(index == 0 ? 1 : 0), [])).ToArray();
        }
        return [Volume(0), Volume(1)];
    }

    private sealed class V020CountedSource(Stream inner, Action<int> counted) : Stream
    {
        public override bool CanRead => true; public override bool CanSeek => true; public override bool CanWrite => false;
        public override long Length => inner.Length; public override long Position { get => inner.Position; set => inner.Position = value; }
        public override int Read(byte[] buffer, int offset, int count) { int read = inner.Read(buffer, offset, count); counted(read); return read; }
        public override int Read(Span<byte> buffer) { int read = inner.Read(buffer); counted(read); return read; }
        public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken token = default)
        { int read = await inner.ReadAsync(buffer, token); counted(read); return read; }
        public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken token) => ReadAsync(buffer.AsMemory(offset, count), token).AsTask();
        public override long Seek(long offset, SeekOrigin origin) => inner.Seek(offset, origin);
        public override void Flush() { }
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }
}
