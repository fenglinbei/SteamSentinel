/*
 * RAR password/checksum adaptation includes logic derived from UnRAR
 * (copyright Alexander Roshal): CryptData::SetKey30, sha1_process_rar29,
 * SetKey50/pbkdf2 and ConvertHashToMAC. Cryptographic primitives use .NET.
 * Source snapshot: SharpCompress c083c6efd843a844b0c8f7878787360e815be781,
 * reference/unrar/{crypt3.cpp,sha1.cpp,crypt5.cpp,license.txt}.
 * The SHA-1 reference also credits Steve Reid's public-domain foundation.
 *
 * UnRAR source code may be used in any software to handle
 * RAR archives without limitations free of charge, but cannot be
 * used to develop RAR (WinRAR) compatible archiver and to
 * re-create RAR compression algorithm, which is proprietary.
 * Distribution of modified UnRAR source code in separate form
 * or as a part of other software is permitted, provided that
 * full text of this paragraph, starting from "UnRAR source code"
 * words, is included in license, or in documentation if license
 * is not available, and in source code comments of resulting package.
 */
using System.Buffers.Binary;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using SharpCompress.Common;
using SharpCompress.Common.Rar.Headers;
using SharpCompress.IO;
using SharpCompress.Readers;

namespace SteamSentinel.Core.Inspection;

/// <summary>Checksums are obtained from the last part of each complete logical file.</summary>
public sealed class ArchiveRarEntryChecksum
{
    public string Key { get; }
    public long Size { get; }
    public bool IsDirectory { get; }
    public bool IsEncrypted { get; }
    internal bool Rar5 { get; }
    internal bool HashMac { get; }
    internal byte[] ExpectedHash { get; }
    internal byte[] Salt { get; }
    internal int KdfLog2 { get; }
    internal object FirstHeader { get; }
    internal IReadOnlyList<ArchiveRarPackedPart> PackedParts { get; }

    internal ArchiveRarEntryChecksum(string key, long size, bool directory, bool encrypted,
        bool rar5, bool hashMac, byte[] expectedHash, byte[] salt, int kdfLog2,
        object firstHeader, IReadOnlyList<ArchiveRarPackedPart> packedParts)
    {
        Key = key; Size = size; IsDirectory = directory; IsEncrypted = encrypted;
        Rar5 = rar5; HashMac = hashMac; ExpectedHash = expectedHash.ToArray();
        Salt = salt.ToArray(); KdfLog2 = kdfLog2;
        FirstHeader = firstHeader; PackedParts = Array.AsReadOnly(packedParts.ToArray());
    }
}

public sealed class ArchiveRarIntegrityIndex
{
    private readonly Dictionary<string, ArchiveRarEntryChecksum?> _byKey = new(StringComparer.Ordinal);
    public IReadOnlyList<ArchiveRarEntryChecksum> Entries { get; }
    public bool HeaderEncrypted { get; }
    public bool IsSolid { get; }
    internal ArchiveRarIntegrityIndex(IEnumerable<ArchiveRarEntryChecksum> entries, bool encrypted, bool solid)
    {
        Entries = Array.AsReadOnly(entries.ToArray()); HeaderEncrypted = encrypted; IsSolid = solid;
        foreach (ArchiveRarEntryChecksum entry in Entries)
        {
            if (!_byKey.TryAdd(entry.Key, entry)) _byKey[entry.Key] = null;
        }
    }

    public ArchiveRarEntryChecksum Match(IEntry entry)
    {
        ArgumentNullException.ThrowIfNull(entry);
        if (entry.Key is null || !_byKey.TryGetValue(entry.Key, out ArchiveRarEntryChecksum? checksum) || checksum is null)
            throw RarIntegrityReflection.Invalid("RAR 成员在已验证清单中缺失或重名，无法唯一关联校验值。");
        if (entry.Size != checksum.Size || entry.IsDirectory != checksum.IsDirectory || entry.IsEncrypted != checksum.IsEncrypted)
            throw RarIntegrityReflection.Invalid("RAR 成员与已验证清单的元数据不一致。");
        return checksum;
    }

    public IReader OpenReader(string? password, CancellationToken token = default) =>
        new ArchiveVolumeRarReader(this, password, token);
}

/// <summary>Complete must run after a nonempty-buffer read returned EOF and before disposing decodedStream.</summary>
public sealed class ArchiveIntegrityRarVerifier : IDisposable
{
    private readonly ArchiveRarEntryChecksum _checksum;
    private byte[]? _hashKey;
    private bool _completed;
    private bool _disposed;
    public ArchiveIntegrityRequirement Requirement { get; }

    internal ArchiveIntegrityRarVerifier(ArchiveRarEntryChecksum checksum, string? password)
    {
        _checksum = checksum;
        if (checksum.IsEncrypted && password is null)
            throw new SharpCompress.Common.CryptographicException("RAR 成员需要密码。");
        if (checksum.HashMac)
        {
            byte[] passwordBytes = Encoding.UTF8.GetBytes(password!);
            try
            {
                // RAR5 supplements the initial PBKDF2 result with 16 further rounds.
                // https://www.rarlab.com/technote.htm; UnRAR crypt5.cpp, pbkdf2/ConvertHashToMAC.
                _hashKey = Rfc2898DeriveBytes.Pbkdf2(passwordBytes, checksum.Salt,
                    checked((1 << checksum.KdfLog2) + 16), HashAlgorithmName.SHA256, 32);
            }
            finally { CryptographicOperations.ZeroMemory(passwordBytes); }
        }
        bool plainCrc = checksum.ExpectedHash.Length == 4 && !checksum.HashMac;
        Requirement = new(true, plainCrc,
            plainCrc ? BinaryPrimitives.ReadUInt32LittleEndian(checksum.ExpectedHash) : 0,
            checksum.Size, checksum.IsEncrypted && checksum.Size > 0,
            checksum.HashMac ? "RAR5 密码关联校验" : "RAR 内容校验");
    }

    public void Complete(Stream decodedStream, long copied, uint actualCrc32)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (_completed) throw new InvalidOperationException("RAR 校验已经结束。");
        if (copied != _checksum.Size)
            throw RarIntegrityReflection.Invalid("RAR 成员实际长度与声明不一致。");
        byte[] actual;
        if (_checksum.ExpectedHash.Length == 4)
        {
            actual = new byte[4];
            BinaryPrimitives.WriteUInt32LittleEndian(actual, actualCrc32);
        }
        else
        {
            // Our decoded-content wrapper calculates BLAKE2sp during the bounded read;
            // consume its completed value without decoding or opening a member again.
            actual = RarIntegrityReflection.ReadCompletedBlake(decodedStream);
        }
        try
        {
            if (_hashKey is not null)
            {
                byte[] digest = HMACSHA256.HashData(_hashKey, actual);
                try
                {
                    if (actual.Length == 4)
                    {
                        uint folded = 0;
                        for (int i = 0; i < digest.Length; i += 4)
                            folded ^= BinaryPrimitives.ReadUInt32LittleEndian(digest.AsSpan(i, 4));
                        BinaryPrimitives.WriteUInt32LittleEndian(actual, folded);
                    }
                    else digest.CopyTo(actual, 0);
                }
                finally { CryptographicOperations.ZeroMemory(digest); }
            }
            if (!CryptographicOperations.FixedTimeEquals(actual, _checksum.ExpectedHash))
                throw RarIntegrityReflection.Invalid("RAR 成员内容校验不匹配。");
            _completed = true;
        }
        finally { CryptographicOperations.ZeroMemory(actual); }
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        if (_hashKey is not null) CryptographicOperations.ZeroMemory(_hashKey);
        _hashKey = null;
    }
}

public static partial class ArchiveIntegrity
{
    /// <summary>Only streams already admitted by the bounded volume resolver may be passed here.</summary>
    public static ArchiveRarIntegrityIndex InspectRarHeaders(IReadOnlyList<Stream> volumes,
        string? password, ArchiveVolumeLimits limits, CancellationToken token = default)
    {
        ArgumentNullException.ThrowIfNull(volumes);
        ArgumentNullException.ThrowIfNull(limits);
        limits.Validate();
        RarIntegrityReflection.EnsureVersion();
        if (password is { Length: > 256 })
            throw new ArchiveVolumeException(ArchiveVolumeStatus.LimitExceeded, "RAR 密码长度超出格式适配预算。");
        if (volumes.Count is < 1 || volumes.Count > limits.MaximumVolumes)
            throw new ArchiveVolumeException(ArchiveVolumeStatus.LimitExceeded, "RAR 卷数超出预算。");
        var entries = new List<ArchiveRarEntryChecksum>();
        ArchiveRarEntryChecksum? pending = null;
        bool? commonRar5 = null, commonSolid = null, commonEncrypted = null;
        long metadataRead = 0;
        int headerCount = 0;
        foreach ((Stream source, int volumeIndex) in volumes.Select((s, i) => (s, i)))
        {
            token.ThrowIfCancellationRequested();
            if (!source.CanRead || !source.CanSeek)
                throw RarIntegrityReflection.Invalid("RAR 卷流必须可读且可定位。");
            long originalPosition = source.Position;
            using var bounded = new RarMetadataStream(source, limits.MaximumMetadataBytes,
                count => { metadataRead = checked(metadataRead + count); return metadataRead; }, token);
            byte[]? headerKey = null;
            try
            {
                bounded.Position = 0;
                var options = new ReaderOptions { Password = password, LeaveStreamOpen = true, LookForHeader = false };
                var factory = new RarHeaderFactory(StreamingMode.Seekable, options);
                using var headers = factory.ReadHeaders(bounded).GetEnumerator();
                bool sawMark = false, sawMain = false, sawEnd = false, rar5 = false;
                bool volumeEncrypted = false;
                while (true)
                {
                    token.ThrowIfCancellationRequested();
                    if (++headerCount > checked(limits.MaximumEntries + limits.MaximumVolumes * 8))
                        throw new ArchiveVolumeException(ArchiveVolumeStatus.LimitExceeded, "RAR 头数量超出预算。");
                    long headerStart = bounded.Position;
                    bool encryptedHeader = factory.IsEncrypted;
                    long? controlledDataStart = null;
                    IRarHeader header;
                    if (sawMain && !rar5 && encryptedHeader)
                    {
                        // RAR4 header encryption uses the same historical KDF as its
                        // content. Decode the original header through our bounded view
                        // so long and Unicode passwords do not enter the library KDF.
                        Rar4EncryptedHeaderResult decodedHeader = Rar4EncryptedHeaderReader.ReadNext(
                            bounded, options, limits, token);
                        header = decodedHeader.Header;
                        controlledDataStart = decodedHeader.DataStartPosition;
                    }
                    else
                    {
                        if (!headers.MoveNext()) break;
                        header = headers.Current;
                    }
                    if (header.HeaderType == HeaderType.Mark)
                    {
                        if (sawMark) throw RarIntegrityReflection.Invalid("重复 RAR 标记。");
                        sawMark = true;
                        rar5 = RarIntegrityReflection.Property<bool>(header, "IsRar5");
                        if (commonRar5.HasValue && commonRar5.Value != rar5)
                            throw RarIntegrityReflection.Invalid("RAR 各卷格式不一致。");
                        commonRar5 = rar5;
                        continue;
                    }
                    if (!sawMark) throw RarIntegrityReflection.Invalid("RAR 标记缺失。");
                    if (header.HeaderType == HeaderType.Crypt)
                    {
                        if (!rar5 || sawMain || headerKey is not null)
                            throw RarIntegrityReflection.Invalid("RAR 加密头位置不合法。");
                        object crypto = RarIntegrityReflection.FieldObject(header, "CryptInfo",
                            "SharpCompress.Common.Rar.Rar5CryptoInfo");
                        byte[] salt = RarIntegrityReflection.Field<byte[]>(crypto, "Salt");
                        int log2 = RarIntegrityReflection.Field<int>(crypto, "LG2Count");
                        RarIntegrityReflection.ValidateKdf(log2, salt);
                        if (password is null) throw new SharpCompress.Common.CryptographicException("RAR 加密头需要密码。");
                        byte[] passwordBytes = Encoding.UTF8.GetBytes(password);
                        try { headerKey = Rfc2898DeriveBytes.Pbkdf2(passwordBytes, salt, 1 << log2, HashAlgorithmName.SHA256, 32); }
                        finally { CryptographicOperations.ZeroMemory(passwordBytes); }
                        volumeEncrypted = true;
                        continue;
                    }
                    if (header.HeaderType == HeaderType.Archive)
                    {
                        if (sawMain) throw RarIntegrityReflection.Invalid("重复 RAR 主头。");
                        sawMain = true;
                        bool multi = RarIntegrityReflection.Property<bool>(header, "IsVolume");
                        bool first = RarIntegrityReflection.Property<bool>(header, "IsFirstVolume");
                        bool solid = RarIntegrityReflection.Property<bool>(header, "IsSolid");
                        int? number = RarIntegrityReflection.Property<int?>(header, "VolumeNumber");
                        volumeEncrypted |= factory.IsEncrypted;
                        if ((volumes.Count > 1 && !multi) || (multi && first != (volumeIndex == 0)) ||
                            (rar5 && (number ?? 0) != volumeIndex))
                            throw RarIntegrityReflection.Invalid("RAR 主头卷顺序或卷标志不一致。");
                        if ((commonSolid.HasValue && commonSolid.Value != solid) ||
                            (commonEncrypted.HasValue && commonEncrypted.Value != volumeEncrypted))
                            throw RarIntegrityReflection.Invalid("RAR 各卷固实或加密设置不一致。");
                        commonSolid = solid; commonEncrypted = volumeEncrypted;
                        continue;
                    }
                    if (!sawMain) throw RarIntegrityReflection.Invalid("RAR 主头缺失。");
                    if (header.HeaderType == HeaderType.EndArchive)
                    {
                        ushort flags = RarIntegrityReflection.Property<ushort>(header, "Flags");
                        bool next = (flags & 1) != 0;
                        if (next != (volumeIndex < volumes.Count - 1))
                            throw new ArchiveVolumeException(ArchiveVolumeStatus.MissingVolume, "RAR 结束标记与受控卷清单不一致。");
                        if (!rar5)
                        {
                            short? number = RarIntegrityReflection.Property<short?>(header, "VolumeNumber");
                            if (number.HasValue && number.Value != volumeIndex)
                                throw RarIntegrityReflection.Invalid("RAR 结束头卷号不一致。");
                        }
                        sawEnd = true;
                        break;
                    }
                    if (header.HeaderType is HeaderType.File or HeaderType.Service or HeaderType.NewSub)
                    {
                        if (header.HeaderType != HeaderType.File)
                        {
                            // The library leaves RAR5 CMT service data unread, even in seekable mode.
                            if (header.HeaderType == HeaderType.Service &&
                                RarIntegrityReflection.Property<string>(header, "FileName") == "CMT")
                                bounded.Position = checked(bounded.Position + RarIntegrityReflection.Property<long>(header, "CompressedSize"));
                            continue;
                        }
                        string name = RarIntegrityReflection.Property<string>(header, "FileName");
                        long size = RarIntegrityReflection.Property<long>(header, "UncompressedSize");
                        bool directory = RarIntegrityReflection.Property<bool>(header, "IsDirectory");
                        bool encrypted = RarIntegrityReflection.Property<bool>(header, "IsEncrypted");
                        bool splitBefore = RarIntegrityReflection.Property<bool>(header, "IsSplitBefore");
                        bool splitAfter = RarIntegrityReflection.Property<bool>(header, "IsSplitAfter");
                        if (RarIntegrityReflection.Property<bool>(header, "IsRedir"))
                            throw new ArchiveVolumeException(ArchiveVolumeStatus.UnsupportedIntegrity, "RAR 重定向成员不具有可校验的独立内容流。");
                        byte[] expected = RarIntegrityReflection.NullableBytes(header, "FileCrc") ?? [];
                        if (size < 0 || size == long.MaxValue || (!directory && expected.Length is not (4 or 32)))
                            throw new ArchiveVolumeException(ArchiveVolumeStatus.UnsupportedIntegrity, "RAR 成员缺少受支持的长度或内容校验值。");
                        byte[] salt = []; int log2 = 0; bool hashMac = false;
                        if (rar5)
                        {
                            RarCryptoRecord record = RarIntegrityReflection.ReadRar5Crypto(bounded, headerStart,
                                encryptedHeader ? headerKey : null, limits.MaximumMetadataBytes);
                            if (record.Encrypted != encrypted)
                                throw RarIntegrityReflection.Invalid("RAR5 加密元数据与解码器解释不一致。");
                            salt = record.Salt; log2 = record.Log2; hashMac = record.HashMac;
                            if (encrypted) RarIntegrityReflection.ValidateKdf(log2, salt);
                        }
                        long dataStart = controlledDataStart ?? RarIntegrityReflection.Property<long>(header, "DataStartPosition");
                        long packedLength = RarIntegrityReflection.Property<long>(header, "CompressedSize");
                        if (dataStart < 0 || packedLength < 0 || dataStart > source.Length - packedLength)
                            throw RarIntegrityReflection.Invalid("RAR 压缩数据区超出受控卷范围。");
                        var part = new ArchiveRarPackedPart(source, dataStart, packedLength, volumeIndex);
                        object firstHeader = pending?.FirstHeader ?? header;
                        IReadOnlyList<ArchiveRarPackedPart> parts = pending is null ? [part] : [.. pending.PackedParts, part];
                        var current = new ArchiveRarEntryChecksum(name, size, directory, encrypted, rar5,
                            hashMac, expected, salt, log2, firstHeader, parts);
                        if (splitBefore)
                        {
                            if (pending is null || pending.Key != current.Key || pending.Size != current.Size ||
                                pending.IsDirectory != current.IsDirectory || pending.IsEncrypted != current.IsEncrypted ||
                                pending.KdfLog2 != current.KdfLog2 ||
                                !pending.Salt.AsSpan().SequenceEqual(current.Salt))
                                throw new ArchiveVolumeException(ArchiveVolumeStatus.MixedVolumes, "RAR 拆分成员的相邻卷元数据不一致。");
                            if (!RarIntegrityReflection.CryptoParametersMatch(pending.FirstHeader, header, rar5))
                                throw new ArchiveVolumeException(ArchiveVolumeStatus.MixedVolumes, "RAR 拆分成员的加密参数不一致。");
                            // Intermediate parts have a packed-part checksum and may omit
                            // HashMAC. Only the last part supplies the logical content hash.
                        }
                        else if (pending is not null)
                            throw new ArchiveVolumeException(ArchiveVolumeStatus.MissingVolume, "RAR 拆分成员缺少连续后续卷。");
                        if (splitAfter) pending = current;
                        else
                        {
                            pending = null;
                            entries.Add(current);
                            if (entries.Count > limits.MaximumEntries)
                                throw new ArchiveVolumeException(ArchiveVolumeStatus.LimitExceeded, "RAR 成员数超出预算。");
                        }
                    }
                }
                if (!sawMain || !sawEnd)
                    throw new ArchiveVolumeException(ArchiveVolumeStatus.MissingVolume, "RAR 卷缺少经过校验的主头或结束标记。");
            }
            finally
            {
                if (headerKey is not null) CryptographicOperations.ZeroMemory(headerKey);
                source.Position = originalPosition;
            }
        }
        if (pending is not null)
            throw new ArchiveVolumeException(ArchiveVolumeStatus.MissingVolume, "RAR 最后成员仍要求后续卷。");
        return new ArchiveRarIntegrityIndex(entries, commonEncrypted ?? false, commonSolid ?? false);
    }

    public static ArchiveIntegrityRarVerifier BeginRar(IEntry entry, ArchiveRarEntryChecksum checksum, string? password)
    {
        ArgumentNullException.ThrowIfNull(entry);
        ArgumentNullException.ThrowIfNull(checksum);
        RarIntegrityReflection.EnsureVersion();
        if (entry.CompressionType != CompressionType.Rar || entry.Key != checksum.Key ||
            entry.Size != checksum.Size || entry.IsDirectory != checksum.IsDirectory || entry.IsEncrypted != checksum.IsEncrypted)
            throw RarIntegrityReflection.Invalid("RAR 实际成员与已验证的顺序清单不一致。");
        if (checksum.IsDirectory)
            throw new ArchiveVolumeException(ArchiveVolumeStatus.UnsupportedIntegrity, "RAR 目录不具有内容流。");
        return new ArchiveIntegrityRarVerifier(checksum, password);
    }

    public static ArchiveIntegrityRarVerifier BeginRar(IEntry entry, ArchiveRarIntegrityIndex index, string? password) =>
        BeginRar(entry, index.Match(entry), password);
}

internal readonly record struct RarCryptoRecord(bool Encrypted, bool HashMac, byte[] Salt, int Log2);
internal sealed record ArchiveRarPackedPart(Stream Source, long Offset, long Length, int VolumeIndex);

internal static class RarIntegrityReflection
{
    private const BindingFlags InstanceMembers = BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.DeclaredOnly;
    internal static void EnsureVersion()
    {
        Assembly assembly = typeof(RarHeaderFactory).Assembly;
        if (assembly.GetName().Version != new Version(0, 50, 4, 0) ||
            assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion != "0.50.4")
            throw Unsupported("RAR 校验适配器仅适用于锁定的 SharpCompress 0.50.4。");
    }

    internal static ArchiveVolumeException Invalid(string message) => new(ArchiveVolumeStatus.InvalidMetadata, message);
    private static ArchiveVolumeException Unsupported(string message) => new(ArchiveVolumeStatus.UnsupportedIntegrity, message);

    private static PropertyInfo FindProperty(object value, string name)
    {
        for (Type? type = value.GetType(); type is not null; type = type.BaseType)
        {
            if (type.Assembly != typeof(RarHeaderFactory).Assembly) break;
            PropertyInfo? property = type.GetProperty(name, InstanceMembers);
            if (property is not null && property.GetIndexParameters().Length == 0 && property.GetMethod is not null)
                return property;
        }
        throw Unsupported("锁定版本的 RAR 元数据属性不可用：" + name);
    }

    internal static T Property<T>(object value, string name)
    {
        PropertyInfo property = FindProperty(value, name);
        if (property.PropertyType != typeof(T)) throw Unsupported("RAR 元数据属性形状已改变：" + name);
        object? result = property.GetValue(value);
        if (result is T typed) return typed;
        if (result is null && Nullable.GetUnderlyingType(typeof(T)) is not null) return default!;
        throw Invalid("RAR 元数据属性为空：" + name);
    }

    internal static object PropertyObject(object value, string name, string expectedType)
    {
        PropertyInfo property = FindProperty(value, name);
        if (property.PropertyType.FullName != expectedType || property.PropertyType.Assembly != typeof(RarHeaderFactory).Assembly)
            throw Unsupported("RAR 元数据属性形状已改变：" + name);
        return property.GetValue(value) ?? throw Invalid("RAR 加密元数据为空。");
    }

    internal static byte[]? NullableBytes(object value, string name)
    {
        PropertyInfo property = FindProperty(value, name);
        if (property.PropertyType != typeof(byte[])) throw Unsupported("RAR 校验属性形状已改变。");
        return (byte[]?)property.GetValue(value);
    }

    internal static T Field<T>(object value, string name)
    {
        FieldInfo? field = value.GetType().GetField(name, InstanceMembers);
        if (value.GetType().Assembly != typeof(RarHeaderFactory).Assembly || field is null || field.FieldType != typeof(T))
            throw Unsupported("RAR 元数据字段形状已改变：" + name);
        return field.GetValue(value) is T typed ? typed : throw Invalid("RAR 元数据字段为空：" + name);
    }

    internal static object FieldObject(object value, string name, string expectedType)
    {
        FieldInfo? field = value.GetType().GetField(name, InstanceMembers);
        if (value.GetType().Assembly != typeof(RarHeaderFactory).Assembly || field is null ||
            field.FieldType.FullName != expectedType || field.FieldType.Assembly != typeof(RarHeaderFactory).Assembly)
            throw Unsupported("RAR 元数据字段形状已改变：" + name);
        return field.GetValue(value) ?? throw Invalid("RAR 加密元数据字段为空。");
    }

    internal static void ValidateKdf(int log2, byte[] salt)
    {
        // The library accepts larger counts; the scanner deliberately bounds this work.
        if (log2 is < 0 or > 20)
            throw new ArchiveVolumeException(ArchiveVolumeStatus.LimitExceeded, "RAR 密码派生工作量超出预算。");
        if (salt.Length != 16) throw Invalid("RAR5 salt 长度不合法。");
    }

    internal static byte[] ReadCompletedBlake(Stream decoded)
    {
        EnsureVersion();
        if (decoded.GetType() == typeof(EntryStream)) decoded = Field<Stream>(decoded, "_stream");
        if (decoded is RarDecodedContentStream controlled) return controlled.GetCompletedBlake();
        Type type = decoded.GetType();
        if (type.Assembly != typeof(RarHeaderFactory).Assembly ||
            type.FullName != "SharpCompress.Compressors.Rar.RarBLAKE2spStream")
            throw Unsupported("RAR BLAKE2sp 校验流形状不受支持。");
        MethodInfo? method = type.GetMethod("GetCrc", BindingFlags.Instance | BindingFlags.Public,
            binder: null, types: Type.EmptyTypes, modifiers: null);
        if (method is null || method.ReturnType != typeof(byte[])) throw Unsupported("RAR BLAKE2sp 校验接口已改变。");
        try
        {
            if (method.Invoke(decoded, null) is not byte[] { Length: 32 } result)
                throw Invalid("RAR BLAKE2sp 校验结果不合法。");
            return result.ToArray();
        }
        catch (TargetInvocationException ex)
        { throw new ArchiveVolumeException(ArchiveVolumeStatus.InvalidMetadata, "RAR 内容流尚未完成 BLAKE2sp 校验。", ex.InnerException ?? ex); }
    }

    internal static bool CryptoParametersMatch(object first, object current, bool rar5)
    {
        if (Property<byte>(first, "CompressionAlgorithm") != Property<byte>(current, "CompressionAlgorithm") ||
            Property<byte>(first, "CompressionMethod") != Property<byte>(current, "CompressionMethod") ||
            Property<uint>(first, "WindowSize") != Property<uint>(current, "WindowSize") ||
            Property<bool>(first, "IsSolid") != Property<bool>(current, "IsSolid")) return false;
        if (Property<bool>(first, "IsEncrypted") != Property<bool>(current, "IsEncrypted")) return false;
        if (!Property<bool>(first, "IsEncrypted")) return true;
        if (!rar5) return (NullableBytes(first, "R4Salt") ?? []).AsSpan().SequenceEqual(NullableBytes(current, "R4Salt") ?? []);
        object a = PropertyObject(first, "Rar5CryptoInfo", "SharpCompress.Common.Rar.Rar5CryptoInfo");
        object b = PropertyObject(current, "Rar5CryptoInfo", "SharpCompress.Common.Rar.Rar5CryptoInfo");
        return Field<byte[]>(a, "InitV").AsSpan().SequenceEqual(Field<byte[]>(b, "InitV"));
    }

    internal static RarCryptoRecord ReadRar5Crypto(Stream source, long start, byte[]? key, int maximumHeaderBytes)
    {
        long restore = source.Position;
        byte[]? plaintext = null;
        try
        {
            source.Position = start;
            if (key is null)
            {
                byte[] prefix = new byte[7];
                source.ReadExactly(prefix.AsSpan(0, 5));
                int prefixLength = 5;
                while ((prefix[prefixLength - 1] & 0x80) != 0)
                {
                    if (prefixLength == 7) throw Invalid("RAR5 头长度编码超限。");
                    source.ReadExactly(prefix.AsSpan(prefixLength++, 1));
                }
                int index = 4;
                int body = checked((int)ReadVint(prefix.AsSpan(0, prefixLength), ref index));
                int length = checked(index + body);
                if (length > maximumHeaderBytes || length < index) throw Invalid("RAR5 头长度超出预算。");
                plaintext = new byte[length];
                prefix.AsSpan(0, index).CopyTo(plaintext);
                source.ReadExactly(plaintext.AsSpan(index));
            }
            else
            {
                byte[] iv = new byte[16], first = new byte[16];
                source.ReadExactly(iv); source.ReadExactly(first);
                using Aes aes = Aes.Create();
                aes.Key = key; aes.IV = iv; aes.Mode = CipherMode.CBC; aes.Padding = PaddingMode.None;
                using ICryptoTransform decryptor = aes.CreateDecryptor();
                byte[] initial = new byte[16];
                decryptor.TransformBlock(first, 0, 16, initial, 0);
                int index = 4;
                int body = checked((int)ReadVint(initial, ref index));
                if (index > 7) throw Invalid("RAR5 头长度编码超限。");
                int length = checked(index + body);
                if (length > maximumHeaderBytes || length < index) throw Invalid("RAR5 加密头长度超出预算。");
                int aligned = checked((length + 15) & ~15);
                plaintext = new byte[aligned]; initial.CopyTo(plaintext, 0);
                if (aligned > 16)
                {
                    byte[] cipher = new byte[aligned - 16];
                    source.ReadExactly(cipher);
                    decryptor.TransformBlock(cipher, 0, cipher.Length, plaintext, 16);
                }
            }
            int cursor = 4;
            int headerSize = checked((int)ReadVint(plaintext, ref cursor));
            int end = checked(cursor + headerSize);
            if (end > plaintext.Length || ArchiveIntegrity.Crc32(plaintext.AsSpan(4, end - 4)) != BinaryPrimitives.ReadUInt32LittleEndian(plaintext))
                throw Invalid("RAR5 原始头 CRC32 不匹配。");
            ulong typeCode = ReadVint(plaintext.AsSpan(0, end), ref cursor);
            ulong flags = ReadVint(plaintext.AsSpan(0, end), ref cursor);
            if (typeCode != 2) throw Invalid("RAR5 文件头位置与解码器不一致。");
            int extra = (flags & 1) != 0 ? checked((int)ReadVint(plaintext.AsSpan(0, end), ref cursor)) : 0;
            if ((flags & 2) != 0) _ = ReadVint(plaintext.AsSpan(0, end), ref cursor);
            int extraStart = checked(end - extra);
            if (extraStart < cursor) throw Invalid("RAR5 扩展区长度不合法。");
            cursor = extraStart;
            RarCryptoRecord result = new(false, false, [], 0);
            while (cursor < end)
            {
                int size = checked((int)ReadVint(plaintext.AsSpan(0, end), ref cursor));
                int recordEnd = checked(cursor + size);
                if (size < 1 || recordEnd > end) throw Invalid("RAR5 扩展记录长度不合法。");
                ulong recordType = ReadVint(plaintext.AsSpan(0, recordEnd), ref cursor);
                if (recordType == 1)
                {
                    if (result.Encrypted) throw Invalid("重复 RAR5 文件加密记录。");
                    ulong version = ReadVint(plaintext.AsSpan(0, recordEnd), ref cursor);
                    ulong cryptoFlags = ReadVint(plaintext.AsSpan(0, recordEnd), ref cursor);
                    if (version != 0 || (cryptoFlags & ~3UL) != 0)
                        throw Unsupported("RAR5 文件加密版本或标志不受支持。");
                    int required = (cryptoFlags & 1) != 0 ? 45 : 33;
                    if (recordEnd - cursor != required) throw Invalid("RAR5 文件加密记录尺寸不合法。");
                    int log2 = plaintext[cursor++];
                    byte[] salt = plaintext.AsSpan(cursor, 16).ToArray();
                    result = new(true, (cryptoFlags & 2) != 0, salt, log2);
                }
                cursor = recordEnd;
            }
            return result;
        }
        finally
        {
            if (plaintext is not null) CryptographicOperations.ZeroMemory(plaintext);
            source.Position = restore;
        }
    }

    private static ulong ReadVint(ReadOnlySpan<byte> data, ref int index)
    {
        ulong value = 0;
        for (int shift = 0; shift < 70; shift += 7)
        {
            if ((uint)index >= (uint)data.Length) throw Invalid("RAR5 整数编码被截断。");
            byte next = data[index++];
            if (shift == 63 && next > 1) throw Invalid("RAR5 整数编码溢出。");
            value |= (ulong)(next & 0x7f) << shift;
            if ((next & 0x80) == 0) return value;
        }
        throw Invalid("RAR5 整数编码超限。");
    }
}

internal sealed class RarMetadataStream(Stream source, long maximumBytes, Func<int, long> account, CancellationToken token) : Stream
{
    public override bool CanRead => true;
    public override bool CanSeek => true;
    public override bool CanWrite => false;
    public override long Length => source.Length;
    public override long Position
    {
        get => source.Position;
        set
        {
            token.ThrowIfCancellationRequested();
            if (value < 0 || value > Length) throw RarIntegrityReflection.Invalid("RAR 数据区超出受控卷范围。");
            source.Position = value;
        }
    }
    public override int Read(byte[] buffer, int offset, int count) => Read(buffer.AsSpan(offset, count));
    public override int Read(Span<byte> buffer)
    {
        token.ThrowIfCancellationRequested();
        if (buffer.Length > maximumBytes) throw new ArchiveVolumeException(ArchiveVolumeStatus.LimitExceeded, "RAR 单次元数据读取超出预算。");
        int read = source.Read(buffer);
        if (account(read) > maximumBytes) throw new ArchiveVolumeException(ArchiveVolumeStatus.LimitExceeded, "RAR 元数据读取总量超出预算。");
        return read;
    }
    public override int ReadByte()
    {
        Span<byte> single = stackalloc byte[1];
        return Read(single) == 0 ? -1 : single[0];
    }
    public override long Seek(long offset, SeekOrigin origin)
    {
        Position = checked((origin switch
        {
            SeekOrigin.Begin => 0,
            SeekOrigin.Current => Position,
            SeekOrigin.End => Length,
            _ => throw new ArgumentOutOfRangeException(nameof(origin))
        }) + offset);
        return Position;
    }
    public override void Flush() { }
    public override void SetLength(long value) => throw new NotSupportedException();
    public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
}
