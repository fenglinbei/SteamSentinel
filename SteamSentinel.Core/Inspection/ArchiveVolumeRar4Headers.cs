using System.Buffers.Binary;
using System.Reflection;
using System.Security.Cryptography;
using SharpCompress.Common;
using SharpCompress.Common.Rar.Headers;
using SharpCompress.Readers;

namespace SteamSentinel.Core.Inspection;

internal readonly record struct Rar4EncryptedHeaderResult(IRarHeader Header, long DataStartPosition);

/// <summary>
/// RAR4's plaintext main header is parsed normally. Subsequent encrypted headers
/// use the independently verified RAR4 KDF rather than the pinned library's
/// ASCII-only derivation. Library parsers receive original, CRC-verified plaintext;
/// physical data offsets remain separate and no library metadata is changed.
/// </summary>
internal static class Rar4EncryptedHeaderReader
{
    internal static Rar4EncryptedHeaderResult ReadNext(Stream source, ReaderOptions options,
        ArchiveVolumeLimits limits, CancellationToken token)
    {
        RarIntegrityReflection.EnsureVersion();
        token.ThrowIfCancellationRequested();
        string password = options.Password ?? throw new SharpCompress.Common.CryptographicException("RAR4 加密头需要密码。");
        if (password.Length > 256)
            throw new ArchiveVolumeException(ArchiveVolumeStatus.LimitExceeded, "RAR4 密码长度超出格式适配预算。");
        if (!source.CanRead || !source.CanSeek)
            throw RarIntegrityReflection.Invalid("RAR4 加密头要求受控可定位源流。");
        if (source.Position < 0 || source.Position > source.Length - 24)
            throw new ArchiveVolumeException(ArchiveVolumeStatus.MissingVolume, "RAR4 加密头的 salt 或首个 AES 分组被截断。");

        byte[] salt = new byte[8], first = new byte[16];
        byte[]? key = null, iv = null, plaintext = null, remainder = null;
        try
        {
            source.ReadExactly(salt); source.ReadExactly(first);
            (key, iv) = RarContinuousCrypto.DeriveRar4(password, salt, token);
            token.ThrowIfCancellationRequested();
            using Aes aes = Aes.Create();
            aes.Mode = CipherMode.CBC; aes.Padding = PaddingMode.None; aes.Key = key; aes.IV = iv;
            using ICryptoTransform decryptor = aes.CreateDecryptor();
            byte[] initial = new byte[16];
            try
            {
                decryptor.TransformBlock(first, 0, first.Length, initial, 0);
                int headerLength = BinaryPrimitives.ReadUInt16LittleEndian(initial.AsSpan(5, 2));
                if (headerLength < 7)
                    throw RarIntegrityReflection.Invalid("RAR4 加密头长度无效，密码不匹配或数据已损坏。");
                int aligned = checked((headerLength + 15) & ~15);
                if (aligned > limits.MaximumMetadataBytes)
                    throw new ArchiveVolumeException(ArchiveVolumeStatus.LimitExceeded, "RAR4 加密头超出元数据预算。");
                if (aligned - 16 > source.Length - source.Position)
                    throw RarIntegrityReflection.Invalid("RAR4 加密头范围无效，密码不匹配或密文被截断。");
                plaintext = new byte[aligned]; initial.CopyTo(plaintext, 0);
                if (aligned > 16)
                {
                    remainder = new byte[aligned - 16]; source.ReadExactly(remainder);
                    decryptor.TransformBlock(remainder, 0, remainder.Length, plaintext, 16);
                }
                token.ThrowIfCancellationRequested();
                ushort expected = BinaryPrimitives.ReadUInt16LittleEndian(plaintext);
                if ((ushort)ArchiveIntegrity.Crc32(plaintext.AsSpan(2, headerLength - 2)) != expected)
                    throw RarIntegrityReflection.Invalid("RAR4 加密头 CRC 不匹配，密码不匹配或数据已损坏。");
                // SharpCompress's RAR4 parser stores HEAD_SIZE in a signed Int16.
                // Reject that decoder boundary only after the original header CRC passes.
                if (headerLength > short.MaxValue)
                    throw new ArchiveVolumeException(ArchiveVolumeStatus.UnsupportedIntegrity, "RAR4 头长度超出锁定元数据解析器支持范围。");
                long dataStart = source.Position;
                IRarHeader header = ParseOriginalHeader(plaintext, headerLength, options);
                long packed = header.HeaderType switch
                {
                    HeaderType.File or HeaderType.NewSub => RarIntegrityReflection.Property<long>(header, "CompressedSize"),
                    HeaderType.Protect => RarIntegrityReflection.Property<uint>(header, "DataSize"),
                    HeaderType.EndArchive => 0,
                    _ => throw new ArchiveVolumeException(ArchiveVolumeStatus.UnsupportedIntegrity, "RAR4 加密头类型不受支持。")
                };
                if (packed < 0 || dataStart > source.Length - packed)
                    throw new ArchiveVolumeException(ArchiveVolumeStatus.MissingVolume, "RAR4 已验证头声明的数据区超出受控卷范围。");
                source.Position = checked(dataStart + packed);
                return new(header, dataStart);
            }
            finally { CryptographicOperations.ZeroMemory(initial); }
        }
        catch (EndOfStreamException ex)
        { throw new ArchiveVolumeException(ArchiveVolumeStatus.MissingVolume, "RAR4 加密头密文被截断。", ex); }
        finally
        {
            CryptographicOperations.ZeroMemory(salt); CryptographicOperations.ZeroMemory(first);
            if (key is not null) CryptographicOperations.ZeroMemory(key);
            if (iv is not null) CryptographicOperations.ZeroMemory(iv);
            if (plaintext is not null) CryptographicOperations.ZeroMemory(plaintext);
            if (remainder is not null) CryptographicOperations.ZeroMemory(remainder);
        }
    }

    private static IRarHeader ParseOriginalHeader(byte[] plaintext, int length, ReaderOptions options)
    {
        Assembly assembly = typeof(RarHeaderFactory).Assembly;
        Type Required(string name) => assembly.GetType(name, throwOnError: false) ?? throw Unsupported();
        Type crcType = Required("SharpCompress.Common.Rar.RarCrcBinaryReader");
        Type baseType = Required("SharpCompress.Common.Rar.Headers.RarHeader");
        ConstructorInfo constructor = crcType.GetConstructor([typeof(Stream)]) ?? throw Unsupported();
        MethodInfo parseBase = baseType.GetMethod("TryReadBase", BindingFlags.NonPublic | BindingFlags.Static,
            binder: null, types: [crcType, typeof(bool), typeof(IArchiveEncoding)], modifiers: null) ?? throw Unsupported();
        if (parseBase.ReturnType != baseType) throw Unsupported();
        using MemoryStream buffer = new(plaintext, 0, length, writable: false, publiclyVisible: false);
        using IDisposable reader = constructor.Invoke([buffer]) as IDisposable ?? throw Unsupported();
        try
        {
            object header = parseBase.Invoke(null, [reader, false, options.ArchiveEncoding])
                ?? throw RarIntegrityReflection.Invalid("RAR4 原始头无法解析。");
            byte code = RarIntegrityReflection.Property<byte>(header, "HeaderCode");
            (string TypeName, HeaderType Kind, bool File) shape = code switch
            {
                0x74 => ("FileHeader", HeaderType.File, true),
                0x7a => ("FileHeader", HeaderType.NewSub, true),
                0x7b => ("EndArchiveHeader", HeaderType.EndArchive, false),
                0x78 => ("ProtectHeader", HeaderType.Protect, false),
                _ => throw new ArchiveVolumeException(ArchiveVolumeStatus.UnsupportedIntegrity, "RAR4 加密头包含未支持的记录类型。")
            };
            Type childType = Required("SharpCompress.Common.Rar.Headers." + shape.TypeName);
            Type[] signature = shape.File ? [baseType, crcType, typeof(HeaderType)] : [baseType, crcType];
            MethodInfo create = childType.GetMethod("Create", BindingFlags.Public | BindingFlags.Static,
                binder: null, types: signature, modifiers: null) ?? throw Unsupported();
            if (create.ReturnType != childType) throw Unsupported();
            object?[] arguments = shape.File ? [header, reader, shape.Kind] : [header, reader];
            if (create.Invoke(null, arguments) is not IRarHeader parsed || parsed.HeaderType != shape.Kind || buffer.Position != length)
                throw RarIntegrityReflection.Invalid("RAR4 原始头字段或范围不一致。");
            return parsed;
        }
        catch (TargetInvocationException ex)
        { throw new ArchiveVolumeException(ArchiveVolumeStatus.InvalidMetadata, "RAR4 已校验头的字段无法解析。", ex.InnerException ?? ex); }
    }

    private static ArchiveVolumeException Unsupported() => new(ArchiveVolumeStatus.UnsupportedIntegrity,
        "锁定的 RAR4 元数据解析接口不可用。");
}
