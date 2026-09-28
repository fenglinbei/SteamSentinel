using SteamSentinel.Core.Reporting;
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
        string password = options.Password ?? throw MessageExceptions.Create(MessageText.Create("Backend.Core.ArchiveVolumeRar4Headers.ReadNext.01"), sourceText => new SharpCompress.Common.CryptographicException(sourceText));
        if (password.Length > 256)
            throw MessageExceptions.Create(MessageText.Create("Backend.Core.ArchiveVolumeRar4Headers.ReadNext.02"), sourceText => new ArchiveVolumeException(ArchiveVolumeStatus.LimitExceeded, sourceText));
        if (!source.CanRead || !source.CanSeek)
            throw RarIntegrityReflection.Invalid(MessageText.Create("Backend.Core.ArchiveVolumeRar4Headers.ReadNext.03"));
        if (source.Position < 0 || source.Position > source.Length - 24)
            throw MessageExceptions.Create(MessageText.Create("Backend.Core.ArchiveVolumeRar4Headers.ReadNext.04"), sourceText => new ArchiveVolumeException(ArchiveVolumeStatus.MissingVolume, sourceText));

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
                    throw RarIntegrityReflection.Invalid(MessageText.Create("Backend.Core.ArchiveVolumeRar4Headers.ReadNext.05"));
                int aligned = checked((headerLength + 15) & ~15);
                if (aligned > limits.MaximumMetadataBytes)
                    throw MessageExceptions.Create(MessageText.Create("Backend.Core.ArchiveVolumeRar4Headers.ReadNext.06"), sourceText => new ArchiveVolumeException(ArchiveVolumeStatus.LimitExceeded, sourceText));
                if (aligned - 16 > source.Length - source.Position)
                    throw RarIntegrityReflection.Invalid(MessageText.Create("Backend.Core.ArchiveVolumeRar4Headers.ReadNext.07"));
                plaintext = new byte[aligned]; initial.CopyTo(plaintext, 0);
                if (aligned > 16)
                {
                    remainder = new byte[aligned - 16]; source.ReadExactly(remainder);
                    decryptor.TransformBlock(remainder, 0, remainder.Length, plaintext, 16);
                }
                token.ThrowIfCancellationRequested();
                ushort expected = BinaryPrimitives.ReadUInt16LittleEndian(plaintext);
                if ((ushort)ArchiveIntegrity.Crc32(plaintext.AsSpan(2, headerLength - 2)) != expected)
                    throw RarIntegrityReflection.Invalid(MessageText.Create("Backend.Core.ArchiveVolumeRar4Headers.ReadNext.08"));
                // SharpCompress's RAR4 parser stores HEAD_SIZE in a signed Int16.
                // Reject that decoder boundary only after the original header CRC passes.
                if (headerLength > short.MaxValue)
                    throw MessageExceptions.Create(MessageText.Create("Backend.Core.ArchiveVolumeRar4Headers.ReadNext.09"), sourceText => new ArchiveVolumeException(ArchiveVolumeStatus.UnsupportedIntegrity, sourceText));
                long dataStart = source.Position;
                IRarHeader header = ParseOriginalHeader(plaintext, headerLength, options);
                long packed = header.HeaderType switch
                {
                    HeaderType.File or HeaderType.NewSub => RarIntegrityReflection.Property<long>(header, "CompressedSize"),
                    HeaderType.Protect => RarIntegrityReflection.Property<uint>(header, "DataSize"),
                    HeaderType.EndArchive => 0,
                    _ => throw MessageExceptions.Create(MessageText.Create("Backend.Core.ArchiveVolumeRar4Headers.ReadNext.10"), sourceText => new ArchiveVolumeException(ArchiveVolumeStatus.UnsupportedIntegrity, sourceText))
                };
                if (packed < 0 || dataStart > source.Length - packed)
                    throw MessageExceptions.Create(MessageText.Create("Backend.Core.ArchiveVolumeRar4Headers.ReadNext.11"), sourceText => new ArchiveVolumeException(ArchiveVolumeStatus.MissingVolume, sourceText));
                source.Position = checked(dataStart + packed);
                return new(header, dataStart);
            }
            finally { CryptographicOperations.ZeroMemory(initial); }
        }
        catch (EndOfStreamException ex)
        { throw MessageExceptions.Create(MessageText.Create("Backend.Core.ArchiveVolumeRar4Headers.ReadNext.12"), sourceText => new ArchiveVolumeException(ArchiveVolumeStatus.MissingVolume, sourceText, ex)); }
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
                ?? throw RarIntegrityReflection.Invalid(MessageText.Create("Backend.Core.ArchiveVolumeRar4Headers.ParseOriginalHeader.01"));
            byte code = RarIntegrityReflection.Property<byte>(header, "HeaderCode");
            (string TypeName, HeaderType Kind, bool File) shape = code switch
            {
                0x74 => ("FileHeader", HeaderType.File, true),
                0x7a => ("FileHeader", HeaderType.NewSub, true),
                0x7b => ("EndArchiveHeader", HeaderType.EndArchive, false),
                0x78 => ("ProtectHeader", HeaderType.Protect, false),
                _ => throw MessageExceptions.Create(MessageText.Create("Backend.Core.ArchiveVolumeRar4Headers.ParseOriginalHeader.02"), sourceText => new ArchiveVolumeException(ArchiveVolumeStatus.UnsupportedIntegrity, sourceText))
            };
            Type childType = Required("SharpCompress.Common.Rar.Headers." + shape.TypeName);
            Type[] signature = shape.File ? [baseType, crcType, typeof(HeaderType)] : [baseType, crcType];
            MethodInfo create = childType.GetMethod("Create", BindingFlags.Public | BindingFlags.Static,
                binder: null, types: signature, modifiers: null) ?? throw Unsupported();
            if (create.ReturnType != childType) throw Unsupported();
            object?[] arguments = shape.File ? [header, reader, shape.Kind] : [header, reader];
            if (create.Invoke(null, arguments) is not IRarHeader parsed || parsed.HeaderType != shape.Kind || buffer.Position != length)
                throw RarIntegrityReflection.Invalid(MessageText.Create("Backend.Core.ArchiveVolumeRar4Headers.ParseOriginalHeader.03"));
            return parsed;
        }
        catch (TargetInvocationException ex)
        { throw MessageExceptions.Create(MessageText.Create("Backend.Core.ArchiveVolumeRar4Headers.ParseOriginalHeader.04"), sourceText => new ArchiveVolumeException(ArchiveVolumeStatus.InvalidMetadata, sourceText, ex.InnerException ?? ex)); }
    }

    private static ArchiveVolumeException Unsupported() => new(ArchiveVolumeStatus.UnsupportedIntegrity,
        MessageText.Create("Backend.Core.ArchiveVolumeRar4Headers.Unsupported.01"));
}
