using SteamSentinel.Core.Reporting;
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
using System.Numerics;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using SharpCompress.Common;
using SharpCompress.Common.Options;
using SharpCompress.Common.Rar.Headers;
using SharpCompress.Readers;

namespace SteamSentinel.Core.Inspection;

/// <summary>
/// Each logical member has one continuous ciphertext stream and one CBC transform.
/// SharpCompress 0.50.4 resets CBC at volume boundaries and cannot provide this path.
/// Reflection only constructs pinned decoder objects; archive metadata is never changed.
/// </summary>
internal sealed class ArchiveVolumeRarReader : IReader
{
    private readonly ArchiveRarIntegrityIndex _index;
    private readonly ReaderOptions _options;
    private readonly CancellationToken _token;
    private readonly Assembly _assembly = typeof(RarHeaderFactory).Assembly;
    private object? _legacyUnpack, _modernUnpack;
    private RarDecodedContentStream? _currentStream;
    private int _position = -1;
    private bool _opened, _disposed;
    public ArchiveType Type => ArchiveType.Rar;
    public bool Cancelled { get; private set; }
    public IEntry Entry => _position >= 0 && _position < _index.Entries.Count
        ? new RarIndexedEntry(_index.Entries[_position], _options)
        : throw MessageExceptions.Create(MessageText.Create("Backend.Core.ArchiveVolumeRarReader.Entry.01"), sourceText => new InvalidOperationException(sourceText));

    internal ArchiveVolumeRarReader(ArchiveRarIntegrityIndex index, string? password, CancellationToken token)
    {
        RarIntegrityReflection.EnsureVersion();
        _index = index; _token = token;
        _options = new ReaderOptions { Password = password, LeaveStreamOpen = true };
    }

    public void Cancel() => Cancelled = true;

    private void CheckActive()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        _token.ThrowIfCancellationRequested();
        if (Cancelled) throw MessageExceptions.Create(MessageText.Create("Backend.Core.ArchiveVolumeRarReader.CheckActive.01"), sourceText => new OperationCanceledException(sourceText));
    }

    public bool MoveToNextEntry()
    {
        CheckActive();
        if (_position >= 0 && _position < _index.Entries.Count && !_index.Entries[_position].IsDirectory &&
            ((_currentStream is not null && !_currentStream.Completed) || (_index.IsSolid && !_opened)))
            throw new ArchiveVolumeException(ArchiveVolumeStatus.UnsupportedIntegrity,
                MessageText.Create("Backend.Core.ArchiveVolumeRarReader.MoveToNextEntry.01"));
        _currentStream?.Dispose();
        _currentStream = null; _opened = false;
        if (_position >= _index.Entries.Count) return false;
        _position++;
        return _position < _index.Entries.Count;
    }

    public EntryStream OpenEntryStream()
    {
        CheckActive();
        if (_opened) throw MessageExceptions.Create(MessageText.Create("Backend.Core.ArchiveVolumeRarReader.OpenEntryStream.01"), sourceText => new InvalidOperationException(sourceText));
        ArchiveRarEntryChecksum metadata = _index.Match(Entry);
        if (metadata.IsDirectory) throw MessageExceptions.Create(MessageText.Create("Backend.Core.ArchiveVolumeRarReader.OpenEntryStream.02"), sourceText => new InvalidOperationException(sourceText));
        object header = metadata.FirstHeader;
        uint dictionarySize = RarIntegrityReflection.Property<uint>(header, "WindowSize");
        if (dictionarySize > 128u * 1024 * 1024)
            throw new ArchiveVolumeException(ArchiveVolumeStatus.LimitExceeded, MessageText.Create("Backend.Core.ArchiveVolumeRarReader.OpenEntryStream.03"));
        byte algorithm = RarIntegrityReflection.Property<byte>(header, "CompressionAlgorithm");
        bool legacy = algorithm is 15 or 20 or 26 or 29 or 36;
        if (!legacy && algorithm != 50)
            throw new ArchiveVolumeException(ArchiveVolumeStatus.UnsupportedIntegrity, MessageText.Create("Backend.Core.ArchiveVolumeRarReader.OpenEntryStream.04"));
        object unpack = legacy ? (_legacyUnpack ??= CreateUnpack(true)) : (_modernUnpack ??= CreateUnpack(false));
        Stream packed = new RarPackedMemberStream(metadata.PackedParts, CheckActive);
        Stream? decoded = null;
        try
        {
            if (metadata.IsEncrypted) packed = RarContinuousCrypto.Open(packed, metadata, _options.Password, _token);
            if (RarIntegrityReflection.Property<bool>(header, "IsStored"))
                packed = new RarStoredLengthStream(packed, metadata.Size);
            Type decoderType = RequiredType("SharpCompress.Compressors.Rar.RarStream");
            ConstructorInfo? decoderCtor = decoderType.GetConstructor([
                RequiredType("SharpCompress.Compressors.Rar.IRarUnpack"),
                RequiredType("SharpCompress.Common.Rar.Headers.FileHeader"), typeof(Stream)]);
            if (decoderCtor is null)
                throw new ArchiveVolumeException(ArchiveVolumeStatus.UnsupportedIntegrity, MessageText.Create("Backend.Core.ArchiveVolumeRarReader.OpenEntryStream.05"));
            decoded = (Stream)decoderCtor.Invoke([unpack, header, packed]);
            var content = new RarDecodedContentStream(decoded, metadata.ExpectedHash.Length == 32, CheckActive);
            ConstructorInfo? entryCtor = typeof(EntryStream).GetConstructor(
                BindingFlags.Instance | BindingFlags.NonPublic, binder: null,
                types: [typeof(IReader), typeof(Stream)], modifiers: null);
            if (entryCtor is null)
                throw new ArchiveVolumeException(ArchiveVolumeStatus.UnsupportedIntegrity, MessageText.Create("Backend.Core.ArchiveVolumeRarReader.OpenEntryStream.06"));
            EntryStream result = (EntryStream)entryCtor.Invoke([this, content]);
            _currentStream = content; _opened = true;
            return result;
        }
        catch
        {
            decoded?.Dispose();
            packed.Dispose();
            throw;
        }
    }

    private Type RequiredType(string name) => _assembly.GetType(name, throwOnError: false)
        ?? throw new ArchiveVolumeException(ArchiveVolumeStatus.UnsupportedIntegrity, MessageText.Create("Backend.Core.ArchiveVolumeRarReader.RequiredType.01"));

    private object CreateUnpack(bool legacy)
    {
        Type type = RequiredType(legacy ? "SharpCompress.Compressors.Rar.UnpackV1.Unpack" :
            "SharpCompress.Compressors.Rar.UnpackV2017.Unpack");
        ConstructorInfo? ctor = type.GetConstructor(System.Type.EmptyTypes);
        return ctor?.Invoke(null) ?? throw new ArchiveVolumeException(ArchiveVolumeStatus.UnsupportedIntegrity,
            MessageText.Create("Backend.Core.ArchiveVolumeRarReader.CreateUnpack.01"));
    }

    public void WriteEntryTo(Stream writableStream) =>
        throw MessageExceptions.Create(MessageText.Create("Backend.Core.ArchiveVolumeRarReader.WriteEntryTo.01"), sourceText => new NotSupportedException(sourceText));

    public void Dispose()
    {
        if (_disposed) return;
        Cancelled = true; _disposed = true;
        _currentStream?.Dispose();
        if (_legacyUnpack is IDisposable legacy) legacy.Dispose();
        if (_modernUnpack is IDisposable modern) modern.Dispose();
        _options.Password = null;
    }
}

internal sealed class RarIndexedEntry(ArchiveRarEntryChecksum metadata, IReaderOptions options) : IEntry
{
    public CompressionType CompressionType => CompressionType.Rar;
    public string Key => metadata.Key;
    public string? LinkTarget => null;
    public long Size => metadata.Size;
    public long CompressedSize => metadata.PackedParts.Aggregate(0L, (n, p) => checked(n + p.Length));
    public long Crc => metadata.ExpectedHash.Length >= 4 ? BinaryPrimitives.ReadUInt32LittleEndian(metadata.ExpectedHash) : 0;
    public bool IsDirectory => metadata.IsDirectory;
    public bool IsEncrypted => metadata.IsEncrypted;
    public bool IsSplitAfter => false;
    public bool IsSolid => RarIntegrityReflection.Property<bool>(metadata.FirstHeader, "IsSolid");
    public int VolumeIndexFirst => metadata.PackedParts[0].VolumeIndex;
    public int VolumeIndexLast => metadata.PackedParts[^1].VolumeIndex;
    public int? Attrib => unchecked((int)RarIntegrityReflection.Property<uint>(metadata.FirstHeader, "FileAttributes"));
    public DateTime? ArchivedTime => RarIntegrityReflection.Property<DateTime?>(metadata.FirstHeader, "FileArchivedTime");
    public DateTime? CreatedTime => RarIntegrityReflection.Property<DateTime?>(metadata.FirstHeader, "FileCreatedTime");
    public DateTime? LastAccessedTime => RarIntegrityReflection.Property<DateTime?>(metadata.FirstHeader, "FileLastAccessedTime");
    public DateTime? LastModifiedTime => RarIntegrityReflection.Property<DateTime?>(metadata.FirstHeader, "FileLastModifiedTime");
    public IReaderOptions Options => options;
}

internal sealed class RarPackedMemberStream(IReadOnlyList<ArchiveRarPackedPart> parts, Action checkActive) : Stream
{
    private int _part;
    private long _within, _position;
    private bool _disposed;
    public override bool CanRead => !_disposed;
    public override bool CanSeek => false;
    public override bool CanWrite => false;
    public override long Length => parts.Aggregate(0L, (n, p) => checked(n + p.Length));
    public override long Position { get => _position; set => throw new NotSupportedException(); }
    public override int Read(byte[] buffer, int offset, int count) => Read(buffer.AsSpan(offset, count));
    public override int Read(Span<byte> buffer)
    {
        ObjectDisposedException.ThrowIf(_disposed, this); checkActive();
        int total = 0;
        while (!buffer.IsEmpty && _part < parts.Count)
        {
            ArchiveRarPackedPart part = parts[_part];
            if (_within == part.Length) { _part++; _within = 0; continue; }
            int wanted = (int)Math.Min(buffer.Length, part.Length - _within);
            int read;
            lock (part.Source)
            {
                part.Source.Position = checked(part.Offset + _within);
                read = part.Source.Read(buffer[..wanted]);
            }
            if (read == 0) throw RarIntegrityReflection.Invalid(MessageText.Create("Backend.Core.ArchiveVolumeRarReader.Read.01"));
            _within += read; _position += read; total += read; buffer = buffer[read..];
            checkActive();
        }
        return total;
    }
    public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
    { cancellationToken.ThrowIfCancellationRequested(); return ValueTask.FromResult(Read(buffer.Span)); }
    public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
    { cancellationToken.ThrowIfCancellationRequested(); return Task.FromResult(Read(buffer, offset, count)); }
    protected override void Dispose(bool disposing) { _disposed = true; base.Dispose(disposing); }
    public override void Flush() { }
    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
    public override void SetLength(long value) => throw new NotSupportedException();
    public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
}

internal static class RarContinuousCrypto
{
    internal static Stream Open(Stream ciphertext, ArchiveRarEntryChecksum metadata, string? password,
        CancellationToken token = default)
    {
        token.ThrowIfCancellationRequested();
        if (password is null) throw MessageExceptions.Create(MessageText.Create("Backend.Core.ArchiveVolumeRarReader.Open.01"), sourceText => new SharpCompress.Common.CryptographicException(sourceText));
        if (password.Length > 256)
            throw new ArchiveVolumeException(ArchiveVolumeStatus.LimitExceeded, MessageText.Create("Backend.Core.ArchiveVolumeRarReader.Open.02"));
        if (ciphertext.Length % 16 != 0)
            throw RarIntegrityReflection.Invalid(MessageText.Create("Backend.Core.ArchiveVolumeRarReader.Open.03"));
        byte[] key, iv;
        if (metadata.Rar5)
        {
            object crypto = RarIntegrityReflection.PropertyObject(metadata.FirstHeader, "Rar5CryptoInfo",
                "SharpCompress.Common.Rar.Rar5CryptoInfo");
            iv = RarIntegrityReflection.Field<byte[]>(crypto, "InitV").ToArray();
            byte[] passwordBytes = Encoding.UTF8.GetBytes(password);
            try
            {
                if (RarIntegrityReflection.Field<bool>(crypto, "UsePswCheck"))
                {
                    byte[] storedCheck = RarIntegrityReflection.Field<byte[]>(crypto, "PswCheck");
                    byte[] checkHash = Rfc2898DeriveBytes.Pbkdf2(passwordBytes, metadata.Salt,
                        checked((1 << metadata.KdfLog2) + 32), HashAlgorithmName.SHA256, 32);
                    Span<byte> check = stackalloc byte[8];
                    check.Clear();
                    for (int i = 0; i < checkHash.Length; i++) check[i & 7] ^= checkHash[i];
                    bool matches = storedCheck.Length == 8 && CryptographicOperations.FixedTimeEquals(check, storedCheck);
                    CryptographicOperations.ZeroMemory(checkHash); CryptographicOperations.ZeroMemory(check);
                    if (!matches) throw MessageExceptions.Create(MessageText.Create("Backend.Core.ArchiveVolumeRarReader.Open.04"), sourceText => new SharpCompress.Common.CryptographicException(sourceText));
                }
                key = Rfc2898DeriveBytes.Pbkdf2(passwordBytes, metadata.Salt, 1 << metadata.KdfLog2, HashAlgorithmName.SHA256, 32);
            }
            finally { CryptographicOperations.ZeroMemory(passwordBytes); }
        }
        else
        {
            byte[] salt = RarIntegrityReflection.NullableBytes(metadata.FirstHeader, "R4Salt") ?? [];
            if (salt.Length != 8) throw RarIntegrityReflection.Invalid(MessageText.Create("Backend.Core.ArchiveVolumeRarReader.Open.05"));
            (key, iv) = DeriveRar4(password, salt, token);
        }
        try
        {
            token.ThrowIfCancellationRequested();
            if (iv.Length != 16) throw RarIntegrityReflection.Invalid(MessageText.Create("Backend.Core.ArchiveVolumeRarReader.Open.06"));
            using Aes aes = Aes.Create();
            aes.Mode = CipherMode.CBC; aes.Padding = PaddingMode.None;
            aes.Key = key; aes.IV = iv;
            return new CryptoStream(ciphertext, aes.CreateDecryptor(), CryptoStreamMode.Read);
        }
        finally { CryptographicOperations.ZeroMemory(key); CryptographicOperations.ZeroMemory(iv); }
    }

    internal static (byte[] Key, byte[] IV) DeriveRar4(string password, byte[] salt,
        CancellationToken token = default)
    {
        // RAR3/4 uses UTF-16LE, SHA-1 snapshots and 2^18 rounds. The historical
        // sha1_process_rar29 password-buffer mutation also matters for long passwords.
        // Incremental hashing avoids a password-dependent giant buffer.
        byte[] passwordBytes = Encoding.Unicode.GetBytes(password);
        byte[] block = new byte[checked(passwordBytes.Length + 8 + 3)];
        byte[] iv = new byte[16], key = new byte[16];
        passwordBytes.CopyTo(block, 0); salt.CopyTo(block, passwordBytes.Length);
        try
        {
            using IncrementalHash sha = IncrementalHash.CreateHash(HashAlgorithmName.SHA1);
            for (int round = 0; round < 1 << 18; round++)
            {
                if ((round & 0x3fff) == 0) token.ThrowIfCancellationRequested();
                block[^3] = (byte)round; block[^2] = (byte)(round >> 8); block[^1] = (byte)(round >> 16);
                sha.AppendData(block);
                MutateRar4PasswordBlocks(block.AsSpan(0, block.Length - 3),
                    (int)(((long)round * block.Length) & 63));
                if ((round & 0x3fff) == 0)
                {
                    byte[] snapshot = sha.GetCurrentHash();
                    iv[round >> 14] = snapshot[19];
                    CryptographicOperations.ZeroMemory(snapshot);
                }
            }
            byte[] digest = sha.GetHashAndReset();
            for (int word = 0; word < 4; word++)
                for (int b = 0; b < 4; b++) key[word * 4 + b] = digest[word * 4 + 3 - b];
            CryptographicOperations.ZeroMemory(digest);
            return (key, iv);
        }
        catch { CryptographicOperations.ZeroMemory(key); CryptographicOperations.ZeroMemory(iv); throw; }
        finally { CryptographicOperations.ZeroMemory(passwordBytes); CryptographicOperations.ZeroMemory(block); }
    }

    private static void MutateRar4PasswordBlocks(Span<byte> passwordAndSalt, int shaBufferedBytes)
    {
        // UnRAR hashes the first partial block through its private buffer, then
        // writes the final SHA-1 message schedule back into each full source block.
        Span<uint> words = stackalloc uint[16];
        for (int offset = 64 - shaBufferedBytes; offset <= passwordAndSalt.Length - 64; offset += 64)
        {
            Span<byte> block = passwordAndSalt.Slice(offset, 64);
            for (int i = 0; i < 16; i++) words[i] = BinaryPrimitives.ReadUInt32BigEndian(block.Slice(i * 4, 4));
            for (int i = 16; i < 80; i++)
                words[i & 15] = BitOperations.RotateLeft(words[(i + 13) & 15] ^ words[(i + 8) & 15] ^
                    words[(i + 2) & 15] ^ words[i & 15], 1);
            for (int i = 0; i < 16; i++) BinaryPrimitives.WriteUInt32LittleEndian(block.Slice(i * 4, 4), words[i]);
        }
        words.Clear();
    }
}

internal sealed class RarStoredLengthStream(Stream source, long length) : Stream
{
    private long _position;
    public override bool CanRead => true;
    public override bool CanSeek => false;
    public override bool CanWrite => false;
    public override long Length => length;
    public override long Position { get => _position; set => throw new NotSupportedException(); }
    public override int Read(byte[] buffer, int offset, int count) => Read(buffer.AsSpan(offset, count));
    public override int Read(Span<byte> buffer)
    {
        if (buffer.IsEmpty || _position == length) return 0;
        int read = source.Read(buffer[..(int)Math.Min(buffer.Length, length - _position)]);
        if (read == 0) throw RarIntegrityReflection.Invalid(MessageText.Create("Backend.Core.ArchiveVolumeRarReader.Read.02"));
        _position += read; return read;
    }
    public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
    {
        if (buffer.IsEmpty || _position == length) return 0;
        int read = await source.ReadAsync(buffer[..(int)Math.Min(buffer.Length, length - _position)], cancellationToken).ConfigureAwait(false);
        if (read == 0) throw RarIntegrityReflection.Invalid(MessageText.Create("Backend.Core.ArchiveVolumeRarReader.ReadAsync.01"));
        _position += read; return read;
    }
    public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken) =>
        ReadAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();
    protected override void Dispose(bool disposing) { if (disposing) source.Dispose(); base.Dispose(disposing); }
    public override void Flush() { }
    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
    public override void SetLength(long value) => throw new NotSupportedException();
    public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
}

internal sealed class RarDecodedContentStream(Stream source, bool useBlake, Action checkActive) : Stream
{
    private readonly RarBlake2sp? _blake = useBlake ? new RarBlake2sp() : null;
    private byte[]? _digest;
    private bool _disposed;
    internal bool Completed { get; private set; }
    internal byte[] GetCompletedBlake()
    {
        if (!Completed || _digest is null) throw RarIntegrityReflection.Invalid(MessageText.Create("Backend.Core.ArchiveVolumeRarReader.GetCompletedBlake.01"));
        return _digest.ToArray();
    }
    private int Observe(ReadOnlySpan<byte> bytes, int requested)
    {
        if (!bytes.IsEmpty) _blake?.Update(bytes);
        else if (requested > 0 && !Completed)
        { Completed = true; _digest = _blake?.Finish(); }
        return bytes.Length;
    }
    public override bool CanRead => !_disposed;
    public override bool CanSeek => false;
    public override bool CanWrite => false;
    public override long Length => source.Length;
    public override long Position { get => source.Position; set => throw new NotSupportedException(); }
    public override int Read(byte[] buffer, int offset, int count)
    { checkActive(); int read = source.Read(buffer, offset, count); return Observe(buffer.AsSpan(offset, read), count); }
    public override int Read(Span<byte> buffer)
    { checkActive(); int read = source.Read(buffer); return Observe(buffer[..read], buffer.Length); }
    public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return Task.FromResult(Read(buffer, offset, count));
    }
    public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return ValueTask.FromResult(Read(buffer.Span));
    }
    protected override void Dispose(bool disposing)
    { if (!_disposed) { _disposed = true; if (disposing) source.Dispose(); } base.Dispose(disposing); }
    public override void Flush() { }
    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
    public override void SetLength(long value) => throw new NotSupportedException();
    public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
}

/// <summary>Unkeyed BLAKE2sp-256: eight BLAKE2s leaves, 64-byte stripes and a depth-one root.</summary>
// Managed, unkeyed specialization of Samuel Neves' BLAKE2 C reference (2012),
// used under its CC0 1.0 option. Source: BLAKE2 commit
// ed1974ea83433eba7b2d95c5dcd9ac33cb847913, ref/blake2sp-ref.c and ref/blake2s-ref.c.
// The complete CC0 text is included with the distribution's third-party notices.
internal sealed class RarBlake2sp
{
    private readonly Blake2sNode[] _leaves = Enumerable.Range(0, 8).Select(i => new Blake2sNode((uint)i, false, i == 7)).ToArray();
    private int _stripe;
    private bool _finished;
    internal void Update(ReadOnlySpan<byte> bytes)
    {
        if (_finished) throw MessageExceptions.Create(MessageText.Create("Backend.Core.ArchiveVolumeRarReader.Update.01"), sourceText => new InvalidOperationException(sourceText));
        while (!bytes.IsEmpty)
        {
            int count = Math.Min(bytes.Length, 64 - (_stripe & 63));
            _leaves[_stripe / 64].Update(bytes[..count]);
            bytes = bytes[count..]; _stripe = (_stripe + count) & 511;
        }
    }
    internal byte[] Finish()
    {
        if (_finished) throw MessageExceptions.Create(MessageText.Create("Backend.Core.ArchiveVolumeRarReader.Finish.01"), sourceText => new InvalidOperationException(sourceText));
        _finished = true;
        var root = new Blake2sNode(0, true, true);
        foreach (Blake2sNode leaf in _leaves)
        {
            byte[] digest = leaf.Finish(); root.Update(digest); CryptographicOperations.ZeroMemory(digest);
        }
        return root.Finish();
    }

    private sealed class Blake2sNode
    {
        private static readonly uint[] Iv = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19];
        private static readonly byte[,] Sigma = {
            {0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15}, {14,10,4,8,9,15,13,6,1,12,0,2,11,7,5,3},
            {11,8,12,0,5,2,15,13,10,14,3,6,7,1,9,4}, {7,9,3,1,13,12,11,14,2,6,5,10,4,0,15,8},
            {9,0,5,7,2,4,10,15,14,1,11,12,6,8,3,13}, {2,12,6,10,0,11,8,3,4,13,7,5,15,14,1,9},
            {12,5,1,15,14,13,4,10,0,7,6,3,9,2,8,11}, {13,11,7,14,12,1,3,9,5,0,15,4,8,6,2,10},
            {6,15,14,9,11,3,0,8,12,2,13,7,1,4,10,5}, {10,2,8,4,7,6,1,5,15,11,9,14,3,12,13,0} };
        private readonly uint[] _h = Iv.ToArray();
        private readonly byte[] _buffer = new byte[64];
        private readonly bool _last;
        private int _used;
        private ulong _count;
        internal Blake2sNode(uint offset, bool root, bool last)
        {
            _h[0] ^= 0x02080020; _h[2] ^= offset;
            _h[3] ^= root ? 0x20010000u : 0x20000000u; _last = last;
        }
        internal void Update(ReadOnlySpan<byte> bytes)
        {
            while (!bytes.IsEmpty)
            {
                if (_used == 64) { _count += 64; Compress(false); _used = 0; }
                int take = Math.Min(64 - _used, bytes.Length);
                bytes[..take].CopyTo(_buffer.AsSpan(_used)); _used += take; bytes = bytes[take..];
            }
        }
        internal byte[] Finish()
        {
            _count += (uint)_used; _buffer.AsSpan(_used).Clear(); Compress(true);
            byte[] result = new byte[32];
            for (int i = 0; i < 8; i++) BinaryPrimitives.WriteUInt32LittleEndian(result.AsSpan(i * 4, 4), _h[i]);
            CryptographicOperations.ZeroMemory(_buffer); Array.Clear(_h);
            return result;
        }
        private void Compress(bool final)
        {
            Span<uint> message = stackalloc uint[16], state = stackalloc uint[16];
            for (int i = 0; i < 16; i++) message[i] = BinaryPrimitives.ReadUInt32LittleEndian(_buffer.AsSpan(i * 4, 4));
            _h.AsSpan().CopyTo(state); Iv.AsSpan().CopyTo(state[8..]);
            state[12] ^= (uint)_count; state[13] ^= (uint)(_count >> 32);
            if (final) { state[14] ^= uint.MaxValue; if (_last) state[15] ^= uint.MaxValue; }
            for (int r = 0; r < 10; r++)
            {
                Mix(state, 0, 4, 8, 12, message[Sigma[r, 0]], message[Sigma[r, 1]]);
                Mix(state, 1, 5, 9, 13, message[Sigma[r, 2]], message[Sigma[r, 3]]);
                Mix(state, 2, 6, 10, 14, message[Sigma[r, 4]], message[Sigma[r, 5]]);
                Mix(state, 3, 7, 11, 15, message[Sigma[r, 6]], message[Sigma[r, 7]]);
                Mix(state, 0, 5, 10, 15, message[Sigma[r, 8]], message[Sigma[r, 9]]);
                Mix(state, 1, 6, 11, 12, message[Sigma[r, 10]], message[Sigma[r, 11]]);
                Mix(state, 2, 7, 8, 13, message[Sigma[r, 12]], message[Sigma[r, 13]]);
                Mix(state, 3, 4, 9, 14, message[Sigma[r, 14]], message[Sigma[r, 15]]);
            }
            for (int i = 0; i < 8; i++) _h[i] ^= state[i] ^ state[i + 8];
        }
        private static void Mix(Span<uint> v, int a, int b, int c, int d, uint x, uint y)
        {
            unchecked
            {
                v[a] += v[b] + x; v[d] = BitOperations.RotateRight(v[d] ^ v[a], 16);
                v[c] += v[d]; v[b] = BitOperations.RotateRight(v[b] ^ v[c], 12);
                v[a] += v[b] + y; v[d] = BitOperations.RotateRight(v[d] ^ v[a], 8);
                v[c] += v[d]; v[b] = BitOperations.RotateRight(v[b] ^ v[c], 7);
            }
        }
    }
}
