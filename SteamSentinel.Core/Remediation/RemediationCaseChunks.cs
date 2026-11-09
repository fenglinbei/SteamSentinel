using System.Security.Cryptography;
using System.Text.Json;
using SteamSentinel.Core.Models;
using SteamSentinel.Core.Reporting;
using SteamSentinel.Core.Scanning;
using SteamSentinel.Core.Utilities;

namespace SteamSentinel.Core.Remediation;

/// <summary>
/// Immutable, bounded pieces of the ordinary case JSON. The small manifest is the only commit
/// point; a failed write cannot replace the previous revision. Hashes detect damaged pieces,
/// not authorization: the hydrated case remains an untrusted, user-owned record.
/// </summary>
internal static class RemediationCaseChunks
{
    internal const string Format = "SteamSentinel.CaseChunks/1";
    internal const int ChunkBytes = 8 * 1024 * 1024;
    internal const int MaximumChunks = 256;
    internal const long MaximumBytes = (long)ChunkBytes * MaximumChunks;
    internal const int MaximumManifestBytes = 128 * 1024;

    internal sealed class Manifest
    {
        public string StorageFormat { get; init; } = Format;
        public Guid CaseId { get; init; }
        public long Revision { get; init; }
        public long TotalBytes { get; init; }
        public List<Part> Parts { get; init; } = [];
    }

    internal sealed record Part(int Index, int Bytes, string Sha256);

    internal static Manifest ParseManifest(JsonElement root)
    {
        RequireProperties(root, ["StorageFormat", "CaseId", "Revision", "TotalBytes", "Parts"]);
        JsonElement parts = root.GetProperty("Parts");
        if (parts.ValueKind != JsonValueKind.Array || parts.GetArrayLength() is < 1 or > MaximumChunks) throw Invalid();
        foreach (JsonElement part in parts.EnumerateArray()) RequireProperties(part, ["Index", "Bytes", "Sha256"]);
        Manifest manifest = root.Deserialize<Manifest>(JsonFile.Options) ?? throw Invalid();
        Validate(manifest);
        return manifest;
    }

    private static void RequireProperties(JsonElement value, string[] expected)
    {
        if (value.ValueKind != JsonValueKind.Object) throw Invalid();
        HashSet<string> seen = new(StringComparer.Ordinal);
        foreach (JsonProperty property in value.EnumerateObject())
            if (!expected.Contains(property.Name, StringComparer.Ordinal) || !seen.Add(property.Name)) throw Invalid();
        if (seen.Count != expected.Length) throw Invalid();
    }

    internal static string PartPath(string directory, Part part) =>
        Path.Combine(directory, "case-part-" + part.Sha256 + ".jsonpart");

    // Caller holds the exclusive case lock and directory leases; all public readers share that
    // lock until hydration finishes. Never collect before the new manifest is durable.
    internal static void Prune(string directory, Manifest current, Action<string> checkPath, CancellationToken token)
    {
        HashSet<string> retained = current.Parts.Select(part => Path.GetFileName(PartPath(directory, part)))
            .ToHashSet(StringComparer.Ordinal);
        try
        {
            checkPath(directory);
            foreach (string path in Directory.EnumerateFiles(directory, "case-part-*.jsonpart", SearchOption.TopDirectoryOnly).Take(4096))
            {
                if (token.IsCancellationRequested) return;
                string name = Path.GetFileName(path);
                if (retained.Contains(name) || name.Length != 10 + 64 + 9 ||
                    !name.StartsWith("case-part-", StringComparison.Ordinal) || !name.EndsWith(".jsonpart", StringComparison.Ordinal) ||
                    name.AsSpan(10, 64).ContainsAnyExcept("0123456789ABCDEF")) continue;
                try
                {
                    checkPath(path);
                    if ((File.GetAttributes(path) & (FileAttributes.ReparsePoint | FileAttributes.Directory)) != 0) continue;
                    File.Delete(path);
                }
                catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or System.ComponentModel.Win32Exception) { }
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or System.ComponentModel.Win32Exception) { }
    }

    internal static void Validate(Manifest manifest)
    {
        if (manifest.StorageFormat != Format || manifest.CaseId == Guid.Empty || manifest.Revision <= 0 ||
            manifest.TotalBytes is <= 0 or > MaximumBytes || manifest.Parts is null ||
            manifest.Parts.Count is < 1 or > MaximumChunks) throw Invalid();
        long bytes = 0;
        for (int i = 0; i < manifest.Parts.Count; i++)
        {
            Part part = manifest.Parts[i];
            if (part is null || part.Index != i || part.Bytes is < 1 or > ChunkBytes ||
                i < manifest.Parts.Count - 1 && part.Bytes != ChunkBytes ||
                part.Sha256 is null || part.Sha256.Length != 64 ||
                part.Sha256.Any(c => c is not (>= '0' and <= '9') and not (>= 'A' and <= 'F')))
                throw Invalid();
            bytes = checked(bytes + part.Bytes);
        }
        if (bytes != manifest.TotalBytes) throw Invalid();
    }

    internal static async Task<Manifest> WriteAsync(string directory, RemediationCaseRecord record,
        Action<string> checkPath, CancellationToken token, ICollection<string>? createdFiles = null)
    {
        await using ChunkWriter writer = new(directory, checkPath, createdFiles);
        await JsonSerializer.SerializeAsync(writer, record, JsonFile.Options, token).ConfigureAwait(false);
        await writer.CompleteAsync(token).ConfigureAwait(false);
        return new() { CaseId = record.CaseId, Revision = record.Revision, TotalBytes = writer.Written, Parts = writer.Parts };
    }

    internal static async Task<RemediationCaseRecord> ReadAsync(string directory, Manifest manifest,
        Action<string> checkPath, CancellationToken token, JsonSerializerOptions? options = null)
    {
        Validate(manifest);
        await using ChunkReader reader = new(directory, manifest, checkPath);
        RemediationCaseRecord record = await JsonSerializer.DeserializeAsync<RemediationCaseRecord>(reader, options ?? JsonFile.Options, token)
            .ConfigureAwait(false) ?? throw Invalid();
        // DeserializeAsync consumes the complete stream and rejects non-whitespace after the value.
        if (reader.Position != manifest.TotalBytes || record.CaseId != manifest.CaseId || record.Revision != manifest.Revision)
            throw Invalid();
        return record;
    }

    internal static InvalidDataException Invalid() => MessageExceptions.Create(
        MessageText.Create("Backend.Core.RemediationCaseChunks.Invalid.01"), text => new InvalidDataException(text));

    private static async Task ReadPartAsync(string directory, Part part, Memory<byte> bytes,
        Action<string> checkPath, CancellationToken token)
    {
        string path = PartPath(directory, part);
        checkPath(path);
        await using FileStream stream = RelatedArtifactReader.Open(path);
        if (stream.Length != part.Bytes) throw Invalid();
        await stream.ReadExactlyAsync(bytes[..part.Bytes], token).ConfigureAwait(false);
        if (!Convert.ToHexString(SHA256.HashData(bytes.Span[..part.Bytes])).Equals(part.Sha256, StringComparison.Ordinal))
            throw Invalid();
        checkPath(path);
    }

    private sealed class ChunkWriter(string directory, Action<string> checkPath, ICollection<string>? createdFiles) : Stream
    {
        private readonly byte[] _buffer = new byte[ChunkBytes];
        private int _buffered;
        internal long Written { get; private set; }
        internal List<Part> Parts { get; } = [];
        public override bool CanRead => false;
        public override bool CanSeek => false;
        public override bool CanWrite => true;
        public override long Length => Written;
        public override long Position { get => Written; set => throw new NotSupportedException(); }

        public override async ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken token = default)
        {
            if (buffer.Length > MaximumBytes - Written)
                throw MessageExceptions.Create(MessageText.Create("Backend.Core.RemediationCaseChunks.Capacity.01"),
                    text => new InvalidDataException(text));
            while (!buffer.IsEmpty)
            {
                token.ThrowIfCancellationRequested();
                int count = Math.Min(buffer.Length, ChunkBytes - _buffered);
                buffer[..count].CopyTo(_buffer.AsMemory(_buffered));
                _buffered += count; Written += count; buffer = buffer[count..];
                if (_buffered == ChunkBytes) await FlushPartAsync(token).ConfigureAwait(false);
            }
        }
        public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken token) =>
            WriteAsync(buffer.AsMemory(offset, count), token).AsTask();
        public override void Write(byte[] buffer, int offset, int count) =>
            WriteAsync(buffer.AsMemory(offset, count)).AsTask().GetAwaiter().GetResult();
        internal Task CompleteAsync(CancellationToken token) => FlushPartAsync(token);

        private async Task FlushPartAsync(CancellationToken token)
        {
            if (_buffered == 0) return;
            if (Parts.Count >= MaximumChunks) throw Invalid();
            Part part = new(Parts.Count, _buffered, Convert.ToHexString(SHA256.HashData(_buffer.AsSpan(0, _buffered))));
            string path = PartPath(directory, part);
            checkPath(path);
            if (File.Exists(path))
            {
                // Do not trust an existing content-addressed name. Reuse only verified bytes.
                byte[] existing = new byte[part.Bytes];
                await ReadPartAsync(directory, part, existing, checkPath, token).ConfigureAwait(false);
            }
            else
            {
                await AtomicFile.WriteAsync(path, async stream =>
                {
                    RelatedArtifactReader.ValidatePath(stream.SafeFileHandle, Path.GetFullPath(stream.Name));
                    await stream.WriteAsync(_buffer.AsMemory(0, _buffered), token).ConfigureAwait(false);
                    checkPath(path);
                }, token).ConfigureAwait(false);
                createdFiles?.Add(path);
            }
            Parts.Add(part); _buffered = 0;
        }

        public override void Flush() { }
        public override Task FlushAsync(CancellationToken token) => Task.CompletedTask;
        public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
    }

    private sealed class ChunkReader(string directory, Manifest manifest, Action<string> checkPath) : Stream
    {
        private readonly byte[] _buffer = new byte[ChunkBytes];
        private int _part, _offset, _available;
        private long _position;
        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => manifest.TotalBytes;
        public override long Position { get => _position; set => throw new NotSupportedException(); }

        public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken token = default)
        {
            if (buffer.IsEmpty) return 0;
            token.ThrowIfCancellationRequested();
            if (_offset == _available)
            {
                if (_part == manifest.Parts.Count) return 0;
                Part part = manifest.Parts[_part++];
                await ReadPartAsync(directory, part, _buffer, checkPath, token).ConfigureAwait(false);
                _offset = 0; _available = part.Bytes;
            }
            int count = Math.Min(buffer.Length, _available - _offset);
            _buffer.AsMemory(_offset, count).CopyTo(buffer);
            _offset += count; _position += count;
            return count;
        }
        public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken token) =>
            ReadAsync(buffer.AsMemory(offset, count), token).AsTask();
        public override int Read(byte[] buffer, int offset, int count) =>
            ReadAsync(buffer.AsMemory(offset, count)).AsTask().GetAwaiter().GetResult();
        public override void Flush() { }
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
    }
}
