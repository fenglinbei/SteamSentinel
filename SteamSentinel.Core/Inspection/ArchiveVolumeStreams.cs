namespace SteamSentinel.Core.Inspection;

/// <summary>A non-owning seekable read view. Neither seeking nor decoding can escape its verified range.</summary>
internal sealed class ArchiveVolumeSliceStream(Stream source, long offset, long length) : Stream
{
    private long _position;
    public override bool CanRead => true;
    public override bool CanSeek => true;
    public override bool CanWrite => false;
    public override long Length => length;
    public override long Position { get => _position; set => Seek(value, SeekOrigin.Begin); }
    public override int Read(byte[] buffer, int start, int count) => Read(buffer.AsSpan(start, count));
    public override int Read(Span<byte> buffer)
    {
        int count = (int)Math.Min(buffer.Length, length - _position);
        if (count == 0) return 0;
        source.Position = checked(offset + _position);
        int read = source.Read(buffer[..count]); _position += read; return read;
    }
    public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
    {
        int count = (int)Math.Min(buffer.Length, length - _position);
        if (count == 0) return 0;
        source.Position = checked(offset + _position);
        int read = await source.ReadAsync(buffer[..count], cancellationToken).ConfigureAwait(false);
        _position += read; return read;
    }
    public override Task<int> ReadAsync(byte[] buffer, int start, int count, CancellationToken cancellationToken) =>
        ReadAsync(buffer.AsMemory(start, count), cancellationToken).AsTask();
    public override long Seek(long value, SeekOrigin origin)
    {
        long next = checked((origin switch
        {
            SeekOrigin.Begin => 0,
            SeekOrigin.Current => _position,
            SeekOrigin.End => length,
            _ => throw new ArgumentOutOfRangeException(nameof(origin))
        }) + value);
        if (next < 0 || next > length) throw new IOException("分卷读取尝试越过受限范围。");
        return _position = next;
    }
    public override void Flush() { }
    public override void SetLength(long value) => throw new NotSupportedException();
    public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
}

internal sealed class ArchiveVolumeJoinedStream : Stream
{
    private readonly IReadOnlyList<Stream> _parts;
    private readonly long[] _starts;
    private readonly long _length;
    private long _position;
    public ArchiveVolumeJoinedStream(IReadOnlyList<Stream> parts)
    {
        _parts = parts; _starts = new long[parts.Count];
        for (int i = 0; i < parts.Count; i++) { _starts[i] = _length; _length = checked(_length + parts[i].Length); }
    }
    public long DiskOffset(int disk, long offset)
    {
        if (disk < 0 || disk >= _parts.Count || offset < 0 || offset > _parts[disk].Length)
            throw new ArchiveVolumeException(ArchiveVolumeStatus.MissingVolume, "ZIP 分卷编号或卷内偏移无效。");
        return checked(_starts[disk] + offset);
    }
    public override bool CanRead => true;
    public override bool CanSeek => true;
    public override bool CanWrite => false;
    public override long Length => _length;
    public override long Position { get => _position; set => Seek(value, SeekOrigin.Begin); }
    public override int Read(byte[] buffer, int offset, int count) => Read(buffer.AsSpan(offset, count));
    public override int Read(Span<byte> buffer)
    {
        int total = 0;
        while (!buffer.IsEmpty && _position < _length)
        {
            int index = Array.BinarySearch(_starts, _position);
            if (index < 0) index = ~index - 1;
            Stream part = _parts[index]; part.Position = _position - _starts[index];
            int count = (int)Math.Min(buffer.Length, part.Length - part.Position);
            if (count == 0) throw new EndOfStreamException("归档存在空分卷或不连续范围。");
            int read = part.Read(buffer[..count]);
            if (read == 0) throw new EndOfStreamException("归档分卷在声明长度前结束。");
            _position += read; total += read; buffer = buffer[read..];
        }
        return total;
    }
    public override long Seek(long value, SeekOrigin origin)
    {
        long next = checked((origin switch
        {
            SeekOrigin.Begin => 0,
            SeekOrigin.Current => _position,
            SeekOrigin.End => _length,
            _ => throw new ArgumentOutOfRangeException(nameof(origin))
        }) + value);
        if (next < 0 || next > _length) throw new IOException("归档读取越过受限卷组。");
        return _position = next;
    }
    public override void Flush() { }
    public override void SetLength(long value) => throw new NotSupportedException();
    public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
}
