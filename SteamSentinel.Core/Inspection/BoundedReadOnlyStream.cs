using SteamSentinel.Core.Reporting;
using SteamSentinel.Core.Scanning;

namespace SteamSentinel.Core.Inspection;

/// <summary>A seekable read-only view. Position and offsets are relative to this range.</summary>
public sealed class BoundedReadOnlyStream : Stream
{
    private readonly Stream _source;
    private readonly long _offset, _length;
    private readonly bool _leaveOpen;
    private readonly ContainerResourceBudget? _budget;
    private long _position;
    private bool _disposed;
    public BoundedReadOnlyStream(Stream source, long offset, long length, bool leaveOpen = true, ContainerResourceBudget? budget = null)
    {
        if (!source.CanRead || !source.CanSeek || offset < 0 || length < 0 || offset > source.Length || length > source.Length - offset)
            throw MessageExceptions.Create(MessageText.Create("Backend.Core.BoundedReadOnlyStream.Constructor.01"), sourceText => new ArgumentOutOfRangeException(nameof(length), sourceText));
        _source = source; _offset = offset; _length = length; _leaveOpen = leaveOpen; _budget = budget;
    }
    public override bool CanRead => !_disposed;
    public override bool CanSeek => !_disposed;
    public override bool CanWrite => false;
    public override long Length => _length;
    public override long Position { get => _position; set => Seek(value, SeekOrigin.Begin); }
    public override long Seek(long offset, SeekOrigin origin)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        long target = origin switch
        {
            SeekOrigin.Begin => offset,
            SeekOrigin.Current => checked(_position + offset),
            SeekOrigin.End => checked(_length + offset),
            _ => throw new ArgumentOutOfRangeException(nameof(origin))
        };
        if (target < 0 || target > _length) throw MessageExceptions.Create(MessageText.Create("Backend.Core.BoundedReadOnlyStream.Seek.01"), sourceText => new IOException(sourceText));
        return _position = target;
    }
    public override int Read(byte[] buffer, int offset, int count) => Read(buffer.AsSpan(offset, count));
    public override int Read(Span<byte> buffer)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        int count = (int)Math.Min(buffer.Length, _length - _position);
        if (count == 0) return 0;
        count = _budget?.ReadAllowance(count) ?? count;
        _source.Position = checked(_offset + _position);
        int read = _source.Read(buffer[..count]);
        _position = checked(_position + read); _budget?.ChargeRead(read); return read;
    }
    public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(_disposed, this); cancellationToken.ThrowIfCancellationRequested();
        int count = (int)Math.Min(buffer.Length, _length - _position);
        if (count == 0) return 0;
        count = _budget?.ReadAllowance(count) ?? count;
        _source.Position = checked(_offset + _position);
        int read = await _source.ReadAsync(buffer[..count], cancellationToken).ConfigureAwait(false);
        _position = checked(_position + read); _budget?.ChargeRead(read); return read;
    }
    public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken) =>
        ReadAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();
    public override void Flush() { }
    public override void SetLength(long value) => throw new NotSupportedException();
    public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    protected override void Dispose(bool disposing)
    {
        if (!_disposed && disposing && !_leaveOpen) _source.Dispose();
        _disposed = true; base.Dispose(disposing);
    }
}
