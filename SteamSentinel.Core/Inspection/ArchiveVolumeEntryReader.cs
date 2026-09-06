using System.Reflection;
using SharpCompress.Archives;
using SharpCompress.Common;
using SharpCompress.Readers;

namespace SteamSentinel.Core.Inspection;

/// <summary>Uses ZIP's seekable central-directory API while exposing the same ordered scanner contract.</summary>
internal sealed class ArchiveVolumeEntryReader : IReader
{
    private readonly IEnumerator<IArchiveEntry> _entries;
    private IArchiveEntry? _current;
    private EntryStream? _entryStream;
    private CompletionStream? _completion;
    private bool _opened;
    private bool _disposed;
    public ArchiveType Type { get; }
    public IEntry Entry => _current ?? throw new InvalidOperationException("尚未选择归档成员。");
    public bool Cancelled { get; private set; }
    internal bool CanSkipCurrentUnopenedEntry => !_disposed && !Cancelled && !_opened &&
        _current is { IsDirectory: false } && Type == ArchiveType.Zip;

    internal ArchiveVolumeEntryReader(IArchive archive)
    { Type = archive.Type; _entries = archive.Entries.GetEnumerator(); }

    public bool MoveToNextEntry()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (Cancelled) return false;
        if (_opened && _completion is { Completed: false })
        {
            Cancel(); throw new InvalidOperationException("上一成员未读完，不能推进归档遍历。");
        }
        _entryStream?.Dispose(); _entryStream = null; _completion = null; _opened = false;
        bool moved = _entries.MoveNext(); _current = moved ? _entries.Current : null; return moved;
    }

    public EntryStream OpenEntryStream()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (Cancelled || _current is null || _opened) throw new InvalidOperationException("归档成员不能重复打开或在取消后读取。");
        Assembly assembly = typeof(EntryStream).Assembly;
        ConstructorInfo? constructor = typeof(EntryStream).GetConstructor(BindingFlags.Instance | BindingFlags.NonPublic,
            binder: null, types: [typeof(IReader), typeof(Stream)], modifiers: null);
        if (assembly.GetName().Version != new Version(0, 50, 4, 0) || constructor is null)
            throw new ArchiveVolumeException(ArchiveVolumeStatus.UnsupportedLayout, "归档读取接口与锁定依赖版本不一致。");
        _opened = true;
        _completion = new CompletionStream(_current.OpenEntryStream());
        try { return _entryStream = (EntryStream)constructor.Invoke([this, _completion]); }
        catch { _completion.Dispose(); throw; }
    }

    public void WriteEntryTo(Stream writableStream)
    {
        using Stream input = OpenEntryStream();
        try { input.CopyTo(writableStream); }
        catch { Cancel(); throw; }
    }
    public void Cancel() => Cancelled = true;
    public void Dispose()
    {
        if (_disposed) return; _disposed = true; Cancel();
        try { _entryStream?.Dispose(); } finally { _entries.Dispose(); }
    }

    private sealed class CompletionStream(Stream source) : Stream
    {
        internal bool Completed { get; private set; }
        public override bool CanRead => source.CanRead;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => source.Length;
        public override long Position { get => source.Position; set => throw new NotSupportedException(); }
        public override int Read(byte[] buffer, int offset, int count)
        { int read = source.Read(buffer, offset, count); if (count > 0 && read == 0) Completed = true; return read; }
        public override int Read(Span<byte> buffer)
        { int read = source.Read(buffer); if (!buffer.IsEmpty && read == 0) Completed = true; return read; }
        public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken token = default)
        { int read = await source.ReadAsync(buffer, token).ConfigureAwait(false); if (!buffer.IsEmpty && read == 0) Completed = true; return read; }
        public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken token) => ReadAsync(buffer.AsMemory(offset, count), token).AsTask();
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void Flush() { }
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
        protected override void Dispose(bool disposing) { if (disposing) source.Dispose(); base.Dispose(disposing); }
    }
}
