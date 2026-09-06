using SharpCompress.Common;
using SharpCompress.Readers;

namespace SteamSentinel.Core.Inspection;

/// <summary>Tracks the one actual traversal and successful integrity checks without reopening metadata or content.</summary>
internal sealed class ArchiveVolumeTraversal(IReader reader, int expectedEntries, int expectedFiles) : IReader
{
    private IEntry? _current;
    private int _entries, _files, _verified, _skipped;
    private bool _currentVerified, _currentOpened, _currentSkipped, _reachedEnd, _disposed;
    public ArchiveType Type => reader.Type;
    public IEntry Entry => _current ?? throw new InvalidOperationException("尚未定位归档成员。");
    public bool Cancelled => reader.Cancelled;
    internal int SkippedEntries => _skipped;
    internal bool CanSkipCurrentUnopenedEntry => !_disposed && !_reachedEnd && !Cancelled &&
        !_currentOpened && !_currentVerified && !_currentSkipped && _current is { IsDirectory: false } &&
        reader is ArchiveVolumeEntryReader { CanSkipCurrentUnopenedEntry: true };
    public bool MoveToNextEntry()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (_reachedEnd) return false;
        bool moved = reader.MoveToNextEntry();
        _current = moved ? reader.Entry : null;
        _currentVerified = false; _currentOpened = false; _currentSkipped = false;
        if (!moved) { _reachedEnd = true; return false; }
        _entries++; if (!_current!.IsDirectory) _files++;
        if (_entries > expectedEntries || _files > expectedFiles)
            throw new ArchiveVolumeException(ArchiveVolumeStatus.InvalidMetadata, "实际解码条目超过已验证目录清单。");
        return true;
    }
    public EntryStream OpenEntryStream()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (_current is null || _reachedEnd || Cancelled || _currentOpened || _currentVerified || _currentSkipped)
            throw new InvalidOperationException("当前归档成员已经打开、跳过或结束。");
        _currentOpened = true;
        return reader.OpenEntryStream();
    }
    public void WriteEntryTo(Stream writableStream) =>
        throw new NotSupportedException("成员必须通过有预算的流读取和完整性校验。");
    public void Cancel() => reader.Cancel();
    internal void RequireCurrent(IEntry entry)
    {
        if (_disposed || _reachedEnd || Cancelled || !ReferenceEquals(entry, _current) || _currentVerified || _currentSkipped)
            throw new InvalidOperationException("完整性校验必须绑定当前唯一归档成员。");
    }
    internal void SkipCurrentUnopenedEntry(IEntry entry)
    {
        RequireCurrent(entry);
        if (!CanSkipCurrentUnopenedEntry)
            throw new InvalidOperationException("只能显式跳过尚未打开的 ZIP 文件成员。");
        // ZIP's central-directory reader advances by seekable entry metadata. No
        // entry stream was opened, so moving onward cannot auto-drain any content.
        _currentSkipped = true; _skipped++;
    }
    internal void MarkVerified(IEntry entry)
    {
        RequireCurrent(entry);
        if (entry.IsDirectory || !_currentOpened) throw new InvalidOperationException("目录或未打开成员不计为内容完整性证据。");
        _currentVerified = true; _verified++;
    }
    internal void VerifyCompleted(bool allowSkipped)
    {
        if (!_reachedEnd || Cancelled || _entries != expectedEntries || _files != expectedFiles ||
            _verified + (allowSkipped ? _skipped : 0) != expectedFiles)
            throw new ArchiveVolumeException(ArchiveVolumeStatus.InvalidMetadata, "归档遍历未到达结束，或有目录条目未完成内容校验。");
    }
    public void Dispose()
    {
        if (_disposed) return; _disposed = true; reader.Dispose();
    }
}
