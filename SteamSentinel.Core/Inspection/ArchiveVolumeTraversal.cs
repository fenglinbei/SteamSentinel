using SteamSentinel.Core.Reporting;
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
    public IEntry Entry => _current ?? throw MessageExceptions.Create(MessageText.Create("Backend.Core.ArchiveVolumeTraversal.Entry.01"), sourceText => new InvalidOperationException(sourceText));
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
            throw MessageExceptions.Create(MessageText.Create("Backend.Core.ArchiveVolumeTraversal.MoveToNextEntry.01"), sourceText => new ArchiveVolumeException(ArchiveVolumeStatus.InvalidMetadata, sourceText));
        return true;
    }
    public EntryStream OpenEntryStream()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (_current is null || _reachedEnd || Cancelled || _currentOpened || _currentVerified || _currentSkipped)
            throw MessageExceptions.Create(MessageText.Create("Backend.Core.ArchiveVolumeTraversal.OpenEntryStream.01"), sourceText => new InvalidOperationException(sourceText));
        _currentOpened = true;
        return reader.OpenEntryStream();
    }
    public void WriteEntryTo(Stream writableStream) =>
        throw MessageExceptions.Create(MessageText.Create("Backend.Core.ArchiveVolumeTraversal.WriteEntryTo.01"), sourceText => new NotSupportedException(sourceText));
    public void Cancel() => reader.Cancel();
    internal void RequireCurrent(IEntry entry)
    {
        if (_disposed || _reachedEnd || Cancelled || !ReferenceEquals(entry, _current) || _currentVerified || _currentSkipped)
            throw MessageExceptions.Create(MessageText.Create("Backend.Core.ArchiveVolumeTraversal.RequireCurrent.01"), sourceText => new InvalidOperationException(sourceText));
    }
    internal void SkipCurrentUnopenedEntry(IEntry entry)
    {
        RequireCurrent(entry);
        if (!CanSkipCurrentUnopenedEntry)
            throw MessageExceptions.Create(MessageText.Create("Backend.Core.ArchiveVolumeTraversal.SkipCurrentUnopenedEntry.01"), sourceText => new InvalidOperationException(sourceText));
        // ZIP's central-directory reader advances by seekable entry metadata. No
        // entry stream was opened, so moving onward cannot auto-drain any content.
        _currentSkipped = true; _skipped++;
    }
    internal void MarkVerified(IEntry entry)
    {
        RequireCurrent(entry);
        if (entry.IsDirectory || !_currentOpened) throw MessageExceptions.Create(MessageText.Create("Backend.Core.ArchiveVolumeTraversal.MarkVerified.01"), sourceText => new InvalidOperationException(sourceText));
        _currentVerified = true; _verified++;
    }
    internal void VerifyCompleted(bool allowSkipped)
    {
        if (!_reachedEnd || Cancelled || _entries != expectedEntries || _files != expectedFiles ||
            _verified + (allowSkipped ? _skipped : 0) != expectedFiles)
            throw MessageExceptions.Create(MessageText.Create("Backend.Core.ArchiveVolumeTraversal.VerifyCompleted.01"), sourceText => new ArchiveVolumeException(ArchiveVolumeStatus.InvalidMetadata, sourceText));
    }
    public void Dispose()
    {
        if (_disposed) return; _disposed = true; reader.Dispose();
    }
}
