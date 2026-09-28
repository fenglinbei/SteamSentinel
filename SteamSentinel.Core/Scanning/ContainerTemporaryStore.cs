using SteamSentinel.Core.Reporting;
using SteamSentinel.Core.Utilities;

namespace SteamSentinel.Core.Scanning;

/// <summary>Numbered non-executable working files, owned only by this scan scope.</summary>
public sealed class ContainerTemporaryStore : IDisposable
{
    private readonly TemporaryDirectory _directory = new();
    private readonly ContainerResourceBudget _budget;
    private readonly List<ContainerTemporaryFile> _files = [];
    private bool _disposed;
    public string Path => _directory.Path;
    public ContainerTemporaryStore(ContainerResourceBudget budget) => _budget = budget;

    public ContainerTemporaryFile CreateFile()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        _budget.Check();
        string path = System.IO.Path.Combine(Path, $"{_files.Count:D8}-{Guid.NewGuid():N}.scan");
        if (Validation.ContainsReparsePoint(Path)) throw MessageExceptions.Create(MessageText.Create("Backend.Core.ContainerTemporaryStore.CreateFile.01"), sourceText => new IOException(sourceText));
        ContainerTemporaryFile file = new(path, _budget); _files.Add(file); return file;
    }

    public void Dispose()
    {
        if (_disposed) return;
        foreach (ContainerTemporaryFile file in _files) file.Dispose();
        _directory.Dispose();
        foreach (ContainerTemporaryFile file in _files) file.ReconcileDeleted();
        _disposed = true;
    }
}

public sealed class ContainerTemporaryFile : IDisposable
{
    private FileStream? _stream;
    private readonly ContainerResourceBudget _budget;
    private long _charged;
    private bool _disposed;
    public string Path { get; }
    public long Length => _stream?.Length ?? _charged;
    internal ContainerTemporaryFile(string path, ContainerResourceBudget budget)
    {
        Path = path; _budget = budget;
        _stream = new(path, FileMode.CreateNew, FileAccess.Write, FileShare.None, 128 * 1024,
            FileOptions.Asynchronous | FileOptions.SequentialScan);
    }

    public async ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken token)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (_stream is null) throw MessageExceptions.Create(MessageText.Create("Backend.Core.ContainerTemporaryStore.WriteAsync.01"), sourceText => new InvalidOperationException(sourceText));
        _budget.Check(); token.ThrowIfCancellationRequested();
        string root = System.IO.Path.GetPathRoot(Path) ?? throw MessageExceptions.Create(MessageText.Create("Backend.Core.ContainerTemporaryStore.WriteAsync.02"), sourceText => new IOException(sourceText));
        if (new DriveInfo(root).AvailableFreeSpace - _budget.EffectiveDiskReserve < buffer.Length)
            throw MessageExceptions.Create(MessageText.Create("Backend.Core.ContainerTemporaryStore.WriteAsync.03"), sourceText => new ScanResourceLimitException(sourceText));
        _budget.ReserveTemporary(buffer.Length);
        _charged = checked(_charged + buffer.Length);
        try { await _stream.WriteAsync(buffer, token).ConfigureAwait(false); }
        catch (Exception ex)
        {
            // A cancelled write can have partly reached the filesystem. Measure only this owned file.
            long actual = _stream.Length;
            if (actual < _charged) { _budget.ReleaseTemporary(_charged - actual); _charged = actual; }
            if (ex is IOException && (ex.HResult & 0xffff) is 0x27 or 0x70)
                throw MessageExceptions.Create(MessageText.Create("Backend.Core.ContainerTemporaryStore.WriteAsync.04"), sourceText => new ScanResourceLimitException(sourceText));
            throw;
        }
    }

    public async Task SealAsync(CancellationToken token = default)
    {
        if (_stream is null) return;
        await _stream.FlushAsync(token).ConfigureAwait(false);
        await _stream.DisposeAsync().ConfigureAwait(false); _stream = null;
    }

    public void Dispose()
    {
        if (_disposed) return;
        _stream?.Dispose(); _stream = null;
        // The path is generated in the owned directory; no recursive delete or untrusted member name.
        try
        {
            if (!Validation.ContainsReparsePoint(Path)) File.Delete(Path);
            if (!File.Exists(Path)) { _budget.ReleaseTemporary(_charged); _charged = 0; }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        { /* Worker session cleanup retries; retained bytes remain charged and visible. */ }
        _disposed = true;
    }

    internal void ReconcileDeleted()
    {
        if (_charged > 0 && !File.Exists(Path)) { _budget.ReleaseTemporary(_charged); _charged = 0; }
    }
}
