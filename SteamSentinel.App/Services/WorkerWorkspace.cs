using SteamSentinel.Core.Reporting;
using SteamSentinel.Core.Utilities;

namespace SteamSentinel.App.Services;

internal sealed class WorkerWorkspace : IDisposable, IAsyncDisposable
{
    private const string Marker = ".steamsentinel-session";
    private readonly FileStream _lease;
    private readonly string _root;
    internal string Path { get; }

    internal WorkerWorkspace()
    {
        string root = System.IO.Path.GetFullPath(AppPaths.WorkerTemporaryRoot);
        if (Validation.ContainsReparsePoint(root)) throw MessageExceptions.Create(MessageText.Create("Backend.App.WorkerWorkspace.Constructor.01"), sourceText => new IOException(sourceText));
        Directory.CreateDirectory(root);
        root = _root = OwnedDirectoryPhysicalPath.ResolveForCreation(root);
        CleanStaleSessions(root);
        string candidate = System.IO.Path.Combine(root, Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(candidate);
        Path = OwnedDirectoryPhysicalPath.ResolveExisting(candidate);
        if (!string.Equals(System.IO.Path.GetDirectoryName(Path), root, StringComparison.OrdinalIgnoreCase))
            throw MessageExceptions.Create(MessageText.Create("Backend.App.WorkerWorkspace.Constructor.02"), sourceText => new IOException(sourceText));
        _lease = new FileStream(System.IO.Path.Combine(Path, Marker), FileMode.CreateNew, FileAccess.ReadWrite, FileShare.None);
        _lease.Write("SteamSentinel session v1"u8);
        _lease.Flush(true);
    }

    public void Dispose()
    {
        _lease.Dispose();
        TryClean(Path, _root);
    }

    public async ValueTask DisposeAsync()
    {
        await _lease.DisposeAsync().ConfigureAwait(false);
        for (int attempt = 0; attempt < 5; attempt++)
        {
            if (TryClean(Path, _root, logFailure: attempt == 4)) return;
            // Windows may signal process exit just before releasing its current-directory handle.
            await Task.Delay(50 * (attempt + 1)).ConfigureAwait(false);
        }
    }

    private static void CleanStaleSessions(string root)
    {
        // Only directories created with this version's marker are eligible. Legacy/unknown data is retained.
        foreach (string path in Directory.EnumerateDirectories(root).Take(64))
        {
            if (!Guid.TryParseExact(System.IO.Path.GetFileName(path), "N", out _) || Validation.ContainsReparsePoint(path)) continue;
            string marker = System.IO.Path.Combine(path, Marker);
            if (!File.Exists(marker) || Validation.ContainsReparsePoint(marker) || File.GetLastWriteTimeUtc(marker) > DateTime.UtcNow.AddDays(-1)) continue;
            try
            {
                using (FileStream lease = new(marker, FileMode.Open, FileAccess.ReadWrite, FileShare.None))
                {
                    if (lease.Length != "SteamSentinel session v1"u8.Length) continue;
                    byte[] data = new byte[lease.Length];
                    lease.ReadExactly(data);
                    if (!data.AsSpan().SequenceEqual("SteamSentinel session v1"u8)) continue;
                }
                TryClean(path, root);
            }
            catch (IOException) { /* Active run or concurrent cleanup: keep it. */ }
            catch (UnauthorizedAccessException) { /* Unknown ownership: keep it. */ }
        }
    }

    private static bool TryClean(string path, string ownedRoot, bool logFailure = true)
    {
        string root = System.IO.Path.TrimEndingDirectorySeparator(System.IO.Path.GetFullPath(ownedRoot));
        string full = System.IO.Path.GetFullPath(path);
        if (!string.Equals(System.IO.Path.GetDirectoryName(full), root, StringComparison.OrdinalIgnoreCase) ||
            !Guid.TryParseExact(System.IO.Path.GetFileName(full), "N", out _)) return false;
        try
        {
            if (Directory.Exists(full) && !Validation.ContainsReparsePoint(full)) Directory.Delete(full, recursive: true);
            return !Directory.Exists(full);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            if (logFailure) AppErrorLog.Write("WorkerTemporaryCleanup", MessageExceptions.Create(MessageText.Create("Backend.App.WorkerWorkspace.TryClean.01") + full, sourceText => new IOException(sourceText, ex)));
            return false;
        }
    }
}
