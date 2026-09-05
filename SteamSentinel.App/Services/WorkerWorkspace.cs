using SteamSentinel.Core.Utilities;

namespace SteamSentinel.App.Services;

internal sealed class WorkerWorkspace : IDisposable, IAsyncDisposable
{
    private const string Marker = ".steamsentinel-session";
    private readonly FileStream _lease;
    internal string Path { get; }

    internal WorkerWorkspace()
    {
        string root = System.IO.Path.GetFullPath(AppPaths.WorkerTemporaryRoot);
        if (Validation.ContainsReparsePoint(root)) throw new IOException("扫描临时根目录包含重解析点。");
        Directory.CreateDirectory(root);
        CleanStaleSessions(root);
        Path = System.IO.Path.Combine(root, Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(Path);
        _lease = new FileStream(System.IO.Path.Combine(Path, Marker), FileMode.CreateNew, FileAccess.ReadWrite, FileShare.None);
        _lease.Write("SteamSentinel session v1"u8);
        _lease.Flush(true);
    }

    public void Dispose()
    {
        _lease.Dispose();
        TryClean(Path);
    }

    public async ValueTask DisposeAsync()
    {
        await _lease.DisposeAsync().ConfigureAwait(false);
        for (int attempt = 0; attempt < 5; attempt++)
        {
            if (TryClean(Path, logFailure: attempt == 4)) return;
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
                TryClean(path);
            }
            catch (IOException) { /* Active run or concurrent cleanup: keep it. */ }
            catch (UnauthorizedAccessException) { /* Unknown ownership: keep it. */ }
        }
    }

    private static bool TryClean(string path, bool logFailure = true)
    {
        string root = System.IO.Path.TrimEndingDirectorySeparator(System.IO.Path.GetFullPath(AppPaths.WorkerTemporaryRoot));
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
            if (logFailure) AppErrorLog.Write("WorkerTemporaryCleanup", new IOException("本轮扫描临时内容尚未完全清理：" + full, ex));
            return false;
        }
    }
}
