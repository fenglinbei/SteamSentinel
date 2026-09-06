namespace SteamSentinel.Core.Utilities;

public sealed class TemporaryDirectory : IDisposable
{
    public string Path { get; }
    private bool _disposed;
    private readonly string _root;

    public TemporaryDirectory()
    {
        string root = GetRoot();
        if (Validation.ContainsReparsePoint(root)) throw new IOException("扫描临时目录包含重解析点。");
        Directory.CreateDirectory(root);
        root = _root = OwnedDirectoryPhysicalPath.ResolveForCreation(root);
        string candidate = System.IO.Path.Combine(root, Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(candidate);
        Path = OwnedDirectoryPhysicalPath.ResolveExisting(candidate);
        if (!string.Equals(System.IO.Path.GetDirectoryName(Path), root, StringComparison.OrdinalIgnoreCase))
            throw new IOException("新建临时目录不在本轮自有物理根目录内。");
    }

    public string CreateFilePath(string? originalName = null)
    {
        EnsureFreeSpace(Path);
        // Never retain an executable extension. Detection uses the virtual member name.
        return System.IO.Path.Combine(Path, $"{Guid.NewGuid():N}.scan");
    }

    public void Dispose()
    {
        if (_disposed) return;
        try
        {
            string root = _root;
            string target = System.IO.Path.GetFullPath(Path);
            if (target.StartsWith(root + System.IO.Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase) &&
                Directory.Exists(target) &&
                !Validation.ContainsReparsePoint(target))
            {
                Directory.Delete(target, recursive: true);
            }
        }
        catch
        {
            // A leftover may contain malicious bytes, never launch it or call it harmless.
        }

        _disposed = true;
    }

    internal static string GetRoot()
    {
        if (ProcessIntegrity.GetCurrent() is not (ProcessIntegrityLevel.Low or ProcessIntegrityLevel.Untrusted))
            return System.IO.Path.GetFullPath(AppPaths.TemporaryRoot);
        string session = System.IO.Path.TrimEndingDirectorySeparator(System.IO.Path.GetFullPath(Environment.CurrentDirectory));
        string configured = System.IO.Path.TrimEndingDirectorySeparator(System.IO.Path.GetFullPath(AppPaths.WorkerTemporaryRoot));
        string allowed = OwnedDirectoryPhysicalPath.ResolveForCreation(configured);
        string? parent = System.IO.Path.GetDirectoryName(session);
        if (!(string.Equals(parent, allowed, StringComparison.OrdinalIgnoreCase) || string.Equals(parent, configured, StringComparison.OrdinalIgnoreCase)) ||
            Validation.ContainsReparsePoint(session))
            throw new IOException("受限扫描必须使用本轮独立临时目录。");
        session = OwnedDirectoryPhysicalPath.ResolveExisting(session);
        if (!string.Equals(System.IO.Path.GetDirectoryName(session), allowed, StringComparison.OrdinalIgnoreCase))
            throw new IOException("受限扫描会话不在自有物理根目录内。");
        return session;
    }

    public static void EnsureFreeSpace(string path, long nextWriteBytes = 0)
    {
        const long reserve = 256L * 1024 * 1024;
        string volume = System.IO.Path.GetPathRoot(System.IO.Path.GetFullPath(path))
            ?? throw new IOException("无法确定扫描临时文件所在磁盘。");
        if (nextWriteBytes < 0 || new DriveInfo(volume).AvailableFreeSpace - reserve < nextWriteBytes)
            throw new Scanning.ScanResourceLimitException("临时磁盘空间不足：扫描需保留至少 256 MiB 空闲空间，未继续展开内容。");
    }
}
