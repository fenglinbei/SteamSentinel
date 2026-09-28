using SteamSentinel.Core.Reporting;
namespace SteamSentinel.Core.Utilities;

public sealed class TemporaryDirectory : IDisposable
{
    public string Path { get; }
    private bool _disposed;
    private readonly string _root;

    public TemporaryDirectory()
    {
        string root = GetRoot();
        if (Validation.ContainsReparsePoint(root)) throw MessageExceptions.Create(MessageText.Create("Backend.Core.TemporaryDirectory.Constructor.01"), sourceText => new IOException(sourceText));
        Directory.CreateDirectory(root);
        root = _root = OwnedDirectoryPhysicalPath.ResolveForCreation(root);
        string candidate = System.IO.Path.Combine(root, Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(candidate);
        Path = OwnedDirectoryPhysicalPath.ResolveExisting(candidate);
        if (!string.Equals(System.IO.Path.GetDirectoryName(Path), root, StringComparison.OrdinalIgnoreCase))
            throw MessageExceptions.Create(MessageText.Create("Backend.Core.TemporaryDirectory.Constructor.02"), sourceText => new IOException(sourceText));
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
            throw MessageExceptions.Create(MessageText.Create("Backend.Core.TemporaryDirectory.GetRoot.01"), sourceText => new IOException(sourceText));
        session = OwnedDirectoryPhysicalPath.ResolveExisting(session);
        if (!string.Equals(System.IO.Path.GetDirectoryName(session), allowed, StringComparison.OrdinalIgnoreCase))
            throw MessageExceptions.Create(MessageText.Create("Backend.Core.TemporaryDirectory.GetRoot.02"), sourceText => new IOException(sourceText));
        return session;
    }

    public static void EnsureFreeSpace(string path, long nextWriteBytes = 0)
    {
        const long reserve = 256L * 1024 * 1024;
        string volume = System.IO.Path.GetPathRoot(System.IO.Path.GetFullPath(path))
            ?? throw MessageExceptions.Create(MessageText.Create("Backend.Core.TemporaryDirectory.EnsureFreeSpace.01"), sourceText => new IOException(sourceText));
        if (nextWriteBytes < 0 || new DriveInfo(volume).AvailableFreeSpace - reserve < nextWriteBytes)
            throw MessageExceptions.Create(MessageText.Create("Backend.Core.TemporaryDirectory.EnsureFreeSpace.02"), sourceText => new Scanning.ScanResourceLimitException(sourceText));
    }
}
