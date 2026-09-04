namespace SteamSentinel.Core.Utilities;

public sealed class TemporaryDirectory : IDisposable
{
    public string Path { get; }
    private bool _disposed;

    public TemporaryDirectory()
    {
        string root = GetRoot();
        Directory.CreateDirectory(root);
        Path = System.IO.Path.Combine(root, Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(Path);
    }

    public string CreateFilePath(string? originalName = null)
    {
        // Never retain an executable extension. Detection uses the virtual member name.
        return System.IO.Path.Combine(Path, $"{Guid.NewGuid():N}.scan");
    }

    public void Dispose()
    {
        if (_disposed) return;
        try
        {
            string root = GetRoot();
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

    private static string GetRoot() => System.IO.Path.GetFullPath(
        ProcessIntegrity.GetCurrent() is ProcessIntegrityLevel.Low or ProcessIntegrityLevel.Untrusted
            ? AppPaths.WorkerTemporaryRoot
            : AppPaths.TemporaryRoot);
}
