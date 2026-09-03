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
        string extension = string.Empty;
        if (!string.IsNullOrWhiteSpace(originalName))
        {
            extension = System.IO.Path.GetExtension(originalName);
            if (extension.Length > 16 || extension.Any(c => !char.IsLetterOrDigit(c) && c != '.')) extension = string.Empty;
        }

        return System.IO.Path.Combine(Path, $"{Guid.NewGuid():N}.scan{extension}");
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
            // A locked scan artifact is harmless and can be cleaned on the next launch.
        }

        _disposed = true;
    }

    private static string GetRoot() => System.IO.Path.GetFullPath(
        ProcessIntegrity.GetCurrent() is ProcessIntegrityLevel.Low or ProcessIntegrityLevel.Untrusted
            ? AppPaths.WorkerTemporaryRoot
            : AppPaths.TemporaryRoot);
}
