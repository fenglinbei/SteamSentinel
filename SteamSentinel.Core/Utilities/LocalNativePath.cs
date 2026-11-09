namespace SteamSentinel.Core.Utilities;

/// <summary>
/// Encodes an already validated local path only at a Win32 I/O boundary. Keep the ordinary
/// canonical path for all policy and final-handle comparisons; never admit supplied device/UNC
/// paths through this helper. Managed file I/O already supports these lengths automatically.
/// </summary>
internal static class LocalNativePath
{
    internal static string Encode(string path)
    {
        if (!Path.IsPathFullyQualified(path) || path.StartsWith(@"\\", StringComparison.Ordinal))
            throw new ArgumentException("A fully qualified local path is required.", nameof(path));
        string full = Path.GetFullPath(path);
        if (full.Length < 3 || full[1] != ':' || full[2] != Path.DirectorySeparatorChar || full.IndexOf(':', 2) >= 0)
            throw new ArgumentException("A local drive path is required.", nameof(path));
        return full.Length >= 248 ? @"\\?\" + full : full;
    }
}
