using System.Text.RegularExpressions;

namespace SteamSentinel.Core.Utilities;

public static partial class Validation
{
    [GeneratedRegex("^(?=.{1,253}$)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\\.)+[a-zA-Z]{2,63}$", RegexOptions.CultureInvariant)]
    private static partial Regex DomainRegex();

    public static bool IsSafeDomain(string value) => DomainRegex().IsMatch(value);

    public static bool IsHexSha256(string? value) =>
        value is { Length: 64 } && value.All(Uri.IsHexDigit);

    public static bool IsSafeExactTarget(string path)
    {
        if (string.IsNullOrWhiteSpace(path) || !Path.IsPathFullyQualified(path))
        {
            return false;
        }

        string fullPath;
        try
        {
            fullPath = Path.TrimEndingDirectorySeparator(Path.GetFullPath(path));
        }
        catch
        {
            return false;
        }

        string? root = Path.GetPathRoot(fullPath);
        if (string.IsNullOrWhiteSpace(root) ||
            string.Equals(Path.TrimEndingDirectorySeparator(root), fullPath, StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        string windows = Path.TrimEndingDirectorySeparator(Environment.GetFolderPath(Environment.SpecialFolder.Windows));
        string programFiles = Path.TrimEndingDirectorySeparator(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles));
        string programFilesX86 = Path.TrimEndingDirectorySeparator(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86));
        string userProfile = Path.TrimEndingDirectorySeparator(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile));

        return !string.Equals(fullPath, windows, StringComparison.OrdinalIgnoreCase) &&
               !string.Equals(fullPath, programFiles, StringComparison.OrdinalIgnoreCase) &&
               !string.Equals(fullPath, programFilesX86, StringComparison.OrdinalIgnoreCase) &&
               !string.Equals(fullPath, userProfile, StringComparison.OrdinalIgnoreCase);
    }

    public static bool ContainsReparsePoint(string path)
    {
        string full = Path.GetFullPath(path);
        string? root = Path.GetPathRoot(full);
        if (root is null)
        {
            return true;
        }

        string current = root;
        foreach (string part in full[root.Length..].Split(Path.DirectorySeparatorChar, StringSplitOptions.RemoveEmptyEntries))
        {
            current = Path.Combine(current, part);
            if (!File.Exists(current) && !Directory.Exists(current))
            {
                continue;
            }

            FileAttributes attributes = File.GetAttributes(current);
            if ((attributes & FileAttributes.ReparsePoint) != 0)
            {
                return true;
            }
        }

        return false;
    }
}
