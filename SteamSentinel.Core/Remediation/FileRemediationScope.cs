using SteamSentinel.Core.Models;
using SteamSentinel.Core.Steam;
using SteamSentinel.Core.Utilities;

namespace SteamSentinel.Core.Remediation;

/// <summary>
/// The existing Broker file-scope policy, shared with plan preparation. This is a scope check only:
/// callers must still verify the file identity, safe path, permissions and final locked handle.
/// Each process uses its own account and discovered Steam layout; a client check cannot authorize a Broker.
/// </summary>
public static class FileRemediationScope
{
    public static bool IsAllowed(string path, string? hash, RuleSet rules, SteamLayout layout) =>
        IsAllowed(path, hash, rules, layout,
            Environment.GetFolderPath(Environment.SpecialFolder.Windows), AppPaths.MachineStateRoot,
            AppContext.BaseDirectory, Environment.GetFolderPath(Environment.SpecialFolder.UserProfile));

    // Explicit roots keep policy tests independent of the host's disks and accounts.
    internal static bool IsAllowed(string path, string? hash, RuleSet rules, SteamLayout layout,
        string windowsRoot, string machineStateRoot, string applicationRoot, string userProfile)
    {
        if (IsWithin(path, windowsRoot)) return false;
        if (IsWithin(path, machineStateRoot) || IsWithin(path, applicationRoot)) return false;
        if (rules.KnownPathTemplates.Any(template =>
                PathsEquivalent(path, Environment.ExpandEnvironmentVariables(template)) ||
                IsWithin(path, Environment.ExpandEnvironmentVariables(template))) ||
            IsWithin(path, userProfile) || layout.SteamRoots.Any(root => IsWithin(path, root)) ||
            layout.LibraryRoots.Any(root => IsWithin(path, root))) return true;
        return Validation.IsHexSha256(hash) && rules.KnownHashes.Any(rule =>
            rule.Malware && rule.Sha256.Equals(hash, StringComparison.OrdinalIgnoreCase));
    }

    private static bool IsWithin(string candidate, string root)
    {
        if (string.IsNullOrWhiteSpace(root)) return false;
        try
        {
            string fullCandidate = Path.TrimEndingDirectorySeparator(Path.GetFullPath(candidate));
            string fullRoot = Path.TrimEndingDirectorySeparator(Path.GetFullPath(root));
            return fullCandidate.Equals(fullRoot, StringComparison.OrdinalIgnoreCase) ||
                   fullCandidate.StartsWith(fullRoot + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase);
        }
        catch { return false; }
    }

    private static bool PathsEquivalent(string left, string right)
    {
        try
        {
            return Path.TrimEndingDirectorySeparator(Path.GetFullPath(left))
                .Equals(Path.TrimEndingDirectorySeparator(Path.GetFullPath(right)), StringComparison.OrdinalIgnoreCase);
        }
        catch { return false; }
    }
}

internal sealed class FileRemediationScopeException(string message) : UnauthorizedAccessException(message);
