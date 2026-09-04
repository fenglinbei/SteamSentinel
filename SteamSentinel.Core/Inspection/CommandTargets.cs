using System.Text.RegularExpressions;
using SteamSentinel.Core.Steam;

namespace SteamSentinel.Core.Inspection;

public static class CommandTargets
{
    private static readonly Regex LocalFile = new("(?<path>[A-Za-z]:[\\\\/][^\\r\\n\\\"<>|]*?\\.(?:exe|dll|bat|cmd|ps1|vbs|js|py|pyc|lnk))(?=[\\s\\\"'&,]|$)",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant, TimeSpan.FromMilliseconds(100));

    public static IReadOnlyList<string> Extract(string command)
    {
        if (command.Length > 32_768) return [];
        try
        {
            string expanded = Environment.ExpandEnvironmentVariables(command);
            return LocalFile.Matches(expanded).Cast<Match>().Take(32).Select(match => match.Groups["path"].Value.Trim())
                .Where(ContentDiscovery.IsLocalSafePath).Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
        }
        catch (Exception ex) when (ex is ArgumentException or RegexMatchTimeoutException) { return []; }
    }

    public static IReadOnlyList<string> WithScriptTargets(string command)
    {
        List<string> result = [.. Extract(command)];
        foreach (string path in result.ToArray())
        {
            string extension = Path.GetExtension(path).ToLowerInvariant();
            if (extension is not (".bat" or ".cmd" or ".ps1" or ".vbs" or ".js" or ".py")) continue;
            try
            {
                if (File.Exists(path) && new FileInfo(path).Length <= 256 * 1024)
                {
                    string text = File.ReadAllText(path);
                    string directory = Path.GetDirectoryName(path)! + Path.DirectorySeparatorChar;
                    text = text.Replace("%~dp0", directory, StringComparison.OrdinalIgnoreCase)
                        .Replace("$PSScriptRoot", directory.TrimEnd(Path.DirectorySeparatorChar), StringComparison.OrdinalIgnoreCase);
                    result.AddRange(Extract(ScriptSignals.Normalize(text)));
                }
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { }
        }
        return result.Distinct(StringComparer.OrdinalIgnoreCase).Take(64).ToArray();
    }
}
