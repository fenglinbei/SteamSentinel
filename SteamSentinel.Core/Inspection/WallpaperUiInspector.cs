using System.Text.RegularExpressions;
using SteamSentinel.Core.Steam;

namespace SteamSentinel.Core.Inspection;

public static class WallpaperUiInspector
{
    private static readonly Regex Disabled = new(@"(?:canReport|reportEnabled|can_report)\s*[:=]\s*(?:false|!1)|(?:canReport|reportEnabled)\s*[:=][^{]{0,30}\{\s*return\s+(?:false|!1)",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant, TimeSpan.FromMilliseconds(100));
    private static readonly Regex Hidden = new("""(?:[#.][\w-]*report[\w-]*[^{}]{0,80}\{[^{}]{0,180}display\s*:\s*none|[\w-]*report[\w-]*["']\)\s*\.hide\s*\()""",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant, TimeSpan.FromMilliseconds(100));
    public static bool HasCombinedSuppression(string text)
    {
        if (text.Length > 32 * 1024 * 1024) return false;
        try { return Disabled.IsMatch(text) && Hidden.IsMatch(text); }
        catch (RegexMatchTimeoutException) { return false; }
    }
    public static IReadOnlyList<string> CandidateFiles(SteamLayout layout) => layout.LibraryRoots
        .Select(root => Path.Combine(root, "steamapps", "common", "wallpaper_engine"))
        .Concat(layout.Games.Where(game => game.AppId == "431960").Select(game => game.Directory))
        .Select(root => Path.Combine(root, "ui", "dist", "scripts", "scripts.js"))
        .Where(File.Exists).Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
}
