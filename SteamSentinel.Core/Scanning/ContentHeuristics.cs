using SteamSentinel.Core.Reporting;
namespace SteamSentinel.Core.Scanning;

internal sealed record HeuristicMatch(string Id, MessageText Title, MessageText Evidence, int Score);

internal static class ContentHeuristics
{
    internal static readonly string[] Tokens = ["steam://open/supportalert", "SupportMessages", "HelpFrontPage", "steamhelper",
        "bSupportPopupMessage", "steam.cfg", "SteamKey20260310", "CryptUnprotectData", "steam.exe", "/downloadlog/",
        "steam_save_mafile", "steam_outbox_list", "proconnector.cfd", "/api/v1/plugin/beacon", "password",
        "bootstrap_secret", "KEY_ENC", "payload.bin", "marshal", "decompress", "runtime_manifest", "key_xor", "MODE_CTR", "<BB16s32s32s16s"];
    public static HeuristicMatch? Match(string text, string path)
        => Match(value => text.Contains(value, StringComparison.OrdinalIgnoreCase), path);

    internal static HeuristicMatch? Match(Func<string, bool> Has, string path)
    {
        string extension = Path.GetExtension(path).ToLowerInvariant();
        if (extension is ".md" or ".log" or ".lo") return null;
        if (Has("steam://open/supportalert") && Has("SupportMessages") && Has("HelpFrontPage") &&
            Has("steamhelper") && (Has("bSupportPopupMessage") || Has("steam.cfg")))
            return new("HEUR-STEAM-UI-PATCHER", MessageText.Create("Backend.Core.ContentHeuristics.Match.01"),
                MessageText.Create("Backend.Core.ContentHeuristics.Match.02"), 90);
        if (Has("SteamKey20260310") && Has("CryptUnprotectData") && Has("steam.exe") && Has("/downloadlog/"))
            return new("HEUR-STEAM-TOKEN-STEALER", MessageText.Create("Backend.Core.ContentHeuristics.Match.03"),
                MessageText.Create("Backend.Core.ContentHeuristics.Match.04"), 95);
        if (Has("steam_save_mafile") && Has("steam_outbox_list") &&
            (Has("proconnector.cfd") || Has("/api/v1/plugin/beacon")) && Has("password"))
            return new("HEUR-STEAM-CREDENTIAL-PLUGIN", MessageText.Create("Backend.Core.ContentHeuristics.Match.05"),
                MessageText.Create("Backend.Core.ContentHeuristics.Match.06"), 95);
        if ((Has("bootstrap_secret") && Has("KEY_ENC") && Has("payload.bin") && Has("marshal") && Has("decompress")) ||
            (Has("runtime_manifest") && Has("key_xor") && Has("MODE_CTR") && Has("marshal") && Has("<BB16s32s32s16s")))
            return new("HEUR-ENCRYPTED-PYTHON-LOADER", MessageText.Create("Backend.Core.ContentHeuristics.Match.07"),
                MessageText.Create("Backend.Core.ContentHeuristics.Match.08"), 80);
        return null;
    }
}
