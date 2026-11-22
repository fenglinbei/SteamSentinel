using SteamSentinel.Core.Reporting;
namespace SteamSentinel.Core.Scanning;

internal sealed record HeuristicMatch(string Id, MessageText Title, MessageText Evidence, int Score);

internal static class ContentHeuristics
{
    internal static readonly string[] Tokens = ["steam://open/supportalert", "SupportMessages", "HelpFrontPage", "steamhelper",
        "bSupportPopupMessage", "steam.cfg", "SteamKey20260310", "CryptUnprotectData", "steam.exe", "/downloadlog/",
        "steam_save_mafile", "steam_outbox_list", "proconnector.cfd", "/api/v1/plugin/beacon", "password",
        "bootstrap_secret", "KEY_ENC", "payload.bin", "marshal", "decompress", "runtime_manifest", "key_xor", "MODE_CTR", "<BB16s32s32s16s",
        "-cef-enable-debugging", "--remote-debugging-port", ".cef-enable-remote-debugging", "BootStrapperInhibitAll",
        "steamui", "clientui", "libraryroot", "WriteAllText", "Set-Content", "createElement",
        "Start-Process", "Invoke-WebRequest", "Invoke-RestMethod", "DownloadFile", "DownloadString",
        "urllib.request", "Invoke-Expression", "subprocess.Popen", "os.startfile",
        @"CurrentVersion\Run", "schtasks", "Register-ScheduledTask", @"\Startup\"];

    public static HeuristicMatch? Match(string text, string path)
        => Match(value => text.Contains(value, StringComparison.OrdinalIgnoreCase), path, null);

    internal static HeuristicMatch? Match(Func<string, bool> Has, string path, string? workshopId = null)
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
        // 通用假红信机制 1：通过调试开关 / 禁止更新 + steamui/clientui 改动与脚本/文件写入实施客户端劫持
        if ((Has("-cef-enable-debugging") || Has("--remote-debugging-port") || Has(".cef-enable-remote-debugging") || Has("BootStrapperInhibitAll")) &&
            (Has("steamui") || Has("clientui") || Has("libraryroot")) &&
            (Has("WriteAllText") || Has("Set-Content") || Has("createElement") || Has("Start-Process")))
            return new("HEUR-STEAM-CEF-HIJACK", MessageText.Create("Backend.Core.ContentHeuristics.Match.09"),
                MessageText.Create("Backend.Core.ContentHeuristics.Match.10"), 90);
        // 通用假红信机制 2：仅在工坊路径范围内识别下载 + 执行 + 持久化三段式释放链
        bool isWorkshop = workshopId is not null || Steam.ContentDiscovery.IsWorkshopContentPath(path);
        if (isWorkshop &&
            (Has("Invoke-WebRequest") || Has("Invoke-RestMethod") || Has("DownloadFile") || Has("DownloadString") || Has("urllib.request")) &&
            (Has("Start-Process") || Has("Invoke-Expression") || Has("subprocess.Popen") || Has("os.startfile")) &&
            (Has(@"CurrentVersion\Run") || Has("schtasks") || Has("Register-ScheduledTask") || Has(@"\Startup\")))
            return new("HEUR-WORKSHOP-DROPPER-EXEC", MessageText.Create("Backend.Core.ContentHeuristics.Match.11"),
                MessageText.Create("Backend.Core.ContentHeuristics.Match.12"), 85);
        return null;
    }
}
