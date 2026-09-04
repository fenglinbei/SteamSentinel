namespace SteamSentinel.Core.Scanning;

internal sealed record HeuristicMatch(string Id, string Title, string Evidence, int Score);

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
            return new("HEUR-STEAM-UI-PATCHER", "发现修改 Steam 客服页面的组合特征",
                "同时包含假红信入口、客服路由替换及账户提醒/禁更修改特征，可在核对后隔离。", 90);
        if (Has("SteamKey20260310") && Has("CryptUnprotectData") && Has("steam.exe") && Has("/downloadlog/"))
            return new("HEUR-STEAM-TOKEN-STEALER", "发现 Steam 凭据读取与外传组合特征",
                "同时包含家族通信标记、凭据解密、Steam 进程读取及下载日志上报端点。", 95);
        if (Has("steam_save_mafile") && Has("steam_outbox_list") &&
            (Has("proconnector.cfd") || Has("/api/v1/plugin/beacon")) && Has("password"))
            return new("HEUR-STEAM-CREDENTIAL-PLUGIN", "发现拦截登录与外传验证资料的插件特征",
                "同一文件包含密码字段、验证资料保存、待发送队列及第三方接收端点。", 95);
        if ((Has("bootstrap_secret") && Has("KEY_ENC") && Has("payload.bin") && Has("marshal") && Has("decompress")) ||
            (Has("runtime_manifest") && Has("key_xor") && Has("MODE_CTR") && Has("marshal") && Has("<BB16s32s32s16s")))
            return new("HEUR-ENCRYPTED-PYTHON-LOADER", "发现隐藏载荷的 Python 加载链",
                "同时包含样本加载链的索引/密钥、解密解压及字节码加载特征，尚不等于已确认最终载荷，可手动隔离。", 80);
        return null;
    }
}
