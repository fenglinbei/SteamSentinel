using System.Text;
using System.Text.RegularExpressions;

namespace SteamSentinel.Core.Inspection;

/// <summary>Bounded literal normalization. Never evaluates scripts or invokes a command interpreter.</summary>
public static class ScriptSignals
{
    private const int Limit = 2 * 1024 * 1024;
    private static readonly Regex JoinLiterals = new("""(?<q>['"])(?<left>[A-Za-z0-9_./:\\-]{0,512})\k<q>\s*\+\s*\k<q>(?<right>[A-Za-z0-9_./:\\-]{0,512})\k<q>""",
        RegexOptions.CultureInvariant, TimeSpan.FromMilliseconds(100));
    private static readonly Regex Encoded = new("""(?:FromBase64String\s*\(\s*['"]|-(?:enc|encodedcommand)\s+)(?<data>[A-Za-z0-9+/]{32,65536}={0,2})""",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant, TimeSpan.FromMilliseconds(100));
    private static readonly Regex Secret = new("""(?i)(?<key>(?:password|passwd|token|shared_secret|identity_secret|authorization|cookie|sessionid)["']?\s*[:=]\s*["']?)[^"'\s&;,}\\]+""",
        RegexOptions.CultureInvariant, TimeSpan.FromMilliseconds(100));
    private static readonly Regex QuotedSecret = new("""(?i)(?<key>(?:password|passwd|token|shared_secret|identity_secret|authorization|cookie|sessionid)["']?\s*[:=]\s*)(?<q>["'])(?:(?!\k<q>).){0,8192}\k<q>""",
        RegexOptions.CultureInvariant, TimeSpan.FromMilliseconds(100));
    private static readonly Regex Query = new("""(?i)(?<key>[?&][^=\s"'<>]{1,64}=)[^&\s"'<>]*""",
        RegexOptions.CultureInvariant, TimeSpan.FromMilliseconds(100));

    public static string Normalize(string text)
    {
        string result = text.Length > Limit ? text[..Limit] : text;
        try
        {
            for (int i = 0; i < 6; i++)
            {
                string next = JoinLiterals.Replace(result, "${q}${left}${right}${q}");
                if (next == result) break;
                result = next;
            }
            StringBuilder decoded = new(result);
            foreach (Match match in Encoded.Matches(result).Cast<Match>().Take(4))
            {
                try
                {
                    byte[] bytes = Convert.FromBase64String(match.Groups["data"].Value);
                    try
                    {
                        string candidate = bytes.Length > 1 && bytes[1] == 0 ? Encoding.Unicode.GetString(bytes) : Encoding.UTF8.GetString(bytes);
                        decoded.Append('\n').Append(candidate);
                    }
                    finally { Array.Clear(bytes); }
                }
                catch (FormatException) { }
            }
            return decoded.ToString();
        }
        catch (RegexMatchTimeoutException) { return result; }
    }

    public static IReadOnlyList<string> Analyze(string text)
    {
        string value = Normalize(text);
        return Analyze(s => value.Contains(s, StringComparison.OrdinalIgnoreCase));
    }

    internal static readonly string[] Tokens = ["DownloadString", "DownloadData", "Invoke-WebRequest", "Invoke-RestMethod",
        "http://", "https://", "Start-Process", "Invoke-Expression", "iex ", "wscript", "mshta", "rundll32", "steamprocess",
        "wsock32.dll", "millennium", "SteamKey20260310", "Add-MpPreference", "ExclusionPath", "AttackSurfaceReductionOnlyExclusions",
        "captcha", "Verification ID", "human verification", "steam_save_mafile", "steam_outbox_list", "password",
        "/api/v1/plugin/beacon", "proconnector.cfd"];

    internal static IReadOnlyList<string> Analyze(Func<string, bool> Has)
    {
        List<string> signals = [];
        bool download = Has("DownloadString") || Has("DownloadData") || Has("Invoke-WebRequest") || Has("Invoke-RestMethod") || Has("http://") || Has("https://");
        bool execute = Has("Start-Process") || Has("Invoke-Expression") || Has("iex ") || Has("wscript") || Has("mshta") || Has("rundll32");
        bool steam = Has("steamprocess") || Has("wsock32.dll") && Has("millennium") || Has("SteamKey20260310");
        bool defense = Has("Add-MpPreference") || Has("ExclusionPath") || Has("AttackSurfaceReductionOnlyExclusions");
        if (download && execute && steam) signals.Add("下载执行链与 Steam 插件或家族载荷同时出现");
        if (steam && defense) signals.Add("Steam 插件部署同时尝试修改安全排除项");
        if (download && execute && (Has("captcha") || Has("Verification ID") || Has("human verification")))
            signals.Add("验证码提示与下载执行命令同时出现");
        if (Has("steam_save_mafile") && Has("steam_outbox_list") && Has("password") &&
            (Has("/api/v1/plugin/beacon") || Has("proconnector.cfd")))
            signals.Add("Steam 登录拦截、验证资料发送队列与第三方接收端点同时出现");
        return signals;
    }

    public static string Redact(string value)
    {
        string result = RedactSecrets(value);
        return result.Length > 4096 ? result[..4096] + "…" : result;
    }

    public static string RedactSecrets(string value)
    {
        try
        {
            string result = QuotedSecret.Replace(value, "${key}${q}[REDACTED]${q}");
            result = Secret.Replace(result, "${key}[REDACTED]");
            result = Query.Replace(result, "${key}[REDACTED]");
            return result;
        }
        catch (RegexMatchTimeoutException) { return "[内容已隐藏]"; }
    }
}
