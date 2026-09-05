using System.Text.RegularExpressions;
using System.Text;
using SteamSentinel.Core.Inspection;
using SteamSentinel.Core.Models;
using SteamSentinel.Core.Steam;
using SteamSentinel.Core.Utilities;

namespace SteamSentinel.Core.Scanning;

public sealed class SteamSecurityScanner(RuleSet rules)
{
    private const long MaximumScriptBytes = 32L * 1024 * 1024;
    private const long MaximumTotalScriptBytes = 256L * 1024 * 1024;
    private static readonly Regex ConstantReturnRegex = new(@"return\s*(?<expr>!!?\s*[01]|[01]|true|false)\s*(?:[;,}])", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant, TimeSpan.FromMilliseconds(100));
    private static readonly Regex SupportAlertCallRegex = new("ExecuteSteamURL\\s*\\(\\s*[\\\"']steam://open/supportalert[\\\"']\\s*\\)", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant, TimeSpan.FromMilliseconds(100));
    private static readonly Regex HiddenUrlBarRegex = new(@"style\s*:\s*\{\s*display\s*:\s*[""']none[""']\s*\}", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant, TimeSpan.FromMilliseconds(100));
    private static readonly Regex DirectRouteValueRegex = new(@"^[""']?\s*[:=]\s*[""'](?<url>https?://[^""'<>\s]+)", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant, TimeSpan.FromMilliseconds(100));
    private static readonly Regex RouteVariableValueRegex = new(@"^[""']?\s*:\s*(?<var>[$A-Z_a-z][$\w]*)", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant, TimeSpan.FromMilliseconds(100));
    private static readonly Regex UrlVariableRegex = new(@"(?<![$\w])(?<var>[$A-Z_a-z][$\w]*)\s*=\s*[""'](?<url>https?://[^""'<>\s]+)[""']", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant, TimeSpan.FromMilliseconds(100));

    public async Task ScanAsync(
        SteamLayout layout,
        ScanReport report,
        CancellationToken cancellationToken = default)
    {
        foreach (string path in WallpaperUiInspector.CandidateFiles(layout))
        {
            try
            {
                if (!ContentDiscovery.IsLocalSafePath(path) || new FileInfo(path).Length > MaximumScriptBytes) throw new IOException("路径或大小超出检查范围");
                string text = await ReadUtf8BoundedAsync(path, MaximumScriptBytes, cancellationToken);
                if (!WallpaperUiInspector.HasCombinedSuppression(text)) continue;
                report.Findings.Add(new Finding
                {
                    RuleId = "WALLPAPER-REPORT-SUPPRESSION",
                    Category = FindingCategory.WallpaperEngine,
                    Severity = FindingSeverity.High,
                    Score = 75,
                    Title = "Wallpaper 举报入口存在组合隐藏信号",
                    Target = path,
                    Sha256 = await Hashing.Sha256FileAsync(path, cancellationToken,
                        maximumBytes: new FileInfo(path).Length),
                    Description = "同时出现举报能力强制关闭与界面隐藏，需核对插件和修改来源，不自动替换版本未知的 Wallpaper 文件。",
                    Evidence = "举报状态常量与隐藏样式组合",
                    SuggestedActions = [SuggestedActionKind.ReviewOnly],
                    CanRemediate = false
                });
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            { report.Coverage = ScanCoverage.Partial; report.CoverageNotes.Add("Wallpaper 界面检查未完成：" + path); }
        }
        foreach (string steamRoot in layout.SteamRoots)
        {
            cancellationToken.ThrowIfCancellationRequested();
            await ScanSensitiveRootFilesAsync(steamRoot, report, cancellationToken);
            await ScanSteamUiAsync(steamRoot, report, cancellationToken);

            string millennium = Path.Combine(steamRoot, "millennium");
            if (Directory.Exists(millennium))
            {
                report.Findings.Add(new Finding
                {
                    RuleId = "STEAM-MOD-MILLENNIUM",
                    Category = FindingCategory.Steam,
                    Severity = FindingSeverity.Information,
                    Score = 5,
                    Title = "检测到 Millennium 或同名模组目录",
                    Description = "合法模组可能修改 Steam UI，不能仅凭目录存在自动删除。",
                    Target = millennium,
                    Evidence = "仅记录，需要与恶意哈希、隐藏地址栏或异常安装时间关联。",
                    CanRemediate = false,
                    SuggestedActions = [SuggestedActionKind.ReviewOnly]
                });
            }
        }
    }

    private async Task ScanSensitiveRootFilesAsync(string steamRoot, ScanReport report, CancellationToken cancellationToken)
    {
        foreach (string name in rules.SteamInjectionNames)
        {
            string path = Path.Combine(steamRoot, name);
            if (!File.Exists(path)) continue;

            FileInfo info = new(path);
            string sha256 = await Hashing.Sha256FileAsync(path, cancellationToken,
                bytes => report.Metrics.BytesHashed += bytes, maximumBytes: info.Length);
            HashRule? known = FindKnownHash(sha256);

            if (name.Equals("steam.cfg", StringComparison.OrdinalIgnoreCase))
            {
                string text = info.Length <= 1024 * 1024 ? await File.ReadAllTextAsync(path, cancellationToken) : string.Empty;
                Dictionary<string, string> values = ParseConfig(text);
                bool inhibitAll = HasValue(values, "BootStrapperInhibitAll", "enable", "enabled", "true", "1");
                bool disableSelfUpdate = HasValue(values, "BootStrapperForceSelfUpdate", "disable", "disabled", "false", "0");
                bool forceOffline = HasValue(values, "ForceOfflineMode", "enable", "enabled", "true", "1");
                bool paired = inhibitAll && disableSelfUpdate;
                bool suspicious = paired || inhibitAll || disableSelfUpdate || forceOffline;
                report.Findings.Add(new Finding
                {
                    RuleId = paired ? "STEAM-CFG-UPDATE-SUPPRESSION-PAIR" : suspicious ? "STEAM-CFG-CONTROL-SETTING" : "STEAM-CFG-PRESENT",
                    Category = FindingCategory.Steam,
                    Severity = paired ? FindingSeverity.High : suspicious ? FindingSeverity.Medium : FindingSeverity.Low,
                    Score = paired ? 85 : suspicious ? 45 : 15,
                    Title = paired ? "Steam 自更新被成对抑制" : suspicious ? "Steam 配置包含更新/离线控制项" : "Steam 根目录存在 steam.cfg",
                    Description = paired
                        ? "同时启用 BootStrapperInhibitAll 并禁用 BootStrapperForceSelfUpdate，本次真实样本使用这一组合维持被篡改的前端。"
                        : suspicious ? "单项高级配置需要结合用途核对。" : "配置存在，但未命中本版目标键值。",
                    Target = path,
                    Evidence = $"SHA-256={sha256}；设置={string.Join(';', values.Select(item => $"{item.Key}={item.Value}"))}",
                    Sha256 = sha256,
                    IsKnownMalware = false,
                    CanRemediate = paired,
                    SuggestedActions = paired ? [SuggestedActionKind.QuarantineFile] : [SuggestedActionKind.ReviewOnly]
                });
                continue;
            }

            SignatureResult signature = AuthenticodeVerifier.Verify(path);
            FindingSeverity severity = known?.Malware == true ? FindingSeverity.Critical :
                signature.Status == SignatureStatus.Valid ? FindingSeverity.Low : FindingSeverity.Medium;
            int score = known?.Malware == true ? 100 : signature.Status == SignatureStatus.Valid ? 15 : 45;
            report.Findings.Add(new Finding
            {
                RuleId = known?.Id ?? "STEAM-PROXY-DLL-PRESENT",
                Category = FindingCategory.Steam,
                Severity = severity,
                Score = score,
                Title = known?.Malware == true ? "Steam 根目录存在已确认恶意 DLL" : "Steam 根目录存在可旁加载 DLL",
                Description = "该名称也可能来自合法模组，必须结合签名、哈希和安装来源判断。",
                Target = path,
                Evidence = $"{signature.Detail}；SHA-256={sha256}",
                Sha256 = sha256,
                IsKnownMalware = known?.Malware == true,
                CanRemediate = known?.Malware == true,
                SuggestedActions = known?.Malware == true
                    ? [SuggestedActionKind.QuarantineFile]
                    : [SuggestedActionKind.ReviewOnly]
            });
        }
    }

    private async Task ScanSteamUiAsync(string steamRoot, ScanReport report, CancellationToken cancellationToken)
    {
        long totalBytes = 0;
        int checkedFiles = 0;
        int skippedFiles = 0;
        foreach (string root in new[] { Path.Combine(steamRoot, "steamui"), Path.Combine(steamRoot, "clientui") })
        {
            string[] files;
            List<string> discoveryNotes = [];
            try
            {
                files = Directory.Exists(root)
                    ? ContentDiscovery.Files(root, discoveryNotes, 100_000, 32, cancellationToken)
                        .Where(path => Path.GetExtension(path).Equals(".js", StringComparison.OrdinalIgnoreCase))
                        .Take(2001).ToArray()
                    : [];
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            { skippedFiles++; continue; }
            if (files.Length > 2000)
            {
                discoveryNotes.Add($"Steam UI 脚本数量超过 2,000 项上限：{root}");
                files = files[..2000];
            }
            if (discoveryNotes.Count > 0)
            {
                skippedFiles += discoveryNotes.Count;
                report.CoverageNotes.AddRange(discoveryNotes.Distinct().Take(16));
                if (discoveryNotes.Count > 16)
                    report.CoverageNotes.Add($"Steam UI 发现阶段另有 {discoveryNotes.Count - 16:N0} 条受限路径说明未逐条列出。");
            }

            foreach (string path in files)
            {
                cancellationToken.ThrowIfCancellationRequested();
                FileInfo info;
                try { info = new FileInfo(path); }
                catch { skippedFiles++; continue; }
                if (info.Length > MaximumScriptBytes || totalBytes + info.Length > MaximumTotalScriptBytes)
                {
                    skippedFiles++;
                    continue;
                }

                string text, sha256;
                try
                {
                    text = await ReadUtf8BoundedAsync(path, MaximumScriptBytes, cancellationToken);
                    sha256 = await Hashing.Sha256FileAsync(path, cancellationToken,
                        bytes => report.Metrics.BytesHashed += bytes, maximumBytes: info.Length);
                }
                catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
                {
                    skippedFiles++;
                    continue;
                }
                totalBytes += info.Length;
                checkedFiles++;

                HashRule? known = FindKnownHash(sha256);
                List<string> signals = AnalyzeSteamUi(text);
                if (known?.Malware != true && signals.Count == 0) continue;

                bool highConfidence = known?.Malware == true || signals.Count >= 2;
                report.Findings.Add(new Finding
                {
                    RuleId = known?.Id ?? "STEAM-UI-SEMANTIC-TAMPERING",
                    Category = FindingCategory.Steam,
                    Severity = known?.Malware == true ? FindingSeverity.Critical : highConfidence ? FindingSeverity.High : FindingSeverity.Medium,
                    Score = known?.Malware == true ? 100 : highConfidence ? 90 : 55,
                    Title = known?.Malware == true ? "命中已确认被篡改的 Steam 前端文件" : "Steam 前端出现假红信语义篡改",
                    Description = string.Join("；", signals.Count == 0 ? [known!.Label] : signals),
                    Target = path,
                    Evidence = $"SHA-256={sha256}；大小={info.Length:N0}；修改时间={info.LastWriteTimeUtc:O}",
                    Sha256 = sha256,
                    IsKnownMalware = known?.Malware == true,
                    CanRemediate = highConfidence,
                    SuggestedActions = highConfidence
                        ? [SuggestedActionKind.QuarantineFile, SuggestedActionKind.BlockKnownDomains]
                        : [SuggestedActionKind.ReviewOnly]
                });
            }
        }

        report.CoverageNotes.Add($"Steam UI 语义检查：读取 {checkedFiles} 个脚本、{totalBytes / 1024.0 / 1024.0:N1} MiB，跳过 {skippedFiles} 个权限或大小受限文件。本项只覆盖已支持的假红信模式。");
        if (skippedFiles > 0) report.Coverage = ScanCoverage.Partial;
    }

    private static async Task<string> ReadUtf8BoundedAsync(string path, long maximumBytes, CancellationToken token)
    {
        await using FileStream stream = new(path, FileMode.Open, FileAccess.Read, FileShare.Read,
            64 * 1024, FileOptions.Asynchronous | FileOptions.SequentialScan);
        if (stream.Length > maximumBytes || maximumBytes >= int.MaxValue)
            throw new IOException("脚本超过读取大小上限。");
        byte[] bytes = new byte[(int)Math.Min(maximumBytes + 1, stream.Length + 1)];
        int total = 0;
        while (total < bytes.Length)
        {
            int read = await stream.ReadAsync(bytes.AsMemory(total), token);
            if (read == 0) break;
            total += read;
        }
        if (total > maximumBytes || stream.ReadByte() >= 0)
            throw new IOException("脚本在读取期间超过大小上限。");
        return Encoding.UTF8.GetString(bytes, 0, total);
    }

    internal static List<string> AnalyzeSteamUi(string text)
    {
        List<string> signals = [];
        foreach ((string method, string label) in new[]
        {
            ("BMustShowSupportAlertDialog", "客服弹窗条件"),
            ("BHasActiveSupportAlerts", "客服告警状态")
        })
        {
            int index = text.IndexOf(method, StringComparison.Ordinal);
            if (index < 0) continue;
            string window = Slice(text, index, 420);
            Match constant = ConstantReturnRegex.Match(window);
            if (!constant.Success || constant.Index > 260) continue;
            string expression = Regex.Replace(constant.Groups["expr"].Value, @"\s+", string.Empty);
            bool? value = JavaScriptBoolean(expression);
            if (value is not null) signals.Add($"{label}被固定为{(value.Value ? "真" : "假")}（return {expression}）");
        }

        int action = text.IndexOf("OnGameActionUserRequest", StringComparison.Ordinal);
        if (action >= 0)
        {
            string window = Slice(text, action, 1600);
            Match call = SupportAlertCallRegex.Match(window);
            int returnIndex = call.Success ? window.IndexOf("return", call.Index + call.Length, StringComparison.Ordinal) : -1;
            int switchIndex = window.IndexOf("switch", StringComparison.Ordinal);
            if (call.Success && returnIndex >= 0 && returnIndex - (call.Index + call.Length) < 90 && (switchIndex < 0 || call.Index < switchIndex))
                signals.Add("游戏启动处理被改成先打开 steam://open/supportalert 并立即返回");
        }

        foreach (Match hidden in HiddenUrlBarRegex.Matches(text).Cast<Match>().Take(80))
        {
            string window = SliceCentered(text, hidden.Index, 1000);
            if (window.Contains("URLBar", StringComparison.OrdinalIgnoreCase) &&
                (window.Contains("bIsSecure", StringComparison.Ordinal) || window.Contains("Browser_NotSecure", StringComparison.Ordinal)))
            {
                signals.Add("Steam 内置浏览器地址栏在证书状态逻辑附近被设为 display:none");
                break;
            }
        }

        HashSet<string> routeHosts = new(StringComparer.OrdinalIgnoreCase);
        foreach (string key in new[] { "SupportMessages", "HelpAppPage", "HelpFrontPage" })
        {
            foreach (int index in AllIndexesOf(text, key).Take(80))
            {
                int valueIndex = index + key.Length;
                string suffix = Slice(text, valueIndex, 300);
                Match direct = DirectRouteValueRegex.Match(suffix);
                if (direct.Success)
                {
                    AddThirdPartyHost(direct.Groups["url"].Value, routeHosts);
                    continue;
                }

                Match map = RouteVariableValueRegex.Match(suffix);
                if (!map.Success) continue;
                int start = Math.Max(0, index - 8000);
                string prefix = text.Substring(start, index - start);
                string variable = map.Groups["var"].Value;
                Match? assignment = UrlVariableRegex.Matches(prefix).Cast<Match>()
                    .LastOrDefault(item => item.Groups["var"].Value.Equals(variable, StringComparison.Ordinal));
                if (assignment is not null) AddThirdPartyHost(assignment.Groups["url"].Value, routeHosts);
            }
        }
        foreach (string host in routeHosts) signals.Add($"客服路由被映射到第三方主机 {host}");
        return signals.Distinct(StringComparer.Ordinal).ToList();
    }

    private HashRule? FindKnownHash(string sha256) => rules.KnownHashes.FirstOrDefault(rule =>
        rule.Sha256.Equals(sha256, StringComparison.OrdinalIgnoreCase));

    private static Dictionary<string, string> ParseConfig(string text)
    {
        Dictionary<string, string> values = new(StringComparer.OrdinalIgnoreCase);
        foreach (string raw in text.Split(['\r', '\n'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            string line = raw.Trim();
            if (line.StartsWith('#') || line.StartsWith(';') || line.StartsWith("//", StringComparison.Ordinal)) continue;
            int separator = line.IndexOf('=');
            if (separator > 0) values[line[..separator].Trim()] = line[(separator + 1)..].Trim();
        }
        return values;
    }

    private static bool HasValue(IReadOnlyDictionary<string, string> values, string key, params string[] targets) =>
        values.TryGetValue(key, out string? value) && targets.Contains(value, StringComparer.OrdinalIgnoreCase);

    private static bool? JavaScriptBoolean(string expression) => expression.ToLowerInvariant() switch
    {
        "true" or "1" or "!0" or "!!1" => true,
        "false" or "0" or "!1" or "!!0" => false,
        _ => null
    };

    private static void AddThirdPartyHost(string url, ISet<string> hosts)
    {
        if (!Uri.TryCreate(url.TrimEnd('.', ',', ';', ')', ']', '}'), UriKind.Absolute, out Uri? uri)) return;
        if (uri.Host.Equals("steampowered.com", StringComparison.OrdinalIgnoreCase) ||
            uri.Host.EndsWith(".steampowered.com", StringComparison.OrdinalIgnoreCase)) return;
        hosts.Add(uri.IdnHost);
    }

    private static string Slice(string text, int index, int length) => text.Substring(index, Math.Min(length, text.Length - index));

    private static IEnumerable<int> AllIndexesOf(string text, string value)
    {
        int start = 0;
        while (start < text.Length)
        {
            int index = text.IndexOf(value, start, StringComparison.Ordinal);
            if (index < 0) yield break;
            yield return index;
            start = index + value.Length;
        }
    }

    private static string SliceCentered(string text, int index, int radius)
    {
        int start = Math.Max(0, index - radius);
        return text.Substring(start, Math.Min(text.Length - start, radius * 2));
    }
}
