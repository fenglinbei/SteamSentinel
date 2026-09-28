using SteamSentinel.Core.Reporting;
using System.Text.RegularExpressions;
using System.Text;
using System.Security.Cryptography;
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
                if (!ContentDiscovery.IsLocalSafePath(path) || new FileInfo(path).Length > MaximumScriptBytes) throw MessageExceptions.Create(MessageText.Create("Backend.Core.SteamSecurityScanner.ScanAsync.01"), sourceText => new IOException(sourceText));
                string text = await ReadUtf8BoundedAsync(path, MaximumScriptBytes, cancellationToken);
                if (!WallpaperUiInspector.HasCombinedSuppression(text)) continue;
                report.Findings.Add(new Finding
                {
                    RuleId = "WALLPAPER-REPORT-SUPPRESSION",
                    Category = FindingCategory.WallpaperEngine,
                    Severity = FindingSeverity.High,
                    Score = 75,
                    TitleText = MessageText.Create("Backend.Core.SteamSecurityScanner.ScanAsync.02"),
                    Target = path,
                    Sha256 = await Hashing.Sha256FileAsync(path, cancellationToken,
                        maximumBytes: new FileInfo(path).Length),
                    DescriptionText = MessageText.Create("Backend.Core.SteamSecurityScanner.ScanAsync.03"),
                    EvidenceText = MessageText.Create("Backend.Core.SteamSecurityScanner.ScanAsync.04"),
                    SuggestedActions = [SuggestedActionKind.ReviewOnly],
                    CanRemediate = false
                });
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            { report.Coverage = ScanCoverage.Partial; report.AddCoverageNote(MessageText.Create("Backend.Core.SteamSecurityScanner.ScanAsync.05") + path); }
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
                    TitleText = MessageText.Create("Backend.Core.SteamSecurityScanner.ScanAsync.06"),
                    DescriptionText = MessageText.Create("Backend.Core.SteamSecurityScanner.ScanAsync.07"),
                    Target = millennium,
                    EvidenceText = MessageText.Create("Backend.Core.SteamSecurityScanner.ScanAsync.08"),
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
                    TitleText = paired ? MessageText.Create("Backend.Core.SteamSecurityScanner.ScanSensitiveRootFilesAsync.01") : suspicious ? MessageText.Create("Backend.Core.SteamSecurityScanner.ScanSensitiveRootFilesAsync.02") : MessageText.Create("Backend.Core.SteamSecurityScanner.ScanSensitiveRootFilesAsync.03"),
                    DescriptionText = paired
                        ? MessageText.Create("Backend.Core.SteamSecurityScanner.ScanSensitiveRootFilesAsync.04")
                        : suspicious ? MessageText.Create("Backend.Core.SteamSecurityScanner.ScanSensitiveRootFilesAsync.05") : MessageText.Create("Backend.Core.SteamSecurityScanner.ScanSensitiveRootFilesAsync.06"),
                    Target = path,
                    EvidenceText = MessageText.Create("Backend.Core.SteamSecurityScanner.ScanSensitiveRootFilesAsync.07", (sha256), (string.Join(';', values.Select(item => $"{item.Key}={item.Value}")))),
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
                TitleText = known?.Malware == true ? MessageText.Create("Backend.Core.SteamSecurityScanner.ScanSensitiveRootFilesAsync.08") : MessageText.Create("Backend.Core.SteamSecurityScanner.ScanSensitiveRootFilesAsync.09"),
                DescriptionText = MessageText.Create("Backend.Core.SteamSecurityScanner.ScanSensitiveRootFilesAsync.10"),
                Target = path,
                EvidenceText = $"{signature.Detail}；SHA-256={sha256}",
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
        VPetSteamUiInspector family = new(rules.KnownDomains);
        foreach (string root in new[] { Path.Combine(steamRoot, "steamui"), Path.Combine(steamRoot, "clientui"), Path.Combine(steamRoot, "resource") })
        {
            string[] files;
            MessageTextCollection discoveryNotes = [];
            try
            {
                files = root == Path.Combine(steamRoot, "resource")
                    ? File.Exists(Path.Combine(root, "webkit.css")) ? [Path.Combine(root, "webkit.css")] : []
                    : Directory.Exists(root)
                    ? ContentDiscovery.Files(root, discoveryNotes, 100_000, 32, cancellationToken)
                        .Where(path => Path.GetExtension(path).ToLowerInvariant() is ".js" or ".html" or ".css")
                        .Take(2001).ToArray()
                    : [];
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            { skippedFiles++; continue; }
            if (files.Length > 2000)
            {
                discoveryNotes.AddText(MessageText.Create("Backend.Core.SteamSecurityScanner.ScanSteamUiAsync.01", (root)));
                files = files[..2000];
            }
            if (discoveryNotes.Count > 0)
            {
                skippedFiles += discoveryNotes.Count;
                foreach (MessageText note in discoveryNotes.Texts.DistinctBy(n => n.OriginalText).Take(16)) report.AddCoverageNote(note);
                if (discoveryNotes.Count > 16)
                    report.AddCoverageNote(MessageText.Create("Backend.Core.SteamSecurityScanner.ScanSteamUiAsync.02", (System.FormattableString.Invariant($"{discoveryNotes.Count - 16:N0}"))));
            }

            foreach (string path in files)
            {
                cancellationToken.ThrowIfCancellationRequested();
                long length;
                try { length = new FileInfo(path).Length; }
                catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { skippedFiles++; continue; }
                if (length > MaximumScriptBytes || totalBytes + length > MaximumTotalScriptBytes)
                {
                    skippedFiles++;
                    continue;
                }

                string text, sha256; long capturedLength;
                try
                {
                    (text, sha256, capturedLength) = await ReadSteamUiSnapshotAsync(path,
                        Math.Min(MaximumScriptBytes, MaximumTotalScriptBytes - totalBytes), cancellationToken);
                    report.Metrics.BytesHashed += capturedLength;
                }
                catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or System.ComponentModel.Win32Exception or DecoderFallbackException)
                {
                    skippedFiles++;
                    continue;
                }
                totalBytes += capturedLength;
                checkedFiles++;
                family.Observe(Path.GetRelativePath(steamRoot, path), sha256, text);

                HashRule? known = FindKnownHash(sha256);
                List<MessageText> signals = Path.GetExtension(path).Equals(".js", StringComparison.OrdinalIgnoreCase) ? AnalyzeSteamUiMessages(text) : [];
                if (known?.Malware != true && signals.Count == 0) continue;

                bool highConfidence = known?.Malware == true || signals.Count >= 2;
                report.Findings.Add(new Finding
                {
                    RuleId = known?.Id ?? "STEAM-UI-SEMANTIC-TAMPERING",
                    Category = FindingCategory.Steam,
                    Severity = known?.Malware == true ? FindingSeverity.Critical : highConfidence ? FindingSeverity.High : FindingSeverity.Medium,
                    Score = known?.Malware == true ? 100 : highConfidence ? 90 : 55,
                    TitleText = known?.Malware == true ? MessageText.Create("Backend.Core.SteamSecurityScanner.ScanSteamUiAsync.03") : MessageText.Create("Backend.Core.SteamSecurityScanner.ScanSteamUiAsync.04"),
                    DescriptionText = MessageText.List(signals.Count == 0 ? [known!.LabelText] : signals),
                    Target = path,
                    EvidenceText = MessageText.Create("Backend.Core.SteamSecurityScanner.ScanSteamUiAsync.05", (sha256), (System.FormattableString.Invariant($"{capturedLength:N0}"))),
                    Sha256 = sha256,
                    IsKnownMalware = known?.Malware == true,
                    CanRemediate = highConfidence,
                    SuggestedActions = highConfidence
                        ? [SuggestedActionKind.QuarantineFile, SuggestedActionKind.BlockKnownDomains]
                        : [SuggestedActionKind.ReviewOnly]
                });
            }
        }

        foreach (var match in family.Complete())
        {
            report.Findings.Add(new()
            {
                RuleId = match.Evidence.SupportRoutesLinked ? "VPET-STEAM-UI-CHAIN" : "VPET-STEAM-UI-PROVIDER",
                Category = FindingCategory.Steam,
                Severity = FindingSeverity.High,
                Score = match.Evidence.SupportRoutesLinked ? 90 : 80,
                TitleText = match.Evidence.SupportRoutesLinked ? MessageText.Create("Backend.Core.SteamSecurityScanner.ScanSteamUiAsync.06") : MessageText.Create("Backend.Core.SteamSecurityScanner.ScanSteamUiAsync.07"),
                DescriptionText = (match.Evidence.SupportRoutesLinked ? MessageText.Create("Backend.Core.SteamSecurityScanner.ScanSteamUiAsync.08") :
                    MessageText.Create("Backend.Core.SteamSecurityScanner.ScanSteamUiAsync.09")) +
                    (match.Evidence.EntryReferenceVerified ? MessageText.Create("Backend.Core.SteamSecurityScanner.ScanSteamUiAsync.10") : MessageText.Create("Backend.Core.SteamSecurityScanner.ScanSteamUiAsync.11")) +
                    (match.Evidence.ActivationGateObserved ? MessageText.Create("Backend.Core.SteamSecurityScanner.ScanSteamUiAsync.12") : (MessageText)"") +
                    MessageText.Create("Backend.Core.SteamSecurityScanner.ScanSteamUiAsync.13"),
                Target = Path.Combine(steamRoot, match.Target.Replace('/', Path.DirectorySeparatorChar)),
                Sha256 = match.Hash,
                EvidenceText = string.Join("；", match.Evidence.Signals),
                SteamUiEvidence = match.Evidence,
                IsKnownMalware = false,
                CanRemediate = false,
                SuggestedActions = [SuggestedActionKind.ReviewOnly]
            });
        }
        if (family.Incomplete)
        {
            skippedFiles++; report.AddCoverageNote(MessageText.Create("Backend.Core.SteamSecurityScanner.ScanSteamUiAsync.14"));
        }
        report.AddCoverageNote(MessageText.Create("Backend.Core.SteamSecurityScanner.ScanSteamUiAsync.15", (checkedFiles), (System.FormattableString.Invariant($"{totalBytes / 1024.0 / 1024.0:N1}")), (skippedFiles)));
        if (skippedFiles > 0) report.Coverage = ScanCoverage.Partial;
    }

    private static async Task<(string Text, string Hash, long Length)> ReadSteamUiSnapshotAsync(string path, long maximumBytes, CancellationToken token)
    {
        await using FileStream stream = RelatedArtifactReader.Open(path);
        if (stream.Length > maximumBytes || stream.Length > int.MaxValue) throw MessageExceptions.Create(MessageText.Create("Backend.Core.SteamSecurityScanner.ReadSteamUiSnapshotAsync.01"), sourceText => new IOException(sourceText));
        byte[] bytes = new byte[checked((int)stream.Length)];
        try
        {
            await stream.ReadExactlyAsync(bytes, token);
            if (stream.ReadByte() != -1) throw MessageExceptions.Create(MessageText.Create("Backend.Core.SteamSecurityScanner.ReadSteamUiSnapshotAsync.02"), sourceText => new IOException(sourceText));
            string text = new UTF8Encoding(false, true).GetString(bytes);
            string hash = Convert.ToHexString(SHA256.HashData(bytes));
            RelatedArtifactReader.ValidatePath(stream.SafeFileHandle, Path.GetFullPath(path));
            return (text, hash, bytes.Length);
        }
        finally { Array.Clear(bytes); }
    }

    private static async Task<string> ReadUtf8BoundedAsync(string path, long maximumBytes, CancellationToken token)
    {
        await using FileStream stream = new(path, FileMode.Open, FileAccess.Read, FileShare.Read,
            64 * 1024, FileOptions.Asynchronous | FileOptions.SequentialScan);
        if (stream.Length > maximumBytes || maximumBytes >= int.MaxValue)
            throw MessageExceptions.Create(MessageText.Create("Backend.Core.SteamSecurityScanner.ReadUtf8BoundedAsync.01"), sourceText => new IOException(sourceText));
        byte[] bytes = new byte[(int)Math.Min(maximumBytes + 1, stream.Length + 1)];
        int total = 0;
        while (total < bytes.Length)
        {
            int read = await stream.ReadAsync(bytes.AsMemory(total), token);
            if (read == 0) break;
            total += read;
        }
        if (total > maximumBytes || stream.ReadByte() >= 0)
            throw MessageExceptions.Create(MessageText.Create("Backend.Core.SteamSecurityScanner.ReadUtf8BoundedAsync.02"), sourceText => new IOException(sourceText));
        return Encoding.UTF8.GetString(bytes, 0, total);
    }

    internal static List<string> AnalyzeSteamUi(string text) => AnalyzeSteamUiMessages(text).Select(message => message.OriginalText).ToList();

    internal static List<MessageText> AnalyzeSteamUiMessages(string text)
    {
        List<MessageText> signals = [];
        foreach ((string method, MessageText label) in new[]
        {
            ("BMustShowSupportAlertDialog", MessageText.Create("Backend.Core.SteamSecurityScanner.AnalyzeSteamUi.01")),
            ("BHasActiveSupportAlerts", MessageText.Create("Backend.Core.SteamSecurityScanner.AnalyzeSteamUi.02"))
        })
        {
            int index = text.IndexOf(method, StringComparison.Ordinal);
            if (index < 0) continue;
            string window = Slice(text, index, 420);
            Match constant = ConstantReturnRegex.Match(window);
            if (!constant.Success || constant.Index > 260) continue;
            string expression = Regex.Replace(constant.Groups["expr"].Value, @"\s+", string.Empty);
            bool? value = JavaScriptBoolean(expression);
            if (value is not null) signals.Add(MessageText.Create("Backend.Core.SteamSecurityScanner.AnalyzeSteamUi.03", (label), ((value.Value ? MessageText.Create("Backend.Core.SteamSecurityScanner.AnalyzeSteamUi.04") : MessageText.Create("Backend.Core.SteamSecurityScanner.AnalyzeSteamUi.05"))), (expression)));
        }

        int action = text.IndexOf("OnGameActionUserRequest", StringComparison.Ordinal);
        if (action >= 0)
        {
            string window = Slice(text, action, 1600);
            Match call = SupportAlertCallRegex.Match(window);
            int returnIndex = call.Success ? window.IndexOf("return", call.Index + call.Length, StringComparison.Ordinal) : -1;
            int switchIndex = window.IndexOf("switch", StringComparison.Ordinal);
            if (call.Success && returnIndex >= 0 && returnIndex - (call.Index + call.Length) < 90 && (switchIndex < 0 || call.Index < switchIndex))
                signals.Add(MessageText.Create("Backend.Core.SteamSecurityScanner.AnalyzeSteamUi.06"));
        }

        foreach (Match hidden in HiddenUrlBarRegex.Matches(text).Cast<Match>().Take(80))
        {
            string window = SliceCentered(text, hidden.Index, 1000);
            if (window.Contains("URLBar", StringComparison.OrdinalIgnoreCase) &&
                (window.Contains("bIsSecure", StringComparison.Ordinal) || window.Contains("Browser_NotSecure", StringComparison.Ordinal)))
            {
                signals.Add(MessageText.Create("Backend.Core.SteamSecurityScanner.AnalyzeSteamUi.07"));
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
        foreach (string host in routeHosts) signals.Add(MessageText.Create("Backend.Core.SteamSecurityScanner.AnalyzeSteamUi.08", (host)));
        return signals.DistinctBy(message => message.OriginalText, StringComparer.Ordinal).ToList();
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
