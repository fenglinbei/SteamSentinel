using SteamSentinel.Core.Reporting;
using System.Text.RegularExpressions;
using System.Text;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Win32.SafeHandles;
using SteamSentinel.Core.Inspection;
using SteamSentinel.Core.Models;
using SteamSentinel.Core.Remediation;
using SteamSentinel.Core.Steam;
using SteamSentinel.Core.Utilities;

namespace SteamSentinel.Core.Scanning;

public sealed partial class SteamSecurityScanner(RuleSet rules)
{
    private readonly Func<string, SafeFileHandle?, SignatureResult>? _verifyBinarySignature;

    internal SteamSecurityScanner(RuleSet rules, Func<string, SafeFileHandle?, SignatureResult>? verifyBinarySignature)
        : this(rules) => _verifyBinarySignature = verifyBinarySignature;

    private const long MaximumScriptBytes = 32L * 1024 * 1024;
    private const long MaximumTotalScriptBytes = 256L * 1024 * 1024;
    private static readonly Regex ConstantReturnRegex = new(@"return\s*(?<expr>!!?\s*[01]|[01]|true|false)\s*(?:[;,}])", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant, TimeSpan.FromMilliseconds(100));
    private static readonly Regex SupportAlertCallRegex = new("ExecuteSteamURL\\s*\\(\\s*[\\\"']steam://open/supportalert[\\\"']\\s*\\)", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant, TimeSpan.FromMilliseconds(100));
    private static readonly Regex HiddenUrlBarRegex = new(@"style\s*:\s*\{\s*display\s*:\s*[""']none[""']\s*\}", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant, TimeSpan.FromMilliseconds(100));
    private static readonly Regex DirectRouteValueRegex = new(@"^[""']?\s*[:=]\s*[""'](?<url>https?://[^""'<>\s]+)", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant, TimeSpan.FromMilliseconds(100));
    private static readonly Regex RouteVariableValueRegex = new(@"^[""']?\s*:\s*(?<var>[$A-Z_a-z][$\w]*)", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant, TimeSpan.FromMilliseconds(100));
    private static readonly Regex UrlVariableRegex = new(@"(?<![$\w])(?<var>[$A-Z_a-z][$\w]*)\s*=\s*[""'](?<url>https?://[^""'<>\s]+)[""']", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant, TimeSpan.FromMilliseconds(100));
    private static readonly Regex CssSuppressionRegex = new("(?:\\.URLBar|#ReportItemBtn)[^{]{0,120}\\{[^}]{0,512}(?:display\\s*:\\s*none|visibility\\s*:\\s*hidden)", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant | RegexOptions.NonBacktracking, TimeSpan.FromMilliseconds(150));

    internal static bool HasCssSuppression(string text) => CssSuppressionRegex.IsMatch(text);

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
            SteamPackageCatalog.TryLoadForSteamRoot(steamRoot, out SteamPackageCatalog? catalog);
            await ScanSteamUiAsync(steamRoot, report, cancellationToken, catalog);
            await ScanSteamClientBinaryAsync(steamRoot, catalog, report, cancellationToken, _verifyBinarySignature);
            await ScanSensitiveRootFilesAsync(steamRoot, catalog, report, cancellationToken);
            await ScanSteamConfigurationFileAsync(Path.Combine(steamRoot, ".cef-enable-remote-debugging"),
                SteamConfigurationRepair.Marker, report, cancellationToken);

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
        await ScanSteamLaunchConfigurationAsync(layout, report, cancellationToken);
    }

    private static readonly string[] ExtendedInjectionDllNames =
    [
        "msacm32.drv",
        "winhttp.dll",
        "dinput8.dll",
        "dbghelp.dll"
    ];

    private async Task ScanSensitiveRootFilesAsync(
        string steamRoot,
        SteamPackageCatalog? catalog,
        ScanReport report,
        CancellationToken cancellationToken)
    {
        string cfgPath = Path.Combine(steamRoot, "steam.cfg");
        if (File.Exists(cfgPath))
            await ScanSteamConfigurationFileAsync(cfgPath, SteamConfigurationRepair.Cfg, report, cancellationToken);

        List<string> sensitiveDirectories = [];
        HashSet<string> seenDirectories = new(StringComparer.OrdinalIgnoreCase);
        void AddSensitiveDirectory(string candidate)
        {
            if (Directory.Exists(candidate) && ContentDiscovery.IsLocalSafePath(candidate))
            {
                string full = Path.GetFullPath(candidate);
                if (seenDirectories.Add(full)) sensitiveDirectories.Add(full);
            }
        }

        AddSensitiveDirectory(steamRoot);
        foreach (string relative in new[] { "bin", "win64", "steamui", "clientui", Path.Combine("bin", "cef") })
            AddSensitiveDirectory(Path.Combine(steamRoot, relative));

        string cefDirectory = Path.Combine(steamRoot, "bin", "cef");
        if (Directory.Exists(cefDirectory) && ContentDiscovery.IsLocalSafePath(cefDirectory))
        {
            try
            {
                foreach (string child in Directory.EnumerateDirectories(cefDirectory))
                    AddSensitiveDirectory(child);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                // 单个 CEF 子目录无权限读取时不阻断其余目录核验
            }
        }

        bool millenniumPresent = Directory.Exists(Path.Combine(steamRoot, "millennium"));
        bool hasMaliciousSteamFeatures = report.Findings.Any(f =>
            f.Severity >= FindingSeverity.High &&
            f.Category == FindingCategory.Steam &&
            ContentDiscovery.IsWithin(f.Target, steamRoot));
        string[] candidateDlls = rules.SteamInjectionNames
            .Concat(ExtendedInjectionDllNames)
            .Where(name => !name.Equals("steam.cfg", StringComparison.OrdinalIgnoreCase) &&
                           !name.Equals("versionOrg.dll", StringComparison.OrdinalIgnoreCase))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();

        foreach (string directory in sensitiveDirectories)
        {
            cancellationToken.ThrowIfCancellationRequested();
            HashSet<string> handled = new(StringComparer.OrdinalIgnoreCase);
            bool cefLocation = directory.Contains($"{Path.DirectorySeparatorChar}cef", StringComparison.OrdinalIgnoreCase);

            string forwarderPath = Path.Combine(directory, "versionOrg.dll");
            if (File.Exists(forwarderPath))
            {
                FileInfo forwarderInfo = new(forwarderPath);
                string forwarderSha256 = await Hashing.Sha256FileAsync(forwarderPath, cancellationToken,
                    bytes => report.Metrics.BytesHashed += bytes, maximumBytes: forwarderInfo.Length);
                HashRule? forwarderKnown = FindKnownHash(forwarderSha256);
                bool forwarderMalware = forwarderKnown?.Malware == true;
                bool forwarderOfficial = !forwarderMalware && await IsOfficialInstalledMatchAsync(steamRoot, forwarderPath, catalog, cancellationToken);
                handled.Add(forwarderPath);

                string versionPath = Path.Combine(directory, "version.dll");
                bool hasVersionDll = File.Exists(versionPath);
                string? versionSha256 = null;
                HashRule? versionKnown = null;
                if (hasVersionDll)
                {
                    FileInfo versionInfo = new(versionPath);
                    versionSha256 = await Hashing.Sha256FileAsync(versionPath, cancellationToken,
                        bytes => report.Metrics.BytesHashed += bytes, maximumBytes: versionInfo.Length);
                    versionKnown = FindKnownHash(versionSha256);
                    // 若 version.dll 本身尚未命中精确恶意哈希，则合并进转发链避免重复高危；若确认为已知恶意样本则留给下方单列可隔离项
                    if (versionKnown?.Malware != true)
                        handled.Add(versionPath);
                }

                if (!forwarderOfficial)
                {
                    SignatureResult forwarderSignature = VerifyRootFileSignature(forwarderPath);
                    bool forwarderTrusted = IsTrustedOfficialBinarySignature(forwarderSignature);
                    bool canRemediateForwarder = forwarderMalware || !forwarderTrusted;
                    report.Findings.Add(new Finding
                    {
                        RuleId = forwarderKnown?.Id ?? "STEAM-DLL-VERSION-FORWARDER",
                        Category = FindingCategory.Steam,
                        Severity = forwarderMalware ? FindingSeverity.Critical : FindingSeverity.High,
                        Score = forwarderMalware ? 100 : 90,
                        TitleText = MessageText.Create("Steam.DllForwarder.Title"),
                        DescriptionText = MessageText.Create("Steam.DllForwarder.Description"),
                        Target = forwarderPath,
                        EvidenceText = hasVersionDll
                            ? MessageText.Create("Steam.DllForwarder.EvidencePair", forwarderSignature.DetailText, forwarderSha256, versionSha256 ?? string.Empty)
                            : MessageText.Create("Steam.DllForwarder.EvidenceSingle", forwarderSignature.DetailText, forwarderSha256),
                        HandlingDetailsText = !forwarderMalware && canRemediateForwarder
                            ? MessageText.Create("Steam.ProxyDll.QuarantineHandling")
                            : (MessageText)"",
                        Sha256 = forwarderSha256,
                        TargetSha256 = canRemediateForwarder ? forwarderSha256 : null,
                        IsKnownMalware = forwarderMalware,
                        CanRemediate = canRemediateForwarder,
                        SuggestedActions = canRemediateForwarder
                            ? [SuggestedActionKind.QuarantineFile]
                            : [SuggestedActionKind.ReviewOnly]
                    });
                }
            }

            foreach (string name in candidateDlls)
            {
                cancellationToken.ThrowIfCancellationRequested();
                string path = Path.Combine(directory, name);
                if (!File.Exists(path) || handled.Contains(path)) continue;

                FileInfo info = new(path);
                string sha256 = await Hashing.Sha256FileAsync(path, cancellationToken,
                    bytes => report.Metrics.BytesHashed += bytes, maximumBytes: info.Length);
                HashRule? known = FindKnownHash(sha256);
                bool knownMalware = known?.Malware == true;
                if (!knownMalware && await IsOfficialInstalledMatchAsync(steamRoot, path, catalog, cancellationToken))
                    continue;

                SignatureResult signature = VerifyRootFileSignature(path);
                bool trustedValve = signature.Status == SignatureStatus.Valid &&
                    (signature.IsValveSigner || AuthenticodeVerifier.IsTrustedValveSigner(signature.Status, signature.SignerSubject));
                bool trustedMicrosoft = signature.Status == SignatureStatus.Valid &&
                    IsTrustedMicrosoftSigner(signature.Status, signature.SignerSubject);
                bool trustedSigner = trustedValve || trustedMicrosoft;
                bool acknowledgedMod = millenniumPresent &&
                    name.Equals("wsock32.dll", StringComparison.OrdinalIgnoreCase) &&
                    signature.Status is SignatureStatus.Valid or SignatureStatus.Unsigned;

                FindingSeverity severity;
                int score;
                if (knownMalware)
                {
                    severity = FindingSeverity.Critical;
                    score = 100;
                }
                else if (trustedSigner)
                {
                    severity = FindingSeverity.Low;
                    score = 15;
                }
                else if (signature.Status is SignatureStatus.Invalid or SignatureStatus.HashMismatch or SignatureStatus.Untrusted || cefLocation)
                {
                    severity = FindingSeverity.High;
                    score = 85;
                }
                else if (acknowledgedMod)
                {
                    severity = FindingSeverity.Medium;
                    score = 45;
                }
                else
                {
                    severity = FindingSeverity.High;
                    score = 75;
                }

                bool coOccurs = hasMaliciousSteamFeatures || File.Exists(Path.Combine(directory, "versionOrg.dll"));
                bool canRemediateProxy = knownMalware ||
                    (!acknowledgedMod && !trustedSigner && severity >= FindingSeverity.High &&
                     (signature.Status != SignatureStatus.Valid || coOccurs));

                MessageText titleText = knownMalware
                    ? MessageText.Create("Backend.Core.SteamSecurityScanner.ScanSensitiveRootFilesAsync.08")
                    : signature.IsValveSigner
                        ? MessageText.Create("Steam.ProxyDll.SeverityTitle.Valve")
                        : MessageText.Create("Backend.Core.SteamSecurityScanner.ScanSensitiveRootFilesAsync.09");

                MessageText evidenceText = string.IsNullOrWhiteSpace(signature.SignerSubject)
                    ? $"{signature.Detail}；SHA-256={sha256}"
                    : MessageText.Create("Steam.ProxyDll.EvidenceWithSigner", signature.DetailText, signature.SignerSubject, sha256);

                report.Findings.Add(new Finding
                {
                    RuleId = known?.Id ?? "STEAM-PROXY-DLL-PRESENT",
                    Category = FindingCategory.Steam,
                    Severity = severity,
                    Score = score,
                    TitleText = titleText,
                    DescriptionText = MessageText.Create("Backend.Core.SteamSecurityScanner.ScanSensitiveRootFilesAsync.10"),
                    HandlingDetailsText = !knownMalware && canRemediateProxy
                        ? MessageText.Create("Steam.ProxyDll.QuarantineHandling")
                        : (MessageText)"",
                    Target = path,
                    EvidenceText = evidenceText,
                    Sha256 = sha256,
                    TargetSha256 = canRemediateProxy ? sha256 : null,
                    IsKnownMalware = knownMalware,
                    CanRemediate = canRemediateProxy,
                    SuggestedActions = canRemediateProxy
                        ? [SuggestedActionKind.QuarantineFile]
                        : [SuggestedActionKind.ReviewOnly]
                });
            }
        }
    }

    internal Task ScanSteamUiAsync(string steamRoot, ScanReport report, CancellationToken cancellationToken)
    {
        SteamPackageCatalog.TryLoadForSteamRoot(steamRoot, out SteamPackageCatalog? catalog);
        return ScanSteamUiAsync(steamRoot, report, cancellationToken, catalog);
    }

    internal async Task ScanSteamUiAsync(
        string steamRoot,
        ScanReport report,
        CancellationToken cancellationToken,
        SteamPackageCatalog? catalog)
    {
        long totalBytes = 0;
        int checkedFiles = 0;
        int skippedFiles = 0;
        VPetSteamUiInspector family = new(rules.KnownDomains);
        Dictionary<string, (string FullPath, string Sha256, long Length, uint Crc32)> observedSnapshots = new(StringComparer.OrdinalIgnoreCase);
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

                string text, sha256; long capturedLength; uint crc32;
                try
                {
                    (text, sha256, capturedLength, crc32) = await ReadSteamUiSnapshotAsync(path,
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
                string relativePath = Path.GetRelativePath(steamRoot, path);
                string normalizedRel = relativePath.Replace('\\', '/');
                observedSnapshots[normalizedRel] = (Path.GetFullPath(path), sha256, capturedLength, crc32);
                family.Observe(relativePath, sha256, text);

                bool isKnownOfficialDeviating = IsOfficialDeviating(catalog, normalizedRel, capturedLength, crc32);
                HashRule? known = FindKnownHash(sha256);
                bool isCss = Path.GetExtension(path).Equals(".css", StringComparison.OrdinalIgnoreCase);
                if (isCss && HasCssSuppression(text) &&
                    (path.Equals(Path.Combine(steamRoot, "resource", "webkit.css"), StringComparison.OrdinalIgnoreCase) || isKnownOfficialDeviating))
                {
                    report.Findings.Add(new Finding
                    {
                        RuleId = "STEAM-UI-CSS-SUPPRESSION",
                        Category = FindingCategory.Steam,
                        Severity = FindingSeverity.High,
                        Score = 85,
                        TitleText = MessageText.Create("Steam.UiCssSuppression.Title"),
                        DescriptionText = MessageText.Create("Steam.UiCssSuppression.Description"),
                        EvidenceText = MessageText.Create("Steam.UiCssSuppression.Evidence", sha256),
                        HandlingDetailsText = isKnownOfficialDeviating
                            ? MessageText.Create("SteamConfig.PackageRestoreDescription")
                            : (MessageText)"",
                        Sha256 = sha256,
                        TargetSha256 = isKnownOfficialDeviating ? sha256 : null,
                        ConfigurationKind = isKnownOfficialDeviating ? SteamConfigurationRepair.PackageRestore : null,
                        Target = path,
                        IsKnownMalware = false,
                        CanRemediate = isKnownOfficialDeviating,
                        SuggestedActions = isKnownOfficialDeviating
                            ? [SuggestedActionKind.RepairSteamConfiguration]
                            : [SuggestedActionKind.ReviewOnly]
                    });
                }

                bool isScript = Path.GetExtension(path).Equals(".js", StringComparison.OrdinalIgnoreCase);
                LoopbackScriptReference? loopback = isScript ? SteamUiLoopbackInspector.Find(text) : null;
                if (loopback is not null) report.Findings.Add(CreateLoopbackFinding(steamRoot, path, sha256, loopback, isKnownOfficialDeviating));
                LoopbackScriptReference? external = isScript ? SteamUiLoopbackInspector.FindExternal(text) : null;
                if (external is not null) report.Findings.Add(CreateExternalScriptFinding(path, sha256, external, isKnownOfficialDeviating));
                List<MessageText> signals = isScript ? AnalyzeSteamUiMessages(text) : [];
                if (known?.Malware != true && signals.Count == 0) continue;

                bool isMalwareFile = known?.Malware == true;
                bool highConfidence = isMalwareFile || signals.Count >= 2;
                bool canPackageRestore = !isMalwareFile && isKnownOfficialDeviating && IsSupportedPackageRestoreUiPath(steamRoot, path);
                // 无官方分包清单时沿用原有高置信与非回环门禁，避免误删可能被局部修改的核心 chunk；
                // 存在官方分包清单且命中官方路径时直接开放原位 PackageRestore 覆盖还原。
                bool isRemediableUiFile = !isMalwareFile && !canPackageRestore && highConfidence && isScript && loopback is null &&
                    (ContentDiscovery.IsWithin(path, Path.Combine(steamRoot, "steamui")) ||
                     ContentDiscovery.IsWithin(path, Path.Combine(steamRoot, "clientui")));
                bool canRemediate = isMalwareFile || canPackageRestore || isRemediableUiFile;
                report.Findings.Add(new Finding
                {
                    RuleId = known?.Id ?? "STEAM-UI-SEMANTIC-TAMPERING",
                    Category = FindingCategory.Steam,
                    Severity = isMalwareFile ? FindingSeverity.Critical : highConfidence ? FindingSeverity.High : FindingSeverity.Medium,
                    Score = isMalwareFile ? 100 : highConfidence ? 90 : 55,
                    TitleText = isMalwareFile ? MessageText.Create("Backend.Core.SteamSecurityScanner.ScanSteamUiAsync.03") : MessageText.Create("Backend.Core.SteamSecurityScanner.ScanSteamUiAsync.04"),
                    DescriptionText = MessageText.List(signals.Count == 0 ? [known!.LabelText] : signals),
                    Target = path,
                    EvidenceText = MessageText.Create("Backend.Core.SteamSecurityScanner.ScanSteamUiAsync.05", (sha256), (System.FormattableString.Invariant($"{capturedLength:N0}"))),
                    HandlingDetailsText = canPackageRestore
                        ? MessageText.Create("SteamConfig.PackageRestoreDescription")
                        : isRemediableUiFile ? MessageText.Create("SteamConfig.UiFileHandling") : (MessageText)"",
                    Sha256 = sha256,
                    TargetSha256 = canRemediate ? sha256 : null,
                    ConfigurationKind = canPackageRestore ? SteamConfigurationRepair.PackageRestore : isRemediableUiFile ? SteamConfigurationRepair.UiFile : null,
                    IsKnownMalware = isMalwareFile,
                    CanRemediate = canRemediate,
                    SuggestedActions = isMalwareFile
                        ? [SuggestedActionKind.QuarantineFile, SuggestedActionKind.BlockKnownDomains]
                        : canPackageRestore || isRemediableUiFile ? [SuggestedActionKind.RepairSteamConfiguration] : [SuggestedActionKind.ReviewOnly]
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

            if (catalog is null) continue;
            foreach (SteamUiEvidenceFile participant in match.Evidence.Files)
            {
                if (!SteamPackageCatalog.TryNormalizeRelativePath(participant.RelativePath, out string relPath) ||
                    !observedSnapshots.TryGetValue(relPath, out var snapshot) ||
                    !IsOfficialDeviating(catalog, relPath, snapshot.Length, snapshot.Crc32) ||
                    !IsSupportedPackageRestoreUiPath(steamRoot, snapshot.FullPath))
                    continue;

                bool alreadyRemediable = report.Findings.Any(f =>
                    f.CanRemediate &&
                    (f.ConfigurationKind is SteamConfigurationRepair.PackageRestore or SteamConfigurationRepair.UiFile ||
                     f.SuggestedActions.Contains(SuggestedActionKind.QuarantineFile)) &&
                    RelatedArtifactRelations.SamePath(f.Target, snapshot.FullPath));
                if (alreadyRemediable) continue;

                bool isCssParticipant = relPath.EndsWith(".css", StringComparison.OrdinalIgnoreCase);
                report.Findings.Add(new Finding
                {
                    RuleId = isCssParticipant ? "STEAM-UI-CSS-SUPPRESSION" : "STEAM-UI-SEMANTIC-TAMPERING",
                    Category = FindingCategory.Steam,
                    Severity = FindingSeverity.High,
                    Score = 85,
                    TitleText = MessageText.Create(isCssParticipant ? "Steam.UiCssSuppression.Title" : "Steam.UiPackageParticipant.Title"),
                    DescriptionText = MessageText.Create(isCssParticipant ? "Steam.UiCssSuppression.Description" : "Steam.UiPackageParticipant.Description"),
                    EvidenceText = MessageText.Create("Steam.UiPackageParticipant.Evidence", relPath, snapshot.Sha256),
                    HandlingDetailsText = MessageText.Create("SteamConfig.PackageRestoreDescription"),
                    Sha256 = snapshot.Sha256,
                    TargetSha256 = snapshot.Sha256,
                    ConfigurationKind = SteamConfigurationRepair.PackageRestore,
                    Target = snapshot.FullPath,
                    IsKnownMalware = false,
                    CanRemediate = true,
                    SuggestedActions = [SuggestedActionKind.RepairSteamConfiguration]
                });
            }
        }
        if (family.Incomplete)
        {
            skippedFiles++; report.AddCoverageNote(MessageText.Create("Backend.Core.SteamSecurityScanner.ScanSteamUiAsync.14"));
        }
        report.AddCoverageNote(MessageText.Create("Backend.Core.SteamSecurityScanner.ScanSteamUiAsync.15", (checkedFiles), (System.FormattableString.Invariant($"{totalBytes / 1024.0 / 1024.0:N1}")), (skippedFiles)));
        if (skippedFiles > 0) report.Coverage = ScanCoverage.Partial;
    }

    private SignatureResult VerifyRootFileSignature(string path) =>
        _verifyBinarySignature is not null
            ? _verifyBinarySignature(path, null)
            : AuthenticodeVerifier.VerifyOffline(path);

    private static bool IsTrustedOfficialBinarySignature(SignatureResult signature) =>
        signature.Status == SignatureStatus.Valid &&
        (signature.IsValveSigner ||
         AuthenticodeVerifier.IsTrustedValveSigner(signature.Status, signature.SignerSubject) ||
         IsTrustedMicrosoftSigner(signature.Status, signature.SignerSubject));

    private static bool IsTrustedMicrosoftSigner(SignatureStatus status, string? subject)
    {
        if (status != SignatureStatus.Valid || string.IsNullOrWhiteSpace(subject)) return false;
        try
        {
            X500DistinguishedName name = new(subject);
            bool found = false;
            foreach (X500RelativeDistinguishedName attribute in name.EnumerateRelativeDistinguishedNames())
            {
                if (attribute.HasMultipleElements) return false;
                string? oid = attribute.GetSingleElementType().Value;
                if (oid is not ("2.5.4.3" or "2.5.4.10")) continue;
                string? value = attribute.GetSingleElementValue();
                if (!string.Equals(value, "Microsoft Corporation", StringComparison.OrdinalIgnoreCase) &&
                    !string.Equals(value, "Microsoft Windows", StringComparison.OrdinalIgnoreCase))
                    return false;
                found = true;
            }
            return found;
        }
        catch (Exception ex) when (ex is CryptographicException or ArgumentException or InvalidOperationException)
        {
            return false;
        }
    }

    private static bool IsOfficialDeviating(SteamPackageCatalog? catalog, string normalizedRel, long length, uint crc32) =>
        catalog is not null &&
        catalog.TryGetInstalledEntry(normalizedRel, out SteamInstalledFileEntry? entry) &&
        !entry.IsDirectory &&
        (length != entry.Size || crc32 != entry.Crc32);

    private static bool IsSupportedPackageRestoreUiPath(string steamRoot, string fullPath) =>
        ContentDiscovery.IsWithin(fullPath, Path.Combine(steamRoot, "steamui")) ||
        ContentDiscovery.IsWithin(fullPath, Path.Combine(steamRoot, "clientui")) ||
        Path.GetFullPath(fullPath).Equals(Path.GetFullPath(Path.Combine(steamRoot, "resource", "webkit.css")), StringComparison.OrdinalIgnoreCase);

    private static async Task<bool> IsOfficialInstalledMatchAsync(
        string steamRoot,
        string path,
        SteamPackageCatalog? catalog,
        CancellationToken token)
    {
        if (catalog is null || !catalog.HasVerifiedInstalledIndex) return false;
        string rel = Path.GetRelativePath(steamRoot, path);
        if (!catalog.TryGetInstalledEntry(rel, out SteamInstalledFileEntry? entry) || entry.IsDirectory)
            return false;
        try
        {
            await using FileStream stream = RelatedArtifactReader.Open(path);
            if (stream.Length != entry.Size || stream.Length > SteamPackageArchive.MaximumExtractedFileBytes)
                return false;
            uint crc = 0xFFFFFFFFu;
            byte[] buffer = new byte[64 * 1024];
            while (true)
            {
                int read = await stream.ReadAsync(buffer, token).ConfigureAwait(false);
                if (read == 0) break;
                crc = SteamPackageArchive.UpdateCrc32(crc, buffer.AsSpan(0, read));
            }
            return (crc ^ 0xFFFFFFFFu) == entry.Crc32;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or System.ComponentModel.Win32Exception)
        {
            return false;
        }
    }

    private static async Task<(string Text, string Hash, long Length, uint Crc32)> ReadSteamUiSnapshotAsync(string path, long maximumBytes, CancellationToken token)
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
            uint crc32 = SteamPackageArchive.ComputeCrc32(bytes);
            RelatedArtifactReader.ValidatePath(stream.SafeFileHandle, Path.GetFullPath(path));
            return (text, hash, bytes.Length, crc32);
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
