using System.IO;
using System.Reflection;
using System.Security.Cryptography;
using SteamSentinel.Core.Inspection;
using SteamSentinel.Core.Models;
using SteamSentinel.Core.Scanning;

namespace SteamSentinel.SelfTest;

internal static partial class Program
{
    private static async Task TestV030FalsePositiveFormatPathAsync(string root)
    {
        string directory = Path.Combine(root, "v030-false-positive-format-path");
        Directory.CreateDirectory(directory);
        // Inert PE recognition headers, never loaded or executed. The test-only hash rule
        // marks a distinct fixture, not real malicious content or a trusted publisher.
        byte[] normalBytes = [.. CreateV0117PeHeader(), .. "inert native addon format fixture"u8];
        byte[] hashBytes = [.. CreateV0117PeHeader(), .. "inert exact identity fixture only"u8];
        string normalNode = Path.Combine(directory, "normal.NODE");
        string disguisedPng = Path.Combine(directory, "disguised.png");
        string hashNode = Path.Combine(directory, "hash-match.node");
        await File.WriteAllBytesAsync(normalNode, normalBytes);
        await File.WriteAllBytesAsync(disguisedPng, normalBytes);
        await File.WriteAllBytesAsync(hashNode, hashBytes);
        string exactHash = Convert.ToHexString(SHA256.HashData(hashBytes));
        RuleSet hashRules = new()
        {
            KnownHashes = [new HashRule
            {
                Id = "TEST-NATIVE-ADDON-EXACT-HASH", Sha256 = exactHash,
                Label = "Inert exact hash fixture", Malware = true, Severity = FindingSeverity.Critical
            }]
        };

        FileTypeResult nodeType = await FileTypeDetector.DetectAsync(normalNode);
        Check("0.3.0 原生 NODE 扩展名与 PE 格式兼容且仍是可执行内容",
            nodeType.Type == DetectedFileType.PortableExecutable && !nodeType.ExtensionMismatch && nodeType.IsExecutableOrScript);
        ScanReport normal = await ScanV030FormatFixtureAsync(normalNode, hashRules);
        Check("0.3.0 正常 NODE 不因扩展名报警且仍读取文件哈希",
            normal.Findings.All(f => f.RuleId != "CONTENT-EXTENSION-MISMATCH" && !f.IsKnownMalware) &&
            normal.Metrics.BytesHashed >= normalBytes.Length);

        ScanReport disguised = await ScanV030FormatFixtureAsync(disguisedPng, hashRules);
        Check("0.3.0 PE 伪装 PNG 仍保留高风险格式不符提示",
            disguised.Findings.Any(f => f.RuleId == "CONTENT-EXTENSION-MISMATCH" && f.Severity == FindingSeverity.High));
        ScanReport exact = await ScanV030FormatFixtureAsync(hashNode, hashRules);
        Check("0.3.0 NODE 兼容不豁免精确恶意哈希检测及处置资格",
            exact.Findings.Any(f => f.RuleId == "TEST-NATIVE-ADDON-EXACT-HASH" &&
                f.Severity == FindingSeverity.Critical && f.IsKnownMalware && f.CanRemediate &&
                f.Sha256 == exactHash && f.TargetSha256 == exactHash &&
                f.SuggestedActions.Contains(SuggestedActionKind.QuarantineFile)) &&
            exact.Findings.All(f => f.RuleId != "CONTENT-EXTENSION-MISMATCH"));

        string emptyDirectory = Path.Combine(directory, "reused-drop-directory");
        Directory.CreateDirectory(emptyDirectory);
        string unconfirmedFile = Path.Combine(directory, "reused-drop-file.exe");
        await File.WriteAllTextAsync(unconfirmedFile, "inert file with a reused incident path");
        string unconfirmedHash = Convert.ToHexString(SHA256.HashData(await File.ReadAllBytesAsync(unconfirmedFile)));
        RuleSet pathRules = new()
        {
            KnownPathTemplates = [emptyDirectory, unconfirmedFile, hashNode],
            KnownHashes = [hashRules.KnownHashes[0], new HashRule
            {
                Id = "TEST-PATH-NONMALICIOUS-HASH", Sha256 = unconfirmedHash,
                Label = "Inert nonmalicious hash fixture", Malware = false, Remediable = true
            }]
        };
        ScanReport paths = new();
        MethodInfo scanKnownPaths = typeof(SystemScanner).GetMethod("ScanKnownPathsAsync", BindingFlags.Instance | BindingFlags.NonPublic)
            ?? throw new MissingMethodException(nameof(SystemScanner), "ScanKnownPathsAsync");
        await (Task)scanKnownPaths.Invoke(new SystemScanner(pathRules), [paths, CancellationToken.None])!;

        Finding directoryMatch = paths.Findings.Single(f => f.Target == emptyDirectory);
        Check("0.3.0 同名空目录仅为低风险路径观察且不能处置",
            directoryMatch is
            {
                RuleId: "KNOWN-DROP-PATH", Severity: FindingSeverity.Low, Score: 20,
                ReasonCode: "KnownPathOnly", IsKnownMalware: false, CanRemediate: false, Sha256: null
            } &&
            directoryMatch.SuggestedActions.SequenceEqual([SuggestedActionKind.ReviewOnly]));
        Finding fileMatch = paths.Findings.Single(f => f.Target == unconfirmedFile);
        Check("0.3.0 路径或非恶意哈希重合不会升级高风险或授予隔离",
            fileMatch is
            {
                Severity: FindingSeverity.Low, Score: 20, ReasonCode: "KnownPathOnly",
                IsKnownMalware: false, CanRemediate: false
            } && fileMatch.Sha256 == unconfirmedHash &&
            fileMatch.SuggestedActions.SequenceEqual([SuggestedActionKind.ReviewOnly]));
        Finding knownMatch = paths.Findings.Single(f => f.Target == hashNode);
        Check("0.3.0 已知路径及精确恶意哈希共同命中仍为严重且可隔离",
            knownMatch is
            {
                RuleId: "KNOWN-DROP-PATH", Severity: FindingSeverity.Critical, Score: 100,
                ReasonCode: null, IsKnownMalware: true, CanRemediate: true
            } && knownMatch.Sha256 == exactHash &&
            knownMatch.SuggestedActions.SequenceEqual([SuggestedActionKind.QuarantineFile, SuggestedActionKind.BlockKnownDomains]));
        Check("0.3.0 路径回归仅访问指定测试目标并保留原文件",
            paths.Findings.Count == 3 && File.Exists(unconfirmedFile) && File.Exists(hashNode) &&
            !Directory.EnumerateFileSystemEntries(emptyDirectory).Any());
    }

    private static async Task<ScanReport> ScanV030FormatFixtureAsync(string path, RuleSet rules)
    {
        ScanReport report = new();
        using ContentScanner scanner = new(rules);
        await scanner.ScanRootAsync(path, report, new ScanOptions
        {
            Mode = ScanMode.Custom,
            IncludeSystem = false,
            IncludeSteam = false,
            IncludeWorkshop = false,
            UseAmsi = false,
            InspectArchives = false,
            InspectDeepSignatures = false,
            HashEveryFile = true
        }, new NullPasswordProvider());
        return report;
    }
}
