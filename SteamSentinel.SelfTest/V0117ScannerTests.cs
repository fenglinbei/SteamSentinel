using System.Diagnostics;
using System.IO;
using System.IO.Compression;
using System.Text;
using SteamSentinel.Core.Inspection;
using SteamSentinel.Core.Models;
using SteamSentinel.Core.Rules;
using SteamSentinel.Core.Scanning;
using SteamSentinel.Core.Steam;
using SteamSentinel.Core.Utilities;

namespace SteamSentinel.SelfTest;

internal static partial class Program
{
    private static async Task TestV0117ScannerAsync(string root)
    {
        string directory = Path.Combine(root, "v0117-scanner");
        Directory.CreateDirectory(directory);
        RuleSet rules = RuleLoader.LoadEmbedded();

        FileTypeResult shortMz = FileTypeDetector.Detect([0x4D, 0x5A, 0, 0, 0, 0], ".mp4");
        FileTypeResult officeZip = FileTypeDetector.Detect([0x50, 0x4B, 0x03, 0x04], ".docm");
        FileTypeResult disguisedBzip = FileTypeDetector.Detect("BZh9"u8, ".txt");
        Check("短 MZ 不再冒充 PE，常见 ZIP 容器扩展名不误报", shortMz.Type == DetectedFileType.Unknown &&
            !shortMz.ExtensionMismatch && officeZip.Type == DetectedFileType.Zip && !officeZip.ExtensionMismatch &&
            disguisedBzip.Type == DetectedFileType.BZip2 && disguisedBzip.ExtensionMismatch);

        bool hashLimitRejected = false;
        try { await Hashing.Sha256StreamAsync(new MemoryStream([1, 2]), maximumBytes: 1); }
        catch (InvalidDataException) { hashLimitRejected = true; }
        Check("流式哈希严格拒绝读取期间超过上限的内容", hashLimitRejected);

        string falseDomain = Path.Combine(directory, "domain-boundary.txt");
        await File.WriteAllTextAsync(falseDomain, "https://notproconnector.cfd.example/inert");
        var falseSignals = await StreamingStringInspection.ReadAsync(falseDomain, [], ["proconnector.cfd"],
            1024 * 1024, CancellationToken.None);
        string trueDomain = Path.Combine(directory, "domain-subdomain.txt");
        await File.WriteAllTextAsync(trueDomain, "https://sub.proconnector.cfd/inert");
        var trueSignals = await StreamingStringInspection.ReadAsync(trueDomain, [], ["proconnector.cfd"],
            1024 * 1024, CancellationToken.None);
        string utf16Be = Path.Combine(directory, "utf16be.txt");
        await File.WriteAllBytesAsync(utf16Be, Encoding.BigEndianUnicode.GetBytes("prefix SteamKey20260310 suffix"));
        var wideSignals = await StreamingStringInspection.ReadAsync(utf16Be, ["SteamKey20260310"], [],
            1024 * 1024, CancellationToken.None);
        Check("域名按边界匹配且支持 UTF-16BE 规则字符串", !falseSignals.Raw.Contains("proconnector.cfd") &&
            trueSignals.Raw.Contains("proconnector.cfd") && wideSignals.Raw.Contains("SteamKey20260310"));

        string quickLarge = Path.Combine(directory, "quick-65mib.dat");
        await using (FileStream sparse = new(quickLarge, FileMode.CreateNew, FileAccess.Write, FileShare.None))
            sparse.SetLength(65L * 1024 * 1024);
        ScanReport quickReport = new();
        using (ContentScanner scanner = new(rules))
            await scanner.ScanRootAsync(quickLarge, quickReport, ScannerOptions(ScanMode.Quick), new NullPasswordProvider());
        Check("Quick 的 65 MiB 普通文件不再误报 Complete", quickReport.Metrics.BytesHashed == 0 &&
            quickReport.Coverage == ScanCoverage.Partial &&
            quickReport.CoverageAggregates.Any(item => item.RuleId == "QUICK-CONTENT-NOT-HASHED") &&
            quickReport.RootSummaries.Single().Coverage == ScanCoverage.Partial);

        string ordinaryZip = Path.Combine(directory, "ordinary-relative.zip");
        CreateZip(ordinaryZip, archive =>
        {
            using StreamWriter writer = new(archive.CreateEntry("./docs/readme.txt").Open());
            writer.Write("ordinary harmless archive member");
        });
        ScanReport ordinaryReport = new();
        using (ContentScanner scanner = new(rules))
            await scanner.ScanRootAsync(ordinaryZip, ordinaryReport, ScannerOptions(ScanMode.Full), new NullPasswordProvider());
        Check("压缩包 ./ 相对前缀不再误报路径穿越", ordinaryReport.Coverage == ScanCoverage.Complete &&
            ordinaryReport.Findings.All(finding => finding.RuleId != "ARCHIVE-PATH-TRAVERSAL"));

        string damagedByExtension = Path.Combine(directory, "damaged-header.zip");
        await File.WriteAllTextAsync(damagedByExtension, "harmless non-archive fixture");
        ScanReport damagedReport = new();
        using (ContentScanner scanner = new(rules))
            await scanner.ScanRootAsync(damagedByExtension, damagedReport, ScannerOptions(ScanMode.Full), new NullPasswordProvider());
        Check("归档扩展名即使魔数损坏也不会静默漏扫", damagedReport.Coverage == ScanCoverage.Partial &&
            damagedReport.Findings.Any(finding => finding.RuleId == "ARCHIVE-UNSUPPORTED") &&
            damagedReport.RootSummaries.Single().Coverage == ScanCoverage.Partial);

        string firstArchive = Path.Combine(directory, "global-budget-a.zip");
        string secondArchive = Path.Combine(directory, "global-budget-b.zip");
        CreateSizedZip(firstArchive, "a.bin", 700);
        CreateSizedZip(secondArchive, "b.bin", 700);
        ScanOptions globalBudgetOptions = ScannerOptions(ScanMode.Full, maximumExpandedBytes: 1024);
        ScanReport globalBudgetReport = new();
        using (ContentScanner scanner = new(rules))
        {
            await scanner.ScanRootAsync(firstArchive, globalBudgetReport, globalBudgetOptions, new NullPasswordProvider());
            await scanner.ScanRootAsync(secondArchive, globalBudgetReport, globalBudgetOptions, new NullPasswordProvider());
        }
        Check("归档展开预算在同一报告的多个根之间共享", globalBudgetReport.Metrics.ArchiveBytesExpanded == 700 &&
            globalBudgetReport.Coverage == ScanCoverage.Partial &&
            globalBudgetReport.RootSummaries[0].Coverage == ScanCoverage.Complete &&
            globalBudgetReport.RootSummaries[1].Coverage == ScanCoverage.Partial);

        string directoryEntries = Path.Combine(directory, "directory-entry-budget.zip");
        CreateZip(directoryEntries, archive =>
        {
            archive.CreateEntry("one/");
            archive.CreateEntry("two/");
            using StreamWriter writer = new(archive.CreateEntry("payload.txt").Open());
            writer.Write("inert");
        });
        ScanReport directoryEntryReport = new();
        using (ContentScanner scanner = new(rules))
            await scanner.ScanRootAsync(directoryEntries, directoryEntryReport, new ScanOptions
            {
                Mode = ScanMode.Full,
                IncludeSystem = false,
                IncludeSteam = false,
                IncludeWorkshop = false,
                UseAmsi = false,
                InspectArchives = true,
                HashEveryFile = true,
                MaximumArchiveEntries = 2
            }, new NullPasswordProvider());
        Check("空目录成员也消耗归档条目预算", directoryEntryReport.Coverage == ScanCoverage.Partial &&
            directoryEntryReport.Metrics.ArchiveEntriesVisited == 2 &&
            directoryEntryReport.CoverageNotes.Any(note => note.Contains("条目数达到上限", StringComparison.Ordinal)));

        string excluded = Path.Combine(directory, "excluded");
        Directory.CreateDirectory(excluded);
        await File.WriteAllTextAsync(Path.Combine(excluded, "inert.txt"), "inert");
        ScanReport excludedReport = new();
        using (ContentScanner scanner = new(rules))
            await scanner.ScanRootAsync(excluded, excludedReport, new ScanOptions
            {
                Mode = ScanMode.Full,
                IncludeSystem = false,
                IncludeSteam = false,
                IncludeWorkshop = false,
                UseAmsi = false,
                ExcludedRoots = [excluded]
            }, new NullPasswordProvider());
        Check("显式选择又排除的根会标记 Partial", excludedReport.Coverage == ScanCoverage.Partial &&
            excludedReport.Findings.Any(finding => finding.RuleId == "SCAN-EXCLUDED") &&
            excludedReport.RootSummaries.Single().Coverage == ScanCoverage.Partial);

        string steamRoot = Path.Combine(directory, "steam-root");
        string steamUi = Path.Combine(steamRoot, "steamui");
        Directory.CreateDirectory(steamUi);
        for (int i = 0; i < 2001; i++) await File.WriteAllTextAsync(Path.Combine(steamUi, $"inert-{i:D4}.js"), "// inert");
        SteamLayout layout = new();
        layout.SteamRoots.Add(steamRoot);
        ScanReport steamUiReport = new();
        await new SteamSecurityScanner(new RuleSet()).ScanAsync(layout, steamUiReport);
        Check("Steam UI 超过 2,000 个脚本会明确标记 Partial", steamUiReport.Coverage == ScanCoverage.Partial &&
            steamUiReport.CoverageNotes.Any(note => note.Contains("超过 2,000", StringComparison.Ordinal)));

        const string duplicateHash = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        bool duplicateRejected = false;
        try
        {
            RuleLoader.Validate(new RuleSet
            {
                Version = "synthetic",
                KnownHashes =
                [
                    new HashRule { Id = "ONE", Sha256 = duplicateHash, Label = "one" },
                    new HashRule { Id = "TWO", Sha256 = duplicateHash, Label = "two" }
                ]
            });
        }
        catch (InvalidDataException) { duplicateRejected = true; }
        Check("规则加载拒绝重复 SHA-256", duplicateRejected);

        await TestV0117PasswordBudgetAsync(directory, rules);
    }

    private static ScanOptions ScannerOptions(ScanMode mode, long maximumExpandedBytes = 2L * 1024 * 1024 * 1024) => new()
    {
        Mode = mode,
        IncludeSystem = false,
        IncludeSteam = false,
        IncludeWorkshop = false,
        UseAmsi = false,
        InspectArchives = true,
        HashEveryFile = mode != ScanMode.Quick,
        MaximumExpandedBytes = maximumExpandedBytes
    };

    private static void CreateSizedZip(string path, string name, int bytes)
    {
        using ZipArchive archive = ZipFile.Open(path, ZipArchiveMode.Create);
        using Stream output = archive.CreateEntry(name, CompressionLevel.NoCompression).Open();
        output.Write(new byte[bytes]);
    }

    private static async Task TestV0117PasswordBudgetAsync(string directory, RuleSet rules)
    {
        string? sevenZip = new[]
        {
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "7-Zip", "7z.exe"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "scoop", "apps", "7zip", "current", "7z.exe")
        }.FirstOrDefault(File.Exists);
        if (sevenZip is null) { Skip("0.1.17 错误密码预算回滚（缺少 7-Zip）"); return; }

        string input = Path.Combine(directory, "password-budget.txt");
        string archive = Path.Combine(directory, "password-budget.zip");
        await File.WriteAllTextAsync(input, "harmless encrypted fixture");
        ProcessStartInfo start = new(sevenZip)
        {
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardError = true,
            RedirectStandardOutput = true,
            WorkingDirectory = directory
        };
        foreach (string argument in new[] { "a", "-tzip", "-mem=AES256", "-pv0117-correct", archive, input })
            start.ArgumentList.Add(argument);
        using (Process process = Process.Start(start)!)
        {
            Task<string> stdout = process.StandardOutput.ReadToEndAsync();
            Task<string> stderr = process.StandardError.ReadToEndAsync();
            await process.WaitForExitAsync();
            await Task.WhenAll(stdout, stderr);
            if (process.ExitCode != 0) throw new InvalidOperationException("Cannot create inert encrypted archive fixture");
        }

        V0117Passwords passwords = new();
        ScanReport report = new();
        using (ContentScanner scanner = new(rules))
            await scanner.ScanRootAsync(archive, report, new ScanOptions
            {
                Mode = ScanMode.Full,
                IncludeSystem = false,
                IncludeSteam = false,
                IncludeWorkshop = false,
                UseAmsi = false,
                InspectArchives = true,
                HashEveryFile = true,
                MaximumArchiveEntries = 1
            }, passwords);
        Check("错误密码尝试不污染正确重试的条目预算", passwords.Requests == 2 &&
            report.Metrics.ArchiveEntriesVisited == 1 && report.Coverage == ScanCoverage.Complete &&
            report.CoverageNotes.All(note => !note.Contains("条目数达到上限", StringComparison.Ordinal)));
    }

    private sealed class V0117Passwords : IArchivePasswordProvider
    {
        public int Requests { get; private set; }

        public Task<ArchivePasswordResponse> RequestPasswordAsync(ArchivePasswordRequest request, CancellationToken token)
        {
            token.ThrowIfCancellationRequested();
            Requests++;
            string password = Requests == 1 ? "v0117-wrong" : "v0117-correct";
            return Task.FromResult(new ArchivePasswordResponse(request.RequestId, false, password, false,
                ArchivePasswordReuseScope.Session));
        }
    }
}
