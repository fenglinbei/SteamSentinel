using System.Diagnostics;
using System.IO;
using System.Text;
using SteamSentinel.App.Services;
using SteamSentinel.App.ViewModels;
using SteamSentinel.Core.Inspection;
using SteamSentinel.Core.Models;
using SteamSentinel.Core.Remediation;
using SteamSentinel.Core.Scanning;
using SteamSentinel.Core.Utilities;

namespace SteamSentinel.SelfTest;

internal static partial class Program
{
    private static ScanOptions ContentOptions() => new()
    {
        Mode = ScanMode.Custom,
        IncludeSystem = false,
        IncludeSteam = false,
        IncludeWorkshop = false,
        UseAmsi = false,
        InspectArchives = true,
        HashEveryFile = true
    };

    private static async Task TestV015Async(string root, RuleSet rules)
    {
        string directory = Path.Combine(root, "v015");
        Directory.CreateDirectory(directory);
        // Inert keyword fixture, no executable JavaScript or malware behavior.
        const string markers = "steam_save_mafile steam_outbox_list /api/v1/plugin/beacon password";
        string wide = Path.Combine(directory, "wide.txt");
        await File.WriteAllTextAsync(wide, markers, Encoding.Unicode);
        ScanReport report = new();
        using (ContentScanner scanner = new(rules))
            await scanner.ScanRootAsync(wide, report, ContentOptions(), new NullPasswordProvider());
        Finding? match = report.Findings.FirstOrDefault(f => f.RuleId == "HEUR-STEAM-CREDENTIAL-PLUGIN");
        Check("UTF-16 组合规则可手选、不默认勾选", match is { CanRemediate: true, IsKnownMalware: false } &&
            !new FindingItemViewModel(match).IsSelected);
        Check("扫描内容与目标身份独立记录", match?.TargetSha256 == await Hashing.Sha256FileAsync(wide) && match.ContentPath == wide);
        await File.AppendAllTextAsync(wide, "changed");
        bool rejected = false;
        try { await new RemediationPlanBuilder(rules).BuildAsync([match!], false); }
        catch (InvalidDataException) { rejected = true; }
        Check("拒绝隔离扫描后已变化的目标", rejected);

        string doc = Path.Combine(directory, "analysis.md");
        await File.WriteAllTextAsync(doc, markers + " SteamKey20260310 /downloadlog/");
        ScanReport documentation = new();
        using (ContentScanner scanner = new(rules))
            await scanner.ScanRootAsync(doc, documentation, ContentOptions(), new NullPasswordProvider());
        Check("分析文档引用特征不升级为可处置病毒", documentation.Findings.All(f => !f.CanRemediate && !f.IsKnownMalware));

        string zip = Path.Combine(directory, "nested.zip");
        CreateZip(zip, archive =>
        {
            foreach (string name in new[] { "one.txt", "two.txt" })
            {
                using StreamWriter writer = new(archive.CreateEntry(name).Open());
                writer.Write(markers);
            }
        });
        ScanReport nested = new();
        using (ContentScanner scanner = new(rules))
            await scanner.ScanRootAsync(zip, nested, ContentOptions(), new NullPasswordProvider());
        Finding[] actionable = nested.Findings.Where(f => f.CanRemediate).ToArray();
        RemediationPlan plan = await new RemediationPlanBuilder(rules).BuildAsync(actionable, false);
        Check("两个命中成员只隔离一个外层包", actionable.Length == 2 && plan.Actions.Count == 1 && plan.Actions[0].Target == zip);
        Check("成员 SHA 与外层 SHA 不混用", actionable.All(f => f.Sha256 != f.TargetSha256 && f.ContentPath!.Contains("!/", StringComparison.Ordinal)) &&
            plan.Actions[0].ExpectedSha256 == await Hashing.Sha256FileAsync(zip));

        const string inertKnownContent = "inert exact hash fixture";
        RuleSet fixtureRules = new()
        {
            KnownHashes = [new HashRule { Id = "SYNTHETIC-HASH", Sha256 = Convert.ToHexString(
                System.Security.Cryptography.SHA256.HashData(Encoding.UTF8.GetBytes(inertKnownContent))), Label = "Synthetic only" }]
        };
        string renamed = Path.Combine(directory, "renamed.mp4");
        CreateZip(renamed, archive =>
        {
            using StreamWriter writer = new(archive.CreateEntry("renamed.data").Open(), new UTF8Encoding(false));
            writer.Write(inertKnownContent);
        });
        ScanReport exact = new();
        using (ContentScanner scanner = new(fixtureRules))
            await scanner.ScanRootAsync(renamed, exact, ContentOptions(), new NullPasswordProvider());
        Finding? exactMatch = exact.Findings.FirstOrDefault(f => f.IsKnownMalware);
        Check("已知成员重新打包和改名仍命中内容哈希", exactMatch is { CanRemediate: true } && exactMatch.Target == renamed &&
            exactMatch.ContentPath!.EndsWith("!/renamed.data", StringComparison.Ordinal));

        string mp4 = Path.Combine(directory, "media.mp4");
        await using (FileStream output = File.Create(mp4))
        {
            await output.WriteAsync(CreateMinimalMp4());
            await using FileStream input = File.OpenRead(zip);
            await input.CopyToAsync(output);
        }
        ScanReport overlay = new();
        using (ContentScanner scanner = new(rules))
            await scanner.ScanRootAsync(mp4, overlay, ContentOptions(), new NullPasswordProvider());
        Check("MP4 尾随归档递归检测与外层处置", overlay.Findings.Any(f => f.CanRemediate && f.Target == mp4 && f.ContentPath!.Contains("尾随内容", StringComparison.Ordinal)));
        using (TemporaryDirectory temporary = new())
            Check("扫描临时副本不使用可执行扩展名", Path.GetExtension(temporary.CreateFilePath("danger.exe")) == ".scan");

        string compound = Path.Combine(directory, "disguised.mp4");
        await File.WriteAllBytesAsync(compound, [0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1]);
        ScanReport msi = new();
        using (ContentScanner scanner = new(rules))
            await scanner.ScanRootAsync(compound, msi, ContentOptions(), new NullPasswordProvider());
        Check("无法解析的结构化安装包不伪报完整", msi.Coverage == ScanCoverage.Partial && msi.Findings.Any(f => f.RuleId == "INSTALLER-PARTIAL"));
        Check("逐路径报告保留覆盖与告警", msi.RootSummaries.Single().Coverage == ScanCoverage.Partial && nested.RootSummaries.Single().ActionableFindings == 2);
        ScanReport cancelled = new();
        using (ContentScanner scanner = new(rules))
        {
            try { await scanner.ScanRootAsync(doc, cancelled, ContentOptions(), new NullPasswordProvider(), cancellationToken: new CancellationToken(true)); }
            catch (OperationCanceledException) { }
        }
        Check("取消中的路径不标记为完整扫描", cancelled.Coverage == ScanCoverage.Partial && cancelled.RootSummaries.Single().Coverage == ScanCoverage.Partial);
        ScanReport unavailable = new();
        using (ContentScanner scanner = new(rules))
        {
            var addAmsiCoverage = typeof(ContentScanner).GetMethod("AddAmsiCoverage",
                System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic)!;
            void SimulateUnavailable() => addAmsiCoverage.Invoke(scanner, [unavailable, "synthetic unavailable provider"]);
            SimulateUnavailable();
            await scanner.ScanRootAsync(doc, unavailable, ContentOptions(), new NullPasswordProvider(),
                new InlineScanProgress(_ => SimulateUnavailable()));
        }
        Check("合并 AMSI 提示后仍保留逐路径覆盖缺口", unavailable.CoverageNotes.Count == 1 && unavailable.RootSummaries.Single().Coverage == ScanCoverage.Partial);
        string gzip = Path.Combine(directory, "unnamed.gz");
        await using (FileStream output = File.Create(gzip))
        await using (System.IO.Compression.GZipStream stream = new(output, System.IO.Compression.CompressionMode.Compress))
            await stream.WriteAsync("harmless unnamed stream"u8.ToArray());
        ScanReport unnamed = new();
        using (ContentScanner scanner = new(rules))
            await scanner.ScanRootAsync(gzip, unnamed, ContentOptions(), new NullPasswordProvider());
        Check("无内嵌文件名的 GZip 不误报路径穿越", unnamed.Findings.All(f => f.RuleId != "ARCHIVE-PATH-TRAVERSAL" && !f.CanRemediate));
        var passwordFailure = typeof(ContentScanner).GetMethod("LooksLikePasswordFailure",
            System.Reflection.BindingFlags.Static | System.Reflection.BindingFlags.NonPublic)!;
        Check("安全软件或文件占用错误不误当密码错误", !(bool)passwordFailure.Invoke(null,
            [new IOException("Cannot access C:\\密码\\encrypted.zip, file is used by another process")])!);

        string? tool = FindArchiveTool(out bool useRar);
        if (tool is null) { Skip("密码复用作用域（缺少测试归档工具）"); return; }
        string note = Path.Combine(directory, "note.txt");
        await File.WriteAllTextAsync(note, "harmless password fixture");
        string extension = useRar ? ".rar" : ".zip";
        async Task<string> Encrypt(string name, params string[] entries)
        {
            string output = Path.Combine(directory, name + extension);
            ProcessStartInfo start = new(tool)
            {
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                WorkingDirectory = directory
            };
            string[] flags = useRar ? ["a", "-idq", "-ep", "-ptestpass"] : ["a", "-tzip", "-mem=AES256", "-ptestpass"];
            foreach (string arg in flags.Concat([output]).Concat(entries)) start.ArgumentList.Add(arg);
            using Process process = Process.Start(start)!;
            Task<string> stdout = process.StandardOutput.ReadToEndAsync();
            Task<string> stderr = process.StandardError.ReadToEndAsync();
            await process.WaitForExitAsync();
            await Task.WhenAll(stdout, stderr);
            if (process.ExitCode != 0) throw new InvalidOperationException("Cannot create encrypted fixture");
            return output;
        }
        string a = await Encrypt("a", note);
        await File.WriteAllTextAsync(note, "different harmless password fixture");
        string b = await Encrypt("b", note);
        string outer = await Encrypt("outer", a, b);
        async Task<(ScanReport Report, int Prompts)> ScanPassword(ArchivePasswordReuseScope scope, string[] paths, params string?[] passwords)
        {
            SequencePasswords provider = new(scope, passwords);
            ScanReport result = new();
            using ContentScanner scanner = new(rules);
            foreach (string path in paths) await scanner.ScanRootAsync(path, result, ContentOptions(), provider);
            return (result, provider.Count);
        }
        var tree = await ScanPassword(ArchivePasswordReuseScope.ArchiveTree, [outer], "testpass");
        Check("同一外层文件的嵌套密码只询问一次", tree.Prompts == 1 && tree.Report.Coverage == ScanCoverage.Complete);
        var only = await ScanPassword(ArchivePasswordReuseScope.CurrentOnly, [outer], "testpass");
        Check("仅当前层不越界复用密码", only.Prompts == 3 && only.Report.Coverage == ScanCoverage.Complete);
        var session = await ScanPassword(ArchivePasswordReuseScope.Session, [a, b], "testpass");
        Check("跨不同哈希的压缩包复用成功密码", session.Prompts == 1 && session.Report.Coverage == ScanCoverage.Complete);
        var separate = await ScanPassword(ArchivePasswordReuseScope.ArchiveTree, [a, b], "testpass");
        Check("包内作用域不泄漏到另一个顶层文件", separate.Prompts == 2);
        var retry = await ScanPassword(ArchivePasswordReuseScope.Session, [a], "wrong", "testpass");
        Check("错误密码可更正且结果不重复", retry.Prompts == 2 && retry.Report.Coverage == ScanCoverage.Complete && retry.Report.Metrics.ArchiveEntriesVisited == 1);
        var skipped = await ScanPassword(ArchivePasswordReuseScope.Session, [a], (string?)null);
        Check("跳过加密内容仍记录对应路径", skipped.Report.Coverage == ScanCoverage.Partial && skipped.Report.RootSummaries.Single().Coverage == ScanCoverage.Partial);
    }

    private sealed class InlineScanProgress(Action<ScanProgress> action) : IProgress<ScanProgress>
    {
        public void Report(ScanProgress value) => action(value);
    }

    private sealed class SequencePasswords(ArchivePasswordReuseScope scope, string?[] passwords) : IArchivePasswordProvider
    {
        public int Count { get; private set; }
        public Task<ArchivePasswordResponse> RequestPasswordAsync(ArchivePasswordRequest request, CancellationToken cancellationToken)
        {
            string? password = passwords[Math.Min(Count++, passwords.Length - 1)];
            return Task.FromResult(new ArchivePasswordResponse(request.RequestId, password is null, password, false, scope));
        }
    }
}
