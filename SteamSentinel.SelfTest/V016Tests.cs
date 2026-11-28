using System.Diagnostics;
using System.IO;
using System.Text.Json;
using System.Windows.Controls;
using SteamSentinel.App;
using SteamSentinel.App.Dialogs;
using SteamSentinel.App.Services;
using SteamSentinel.Core.Models;
using SteamSentinel.Core.Scanning;
using SteamSentinel.Core.Utilities;

namespace SteamSentinel.SelfTest;

internal static partial class Program
{
    private static bool _v020LegacyDiagnostics;
    private static async Task TestV016Async(string root, RuleSet rules, bool runDialog = true)
    {
        string directory = Path.Combine(root, "v016");
        Directory.CreateDirectory(directory);
        string small = Path.Combine(directory, "small.txt"), large = Path.Combine(directory, "large.txt");
        await File.WriteAllTextAsync(small, "harmless fixture");
        await File.WriteAllTextAsync(large, string.Concat(Enumerable.Range(0, 100).Select(_ => Guid.NewGuid().ToString("N"))));
        string? sevenZip = new[]
        {
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "7-Zip", "7z.exe"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "scoop", "apps", "7zip", "current", "7z.exe")
        }.FirstOrDefault(File.Exists);
        string? rar = new[]
        {
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "WinRAR", "Rar.exe"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86), "WinRAR", "Rar.exe")
        }.FirstOrDefault(File.Exists);
        if (sevenZip is null) { Skip("0.1.6 ZIP AES/传统加密/7z（缺少 7-Zip）"); return; }
        const string secret = "v016-inert-secret", otherSecret = "v016-other-secret";
        async Task<string> Encrypt(string name, string format, string password, params string[] files)
        {
            bool isRar = format == "rar";
            string path = Path.Combine(directory, name + (isRar ? ".rar" : format == "7z" ? ".7z" : ".zip"));
            ProcessStartInfo start = new(isRar ? rar! : sevenZip)
            {
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardError = true,
                RedirectStandardOutput = true,
                WorkingDirectory = directory
            };
            string[] flags = isRar ? ["a", "-idq", "-ep", "-hp" + password] :
                ["a", format == "7z" ? "-t7z" : "-tzip", format == "7z" ? "-mhe=on" : format == "classic" ? "-mem=ZipCrypto" : "-mem=AES256", "-p" + password];
            foreach (string arg in flags.Concat([path]).Concat(files)) start.ArgumentList.Add(arg);
            using Process process = Process.Start(start)!;
            Task<string> stdout = process.StandardOutput.ReadToEndAsync(), stderr = process.StandardError.ReadToEndAsync();
            await process.WaitForExitAsync(); await Task.WhenAll(stdout, stderr);
            if (process.ExitCode != 0) throw new InvalidOperationException("Cannot create inert archive fixture");
            return path;
        }
        int scanOrdinal = 0;
        async Task<ScanReport> Scan(string[] paths, RecordingPasswords provider, long limit = 256L * 1024 * 1024)
        {
            ScanReport report = new();
            using ContentScanner scanner = new(rules);
            foreach (string path in paths) await scanner.ScanRootAsync(path, report, new ScanOptions
            {
                Mode = ScanMode.Custom,
                IncludeSystem = false,
                IncludeSteam = false,
                IncludeWorkshop = false,
                UseAmsi = false,
                HashEveryFile = true,
                MaximumEntryBytes = limit
            }, provider);
            if (_v020LegacyDiagnostics)
                await JsonFile.WriteAtomicAsync(Path.Combine(directory, $"scan-{++scanOrdinal:D2}.json"), new
                {
                    Paths = paths,
                    Requests = provider.Requests,
                    Report = report
                }, options: SteamSentinel.Core.Reporting.ReportPrivacy.ExportOptions);
            return report;
        }
        string mixedArchive = Path.Combine(directory, "mixed-entry.zip");
        CreateZip(mixedArchive, archive => { using StreamWriter writer = new(archive.CreateEntry("plain.txt").Open()); writer.Write("inert plain entry"); });

        // 第一阶段：并发创建互不依赖的加密归档，保持文件命名隔离与后续扫描顺序不变
        string[] formats = ["aes", "classic", "7z", "rar"];
        Dictionary<string, (Task<string> First, Task<string> Second)> formatTasks = new(StringComparer.Ordinal);
        List<Task> stage1Tasks = [];
        foreach (string format in formats)
        {
            if (format == "rar" && rar is null) continue;
            Task<string> firstTask = Encrypt(format + "-a", format, secret, small);
            Task<string> secondTask = Encrypt(format + "-b", format, secret, large);
            formatTasks[format] = (firstTask, secondTask);
            stage1Tasks.Add(firstTask);
            stage1Tasks.Add(secondTask);
        }
        Task<string> limitedTask = Encrypt("limited", "aes", secret, small, large);
        Task<string> mixedEntryTask = Encrypt("mixed-entry", "aes", secret, large);
        Task<string> innerTask = Encrypt("inner", "aes", otherSecret, small);
        Task<string> learnTask = Encrypt("learn", "aes", otherSecret, large);
        stage1Tasks.Add(limitedTask);
        stage1Tasks.Add(mixedEntryTask);
        stage1Tasks.Add(innerTask);
        stage1Tasks.Add(learnTask);
        await Task.WhenAll(stage1Tasks);

        string limited = await limitedTask;
        _ = await mixedEntryTask;
        string inner = await innerTask;
        string learn = await learnTask;

        // 第二阶段：基于 inner.zip 并发创建嵌套归档，并同步准备衍生夹具
        Task<string> outerATask = Encrypt("outer-a", "aes", secret, inner);
        Task<string> outerBTask = Encrypt("outer-b", "aes", secret, inner, small);

        string badCrc = Path.Combine(directory, "bad-crc.zip");
        byte[] crcBytes = await File.ReadAllBytesAsync(Path.Combine(directory, "classic-a.zip"));
        int central = crcBytes.AsSpan().IndexOf(new byte[] { 0x50, 0x4b, 0x01, 0x02 });
        if (central < 0) throw new InvalidDataException("Fixture central directory missing");
        crcBytes[central + 16] ^= 1;
        crcBytes[14] ^= 1;
        await File.WriteAllBytesAsync(badCrc, crcBytes);

        string malformed = Path.Combine(directory, "broken.7z");
        await File.WriteAllBytesAsync(malformed, [0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C, 0, 4]);

        await Task.WhenAll(outerATask, outerBTask);
        string outerA = await outerATask, outerB = await outerBTask;

        string plainOuterA = Path.Combine(directory, "plain-a.zip"), plainOuterB = Path.Combine(directory, "plain-b.zip");
        CreateZip(plainOuterA, archive => { using Stream s = archive.CreateEntry("inner.zip").Open(); using FileStream f = File.OpenRead(inner); f.CopyTo(s); });
        CreateZip(plainOuterB, archive => { using Stream s = archive.CreateEntry("copy.zip").Open(); using FileStream f = File.OpenRead(inner); f.CopyTo(s); });

        foreach (string format in formats)
        {
            if (format == "rar" && rar is null) { Skip("0.1.6 RAR 独立密码回归（缺少 RAR）"); continue; }
            (Task<string> firstTask, Task<string> secondTask) = formatTasks[format];
            string a = await firstTask, b = await secondTask;
            RecordingPasswords provider = new((_, n) => n == 1 ? "wrong-inert-secret" : secret);
            ScanReport result = await Scan([a, b], provider);
            Check($"{format} 错误密码可更正并跨文件复用", result.Coverage == ScanCoverage.Complete && provider.Requests.Count == 2 &&
                provider.Requests[1].PromptKind == ArchivePasswordPromptKind.EnteredPasswordFailed && result.Metrics.ArchiveEntriesVisited == 2);
            Check($"{format} 错误后仍沿用本次扫描作用域", provider.Requests.Count >= 2 &&
                provider.Requests[1].PreferredReuseScope == ArchivePasswordReuseScope.Session);
        }

        string one = Path.Combine(directory, "aes-a.zip"), two = Path.Combine(directory, "aes-b.zip");
        RecordingPasswords partialProvider = new((_, _) => secret);
        ScanReport partial = await Scan([limited, one], partialProvider, 64);
        Check("已验证密码不因另一成员超过大小上限而丢失", partial.Coverage == ScanCoverage.Partial && partialProvider.Requests.Count == 1 &&
            // Metadata-attempt accounting deliberately includes the oversized member even though
            // its contents are not expanded: limited.zip has two entries and aes-a.zip has one.
            partial.Metrics.ArchiveEntriesVisited == 3);

        // An archive with only skipped encrypted members has not verified the password.
        RecordingPasswords unverifiedProvider = new((_, _) => secret);
        ScanReport unverified = await Scan([two, one], unverifiedProvider, 64);
        Check("未读取任何加密成员时不冒充密码已验证", unverified.Coverage == ScanCoverage.Partial && unverifiedProvider.Requests.Count == 2);

        RecordingPasswords mixedEntries = new((_, _) => secret);
        ScanReport mixedEntryResult = await Scan([mixedArchive, one], mixedEntries, 64);
        Check("普通成员读完不代表跳过的加密成员已验证", mixedEntryResult.Coverage == ScanCoverage.Partial && mixedEntries.Requests.Count == 2);

        RecordingPasswords crcProvider = new((_, _) => secret);
        ScanReport crcResult = await Scan([badCrc, one], crcProvider);
        Check("ZIP 校验失败不缓存密码且后续文件继续", crcResult.Coverage == ScanCoverage.Partial &&
            crcProvider.Requests.Count(request => request.ArchivePath == one) == 1 && crcProvider.Requests.Last().PromptKind == ArchivePasswordPromptKind.Needed &&
            crcResult.Containers?.Resources.PasswordAttempts == 2 &&
            crcResult.RootSummaries.Last().Coverage == ScanCoverage.Complete);

        RecordingPasswords skipInner = new((request, _) => request.Depth > 0 ? null : secret);
        ScanReport deferred = await Scan([outerA, outerB], skipInner);
        Check("同哈希内层跳过一次后不重复弹窗", skipInner.Requests.Count == 2 &&
            deferred.Findings.Any(f => f.RuleId == "ARCHIVE-ENCRYPTED-DEFERRED") && deferred.Coverage == ScanCoverage.Partial);
        Check("自动复用失败的弹窗明确说明原因", skipInner.Requests[1].PromptKind == ArchivePasswordPromptKind.CachedPasswordFailed &&
            skipInner.Requests[1].Reason.Contains("已尝试本次暂存且适用的密码", StringComparison.Ordinal));
        RecordingPasswords failInner = new((_, _) => secret);
        ScanReport repeated = await Scan([outerA, outerB], failInner);
        Check("重复失败密码不重复解包且同内容合并询问", failInner.Requests.Count == 4 &&
            failInner.Requests.Any(r => r.PromptKind == ArchivePasswordPromptKind.RepeatedPassword) &&
            repeated.Findings.Any(f => f.RuleId == "ARCHIVE-ENCRYPTED-DEFERRED"));
        Check("重试入口只取真实外层文件并去重", MainWindow.GetPasswordRetryTargets(deferred).Order().SequenceEqual(new[] { outerA, outerB }.Order()));

        RecordingPasswords learnLater = new((request, _) => request.ArchivePath.StartsWith(plainOuterA, StringComparison.Ordinal) ? null : otherSecret);
        ScanReport recovered = await Scan([plainOuterA, learn, plainOuterB], learnLater);
        Check("之后取得新成功密码仍可自动尝试此前跳过内容", learnLater.Requests.Count == 2 && recovered.RootSummaries.Last().Coverage == ScanCoverage.Complete);

        RecordingPasswords mixed = new((request, _) => request.Depth > 0 ? otherSecret : secret);
        ScanReport mixedResult = await Scan([outerA, outerB], mixed);
        Check("内外层不同密码可同时缓存并完成后续包", mixedResult.Coverage == ScanCoverage.Complete && mixed.Requests.Count == 2);
        RecordingPasswords newScan = new((_, _) => secret);
        await Scan([one], newScan);
        Check("新扫描不继承旧密码或作用域偏好", newScan.Requests.Count == 1 && newScan.Requests[0].PreferredReuseScope == ArchivePasswordReuseScope.ArchiveTree);
        Check("导出报告不含输入密码", !JsonSerializer.Serialize(mixedResult, JsonFile.Options).Contains(secret, StringComparison.Ordinal) &&
            !JsonSerializer.Serialize(mixedResult, JsonFile.Options).Contains(otherSecret, StringComparison.Ordinal));

        RecordingPasswords malformedProvider = new((request, _) => request.ArchivePath == one ? secret : null);
        ScanReport broken = await Scan([malformed, one], malformedProvider);
        Check("损坏压缩包保留缺口并继续下一个文件", broken.Coverage == ScanCoverage.Partial &&
            broken.Findings.Any(f => f.RuleId == "ARCHIVE-UNSUPPORTED") && broken.RootSummaries.Last().Coverage == ScanCoverage.Complete);

        string worker = DevelopmentWorkerPath();
        RecordingPasswords wire = new((_, n) => n == 1 ? "wrong-inert-secret" : secret);
        using CancellationTokenSource timeout = new(TimeSpan.FromSeconds(45));
        ScanReport wireResult = await new ArchiveWorkerClient(worker).RunAsync(new ScanOptions
        {
            Mode = ScanMode.Custom,
            IncludeSystem = false,
            IncludeSteam = false,
            IncludeWorkshop = false,
            UseAmsi = false,
            HashEveryFile = true,
            CustomRoots = [malformed, one, two]
        }, wire.RequestPasswordAsync, null, timeout.Token);
        Check("受限工作进程中 ZIP 错密码与损坏包不中止整次扫描", wireResult.Coverage == ScanCoverage.Partial && wire.Requests.Count == 2 &&
            wireResult.RootSummaries.Last().Coverage == ScanCoverage.Complete && wire.Requests[1].PreferredReuseScope == ArchivePasswordReuseScope.Session);
        if (runDialog) TestV016Dialog();
    }

    private static void TestV016Dialog()
    {
        bool passed = false;
        UiFixtureApplication.RunOnStaApplication(app =>
        {
            ArchivePasswordRequest request = new("ui", "inert.zip", new string('A', 64), "ZIP", 1, null, "inert",
                ArchivePasswordReuseScope.Session, ArchivePasswordPromptKind.CachedPasswordFailed);
            PasswordDialog dialog = new(request);
            passed = ((RadioButton)dialog.FindName("SessionRadio")).IsChecked == true &&
                ((RadioButton)dialog.FindName("ArchiveTreeRadio")).IsChecked == false && dialog.PromptTitle == "本次暂存的密码未能解开这一层";
            dialog.Close();
            TestV017Window();
            TestV018Window();
            TestV0115Window();
            TestV0117Layout();
            TestV030UiPresentation(null);
            TestFindingPriorityUi();
            TestV030LanguageControls(null);
            Check("UI 夹具没有安排或加载真实产品窗口", app.StartupUri is null &&
                app.Windows.OfType<MainWindow>().All(window => !window.IsLoaded));
        });
        Check("新密码窗口沿用作用域并展示对应失败标题", passed);
    }

    private sealed class RecordingPasswords(Func<ArchivePasswordRequest, int, string?> respond) : IArchivePasswordProvider
    {
        public List<ArchivePasswordRequest> Requests { get; } = [];
        public Task<ArchivePasswordResponse> RequestPasswordAsync(ArchivePasswordRequest request, CancellationToken token)
        {
            token.ThrowIfCancellationRequested();
            Requests.Add(request);
            string? password = respond(request, Requests.Count);
            return Task.FromResult(new ArchivePasswordResponse(request.RequestId, password is null, password, false, ArchivePasswordReuseScope.Session));
        }
    }
}
