using System.Diagnostics;
using System.IO;
using System.Reflection;
using System.Text;
using System.Text.Json;
using SteamSentinel.App;
using SteamSentinel.App.Services;
using SteamSentinel.Core.Models;
using SteamSentinel.Core.Scanning;
using SteamSentinel.Core.Utilities;

namespace SteamSentinel.SelfTest;

internal static partial class Program
{
    private static async Task TestV0119PasswordsAsync(string root, RuleSet rules, string? workerOverride = null)
    {
        ArchivePasswordCache candidateCache = new();
        candidateCache.SetUserCandidates(["inert-first", "inert-second"], "root-a", ArchivePasswordReuseScope.Session);
        int ValidatedCount() => ((System.Collections.ICollection)typeof(ArchivePasswordCache)
            .GetField("_validated", System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic)!.GetValue(candidateCache)!).Count;
        Check("0.1.19 用户候选可按原序试用但不伪记为已验证密码", candidateCache.Candidates("root-b").SequenceEqual(["inert-first", "inert-second"]) && ValidatedCount() == 0);
        candidateCache.Remember("inert-second", "root-a", ArchivePasswordReuseScope.Session);
        Check("0.1.19 候选后来验证成功也不改变用户固定尝试顺序", candidateCache.Candidates("root-b").SequenceEqual(["inert-first", "inert-second"]) && ValidatedCount() == 1);
        candidateCache.SetUserCandidates(["inert-tree-first", "inert-tree-second"], "root-tree", ArchivePasswordReuseScope.ArchiveTree);
        Check("0.1.19 原树候选之后仍按顺序尝试适用会话候选", candidateCache.Candidates("root-tree").SequenceEqual(["inert-tree-first", "inert-tree-second", "inert-first", "inert-second"]) &&
            candidateCache.Candidates("other-root").SequenceEqual(["inert-first", "inert-second"]));
        ArchivePasswordCache currentOnly = new();
        currentOnly.SetUserCandidates(["inert-current"], "root-a", ArchivePasswordReuseScope.CurrentOnly);
        Check("0.1.19 当前层多候选不进入可复用缓存", currentOnly.Candidates("root-a").Count == 0 && currentOnly.Candidates("root-b").Count == 0);
        candidateCache.EnableSkipAllEncrypted();
        candidateCache.RememberFailure("inert-hash", "inert-first");
        candidateCache.Defer("inert-hash");
        candidateCache.PreferredScope = ArchivePasswordReuseScope.Session;
        candidateCache.Clear();
        Check("0.1.19 清理扫描会话同时重置候选验证失败及全部跳过", candidateCache.Candidates("root-a").Count == 0 && ValidatedCount() == 0 &&
            !candidateCache.SkipAllEncrypted && !candidateCache.HasFailed("inert-hash", "inert-first") && !candidateCache.IsDeferred("inert-hash") &&
            candidateCache.PreferredScope == ArchivePasswordReuseScope.ArchiveTree);
        ArchivePasswordCache failureCache = new();
        const string failureHash = "v0119-inert-failure-history";
        string[] failedSecrets = Enumerable.Range(1, ArchivePasswordCache.MaximumPasswordDecodeAttempts)
            .Select(i => $"v0119-inert-failed-{i:D4}").ToArray();
        foreach (string secret in failedSecrets) failureCache.RememberFailure(failureHash, secret);
        Check("0.1.19 失败历史记住第41次至整轮512次且不误命中", failedSecrets.Length == 512 &&
            failedSecrets.All(secret => failureCache.HasFailed(failureHash, secret)) &&
            !failureCache.HasFailed(failureHash, "v0119-inert-never-attempted") &&
            !failureCache.HasFailed("v0119-inert-other-archive", failedSecrets[40]));
        failureCache.RememberFailure(failureHash, "v0119-inert-history-overflow");
        const BindingFlags instanceFields = BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic;
        System.Collections.IDictionary histories = (System.Collections.IDictionary)typeof(ArchivePasswordCache)
            .GetField("_history", instanceFields)!.GetValue(failureCache)!;
        object[] FailureFingerprints() => ((System.Collections.IEnumerable)histories[failureHash]!.GetType()
            .GetProperty("Failed", instanceFields)!.GetValue(histories[failureHash])!).Cast<object>().ToArray();
        object[] fingerprints = FailureFingerprints();
        Check("0.1.19 失败历史有界且仅保存固定32字节指纹而非明文", fingerprints.Length == 512 &&
            fingerprints.All(value => value.GetType().IsValueType &&
                value.GetType().GetFields(instanceFields) is { Length: 4 } fields && fields.All(field => field.FieldType == typeof(ulong))) &&
            !failureCache.HasFailed(failureHash, "v0119-inert-history-overflow"));
        FieldInfo historyKeyField = typeof(ArchivePasswordCache).GetField("_historyKey", instanceFields)!;
        byte[] oldHistoryKey = (byte[])historyKeyField.GetValue(failureCache)!;
        byte[] oldHistoryKeyCopy = (byte[])oldHistoryKey.Clone();
        failureCache.Clear();
        bool clearedHistory = histories.Count == 0 && failedSecrets.All(secret => !failureCache.HasFailed(failureHash, secret));
        failureCache.RememberFailure(failureHash, failedSecrets[0]);
        byte[] newHistoryKey = (byte[])historyKeyField.GetValue(failureCache)!;
        Check("0.1.19 新会话清空失败记录并清零旧密钥轮换指纹", clearedHistory && oldHistoryKey.All(value => value == 0) &&
            !ReferenceEquals(oldHistoryKey, newHistoryKey) && !oldHistoryKeyCopy.SequenceEqual(newHistoryKey) &&
            !fingerprints.Contains(FailureFingerprints().Single()) && failureCache.HasFailed(failureHash, failedSecrets[0]));
        failureCache.RememberFailure("v0119-inert-ordinal", "\uD800");
        Check("0.1.19 失败指纹保留原始UTF16且不同未配对代理字符不误命中", failureCache.HasFailed("v0119-inert-ordinal", "\uD800") &&
            !failureCache.HasFailed("v0119-inert-ordinal", "\uD801") && !failureCache.HasFailed("v0119-inert-ordinal", "\uFFFD"));
        failureCache.Clear();
        string directory = Path.Combine(root, "v0119-passwords");
        Directory.CreateDirectory(directory);
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
        if (sevenZip is null) { Program.Skip("0.1.19 多密码真实归档测试需要7-Zip"); return; }
        const string alpha = "v0119-inert-alpha", beta = "v0119-inert-beta", wrong = "v0119-inert-wrong";
        string payload = Path.Combine(directory, "harmless.txt"), plain = Path.Combine(directory, "ordinary.txt"), large = Path.Combine(directory, "large.txt");
        await File.WriteAllTextAsync(payload, "Harmless password regression payload; never execute anything.", new UTF8Encoding(false));
        await File.WriteAllTextAsync(plain, "Ordinary unencrypted file must remain readable.", new UTF8Encoding(false));
        await File.WriteAllTextAsync(large, string.Concat(Enumerable.Range(0, 1000).Select(_ => Guid.NewGuid().ToString("N"))), new UTF8Encoding(false));
        RuleSet fixtureRules = new()
        {
            Version = rules.Version,
            KnownHashes = [new() { Id = "V0119-HARMLESS-TEXT", Sha256 = await Hashing.Sha256FileAsync(payload), Malware = true, Label = "无害文本回归规则" }]
        };

        async Task<string> Encrypt(string name, string format, string password, params string[] files)
        {
            bool isRar = format == "rar";
            string archive = Path.Combine(directory, name + (isRar ? ".rar" : format == "7z" ? ".7z" : ".zip"));
            ProcessStartInfo start = new(isRar ? rar! : sevenZip)
            {
                UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true,
                WorkingDirectory = directory
            };
            // All command-line secrets here are generated fixture constants, never user passwords.
            string[] flags = isRar ? ["a", "-idq", "-ep", "-hp" + password] :
                ["a", format == "7z" ? "-t7z" : "-tzip", format == "7z" ? "-mhe=on" : format == "classic" ? "-mem=ZipCrypto" : "-mem=AES256", "-p" + password];
            foreach (string arg in flags.Concat([archive]).Concat(files)) start.ArgumentList.Add(arg);
            using Process process = Process.Start(start)!;
            Task<string> stdout = process.StandardOutput.ReadToEndAsync(), stderr = process.StandardError.ReadToEndAsync();
            using CancellationTokenSource timeout = new(TimeSpan.FromSeconds(45));
            try { await process.WaitForExitAsync(timeout.Token); }
            catch { if (!process.HasExited) process.Kill(entireProcessTree: true); throw; }
            await Task.WhenAll(stdout, stderr);
            if (process.ExitCode != 0) throw new InvalidOperationException("Could not create harmless password regression archive.");
            return archive;
        }
        async Task<ScanReport> Scan(string[] paths, V0119PasswordProvider provider, int entries = 512, long entryBytes = 1024 * 1024,
            V0119PasswordProgress? progress = null, CancellationToken cancellationToken = default)
        {
            ScanReport report = new();
            using ContentScanner scanner = new(fixtureRules);
            foreach (string path in paths)
                await scanner.ScanRootAsync(path, report, V0119PasswordOptions(paths, entries, entryBytes), provider,
                    progress, cancellationToken);
            return report;
        }
        static ArchivePasswordResponse Candidates(ArchivePasswordRequest request, IReadOnlyList<string> passwords,
            ArchivePasswordReuseScope scope = ArchivePasswordReuseScope.Session) => new(request.RequestId, false, null, false, scope, passwords);
        static ArchivePasswordResponse Skip(ArchivePasswordRequest request, bool all = false) => new(request.RequestId, true, null, false,
            ArchivePasswordReuseScope.CurrentOnly, null, all);
        static int PayloadCount(ScanReport report) => report.Findings.Count(f => f.RuleId == "V0119-HARMLESS-TEXT");
        Dictionary<string, string> formatArchives = [];
        foreach (string format in new[] { "aes", "classic", "7z", "rar" })
        {
            if (format == "rar" && rar is null) { Program.Skip("0.1.19 RAR密码回归需要RAR"); continue; }
            string archive = await Encrypt("format-" + format, format, alpha, payload);
            formatArchives[format] = archive;
            V0119PasswordProvider provider = new((r, _) => Candidates(r, [wrong, wrong, alpha]));
            V0119PasswordProgress progress = new();
            ScanReport report = await Scan([archive], provider, entries: 1, progress: progress);
            Check($"0.1.19 {format}多候选错误后正确且不重复询问", report.Coverage == ScanCoverage.Complete && provider.Requests.Count == 1 && PayloadCount(report) == 1);
            Check($"0.1.19 {format}固定候选顺序去重且失败不污染逻辑预算", progress.DirectoryAttempts == 3 &&
                report.Metrics.ArchiveEntriesVisited == 1 && report.Metrics.ArchiveBytesExpanded == new FileInfo(payload).Length &&
                report.CoverageNotes.All(note => !note.Contains("上限")));
        }

        string unencryptedArchive = Path.Combine(directory, "decode-budget-ordinary.zip");
        CreateZip(unencryptedArchive, archive =>
        {
            using Stream input = File.OpenRead(payload);
            using Stream output = archive.CreateEntry("harmless.txt").Open();
            input.CopyTo(output);
        });
        static object ArchiveBudgetFor(ContentScanner scanner) => typeof(ContentScanner)
            .GetField("_archiveBudget", instanceFields)!.GetValue(scanner)!;
        static long PasswordAttempts(object budget) => budget.GetType().GetProperty("PasswordDecodeAttempts", instanceFields) is { } property
            ? (long)property.GetValue(budget)! : (long)budget.GetType().GetField("PasswordDecodeAttempts", instanceFields)!.GetValue(budget)!;
        static void SetPasswordAttempts(object budget, long value)
        {
            if (budget.GetType().GetProperty("PasswordDecodeAttempts", instanceFields) is { } property) property.SetValue(budget, value);
            else budget.GetType().GetField("PasswordDecodeAttempts", instanceFields)!.SetValue(budget, value);
        }
        foreach (string format in new[] { "7z", "rar" })
        {
            if (!formatArchives.TryGetValue(format, out string? archive)) continue;
            string laterEncrypted = await Encrypt("decode-budget-next-" + format, format, beta, payload);
            using ContentScanner scanner = new(fixtureRules);
            using CancellationTokenSource budgetTimeout = new(TimeSpan.FromSeconds(45));
            ScanReport limitedReport = new();
            string[] paths = [plain, archive, laterEncrypted, unencryptedArchive, plain];
            ScanOptions options = V0119PasswordOptions(paths);
            V0119PasswordProvider limitedProvider = new((r, _) => Candidates(r, [wrong + "-first", wrong + "-second", alpha],
                ArchivePasswordReuseScope.CurrentOnly));
            await scanner.ScanRootAsync(plain, limitedReport, options, limitedProvider, cancellationToken: budgetTimeout.Token);
            object budget = ArchiveBudgetFor(scanner);
            // Exercise the real encrypted-header failure path without running 512 expensive key derivations.
            SetPasswordAttempts(budget, ArchivePasswordCache.MaximumPasswordDecodeAttempts - 2);
            V0119PasswordProgress limitedProgress = new();
            await scanner.ScanRootAsync(archive, limitedReport, options, limitedProvider, limitedProgress, budgetTimeout.Token);
            Check($"0.1.19 {format}头部错误消耗真实密码预算且上限不回滚不重复询问", limitedProvider.Requests.Count == 1 &&
                limitedProgress.DirectoryAttempts == 3 && PasswordAttempts(budget) == 512 && limitedReport.Coverage == ScanCoverage.Partial &&
                limitedReport.RootSummaries[^1].Coverage == ScanCoverage.Partial && PayloadCount(limitedReport) == 0 &&
                limitedReport.Metrics.ArchiveEntriesVisited == 0 && limitedReport.Metrics.ArchiveBytesExpanded == 0 &&
                limitedReport.Findings.Any(f => f.RuleId == "ARCHIVE-ATTEMPT-LIMIT" && f.Target == archive));
            await scanner.ScanRootAsync(laterEncrypted, limitedReport, options, limitedProvider, cancellationToken: budgetTimeout.Token);
            await scanner.ScanRootAsync(unencryptedArchive, limitedReport, options, limitedProvider, cancellationToken: budgetTimeout.Token);
            await scanner.ScanRootAsync(plain, limitedReport, options, limitedProvider, cancellationToken: budgetTimeout.Token);
            Check($"0.1.19 {format}预算耗尽不再索取密码且普通归档与文件继续", limitedProvider.Requests.Count == 1 &&
                ReferenceEquals(budget, ArchiveBudgetFor(scanner)) && PasswordAttempts(budget) == 512 &&
                limitedReport.RootSummaries[^3].Coverage == ScanCoverage.Partial &&
                limitedReport.RootSummaries[^2].Coverage == ScanCoverage.Complete && limitedReport.RootSummaries[^1].Coverage == ScanCoverage.Complete &&
                PayloadCount(limitedReport) == 1 && limitedReport.Findings.Any(f => f.RuleId == "ARCHIVE-ATTEMPT-LIMIT" && f.Target == laterEncrypted));
            ScanReport freshReport = new();
            V0119PasswordProvider freshProvider = new((r, _) => Candidates(r, [alpha]));
            await scanner.ScanRootAsync(archive, freshReport, V0119PasswordOptions([archive]), freshProvider, cancellationToken: budgetTimeout.Token);
            Check($"0.1.19 {format}新扫描报告重置解码预算及候选可正常解密", freshProvider.Requests.Count == 1 &&
                freshReport.Coverage == ScanCoverage.Complete && PayloadCount(freshReport) == 1 &&
                !ReferenceEquals(budget, ArchiveBudgetFor(scanner)) && PasswordAttempts(ArchiveBudgetFor(scanner)) == 1 &&
                freshReport.Findings.All(f => f.RuleId != "ARCHIVE-ATTEMPT-LIMIT"));
        }

        string one = formatArchives["aes"];
        foreach ((string outerFormat, string innerFormat) in new[] { ("aes", "classic"), ("classic", "7z"), ("7z", "aes"), ("rar", "7z") })
        {
            if (outerFormat == "rar" && rar is null) continue;
            string inner = await Encrypt("same-inner-" + outerFormat, innerFormat, alpha, payload);
            string outer = await Encrypt("same-outer-" + outerFormat, outerFormat, alpha, inner);
            foreach (ArchivePasswordReuseScope scope in new[] { ArchivePasswordReuseScope.ArchiveTree, ArchivePasswordReuseScope.Session })
            {
                V0119PasswordProvider provider = new((r, n) => n == 1
                    ? new(r.RequestId, false, alpha, false, scope) : Skip(r));
                ScanReport report = await Scan([outer], provider);
                Check($"0.1.19 {scope}下{outerFormat}外层与{innerFormat}内层同密码仅询问一次", report.Coverage == ScanCoverage.Complete &&
                    provider.Requests.Count == 1 && report.Metrics.ArchiveEntriesVisited == 2 && PayloadCount(report) == 1);
            }
        }
        if (rar is not null)
        {
            string inner = await Encrypt("three-inner", "rar", alpha, payload);
            string middle = await Encrypt("three-middle", "7z", alpha, inner);
            string outer = await Encrypt("three-outer", "aes", alpha, middle);
            V0119PasswordProvider provider = new((r, n) => n == 1 ? Candidates(r, [wrong, alpha], ArchivePasswordReuseScope.ArchiveTree) : Skip(r));
            ScanReport report = await Scan([outer], provider);
            Check("0.1.19 AES加7z加RAR三层同密码不重复弹窗", report.Coverage == ScanCoverage.Complete && provider.Requests.Count == 1 &&
                report.Metrics.ArchiveEntriesVisited == 3 && PayloadCount(report) == 1);
        }

        string betaArchive = await Encrypt("other-password", "aes", beta, payload);
        foreach (ArchivePasswordReuseScope scope in Enum.GetValues<ArchivePasswordReuseScope>())
        {
            V0119PasswordProvider provider = new((r, n) => n == 1 ? Candidates(r, [alpha, beta], scope) : Skip(r));
            ScanReport report = await Scan([one, betaArchive], provider);
            bool session = scope == ArchivePasswordReuseScope.Session;
            Check($"0.1.19 多候选跨外层归档遵守{scope}作用域", provider.Requests.Count == (session ? 1 : 2) &&
                report.Coverage == (session ? ScanCoverage.Complete : ScanCoverage.Partial) && PayloadCount(report) == (session ? 2 : 1));
        }
        string nestedDifferent = await Encrypt("nested-different", "7z", alpha, betaArchive);
        V0119PasswordProvider nestedCandidates = new((r, n) => n == 1 ? Candidates(r, [alpha, beta], ArchivePasswordReuseScope.ArchiveTree) : Skip(r));
        ScanReport different = await Scan([nestedDifferent], nestedCandidates);
        Check("0.1.19 尚未验证的内层候选仍可在原归档树依次尝试", nestedCandidates.Requests.Count == 1 && different.Coverage == ScanCoverage.Complete && PayloadCount(different) == 1);
        const string treeSecret = "v0119-inert-tree";
        string treeWithSessionInner = await Encrypt("tree-and-session", "7z", treeSecret, betaArchive);
        V0119PasswordProvider combinedScopes = new((r, n) => n == 1 ? Candidates(r, [alpha, beta]) :
            n == 2 ? Candidates(r, [treeSecret], ArchivePasswordReuseScope.ArchiveTree) : Skip(r));
        ScanReport combinedScopeReport = await Scan([one, treeWithSessionInner], combinedScopes);
        Check("0.1.19 真实嵌套树候选未解开时继续适用会话后备密码", combinedScopes.Requests.Count == 2 &&
            combinedScopeReport.Coverage == ScanCoverage.Complete && PayloadCount(combinedScopeReport) == 2);

        string oversized = await Encrypt("unverified-large", "aes", alpha, large);
        V0119PasswordProvider unverified = new((r, n) => n == 1 ? Candidates(r, [alpha, beta]) : Skip(r));
        ScanReport unverifiedReport = await Scan([oversized, betaArchive], unverified, entryBytes: 128);
        Check("0.1.19 未验证的用户候选保留试用资格但大成员仍记未完成", unverified.Requests.Count == 1 && unverifiedReport.Coverage == ScanCoverage.Partial &&
            unverifiedReport.RootSummaries.Last().Coverage == ScanCoverage.Complete && PayloadCount(unverifiedReport) == 1);

        string unknown = await Encrypt("unknown-password", "classic", "v0119-inert-third", payload);
        string knownLater = await Encrypt("known-after-skip", "7z", alpha, payload);
        V0119PasswordProvider skipAll = new((r, n) => n == 1 ? Candidates(r, [alpha]) : Skip(r, true));
        ScanReport skipped = await Scan([one, betaArchive, unknown, knownLater, plain], skipAll);
        Check("0.1.19 跳过全部后不同未解密归档不再询问且保留Partial", skipAll.Requests.Count == 2 && skipped.Coverage == ScanCoverage.Partial &&
            skipped.RootSummaries[1].Coverage == ScanCoverage.Partial && skipped.RootSummaries[2].Coverage == ScanCoverage.Partial);
        Check("0.1.19 跳过全部仍尝试适用密码并检查普通文件", skipped.RootSummaries[^2].Coverage == ScanCoverage.Complete &&
            skipped.RootSummaries[^1].Coverage == ScanCoverage.Complete && PayloadCount(skipped) == 2);
        Check("0.1.19 跳过全部重试目标只列出实际未解密外层路径", MainWindow.GetPasswordRetryTargets(skipped).Order().SequenceEqual(new[] { betaArchive, unknown }.Order()));
        V0119PasswordProvider reset = new((r, _) => Candidates(r, [beta]));
        ScanReport resetReport = new();
        using (ContentScanner reusedScanner = new(fixtureRules))
        {
            ScanReport earlier = new();
            await reusedScanner.ScanRootAsync(betaArchive, earlier, V0119PasswordOptions([betaArchive]), new V0119PasswordProvider((r, _) => Skip(r, true)));
            await reusedScanner.ScanRootAsync(betaArchive, resetReport, V0119PasswordOptions([betaArchive]), reset);
        }
        Check("0.1.19 新扫描重置跳过全部及密码会话", reset.Requests.Count == 1 && reset.Requests[0].PreferredReuseScope == ArchivePasswordReuseScope.ArchiveTree && resetReport.Coverage == ScanCoverage.Complete);

        string spacesSecret = "  v0119-spaces  ";
        string spacesArchive = await Encrypt("space-password", "aes", spacesSecret, payload);
        V0119PasswordProvider spaces = new((r, _) => Candidates(r, [spacesSecret.Trim(), spacesSecret]));
        ScanReport spaced = await Scan([spacesArchive], spaces);
        Check("0.1.19 多候选保留密码前后空格不擅自修剪", spaces.Requests.Count == 1 && spaced.Coverage == ScanCoverage.Complete && PayloadCount(spaced) == 1);
        string[] sixteen = Enumerable.Range(1, 15).Select(i => "v0119-wrong-" + i).Append(alpha).ToArray();
        V0119PasswordProvider sixteenProvider = new((r, _) => Candidates(r, sixteen));
        ScanReport sixteenReport = await Scan([one], sixteenProvider);
        Check("0.1.19 最多16候选可按顺序尝试到最后一个", sixteenProvider.Requests.Count == 1 && sixteenReport.Coverage == ScanCoverage.Complete && PayloadCount(sixteenReport) == 1);
        V0119PasswordProvider cancel = new((_, _) => throw new OperationCanceledException("inert password cancellation"));
        bool cancelled = false;
        try { await Scan([one], cancel); } catch (OperationCanceledException) { cancelled = true; }
        Check("0.1.19 密码提供过程取消仍传播取消状态", cancelled && cancel.Requests.Count == 1);

        string worker = workerOverride ?? Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "../../../../SteamSentinel.ArchiveWorker/bin/Release/net10.0-windows10.0.19041.0/SteamSentinel.ArchiveWorker.exe"));
        V0119PasswordProvider wire = new((r, n) => n == 1 ? Candidates(r, [wrong, alpha, beta]) : Skip(r));
        using CancellationTokenSource workerTimeout = new(TimeSpan.FromSeconds(90));
        ScanReport wireReport = await new ArchiveWorkerClient(worker).RunAsync(V0119PasswordOptions([one, betaArchive]), wire.RequestPasswordAsync, null, workerTimeout.Token);
        Check("0.1.19 Low Worker多密码往返且未验证后备候选跨归档可用", wire.Requests.Count == 1 && wireReport.Coverage == ScanCoverage.Complete && wireReport.Metrics.ArchiveEntriesVisited == 2);
        V0119PasswordProvider wireSkip = new((r, n) => n == 1 ? Candidates(r, [alpha]) : Skip(r, true));
        ScanReport wireSkipped = await new ArchiveWorkerClient(worker).RunAsync(V0119PasswordOptions([one, betaArchive, unknown, knownLater, plain]), wireSkip.RequestPasswordAsync, null, workerTimeout.Token);
        Check("0.1.19 Low Worker跳过全部往返仍读取已有密码与普通文件", wireSkip.Requests.Count == 2 && wireSkipped.Coverage == ScanCoverage.Partial &&
            wireSkipped.RootSummaries[^2].Coverage == ScanCoverage.Complete && wireSkipped.RootSummaries[^1].Coverage == ScanCoverage.Complete);
        using CancellationTokenSource wireCancelSource = new(TimeSpan.FromSeconds(30));
        bool wireCancelled = false;
        try
        {
            await new ArchiveWorkerClient(worker).RunAsync(V0119PasswordOptions([one]), (request, _) =>
            {
                wireCancelSource.Cancel();
                return Task.FromCanceled<ArchivePasswordResponse>(wireCancelSource.Token);
            }, null, wireCancelSource.Token);
        }
        catch (OperationCanceledException) { wireCancelled = true; }
        Check("0.1.19 Low Worker等待密码时取消不会继续扫描", wireCancelled);
        foreach (bool wrongRequestId in new[] { true, false })
        {
            string processName = Path.GetFileNameWithoutExtension(worker);
            HashSet<int> priorWorkers = Process.GetProcessesByName(processName).Select(process => { using (process) return process.Id; }).ToHashSet();
            using CancellationTokenSource rejectedTimeout = new(TimeSpan.FromSeconds(20));
            string failure = string.Empty;
            bool rejected = false;
            try
            {
                await new ArchiveWorkerClient(worker).RunAsync(V0119PasswordOptions([one]), (request, _) =>
                    Task.FromResult(wrongRequestId ? new ArchivePasswordResponse("inert-wrong-request-id", false, alpha, false) :
                        Candidates(request, Enumerable.Range(1, 17).Select(i => alpha + i).ToArray())), null, rejectedTimeout.Token);
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                rejected = true;
                failure = ex.ToString();
            }
            bool noWorker = false;
            for (int pass = 0; pass < 20; pass++)
            {
                noWorker = Process.GetProcessesByName(processName).All(process => { using (process) return priorWorkers.Contains(process.Id); });
                if (noWorker) break;
                await Task.Delay(50);
            }
            Check(wrongRequestId ? "0.1.19 Low Worker拒绝错配密码请求且不泄密不残留" : "0.1.19 Low Worker拒绝超过16候选且不泄密不残留",
                rejected && !failure.Contains(alpha, StringComparison.Ordinal) && !rejectedTimeout.IsCancellationRequested && noWorker);
        }
        string serialized = JsonSerializer.Serialize(new[] { different, combinedScopeReport, skipped, spaced, sixteenReport, wireReport, wireSkipped }, JsonFile.Options);
        Check("0.1.19 扫描报告不泄露任何已输入或失败候选密码", new[] { alpha, beta, wrong, treeSecret, spacesSecret }.Concat(sixteen)
            .All(secret => !serialized.Contains(secret, StringComparison.Ordinal)));
    }

    private static ScanOptions V0119PasswordOptions(string[] roots, int entries = 512, long entryBytes = 1024 * 1024) => new()
    {
        Mode = ScanMode.Custom, IncludeSystem = false, IncludeSteam = false, IncludeWorkshop = false, UseAmsi = false,
        InspectArchives = true, HashEveryFile = true, MaximumContentBytes = long.MaxValue,
        MaximumArchiveEntries = entries, MaximumEntryBytes = entryBytes, MaximumExpandedBytes = 16 * 1024 * 1024,
        MaximumArchiveDepth = 8, CustomRoots = [.. roots]
    };

    private sealed class V0119PasswordProvider(Func<ArchivePasswordRequest, int, ArchivePasswordResponse> respond) : IArchivePasswordProvider
    {
        public List<ArchivePasswordRequest> Requests { get; } = [];
        public Task<ArchivePasswordResponse> RequestPasswordAsync(ArchivePasswordRequest request, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Requests.Add(request);
            if (Requests.Count > 12) throw new InvalidOperationException("Harmless password test exceeded its bounded prompt limit.");
            return Task.FromResult(respond(request, Requests.Count));
        }
    }

    private sealed class V0119PasswordProgress : IProgress<ScanProgress>
    {
        public int DirectoryAttempts { get; private set; }
        public void Report(ScanProgress value) { if (value.Stage == "压缩包目录") DirectoryAttempts++; }
    }
}
