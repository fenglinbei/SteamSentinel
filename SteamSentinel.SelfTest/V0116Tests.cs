using System.IO;
using System.IO.Compression;
using System.Reflection;
using SteamSentinel.Core.Models;
using SteamSentinel.Core.Remediation;
using SteamSentinel.Core.Reporting;
using SteamSentinel.Core.Scanning;
using SteamSentinel.Core.Utilities;

namespace SteamSentinel.SelfTest;

internal static partial class Program
{
    private static async Task TestV0116Async(string root)
    {
        string directory = Path.Combine(root, "v0116"); Directory.CreateDirectory(directory);
        string file = Path.Combine(directory, "inert.bin"); await File.WriteAllBytesAsync(file, new byte[1024 * 1024]);
        string hash = await Hashing.Sha256FileAsync(file);
        Finding FindingFor(string path, string? identity = null, string? content = null) => new()
        {
            Target = path,
            Sha256 = identity ?? hash,
            TargetSha256 = identity ?? hash,
            ContentPath = content,
            Score = 95,
            RuleId = "INERT-TEST",
            CanRemediate = true,
            SuggestedActions = [SuggestedActionKind.QuarantineFile]
        };
        Finding[] duplicates = Enumerable.Range(0, 200).Select(i => FindingFor(file, content: file + "!/inner-" + i)).ToArray();
        RelatedArtifactExpansion expansion = await new RelatedArtifactScanner(new()).ExpandAsync(duplicates, new() { Findings = duplicates.ToList() });
        Check("0.1.16 总核验额度使用 long 型 4 GiB，保留单文件限制", RelatedArtifactScanner.MaximumVerificationBytes == 4294967296L);
        Check("0.1.16 同一外层200条发现只读取一次身份", expansion.VerificationBytesRead == 1024 * 1024 && expansion.Findings.Count(f => f.CanRemediate) == 1);
        using (FileStream unlocked = File.Open(file, FileMode.Open, FileAccess.ReadWrite, FileShare.None))
            Check("0.1.16 方案核验结束释放所有文件锁", unlocked.CanWrite);

        RelatedArtifactScanner budgetScanner = new(new());
        FieldInfo counter = typeof(RelatedArtifactScanner).GetField("_relatedBytesHashed", BindingFlags.Instance | BindingFlags.NonPublic)!;
        MethodInfo hashMethod = typeof(RelatedArtifactScanner).GetMethod("HashAsync", BindingFlags.Instance | BindingFlags.NonPublic)!;
        counter.SetValue(budgetScanner, RelatedArtifactScanner.MaximumVerificationBytes - 1024 * 1024);
        ScanReport exact = new();
        string? accepted = await (Task<string?>)hashMethod.Invoke(budgetScanner, [file, exact, CancellationToken.None])!;
        Check("0.1.16 恰好到4GiB边界仍可完成核验", accepted == hash && (long)counter.GetValue(budgetScanner)! == RelatedArtifactScanner.MaximumVerificationBytes);
        ScanReport exceeded = new();
        Check("0.1.16 超过4GiB明确返回额度限制而非文件变化", await (Task<string?>)hashMethod.Invoke(budgetScanner, [file, exceeded, CancellationToken.None])! is null &&
            exceeded.CoverageNotes.Any(n => n.Contains("4 GiB")));

        string large = Path.Combine(directory, "large-inert.dat");
        using (FileStream sparse = File.Create(large)) sparse.SetLength(256L * 1024 * 1024 + 1);
        RelatedArtifactExpansion largeExpansion = await new RelatedArtifactScanner(new()).ExpandAsync([FindingFor(large)], new() { Findings = [FindingFor(large)] });
        Check("0.1.16 单文件256MiB限制仍拒绝超限文件并释放句柄", largeExpansion.Findings.All(f => !f.CanRemediate) && largeExpansion.Notes.Any(n => n.Contains("单文件 256 MiB")));
        using (FileStream largeUnlocked = File.Open(large, FileMode.Open, FileAccess.ReadWrite, FileShare.None)) Check("0.1.16 超限路径不残留占用", largeUnlocked.CanWrite);

        ScanOptions originalSettings = new()
        {
            Mode = ScanMode.Custom,
            IncludeSystem = false,
            IncludeSteam = false,
            IncludeWorkshop = false,
            InspectArchives = true,
            HashEveryFile = true,
            CustomRoots = [directory],
            UseAmsi = false
        };
        ScanReport report = new() { Findings = duplicates.ToList(), ContentScanSettings = originalSettings };
        RemediationBatchSession one = await new RemediationBatchPlanner(new()).PrepareAsync(duplicates, report, false,
            (_, _) => Task.FromResult(new ScanReport { ContentScanSettings = new() { InspectArchives = false, CustomRoots = [file] } }));
        Check("0.1.16 全选重复归档按唯一目标生成完整计划", one.Targets.Count == 1 && one.PlannedCount == 1 && one.Plans.Single().Actions.Count == 1 && one.Targets.Single().MissingActions.Count == 0);
        string changing = Path.Combine(directory, "changing.dat"); File.Copy(file, changing);
        Finding changingFinding = FindingFor(changing);
        RemediationBatchSession changedInPreparation = await new RemediationBatchPlanner(new()).PrepareAsync([changingFinding], new() { Findings = [changingFinding] }, false,
            async (_, _) => { await File.WriteAllTextAsync(changing, "changed inert bytes"); return new(); });
        Check("0.1.16 两个核验阶段之间的身份变化不可沿用缓存", changedInPreparation.Plans.Count == 0 && changedInPreparation.Targets.Single().Reason.Contains("变化"));
        RemediationBatchSession inspectionFailure = await new RemediationBatchPlanner(new()).PrepareAsync([FindingFor(file)], report, false,
            (_, _) => throw new InvalidDataException("inert malformed inspector result"));
        Check("0.1.16 附加检查格式失败保留逐项未纳入原因", inspectionFailure.Plans.Count == 0 && inspectionFailure.Targets.Single().Reason.Contains("inert malformed"));
        originalSettings.CustomRoots.Add("later-change");
        Check("0.1.16 附加检查不污染原范围设置且使用深拷贝", one.OriginalContentSettings is { InspectArchives: true } && one.OriginalContentSettings.CustomRoots.SequenceEqual([directory]) && report.ContentScanSettings!.InspectArchives);

        string missing = Path.Combine(directory, "missing.dat");
        Finding stale = FindingFor(file, new string('A', 64));
        RemediationBatchSession omitted = await new RemediationBatchPlanner(new()).PrepareAsync([FindingFor(missing), stale],
            new() { Findings = [FindingFor(missing), stale] }, true);
        Check("0.1.16 原始选择全部丢失时不生成仅阻断域名的成功方案", omitted.Targets.Count == 2 && omitted.Plans.Count == 0 && omitted.Targets.All(t => t.Status == "未处理" && t.MissingActions.Count > 0 && t.Reason.Length > 0));

        Finding[] many = Enumerable.Range(0, 70).Select(i => FindingFor(Path.Combine(directory, $"part-{i}.dat"))).ToArray();
        foreach (Finding f in many) File.Copy(file, f.Target);
        RemediationBatchSession packed = await new RemediationBatchPlanner(new()).PrepareAsync(many, new() { Findings = many.ToList() }, false);
        Check("0.1.16 七十个目标自动拆批且无遗漏", packed.Plans.Count == 2 && packed.Plans.All(p => p.Actions.Count <= 64) &&
            packed.Targets.Count == 70 && packed.Targets.All(t => t.ActionIds.Count == 1 && t.MissingActions.Count == 0) && packed.Plans.Sum(p => p.Actions.Count) == 70);
        Finding relatedFile = many[0];
        Finding process = new()
        {
            Target = file,
            RelatedFilePath = relatedFile.Target,
            ProcessId = 123456,
            SuggestedActions = [SuggestedActionKind.StopHostProcess],
            CanRemediate = true
        };
        Finding shared = new()
        {
            Target = file,
            RelatedFilePath = many[1].Target,
            ProcessId = 123456,
            SuggestedActions = [SuggestedActionKind.StopHostProcess],
            CanRemediate = true
        };
        Check("0.1.16 共享宿主进程及两个文件始终同组", RemediationBatchPlanner.DependencyGroups([relatedFile, process, shared, many[1]]).Count == 1);
        Finding parent = new() { Target = directory, CanRemediate = true, SuggestedActions = [SuggestedActionKind.QuarantineDirectory] };
        Check("0.1.16 父目录与其内文件不跨批拆开", RemediationBatchPlanner.DependencyGroups([parent, many[2]]).Count == 1);

        int calls = 0;
        RemediationRunResult Success(RemediationPlan plan) => new()
        {
            PlanId = plan.PlanId,
            Success = true,
            VerificationStatus = RemediationVerificationStatus.Verified,
            Actions = plan.Actions.Select(a => new RemediationActionResult
            {
                ActionId = a.ActionId,
                Target = a.Target,
                Type = a.Type,
                Success = true,
                VerificationStatus = RemediationVerificationStatus.NoResidual
            }).ToList()
        };
        await RemediationBatchPlanner.ExecuteAsync(packed, p => { calls++; return Task.FromResult(Success(p)); });
        Check("0.1.16 全批模拟执行逐项成功且没有运行Broker", calls == 2 && packed.Targets.All(t => t.Status == "已完成") && packed.Results.Count == 2);
        bool refused = false;
        try { await RemediationBatchPlanner.ExecuteAsync(packed, p => Task.FromResult(Success(p))); } catch (InvalidOperationException) { refused = true; }
        Check("0.1.16 同一批次会话禁止重复执行", refused);

        RemediationBatchSession Two() => new() { Plans = [packed.Plans[0], packed.Plans[1]] };
        RemediationBatchSession failure = Two(); calls = 0;
        await RemediationBatchPlanner.ExecuteAsync(failure, p => { calls++; return Task.FromResult(new RemediationRunResult { PlanId = p.PlanId, Success = false }); });
        Check("0.1.16 一批失败即暂停后续批次且保留失败记录", calls == 1 && failure.Results.Count == 1 && failure.Interruption is not null);
        RemediationBatchSession cancelled = Two(); calls = 0;
        await RemediationBatchPlanner.ExecuteAsync(cancelled, p => { calls++; throw new OperationCanceledException("cancelled UAC"); });
        Check("0.1.16 UAC取消不继续其他批次", calls == 1 && cancelled.Results.Count == 0 && cancelled.Interruption is not null);
        RemediationBatchSession expired = new() { Plans = [new() { ExpiresAtUtc = DateTimeOffset.UtcNow.AddMinutes(-1), Actions = packed.Plans[0].Actions }] };
        calls = 0;
        await RemediationBatchPlanner.ExecuteAsync(expired, p => { calls++; return Task.FromResult(Success(p)); });
        Check("0.1.16 后续计划过期不静默刷新身份和期限", calls == 0 && expired.Interruption!.Contains("过期"));
        RemediationBatchSession inconsistent = Two(); calls = 0;
        await RemediationBatchPlanner.ExecuteAsync(inconsistent, p => { calls++; var result = Success(p); result.Actions[0].Success = false; return Task.FromResult(result); });
        Check("0.1.16 总成功与单项失败矛盾时暂停", calls == 1 && inconsistent.Interruption is not null);
        RemediationBatchSession wrongResult = Two();
        await RemediationBatchPlanner.ExecuteAsync(wrongResult, p => Task.FromResult(new RemediationRunResult { PlanId = Guid.NewGuid(), Success = true }));
        Check("0.1.16 错配计划结果不采信", wrongResult.Results.Count == 0 && wrongResult.Interruption is not null);

        string bundle = Path.Combine(directory, "batch-export.zip");
        await CaseBundleExporter.ExportAsync(bundle, report, null, null, new(), batches: packed, contentFollowUp: new());
        using ZipArchive zip = ZipFile.OpenRead(bundle);
        Check("0.1.16 完整记录含全部批次与两种复查且没有样本", zip.GetEntry("batches.json") is not null &&
            zip.GetEntry("batches/001/result.json") is not null && zip.GetEntry("batches/002/result.json") is not null &&
            zip.GetEntry("content-follow-up.json") is not null && zip.Entries.All(e => !e.Name.EndsWith(".dat")));
        Check("0.1.16 系统保护告警与文件复活明确区分", SteamSentinel.App.MainWindow.SystemFollowUpSummary(new() { Findings = [new() { RuleId = "SECURITY-CONTROLS-DISABLED" }] }).Contains("不是样本复活"));
        Check("0.1.16 内容复查仍有覆盖缺口不声称完全清除", SteamSentinel.App.MainWindow.ContentFollowUpSummary(new() { Coverage = ScanCoverage.Partial }).Contains("不代表全部清除"));
    }
}
