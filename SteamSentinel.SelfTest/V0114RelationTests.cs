using System.IO;
using System.Text;
using System.Xml;
using SteamSentinel.Core.Models;
using SteamSentinel.Core.Remediation;
using SteamSentinel.Core.Scanning;
using SteamSentinel.Core.Utilities;

namespace SteamSentinel.SelfTest;

internal static partial class Program
{
    // Inert file fixtures only: never creates a host Run value/task/service or launches a fixture.
    private static async Task TestV0114RelationAsync(string root)
    {
        string directory = Path.Combine(root, "v0114-relations");
        Directory.CreateDirectory(directory);
        string payload = Path.Combine(directory, "unrelated-name.dat");
        await File.WriteAllTextAsync(payload, "inert relation identity");
        string hash = await Hashing.Sha256FileAsync(payload);
        RuleSet knownRules = new() { KnownHashes = [new() { Id = "FIXTURE", Sha256 = hash, Malware = true }] };
        RelatedArtifactScanner scanner = new(knownRules);
        ScanReport consumed = new(); consumed.Metrics.BytesHashed = 2L * 1024 * 1024 * 1024;
        // A command target needs an executable/script extension, but fixture bytes are never executed.
        string executable = Path.Combine(directory, "random renamed loader.exe");
        File.Copy(payload, executable);
        var match = await scanner.MatchCommandAsync("\"" + executable + "\"", consumed, default);
        Check("关联哈希独立于已超过 1GiB 的报告累计预算", match?.Hash == hash && consumed.Metrics.BytesHashed > 2L * 1024 * 1024 * 1024);
        Check("命令的实际精确目标成为优先候选", consumed.CandidateRoots.FirstOrDefault() == executable);
        await File.WriteAllTextAsync(executable, "changed inert fixture");
        Check("同一 scanner 新调用不重用已变化文件哈希缓存", await scanner.MatchCommandAsync("\"" + executable + "\"", new(), default) is null);
        ScanReport unknownCandidates = new();
        await new RelatedArtifactScanner(new()).MatchCommandAsync("\"" + executable + "\"", unknownCandidates, default);
        Check("未知哈希实际启动目标仍收集且不标记恶意", unknownCandidates.CandidateRoots.Contains(executable) && unknownCandidates.Findings.All(f => !f.IsKnownMalware));

        string tasks = Path.Combine(directory, "tasks"); Directory.CreateDirectory(Path.Combine(tasks, "Folder"));
        string taskFile = Path.Combine(tasks, "Folder", "Test");
        string xml = "<Task xmlns=\"http://schemas.microsoft.com/windows/2004/02/mit/task\"><Actions><Exec><Command>" +
            System.Security.SecurityElement.Escape(executable) + "</Command><Arguments>--fixture</Arguments></Exec></Actions></Task>";
        await File.WriteAllTextAsync(taskFile, xml, Encoding.Unicode);
        RelatedTaskSnapshot snapshot = await RelatedTaskSnapshotReader.ReadUnderRootAsync(@"\Folder\Test", tasks, default);
        Check("任务专用读取器以同一原始字节绑定 XML 哈希", snapshot.Sha256 == await Hashing.Sha256FileAsync(taskFile) && snapshot.Commands.Count == 1);
        Check("任务 Command 空格路径有准确调用形式", snapshot.Invocations.Single() == "\"" + executable + "\" --fixture");
        foreach (string invalid in new[] { @"..\escape", @"C:\outside", @"\\server\share", @"\Folder\Test:stream", @"\Folder\*" })
        {
            bool refused = false;
            try { await RelatedTaskSnapshotReader.ReadUnderRootAsync(invalid, tasks, default); }
            catch (Exception ex) when (ex is IOException or InvalidDataException or UnauthorizedAccessException) { refused = true; }
            Check("任务专用读取器拒绝逃逸/UNC/ADS/通配符 " + invalid, refused);
        }
        await File.WriteAllTextAsync(taskFile, "<!DOCTYPE Task [<!ENTITY x SYSTEM 'file:///not-read'>]><Task><Actions>&x;</Actions></Task>");
        bool rejected = false;
        try { await RelatedTaskSnapshotReader.ReadUnderRootAsync(@"\Folder\Test", tasks, default); }
        catch (XmlException) { rejected = true; }
        Check("任务 XML 禁止 DTD 和外部实体", rejected);
        await File.WriteAllBytesAsync(taskFile, new byte[RelatedTaskSnapshotReader.MaximumBytes + 1]);
        rejected = false;
        try { await RelatedTaskSnapshotReader.ReadUnderRootAsync(@"\Folder\Test", tasks, default); }
        catch (InvalidDataException) { rejected = true; }
        Check("任务 XML 实际读取受 2MiB 限制", rejected);
        using (CancellationTokenSource cancelled = new())
        {
            cancelled.Cancel(); rejected = false;
            try { await scanner.ExpandAsync([], new(), cancelled.Token); }
            catch (OperationCanceledException) { rejected = true; }
            Check("关联扩展传播取消而非返回完整空结果", rejected);
        }

        Finding FileFinding(string target, string? identity, string rule = "FIXTURE") => new()
        {
            RuleId = rule, Category = FindingCategory.File, Target = target, Sha256 = identity, TargetSha256 = identity,
            Score = 95, CanRemediate = true, SuggestedActions = [SuggestedActionKind.QuarantineFile]
        };
        Finding file = FileFinding(payload, hash);
        Finding ProcessFinding(int pid) => new()
        {
            Category = FindingCategory.Process, Target = payload, Sha256 = hash, ProcessId = pid,
            ProcessStartedAtUtc = DateTimeOffset.UnixEpoch.AddMinutes(pid), RelatedFilePath = payload, RelatedFileSha256 = hash,
            CanRemediate = true, Score = 100, SuggestedActions = [SuggestedActionKind.StopProcess]
        };
        Finding RunFinding(string view, string command, string? relatedHash = null) => new()
        {
            RuleId = "PERSISTENCE-RUN-BOUND", Category = FindingCategory.Persistence, Target = command,
            RegistryHive = "HKLM", RegistryView = view, RegistryKey = @"Software\Microsoft\Windows\CurrentVersion\Run",
            RegistryValueName = "sameName", RelatedFilePath = payload, RelatedFileSha256 = relatedHash ?? hash,
            CanRemediate = true, Score = 100, SuggestedActions = [SuggestedActionKind.RemoveRegistryValue]
        };
        Finding task = new()
        {
            RuleId = "PERSISTENCE-TASK-BOUND", Target = @"\Fixture", Sha256 = new string('A', 64),
            RelatedFilePath = payload, RelatedFileSha256 = hash, ConfigurationSnapshot = "\"" + payload + "\"",
            CanRemediate = true, Score = 100, SuggestedActions = [SuggestedActionKind.RemoveScheduledTask]
        };
        Finding[] all = [file, ProcessFinding(10001), ProcessFinding(10002), RunFinding("Registry64", payload),
            RunFinding("Registry32", payload), task, RunFinding("Default", "unrelated", new string('B', 64))];
        RemediationPlan plan = await new RemediationPlanBuilder(knownRules).BuildAsync([file], false, allFindings: all);
        Check("单选文件闭包包含两个精确关联进程、两种注册表视图、任务和隔离", plan.Actions.Count == 6 &&
            plan.Actions.Count(a => a.Type == RemediationActionType.StopProcess) == 2 &&
            plan.Actions.Count(a => a.Type == RemediationActionType.RemoveRegistryValue) == 2 &&
            plan.Actions.Count(a => a.Type == RemediationActionType.QuarantineFile) == 1);
        Check("处置计划先停进程再去启动项最后隔离", plan.Actions.Take(2).All(a => a.Type == RemediationActionType.StopProcess) &&
            plan.Actions.Last().Type == RemediationActionType.QuarantineFile && plan.Actions.All(a => a.Target != "unrelated"));
        Check("进程动作保留 PID 启动时间映像及关联哈希绑定", plan.Actions.Where(a => a.Type == RemediationActionType.StopProcess)
            .All(a => a.ProcessStartedAtUtc is not null && a.ExpectedSha256 == hash && a.RelatedFileSha256 == hash));
        Check("从关联项反向闭包包含确认文件", RelatedArtifactRelations.SelectForPlan([task], all, knownRules).Any(f => f == file));
        rejected = false;
        try { await new RemediationPlanBuilder(new()).BuildAsync([FileFinding(payload, null)], false); }
        catch (InvalidDataException) { rejected = true; }
        Check("文件无原始身份不能在构建计划时采用新哈希", rejected);
        rejected = false;
        try { await new RemediationPlanBuilder(new()).BuildAsync([new Finding { Target = payload, Sha256 = hash, ProcessId = 101,
            CanRemediate = true, SuggestedActions = [SuggestedActionKind.StopProcess] }], false); }
        catch (InvalidDataException) { rejected = true; }
        Check("缺少进程启动时间拒绝输出停止动作", rejected);
        rejected = false;
        try
        {
            await new RemediationPlanBuilder(new()).BuildAsync(Enumerable.Range(0, 65).Select(i => new Finding
            {
                Target = "inert", RegistryHive = "HKCU", RegistryView = "Default", RegistryKey = @"Software\Microsoft\Windows\CurrentVersion\Run",
                RegistryValueName = "fixture-" + i, CanRemediate = true, SuggestedActions = [SuggestedActionKind.RemoveRegistryValue]
            }), false);
        }
        catch (InvalidDataException ex) { rejected = ex.Message.Contains("请按关联组分批处理"); }
        Check("超过64动作整体拒绝而非截断关联链", rejected);

        await File.WriteAllTextAsync(payload, "new inert snapshot");
        rejected = false;
        try { await new RemediationPlanBuilder(new()).BuildAsync([file], false); }
        catch (InvalidDataException) { rejected = true; }
        Check("处置计划拒绝扫描后改变的文件", rejected);
        ScanReport oldReport = new() { Findings = [file] };
        RelatedArtifactExpansion stale = await scanner.ExpandAsync([file], oldReport);
        Check("关联扩展不静默更新旧内容哈希", !stale.Findings.Any(f => f.CanRemediate) && stale.Notes.Any(n => n.Contains("变化")) && oldReport.Findings.Count == 1);

        RuleSet whitelist = new() { KnownRunValueNames = ["allowed"], KnownTaskNames = [@"\Allowed"] };
        RelatedArtifactScanner allowedScanner = new(whitelist);
        Finding legacyRun = new() { RuleId = "PERSISTENCE-RUN-KNOWN", Target = "missing.exe", RegistryHive = "HKCU", RegistryView = "Default",
            RegistryKey = @"Software\Microsoft\Windows\CurrentVersion\Run", RegistryValueName = "allowed", CanRemediate = true,
            SuggestedActions = [SuggestedActionKind.RemoveRegistryValue] };
        Finding? orphan = allowedScanner.PreserveAllowlistedSnapshot(legacyRun, legacyRun);
        Check("原白名单孤立 Run 项原值一致可移除但不宣称已知恶意", orphan is { CanRemediate: true, IsKnownMalware: false, RelatedFilePath: null });
        Finding changedRun = new() { Target = "changed.exe", RegistryHive = "HKCU", RegistryView = "Default", RegistryKey = legacyRun.RegistryKey, RegistryValueName = "allowed" };
        Check("孤立 Run 项不能采用已变化的原值", allowedScanner.PreserveAllowlistedSnapshot(legacyRun, changedRun) is null);
        Finding legacyTask = new() { RuleId = "PERSISTENCE-TASK-KNOWN", Target = @"\Allowed", Sha256 = new string('C', 64), CanRemediate = true,
            SuggestedActions = [SuggestedActionKind.RemoveScheduledTask] };
        Check("原白名单孤立任务保留原 XML 身份", allowedScanner.PreserveAllowlistedSnapshot(legacyTask, legacyTask)?.Sha256 == legacyTask.Sha256 &&
            allowedScanner.PreserveAllowlistedSnapshot(legacyTask, new Finding { RuleId = legacyTask.RuleId, Target = legacyTask.Target, Sha256 = new string('D', 64) }) is null);

        Finding heuristic = FileFinding(payload, await Hashing.Sha256FileAsync(payload), "HEUR-STEAM-UI-PATCHER");
        Check("强原始文件启发式可闭包但仍非已知恶意", RelatedArtifactRelations.SupportsHeuristicEntry(heuristic) && !heuristic.IsKnownMalware);
        Finding archiveHeuristic = new() { RuleId = heuristic.RuleId, Target = payload, ContentPath = payload + "!/inner.py", Sha256 = hash,
            TargetSha256 = heuristic.Sha256, Score = 95, CanRemediate = true, SuggestedActions = [SuggestedActionKind.QuarantineFile] };
        Check("归档内部证据不会当作原始文件独立运行绑定", !RelatedArtifactRelations.SupportsHeuristicEntry(archiveHeuristic) &&
            RelatedArtifactRelations.FileHash(archiveHeuristic) == heuristic.Sha256);
        Check("名称规则与低置信加载器不能获得启发式关联权限", !RelatedArtifactRelations.SupportsHeuristicEntry(FileFinding(payload, hash, "PROCESS-KNOWN-NAME")) &&
            !RelatedArtifactRelations.SupportsHeuristicEntry(FileFinding(payload, hash, "HEUR-ENCRYPTED-PYTHON-LOADER")));

        string restore = Path.Combine(directory, "steam", "package"); Directory.CreateDirectory(restore);
        await File.WriteAllTextAsync(Path.Combine(restore, "inert.txt"), "manual restore fixture");
        Finding folder = new() { RuleId = "STEAM-RESTORE-MANUAL", Category = FindingCategory.Steam, Target = restore,
            CanRemediate = true, SuggestedActions = [SuggestedActionKind.QuarantineDirectory] };
        RelatedArtifactExpansion manual = await new RelatedArtifactScanner(new()).ExpandAsync([folder], new());
        RemediationPlan folderPlan = await new RemediationPlanBuilder(new()).BuildAsync(manual.Findings, false);
        Check("明确选择的 Steam 恢复目录保留且生成兼容指纹", folderPlan.Actions.Single().ExpectedSha256 == await DirectoryFingerprint.ComputeAsync(restore) &&
            manual.Notes.Any(n => n.Contains("人工确认")));
        Finding scannedFolder = new() { Target = restore, TargetSha256 = folderPlan.Actions.Single().ExpectedSha256, CanRemediate = true,
            SuggestedActions = [SuggestedActionKind.QuarantineDirectory] };
        Check("普通可操作扫描目录保留匹配的原始指纹", (await new RelatedArtifactScanner(new()).ExpandAsync([scannedFolder], new())).Findings.Contains(scannedFolder));
        await File.WriteAllTextAsync(Path.Combine(restore, "inert.txt"), "changed directory fixture");
        Check("已变化扫描目录不静默采用新指纹", !(await new RelatedArtifactScanner(new()).ExpandAsync([scannedFolder], new())).Findings.Any(f => f.CanRemediate));
        Finding unknownFolder = new() { Target = restore, SuggestedActions = [SuggestedActionKind.ReviewOnly] };
        Check("未知目录不因存在而变成自动隔离", !(await new RelatedArtifactScanner(new()).ExpandAsync([unknownFolder], new())).Findings.Any(f => f.CanRemediate));

        string link = Path.Combine(directory, "inert-startup.lnk");
        await File.WriteAllTextAsync(link, "inert saved shortcut snapshot; never parsed or executed");
        string linkHash = await Hashing.Sha256FileAsync(link);
        Finding startup = new()
        {
            RuleId = "PERSISTENCE-STARTUP-LINK", Target = link, Sha256 = linkHash,
            RelatedFilePath = Path.Combine(directory, "already-missing.exe"), RelatedFileSha256 = hash,
            CanRemediate = true, SuggestedActions = [SuggestedActionKind.QuarantineFile]
        };
        RelatedArtifactExpansion startupExpansion = await new RelatedArtifactScanner(new()).ExpandAsync([startup], new());
        RemediationPlan startupPlan = await new RemediationPlanBuilder(new()).BuildAsync(startupExpansion.Findings, false, allFindings: startupExpansion.Findings);
        Check("已选择启动快捷方式按自身哈希保留隔离，不借用缺失载荷哈希", startupPlan.Actions.Single().Target == link &&
            startupPlan.Actions.Single().ExpectedSha256 == linkHash && linkHash != hash);
        await File.WriteAllTextAsync(link, "changed inert link snapshot");
        Check("启动快捷方式自身变化拒绝沿用", !(await new RelatedArtifactScanner(new()).ExpandAsync([startup], new())).Findings.Any(f => f.CanRemediate));

        List<Finding> many = [];
        for (int i = 0; i < 65; i++)
        {
            string path = Path.Combine(directory, $"candidate-{i}.dat"); await File.WriteAllTextAsync(path, "inert");
            many.Add(new() { Target = path, SuggestedActions = [SuggestedActionKind.ReviewOnly] });
        }
        RelatedArtifactExpansion bounded = await new RelatedArtifactScanner(new()).ExpandAsync(many, new());
        Check("UI 候选最多64个精确文件且明确标注未覆盖", bounded.CandidatePaths.Count == 64 && bounded.CandidatePaths.All(File.Exists) &&
            bounded.Notes.Any(n => n.Contains("64 项上限")));
    }
}
