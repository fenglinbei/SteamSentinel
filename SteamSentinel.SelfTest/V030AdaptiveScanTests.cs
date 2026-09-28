using System.Diagnostics;
using System.IO;
using System.IO.Compression;
using System.Text.Json;
using SteamSentinel.App.Services;
using SteamSentinel.App.Native;
using SteamSentinel.Core.Inspection;
using SteamSentinel.Core.Models;
using SteamSentinel.Core.Reporting;
using SteamSentinel.Core.Rules;
using SteamSentinel.Core.Scanning;
using SteamSentinel.Core.Utilities;

namespace SteamSentinel.SelfTest;

internal static partial class Program
{
    private static int AdaptiveTestCpuCapacity(int logicalProcessors)
    {
        // Production reserves one of each pair of logical processors, then uses
        // only 1/2/4 slots. Keep real execution inside that CPU capacity.
        int slots = Math.Max(1, logicalProcessors / 2);
        return slots >= 4 ? 4 : slots >= 2 ? 2 : 1;
    }

    private static async Task TestV030AdaptiveScanAsync(string root)
    {
        string directory = Path.Combine(root, "adaptive-" + Guid.NewGuid().ToString("N")); Directory.CreateDirectory(directory);
        const long MiB = 1048576;
        ScanMachineResources machine = new(32L * 1024 * MiB, 32L * 1024 * MiB, 64L * 1024 * MiB, 100L * 1024 * MiB, 16, DateTimeOffset.UtcNow, Path.GetPathRoot(directory)!);
        ScanOptions Options(string path, params (string Key, decimal Value)[] limits)
        {
            ScanLimitSettings settings = new() { PerformanceMode = ScanPerformanceMode.LowImpact };
            foreach (var pair in limits) settings.Full[pair.Key] = pair.Value;
            return settings.Apply(new()
            {
                Mode = ScanMode.Custom,
                IncludeSystem = false,
                IncludeSteam = false,
                IncludeWorkshop = false,
                UseAmsi = false,
                CustomRoots = [path],
                HashEveryFile = true
            });
        }
        ScanLimitResponse Approve(ScanOptions options, ScanLimitRequest request)
        {
            ScanResourceProposal proposal = ScanResourcePlanner.Propose(options, request, machine);
            if (proposal.Assessment != ResourceAssessmentKind.EstimatedAvailable) throw new InvalidDataException(proposal.ReasonCode);
            return new(request.RequestId, ResourceDecisionKind.Approve, proposal.Changes);
        }
        static bool Rejects(Action action) { try { action(); return false; } catch (Exception e) when (e is InvalidDataException or ArgumentException or OverflowException) { return true; } }
        ScanOptions initial = Options(directory, ("ContainerLimits.MaximumEntryBytes", 1m));
        ScanLimitRequest request = new(Guid.NewGuid().ToString("N"), "ContainerLimits.MaximumEntryBytes", MiB, 3 * MiB,
            0, true, "inert.zip!/inert.txt", 256 * MiB, 10 * MiB, 20 * MiB, 5 * MiB);
        ScanResourceProposal proposal = ScanResourcePlanner.Propose(initial, request, machine);
        Check("自适应 已知单项精确提额并评估临时磁盘", proposal.Assessment == ResourceAssessmentKind.EstimatedAvailable && proposal.Changes[0].After == 3 * MiB && proposal.AdditionalTemporaryBytes == 3 * MiB);
        Check("自适应 磁盘预留不能以提高额度绕过", ScanResourcePlanner.Propose(initial, request, machine with { TemporaryFreeBytes = MiB }).Assessment == ResourceAssessmentKind.Insufficient);
        Check("自适应 资源未知不允许估算通过", ScanResourcePlanner.Propose(initial, request, machine with { AvailableMemoryBytes = -1 }).Assessment == ResourceAssessmentKind.Unknown);
        Check("自适应 不足提交余量与物理内存分别检查", ScanResourcePlanner.Propose(initial, request with { LimitKey = "MaximumAmsiBytes", CurrentLimit = initial.MaximumAmsiBytes, RequiredMinimum = 64 * MiB }, machine with { CommitHeadroomBytes = MiB }).Assessment == ResourceAssessmentKind.Insufficient);
        Check("自适应 性能档为有界1/2/4且资源未知回1", ScanResourcePlanner.ParallelFiles(machine, ScanPerformanceMode.LowImpact) == 1 && ScanResourcePlanner.ParallelFiles(machine, ScanPerformanceMode.Automatic) == 2 && ScanResourcePlanner.ParallelFiles(machine, ScanPerformanceMode.HighThroughput) == 4 && ScanResourcePlanner.ParallelFiles(machine with { AvailableMemoryBytes = -1 }, ScanPerformanceMode.HighThroughput) == 1);
        foreach (var (logicalProcessors, expectedCapacity) in new[] { (2, 1), (4, 2), (8, 4) })
            Check($"自适应 模拟{logicalProcessors}逻辑CPU精确规划{expectedCapacity}路",
                ScanResourcePlanner.ParallelFiles(machine with { LogicalProcessors = logicalProcessors }, ScanPerformanceMode.HighThroughput) == expectedCapacity &&
                AdaptiveTestCpuCapacity(logicalProcessors) == expectedCapacity);
        Check("自适应 拒绝权限字段与降低磁盘预留", Rejects(() => ScanLimitAccess.Apply(initial, [new("UseAmsi", 0, 1)])) && Rejects(() => ScanLimitAccess.Apply(initial, [new("ContainerLimits.ReservedDiskBytes", 0, MiB)])));
        ScanOptions copied = ArchiveWorkerClient.CopyOptions(initial);
        ScanLimitAccess.Apply(copied, proposal.Changes);
        Check("自适应 Worker副本与界面默认设置隔离", copied.MaximumEntryBytes == 3 * MiB && initial.MaximumEntryBytes == MiB && !ReferenceEquals(copied.ContainerLimits, initial.ContainerLimits));
        Check("自适应 过期与重复授权原子拒绝", Rejects(() => ScanLimitAccess.Apply(copied, proposal.Changes)) && Rejects(() => ScanLimitAccess.Apply(initial, [proposal.Changes[0], proposal.Changes[0]])) && initial.MaximumEntryBytes == MiB);
        long originalFiles = initial.MaximumFiles;
        Check("自适应 混入无效字段不会应用前面的有效额度", Rejects(() => ScanLimitAccess.Apply(initial, [new("MaximumFiles", originalFiles, originalFiles + 1), new("UseAmsi", 0, 1)])) && initial.MaximumFiles == originalFiles);
        using (JobObject job = new(256 * MiB))
        {
            var before = job.QueryLimits(); job.SetMemoryLimit(512 * MiB); var after = job.QueryLimits();
            Check("自适应 实际Job只提高内存并保留单进程及UI隔离", after.Memory == 512 * MiB && after.Processes == 1 && before.Flags == after.Flags && before.Ui == after.Ui && (after.Flags & 0x2508) == 0x2508);
        }
        ScanOptions recordOptions = Options(directory, ("MaximumReportRecords", 1), ("MaximumReportTextCharacters", 1));
        using (ScanResourceSession session = new(recordOptions, r => Approve(recordOptions, r), default))
        {
            ScanReport records = new() { ContentScanSettings = recordOptions, Findings = [new() { Title = "one" }, new() { Title = "two" }] };
            session.Bind(records); new ScanResourceGuard().Check(records);
            Check("自适应 报告条数和文本限制可授权且保留原记录", records.Findings.Count == 2 && session.Audit.Decisions.Select(d => d.Request.LimitKey).ToHashSet().IsSupersetOf(["MaximumReportRecords", "MaximumReportTextCharacters"]));
        }
        ScanOptions timed = Options(directory, ("ContainerLimits.MaximumDurationSeconds", 1));
        using (ScanResourceSession session = new(timed, r => { Thread.Sleep(1100); return Approve(timed, r); }, default))
        {
            ContainerResourceBudget budget = new(timed.ContainerLimits!);
            bool allowed = ScanResourceSession.Allow("MaximumStringScanBytes", timed.MaximumStringScanBytes + 1);
            budget.Check();
            Check("自适应 等待用户不消耗扫描时限", allowed && session.WaitingMilliseconds >= 1000 && budget.Snapshot().ElapsedMilliseconds < 800);
        }
        ScanOptions refusal = Options(directory);
        int refusalCalls = 0;
        using (ScanResourceSession session = new(refusal, r => { refusalCalls++; return new(r.RequestId, ResourceDecisionKind.Skip, []); }, default))
        {
            using (ScanResourceSession.EnterTarget("first")) ScanResourceSession.Allow("MaximumFiles", refusal.MaximumFiles + 1L, known: false);
            using (ScanResourceSession.EnterTarget("second")) ScanResourceSession.Allow("MaximumFiles", refusal.MaximumFiles + 2L, known: false);
            Check("自适应 已拒绝全局预算不会换文件反复弹窗", refusalCalls == 1 && session.Audit.Decisions.Count == 1);
        }

        string leaf = Path.Combine(directory, "ordinary.txt"); await File.WriteAllTextAsync(leaf, new string('a', 8192));
        ScanOptions increasing = Options(leaf, ("MaximumStringScanBytes", 4m / MiB), ("ContainerLimits.MaximumWorkBytes", 16m / MiB));
        ScanReport approved;
        using (ScanResourceSession session = new(increasing, r => Approve(increasing, r), default))
        {
            approved = await new ScanCoordinator().RunAsync(increasing);
            Check("自适应 读取与字符串限制批准后从检查点完成", approved.Coverage == ScanCoverage.Complete && approved.Metrics.FilesVisited == 1 && approved.Metrics.BytesHashed == 8192 && session.Audit.Decisions.Any(d => d.Request.LimitKey == "ContainerLimits.MaximumWorkBytes") && session.Audit.Decisions.Any(d => d.Request.LimitKey == "MaximumStringScanBytes"));
            Check("自适应 批准未重复建节点或重置累计读取", approved.Containers?.Nodes.Count == 1 && approved.Containers.Resources.ReadBytes >= 16384);
        }
        ScanOptions declining = Options(leaf, ("MaximumStringScanBytes", 4m / MiB));
        using (ScanResourceSession session = new(declining, r => new(r.RequestId, ResourceDecisionKind.Skip, []), default))
        {
            ScanReport declined = await new ScanCoordinator().RunAsync(declining);
            Check("自适应 保持限制真实记录未覆盖与已完成哈希", declined.Coverage == ScanCoverage.Partial && declined.Containers!.Nodes[0].Sha256 is not null && declined.Containers.Nodes[0].Engines.Any(e => e.Status == ContainerStageStatus.LimitReached));
        }
        ScanOptions stopping = Options(leaf, ("MaximumStringScanBytes", 4m / MiB)); ScanReport? stopped = null;
        using (ScanResourceSession session = new(stopping, r => new(r.RequestId, ResourceDecisionKind.Stop, []), default))
        {
            bool cancelled = false;
            try { await new ScanCoordinator().RunAsync(stopping, checkpoint: r => stopped = r); } catch (OperationCanceledException) { cancelled = true; }
            Check("自适应 停止操作保留取消状态和当前节点", cancelled && stopped?.ExecutionState == ScanExecutionState.Cancelled && stopped.Containers?.Nodes[0].Sha256 is not null);
        }

        string archivePath = Path.Combine(directory, "inert.zip");
        using (ZipArchive zip = ZipFile.Open(archivePath, ZipArchiveMode.Create))
        using (Stream member = zip.CreateEntry("inert.txt", CompressionLevel.NoCompression).Open()) member.Write(new byte[8192]);
        ScanOptions archived = Options(archivePath, ("ContainerLimits.MaximumEntryBytes", 4m / MiB));
        using (ScanResourceSession session = new(archived, r => Approve(archived, r), default))
        {
            ScanReport archive = await new ScanCoordinator().RunAsync(archived);
            Check("自适应 ZIP单项提高后真实展开与哈希", archive.Coverage == ScanCoverage.Complete && archive.Containers!.Nodes.Any(n => n.Kind == ContainerNodeKind.ArchiveMember && n.Length == 8192 && n.Sha256 is not null) && session.Audit.Decisions.Any(d => d.Request.LimitKey == "ContainerLimits.MaximumEntryBytes"));
        }
        ScanOptions rangeOptions = Options(archivePath, ("RangeLimits.MaximumSignatureSearchBytes", 16m / MiB), ("RangeLimits.MaximumHeaderBytes", 8m / MiB), ("RangeLimits.MaximumReadBytes", 16m / MiB));
        using (ScanResourceSession session = new(rangeOptions, r => Approve(rangeOptions, r), default))
        using (FileStream input = File.OpenRead(archivePath))
        {
            ContainerRangeInspection range = ContainerRangeInspector.InspectArchiveAt(input, 0, input.Length, limits: rangeOptions.RangeLimits);
            Check("自适应 结构读取、搜索窗口和头长度提额后验证ZIP", range.Ranges.Any(r => r.Status == ContainerRangeStatus.Validated) && session.Audit.Decisions.Count >= 2);
        }
        ScanOptions volumeOptions = Options(directory, ("ContainerLimits.MaximumVolumes", 1), ("ContainerLimits.MaximumDirectoryCandidates", 1));
        using (ScanResourceSession session = new(volumeOptions, r => Approve(volumeOptions, r), default))
        {
            ArchiveVolumeCandidate[] candidates = Enumerable.Range(1, 3).Select(i => new ArchiveVolumeCandidate(Path.Combine(directory, $"data.7z.{i:D3}"), Path.Combine(directory, $"data.7z.{i:D3}"))).ToArray();
            ArchiveVolumePlan plan = ArchiveVolumeResolver.Resolve(candidates[0], candidates, new() { MaximumCandidates = 1, MaximumVolumes = 1 });
            Check("自适应 分卷候选与卷数按段提高并保留全部成员", plan.Status == ArchiveVolumeStatus.Ready && plan.Members.Count == 3 && session.Audit.Decisions.Any(d => d.Request.LimitKey.EndsWith("MaximumVolumes")));
        }
        string multipleZip = Path.Combine(directory, "multiple.zip");
        using (ZipArchive zip = ZipFile.Open(multipleZip, ZipArchiveMode.Create))
            for (int i = 0; i < 3; i++)
                using (Stream member = zip.CreateEntry($"ordinary-{i}.txt", CompressionLevel.NoCompression).Open()) member.Write(new byte[128]);
        ScanOptions metadataOptions = Options(multipleZip, ("ContainerLimits.MaximumMetadataAttempts", 1), ("ContainerLimits.MaximumEntries", 1), ("ContainerLimits.MaximumWorkBytes", 32m / MiB));
        using (ScanResourceSession session = new(metadataOptions, r => Approve(metadataOptions, r), default))
        {
            ScanReport multiple = await new ScanCoordinator().RunAsync(metadataOptions);
            Check("自适应 容器缓存的元数据额度随批准更新并完成全部成员", multiple.Coverage == ScanCoverage.Complete && multiple.Containers!.Nodes.Count(n => n.Kind == ContainerNodeKind.ArchiveMember && n.Sha256 is not null) == 3 && session.Audit.Decisions.Any(d => d.Request.LimitKey == "ContainerLimits.MaximumMetadataAttempts"));
        }
        ScanOptions volumeWorkOptions = Options(multipleZip, ("ContainerLimits.MaximumWorkBytes", 32m / MiB));
        using (ScanResourceSession session = new(volumeWorkOptions, r => Approve(volumeWorkOptions, r), default))
        {
            ArchiveVolumePlan plan = ArchiveVolumeResolver.Single(new(multipleZip, multipleZip), ArchiveVolumeFormat.Zip, new() { MaximumTotalBytes = 32 });
            using ArchiveVolumeSession opened = await ArchiveVolumeSession.OpenAsync(plan);
            Check("自适应 分卷会话物理字节预检可批准继续", opened.Identities.Count == 1 && session.Audit.Decisions.Any(d => d.Request.LimitKey == "ContainerLimits.MaximumWorkBytes"));
        }
        ReportBatchReader reader = new();
        ReportBatchWriter writer = new(batch => reader.Apply(JsonSerializer.Deserialize<ReportBatch>(JsonSerializer.Serialize(batch))!)); writer.Send(approved, final: true);
        Check("自适应 分批协议往返保留授权证据", reader.Report?.ResourceAudit?.Decisions.Count == approved.ResourceAudit!.Decisions.Count && reader.Report?.Containers?.Nodes.Count == 1);
        Check("自适应 拒绝伪造Skip携带额度", Rejects(() => new ScanResourceAudit { Decisions = [new(request, ResourceDecisionKind.Skip, proposal.Changes, DateTimeOffset.UtcNow)] }.Validate()));
        Check("自适应 拒绝历史重复请求", Rejects(() => new ScanResourceAudit { Decisions = [new(request, ResourceDecisionKind.Approve, proposal.Changes, DateTimeOffset.UtcNow), new(request, ResourceDecisionKind.Approve, proposal.Changes, DateTimeOffset.UtcNow)] }.Validate()));

        string corpus = Path.Combine(directory, "parallel"); Directory.CreateDirectory(corpus);
        RuleSet rules = RuleLoader.LoadEmbedded();
        for (int i = 0; i < 32; i++) await File.WriteAllTextAsync(Path.Combine(corpus, $"leaf-{i:D3}.txt"), i % 5 == 0 ? rules.KnownDomains[0] : new string('q', 2048));
        ScanOptions Sequential() => new()
        {
            Mode = ScanMode.Custom,
            IncludeSystem = false,
            IncludeSteam = false,
            IncludeWorkshop = false,
            UseAmsi = false,
            CustomRoots = [corpus],
            HashEveryFile = true,
            MaximumWorkerMemoryBytes = 8L * 1024 * MiB
        };
        ScanReport serial = await new ScanCoordinator().RunAsync(Sequential());
        static string Semantics(ScanReport report) => JsonSerializer.Serialize(new
        {
            report.Coverage,
            report.Metrics,
            nodes = report.Containers!.Nodes.Select(n => new { n.DisplayPath, n.Sha256, n.Length, n.Overall, n.ContentCheck, n.Integrity }).OrderBy(n => n.DisplayPath),
            findings = report.Findings.Select(f => new { f.RuleId, f.Target, f.ContentPath, f.Sha256, f.TargetSha256, f.Score, f.Severity, f.CanRemediate }).OrderBy(f => f.Target).ThenBy(f => f.RuleId),
            report.CoverageNotes
        });
        foreach (int concurrency in new[] { 2, 4 })
        {
            ScanOptions concurrent = Sequential();
            typeof(ScanOptions).GetProperty(nameof(ScanOptions.MaximumParallelFiles))!.SetValue(concurrent, concurrency);
            typeof(ScanOptions).GetProperty(nameof(ScanOptions.PerformanceMode))!.SetValue(concurrent, ScanPerformanceMode.HighThroughput);
            ScanReport parallel = await new ScanCoordinator().RunAsync(concurrent);
            int capacityCpu = AdaptiveTestCpuCapacity(parallel.ResourceAudit?.Preflight?.LogicalProcessors ?? Environment.ProcessorCount);
            int expectedConcurrency = Math.Min(concurrency, capacityCpu);
            Check($"自适应 {concurrency}路结果、哈希、命中和覆盖等价", Semantics(serial) == Semantics(parallel));
            Check($"自适应 {concurrency}路共用工作账本且未重复读取", serial.Containers!.Resources.ReadBytes == parallel.Containers!.Resources.ReadBytes);
            Check($"自适应 请求{concurrency}路按CPU容量实际启用{expectedConcurrency}路且有界", parallel.ResourceAudit?.PeakParallelFiles == expectedConcurrency);
            await JsonFile.WriteAtomicAsync(Path.Combine(directory, $"parallel-{concurrency}.json"), parallel);
        }
        foreach (string boundary in new[] { "files", "work", "hash" })
        {
            async Task<ScanReport> Limited(int concurrency)
            {
                ScanOptions settings = new()
                {
                    Mode = ScanMode.Custom,
                    IncludeSystem = false,
                    IncludeSteam = false,
                    IncludeWorkshop = false,
                    UseAmsi = false,
                    CustomRoots = [corpus],
                    MaximumParallelFiles = concurrency,
                    PerformanceMode = ScanPerformanceMode.HighThroughput,
                    MaximumWorkerMemoryBytes = 8L * 1024 * MiB,
                    MaximumFiles = boundary == "files" ? 3 : 200000,
                    MaximumContentBytes = boundary == "hash" ? 4096 : long.MaxValue,
                    ContainerLimits = new() { MaximumWorkBytes = boundary == "work" ? 8192 : 64L * 1024 * MiB }
                };
                ScanReport? latest = null;
                try { return await new ScanCoordinator().RunAsync(settings, checkpoint: report => latest = report); }
                catch (ScanResourceLimitException) { return latest!; }
            }
            ScanReport one = await Limited(1), four = await Limited(4);
            Check("自适应 接近全局额度回退串行且覆盖一致 " + boundary, Semantics(one) == Semantics(four) && one.Containers!.Resources.ReadBytes == four.Containers!.Resources.ReadBytes);
        }

        ScanOptions workerOptions = Options(leaf, ("MaximumStringScanBytes", 4m / MiB)); int requests = 0;
        ScanReport workerReport = await new ArchiveWorkerClient(DevelopmentWorkerPath()).RunAsync(workerOptions,
            (r, _) => Task.FromResult(new ArchivePasswordResponse(r.RequestId, true, null, false)), null, default,
            (p, _) => { requests++; return Task.FromResult(new ScanLimitResponse(p.Request.RequestId, ResourceDecisionKind.Approve, p.Changes)); });
        Check("自适应 真实受限Worker完成请求批准回传", requests > 0 && workerReport.Coverage == ScanCoverage.Complete && workerReport.ResourceAudit?.Decisions.Any(d => d.Decision == ResourceDecisionKind.Approve) == true);
        Check("自适应 单次Worker授权不写回调用方设置", workerOptions.MaximumStringScanBytes == 4 && workerReport.ContentScanSettings!.MaximumStringScanBytes >= 8192);
        await JsonFile.WriteAtomicAsync(Path.Combine(directory, "worker-approved.json"), workerReport);
        ScanOptions parallelWorkerOptions = new ScanLimitSettings { PerformanceMode = ScanPerformanceMode.HighThroughput }.Apply(new()
        {
            Mode = ScanMode.Custom,
            IncludeSystem = false,
            IncludeSteam = false,
            IncludeWorkshop = false,
            UseAmsi = false,
            CustomRoots = [corpus],
            HashEveryFile = true
        });
        ScanReport parallelWorker = await new ArchiveWorkerClient(DevelopmentWorkerPath()).RunAsync(parallelWorkerOptions,
            (r, _) => Task.FromResult(new ArchivePasswordResponse(r.RequestId, true, null, false)), null, default);
        int workerCapacityCpu = AdaptiveTestCpuCapacity(parallelWorker.ResourceAudit?.Preflight?.LogicalProcessors ?? Environment.ProcessorCount);
        int expectedWorkerConcurrency = Math.Min(parallelWorkerOptions.MaximumParallelFiles, workerCapacityCpu);
        int workerPeak = parallelWorker.ResourceAudit?.PeakParallelFiles ?? 1;
        Check("自适应 真实受限Worker遵守CPU容量且结果等价",
            (expectedWorkerConcurrency == 1 ? workerPeak == 1 : workerPeak >= 2 && workerPeak <= expectedWorkerConcurrency) &&
            Semantics(serial) == Semantics(parallelWorker));
        await JsonFile.WriteAtomicAsync(Path.Combine(directory, "worker-parallel.json"), parallelWorker);
        await TestV030BaselineEnhancementPolicyAsync(directory);
        ScanOptions workerStop = Options(leaf, ("MaximumStringScanBytes", 4m / MiB));
        bool workerCancelled = false;
        try
        {
            await new ArchiveWorkerClient(DevelopmentWorkerPath()).RunAsync(workerStop, (r, _) => Task.FromResult(new ArchivePasswordResponse(r.RequestId, true, null, false)), null, default,
                (p, _) => Task.FromResult(new ScanLimitResponse(p.Request.RequestId, ResourceDecisionKind.Stop, [])));
        }
        catch (WorkerCancelledException ex)
        {
            workerCancelled = ex.PartialReport is { ExecutionState: ScanExecutionState.Cancelled, ResourceAudit.Phase: ScanResourcePhase.Finished } && ex.PartialReport.Containers?.Nodes.Any(n => n.Sha256 is not null) == true;
        }
        Check("自适应 真实Worker停止保持取消语义且交付当前哈希", workerCancelled);
        bool invalidGrantRejected = false;
        try
        {
            await new ArchiveWorkerClient(DevelopmentWorkerPath()).RunAsync(workerStop, (r, _) => Task.FromResult(new ArchivePasswordResponse(r.RequestId, true, null, false)), null, default,
                (p, _) => Task.FromResult(new ScanLimitResponse(p.Request.RequestId, ResourceDecisionKind.Approve, [.. p.Changes, new("UseAmsi", 0, 1)])));
        }
        catch (WorkerFailureException ex) { invalidGrantRejected = ex.PartialReport?.ExecutionState == ScanExecutionState.Failed; }
        Check("自适应 真实协议拒绝夹带权限更改", invalidGrantRejected && workerStop.UseAmsi == false);
        foreach (var culture in new[] { DisplayText.Chinese, DisplayText.English })
            using (DisplayText.UseCulture(culture))
            {
                Check("自适应 中英文资源可解析 " + culture.Name, DisplayText.Get("Resource.Intro") != "Resource.Intro" && DisplayText.Get("Resource.Approve") != DisplayText.Get("Resource.Skip"));
                string[] keys = [.. Enum.GetNames<ResourceAssessmentKind>().Select(n => "Resource.Assessment." + n),
                    .. Enum.GetNames<ScanPerformanceMode>().Select(n => "Resource.Performance." + n),
                    .. new[] { "user_approved", "user_kept_limits", "user_stopped", "capacity_changed", "no_callback" }.Select(n => "Resource.Reason.resource." + n)];
                Check("自适应 动态状态和原因资源齐全 " + culture.Name, keys.All(key => DisplayText.Get(key) != key));
            }
        await TestV030ResourceDialogAsync(directory, proposal);
    }
}
