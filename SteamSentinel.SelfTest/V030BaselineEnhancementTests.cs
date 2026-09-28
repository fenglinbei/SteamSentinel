using System.Diagnostics;
using System.IO;
using System.Text.Json;
using SteamSentinel.App.Native;
using SteamSentinel.App.Services;
using SteamSentinel.Core.Models;
using SteamSentinel.Core.Reporting;
using SteamSentinel.Core.Rules;
using SteamSentinel.Core.Scanning;
using SteamSentinel.Core.Utilities;

namespace SteamSentinel.SelfTest;

internal static partial class Program
{
    private sealed record BaselineDispatchBatch(long Files, int Findings, int FindingTargets);

    private static async Task<(ScanReport Report, List<BaselineDispatchBatch> Batches, string Containment)> ObserveBaselineWorkerAsync(ScanOptions options)
    {
        await using WorkerWorkspace workspace = new();
        using JobObject job = new(options.MaximumWorkerMemoryBytes);
        using RestrictedProcess worker = RestrictedProcess.Start(DevelopmentWorkerPath(), workspace.Path, job);
        using CancellationTokenSource timeout = new(TimeSpan.FromSeconds(60));
        BoundedLineReader output = new(worker.StandardOutput);
        ArchiveWorkerClient.BoundedWorkerError errors = new();
        Task errorDrain = errors.DrainAsync(worker.StandardError, timeout.Token);
        ReportBatchReader reader = new(options.MaximumReportRecords);
        List<BaselineDispatchBatch> dispatches = [];
        try
        {
            string? readyLine = await output.ReadLineAsync(timeout.Token);
            WorkerMessage? ready = readyLine is null ? null : JsonSerializer.Deserialize<WorkerMessage>(readyLine, JsonFile.Options);
            if (ready?.Type != WorkerMessageTypes.Ready || ready.Containment is not ("Low" or "Untrusted"))
                throw new InvalidDataException("The dispatch probe did not receive a restricted Worker handshake.");
            string start = JsonSerializer.Serialize(new WorkerMessage { Type = WorkerMessageTypes.Start, Options = options },
                new JsonSerializerOptions(JsonFile.Options) { WriteIndented = false });
            await worker.StandardInput.WriteLineAsync(start.AsMemory(), timeout.Token);
            await worker.StandardInput.FlushAsync(timeout.Token);
            bool completed = false;
            for (int frames = 0; frames < 512; frames++)
            {
                string? line = await output.ReadLineAsync(timeout.Token);
                if (line is null) break;
                WorkerMessage? message = JsonSerializer.Deserialize<WorkerMessage>(line, JsonFile.Options);
                if (message?.Type == WorkerMessageTypes.Progress) continue;
                if (message?.Type == WorkerMessageTypes.Checkpoint && message.Batch is { } batch)
                {
                    long previousFiles = reader.Report?.Metrics.FilesVisited ?? 0;
                    int previousFindings = reader.Report?.Findings.Count ?? 0;
                    reader.Apply(batch);
                    long width = reader.Report!.Metrics.FilesVisited - previousFiles;
                    if (width > 0)
                    {
                        Finding[] added = reader.Report.Findings.Skip(previousFindings).ToArray();
                        dispatches.Add(new(width, added.Length, added.Select(finding => finding.Target).Distinct(StringComparer.OrdinalIgnoreCase).Count()));
                    }
                    continue;
                }
                if (message?.Type == WorkerMessageTypes.Completed)
                {
                    completed = message.BatchCount == reader.Count && reader.Report is not null &&
                        !reader.HasIncompleteContainers && !reader.HasIncompleteRelatedComponentDiagnostics && !reader.HasIncompleteTrustProxyDiagnostics;
                    break;
                }
                throw new InvalidDataException("Unexpected dispatch probe message: " + message?.Type + "; " + message?.Error);
            }
            await worker.WaitForExitAsync(timeout.Token);
            if (!completed || worker.ExitCode != 0)
                throw new InvalidDataException("The restricted dispatch probe did not finish a complete batch stream: " + errors.Text);
            return (reader.Report!, dispatches, ready.Containment);
        }
        finally
        {
            if (!worker.HasExited) worker.Kill();
            timeout.Cancel();
            try { await errorDrain; } catch (OperationCanceledException) { }
        }
    }

    private static bool HasAmsiObservation(ScanReport report) =>
        report.Containers?.Nodes.Any(node => node.Engines.Any(engine => engine.Engine == "AMSI")) == true ||
        report.CoverageNotices.Any(notice => notice.ReasonCode == ReasonCodes.AmsiUnavailable) ||
        report.Findings.Any(finding => finding.RuleId.StartsWith("AMSI-", StringComparison.Ordinal)) ||
        report.ResourceAudit?.Decisions.Any(decision => decision.Request.LimitKey == nameof(ScanOptions.MaximumAmsiBytes)) == true;

    private static string BaselineScanSemantics(ScanReport report) => JsonSerializer.Serialize(new
    {
        report.Coverage,
        report.Metrics,
        nodes = report.Containers!.Nodes.Select(node => new
        { node.DisplayPath, node.Sha256, node.Length, node.Overall, node.ContentCheck, node.Integrity }).OrderBy(node => node.DisplayPath),
        findings = report.Findings.Select(finding => new
        { finding.RuleId, finding.Target, finding.ContentPath, finding.Sha256, finding.TargetSha256, finding.Score, finding.Severity, finding.CanRemediate })
            .OrderBy(finding => finding.Target).ThenBy(finding => finding.RuleId),
        report.CoverageNotes
    });

    private static async Task TestV030BaselineEnhancementPolicyAsync(string directory)
    {
        Check("基础验收 系统引擎增强暂停且新扫描默认关闭", !ScanEnhancements.AmsiAvailable && !new ScanOptions().UseAmsi);
        string corpus = Path.Combine(directory, "baseline-scripts"); Directory.CreateDirectory(corpus);
        for (int index = 0; index < 16; index++)
            await File.WriteAllTextAsync(Path.Combine(corpus, $"ordinary-{index:D2}.ps1"),
                "# Harmless scanner fixture; never executed.\r\n# " + new string('q', 8192) + "\r\n");
        ScanOptions Requested(ScanPerformanceMode mode)
        {
            ScanOptions requested = new ScanLimitSettings { PerformanceMode = mode }.Apply(new()
            {
                Mode = ScanMode.Custom,
                IncludeSystem = false,
                IncludeSteam = false,
                IncludeWorkshop = false,
                UseAmsi = true,
                CustomRoots = [corpus],
                HashEveryFile = true,
                InspectDeepSignatures = false
            });
            // The full test process has already run allocation-heavy cases. Its
            // retained memory must not turn this policy test into a 1 GiB Job
            // headroom test; this is the same budget as the parallel regressions.
            typeof(ScanOptions).GetProperty(nameof(ScanOptions.MaximumWorkerMemoryBytes))!
                .SetValue(requested, 8L * 1024 * 1024 * 1024);
            return requested;
        }
        var modes = new[] { (ScanPerformanceMode.LowImpact, 1), (ScanPerformanceMode.Automatic, 2), (ScanPerformanceMode.HighThroughput, 4) };
        RuleSet rules = RuleLoader.LoadEmbedded();
        foreach (var (mode, concurrency) in modes)
        {
            ScanOptions requested = Requested(mode);
            // Deliberately below every leaf length: a paused enhancement must not
            // initialize its engine, request a grant, or disqualify parallel files.
            typeof(ScanOptions).GetProperty(nameof(ScanOptions.MaximumAmsiBytes))!.SetValue(requested, 1L);
            string before = JsonSerializer.Serialize(requested, JsonFile.Options);
            int initializations = 0;
            using ContentScanner scanner = new(rules, () =>
            {
                Interlocked.Increment(ref initializations);
                throw new InvalidOperationException("The baseline scan attempted to initialize AMSI.");
            });
            ScanReport report = new() { Mode = ScanMode.Custom };
            long checkpointFiles = 0;
            List<long> checkpointWidths = [];
            scanner.Checkpoint = state =>
            {
                long width = state.Metrics.FilesVisited - checkpointFiles;
                if (width > 0) checkpointWidths.Add(width);
                checkpointFiles = state.Metrics.FilesVisited;
            };
            using Process process = Process.GetCurrentProcess();
            long privateBefore = process.PrivateMemorySize64;
            ScanMachineResources preflight = ScanResourcePlanner.Capture(Path.GetTempPath());
            int capacityCpu = AdaptiveTestCpuCapacity(preflight.LogicalProcessors);
            int expectedConcurrency = Math.Min(concurrency, capacityCpu);
            await scanner.ScanRootAsync(corpus, report, requested, new NullPasswordProvider());
            process.Refresh();
            int peak = report.ResourceAudit?.PeakParallelFiles ?? 1;
            await JsonFile.WriteAtomicAsync(Path.Combine(directory, $"scanner-basic-{concurrency}.json"), report);
            await JsonFile.WriteAtomicAsync(Path.Combine(directory, $"scanner-basic-{concurrency}-diagnostics.json"), new
            {
                requestedConcurrency = concurrency,
                capacityCpu,
                expectedConcurrency,
                requested.MaximumWorkerMemoryBytes,
                privateBefore,
                privateAfter = process.PrivateMemorySize64,
                preflight,
                checkpointWidths,
                actualPeak = peak,
                boundary = "Parent checkpoints expose completed dispatch groups; instantaneous task overlap is scheduler-dependent."
            });
            Check($"基础验收 {concurrency}路不初始化增强引擎也不生成增强缺口", initializations == 0 && !HasAmsiObservation(report) &&
                report.Coverage == ScanCoverage.Complete && report.Metrics.FilesVisited == 16 && report.RootSummaries.All(root => root.Coverage == ScanCoverage.Complete));
            Check($"基础验收 {concurrency}路保留旧请求但报告实际关闭", before == JsonSerializer.Serialize(requested, JsonFile.Options) &&
                requested.UseAmsi && report.ContentScanSettings?.UseAmsi == false);
            // Parallel leaf scanners have no parent Checkpoint callback; the
            // parent publishes the whole completed batch. Serial fallback emits
            // one visited leaf at a time, regardless of thread-pool scheduling.
            Check($"基础验收 暂停的增强额度不限制CPU允许的{expectedConcurrency}路（请求{concurrency}路）", checkpointWidths.Count > 0 &&
                checkpointWidths.Max() == expectedConcurrency && checkpointWidths.All(width => width <= expectedConcurrency) && peak >= 1 && peak <= expectedConcurrency);
        }

        string firstFile = Path.Combine(corpus, "ordinary-00.ps1");
        ScanOptions live = new()
        {
            Mode = ScanMode.Custom,
            IncludeSystem = false,
            IncludeSteam = false,
            IncludeWorkshop = false,
            UseAmsi = true,
            CustomRoots = [firstFile],
            MaximumStringScanBytes = 1,
            HashEveryFile = true,
            InspectDeepSignatures = false
        };
        using (ScanResourceSession session = new(live,
            request => new(request.RequestId, ResourceDecisionKind.Approve, [new(request.LimitKey, request.CurrentLimit, request.RequiredMinimum)]), default))
        {
            ScanReport report = await new ScanCoordinator(rules).RunAsync(live);
            Check("基础验收 报告增强选项副本不切断实时提额", report.Coverage == ScanCoverage.Complete && live.UseAmsi &&
                report.ContentScanSettings?.UseAmsi == false && live.MaximumStringScanBytes >= new FileInfo(firstFile).Length &&
                report.ContentScanSettings.MaximumStringScanBytes == live.MaximumStringScanBytes && session.Audit.Decisions.Count > 0);
        }

        ScanReport? serial = null;
        foreach (var (mode, concurrency) in modes)
        {
            ScanOptions requested = Requested(mode);
            string before = JsonSerializer.Serialize(requested, JsonFile.Options);
            // ArchiveWorkerClient accepts Ready only from a Low/Untrusted Worker;
            // a successful result also exercises the real restricted protocol gate.
            ScanReport report = await new ArchiveWorkerClient(DevelopmentWorkerPath()).RunAsync(requested,
                (request, _) => Task.FromResult(new ArchivePasswordResponse(request.RequestId, true, null, false)), null, default);
            Check($"基础验收 真实受限Worker {concurrency}路完成且没有AMSI观察", report.ExecutionState == ScanExecutionState.Completed &&
                report.Coverage == ScanCoverage.Complete && report.Metrics.FilesVisited == 16 && report.WorkerDiagnostics is not null &&
                report.RootSummaries.All(root => root.Coverage == ScanCoverage.Complete) && !HasAmsiObservation(report));
            Check($"基础验收 真实受限Worker {concurrency}路保留调用方旧设置", before == JsonSerializer.Serialize(requested, JsonFile.Options) &&
                requested.UseAmsi && report.ContentScanSettings?.UseAmsi == false);
            int peak = report.ResourceAudit?.PeakParallelFiles ?? 1;
            int capacityCpu = AdaptiveTestCpuCapacity(report.ResourceAudit?.Preflight?.LogicalProcessors ?? Environment.ProcessorCount);
            int expectedConcurrency = Math.Min(concurrency, capacityCpu);
            Check($"基础验收 真实受限Worker请求{concurrency}路遵守CPU容量{expectedConcurrency}路",
                expectedConcurrency == 1 ? peak == 1 : peak >= 2 && peak <= expectedConcurrency);
            if (serial is not null) Check($"基础验收 真实受限Worker {concurrency}路与串行结果一致", BaselineScanSemantics(serial) == BaselineScanSemantics(report));
            else serial = report;
            await JsonFile.WriteAtomicAsync(Path.Combine(directory, $"worker-basic-{concurrency}.json"), report);
        }
        // Each inert leaf produces a finding so the real Worker cannot coalesce
        // all checkpoints under its one-second unchanged-findings throttle.
        // No fixture is executed and the domain is only scanned as text.
        string dispatchCorpus = Path.Combine(directory, "baseline-dispatch");
        Directory.CreateDirectory(dispatchCorpus);
        for (int index = 0; index < 16; index++)
            await File.WriteAllTextAsync(Path.Combine(dispatchCorpus, $"dispatch-{index:D2}.ps1"),
                "# Inert scanner dispatch fixture; never executed.\r\n# " + rules.KnownDomains[0] + "\r\n");
        ScanReport? dispatchSerial = null;
        foreach (var (mode, concurrency) in modes)
        {
            ScanOptions requested = Requested(mode);
            typeof(ScanOptions).GetProperty(nameof(ScanOptions.CustomRoots))!.SetValue(requested, new List<string> { dispatchCorpus });
            typeof(ScanOptions).GetProperty(nameof(ScanOptions.MaximumAmsiBytes))!.SetValue(requested, 1L);
            var observed = await ObserveBaselineWorkerAsync(requested);
            ScanReport report = observed.Report;
            int peak = report.ResourceAudit?.PeakParallelFiles ?? 1;
            int capacityCpu = AdaptiveTestCpuCapacity(report.ResourceAudit?.Preflight?.LogicalProcessors ?? Environment.ProcessorCount);
            int expectedConcurrency = Math.Min(concurrency, capacityCpu);
            await JsonFile.WriteAtomicAsync(Path.Combine(directory, $"worker-dispatch-{concurrency}.json"), report);
            await JsonFile.WriteAtomicAsync(Path.Combine(directory, $"worker-dispatch-{concurrency}-diagnostics.json"), new
            {
                requestedConcurrency = concurrency,
                capacityCpu,
                expectedConcurrency,
                observed.Containment,
                observed.Batches,
                actualPeak = peak,
                requested.MaximumWorkerMemoryBytes,
                requested.MaximumAmsiBytes,
                preflight = ScanResourcePlanner.Capture(Path.GetTempPath()),
                report.WorkerDiagnostics
            });
            Check($"基础验收 真实受限Worker按CPU容量精确派发{expectedConcurrency}路且未因增强额度回退（请求{concurrency}路）", observed.Batches.Count > 0 &&
                observed.Batches.Max(batch => batch.Files) == expectedConcurrency && observed.Batches.Sum(batch => batch.Files) == 16 &&
                observed.Batches.All(batch => batch.Files <= expectedConcurrency && batch.Findings >= batch.Files && batch.FindingTargets == batch.Files) &&
                (expectedConcurrency == 1 ? peak == 1 : peak >= 2 && peak <= expectedConcurrency) &&
                report.ExecutionState == ScanExecutionState.Completed && report.Coverage == ScanCoverage.Complete &&
                report.Metrics.FilesVisited == 16 && !HasAmsiObservation(report) && report.ContentScanSettings?.UseAmsi == false);
            if (dispatchSerial is not null)
                Check($"基础验收 真实受限Worker派发{concurrency}路与串行语义一致", BaselineScanSemantics(dispatchSerial) == BaselineScanSemantics(report));
            else dispatchSerial = report;
        }
        foreach (var culture in new[] { DisplayText.Chinese, DisplayText.English })
            Check("基础验收 未调用增强项不产生双语覆盖缺口 " + culture.Name,
                StatusPresentation.ScanMessage(serial!).MessageId == "Scan.Completed" &&
                StatusPresentation.Scan(serial!, culture) == StatusPresentation.Text("Scan.Completed", culture) && CoveragePresentation.Groups(serial!, culture).Count == 0);

        using (FileStream locked = new(firstFile, FileMode.Open, FileAccess.Read, FileShare.None))
        {
            ScanReport failed = await new ScanCoordinator(rules).RunAsync(new()
            { Mode = ScanMode.Custom, IncludeSystem = false, IncludeSteam = false, IncludeWorkshop = false, UseAmsi = true, CustomRoots = [firstFile] });
            Check("基础验收 实际文件读取失败仍保留不完整", failed.Coverage == ScanCoverage.Partial &&
                failed.RootSummaries.Any(root => root.Coverage == ScanCoverage.Partial) && CoveragePresentation.Groups(failed).Count > 0);
            Check("基础验收 读取失败不归因于暂停的增强项", !HasAmsiObservation(failed) && failed.ContentScanSettings?.UseAmsi == false);
        }
        ScanReport historical = new()
        {
            ExecutionState = ScanExecutionState.Completed,
            CompletedAtUtc = DateTimeOffset.UtcNow,
            Coverage = ScanCoverage.Partial,
            ContentScanSettings = Requested(ScanPerformanceMode.LowImpact),
            CoverageNotices = [new(ReasonCodes.AmsiUnavailable, "Previously recorded engine failure.")]
        };
        string historicalJson = JsonSerializer.Serialize(historical, JsonFile.Options);
        _ = ScanEnhancements.ForExecution(historical.ContentScanSettings!);
        ScanReport restored = JsonSerializer.Deserialize<ScanReport>(historicalJson, JsonFile.Options)!;
        Check("基础验收 历史增强失败及原始请求仍可往返", historicalJson == JsonSerializer.Serialize(historical, JsonFile.Options) &&
            restored.ContentScanSettings?.UseAmsi == true && restored.Coverage == ScanCoverage.Partial &&
            StatusPresentation.ScanMessage(restored).MessageId == "Scan.CompletedWithGaps" && CoveragePresentation.Groups(restored).Count == 1);
    }
}
