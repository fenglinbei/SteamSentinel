using System.IO;
using System.IO.Compression;
using System.Text.Json;
using SteamSentinel.App;
using SteamSentinel.App.Services;
using SteamSentinel.Core.Models;
using SteamSentinel.Core.Reporting;
using SteamSentinel.Core.Scanning;
using SteamSentinel.Core.Utilities;

namespace SteamSentinel.SelfTest;

internal static partial class Program
{
    private static async Task TestV0114CoverageAsync(string root)
    {
        string directory = Path.Combine(root, "v0114-coverage"); Directory.CreateDirectory(directory);
        ScanReport aggregate = new() { Mode = ScanMode.Full, ContentScanSettings = new() { Mode = ScanMode.Full } };
        ScanResourceGuard guard = new();
        ReportBatchReader reader = new();
        int largest = 0, updates = 0;
        ReportBatchWriter writer = new(batch =>
        {
            string wire = JsonSerializer.Serialize(batch, new JsonSerializerOptions(JsonFile.Options) { WriteIndented = false });
            largest = Math.Max(largest, wire.Length);
            updates += batch.CoverageUpdates.Count;
            reader.Apply(JsonSerializer.Deserialize<ReportBatch>(wire, JsonFile.Options)!);
        });
        const int occurrences = 100_000;
        for (int i = 0; i < occurrences; i++)
        {
            CoverageAggregation.Add(aggregate, "CONTENT-BYTE-BUDGET", directory,
                directory + "\\" + new string('x', 1500) + i + "?token=secret");
            guard.Check(aggregate);
            if (i == 0 || i % 10000 == 0) writer.Send(aggregate);
        }
        aggregate.CompletedAtUtc = DateTimeOffset.UtcNow;
        writer.Send(aggregate, final: true);
        Check("十万重复覆盖缺口不形成逐文件发现或说明", aggregate.Findings.Count == 0 && aggregate.CoverageNotes.Count == 0 &&
            aggregate.CoverageAggregates.Single().Count == occurrences && aggregate.Coverage == ScanCoverage.Partial);
        Check("聚合示例数量和长度有界且补查保留精确根路径", aggregate.CoverageAggregates.Single() is var bounded &&
            bounded.Examples.Count <= CoverageAggregate.MaximumExamples && bounded.Examples.All(p => p.Length <= CoverageAggregate.MaximumExampleCharacters) && bounded.Root == directory);
        Check("只变计数的覆盖更新完整跨协议保留且单帧小于 1 MiB", reader.Report!.CoverageAggregates.Single().Count == occurrences &&
            reader.Report.CompletedAtUtc == aggregate.CompletedAtUtc && updates > 1 && largest < 1024 * 1024);
        CoverageGroup group = CoveragePresentation.Groups(reader.Report!).Single();
        Check("聚合展示准确累计次数，补查整个根而非有限示例", group.Count == occurrences && group.Entries.Count == 1 &&
            group.Details.Contains("示例不是完整清单") && MainWindow.CoverageTargets(group).SequenceEqual([directory]));
        Check("聚合缺口不升级威胁严重度或风险数", aggregate.RiskFindingCount == 0 && aggregate.HighestSeverity == FindingSeverity.Information);
        CoverageEntry safetyStop = CoveragePresentation.Describe("CONTENT-SCAN-FAILED", directory, "ScanResourceLimitException");
        CoverageEntry allocationFailure = CoveragePresentation.Describe("CONTENT-SCAN-FAILED", directory, "OutOfMemoryException");
        Check("安全上限与真实内存分配失败分开展示", safetyStop.Kind != allocationFailure.Kind &&
            safetyStop.NextStep.Contains("不等于系统内存不足") && allocationFailure.Kind.Contains("内存分配失败") &&
            !safetyStop.CanFullScan && !allocationFailure.CanFullScan);
        Check("覆盖短句使用逗号而非不必要分号", !group.Details.Contains('；'));

        long before = reader.Report!.CoverageAggregates[0].Count;
        bool rejected = false;
        ScanReport malformed = new() { ScanId = aggregate.ScanId, Findings = [new() { Title = "must not be added" }] };
        try
        {
            reader.Apply(new(reader.Count, new(0, 0, 0, 0, 0, 0, 0), malformed)
            { CoverageUpdates = [new(0, aggregate.CoverageAggregates[0] with { Count = before - 1 })] });
        }
        catch (InvalidDataException) { rejected = true; }
        Check("递减覆盖计数被拒绝且不会部分提交发现", rejected && reader.Report.Findings.Count == 0 && reader.Report.CoverageAggregates[0].Count == before);
        rejected = false;
        try
        {
            reader.Apply(new(reader.Count, new(0, 0, 0, 0, 0, 0, 0), new() { ScanId = aggregate.ScanId })
            { CoverageUpdates = [new(2, aggregate.CoverageAggregates[0])] });
        }
        catch (InvalidDataException) { rejected = true; }
        Check("不连续覆盖索引不能伪装完整结果", rejected);

        ScanReport second = new();
        CoverageAggregation.Add(second, "CONTENT-BYTE-BUDGET", directory, Path.Combine(directory, "second.dat?token=secret"));
        ScanReport merged = ScanReportMerger.Merge(reader.Report, second);
        Check("合并保留独立扫描的覆盖次数与根路径", CoveragePresentation.Groups(merged).Single().Count == occurrences + 1 &&
            CoverageAggregation.OccurrenceCount(aggregate) == occurrences);
        merged.ContentScanSettings = aggregate.ContentScanSettings;
        string json = Path.Combine(directory, "aggregate.json"), markdown = Path.Combine(directory, "aggregate.md");
        await ReportExporter.ExportJsonAsync(merged, json); await ReportExporter.ExportMarkdownAsync(merged, markdown);
        string jsonText = await File.ReadAllTextAsync(json), md = await File.ReadAllTextAsync(markdown);
        ScanReport decoded = JsonSerializer.Deserialize<ScanReport>(jsonText, JsonFile.Options)!;
        Check("JSON 导出保留聚合次数且继续脱敏", CoverageAggregation.OccurrenceCount(decoded) == occurrences + 1 &&
            !jsonText.Contains("token=secret") && jsonText.Length < 32 * 1024);
        Check("Markdown 明示完整模式无整轮上限及非完整示例", md.Contains("不设整轮哈希字节上限") &&
            md.Contains("100001 次覆盖记录") && md.Contains("示例不是完整清单") && !md.Contains("token=secret"));
        merged.ContentScanSettings = new() { Mode = ScanMode.Quick, MaximumContentBytes = 1L << 30 };
        await ReportExporter.ExportMarkdownAsync(merged, markdown);
        md = await File.ReadAllTextAsync(markdown);
        Check("快速报告同时说明主预算和小启动文件保留预算", md.Contains("128 MiB") && md.Contains("不超过 8 MiB") && !md.Contains("不设整轮哈希字节上限"));

        // Exercise >14k real inert paths, not just synthetic report entries. No content is executed.
        string manyRoot = Path.Combine(directory, "many", new string('a', 90)); Directory.CreateDirectory(manyRoot);
        const int files = 14_050;
        for (int i = 0; i < files; i++) File.WriteAllText(Path.Combine(manyRoot, $"item-{i:D5}.dat"), "x");
        ScanOptions zero = new() { Mode = ScanMode.Full, IncludeSystem = false, IncludeSteam = false,
            IncludeWorkshop = false, UseAmsi = false, MaximumContentBytes = 0, CustomRoots = [manyRoot] };
        ScanReport many = await new ScanCoordinator(new RuleSet()).RunAsync(zero);
        Check("超过一万四千实际路径完成格式遍历而不触发重复文本上限", many.Metrics.FilesVisited == files &&
            many.CoverageAggregates.Single().Count == files && many.Findings.Count == 0 && many.Metrics.BytesHashed == 0);
        Check("聚合缺口使根摘要保持 Partial", many.RootSummaries.Single().Coverage == ScanCoverage.Partial &&
            many.RootSummaries.Single().FilesVisited == files);

        string solution = Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "..", "..", "..", ".."));
        // The release smoke helper selects an installed/signed worker without changing older evidence tests.
        string worker = Environment.GetEnvironmentVariable("STEAMSENTINEL_COVERAGE_WORKER_PATH") is { Length: > 0 } configuredWorker
            ? Path.GetFullPath(configuredWorker)
            : Directory.EnumerateFiles(Path.Combine(solution, "SteamSentinel.ArchiveWorker", "bin"),
                "SteamSentinel.ArchiveWorker.exe", SearchOption.AllDirectories).OrderByDescending(File.GetLastWriteTimeUtc).First();
        static Task<ArchivePasswordResponse> NoPassword(ArchivePasswordRequest request, CancellationToken _) =>
            Task.FromResult(new ArchivePasswordResponse(request.RequestId, true, null, false));
        using (CancellationTokenSource timeout = new(TimeSpan.FromMinutes(3)))
        {
            ScanReport lowMany = await new ArchiveWorkerClient(worker).RunAsync(zero, NoPassword, null, timeout.Token);
            Check("真实 Low Worker 一万四千长路径覆盖计数经检查点完整交回", lowMany.Metrics.FilesVisited == files &&
                lowMany.CoverageAggregates.Single().Count == files && lowMany.Findings.Count == 0 && lowMany.Coverage == ScanCoverage.Partial &&
                lowMany.RootSummaries.Single().Coverage == ScanCoverage.Partial && lowMany.RootSummaries.Single().FilesVisited == files);
            Check("真实 Low Worker 聚合压力测试保留诊断且峰值小于 1 GiB", lowMany.WorkerDiagnostics is
                { PrivateBytes: > 0, PeakPrivateBytes: > 0 and < 1024L * 1024 * 1024 });
            Console.WriteLine($"V0114_COVERAGE_LOW_FILES={lowMany.Metrics.FilesVisited};OCCURRENCES={CoverageAggregation.OccurrenceCount(lowMany)};" +
                $"GROUPS={lowMany.CoverageAggregates.Count};PEAK_MIB={lowMany.WorkerDiagnostics!.PeakPrivateBytes / 1024 / 1024}");
        }

        string file = Path.Combine(directory, "inert.dat"); await File.WriteAllTextAsync(file, "harmless hash fixture");
        ScanReport roots = new();
        using ContentScanner scanner = new(new RuleSet());
        await scanner.ScanRootAsync(file, roots, zero, new NullPasswordProvider());
        await scanner.ScanRootAsync(file, roots, zero, new NullPasswordProvider());
        Check("已有分组只增加计数时第二次根摘要仍 Partial", roots.CoverageAggregates.Single().Count == 2 &&
            roots.RootSummaries.Count == 2 && roots.RootSummaries.All(r => r.Coverage == ScanCoverage.Partial));
        ScanOptions full = new() { Mode = ScanMode.Full, UseAmsi = false, HashEveryFile = true };
        await scanner.ScanRootAsync(file, roots, full, new NullPasswordProvider());
        Check("其他根的既有聚合不把本次完整根误标 Partial", roots.RootSummaries.Last().Coverage == ScanCoverage.Complete);

        long oldLimit = 8L * 1024 * 1024 * 1024;
        ScanReport pastOldLimit = new() { Metrics = new() { BytesHashed = oldLimit + 1 } };
        await scanner.ScanRootAsync(file, pastOldLimit, full, new NullPasswordProvider());
        Check("Full 已累计超过旧 8 GiB 后仍分块哈希下一文件", full.MaximumContentBytes == long.MaxValue &&
            pastOldLimit.Metrics.BytesHashed == oldLimit + 1 + new FileInfo(file).Length && pastOldLimit.Coverage == ScanCoverage.Complete);
        ScanReport finite = new();
        await scanner.ScanRootAsync(file, finite, new() { Mode = ScanMode.Full, UseAmsi = false, MaximumContentBytes = 1 }, new NullPasswordProvider());
        Check("显式有限 Full 预算仍然生效", finite.Metrics.BytesHashed == 0 && finite.CoverageAggregates.Single().Count == 1);

        string archive = Path.Combine(directory, "inert.zip");
        using (ZipArchive zip = ZipFile.Open(archive, ZipArchiveMode.Create))
            for (int i = 0; i < 2; i++)
            {
                using Stream entry = zip.CreateEntry($"inert-{i}.dat", CompressionLevel.NoCompression).Open();
                entry.Write(new byte[768]);
            }
        ScanReport expanded = new();
        await scanner.ScanRootAsync(archive, expanded, new() { Mode = ScanMode.Full, UseAmsi = false,
            MaximumExpandedBytes = 1024 }, new NullPasswordProvider());
        Check("Full 无全局哈希上限不取消压缩展开上限", expanded.Metrics.ArchiveBytesExpanded == 768 &&
            expanded.Coverage == ScanCoverage.Partial && expanded.CoverageNotes.Any(n => n.Contains("累计解压数据达到上限")));

        ScanReport capped = new();
        for (int i = 0; i < CoverageAggregate.MaximumGroups; i++)
            CoverageAggregation.Add(capped, "CONTENT-BYTE-BUDGET", Path.Combine(directory, "root-" + i), "example");
        rejected = false;
        try { CoverageAggregation.Add(capped, "CONTENT-BYTE-BUDGET", Path.Combine(directory, "overflow"), "example"); }
        catch (ScanResourceLimitException) { rejected = true; }
        CoverageAggregation.Add(capped, "CONTENT-BYTE-BUDGET", Path.Combine(directory, "root-0"), "another");
        Check("不同根原因分组上限明确停止且既有组仍可准确累加", rejected &&
            capped.CoverageAggregates.Count == CoverageAggregate.MaximumGroups && CoverageAggregation.OccurrenceCount(capped) == CoverageAggregate.MaximumGroups + 1);
    }
}
