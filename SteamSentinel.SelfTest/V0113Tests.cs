using System.IO;
using System.Text;
using System.Text.Json;
using SteamSentinel.App.Services;
using SteamSentinel.Core.Models;
using SteamSentinel.Core.Reporting;
using SteamSentinel.Core.Scanning;
using SteamSentinel.Core.Utilities;

namespace SteamSentinel.SelfTest;

internal static partial class Program
{
    private static async Task TestV0113Async(string root)
    {
        string directory = Path.Combine(root, "v0113"); Directory.CreateDirectory(directory);
        string fixture = Path.Combine(directory, "large.dat");
        await using (FileStream file = new(fixture, FileMode.CreateNew))
        {
            file.SetLength(32L * 1024 * 1024);
            file.Position = 256 * 1024 - 10; await file.WriteAsync(Encoding.UTF8.GetBytes("steam://open/supportalert"));
            file.Position = 12 * 1024 * 1024; await file.WriteAsync(Encoding.UTF8.GetBytes("SupportMessages HelpFrontPage steamhelper"));
            file.Position = 30 * 1024 * 1024; await file.WriteAsync(Encoding.Unicode.GetBytes("bSupportPopupMessage"));
        }
        ScanOptions options = new() { Mode = ScanMode.Full, IncludeSteam = false, IncludeSystem = false,
            IncludeWorkshop = false, UseAmsi = false, InspectArchives = true, HashEveryFile = true, CustomRoots = [fixture] };
        ScanReport strings = await new ScanCoordinator(new RuleSet()).RunAsync(options);
        Check("32 MiB 分块分析保留跨块与双编码组合命中", strings.Findings.Any(f => f.RuleId == "HEUR-STEAM-UI-PATCHER" && f.CanRemediate));
        Check("分块分析保留完整外层哈希绑定", strings.Findings.All(f => f.TargetSha256?.Length == 64));

        string script = Path.Combine(directory, "split.ps1");
        await using (FileStream file = new(script, FileMode.CreateNew))
        {
            file.SetLength(4 * 1024 * 1024);
            await file.WriteAsync(Encoding.UTF8.GetBytes("Invoke-WebRequest https://example.invalid"));
            file.Position = 2 * 1024 * 1024; await file.WriteAsync(Encoding.Unicode.GetBytes("Start-Process steamprocess Add-MpPreference"));
        }
        ScanReport scriptReport = await new ScanCoordinator(new RuleSet()).RunAsync(new ScanOptions { Mode = ScanMode.Custom,
            IncludeSteam = false, IncludeSystem = false, IncludeWorkshop = false, UseAmsi = false, CustomRoots = [script] });
        Check("脚本链信号跨窗口累积，不仅检查文件开头", scriptReport.Findings.Any(f => f.RuleId == "HEUR-STEAM-DEPLOYMENT-CHAIN"));

        ScanReport many = new() { ContentScanSettings = options };
        for (int i = 0; i < 9000; i++)
        {
            many.Findings.Add(new() { Category = FindingCategory.Coverage, RuleId = "CONTENT-BYTE-BUDGET", Target = "item-" + i, Description = "未读取全部内容" });
            many.CoverageNotes.Add("覆盖记录 " + i);
        }
        many.Metrics.FilesVisited = 9000;
        ReportBatchReader reader = new();
        int largest = 0;
        ReportBatchWriter writer = new(batch =>
        {
            string wire = JsonSerializer.Serialize(batch, new JsonSerializerOptions(JsonFile.Options) { WriteIndented = false });
            largest = Math.Max(largest, wire.Length);
            reader.Apply(JsonSerializer.Deserialize<ReportBatch>(wire, JsonFile.Options)!);
        });
        writer.Send(many);
        many.CoverageNotes[0] = "AMSI 最新状态"; many.CompletedAtUtc = DateTimeOffset.UtcNow;
        writer.Send(many, final: true);
        Check("九千条结果分批往返，单帧小于 1 MiB", largest < 1024 * 1024 && writer.Count > 100);
        Check("重放可变覆盖说明不重复风险与计数", reader.Report!.Findings.Count == 9000 && reader.Report.Metrics.FilesVisited == 9000 && reader.Report.CoverageNotes.Count == 9000 && reader.Report.CoverageNotes[0] == "AMSI 最新状态");
        bool rejected = false;
        try { reader.Apply(new(reader.Count + 1, new(0, 0, 0, 0, 0, 0, 0), new())); } catch (InvalidDataException) { rejected = true; }
        Check("缺失结果批次不能伪装完整", rejected);
        BoundedLineReader lines = new(new StringReader("one\r\ntwo\n"));
        Check("分帧读取保留相邻行", await lines.ReadLineAsync() == "one" && await lines.ReadLineAsync() == "two" && await lines.ReadLineAsync() is null);
        rejected = false;
        try { await new BoundedLineReader(new StringReader(new string('x', 4097)), 4096).ReadLineAsync(); }
        catch (InvalidDataException) { rejected = true; }
        Check("无换行的超长协议帧受限读取", rejected);
        ScanReport excess = new();
        for (int i = 0; i <= ScanResourceGuard.MaximumRecords; i++) excess.Findings.Add(new());
        rejected = false;
        try { new ScanResourceGuard().Check(excess); } catch (ScanResourceLimitException) { rejected = true; }
        Check("结果积累上限可控停止，不静默丢弃", rejected);

        ScanReport partial = new() { ContentScanSettings = options,
            WorkerDiagnostics = new("压缩包目录", "inert.zip!/inner.rar?token=secret", "读取目录", 500, 600, 400, DateTimeOffset.UtcNow, "OutOfMemoryException", "inert stack") };
        partial.Findings.Add(strings.Findings.First()); partial.Metrics.FilesVisited = 3;
        ScanReport preserved = ScanFailureReports.PreserveSystemResults(new() { Metrics = new() { ProcessesVisited = 7 } },
            ScanMode.Full, [], "fixture", new WorkerFailureException(WorkerStage.Scanning, 1, "inert OOM") { PartialReport = partial }, false);
        Check("中断报告保留内容发现、系统计数与未完整状态", preserved.Metrics.FilesVisited == 3 && preserved.Metrics.ProcessesVisited == 7 && preserved.Coverage == ScanCoverage.Partial && preserved.Findings.Any(f => f.CanRemediate));
        string json = Path.Combine(directory, "failure.json"), markdown = Path.Combine(directory, "failure.md");
        await ReportExporter.ExportJsonAsync(preserved, json); await ReportExporter.ExportMarkdownAsync(preserved, markdown);
        string exported = await File.ReadAllTextAsync(json), md = await File.ReadAllTextAsync(markdown);
        Check("流式 JSON 导出保留设置与诊断且继续脱敏", exported.Contains("ContentScanSettings") && exported.Contains("WorkerDiagnostics") && !exported.Contains("token=secret"));
        Check("Markdown 显示最后路径、内部阶段和内存", md.Contains("压缩包目录") && md.Contains("inert.zip") && md.Contains("组件私有内存") && !md.Contains("token=secret"));

        string solution = Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "..", "..", "..", ".."));
        string worker = Directory.EnumerateFiles(Path.Combine(solution, "SteamSentinel.ArchiveWorker", "bin"),
            "SteamSentinel.ArchiveWorker.exe", SearchOption.AllDirectories).OrderByDescending(File.GetLastWriteTimeUtc).First();
        static Task<ArchivePasswordResponse> NoPassword(ArchivePasswordRequest r, CancellationToken _) =>
            Task.FromResult(new ArchivePasswordResponse(r.RequestId, true, null, false));
        using CancellationTokenSource timeout = new(TimeSpan.FromMinutes(3));
        string second = Path.Combine(directory, "large-second.dat"); File.Copy(fixture, second);
        ScanReport lowLarge = await new ArchiveWorkerClient(worker).RunAsync(new ScanOptions { Mode = ScanMode.Full,
            IncludeSystem = false, IncludeSteam = false, IncludeWorkshop = false, UseAmsi = false,
            HashEveryFile = true, CustomRoots = [fixture, second, script] }, NoPassword, null, timeout.Token);
        Check("真实 Low Worker 连续分析两个 32 MiB 文件与分散脚本信号", lowLarge.Findings.Count(f => f.CanRemediate) == 3 && lowLarge.Metrics.FilesVisited == 3);
        Check("真实扫描保留内存诊断且仍在 1 GiB Job 内", lowLarge.WorkerDiagnostics is { PrivateBytes: > 0, PeakPrivateBytes: < 1024L * 1024 * 1024 });
        Console.WriteLine($"V0113_LARGE_PEAK_MIB={lowLarge.WorkerDiagnostics!.PeakPrivateBytes / 1024 / 1024}");
        string manyFiles = Path.Combine(directory, "many"); Directory.CreateDirectory(manyFiles);
        for (int i = 0; i < 6000; i++) await File.WriteAllTextAsync(Path.Combine(manyFiles, $"item-{i:D5}.dat"), "x");
        ScanReport lowMany = await new ArchiveWorkerClient(worker).RunAsync(new ScanOptions { Mode = ScanMode.Full,
            IncludeSystem = false, IncludeSteam = false, IncludeWorkshop = false, UseAmsi = false,
            MaximumContentBytes = 0, CustomRoots = [manyFiles] }, NoPassword, null, timeout.Token);
        Check("真实 Low Worker 六千次覆盖缺口聚合完整交回", lowMany.Metrics.FilesVisited == 6000 &&
            lowMany.Findings.Count == 0 && lowMany.CoverageAggregates.Single().Count == 6000 && lowMany.Coverage == ScanCoverage.Partial &&
            lowMany.RootSummaries.Single().Coverage == ScanCoverage.Partial);
        Console.WriteLine($"V0113_MANY_PEAK_MIB={lowMany.WorkerDiagnostics!.PeakPrivateBytes / 1024 / 1024}");
        WorkerFailureException? limited = null;
        try { await new ArchiveWorkerClient(worker).RunAsync(new ScanOptions { Mode = ScanMode.Full, IncludeSystem = false,
            IncludeSteam = false, IncludeWorkshop = false, UseAmsi = false, MaximumContentBytes = 0, MaximumFiles = 2,
            CustomRoots = Directory.EnumerateFiles(manyFiles).Take(3).ToList() }, NoPassword, null, timeout.Token); }
        catch (WorkerFailureException ex) { limited = ex; }
        Check("真实跨根目录总文件上限保留前两项并说明未完成", limited?.PartialReport?.Metrics.FilesVisited == 2 &&
            limited.PartialReport.CoverageAggregates.Sum(a => a.Count) == 2 &&
            limited.PartialReport.WorkerDiagnostics?.FailureType == nameof(ScanResourceLimitException));
    }
}
