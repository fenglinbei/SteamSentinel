using System.IO;
using System.IO.Compression;
using System.Text.Json;
using SteamSentinel.App.Services;
using SteamSentinel.Core.Models;
using SteamSentinel.Core.Rules;
using SteamSentinel.Core.Scanning;
using SteamSentinel.Core.Reporting;

namespace SteamSentinel.SelfTest;

internal static partial class Program
{
    private static async Task TestScanLimitSettingsAsync(string root, string? workerOverride = null)
    {
        string directory = Path.Combine(root, "user-scan-limits-" + Guid.NewGuid().ToString("N")); Directory.CreateDirectory(directory);
        ScanLimitSettings settings = new();
        foreach (ScanMode mode in new[] { ScanMode.Quick, ScanMode.Full })
        {
            for (int preset = 0; preset < 5; preset++)
            {
                settings.UsePreset(mode, preset);
                ScanOptions effective = settings.Apply(new() { Mode = mode });
                ContainerRequestValidation.Validate(effective);
                Check($"扫描设置 {mode} 五挡预设 {ScanLimitSettings.Presets[preset]} 可用且可识别", settings.DetectPreset(mode) == preset);
            }
        }
        settings.UsePreset(ScanMode.Quick, 2); settings.UsePreset(ScanMode.Full, 2);
        Check("扫描设置 中档等于原默认", settings.Quick.Count == 0 && settings.Full.Count == 0);
        ScanOptions quick = settings.Apply(new() { Mode = ScanMode.Quick });
        ScanOptions full = settings.Apply(new() { Mode = ScanMode.Custom });
        Check("扫描设置 默认快速和完整预算保持兼容", quick.MaximumEntryBytes == 256L * 1048576 && quick.MaximumContentBytes == 1024L * 1048576 &&
            quick.ContainerLimits!.MaximumDepth == 4 && full.MaximumEntryBytes == 8192L * 1048576 && full.MaximumContentBytes == long.MaxValue && full.RangeLimits!.MaximumDuration.TotalSeconds == 15);
        settings.Full["ContainerLimits.MaximumDepth"] = 64;
        settings.Full["ContainerLimits.MaximumEntryBytes"] = 131072;
        settings.Full["ContainerLimits.MaximumCompressionRatio"] = 5000;
        settings.Full["ContainerLimits.MaximumDurationSeconds"] = 10000;
        settings.Full["ContainerLimits.ReservedDiskBytes"] = 0;
        settings.Full["MaximumQuickPriorityBytes"] = 0;
        full = settings.Apply(new() { Mode = ScanMode.Custom, CustomRoots = [directory], UseAmsi = false });
        ContainerRequestValidation.Validate(full);
        Check("扫描设置 超过旧深度大小比率时限允许且零预留保持零", full.MaximumArchiveDepth == 64 && full.MaximumEntryBytes == 131072L * 1048576 &&
            full.ContainerLimits!.MaximumCompressionRatio == 5000 && full.ContainerLimits.MaximumDurationSeconds == 10000 && full.ContainerLimits.ReservedDiskBytes == 0 && full.MaximumQuickPriorityBytes == 0);
        Check("扫描设置 只覆盖预算不改变范围和开关", full.CustomRoots.SequenceEqual([directory]) && !full.UseAmsi && settings.Apply(new() { Mode = ScanMode.Quick }).MaximumArchiveDepth == 4);
        string path = Path.Combine(directory, "settings.json");
        ScanSettingsStore.Save(path, settings);
        Check("扫描设置 保存并重新读取保留两模式", JsonSerializer.Serialize(ScanSettingsStore.Load(path)) == JsonSerializer.Serialize(settings));
        File.WriteAllText(path, "{broken");
        Check("扫描设置 损坏配置不静默当有效设置", V020Throws<JsonException>(() => ScanSettingsStore.Load(path)));
        settings.Full["ContainerLimits.MaximumDepth"] = 1.5m;
        Check("扫描设置 拒绝非整数深度", V020Throws<InvalidDataException>(settings.Validate));
        settings.Full["ContainerLimits.MaximumDepth"] = -1;
        Check("扫描设置 拒绝负数", V020Throws<InvalidDataException>(settings.Validate));
        settings.Full.Clear();
        settings.Full["MaximumAmsiBytes"] = 4096;
        Check("扫描设置 AMSI 拒绝超数组长度输入", V020Throws<InvalidDataException>(settings.Validate));
        settings.Full.Clear();
        full = settings.Apply(new() { Mode = ScanMode.Custom });
        full = ArchiveWorkerClient.CopyOptions(full);
        Check("扫描设置 隔离组件复制保留新增预算", full.RangeLimits is not null && full.MaximumStringScanBytes == 32L * 1048576 && full.MaximumReportRecords == 20000);
        string archive = Path.Combine(directory, "limits.zip");
        using (ZipArchive zip = ZipFile.Open(archive, ZipArchiveMode.Create))
        using (Stream output = zip.CreateEntry("inert.txt", CompressionLevel.NoCompression).Open())
            output.Write(new byte[4096]);
        async Task<ScanReport> Scan(string input, ScanLimitSettings profile, ScanMode mode = ScanMode.Custom)
        {
            ScanOptions options = profile.Apply(new()
            {
                Mode = mode,
                CustomRoots = [input],
                UseAmsi = false,
                IncludeSystem = false,
                IncludeSteam = false,
                IncludeWorkshop = false,
                InspectDeepSignatures = false,
                HashEveryFile = true
            });
            ScanReport report = new() { Mode = mode, ContentScanSettings = options };
            using ContentScanner scanner = new(RuleLoader.LoadEmbedded());
            try { await scanner.ScanRootAsync(input, report, options, new NullPasswordProvider()); }
            catch (ScanResourceLimitException) { report.Coverage = ScanCoverage.Partial; }
            report.CompletedAtUtc = DateTimeOffset.UtcNow;
            return report;
        }
        settings.Full["ContainerLimits.MaximumEntryBytes"] = 1m / 1024;
        ScanReport low = await Scan(archive, settings);
        settings.Full["ContainerLimits.MaximumEntryBytes"] = 1;
        ScanReport high = await Scan(archive, settings);
        Check("扫描设置 实际解压低大小受限调高后完整读取", low.Coverage != ScanCoverage.Complete && high.Containers!.Nodes.Any(n => n.DisplayPath.EndsWith("inert.txt") && n.Sha256 is not null));
        settings.Full["ContainerLimits.MaximumWorkBytes"] = 1m / 1024;
        ScanReport workLow = await Scan(archive, settings);
        settings.Full["ContainerLimits.MaximumWorkBytes"] = 16;
        ScanReport workHigh = await Scan(archive, settings);
        Check("扫描设置 实际读取预算调高解除限制", workLow.Coverage != ScanCoverage.Complete && workHigh.Containers!.Nodes.Any(n => n.Sha256 is not null && n.DisplayPath.EndsWith("inert.txt")));
        string large = Path.Combine(directory, "inert-large.txt");
        using (FileStream file = File.Create(large)) file.SetLength(33L * 1048576);
        settings.Full.Clear();
        ScanReport stringsLow = await Scan(large, settings);
        settings.Full["MaximumStringScanBytes"] = 40;
        ScanReport stringsHigh = await Scan(large, settings);
        Check("扫描设置 超32MiB正文调高后字符串引擎实际完成", stringsLow.Findings.Any(f => f.RuleId == "STRING-ENGINE-SIZE-LIMIT") &&
            stringsHigh.Containers!.Nodes.SelectMany(n => n.Engines).Any(e => e.Engine == "字符串与行为特征" && e.Status == ContainerStageStatus.Complete && e.Length == 33L * 1048576));
        settings.Quick["MaximumQuickFileBytes"] = 1;
        ScanReport quickLow = await Scan(large, settings, ScanMode.Quick);
        settings.Quick["MaximumQuickFileBytes"] = 40;
        ScanReport quickHigh = await Scan(large, settings, ScanMode.Quick);
        Check("扫描设置 快速单文件预算真实控制哈希", quickLow.Metrics.BytesHashed == 0 && quickHigh.Metrics.BytesHashed >= 33L * 1048576);
        string markdown = Path.Combine(directory, "budget-report.md");
        await ReportExporter.ExportMarkdownAsync(stringsHigh, markdown);
        Check("扫描设置 导出报告包含实际正文预算", File.ReadAllText(markdown).Contains("单文件字符串与行为检查：40 MiB"));
        Check("扫描设置 长时间预算传至启动器", ArchiveWorkerClient.ScanHardTimeout(new() { ContainerLimits = new() { MaximumDurationSeconds = 10000 } }) == TimeSpan.FromSeconds(10005));
        ScanReport many = new() { ContentScanSettings = new() { MaximumReportRecords = 30000 } };
        for (int index = 0; index < 20001; index++) many.Findings.Add(new() { Title = "Inert budget fixture" });
        new ScanResourceGuard().Check(many);
        ReportBatchReader reader = new(30000);
        new ReportBatchWriter(reader.Apply).Send(many, final: true);
        Check("扫描设置 调高报告数量允许超过旧20000条并完整回传", reader.Report!.Findings.Count == 20001);
        many.ContentScanSettings = new() { MaximumReportRecords = 10000 };
        Check("扫描设置 调低报告数量受控停止", V020Throws<ScanResourceLimitException>(() => new ScanResourceGuard().Check(many)));
        many.ContentScanSettings = new() { MaximumReportRecords = 30000, MaximumReportTextCharacters = 100 };
        Check("扫描设置 报告文本预算仍独立生效", V020Throws<ScanResourceLimitException>(() => new ScanResourceGuard().Check(many)));
        CoverageEntry amsiLimit = CoveragePresentation.Describe("AMSI-ENGINE-SIZE-LIMIT", archive, "AMSI 未检查大文件正文");
        Check("扫描设置 正文超限指向设置与补查而非误报AMSI不可用", amsiLimit.CanFullScan && amsiLimit.NextStep.Contains("扫描限制设置") && !amsiLimit.Kind.Contains("不可用"));
        byte[] nested = File.ReadAllBytes(archive);
        for (int depth = 0; depth < 34; depth++)
        {
            using MemoryStream output = new();
            using (ZipArchive zip = new(output, ZipArchiveMode.Create, leaveOpen: true))
            using (Stream entry = zip.CreateEntry("nested.zip", CompressionLevel.NoCompression).Open()) entry.Write(nested);
            nested = output.ToArray();
        }
        string deepArchive = Path.Combine(directory, "deep.zip"); File.WriteAllBytes(deepArchive, nested);
        settings.Full.Clear(); settings.Full["ContainerLimits.MaximumDepth"] = 2;
        ScanReport depthLow = await Scan(deepArchive, settings);
        settings.Full["ContainerLimits.MaximumDepth"] = 64;
        ScanOptions workerOptions = settings.Apply(new()
        {
            Mode = ScanMode.Custom,
            CustomRoots = [deepArchive],
            UseAmsi = false,
            IncludeSystem = false,
            IncludeSteam = false,
            IncludeWorkshop = false,
            InspectDeepSignatures = false
        });
        ScanReport workerDeep = await new ArchiveWorkerClient(workerOverride ?? DevelopmentWorkerPath()).RunAsync(workerOptions,
            (request, _) => Task.FromResult(new ArchivePasswordResponse(request.RequestId, true, null, false)), null, CancellationToken.None);
        Check("扫描设置 实际深度2停止而64跨Worker传输超过32层并读到叶子", depthLow.Coverage != ScanCoverage.Complete &&
            workerDeep.Containers!.Nodes.Any(n => n.Depth > 32 && n.DisplayPath.EndsWith("inert.txt") && n.Sha256 is not null));
        Check("扫描设置 Worker报告保留用户预算", workerDeep.ContentScanSettings?.MaximumArchiveDepth == 64 && workerDeep.Containers!.Limits.MaximumDepth == 64);
        settings.UsePreset(ScanMode.Custom, 4);
        workerOptions = settings.Apply(new()
        {
            Mode = ScanMode.Custom,
            CustomRoots = [archive],
            UseAmsi = false,
            IncludeSystem = false,
            IncludeSteam = false,
            IncludeWorkshop = false,
            InspectDeepSignatures = false
        });
        ScanReport extreme = await new ArchiveWorkerClient(workerOverride ?? DevelopmentWorkerPath()).RunAsync(workerOptions,
            (request, _) => Task.FromResult(new ArchivePasswordResponse(request.RequestId, true, null, false)), null, CancellationToken.None);
        Check("扫描设置 极高档实际Worker解压完成且保留4GiB内存预算", extreme.Containers!.Nodes.Any(n => n.DisplayPath.EndsWith("inert.txt") && n.Sha256 is not null) &&
            extreme.ContentScanSettings!.MaximumWorkerMemoryBytes == 4096L * 1048576);
    }
}
