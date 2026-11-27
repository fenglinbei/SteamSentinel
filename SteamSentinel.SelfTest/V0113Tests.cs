using System.Buffers.Binary;
using System.IO;
using System.Text;
using System.Text.Json;
using SteamSentinel.App.Services;
using SteamSentinel.Core.Inspection;
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
        ScanOptions options = new()
        {
            Mode = ScanMode.Full,
            IncludeSteam = false,
            IncludeSystem = false,
            IncludeWorkshop = false,
            UseAmsi = false,
            InspectArchives = true,
            HashEveryFile = true,
            CustomRoots = [fixture]
        };
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
        ScanReport scriptReport = await new ScanCoordinator(new RuleSet()).RunAsync(new ScanOptions
        {
            Mode = ScanMode.Custom,
            IncludeSteam = false,
            IncludeSystem = false,
            IncludeWorkshop = false,
            UseAmsi = false,
            CustomRoots = [script]
        });
        Check("脚本词语跨窗口累积仍只供复核", scriptReport.Findings.Any(f => f.RuleId == "HEUR-SCRIPT-TOKEN-COOCCURRENCE" && f.Severity == FindingSeverity.Medium && !f.CanRemediate));

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

        ScanReport partial = new()
        {
            ContentScanSettings = options,
            WorkerDiagnostics = new("压缩包目录", "inert.zip!/inner.rar?token=secret", "读取目录", 500, 600, 400, DateTimeOffset.UtcNow, "OutOfMemoryException", "inert stack")
        };
        partial.Findings.Add(strings.Findings.First()); partial.Metrics.FilesVisited = 3;
        ScanReport preserved = ScanFailureReports.PreserveSystemResults(new() { Metrics = new() { ProcessesVisited = 7 } },
            ScanMode.Full, [], "fixture", new WorkerFailureException(WorkerStage.Scanning, 1, "inert OOM") { PartialReport = partial }, false);
        Check("中断报告保留内容发现、系统计数与未完整状态", preserved.Metrics.FilesVisited == 3 && preserved.Metrics.ProcessesVisited == 7 && preserved.Coverage == ScanCoverage.Partial && preserved.Findings.Any(f => f.CanRemediate));
        string json = Path.Combine(directory, "failure.json"), markdown = Path.Combine(directory, "failure.md");
        await ReportExporter.ExportJsonAsync(preserved, json); await ReportExporter.ExportMarkdownAsync(preserved, markdown);
        string exported = await File.ReadAllTextAsync(json), md = await File.ReadAllTextAsync(markdown);
        Check("流式 JSON 导出保留设置与诊断且继续脱敏", exported.Contains("ContentScanSettings") && exported.Contains("WorkerDiagnostics") && !exported.Contains("token=secret"));
        Check("Markdown 显示最后路径、内部阶段和内存", md.Contains("压缩包目录") && md.Contains("inert.zip") && md.Contains("组件私有内存") && !md.Contains("token=secret"));

        string worker = ResolveArchiveWorkerPath(allowCoverageEnvOverride: false);
        static Task<ArchivePasswordResponse> NoPassword(ArchivePasswordRequest r, CancellationToken _) =>
            Task.FromResult(new ArchivePasswordResponse(r.RequestId, true, null, false));
        using CancellationTokenSource timeout = new(TimeSpan.FromMinutes(3));
        string second = Path.Combine(directory, "large-second.dat"); File.Copy(fixture, second);
        ScanReport lowLarge = await new ArchiveWorkerClient(worker).RunAsync(new ScanOptions
        {
            Mode = ScanMode.Full,
            IncludeSystem = false,
            IncludeSteam = false,
            IncludeWorkshop = false,
            UseAmsi = false,
            HashEveryFile = true,
            CustomRoots = [fixture, second, script]
        }, NoPassword, null, timeout.Token);
        Check("真实 Low Worker 连续分析两个 32 MiB 文件与分散脚本信号", lowLarge.Findings.Count(f => f.CanRemediate) == 2 && lowLarge.Findings.Count(f => f.RuleId == "HEUR-SCRIPT-TOKEN-COOCCURRENCE" && !f.CanRemediate) == 1 && lowLarge.Metrics.FilesVisited == 3);
        Check("真实扫描保留内存诊断且仍在 1 GiB Job 内", lowLarge.WorkerDiagnostics is { PrivateBytes: > 0, PeakPrivateBytes: < 1024L * 1024 * 1024 });
        Console.WriteLine($"V0113_LARGE_PEAK_MIB={lowLarge.WorkerDiagnostics!.PeakPrivateBytes / 1024 / 1024}");
        string manyFiles = Path.Combine(directory, "many"); Directory.CreateDirectory(manyFiles);
        // 限制并发度写入六千个小文件，消除逐个异步状态机开销
        Parallel.For(0, 6000, new ParallelOptions { MaxDegreeOfParallelism = 4 }, i =>
            File.WriteAllText(Path.Combine(manyFiles, $"item-{i:D5}.dat"), "x"));
        ScanReport lowMany = await new ArchiveWorkerClient(worker).RunAsync(new ScanOptions
        {
            Mode = ScanMode.Full,
            IncludeSystem = false,
            IncludeSteam = false,
            IncludeWorkshop = false,
            UseAmsi = false,
            MaximumContentBytes = 0,
            CustomRoots = [manyFiles]
        }, NoPassword, null, timeout.Token);
        Check("真实 Low Worker 六千次覆盖缺口聚合完整交回", lowMany.Metrics.FilesVisited == 6000 &&
            lowMany.Findings.Count == 0 && lowMany.CoverageAggregates.Single().Count == 6000 && lowMany.Coverage == ScanCoverage.Partial &&
            lowMany.RootSummaries.Single().Coverage == ScanCoverage.Partial);
        Console.WriteLine($"V0113_MANY_PEAK_MIB={lowMany.WorkerDiagnostics!.PeakPrivateBytes / 1024 / 1024}");
        WorkerFailureException? limited = null;
        try
        {
            await new ArchiveWorkerClient(worker).RunAsync(new ScanOptions
            {
                Mode = ScanMode.Full,
                IncludeSystem = false,
                IncludeSteam = false,
                IncludeWorkshop = false,
                UseAmsi = false,
                MaximumContentBytes = 0,
                MaximumFiles = 2,
                CustomRoots = Directory.EnumerateFiles(manyFiles).Take(3).ToList()
            }, NoPassword, null, timeout.Token);
        }
        catch (WorkerFailureException ex) { limited = ex; }
        Check("真实跨根目录总文件上限保留前两项并说明未完成", limited?.PartialReport?.Metrics.FilesVisited == 2 &&
            limited.PartialReport.CoverageAggregates.Sum(a => a.Count) == 2 &&
            limited.PartialReport.WorkerDiagnostics?.FailureType == nameof(ScanResourceLimitException));

        static byte[] BuildSingleSectionPeWithPayload(string asciiPayload)
        {
            byte[] pe = new byte[1024];
            pe[0] = (byte)'M';
            pe[1] = (byte)'Z';
            BinaryPrimitives.WriteInt32LittleEndian(pe.AsSpan(0x3C, 4), 0x40);
            "PE\0\0"u8.CopyTo(pe.AsSpan(0x40, 4));
            // COFF 头: AMD64, 1 节, SizeOfOptionalHeader=240, Characteristics=0x2022
            BinaryPrimitives.WriteUInt16LittleEndian(pe.AsSpan(0x44, 2), 0x8664);
            BinaryPrimitives.WriteUInt16LittleEndian(pe.AsSpan(0x46, 2), 1);
            BinaryPrimitives.WriteUInt16LittleEndian(pe.AsSpan(0x54, 2), 240);
            BinaryPrimitives.WriteUInt16LittleEndian(pe.AsSpan(0x56, 2), 0x2022);
            // PE32+ 可选头: Magic=0x020B, SizeOfHeaders=512
            BinaryPrimitives.WriteUInt16LittleEndian(pe.AsSpan(0x58, 2), 0x020B);
            BinaryPrimitives.WriteUInt32LittleEndian(pe.AsSpan(0x90, 4), 0x2000);
            BinaryPrimitives.WriteUInt32LittleEndian(pe.AsSpan(0x94, 4), 512);
            // 单节 .rdata: RawOffset=512, RawSize=512，恰好覆盖整个 1024 字节文件无尾随区间
            ".rdata\0\0"u8.CopyTo(pe.AsSpan(0x148, 8));
            BinaryPrimitives.WriteUInt32LittleEndian(pe.AsSpan(0x150, 4), 512);
            BinaryPrimitives.WriteUInt32LittleEndian(pe.AsSpan(0x154, 4), 0x1000);
            BinaryPrimitives.WriteUInt32LittleEndian(pe.AsSpan(0x158, 4), 512);
            BinaryPrimitives.WriteUInt32LittleEndian(pe.AsSpan(0x15C, 4), 512);
            BinaryPrimitives.WriteUInt32LittleEndian(pe.AsSpan(0x16C, 4), 0x40000040);

            byte[] payload = Encoding.ASCII.GetBytes("\0" + asciiPayload + "\0");
            if (payload.Length > 512) throw new ArgumentException("Payload exceeds 512-byte section.", nameof(asciiPayload));
            payload.CopyTo(pe.AsSpan(512));
            return pe;
        }

        string peNativePath = Path.Combine(directory, "native-runtime.dll");
        await File.WriteAllBytesAsync(peNativePath, BuildSingleSectionPeWithPayload(
            "https://example.invalid Invoke-WebRequest Start-Process rundll32 steamprocess Add-MpPreference captcha"));
        ScanOptions customFileOptions = new()
        {
            Mode = ScanMode.Custom,
            IncludeSteam = false,
            IncludeSystem = false,
            IncludeWorkshop = false,
            UseAmsi = false,
            CustomRoots = [peNativePath]
        };

        ScanReport peSignedReport = new() { Mode = ScanMode.Custom };
        using (ContentScanner signedScanner = new(new RuleSet()) { PeSignatureVerifier = static (_, _) => SignatureStatus.Valid })
            await signedScanner.ScanRootAsync(peNativePath, peSignedReport, customFileOptions, new NullPasswordProvider());
        Check("合法已签名 PE 二进制豁免脚本词语共现误报",
            peSignedReport.Metrics.FilesVisited == 1 &&
            peSignedReport.Findings.Count == 0);

        foreach (SignatureStatus nonValidStatus in new[] { SignatureStatus.Unsigned, SignatureStatus.HashMismatch })
        {
            ScanReport nonSignedReport = new() { Mode = ScanMode.Custom };
            using ContentScanner nonSignedScanner = new(new RuleSet()) { PeSignatureVerifier = (_, _) => nonValidStatus };
            await nonSignedScanner.ScanRootAsync(peNativePath, nonSignedReport, customFileOptions, new NullPasswordProvider());
            Check($"非合法签名 PE({nonValidStatus}) 仍保留脚本词语共现复核提示",
                nonSignedReport.Metrics.FilesVisited == 1 &&
                nonSignedReport.Findings.Any(f => f.RuleId == "HEUR-SCRIPT-TOKEN-COOCCURRENCE" && !f.CanRemediate));
        }

        string pePatcherPath = Path.Combine(directory, "patcher-host.dll");
        await File.WriteAllBytesAsync(pePatcherPath, BuildSingleSectionPeWithPayload(
            "steam://open/supportalert SupportMessages HelpFrontPage steamhelper bSupportPopupMessage"));
        ScanReport pePatcherSignedReport = new() { Mode = ScanMode.Custom };
        using (ContentScanner patcherScanner = new(new RuleSet()) { PeSignatureVerifier = static (_, _) => SignatureStatus.Valid })
            await patcherScanner.ScanRootAsync(pePatcherPath, pePatcherSignedReport, customFileOptions, new NullPasswordProvider());
        Check("合法签名 PE 仍正常检出强假红信注入器组合规则",
            pePatcherSignedReport.Findings.Any(f => f.RuleId == "HEUR-STEAM-UI-PATCHER" && f.CanRemediate));

        string? dotnetRoot = Environment.GetEnvironmentVariable("DOTNET_ROOT");
        string realSignedSource = new[]
        {
            dotnetRoot is null ? null : Path.Combine(dotnetRoot, "dotnet.exe"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "dotnet", "dotnet.exe")
        }.First(p => p is not null && File.Exists(p))!;
        string realSignedCopy = Path.Combine(directory, "dotnet-signed-copy.exe");
        File.Copy(realSignedSource, realSignedCopy);
        SignatureResult realOfflineSig = AuthenticodeVerifier.VerifyOffline(realSignedCopy);
        ScanReport realSignedReport = await new ScanCoordinator(new RuleSet()).RunAsync(new ScanOptions
        {
            Mode = ScanMode.Custom,
            IncludeSteam = false,
            IncludeSystem = false,
            IncludeWorkshop = false,
            UseAmsi = false,
            CustomRoots = [realSignedCopy]
        });
        Check("真实微软签名 PE 副本通过默认离线验签且无误报",
            realOfflineSig.Status == SignatureStatus.Valid &&
            realSignedReport.Metrics.FilesVisited == 1 &&
            realSignedReport.Findings.All(f => f.Category != FindingCategory.Coverage && f.RuleId != "HEUR-SCRIPT-TOKEN-COOCCURRENCE"));
    }
}
