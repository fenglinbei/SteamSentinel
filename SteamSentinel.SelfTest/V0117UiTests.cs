using System.Diagnostics;
using System.IO;
using System.IO.Compression;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using Microsoft.Win32.SafeHandles;
using SteamSentinel.App.Services;
using SteamSentinel.Core.Models;
using SteamSentinel.Core.Reporting;
using SteamSentinel.Core.Utilities;

namespace SteamSentinel.SelfTest;

internal static partial class Program
{
    private static byte[] CreateV0117PeHeader()
    {
        byte[] header = new byte[128];
        header[0] = 0x4D; header[1] = 0x5A;
        System.Buffers.Binary.BinaryPrimitives.WriteInt32LittleEndian(header.AsSpan(0x3C), 64);
        "PE\0\0"u8.CopyTo(header.AsSpan(64));
        header[68] = 0x64; header[69] = 0x86; header[70] = 1;
        return header;
    }

    private static async Task TestV0117UiAsync(string root)
    {
        ScanReport completed = new() { Mode = ScanMode.Full, CompletedAtUtc = DateTimeOffset.UtcNow };
        Finding preserved = new() { IsKnownMalware = true, Severity = FindingSeverity.High, Target = "inert fixture" };
        completed.Findings.Add(preserved);
        await ScanFailureReports.CollectSupplementAsync(completed, () => throw new System.ComponentModel.Win32Exception("inert blocked PowerShell"));
        Check("0.1.17 附加检查失败保留已发现内容并降为Partial", completed.Findings.Contains(preserved) &&
            completed.Coverage == ScanCoverage.Partial && completed.Findings.Any(f => f.RuleId == "PROTECTION-SUPPLEMENT-INCOMPLETE"));

        DateTimeOffset now = DateTimeOffset.UtcNow, boot = now.AddHours(-1);
        QuarantineManifest incident = new()
        {
            CreatedAtUtc = now.AddDays(-1),
            MachineBootTimeUtc = now.AddDays(-2),
            Records = [new() { RolledBack = true }]
        };
        ScanReport Clean(ScanMode mode = ScanMode.Full, DateTimeOffset? start = null) => new()
        { Mode = mode, StartedAtUtc = start ?? now.AddMinutes(-10), CompletedAtUtc = now.AddMinutes(-2) };
        ScanReport clean = Clean();
        Check("0.1.17 已回滚空事件仅接受本次完整系统与内容复扫", IncidentDeletionPolicy.RejectionReason(incident, clean, clean.ScanId, now, boot) is null);
        ScanReport custom = Clean(ScanMode.Custom);
        Check("0.1.17 无害自定义单文件不能解锁删除", IncidentDeletionPolicy.RejectionReason(incident, custom, custom.ScanId, now, boot) is not null);
        Check("0.1.17 未证明系统阶段或旧扫描ID不能解锁删除", IncidentDeletionPolicy.RejectionReason(incident, clean, Guid.NewGuid(), now, boot) is not null);
        ScanReport beforeBoot = Clean(start: boot.AddMinutes(-1));
        Check("0.1.17 重启前报告不能解锁删除", IncidentDeletionPolicy.RejectionReason(incident, beforeBoot, beforeBoot.ScanId, now, boot) is not null);
        clean.Findings.Add(new() { IsKnownMalware = true, Severity = FindingSeverity.High });
        Check("0.1.17 High已知恶意项也阻止删除", IncidentDeletionPolicy.RejectionReason(incident, clean, clean.ScanId, now, boot) is not null);
        clean.Findings.Clear();
        incident.Records.Add(new() { RolledBack = false });
        Check("0.1.17 活动隔离事件始终保留", IncidentDeletionPolicy.RejectionReason(incident, clean, clean.ScanId, now, boot) is not null);

        string directory = Path.Combine(root, "v0117-ui"); Directory.CreateDirectory(directory);
        string destination = Path.Combine(directory, "retained.md");
        await File.WriteAllTextAsync(destination, "original report");
        try { await AtomicFile.WriteAsync(destination, async stream => { await stream.WriteAsync("partial"u8.ToArray()); throw new IOException("inert failure"); }); }
        catch (IOException) { }
        Check("0.1.17 导出失败不覆盖已有文件且清理临时输出", await File.ReadAllTextAsync(destination) == "original report" && Directory.GetFiles(directory).Length == 1);
        using (CancellationTokenSource cancelled = new())
        {
            cancelled.Cancel();
            try { await CaseBundleExporter.ExportAsync(destination, clean, null, null, null, cancelled.Token); }
            catch (OperationCanceledException) { }
        }
        Check("0.1.17 取消记录包导出保留已有报告", await File.ReadAllTextAsync(destination) == "original report");
        await ReportExporter.ExportMarkdownAsync(clean, destination);
        Check("0.1.17 Markdown报告保留构建标识", (await File.ReadAllTextAsync(destination)).Contains(ProductInfo.BuildIdentity, StringComparison.Ordinal));

        bool bounded = false;
        try { await RemediationClient.WaitForBrokerAsync(new TaskCompletionSource().Task, TimeSpan.FromMilliseconds(20), CancellationToken.None); }
        catch (TimeoutException) { bounded = true; }
        Check("0.1.17 管理员等待有界且不取消后台任务", bounded);

        string session;
        using (WorkerWorkspace workspace = new())
        {
            session = workspace.Path;
            string child = Path.Combine(session, "expanded"); Directory.CreateDirectory(child);
            await File.WriteAllTextAsync(Path.Combine(child, "inert.scan"), "harmless bytes");
        }
        Check("0.1.17 父进程会清理整个扫描会话及嵌套展开目录", !Directory.Exists(session));

        ScanReport original = new() { ProductVersion = "fixture", BuildIdentity = "fixture+commit.preview" };
        ReportBatchReader reader = new(); new ReportBatchWriter(reader.Apply).Send(original, final: true);
        Check("0.1.17 Worker批次不丢失实际构建身份", reader.Report?.BuildIdentity == original.BuildIdentity && reader.Report.ProductVersion == "fixture");
        await TestV0117HandleInheritanceAsync(directory);
        await TestV0117ProgressCancellationAsync(directory);
    }

    private static async Task TestV0117ProgressCancellationAsync(string directory)
    {
        string archivePath = Path.Combine(directory, "stage-cancellation.zip");
        using (ZipArchive archive = ZipFile.Open(archivePath, ZipArchiveMode.Create))
        {
            using Stream member = archive.CreateEntry("inert.dat", CompressionLevel.NoCompression).Open();
            member.Write(new byte[2 * 1024 * 1024]);
        }
        HashSet<string> before = Directory.GetDirectories(AppPaths.WorkerTemporaryRoot).ToHashSet(StringComparer.OrdinalIgnoreCase);
        bool triggered = false, cancelled = false;
        using CancellationTokenSource timeout = new(TimeSpan.FromSeconds(20));
        try
        {
            await new ArchiveWorkerClient(DevelopmentWorkerPath()).RunAsync(new ScanOptions
            {
                Mode = ScanMode.Custom,
                IncludeSystem = false,
                IncludeSteam = false,
                IncludeWorkshop = false,
                UseAmsi = false,
                InspectArchives = true,
                HashEveryFile = true,
                CustomRoots = [archivePath]
            }, (request, _) => Task.FromResult(new ArchivePasswordResponse(request.RequestId, true, null, false)),
            new InlineProgress(progress =>
            {
                if (progress.Stage != "压缩包扫描") return;
                triggered = true;
                timeout.Cancel();
            }), timeout.Token);
        }
        catch (OperationCanceledException) { cancelled = true; }
        Check("0.1.17 阶段切换不被节流丢弃且真实Low取消无临时残留", triggered && cancelled &&
            Directory.GetDirectories(AppPaths.WorkerTemporaryRoot).All(before.Contains));
    }

    private static async Task<int> RunV0117SmokeAsync(string outputPath, string? workerOverride = null)
    {
        string output = Path.GetFullPath(outputPath);
        if (Directory.Exists(output) && Directory.EnumerateFileSystemEntries(output).Any())
            throw new IOException("小规模测试输出目录必须为空，避免覆盖已有记录。");
        Directory.CreateDirectory(output);
        string fixtures = Path.Combine(output, "harmless-fixtures"); Directory.CreateDirectory(fixtures);
        Stopwatch clock = Stopwatch.StartNew();
        await File.WriteAllTextAsync(Path.Combine(fixtures, "readme.txt"), "SteamSentinel harmless local smoke fixture.");
        string zip = Path.Combine(fixtures, "nested.zip");
        using (ZipArchive archive = ZipFile.Open(zip, ZipArchiveMode.Create))
        {
            await using StreamWriter writer = new(archive.CreateEntry("./docs/readme.txt").Open());
            await writer.WriteAsync("Harmless document stored under a conventional relative TAR/ZIP path.");
        }
        string large = Path.Combine(fixtures, "quick-65MiB.dat");
        using (FileStream file = File.Create(large)) file.SetLength(65L * 1024 * 1024);
        string workerPath = workerOverride is null ? DevelopmentWorkerPath() : Path.GetFullPath(workerOverride);
        ArchiveWorkerClient worker = new(workerPath);
        static Task<ArchivePasswordResponse> NoPassword(ArchivePasswordRequest request, CancellationToken _) =>
            Task.FromResult(new ArchivePasswordResponse(request.RequestId, true, null, false));
        using CancellationTokenSource timeout = new(TimeSpan.FromMinutes(2));
        ScanReport full = await worker.RunAsync(new ScanOptions
        {
            Mode = ScanMode.Custom,
            IncludeSystem = false,
            IncludeSteam = false,
            IncludeWorkshop = false,
            UseAmsi = false,
            InspectArchives = true,
            HashEveryFile = true,
            CustomRoots = [Path.Combine(fixtures, "readme.txt"), zip]
        }, NoPassword, null, timeout.Token);
        Check("本机小规模：受限Worker完成普通文件与归档扫描", full.Coverage == ScanCoverage.Complete &&
            full.Metrics.ArchiveEntriesVisited == 1 && full.Metrics.FilesVisited >= 3 && !full.Findings.Any(f => f.IsKnownMalware));
        ScanReport quick = await worker.RunAsync(new ScanOptions
        {
            Mode = ScanMode.Quick,
            IncludeSystem = false,
            IncludeSteam = false,
            IncludeWorkshop = false,
            UseAmsi = false,
            InspectArchives = true,
            CustomRoots = [large]
        }, NoPassword, null, timeout.Token);
        Check("本机小规模：65MiB快速检查明确报告覆盖缺口", quick.Coverage == ScanCoverage.Partial);
        await ReportExporter.ExportJsonAsync(full, Path.Combine(output, "full-scan.json"));
        await ReportExporter.ExportMarkdownAsync(full, Path.Combine(output, "full-scan.md"));
        await ReportExporter.ExportJsonAsync(quick, Path.Combine(output, "quick-scan.json"));
        await CaseBundleExporter.ExportAsync(Path.Combine(output, "case-records.zip"), full, null, null, quick);
        Check("本机小规模：导出记录包可重新打开", ZipFile.OpenRead(Path.Combine(output, "case-records.zip")) is { } exported && ReadAndDisposeSmokeZip(exported));

        string cancelZip = Path.Combine(fixtures, "cancel-during-extraction.zip");
        using (ZipArchive archive = ZipFile.Open(cancelZip, ZipArchiveMode.Create))
        {
            byte[] block = new byte[64 * 1024]; new Random(117).NextBytes(block);
            using Stream member = archive.CreateEntry("inert-data.dat", CompressionLevel.NoCompression).Open();
            for (int i = 0; i < 512; i++) member.Write(block);
        }
        HashSet<string> before = Directory.GetDirectories(AppPaths.WorkerTemporaryRoot).ToHashSet(StringComparer.OrdinalIgnoreCase);
        bool cancelled = false;
        bool cancellationTriggered = false;
        using (CancellationTokenSource cancel = new(TimeSpan.FromSeconds(20)))
        {
            IProgress<ScanProgress> progress = new InlineProgress(p =>
            {
                if (p.Stage != "压缩包扫描") return;
                cancellationTriggered = true;
                cancel.Cancel();
            });
            try
            {
                await worker.RunAsync(new ScanOptions
                {
                    Mode = ScanMode.Custom,
                    IncludeSystem = false,
                    IncludeSteam = false,
                    IncludeWorkshop = false,
                    UseAmsi = false,
                    InspectArchives = true,
                    HashEveryFile = true,
                    CustomRoots = [cancelZip]
                }, NoPassword, progress, cancel.Token);
            }
            catch (OperationCanceledException) { cancelled = true; }
        }
        string[] leftovers = Directory.GetDirectories(AppPaths.WorkerTemporaryRoot).Where(p => !before.Contains(p)).ToArray();
        Check("本机小规模：取消扫描会退出且无新增展开残留", cancellationTriggered && cancelled && leftovers.Length == 0);
        await JsonFile.WriteAtomicAsync(Path.Combine(output, "smoke-results.json"), new
        {
            version = full.ProductVersion,
            buildIdentity = full.BuildIdentity,
            harnessBuildIdentity = ProductInfo.BuildIdentity,
            workerExecutable = workerPath,
            workerSha256 = await Hashing.Sha256FileAsync(workerPath),
            passed = _passed,
            failed = Failures.Count,
            skipped = _skipped,
            failures = Failures,
            elapsedMs = clock.ElapsedMilliseconds,
            completedAtUtc = DateTimeOffset.UtcNow,
            containment = "Low Integrity through production launcher",
            remediationExecuted = false,
            cancellationTriggered,
            cancelled,
            scanned = "Only newly generated harmless fixtures",
            leftovers
        });
        Console.WriteLine($"小规模测试通过：{_passed}；失败：{Failures.Count}；输出：{output}");
        return Failures.Count == 0 ? 0 : 1;
    }

    private static bool ReadAndDisposeSmokeZip(ZipArchive zip)
    { using (zip) return zip.GetEntry("scan.json") is not null && zip.GetEntry("follow-up.json") is not null; }

    private sealed class InlineProgress(Action<ScanProgress> callback) : IProgress<ScanProgress>
    { public void Report(ScanProgress value) => callback(value); }

    private static async Task TestV0117HandleInheritanceAsync(string directory)
    {
        string fixtureRoot = Path.Combine(directory, "inheritance-worker"); Directory.CreateDirectory(fixtureRoot);
        foreach (string file in Directory.EnumerateFiles(AppContext.BaseDirectory)) File.Copy(file, Path.Combine(fixtureRoot, Path.GetFileName(file)));
        string fixture = Path.Combine(fixtureRoot, "SteamSentinelFixture-inheritance.exe");
        File.Copy(Path.Combine(fixtureRoot, "SteamSentinel.SelfTest.exe"), fixture);
        File.Copy(Path.Combine(fixtureRoot, "SteamSentinel.SelfTest.dll"), Path.ChangeExtension(fixture, ".dll"));
        string marker = Path.Combine(directory, "handle-sentinel-" + Guid.NewGuid().ToString("N") + ".txt");
        await using FileStream sentinel = new(marker, FileMode.CreateNew, FileAccess.ReadWrite, FileShare.ReadWrite);
        if (!SetV0117HandleInformation(sentinel.SafeFileHandle, 1, 1)) throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
        try
        {
            using CancellationTokenSource timeout = new(TimeSpan.FromSeconds(15));
            ScanReport result = await new ArchiveWorkerClient(fixture).RunAsync(new ScanOptions
            {
                CustomRoots = [sentinel.SafeFileHandle.DangerousGetHandle().ToInt64().ToString(System.Globalization.CultureInfo.InvariantCulture), Path.GetFileName(marker)]
            }, (_, _) => throw new InvalidOperationException("Probe must not request a password"), null, timeout.Token);
            Check("0.1.17 Low Worker不可访问父进程额外可继承文件句柄", !result.Findings.Any(f => f.RuleId == "HANDLE-LEAK"));
        }
        finally { SetV0117HandleInformation(sentinel.SafeFileHandle, 1, 0); }
    }

    private static async Task<int> RunV0117InheritanceProbeAsync()
    {
        await Console.Out.WriteLineAsync(JsonSerializer.Serialize(new WorkerMessage { Type = WorkerMessageTypes.Ready, Containment = ProcessIntegrity.GetCurrent().ToString() }));
        await Console.Out.FlushAsync();
        WorkerMessage? start = JsonSerializer.Deserialize<WorkerMessage>((await Console.In.ReadLineAsync())!, JsonFile.Options);
        string[] request = start!.Options!.CustomRoots.ToArray();
        StringBuilder path = new(2048);
        uint count = GetV0117FinalPathNameByHandle(new IntPtr(long.Parse(request[0], System.Globalization.CultureInfo.InvariantCulture)), path, 2048, 0);
        ScanReport report = new();
        if (count > 0 && path.ToString().EndsWith("\\" + request[1], StringComparison.OrdinalIgnoreCase))
            report.Findings.Add(new() { RuleId = "HANDLE-LEAK" });
        await Console.Out.WriteLineAsync(JsonSerializer.Serialize(new WorkerMessage { Type = WorkerMessageTypes.Completed, Report = report }));
        await Console.Out.FlushAsync();
        return 0;
    }

    [DllImport("kernel32.dll", EntryPoint = "SetHandleInformation", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetV0117HandleInformation(SafeFileHandle handle, uint mask, uint flags);

    [DllImport("kernel32.dll", EntryPoint = "GetFinalPathNameByHandleW", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern uint GetV0117FinalPathNameByHandle(IntPtr handle, StringBuilder path, uint length, uint flags);
}
