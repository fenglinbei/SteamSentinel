using System.Diagnostics;
using System.IO;
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
    private static async Task<int> RunV020TopologyAsync(string manifestPath, string outputDirectory, bool restricted, string? workerOverride = null)
    {
        string manifestFull = Path.GetFullPath(manifestPath), output = Path.GetFullPath(outputDirectory);
        Directory.CreateDirectory(output);
        using JsonDocument manifest = JsonDocument.Parse(await File.ReadAllTextAsync(manifestFull));
        JsonElement spec = manifest.RootElement;
        if (spec.GetProperty("SchemaVersion").GetInt32() != 1 || !spec.GetProperty("PasswordIsPublicFixtureData").GetBoolean())
            throw new InvalidDataException("此验收入口只接受生成的公开密码惰性夹具清单。");
        string fixtureRoot = Path.GetDirectoryName(manifestFull)!;
        string rootFile = spec.GetProperty("RootFile").GetString()!;
        if (!rootFile.StartsWith(fixtureRoot + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase))
            throw new InvalidDataException("惰性夹具根路径不在本清单目录内。");
        string publicPassword = spec.GetProperty("Password").GetString()!;
        string profile = spec.GetProperty("Profile").GetString()!;
        JsonElement[] expectedLeaves = spec.GetProperty("Leaves").EnumerateArray().ToArray();
        if (expectedLeaves.Length != 167) throw new InvalidDataException("拓扑夹具应包含167个最终成员。");
        ScanOptions options = new()
        {
            Mode = ScanMode.Custom,
            IncludeSystem = false,
            IncludeSteam = false,
            IncludeWorkshop = false,
            IncludeRelatedContent = false,
            UseAmsi = false,
            InspectArchives = true,
            InspectDeepSignatures = true,
            HashEveryFile = true,
            CustomRoots = [rootFile],
            MaximumContentBytes = long.MaxValue,
            RecoveryOutputDirectory = restricted && profile == "Small" ? output : null
        };
        using CancellationTokenSource deadline = new(TimeSpan.FromMinutes(35));
        int prompts = 0;
        Task<ArchivePasswordResponse> Password(ArchivePasswordRequest request, CancellationToken token)
        {
            token.ThrowIfCancellationRequested(); prompts++;
            if (prompts > 6) throw new InvalidOperationException("惰性夹具密码请求异常重复。");
            return Task.FromResult(new ArchivePasswordResponse(request.RequestId, false, publicPassword, false, ArchivePasswordReuseScope.ArchiveTree));
        }
        Stopwatch elapsed = Stopwatch.StartNew();
        long last = 0;
        IProgress<ScanProgress> progress = new V020DirectProgress(value =>
        {
            if (elapsed.ElapsedMilliseconds - last < 3000) return; last = elapsed.ElapsedMilliseconds;
            Console.WriteLine($"TOPOLOGY_PROGRESS {elapsed.Elapsed.TotalSeconds:F0}s {value.Stage} {value.Message}");
        });
        ScanReport report;
        string? workerPath = restricted ? workerOverride ?? DevelopmentWorkerPath() : null;
        try
        {
            report = restricted ? await new ArchiveWorkerClient(workerPath!).RunAsync(options, Password, progress, deadline.Token) :
                await new ScanCoordinator().RunAsync(options, new V020PublicFixturePasswordProvider(Password), progress, deadline.Token);
        }
        catch (WorkerFailureException ex) when (ex.PartialReport is not null)
        {
            report = ex.PartialReport; Failures.Add("0.2实体链Worker失败：" + ex.Message);
        }
        await JsonFile.WriteAtomicAsync(Path.Combine(output, "scan-report.json"), report, options: ReportPrivacy.ExportOptions);
        await ReportExporter.ExportMarkdownAsync(report, Path.Combine(output, "scan-report.md"));
        ContainerScanNode[] nodes = report.Containers?.Nodes.ToArray() ?? [];
        int matched = 0;
        foreach (JsonElement leaf in expectedLeaves)
        {
            string relative = leaf.GetProperty("RelativePath").GetString()!.Replace('\\', '/');
            ContainerScanNode[] actual = nodes.Where(node => node.DisplayPath.Replace('\\', '/').EndsWith("!/" + relative, StringComparison.Ordinal)).ToArray();
            bool identity = actual.Length == 1 && actual[0].Sha256 == leaf.GetProperty("Sha256").GetString() &&
                actual[0].Length == leaf.GetProperty("Length").GetInt64() && actual[0].Integrity == ContainerStageStatus.Complete;
            if (identity) matched++;
            else Failures.Add("0.2实体链叶子未完成或身份不符：" + relative);
        }
        Check("0.2实体链167个叶子长度哈希和归档完整性全部匹配", matched == 167);
        Check("0.2实体链包含MP4和SFX两种父层相对范围", nodes.Count(node => node.Kind == ContainerNodeKind.EmbeddedRange && node.ParentOffset > 0) >= 2);
        Check("0.2实体链三卷按真实身份归组且重复入口不解码", nodes.Any(node => node.Kind == ContainerNodeKind.VolumeGroup && node.Volumes.Count == 3 && node.Integrity == ContainerStageStatus.Complete) &&
            nodes.Count(node => node.ReusedNodeId.HasValue) >= 2);
        Check("0.2实体链密码按原树复用且无额外提示", prompts == 1);
        Check("0.2实体链所有必要归档均完成目录与完整性", nodes.Where(node => node.DirectoryRead != ContainerStageStatus.NotRequested)
            .All(node => node.DirectoryRead == ContainerStageStatus.Complete && node.Integrity == ContainerStageStatus.Complete));
        Check("0.2实体链最终内容可追溯至原外层身份", nodes.All(node => node.OriginalTarget == rootFile && node.OriginalTargetSha256 == nodes.FirstOrDefault()?.Sha256));
        Check("0.2实体链没有执行任何提取内容", nodes.Length > 0 && report.Metrics.ProcessesVisited == 0);
        string reportText = await File.ReadAllTextAsync(Path.Combine(output, "scan-report.json"));
        Check("0.2实体链报告不包含夹具密码", !reportText.Contains(publicPassword, StringComparison.Ordinal));
        if (restricted)
        {
            Check("0.2实体链由受限Worker完成", report.WorkerDiagnostics is not null && report.CompletedAtUtc.HasValue);
            if (profile == "Small")
            {
                Check("0.2实体链主动恢复167个非执行名文件与元数据", report.Containers?.Nodes.Count(node => node.RecoveredContentAvailable) == 167 &&
                    Directory.Exists(report.Containers.RecoveryOutputDirectory) &&
                    Directory.EnumerateFiles(report.Containers.RecoveryOutputDirectory!, "*.scan").Count() == 167 &&
                    File.Exists(Path.Combine(report.Containers.RecoveryOutputDirectory!, "evidence.json")));
            }
        }
        ContainerResourceSnapshot resources = report.Containers?.Resources ?? new();
        if (profile == "Large")
        {
            Check("0.2实体大文件超越旧单成员和累计展开边界", new FileInfo(rootFile).Length > 1024L * 1024 * 1024 &&
                nodes.Any(node => node.Kind == ContainerNodeKind.ArchiveMember && node.Length > 1024L * 1024 * 1024) &&
                resources.DecodedBytes > 4L * 1024 * 1024 * 1024 && resources.AcceptedExpandedBytes > 4L * 1024 * 1024 * 1024);
            Check("0.2实体大文件资源有计量且受预算约束", resources.ReadBytes > 0 && resources.PeakTemporaryBytes > 0 &&
                resources.ReadBytes + resources.DecodedBytes + resources.NativeReservedReadBytes + resources.NativeReservedDecodedBytes <= report.Containers!.Limits.MaximumWorkBytes &&
                resources.PeakTemporaryBytes <= report.Containers.Limits.MaximumTemporaryBytes);
        }
        await JsonFile.WriteAtomicAsync(Path.Combine(output, "topology-results.json"), new
        {
            Passed = _passed,
            Failed = Failures.Count,
            Failures,
            MatchedLeaves = matched,
            Profile = profile,
            RestrictedWorker = restricted,
            BuildIdentity = ProductInfo.BuildIdentity,
            ElapsedMilliseconds = elapsed.ElapsedMilliseconds,
            WorkerBuildIdentity = restricted ? report.BuildIdentity : null,
            WorkerPath = workerPath,
            WorkerSha256 = workerPath is null ? null : await Hashing.Sha256FileAsync(workerPath),
            WorkerAssemblySha256 = workerPath is null ? null : await Hashing.Sha256FileAsync(Path.ChangeExtension(workerPath, ".dll")),
            CoreAssemblySha256 = workerPath is null ? null : await Hashing.Sha256FileAsync(Path.Combine(Path.GetDirectoryName(workerPath)!, "SteamSentinel.Core.dll")),
            Resources = resources,
            CompletedAtUtc = DateTimeOffset.UtcNow,
            Safety = "Only generated inert fixture contents were parsed. No SFX, recovered leaf, malware sample or repair action was executed."
        });
        Console.WriteLine($"V020_TOPOLOGY_PASS={_passed};FAIL={Failures.Count};LEAVES={matched};ELAPSED_MS={elapsed.ElapsedMilliseconds}");
        foreach (string failure in Failures) Console.WriteLine("FAIL: " + failure);
        return Failures.Count == 0 ? 0 : 1;
    }

    private sealed class V020PublicFixturePasswordProvider(Func<ArchivePasswordRequest, CancellationToken, Task<ArchivePasswordResponse>> callback) : IArchivePasswordProvider
    {
        public Task<ArchivePasswordResponse> RequestPasswordAsync(ArchivePasswordRequest request, CancellationToken token) => callback(request, token);
    }
    private sealed class V020DirectProgress(Action<ScanProgress> callback) : IProgress<ScanProgress>
    {
        public void Report(ScanProgress value) => callback(value);
    }
}
