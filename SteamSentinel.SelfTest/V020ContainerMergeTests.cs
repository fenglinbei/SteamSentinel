using System.IO;
using System.Text.Json;
using SteamSentinel.Core.Models;
using SteamSentinel.Core.Reporting;
using SteamSentinel.Core.Rules;
using SteamSentinel.Core.Scanning;
using SteamSentinel.Core.Utilities;

namespace SteamSentinel.SelfTest;

internal static partial class Program
{
    private static async Task TestV020ContainerMergesAsync(string root)
    {
        ScanReport first = V020MergeFixture(1, 1024, 1024 * 1024), second = V020MergeFixture(2, 2048, 2 * 1024 * 1024);
        ScanReport main = ScanReportMerger.Merge(new() { Mode = ScanMode.Full }, first);
        Check("0.2容器合并 单侧有容器时保留对象与原扫描身份", ReferenceEquals(main.Containers, first.Containers) &&
            main.Containers!.Runs.Single().ScanId == first.ScanId);
        ScanReport rightEmpty = ScanReportMerger.Merge(second, new());
        Check("0.2容器合并 另一侧为空也保留容器节点", ReferenceEquals(rightEmpty.Containers, second.Containers) && rightEmpty.Containers!.Nodes.Count == 2);
        ScanReport both = ScanReportMerger.Merge(main, second);
        ContainerScanReport merged = both.Containers!;
        Check("0.2容器合并 两侧完整父图和节点身份都保留", merged.Nodes.Count == 4 && merged.Nodes.Count(node => node.ParentId is null) == 2 &&
            merged.Nodes.Where(node => node.ParentId.HasValue).All(node => merged.Nodes.Any(parent => parent.NodeId == node.ParentId)) &&
            first.Containers!.Nodes.All(node => ReferenceEquals(merged.Nodes.Single(found => found.NodeId == node.NodeId), node)));
        Check("0.2容器合并 不将两轮读取与限额折成一个总预算", merged.Runs.Count == 2 && merged.Runs[0].ScanId == first.ScanId && merged.Runs[1].ScanId == second.ScanId &&
            merged.Runs[0].Resources.ReadBytes == 1024 && merged.Runs[1].Resources.ReadBytes == 2048 &&
            merged.Runs[0].Limits.MaximumWorkBytes == 1024 * 1024 && merged.Runs[1].Limits.MaximumWorkBytes == 2 * 1024 * 1024 &&
            merged.Resources.ReadBytes == 1024 && merged.Limits.MaximumWorkBytes == 1024 * 1024);
        string rendered = ContainerReportPresentation.Describe(merged);
        Check("0.2容器合并 展示逐轮开始结束根路径与独立计量", rendered.Contains(first.ScanId.ToString(), StringComparison.Ordinal) &&
            rendered.Contains(second.ScanId.ToString(), StringComparison.Ordinal) && rendered.Contains("每轮预算分别适用", StringComparison.Ordinal) &&
            merged.Runs.All(run => run.Roots.Count == 1 && run.NodeIds.Count == 2 && run.CompletedAtUtc.HasValue));
        ScanReport twice = ScanReportMerger.Merge(both, first);
        Check("0.2容器合并 相同报告重复合并不会重复节点或轮次", twice.Containers!.Nodes.Count == 4 && twice.Containers.Runs.Count == 2);
        ScanReport third = V020MergeFixture(3, 4096, 3 * 1024 * 1024);
        ScanReport three = ScanReportMerger.Merge(twice, third);
        Check("0.2容器合并 已合并报告再补查仍保留原始三个ScanId", three.Containers!.Runs.Select(run => run.ScanId).ToHashSet().SetEquals([first.ScanId, second.ScanId, third.ScanId]) &&
            three.Containers.Nodes.Count == 6 && three.Containers.Runs.All(run => run.ScanId != both.ScanId));
        string serialized = JsonSerializer.Serialize(three, JsonFile.Options);
        ScanReport restored = JsonSerializer.Deserialize<ScanReport>(serialized, JsonFile.Options)!;
        Check("0.2容器合并 JSON往返保留每轮原始资源与节点对应关系", restored.Containers!.Runs.Count == 3 && restored.Containers.Runs[2].Resources.ReadBytes == 4096 &&
            restored.Containers.Runs.All(run => run.NodeIds.All(id => restored.Containers.Nodes.Any(node => node.NodeId == id))));

        ScanReport revision = JsonSerializer.Deserialize<ScanReport>(JsonSerializer.Serialize(first, JsonFile.Options), JsonFile.Options)!;
        revision.Containers!.Nodes[1].Revision = 10; revision.Containers.Nodes[1].Details.Add("inert later checkpoint");
        ContainerScanReport revised = ContainerReportMerger.Merge(first, revision)!;
        Check("0.2容器合并 同ID相同身份只保留较新修订", revised.Nodes.Count == 2 && revised.Nodes.Single(node => node.ParentId.HasValue).Revision == 10 &&
            revised.Nodes.Single(node => node.ParentId.HasValue).Details.Contains("inert later checkpoint"));
        ScanReport conflict = JsonSerializer.Deserialize<ScanReport>(JsonSerializer.Serialize(first, JsonFile.Options), JsonFile.Options)!;
        conflict.Containers!.Nodes[1].Sha256 = new string('F', 64); conflict.Containers.Nodes[1].Revision = 20;
        ScanReport conflicted = ScanReportMerger.Merge(first, conflict);
        Check("0.2容器合并 同ID身份冲突不能改写先前父链", !conflicted.Containers!.Complete && conflicted.Coverage == ScanCoverage.Partial &&
            conflicted.Containers.Nodes[1].Sha256 == first.Containers!.Nodes[1].Sha256 && conflicted.Containers.Nodes[1].ParentId == first.Containers.Nodes[1].ParentId &&
            conflicted.Containers.Checks.Any(check => check.Contains("身份冲突", StringComparison.Ordinal)));
        ScanReport tooMany = V020MergeFixture(4, 1, 1024);
        for (int i = 0; i < 65; i++) tooMany.Containers!.Runs.Add(new() { ScanId = Guid.NewGuid(), Complete = true, NodeIds = tooMany.Containers.Nodes.Select(node => node.NodeId).ToList() });
        ContainerScanReport over = ContainerReportMerger.Merge(tooMany, second)!;
        Check("0.2容器合并 超出轮次传输限额保留证据并明确Partial", !over.Complete && over.Runs.Count == 66 && over.Nodes.Count == 4 &&
            over.Checks.Any(check => check.Contains("超过64轮", StringComparison.Ordinal)));

        const long mib = 1024 * 1024;
        ScanOptions preference = new()
        {
            Mode = ScanMode.Custom,
            InspectDeepSignatures = false,
            RecoveryOutputDirectory = @"C:\Inert\old-recovery",
            SupplementalVolumeDirectories = [@"C:\Inert\explicit-volumes"],
            ContainerLimits = new()
            {
                MaximumEntryBytes = 8 * mib,
                MaximumExpandedBytes = 16 * mib,
                MaximumWorkBytes = 24 * mib,
                MaximumTemporaryBytes = 8 * mib,
                MaximumDepth = 3,
                MaximumEntries = 100,
                MaximumMetadataAttempts = 1000,
                MaximumPasswordAttempts = 8,
                MaximumDurationSeconds = 20
            }
        };
        ScanOptions bounded = RelatedComponentPipeline.FollowUpOptions(preference, [@"C:\Inert\outer.rar"], 12 * mib);
        Check("0.2关联补查 显式窄容器预算受剩余关联预算和原偏好共同约束", bounded.ContainerLimits is { } limits && limits.MaximumWorkBytes == 12 * mib &&
            limits.MaximumEntryBytes == 6 * mib && limits.MaximumExpandedBytes == 6 * mib && limits.MaximumTemporaryBytes == 8 * mib && limits.MaximumDepth == 3 &&
            limits.MaximumEntries == 100 && limits.MaximumPasswordAttempts == 8 && limits.MaximumDurationSeconds == 20);
        Check("0.2关联补查 保留补卷目录签名偏好且禁止继承恢复写出", !bounded.InspectDeepSignatures && bounded.RecoveryOutputDirectory is null &&
            bounded.SupplementalVolumeDirectories.SequenceEqual(preference.SupplementalVolumeDirectories) && !ReferenceEquals(bounded.SupplementalVolumeDirectories, preference.SupplementalVolumeDirectories));
        bool tinyRejected = false;
        try { _ = RelatedComponentPipeline.FollowUpOptions(preference, [], 1); } catch (ArgumentOutOfRangeException) { tinyRejected = true; }
        Check("0.2关联补查 无可分配读取展开预算时不能回退64GiB默认", tinyRejected);

        string directory = Path.Combine(root, "v020-merge-pipeline-" + Guid.NewGuid().ToString("N")); Directory.CreateDirectory(directory);
        string candidate = Path.Combine(directory, "inert-candidate.txt"); await File.WriteAllTextAsync(candidate, "Inert read-only metadata merge fixture.");
        ScanReport pipelineReport = V020MergeFixture(5, 100, 1024 * 1024);
        Guid originalScanId = pipelineReport.ScanId;
        pipelineReport.RelatedComponentDiagnostics = new() { TargetUserSid = "S-1-5-21-1-2-3-1001", Candidates = [new() { Path = candidate, Reason = "inert explicit candidate" }] };
        ScanOptions original = new() { Mode = ScanMode.Full, IncludeSystem = false, InspectDeepSignatures = false };
        RelatedComponentPipeline pipeline = new(RuleLoader.LoadEmbedded(), (_, _, _, _) => { }, () => "S-1-5-21-1-2-3-1001", (_, _, _, _) => Task.FromResult(new RelatedArtifactExpansion([], [], [])));
        Guid workerScanId = Guid.Empty;
        await pipeline.CompleteAsync(pipelineReport, original, (options, _, _) =>
        {
            ScanReport content = V020MergeFixture(6, 333, 512 * 1024); workerScanId = content.ScanId;
            content.RootSummaries.Add(new(candidate, ScanCoverage.Complete, 0, 0, 1));
            return Task.FromResult(content);
        });
        Check("0.2关联补查 AppendContent保留主扫描与补查所有容器轮", pipelineReport.Containers!.Nodes.Count == 4 &&
            pipelineReport.Containers.Runs.Select(run => run.ScanId).ToHashSet().SetEquals([originalScanId, workerScanId]) &&
            pipelineReport.Containers.Runs.Single(run => run.ScanId == workerScanId).Resources.ReadBytes == 333);
        ScanReport skipped = new() { RelatedComponentDiagnostics = new() { TargetUserSid = "S-1-5-21-1-2-3-1001", Candidates = [new() { Path = candidate }] } };
        await pipeline.CompleteAsync(skipped, original, (_, _, _) => throw new InvalidOperationException("Tiny budget must not start a worker."), limits: new() { MaximumTotalBytes = 1 });
        Check("0.2关联补查 大目标预算缺口提供原始外层补查路径", skipped.Coverage == ScanCoverage.Partial &&
            skipped.Findings.Any(f => f.Category == FindingCategory.Coverage && f.RuleId == "CONTENT-BYTE-BUDGET" && f.Target == candidate && !f.CanRemediate) &&
            CoveragePresentation.Groups(skipped).Any(group => group.CanFullScan && group.Entries.Any(entry => entry.Target == candidate)));
    }

    private static ScanReport V020MergeFixture(int key, long readBytes, long workLimit)
    {
        Guid id = Guid.NewGuid();
        DateTimeOffset started = new(2026, 9, 6, 8, key, 0, TimeSpan.Zero);
        string path = $@"C:\Inert\run-{key}\outer.rar";
        ContainerScanNode outer = new()
        {
            NodeId = id,
            Kind = ContainerNodeKind.File,
            DisplayPath = path,
            OriginalTarget = path,
            Format = "RAR5",
            Length = 100,
            Sha256 = new string('A', 64),
            OriginalTargetSha256 = new string('A', 64),
            Recognition = ContainerStageStatus.Complete,
            DirectoryRead = ContainerStageStatus.Complete,
            Decryption = ContainerStageStatus.NotRequested,
            Integrity = ContainerStageStatus.Complete,
            ContentCheck = ContainerStageStatus.Complete,
            Overall = ContainerStageStatus.Complete,
            StartedAtUtc = started,
            CompletedAtUtc = started.AddSeconds(1)
        };
        ContainerScanNode child = new()
        {
            ParentId = id,
            Kind = ContainerNodeKind.ArchiveMember,
            DisplayPath = path + "::inert.txt",
            OriginalTarget = path,
            Format = "Text",
            Length = 12,
            Depth = 1,
            Sha256 = new string('B', 64),
            OriginalTargetSha256 = new string('A', 64),
            Recognition = ContainerStageStatus.Complete,
            DirectoryRead = ContainerStageStatus.NotRequested,
            Decryption = ContainerStageStatus.NotRequested,
            Integrity = ContainerStageStatus.Complete,
            ContentCheck = ContainerStageStatus.Complete,
            Overall = ContainerStageStatus.Complete,
            StartedAtUtc = started,
            CompletedAtUtc = started.AddSeconds(1)
        };
        return new()
        {
            Mode = ScanMode.Custom,
            StartedAtUtc = started,
            CompletedAtUtc = started.AddSeconds(2),
            Roots = [path],
            Containers = new() { Complete = true, Nodes = [outer, child], Resources = new() { ReadBytes = readBytes }, Limits = new() { MaximumWorkBytes = workLimit } }
        };
    }
}
