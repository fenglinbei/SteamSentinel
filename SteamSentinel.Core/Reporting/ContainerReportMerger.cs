using SteamSentinel.Core.Models;

namespace SteamSentinel.Core.Reporting;

public static class ContainerReportMerger
{
    public static ContainerScanReport? Merge(ScanReport first, ScanReport second)
    {
        if (first.Containers is null) return PreserveOrigin(second);
        if (second.Containers is null) return PreserveOrigin(first);
        ContainerScanReport left = first.Containers, right = second.Containers;
        if (ReferenceEquals(left, right)) return PreserveOrigin(first);
        List<ContainerScanRunSummary> leftRuns = Runs(first), rightRuns = Runs(second);
        ContainerScanReport merged = new()
        {
            // Backward-compatible fields deliberately retain one real round. They are
            // never summed and must not be presented as the aggregate's budget/usage.
            Limits = leftRuns[0].Limits,
            Resources = leftRuns[0].Resources,
            Complete = left.Complete && right.Complete,
            RecoveryOutputDirectory = string.Equals(left.RecoveryOutputDirectory, right.RecoveryOutputDirectory, StringComparison.OrdinalIgnoreCase)
                ? left.RecoveryOutputDirectory : null
        };
        merged.Checks.AddRange(left.Checks.Concat(right.Checks).Distinct(StringComparer.Ordinal));
        Dictionary<Guid, int> indexes = [];
        foreach (ContainerScanNode node in left.Nodes.Concat(right.Nodes))
        {
            if (!indexes.TryGetValue(node.NodeId, out int index))
            { indexes[node.NodeId] = merged.Nodes.Count; merged.Nodes.Add(node); continue; }
            ContainerScanNode previous = merged.Nodes[index];
            if (IdentityConflict(previous, node))
            {
                merged.Complete = false;
                merged.Checks.Add($"合并节点身份冲突 {node.NodeId}：保留先前父链；先前父节点 {previous.ParentId}、来源 {previous.OriginalTarget}、SHA-256 {previous.Sha256}；后续父节点 {node.ParentId}、来源 {node.OriginalTarget}、SHA-256 {node.Sha256}。后续冲突记录未替换可信链。");
            }
            else if (node.Revision > previous.Revision || node.Revision == previous.Revision &&
                (node.CompletedAtUtc ?? DateTimeOffset.MinValue) > (previous.CompletedAtUtc ?? DateTimeOffset.MinValue))
                merged.Nodes[index] = node;
        }
        foreach (IGrouping<Guid, ContainerScanRunSummary> group in leftRuns.Concat(rightRuns).GroupBy(run => run.ScanId))
        {
            ContainerScanRunSummary[] versions = group.ToArray();
            ContainerScanRunSummary latest = versions.OrderBy(run => run.CompletedAtUtc ?? DateTimeOffset.MinValue).ThenBy(run => run.NodeIds.Count).Last();
            merged.Runs.Add(new()
            {
                ScanId = latest.ScanId,
                Mode = latest.Mode,
                StartedAtUtc = versions.Min(run => run.StartedAtUtc),
                CompletedAtUtc = latest.CompletedAtUtc,
                Complete = latest.Complete,
                Roots = versions.SelectMany(run => run.Roots).Distinct(StringComparer.OrdinalIgnoreCase).ToList(),
                NodeIds = versions.SelectMany(run => run.NodeIds).Distinct().ToList(),
                Limits = latest.Limits,
                Resources = latest.Resources,
                RecoveryOutputDirectory = latest.RecoveryOutputDirectory
            });
        }
        if (merged.Runs.Count > ContainerScanRunSummary.MaximumRuns || merged.Runs.Any(run => run.NodeIds.Count > ContainerScanReport.MaximumNodes || run.Roots.Count > ContainerScanRunSummary.MaximumRoots))
        {
            // Preserve source evidence rather than silently trim it. Such an abnormal
            // local aggregate is partial and must not be sent as a worker fragment.
            merged.Complete = false;
            merged.Checks.Add("本地合并结果超过64轮、节点数或512根路径的传输格式上限；已保留原始节点与分轮摘要，合并结果仅能作为部分检查记录，不能再作为Worker分片发送。");
        }
        if (merged.Nodes.Any(node => node.ParentId is Guid parent && !indexes.ContainsKey(parent)))
        { merged.Complete = false; merged.Checks.Add("合并图有未取得的父节点；保留原 ParentId，缺失父层未重建或推断。"); }
        if (merged.Nodes.Any(node => node.ReusedNodeId is Guid reused && !indexes.ContainsKey(reused)))
        { merged.Complete = false; merged.Checks.Add("合并图缺少所引用的已检查内容节点；保留复用ID，该关系尚不完整。"); }
        merged.Complete &= merged.Nodes.All(ContainerReportPresentation.NodeComplete) && merged.Runs.All(run => run.Complete);
        const string accounting = "多个独立扫描轮次已合并；每轮身份、原始预算与实际计量分别保存在 Runs，不能把合计读取量解释为受同一个读取上限约束。顶层 Resources/Limits 仅保留首轮兼容值。";
        if (!merged.Checks.Contains(accounting, StringComparer.Ordinal)) merged.Checks.Add(accounting);
        if (merged.Checks.Count > 512 || merged.Checks.Any(check => check.Length > 2048))
        {
            merged.Complete = false;
            merged.Checks.Add("合并检查说明超过512条或单条2048字的传输上限；未删除原说明，合并结果为部分检查记录，不能作为Worker分片发送。");
        }
        return merged;
    }

    private static ContainerScanReport? PreserveOrigin(ScanReport report)
    {
        ContainerScanReport? containers = report.Containers;
        // The same container object is retained. Register its original round before an
        // enclosing ScanReport receives a new ID, so later merges retain provenance.
        if (containers is not null && containers.Runs.Count == 0) containers.Runs.Add(Capture(report, containers));
        return containers;
    }

    private static List<ContainerScanRunSummary> Runs(ScanReport report) => report.Containers!.Runs.Count > 0
        ? [.. report.Containers.Runs] : [Capture(report, report.Containers)];

    private static ContainerScanRunSummary Capture(ScanReport report, ContainerScanReport containers) => new()
    {
        ScanId = report.ScanId,
        Mode = report.Mode,
        StartedAtUtc = report.StartedAtUtc,
        CompletedAtUtc = report.CompletedAtUtc,
        Complete = containers.Complete,
        Roots = report.Roots.Concat(report.ContentScanSettings?.CustomRoots ?? []).Distinct(StringComparer.OrdinalIgnoreCase).ToList(),
        NodeIds = containers.Nodes.Select(node => node.NodeId).Distinct().ToList(),
        Limits = containers.Limits,
        Resources = containers.Resources,
        RecoveryOutputDirectory = containers.RecoveryOutputDirectory
    };

    private static bool IdentityConflict(ContainerScanNode left, ContainerScanNode right) => left.ParentId != right.ParentId || left.Depth != right.Depth ||
        !string.Equals(left.OriginalTarget, right.OriginalTarget, StringComparison.OrdinalIgnoreCase) ||
        !string.Equals(left.DisplayPath, right.DisplayPath, StringComparison.Ordinal) ||
        Different(left.Sha256, right.Sha256) || Different(left.OriginalTargetSha256, right.OriginalTargetSha256) ||
        Different(left.VolumeGroupSha256, right.VolumeGroupSha256) ||
        left.ParentOffset.HasValue && right.ParentOffset.HasValue && left.ParentOffset != right.ParentOffset ||
        left.ParentLength.HasValue && right.ParentLength.HasValue && left.ParentLength != right.ParentLength ||
        left.ReusedNodeId.HasValue && right.ReusedNodeId.HasValue && left.ReusedNodeId != right.ReusedNodeId;
    private static bool Different(string? left, string? right) => left is not null && right is not null && !left.Equals(right, StringComparison.OrdinalIgnoreCase);
}
