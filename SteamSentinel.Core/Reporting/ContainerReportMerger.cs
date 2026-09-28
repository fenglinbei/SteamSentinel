using SteamSentinel.Core.Reporting;
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
        foreach (MessageText check in left.CheckTexts.Concat(right.CheckTexts).DistinctBy(check => check.OriginalText)) merged.AddCheck(check);
        Dictionary<Guid, int> indexes = [];
        foreach (ContainerScanNode node in left.Nodes.Concat(right.Nodes))
        {
            if (!indexes.TryGetValue(node.NodeId, out int index))
            { indexes[node.NodeId] = merged.Nodes.Count; merged.Nodes.Add(node); continue; }
            ContainerScanNode previous = merged.Nodes[index];
            if (IdentityConflict(previous, node))
            {
                merged.Complete = false;
                merged.AddCheck(MessageText.Create("Backend.Core.ContainerReportMerger.Merge.01", (node.NodeId), (previous.ParentId), (previous.OriginalTarget), (previous.Sha256), (node.ParentId), (node.OriginalTarget), (node.Sha256)));
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
            merged.AddCheck(MessageText.Create("Backend.Core.ContainerReportMerger.Merge.02"));
        }
        if (merged.Nodes.Any(node => node.ParentId is Guid parent && !indexes.ContainsKey(parent)))
        { merged.Complete = false; merged.AddCheck(MessageText.Create("Backend.Core.ContainerReportMerger.Merge.03")); }
        if (merged.Nodes.Any(node => node.ReusedNodeId is Guid reused && !indexes.ContainsKey(reused)))
        { merged.Complete = false; merged.AddCheck(MessageText.Create("Backend.Core.ContainerReportMerger.Merge.04")); }
        merged.Complete &= merged.Nodes.All(ContainerReportPresentation.NodeComplete) && merged.Runs.All(run => run.Complete);
        MessageText accounting = MessageText.Create("Backend.Core.ContainerReportMerger.Merge.05");
        if (!merged.Checks.Contains(accounting.OriginalText, StringComparer.Ordinal)) merged.AddCheck(accounting);
        if (merged.Checks.Count > 512 || merged.Checks.Any(check => check.Length > 2048))
        {
            merged.Complete = false;
            merged.AddCheck(MessageText.Create("Backend.Core.ContainerReportMerger.Merge.06"));
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
