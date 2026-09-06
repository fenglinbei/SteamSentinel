using System.Text.Json;
using SteamSentinel.Core.Scanning;
using SteamSentinel.Core.Utilities;

namespace SteamSentinel.Core.Models;

public sealed record ContainerScanMetadata(int TotalNodes, bool Complete, ContainerResourceLimits Limits,
    ContainerResourceSnapshot Resources, List<string> Checks, string? RecoveryOutputDirectory,
    List<ContainerScanRunSummary>? Runs = null);
public sealed record ContainerScanFragment(ContainerScanMetadata Metadata, int Index, ContainerScanNode? Node, bool IsFinal);

internal static class ContainerScanFragments
{
    internal static ContainerScanMetadata Metadata(ContainerScanReport report) =>
        new(report.Nodes.Count, report.Complete, report.Limits, report.Resources, report.Checks, report.RecoveryOutputDirectory, report.Runs);

    internal static void ValidateMetadata(ContainerScanMetadata value)
    {
        if (value is null || value.TotalNodes is < 0 or > ContainerScanReport.MaximumNodes || value.Resources is null || value.Limits is null || value.Checks is null ||
            value.Checks.Count > 512 || value.Checks.Any(s => s is null || s.Length > 2048) || value.RecoveryOutputDirectory?.Length > 32768)
            throw new InvalidDataException("容器记录元数据缺失或超过限制。");
        ContainerResourceBudget.Validate(value.Limits);
        ContainerResourceSnapshot r = value.Resources;
        long workAllowance = value.Limits.MaximumWorkBytes + (value.Complete ? 0 : 128 * 1024);
        if (r.ReadBytes < 0 || r.DecodedBytes < 0 || r.NativeReservedReadBytes < 0 || r.NativeReservedReadBytes > value.Limits.MaximumWorkBytes ||
            r.NativeReservedDecodedBytes < 0 || r.NativeReservedDecodedBytes > value.Limits.MaximumWorkBytes || r.AcceptedExpandedBytes < 0 || r.CurrentTemporaryBytes < 0 || r.RangeCopyBytes < 0 ||
            r.PeakTemporaryBytes < r.CurrentTemporaryBytes || r.PeakPrivateMemoryBytes < 0 || r.MetadataAttempts < 0 ||
            r.PasswordAttempts < 0 || r.ElapsedMilliseconds < 0 || r.ReadBytes > workAllowance ||
            r.DecodedBytes > workAllowance - r.ReadBytes - r.NativeReservedReadBytes - r.NativeReservedDecodedBytes || r.AcceptedExpandedBytes > value.Limits.MaximumExpandedBytes ||
            r.PeakTemporaryBytes > value.Limits.MaximumTemporaryBytes || r.MetadataAttempts > value.Limits.MaximumMetadataAttempts + 1L ||
            r.PasswordAttempts > value.Limits.MaximumPasswordAttempts + 1L)
            throw new InvalidDataException("容器资源计账超出声明范围。");
        if (value.Runs is { } runs)
        {
            if (runs.Count > ContainerScanRunSummary.MaximumRuns || runs.Any(run => run is null) || runs.Select(run => run.ScanId).Distinct().Count() != runs.Count)
                throw new InvalidDataException("容器原始扫描轮次数量过大或身份重复。");
            foreach (ContainerScanRunSummary run in runs)
            {
                if (run is null || run.ScanId == Guid.Empty || !Enum.IsDefined(run.Mode) || run.StartedAtUtc == default ||
                    run.CompletedAtUtc < run.StartedAtUtc || run.Roots is null || run.NodeIds is null ||
                    run.Roots.Count > ContainerScanRunSummary.MaximumRoots || run.NodeIds.Count > ContainerScanReport.MaximumNodes ||
                    run.Roots.Any(path => string.IsNullOrWhiteSpace(path) || path.Length > 32768) ||
                    run.NodeIds.Any(id => id == Guid.Empty) || run.NodeIds.Distinct().Count() != run.NodeIds.Count)
                    throw new InvalidDataException("容器原始扫描轮次字段无效。");
                ValidateMetadata(new(run.NodeIds.Count, run.Complete, run.Limits, run.Resources, [], run.RecoveryOutputDirectory));
            }
        }
        if (JsonSerializer.SerializeToUtf8Bytes(value, JsonFile.Options).Length > 512 * 1024)
            throw new InvalidDataException("容器扫描元数据超过单帧限制。");
    }

    internal static int ValidateNode(ContainerScanNode n)
    {
        if (n is null || n.NodeId == Guid.Empty || n.ParentId == n.NodeId || n.Revision is < 0 or > 1024 || !Enum.IsDefined(n.Kind) ||
            n.Depth is < 0 or >= int.MaxValue || n.Length < 0 || n.ParentOffset < 0 || n.ParentLength < 0 ||
            !Enum.IsDefined(n.Recognition) || !Enum.IsDefined(n.DirectoryRead) || !Enum.IsDefined(n.Decryption) ||
            !Enum.IsDefined(n.Integrity) || !Enum.IsDefined(n.ContentCheck) || !Enum.IsDefined(n.Overall) || !Enum.IsDefined(n.Signature) ||
            n.StartedAtUtc == default || n.CompletedAtUtc < n.StartedAtUtc || n.Volumes is null || n.Engines is null || n.Details is null ||
            n.Engines.Count > 16 || n.Details.Count > 32)
            throw new InvalidDataException("容器节点结构无效。");
        if (n.Overall == ContainerStageStatus.Complete &&
            new[] { n.Recognition, n.DirectoryRead, n.Decryption, n.Integrity, n.ContentCheck }
                .Any(stage => stage is not (ContainerStageStatus.Complete or ContainerStageStatus.NotRequested)))
            throw new InvalidDataException("容器节点存在未完成检查阶段，不能声明全链完成。");
        int characters = 0;
        void Field(string? s, int maximum, bool required = false)
        {
            if (s is null) { if (required) throw new InvalidDataException("容器节点缺少字段。"); return; }
            if (s.Length > maximum || required && string.IsNullOrWhiteSpace(s)) throw new InvalidDataException("容器节点文本超限。");
            characters = checked(characters + s.Length);
        }
        void Hash(string? hash) { if (hash is not null && !Validation.IsHexSha256(hash)) throw new InvalidDataException("容器内容哈希无效。"); }
        Field(n.DisplayPath, 32768, true); Field(n.OriginalTarget, 32768, true); Field(n.Format, 128);
        Field(n.RecoveredContentName, 128); Hash(n.Sha256); Hash(n.OriginalTargetSha256); Hash(n.VolumeGroupSha256);
        foreach (string detail in n.Details) Field(detail, 2048, true);
        foreach (ContainerVolumeIdentity v in n.Volumes)
        {
            if (v is null || v.Length < 0) throw new InvalidDataException("容器分卷身份无效。");
            Field(v.OriginalPath, 32768, true); Field(v.DisplayName, 32768, true); Hash(v.Sha256);
        }
        foreach (ContainerEngineObservation e in n.Engines)
        {
            if (e is null || !Enum.IsDefined(e.Status) || e.Offset < 0 || e.Length < 0) throw new InvalidDataException("内容引擎覆盖记录无效。");
            Field(e.Engine, 128, true); Field(e.Detail, 2048);
        }
        if (characters > 128 * 1024 || JsonSerializer.SerializeToUtf8Bytes(n, JsonFile.Options).Length > 512 * 1024)
            throw new InvalidDataException("容器节点超过单记录限制。");
        return characters;
    }

    internal static void ValidateGraph(IReadOnlyList<ContainerScanNode> nodes)
    {
        Dictionary<Guid, ContainerScanNode> ids = nodes.ToDictionary(n => n.NodeId);
        foreach (ContainerScanNode n in nodes)
        {
            if (n.ParentId is { } parent && (!ids.TryGetValue(parent, out ContainerScanNode? p) || p.Depth >= n.Depth))
                throw new InvalidDataException("容器来源关系缺少父项或形成循环。");
            if (n.ReusedNodeId is { } reused && (reused == n.NodeId || !ids.ContainsKey(reused) || ids[reused].ReusedNodeId.HasValue))
                throw new InvalidDataException("容器复用引用无效。");
        }
    }
}

internal sealed class ContainerScanAssembly
{
    public ContainerScanReport Report { get; } = new();
    public bool IsComplete { get; private set; }
    private long _characters;
    internal PreparedContainerFragment Prepare(ContainerScanFragment f)
    {
        if (f is null || IsComplete) throw new InvalidDataException("容器分片重复结束或缺失。");
        ContainerScanFragments.ValidateMetadata(f.Metadata);
        if (f.Index < 0 || f.Index > Report.Nodes.Count || f.Index > f.Metadata.TotalNodes ||
            f.Node is not null && f.Index >= f.Metadata.TotalNodes || f.IsFinal && f.Node is not null)
            throw new InvalidDataException("容器节点偏移不连续。");
        int length = f.Node is null ? 0 : ContainerScanFragments.ValidateNode(f.Node);
        if (_characters + length > 64L * 1024 * 1024) throw new InvalidDataException("容器分片累计文本超限。");
        if (f.Node is { } n)
        {
            if (f.Index < Report.Nodes.Count)
            {
                ContainerScanNode old = Report.Nodes[f.Index];
                if (old.NodeId != n.NodeId || old.ParentId != n.ParentId || old.Kind != n.Kind || old.DisplayPath != n.DisplayPath ||
                    old.OriginalTarget != n.OriginalTarget || old.Depth != n.Depth || old.Revision >= n.Revision)
                    throw new InvalidDataException("容器节点更新改写了来源身份或版本倒退。");
            }
            else if (Report.Nodes.Any(old => old.NodeId == n.NodeId)) throw new InvalidDataException("容器节点ID重复。");
        }
        if (f.IsFinal)
        {
            if (Report.Nodes.Count != f.Metadata.TotalNodes || f.Index != Report.Nodes.Count)
                throw new InvalidDataException("容器结束帧缺少声明节点。");
            ContainerScanFragments.ValidateGraph(Report.Nodes);
            if (f.Metadata.Runs?.Any(run => run.NodeIds.Any(id => !Report.Nodes.Any(node => node.NodeId == id))) == true)
                throw new InvalidDataException("容器扫描轮次引用了未传输节点。");
            if (f.Metadata.Complete && Report.Nodes.Any(n => n.Overall is not (ContainerStageStatus.Complete or ContainerStageStatus.NotRequested)))
                throw new InvalidDataException("未完成容器不能声明全链完成。");
        }
        else if (f.Node is null) throw new InvalidDataException("容器非结束帧没有节点。");
        return new(f, length);
    }
    internal void Commit(PreparedContainerFragment prepared)
    {
        ContainerScanFragment f = prepared.Fragment;
        if (f.Node is not null)
        {
            if (f.Index == Report.Nodes.Count) Report.Nodes.Add(f.Node); else Report.Nodes[f.Index] = f.Node;
        }
        Report.Limits = f.Metadata.Limits; Report.Resources = f.Metadata.Resources;
        Report.Checks.Clear(); Report.Checks.AddRange(f.Metadata.Checks);
        Report.Runs.Clear(); Report.Runs.AddRange(f.Metadata.Runs ?? []);
        Report.RecoveryOutputDirectory = f.Metadata.RecoveryOutputDirectory;
        Report.Complete = f.IsFinal && f.Metadata.Complete; IsComplete = f.IsFinal; _characters += prepared.Characters;
    }
}
internal sealed record PreparedContainerFragment(ContainerScanFragment Fragment, int Characters);
