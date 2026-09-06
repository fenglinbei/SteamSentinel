using System.Globalization;
using System.Text;
using SteamSentinel.Core.Inspection;
using SteamSentinel.Core.Models;

namespace SteamSentinel.Core.Reporting;

/// <summary>Metadata-only presentation shared by the read-only UI and report export.</summary>
public static class ContainerReportPresentation
{
    public static string Summary(ContainerScanReport? report)
    {
        if (report is null) return "尚无容器递归检查记录";
        int complete = report.Nodes.Count(NodeComplete);
        bool finished = report.Complete && report.Nodes.Count > 0 && complete == report.Nodes.Count;
        return $"容器节点 {report.Nodes.Count:N0} · 阶段完成 {complete:N0} · {(finished ? "本次容器检查已完成" : "仍有未完成或未知内容")}";
    }

    public static string Describe(ContainerScanReport report, Guid? selectedNodeId = null)
    {
        ArgumentNullException.ThrowIfNull(report);
        StringBuilder text = new();
        text.AppendLine(Summary(report));
        text.AppendLine("范围完成、密码正确、成员完整、内容检测和数字签名是不同结果；任一阶段完成都不单独证明内容安全。");
        text.AppendLine("只展示容器关系与检查元数据；不启动 SFX，不执行注释命令，普通报告不包含样本或密码。");
        text.AppendLine();
        if (report.Runs.Count == 0) AppendResources(text, report.Resources, report.Limits, report.RecoveryOutputDirectory);
        else
        {
            text.AppendLine($"独立扫描轮次：{report.Runs.Count:N0}；每轮预算分别适用，不将多轮合计解释为同一个64GiB限额。");
            foreach (ContainerScanRunSummary run in report.Runs)
            {
                text.AppendLine($"扫描轮 {run.ScanId} · {run.Mode} · {(run.Complete ? "该轮容器检查完成" : "该轮仍有未完成内容")}");
                text.AppendLine($"  开始 {run.StartedAtUtc:O}；结束 {run.CompletedAtUtc?.ToString("O") ?? "未完成"}；节点 {run.NodeIds.Count:N0}");
                foreach (string root in run.Roots) text.AppendLine("  该轮原始范围：" + root);
                AppendResources(text, run.Resources, run.Limits, run.RecoveryOutputDirectory);
                text.AppendLine();
            }
        }
        foreach (string check in report.Checks) text.AppendLine("本轮说明：" + check);
        text.AppendLine();
        if (selectedNodeId.HasValue)
        {
            ContainerScanNode? selected = report.Nodes.FirstOrDefault(x => x.NodeId == selectedNodeId.Value);
            if (selected is null) text.AppendLine("所选节点已不在当前报告中，请重新选择。");
            else
            {
                text.AppendLine("容器层级（原始外层 → 所选内容）");
                foreach (ContainerScanNode node in Ancestors(report, selected))
                    text.AppendLine($"  {node.Format} · {node.DisplayPath} [{StatusLabel(node.Overall)}]");
                text.AppendLine(); AppendNode(text, selected);
            }
        }
        else foreach (ContainerScanNode node in report.Nodes) { AppendNode(text, node); text.AppendLine(); }
        return ScriptSignals.RedactSecrets(text.ToString());
    }

    public static IReadOnlyList<ContainerScanNode> Ancestors(ContainerScanReport report, ContainerScanNode selected)
    {
        Dictionary<Guid, ContainerScanNode> byId = report.Nodes.GroupBy(x => x.NodeId).ToDictionary(x => x.Key, x => x.First());
        List<ContainerScanNode> chain = [];
        HashSet<Guid> visited = [];
        ContainerScanNode? node = selected;
        while (node is not null && visited.Add(node.NodeId) && chain.Count < 64)
        {
            chain.Add(node);
            node = node.ParentId is Guid parent && byId.TryGetValue(parent, out ContainerScanNode? value) ? value : null;
        }
        chain.Reverse(); return chain;
    }

    public static bool NodeComplete(ContainerScanNode node) => node.Overall == ContainerStageStatus.Complete &&
        new[] { node.Recognition, node.DirectoryRead, node.Decryption, node.Integrity, node.ContentCheck }
            .All(x => x is ContainerStageStatus.Complete or ContainerStageStatus.NotRequested);

    private static void AppendResources(StringBuilder text, ContainerResourceSnapshot usage, ContainerResourceLimits limits, string? recoveryOutputDirectory)
    {
        decimal work = (decimal)usage.ReadBytes + usage.DecodedBytes;
        text.AppendLine("本轮预算与已发生工作");
        text.AppendLine($"  读取 {Bytes(usage.ReadBytes)}；解码 {Bytes(usage.DecodedBytes)}；已观测读取与解码合计 {Bytes(work)}");
        text.AppendLine($"  原生接口预留读取预算 {Bytes(usage.NativeReservedReadBytes)}，预留解码预算 {Bytes(usage.NativeReservedDecodedBytes)}（保守预留，单独记录，不是已观测的物理读取量）");
        text.AppendLine($"  工作预算占用（含原生预留）{Bytes(work + usage.NativeReservedReadBytes + usage.NativeReservedDecodedBytes)} / {Bytes(limits.MaximumWorkBytes)}");
        text.AppendLine($"  已接受展开 {Bytes(usage.AcceptedExpandedBytes)} / {Bytes(limits.MaximumExpandedBytes)}；单条上限 {Bytes(limits.MaximumEntryBytes)}");
        text.AppendLine($"  范围复制 {Bytes(usage.RangeCopyBytes)}；当前临时占用 {Bytes(usage.CurrentTemporaryBytes)}；峰值 {Bytes(usage.PeakTemporaryBytes)} / {Bytes(limits.MaximumTemporaryBytes)}");
        text.AppendLine($"  保留磁盘空间 {Bytes(limits.ReservedDiskBytes)}；进程私有内存峰值 {Bytes(usage.PeakPrivateMemoryBytes)}");
        text.AppendLine($"  元数据尝试 {usage.MetadataAttempts:N0} / {limits.MaximumMetadataAttempts:N0}；密码尝试 {usage.PasswordAttempts:N0} / {limits.MaximumPasswordAttempts:N0}");
        text.AppendLine($"  深度上限 {limits.MaximumDepth}；条目上限 {limits.MaximumEntries:N0}；卷数上限 {limits.MaximumVolumes}；目录候选上限 {limits.MaximumDirectoryCandidates:N0}；压缩比上限 {limits.MaximumCompressionRatio.ToString("0.##", CultureInfo.InvariantCulture)}");
        text.AppendLine($"  经过 {Math.Max(0, usage.ElapsedMilliseconds) / 1000m:N1} 秒 / {limits.MaximumDurationSeconds:N0} 秒");
        text.AppendLine("  读取数表示交给扫描器/解码器的流字节，含重复读取；不是操作系统物理 I/O。失败密码的已发生读取和解码仍计入预算。");
        text.AppendLine(recoveryOutputDirectory is { Length: > 0 } output
            ? "  本轮明确选择的恢复输出目录：" + output + "；具体输出是否成功以节点记录为准。"
            : "  本轮未请求写出恢复内容；普通报告仅保存元数据。");
    }

    private static void AppendNode(StringBuilder text, ContainerScanNode node)
    {
        text.AppendLine($"节点：{node.DisplayPath}");
        text.AppendLine($"  ID：{node.NodeId}；父节点：{node.ParentId?.ToString() ?? "无（原始外层）"}；修订：{node.Revision}");
        text.AppendLine($"  类型：{KindLabel(node.Kind)}；格式：{(string.IsNullOrWhiteSpace(node.Format) ? "未识别" : node.Format)}；深度：{node.Depth}；长度：{Bytes(node.Length)}");
        if (node.ParentOffset.HasValue || node.ParentLength.HasValue)
            text.AppendLine($"  父容器字节范围：偏移 {node.ParentOffset?.ToString(CultureInfo.InvariantCulture) ?? "未知"}；长度 {node.ParentLength?.ToString(CultureInfo.InvariantCulture) ?? "未知"}");
        text.AppendLine($"  原始外层目标：{node.OriginalTarget}");
        text.AppendLine($"  原始外层 SHA-256：{node.OriginalTargetSha256 ?? "未取得"}");
        text.AppendLine($"  当前节点 SHA-256：{node.Sha256 ?? "未取得"}");
        if (node.VolumeGroupSha256 is { } groupHash) text.AppendLine("  有序分卷组 SHA-256：" + groupHash);
        if (node.ReusedNodeId is Guid reused) text.AppendLine("  复用的已检查内容节点：" + reused + "；这是同内容关系，当前原始来源和父链仍单独保留。");
        text.AppendLine("  五阶段：识别 " + StatusLabel(node.Recognition) + " → 目录 " + StatusLabel(node.DirectoryRead) +
            " → 解密 " + StatusLabel(node.Decryption) + " → 完整性 " + StatusLabel(node.Integrity) + " → 内容检测 " + StatusLabel(node.ContentCheck));
        text.AppendLine("  总体覆盖：" + StatusLabel(node.Overall) + (node.Overall == ContainerStageStatus.Complete && !NodeComplete(node) ? "（阶段状态仍存在缺口，不能视作完成）" : string.Empty));
        text.AppendLine("  文件数字签名：" + SignatureLabel(node.Signature) +
            (node.SignatureCheckedAtUtc is { } checkedAt ? $"；检查时间 {checkedAt:O}" : string.Empty));
        text.AppendLine("  签名状态与恶意性独立；未签名不等于恶意，有效签名也不保证安全。离线信任缺口不当作哈希损坏。");
        text.AppendLine($"  开始 {node.StartedAtUtc:O}；结束 {node.CompletedAtUtc?.ToString("O") ?? "未完成"}");
        if (node.Volumes.Count > 0)
        {
            text.AppendLine("  原始卷组身份：");
            foreach (ContainerVolumeIdentity volume in node.Volumes)
                text.AppendLine($"    {volume.DisplayName} · {volume.OriginalPath} · {Bytes(volume.Length)} · SHA-256 {volume.Sha256} · {(volume.IsTemporary ? "临时表示，不是原始补查目标" : "原始卷")}");
        }
        foreach (ContainerEngineObservation engine in node.Engines)
        {
            text.AppendLine($"  引擎 {engine.Engine}：{StatusLabel(engine.Status)}；偏移 {engine.Offset?.ToString(CultureInfo.InvariantCulture) ?? "未提供"}；长度 {engine.Length?.ToString(CultureInfo.InvariantCulture) ?? "未提供"}");
            text.AppendLine("    " + engine.Detail);
        }
        foreach (string detail in node.Details) text.AppendLine("  说明：" + detail);
        if (node.RecoveredContentAvailable || node.RecoveredContentName is not null)
            text.AppendLine("  恢复内容记录：" + (node.RecoveredContentName ?? "未提供名称") +
                (node.RecoveredContentAvailable ? "；本轮有可用恢复表示，写出情况以本轮目录及说明为准。" : "；当前没有可用恢复表示。"));
    }

    public static string StatusLabel(ContainerStageStatus status) => status switch
    {
        ContainerStageStatus.NotRequested => "本节点不适用/未请求",
        ContainerStageStatus.Pending => "尚未完成",
        ContainerStageStatus.Complete => "完成",
        ContainerStageStatus.Partial => "部分完成",
        ContainerStageStatus.PasswordRequired => "需要密码",
        ContainerStageStatus.PasswordFailed => "密码未通过",
        ContainerStageStatus.Skipped => "已跳过",
        ContainerStageStatus.MissingVolume => "缺少分卷",
        ContainerStageStatus.MixedVolumes => "分卷身份混杂",
        ContainerStageStatus.DuplicateVolume => "分卷重复",
        ContainerStageStatus.Corrupt => "结构或完整性损坏",
        ContainerStageStatus.Unsupported => "格式/方法暂不支持",
        ContainerStageStatus.UnsupportedIntegrity => "完整性算法暂不支持",
        ContainerStageStatus.LimitReached => "达到资源上限",
        ContainerStageStatus.AccessDenied => "无法读取（权限）",
        ContainerStageStatus.SourceChanged => "原始来源已变化",
        ContainerStageStatus.Cancelled => "已取消",
        ContainerStageStatus.Failed => "检查失败",
        _ => "未知状态"
    };
    public static string SignatureLabel(ContentSignatureStatus status) => status switch
    {
        ContentSignatureStatus.NotChecked => "未检查",
        ContentSignatureStatus.Valid => "离线检查有效",
        ContentSignatureStatus.NotSigned => "未签名",
        ContentSignatureStatus.HashMismatch => "签名内容哈希不匹配",
        ContentSignatureStatus.Untrusted => "离线信任未通过/无法确认",
        ContentSignatureStatus.Unavailable => "当前无法检查",
        ContentSignatureStatus.Failed => "签名检查失败",
        _ => "未知状态"
    };
    private static string KindLabel(ContainerNodeKind kind) => kind switch
    {
        ContainerNodeKind.File => "原始文件",
        ContainerNodeKind.EmbeddedRange => "嵌入字节范围",
        ContainerNodeKind.ArchiveMember => "归档成员",
        ContainerNodeKind.VolumeGroup => "分卷组",
        ContainerNodeKind.UnknownRange => "未知字节范围",
        _ => "未知"
    };
    private static string Bytes(decimal bytes) => bytes >= 1024m * 1024 * 1024
        ? $"{bytes / (1024m * 1024 * 1024):N2} GiB（{bytes:N0} 字节）"
        : bytes >= 1024m * 1024 ? $"{bytes / (1024m * 1024):N2} MiB（{bytes:N0} 字节）" : $"{bytes:N0} 字节";
}
