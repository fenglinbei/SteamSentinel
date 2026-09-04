using SteamSentinel.Core.Models;

namespace SteamSentinel.Core.Reporting;

public sealed record CoverageEntry(string Kind, string Target, string Detail, string NextStep, bool CanFullScan)
{
    public long Count { get; init; } = 1;
}
public sealed record CoverageGroup(string Kind, long Count, string NextStep, bool CanFullScan, IReadOnlyList<CoverageEntry> Entries)
{
    public string Details => string.Join(Environment.NewLine + Environment.NewLine,
        Entries.Select(e => $"{e.Target}\n{e.Detail}"));
}

/// <summary>Coverage is not a threat. Legacy coverage findings remain in JSON for worker and retry compatibility.</summary>
public static class CoveragePresentation
{
    public const string FullScanAction = "使用完整内容扫描以覆盖此项";
    public const string QuickScope = "内容快速检查优先检查启动型文件，MP4 先检查真实格式、媒体结构与尾随数据，不逐字节比对正常视频。具体路径以本次所选工坊、MOD、插件、关联落点或自定义位置为准，不是全盘扫描。";
    public const string FullScope = "完整内容扫描对同一范围进行文件哈希比对与已支持的压缩内容检查，耗时更长。加密内容需要正确密码，损坏文件、访问受限内容和安全上限仍可能无法覆盖。";

    public static IReadOnlyList<CoverageGroup> Groups(ScanReport report)
    {
        List<CoverageEntry> entries = [];
        HashSet<string> described = new(StringComparer.Ordinal);
        foreach (Finding f in report.Findings.Where(f => f.Category == FindingCategory.Coverage))
        {
            described.Add(f.Description);
            entries.Add(Describe(f.RuleId, f.Target, f.Description + (string.IsNullOrWhiteSpace(f.Evidence) ? "" : "\n" + f.Evidence)));
        }
        foreach (string note in report.CoverageNotes.Distinct().Where(n => !described.Contains(n)))
            entries.Add(Describe("", "本次扫描", note));
        foreach (CoverageAggregate aggregate in report.CoverageAggregates)
        {
            string reason = aggregate.RuleId switch
            {
                "QUICK-MEDIA-STRUCTURE" => "已检查 MP4 格式、顶层结构和尾随数据，未读取全部媒体数据进行哈希比对。",
                "QUICK-FILE-SIZE" => "快速扫描文件超过 256 MiB，未完整读取，已进行真实格式识别及适用的媒体结构检查。",
                "CONTENT-BYTE-BUDGET" => "文件超过本次剩余读取预算，未完整读取，已进行真实格式识别及适用的媒体结构检查。",
                _ => aggregate.RuleId
            };
            string detail = $"{reason} 此根路径内累计 {aggregate.Count:N0} 次覆盖缺口（不是去重文件数）。" +
                "补查须重新扫描整个根路径，示例不是完整清单，长示例可能截短。" +
                (aggregate.Examples.Count == 0 ? "" : "\n路径示例：\n" + string.Join("\n", aggregate.Examples));
            entries.Add(Describe(aggregate.RuleId, aggregate.Root, detail) with { Count = aggregate.Count });
        }
        return entries.GroupBy(e => (e.Kind, e.NextStep, e.CanFullScan))
            .Select(g => new CoverageGroup(g.Key.Kind, g.Sum(e => e.Count), g.Key.NextStep, g.Key.CanFullScan, g.ToArray())).ToArray();
    }

    public static CoverageEntry Describe(string rule, string target, string detail)
    {
        (string kind, string next, bool full) = rule switch
        {
            "QUICK-MEDIA-STRUCTURE" => ("视频已做结构检查，未做完整比对", FullScanAction + "，将对整个文件进行哈希比对。", true),
            "QUICK-FILE-SIZE" or "CONTENT-BYTE-BUDGET" => ("达到本次读取上限", FullScanAction + "。若仍达到上限，可单独选择该文件或目录扫描。", true),
            "ARCHIVE-NOT-REQUESTED" or "COMPOUND-CONTENT-NOT-EXPANDED" => ("压缩内容未展开", FullScanAction + "，需开启压缩内容检查，仍受格式与安全上限限制。", true),
            "ARCHIVE-PASSWORD-FAILED" or "ARCHIVE-ENCRYPTED-NOT-SCANNED" or "ARCHIVE-ENCRYPTED-DEFERRED" => ("加密内容未解开", "先准备正确的外层和内层密码，再" + FullScanAction + "，也可点击“重试未解密内容”。", true),
            "CONTENT-SCAN-FAILED" when detail.Contains("ScanResourceLimitException") =>
                ("本轮内容检查达到安全上限", "本次触发扫描安全边界，不等于系统内存不足。请查看具体上限，用“扫描目录”分批检查剩余内容。已完成部分的结果仍保留，无需关闭防护。", false),
            "CONTENT-SCAN-FAILED" when detail.Contains("OutOfMemoryException") =>
                ("扫描组件内存分配失败", "扫描组件发生内存分配失败，请导出报告中的诊断记录，再分批检查剩余内容。已完成部分的结果仍保留，无需关闭防护。", false),
            "CONTENT-SCAN-FAILED" or "CONTENT-SCAN-CANCELLED" => ("部分检查未执行", "确认扫描组件可用后重新扫描，已完成部分的结果仍保留。", false),
            _ when detail.Contains("只检查所选工坊") => ("工坊范围选择说明", "本次只检查所选游戏的工坊，要检查其他游戏，请将工坊范围改为“全部本地工坊”后重新扫描。", false),
            _ when detail.Contains("读取达到") || detail.Contains("字节预算") => ("达到本次读取上限", FullScanAction + "。若仍达到上限，请单独扫描较小目录。", true),
            _ when detail.Contains("AMSI", StringComparison.OrdinalIgnoreCase) => ("安全软件辅助检查不可用", "检查本机安全软件是否正常开启，再重试。完整内容扫描不能代替不可用的安全软件接口。", false),
            _ when detail.Contains("取消") || detail.Contains("尚未开始") || detail.Contains("启动失败") => ("部分检查未执行", "确认扫描组件可用后重新扫描，已完成部分的结果仍保留。", false),
            _ when detail.Contains("上限") || detail.Contains("超过扫描限制") || detail.Contains("嵌套深度") => ("达到安全检查上限", "可单独扫描较小目录，压缩比、嵌套层数等安全上限不会因完整扫描而取消。不要为检查而运行安装包。", false),
            _ => ("读取受限或其他覆盖说明", "请查看具体原因。访问受限、文件损坏或格式不支持时，完整内容扫描不一定能补齐，可导出报告进一步核对。", false)
        };
        return new(kind, target, detail, next, full);
    }
}
