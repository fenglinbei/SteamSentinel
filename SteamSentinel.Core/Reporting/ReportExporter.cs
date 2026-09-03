using System.Text;
using SteamSentinel.Core.Models;
using SteamSentinel.Core.Utilities;

namespace SteamSentinel.Core.Reporting;

public static class ReportExporter
{
    public static Task ExportJsonAsync(ScanReport report, string path, CancellationToken cancellationToken = default) =>
        JsonFile.WriteAtomicAsync(path, report, cancellationToken);

    public static async Task ExportMarkdownAsync(ScanReport report, string path, CancellationToken cancellationToken = default)
    {
        StringBuilder text = new();
        text.AppendLine($"# {ProductInfo.Name} 扫描报告");
        text.AppendLine();
        text.AppendLine($"- 工具版本：`{report.ProductVersion}`");
        text.AppendLine($"- 规则版本：`{report.RuleSetVersion}`");
        text.AppendLine($"- 扫描 ID：`{report.ScanId}`");
        text.AppendLine($"- 开始时间：{report.StartedAtUtc.ToLocalTime():yyyy-MM-dd HH:mm:ss zzz}");
        text.AppendLine($"- 完成时间：{report.CompletedAtUtc?.ToLocalTime():yyyy-MM-dd HH:mm:ss zzz}");
        text.AppendLine($"- 覆盖状态：**{CoverageLabel(report.Coverage)}**");
        text.AppendLine($"- 最高严重度：**{SeverityLabel(report.HighestSeverity)}**");
        text.AppendLine();
        text.AppendLine("> “未发现已知威胁”不等同于对未知漏洞或未解密内容的绝对安全保证。");
        text.AppendLine();

        text.AppendLine("## 扫描统计");
        text.AppendLine();
        text.AppendLine($"- 文件：{report.Metrics.FilesVisited}");
        text.AppendLine($"- 进程：{report.Metrics.ProcessesVisited}");
        text.AppendLine($"- 持久化项：{report.Metrics.PersistenceItemsVisited}");
        text.AppendLine($"- 工坊项目：{report.Metrics.WorkshopItemsVisited}");
        text.AppendLine($"- 压缩包条目：{report.Metrics.ArchiveEntriesVisited}");
        text.AppendLine();

        if (report.CoverageNotes.Count > 0)
        {
            text.AppendLine("## 覆盖限制");
            text.AppendLine();
            foreach (string note in report.CoverageNotes) text.AppendLine($"- {Escape(note)}");
            text.AppendLine();
        }

        text.AppendLine("## 发现");
        text.AppendLine();
        text.AppendLine("| 严重度 | 规则 ID | 分类 | 分数 | 标题 | SHA-256 | 目标 |");
        text.AppendLine("|---|---|---|---:|---|---|---|");
        foreach (Finding finding in report.Findings.OrderByDescending(f => f.Severity).ThenByDescending(f => f.Score))
        {
            text.AppendLine($"| {SeverityLabel(finding.Severity)} | `{Escape(finding.RuleId)}` | {CategoryLabel(finding.Category)} | {finding.Score} | {Escape(finding.Title)} | `{Escape(finding.Sha256 ?? "—")}` | `{Escape(finding.Target)}` |");
        }

        text.AppendLine();
        text.AppendLine("## 逐项详情");
        text.AppendLine();
        foreach (Finding finding in report.Findings.OrderByDescending(f => f.Severity).ThenByDescending(f => f.Score))
        {
            text.AppendLine($"### {SeverityLabel(finding.Severity)} · {Escape(finding.Title)}");
            text.AppendLine();
            text.AppendLine($"- 规则 ID：`{Escape(finding.RuleId)}`");
            text.AppendLine($"- 说明：{Escape(finding.Description)}");
            text.AppendLine($"- 目标：`{Escape(finding.Target)}`");
            text.AppendLine($"- SHA-256：`{Escape(finding.Sha256 ?? "未计算/不适用")}`");
            text.AppendLine($"- 证据：{Escape(finding.Evidence)}");
            text.AppendLine($"- 自动处置资格：{(finding.CanRemediate ? "有（仍需用户确认预览）" : "无，仅复核")}");
            text.AppendLine();
        }

        text.AppendLine("## 结论边界");
        text.AppendLine();
        text.AppendLine("本工具只能处理命中已确认哈希或高置信 Steam 篡改规则的目标。即使处置成功，也只表示这些目标已被隔离或恢复，不代表整台电脑已经无毒。请继续使用专业杀毒软件进行全盘扫描并复扫。");

        string fullPath = Path.GetFullPath(path);
        Directory.CreateDirectory(Path.GetDirectoryName(fullPath)!);
        await File.WriteAllTextAsync(fullPath, text.ToString(), new UTF8Encoding(encoderShouldEmitUTF8Identifier: true), cancellationToken);
    }

    private static string Escape(string value) => value.Replace("|", "\\|").Replace("\r", " ").Replace("\n", " ");

    public static string CoverageLabel(ScanCoverage value) => value switch
    {
        ScanCoverage.Complete => "完整扫描，未跳过已支持内容",
        ScanCoverage.Partial => "未完整扫描",
        _ => "已跳过"
    };

    public static string CategoryLabel(FindingCategory value) => value switch
    {
        FindingCategory.File => "文件",
        FindingCategory.Archive => "压缩包",
        FindingCategory.Process => "进程",
        FindingCategory.Persistence => "启动项与驻留",
        FindingCategory.Steam => "Steam 客户端",
        FindingCategory.WallpaperEngine => "Wallpaper Engine",
        FindingCategory.Network => "网络",
        FindingCategory.Certificate => "证书",
        FindingCategory.SecurityControl => "安全设置",
        FindingCategory.Coverage => "检查覆盖",
        _ => "其他"
    };

    public static string ActionLabel(RemediationActionType value) => value switch
    {
        RemediationActionType.StopProcess => "停止进程",
        RemediationActionType.RemoveRegistryValue => "删除启动项",
        RemediationActionType.RemoveScheduledTask => "删除计划任务",
        RemediationActionType.RemoveDefenderExclusion => "移除 Defender 排除项",
        RemediationActionType.QuarantineFile => "隔离文件",
        RemediationActionType.QuarantineDirectory => "隔离目录",
        RemediationActionType.AddProgramFirewallBlock => "阻断程序出站连接",
        RemediationActionType.BlockKnownDomains => "阻断已知恶意域名",
        RemediationActionType.RestoreSecurityControls => "恢复安全设置",
        RemediationActionType.RollbackIncident => "回滚隔离事件",
        RemediationActionType.DeleteIncident => "永久删除隔离事件",
        _ => "其他处置动作"
    };

    public static string SeverityLabel(FindingSeverity value) => value switch
    {
        FindingSeverity.Critical => "已确认/严重",
        FindingSeverity.High => "高度可疑",
        FindingSeverity.Medium => "需要复核",
        FindingSeverity.Low => "低风险提示",
        _ => "信息"
    };
}
