using System.Text;
using SteamSentinel.Core.Models;
using SteamSentinel.Core.Utilities;

namespace SteamSentinel.Core.Reporting;

public static class ReportExporter
{
    public static Task ExportJsonAsync(ScanReport report, string path, CancellationToken cancellationToken = default) =>
        JsonFile.WriteAtomicAsync(path, report, cancellationToken, ReportPrivacy.ExportOptions);

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
        text.AppendLine($"- 执行状态：{report.ExecutionStatus}");
        text.AppendLine($"- 风险或提示数量：{report.RiskFindingCount}，不包含覆盖记录");
        foreach (string scope in report.ScopeNotes) text.AppendLine("- 检查范围：" + Escape(scope));
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
        text.AppendLine("## 内容来源与关联落点");
        if (report.ContentScanSettings is ScanOptions settings)
        {
            text.AppendLine();
            text.AppendLine($"- 内容扫描设置：{settings.Mode}，额外下载/桌面/临时目录：{settings.IncludeDownloadLocations}，压缩包：{settings.InspectArchives}，AMSI：{settings.UseAmsi}");
            string hashBudget = settings.MaximumContentBytes == long.MaxValue ? "不设整轮哈希字节上限" :
                $"{settings.MaximumContentBytes / 1024 / 1024:N0} MiB（{settings.MaximumContentBytes:N0} 字节）";
            text.AppendLine($"- 累计哈希预算：{hashBudget}" +
                (settings.Mode == ScanMode.Quick ? "，另为不超过 8 MiB 的小型启动文件保留最多 128 MiB" : "") +
                $"，单条解压上限：{settings.MaximumEntryBytes / 1024 / 1024:N0} MiB，嵌套深度：{settings.MaximumArchiveDepth}");
        }
        if (report.WorkerDiagnostics is WorkerDiagnostics diagnostic)
        {
            text.AppendLine();
            text.AppendLine("### 扫描组件诊断");
            text.AppendLine();
            text.AppendLine("- 最后处理阶段：" + Escape(diagnostic.Stage + " / " + diagnostic.Operation));
            text.AppendLine("- 最后处理路径：" + Escape(diagnostic.LastPath));
            text.AppendLine($"- 组件私有内存：{diagnostic.PrivateBytes / 1024 / 1024:N0} MiB，峰值：{diagnostic.PeakPrivateBytes / 1024 / 1024:N0} MiB，托管内存：{diagnostic.ManagedBytes / 1024 / 1024:N0} MiB");
            text.AppendLine("- 主窗口权限级别：" + Escape(diagnostic.LauncherIntegrity ?? "未记录"));
            text.AppendLine($"- 内存采样时间：{diagnostic.CapturedAtUtc.ToLocalTime():yyyy-MM-dd HH:mm:ss zzz}，采样值不等同于失败瞬间峰值");
            if (diagnostic.FailureType is not null) text.AppendLine("- 内部错误类型：" + Escape(diagnostic.FailureType));
            if (diagnostic.FailureStack is not null) text.AppendLine("- 内部调用位置：" + Escape(diagnostic.FailureStack));
            text.AppendLine("- 中断时正在处理的文件不能视作已完成检查，已交回结果也不能证明其他内容安全。");
        }
        text.AppendLine();
        foreach (string source in report.ContentSources.Distinct()) text.AppendLine("- " + Escape(source));
        foreach (string source in report.CandidateRoots.Distinct()) text.AppendLine("- 关联候选落点：" + Escape(source));
        text.AppendLine();

        if (report.RootSummaries.Count > 0)
        {
            text.AppendLine("## 各扫描路径的结果");
            text.AppendLine();
            text.AppendLine("| 路径 | 已知威胁数 | 可处置发现数 | 覆盖状态 |");
            text.AppendLine("|---|---:|---:|---|");
            foreach (ScanRootSummary root in report.RootSummaries)
                text.AppendLine($"| {Escape(root.Path)} | {root.KnownThreats} | {root.ActionableFindings} | {CoverageLabel(root.Coverage)} |");
            text.AppendLine();
        }

        if (report.CoverageNotes.Count > 0 || report.CoverageAggregates.Count > 0 || report.Findings.Any(f => f.Category == FindingCategory.Coverage))
        {
            text.AppendLine("## 未检查内容与补查方式");
            text.AppendLine();
            foreach (CoverageGroup group in CoveragePresentation.Groups(report))
            {
                text.AppendLine($"### {Escape(group.Kind)} · {group.Count} 次覆盖记录（非去重文件数）");
                text.AppendLine();
                text.AppendLine(Escape(group.NextStep));
                text.AppendLine();
                foreach (CoverageEntry item in group.Entries) text.AppendLine($"- {Escape(item.Target)}：{Escape(item.Detail)}");
                text.AppendLine();
            }
            text.AppendLine();
        }

        text.AppendLine("## 发现");
        text.AppendLine();
        text.AppendLine("| 严重度 | 规则 ID | 分类 | 分数 | 标题 | SHA-256 | 目标 |");
        text.AppendLine("|---|---|---|---:|---|---|---|");
        foreach (Finding finding in report.Findings.Where(f => f.Category != FindingCategory.Coverage).OrderByDescending(f => f.Severity).ThenByDescending(f => f.Score))
        {
            text.AppendLine($"| {SeverityLabel(finding.Severity)} | `{Escape(finding.RuleId)}` | {CategoryLabel(finding.Category)} | {finding.Score} | {Escape(finding.Title)} | `{Escape(finding.Sha256 ?? "—")}` | `{Escape(finding.Target)}` |");
        }

        text.AppendLine();
        text.AppendLine("## 逐项详情");
        text.AppendLine();
        foreach (Finding finding in report.Findings.Where(f => f.Category != FindingCategory.Coverage).OrderByDescending(f => f.Severity).ThenByDescending(f => f.Score))
        {
            text.AppendLine($"### {SeverityLabel(finding.Severity)} · {Escape(finding.Title)}");
            text.AppendLine();
            text.AppendLine($"- 规则 ID：`{Escape(finding.RuleId)}`");
            text.AppendLine($"- 说明：{Escape(finding.Description)}");
            text.AppendLine($"- 内容归属：AppID {Escape(finding.AppId ?? "—")}，工坊 {Escape(finding.WorkshopId ?? "—")}，{Escape(finding.SourceKind ?? "—")}");
            if (finding.RelatedFilePath is not null) text.AppendLine($"- 关联文件：{Escape(finding.RelatedFilePath)}，SHA-256：{Escape(finding.RelatedFileSha256 ?? "—")}");
            text.AppendLine($"- 目标：`{Escape(finding.Target)}`");
            text.AppendLine($"- SHA-256：`{Escape(finding.Sha256 ?? "未计算/不适用")}`");
            text.AppendLine($"- 命中内容位置：`{Escape(finding.ContentPath ?? finding.Target)}`");
            text.AppendLine($"- 隔离目标 SHA-256：`{Escape(finding.TargetSha256 ?? "未计算/不适用")}`");
            text.AppendLine($"- 证据：{Escape(finding.Evidence)}");
            text.AppendLine($"- 处置资格：{(finding.CanRemediate ? "可选中处置，仍需确认预览" : "仅复核")}");
            text.AppendLine();
        }

        text.AppendLine("## 结论边界");
        text.AppendLine();
        text.AppendLine("文件存在、运行关联和 Steam 篡改是不同证据。工具可隔离已知威胁，也保留需要你确认的启发式处置。处置成功不代表整台电脑无毒，请重启后复扫，必要时用专业杀毒软件全盘检查。如果可能发生凭据窃取，应从可信设备更换密码并撤销其他会话，本地恢复不能撤回已外泄的数据。");

        string fullPath = Path.GetFullPath(path);
        Directory.CreateDirectory(Path.GetDirectoryName(fullPath)!);
        await File.WriteAllTextAsync(fullPath, text.ToString(), new UTF8Encoding(encoderShouldEmitUTF8Identifier: true), cancellationToken);
    }

    private static string Escape(string value) => Inspection.ScriptSignals.RedactSecrets(value).Replace("|", "\\|").Replace("\r", " ").Replace("\n", " ");

    public static string CoverageLabel(ScanCoverage value) => value switch
    {
        ScanCoverage.Complete => "本次支持范围内未跳过检查",
        ScanCoverage.Partial => "有内容未检查或尚未深查",
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
        RemediationActionType.StopHostProcess => "关闭加载恶意组件的宿主",
        RemediationActionType.DisableService => "禁用关联服务",
        RemediationActionType.RemoveRelatedDefenderExclusion => "移除关联安全排除项",
        RemediationActionType.DisableRelatedFirewallRule => "禁用关联放行规则",
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
