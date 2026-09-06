using System.Text;
using SteamSentinel.Core.Inspection;
using SteamSentinel.Core.Models;

namespace SteamSentinel.Core.Reporting;

/// <summary>Bounded, read-only presentation. Observation links never grant remediation eligibility.</summary>
public static class RelatedComponentReportPresentation
{
    public const string SourceKind = "related-components";
    public const int MaximumDescriptionCharacters = 256_000;
    private const int MaximumListedRecords = 1024;
    private const string OmissionNotice = "\n部分显示内容已达到上限；完整结构化记录仍保存在 JSON 报告与完整记录包中。\n";

    public static bool IsRelatedFinding(Finding finding) =>
        finding.AssociationObservationIds.Count > 0 || finding.SourceKind == SourceKind || finding.AssociationEvidenceTier is not null;

    public static string EvidenceTierLabel(RelatedEvidenceTier? tier) => tier switch
    {
        RelatedEvidenceTier.Observation => "观察记录",
        RelatedEvidenceTier.RelatedRisk => "关联风险",
        RelatedEvidenceTier.ConfirmedTarget => "已确认目标",
        _ => "层级未记录"
    };

    public static string StatusLabel(DiagnosticReadStatus status) => status switch
    {
        DiagnosticReadStatus.Complete => "已完成",
        DiagnosticReadStatus.NotPresent => "未发现／不存在",
        DiagnosticReadStatus.NotChecked => "未检查",
        DiagnosticReadStatus.AccessDenied => "权限不足",
        DiagnosticReadStatus.LimitReached => "达到检查上限",
        DiagnosticReadStatus.Cancelled => "已取消",
        _ => "检查失败"
    };

    public static string Summary(RelatedComponentDiagnosticReport diagnostic)
    {
        bool incomplete = diagnostic.Checks.Any(check => check.Required && IsIncomplete(check.Status)) ||
            diagnostic.Rounds.Any(round => round.CompletedAtUtc is null || IsIncomplete(round.Status)) ||
            diagnostic.Sources.Any(source => IsIncomplete(source.Status)) || diagnostic.Hosts.Any(host => IsIncomplete(host.Status)) ||
            diagnostic.Candidates.Any(candidate => IsIncomplete(candidate.Status));
        string state = diagnostic.CompletedAtUtc is null ? "关联检查尚未结束"
            : incomplete ? "关联检查未完成"
            : diagnostic.Candidates.Any(candidate => IsIncomplete(candidate.ContentStatus)) ? "仍有未检查组件"
            : diagnostic.Checks.Count + diagnostic.Rounds.Count == 0 ? "关联状态待核对" : "本轮关联检查已完成";
        return $"{state} · 来源 {diagnostic.Sources.Count} · 宿主 {diagnostic.Hosts.Count} · 候选 {diagnostic.Candidates.Count}";
    }

    public static string Describe(RelatedComponentDiagnosticReport diagnostic)
    {
        BoundedText text = new(MaximumDescriptionCharacters);
        text.Line("组件关联检查（只读）");
        text.Line(Summary(diagnostic));
        text.Line($"目标用户 SID：{Display(diagnostic.TargetUserSid)}");
        text.Line($"采集时间：{diagnostic.StartedAtUtc:O} 至 {Time(diagnostic.CompletedAtUtc)}");
        text.Line("来源、宿主和组件之间的加载或启动关系，不等于确认恶意、写入行为或自动处理资格。写入者仍未定位；候选文件只由受限扫描组件检查。");
        text.Line("路径关系观察与文件核验可能来自不同时间。哈希和签名仅描述核验时该路径的磁盘文件；未读取进程内存，不能证明内存映像或不同时刻的同路径文件内容一致。");
        text.Line("下列命令和说明已隐藏已识别的凭据字段；签名状态不豁免组件内容检查。");
        text.Line();
        text.Line("轮次与预算记录");
        text.Line("签名检查将实际哈希读取与额外一份文件长度的 WinTrust 预留计入预算；原生签名调用不提供实际 I/O 计数。");
        if (diagnostic.AppliedLimits is { } limits)
        {
            text.Line($"本次限制：最多 {limits.MaximumRounds} 轮，累计 {Bytes(limits.MaximumTotalBytes)}，单文件 {Bytes(limits.MaximumFileBytes)}，候选 {limits.MaximumCandidates} 个，宿主 {limits.MaximumHosts} 个。");
            text.Line($"发现时限 {limits.MaximumDiscoveryDuration.TotalSeconds:0.##} 秒；关联补查时限 {limits.MaximumDuration.TotalSeconds:0.##} 秒。限制并不表示已经用尽预算或检查所有文件。");
        }
        else text.Line("本次配置的预算上限未记录，不能由默认设置推定。");
        foreach (RelatedScanRound round in diagnostic.Rounds.Take(16))
        {
            text.Line($"第 {round.Number} 轮 [{StatusLabel(round.Status)}]：计入预算 {Bytes(round.BytesRead)} / 本轮预算 {(round.MaximumBytes is long budget ? Bytes(budget) : "未记录")}；候选 {round.CandidateIds.Count} 个。");
            text.Line($"  时间：{round.StartedAtUtc:O} 至 {Time(round.CompletedAtUtc)}；{Display(round.Detail)}");
            text.Line("  候选 ID：" + References(round.CandidateIds));
        }
        if (diagnostic.Rounds.Count == 0) text.Line("尚无补查轮次记录。");
        if (diagnostic.Rounds.Count > 16) text.Omitted();

        RelatedSourceObservation[] sources = diagnostic.Sources.Take(MaximumListedRecords).ToArray();
        RelatedHostObservation[] hosts = diagnostic.Hosts.Take(MaximumListedRecords).ToArray();
        RelatedComponentCandidate[] candidates = diagnostic.Candidates.Take(MaximumListedRecords).ToArray();
        text.Line();
        text.Line("来源 → 宿主 → 候选组件（路径关系观察）");
        foreach (RelatedSourceObservation source in sources)
        {
            if (text.Full) break;
            text.Line($"[{StatusLabel(source.Status)}] 来源 {Display(source.Kind)} · {Display(source.Scope)} · ID {Display(source.Id)}");
            text.Line("  位置：" + Display(source.Location));
            text.Line("  命令：" + Display(source.RawCommand));
            text.Line($"  工作目录：{Display(source.WorkingDirectory)}；用户 SID：{Display(source.UserSid)}");
            text.Line("  解析目标：" + References(source.ResolvedTargets));
            text.Line("  说明：" + Display(source.Detail));
            RelatedHostObservation[] linkedHosts = hosts.Where(host => host.SourceObservationIds.Contains(source.Id)).Take(16).ToArray();
            RelatedComponentCandidate[] linkedCandidates = candidates.Where(candidate => candidate.SourceObservationIds.Contains(source.Id)).Take(16).ToArray();
            foreach (RelatedHostObservation host in linkedHosts)
            {
                RelatedComponentCandidate[] modules = candidates.Where(candidate => candidate.HostObservationIds.Contains(host.Id)).Take(16).ToArray();
                if (modules.Length == 0) text.Line($"  关系：来源 {Display(source.Id)} → 宿主 PID {host.ProcessId}（{Display(host.ImagePath)}）→ 尚无组件记录");
                foreach (RelatedComponentCandidate candidate in modules)
                    text.Line($"  关系：来源 {Display(source.Id)} → 宿主 PID {host.ProcessId} → 组件 {Display(candidate.Path)}（ID {Display(candidate.Id)}）");
                if (candidates.Count(candidate => candidate.HostObservationIds.Contains(host.Id)) > modules.Length) text.Omitted();
            }
            foreach (RelatedComponentCandidate candidate in linkedCandidates.Where(candidate =>
                !candidate.HostObservationIds.Any(id => linkedHosts.Any(host => host.Id == id))))
                text.Line($"  关系：来源 {Display(source.Id)} → 组件 {Display(candidate.Path)}（宿主关系未取得，ID {Display(candidate.Id)}）");
            if (hosts.Count(host => host.SourceObservationIds.Contains(source.Id)) > linkedHosts.Length ||
                candidates.Count(candidate => candidate.SourceObservationIds.Contains(source.Id)) > linkedCandidates.Length) text.Omitted();
        }

        text.Line();
        text.Line("宿主身份与磁盘文件状态");
        foreach (RelatedHostObservation host in hosts)
        {
            if (text.Full) break;
            text.Line($"[{StatusLabel(host.Status)}] 宿主 PID {host.ProcessId} · ID {Display(host.Id)}");
            text.Line($"  报告的映像路径：{Display(host.ImagePath)}；进程启动时间：{Time(host.StartedAtUtc)}");
            text.Line("  该路径磁盘文件 SHA-256：" + Display(host.ImageSha256));
            text.Line($"  命令：{Display(host.CommandLine)}；工作目录：{Display(host.WorkingDirectory)}");
            text.Line($"  该路径磁盘文件离线签名：{SignatureLabel(host.SignatureStatus)}；{Display(host.SignatureDetail)}");
            text.Line("  来源 ID：" + References(host.SourceObservationIds));
            text.Line("  说明：" + Display(host.Detail));
        }

        text.Line();
        text.Line("候选组件与受限内容检查");
        foreach (RelatedComponentCandidate candidate in candidates)
        {
            if (text.Full) break;
            text.Line($"[{StatusLabel(candidate.Status)}] 组件 {Display(candidate.Path)} · ID {Display(candidate.Id)}");
            text.Line("  纳入原因：" + Display(candidate.Reason));
            text.Line($"  磁盘文件 SHA-256：{Display(candidate.Sha256)}；大小：{(candidate.Length is long size ? Bytes(size) : "未取得")}；文件核验时间：{Time(candidate.VerifiedAtUtc)}");
            text.Line($"  内容检查：{StatusLabel(candidate.ContentStatus)}；{Display(candidate.ContentDetail)}");
            text.Line($"  来源 ID：{References(candidate.SourceObservationIds)}；宿主 ID：{References(candidate.HostObservationIds)}");
            text.Line("  证据观察 ID：" + References(candidate.EvidenceObservationIds));
            text.Line("  说明：" + Display(candidate.Detail));
        }
        if (diagnostic.Sources.Count > sources.Length || diagnostic.Hosts.Count > hosts.Length || diagnostic.Candidates.Count > candidates.Length) text.Omitted();

        text.Line();
        text.Line("已记录的关系与依据");
        foreach (DiagnosticRelation relation in diagnostic.Relations.Take(4096))
        {
            if (text.Full) break;
            text.Line($"{Display(relation.FromId)} → {Display(relation.ToId)} · {Display(relation.Kind)}：{Display(relation.Evidence)}");
        }
        if (diagnostic.Relations.Count > 4096) text.Omitted();
        text.Line();
        text.Line("未完成检查与范围说明");
        foreach (DiagnosticCheck check in diagnostic.Checks.Take(MaximumListedRecords))
        {
            if (text.Full) break;
            text.Line($"[{StatusLabel(check.Status)}] {Display(check.Name)}{(check.Required ? "" : "（本轮范围外）")}：{Display(check.Detail)}；观察 ID {Display(check.ObservationId)}");
        }
        if (diagnostic.Checks.Count > MaximumListedRecords) text.Omitted();
        text.Line("未观察到加载关系不代表没有加载；未定位写入者不代表没有重新写入。结果仅适用于记录的时刻、身份和已检查范围。");
        return text.ToString();
    }

    public static string DescribeFinding(Finding finding, RelatedComponentDiagnosticReport? diagnostic)
    {
        if (!IsRelatedFinding(finding)) return string.Empty;
        BoundedText text = new(12_000);
        text.Line("组件关联依据（只读）");
        text.Line("证据层级：" + EvidenceTierLabel(finding.AssociationEvidenceTier) + "；层级本身不授予处理权限。");
        text.Line("路径关系观察与文件核验可能来自不同时间；SHA-256 与签名仅描述核验时的磁盘文件，未证明进程内存内容。");
        if (diagnostic is null) text.Line("当前没有关联诊断快照，不能由观察 ID 推定原因或处理资格。");
        else foreach (string id in finding.AssociationObservationIds.Distinct(StringComparer.Ordinal).Take(16))
        {
            RelatedComponentCandidate? candidate = diagnostic.Candidates.FirstOrDefault(item => item.Id == id);
            RelatedHostObservation? host = diagnostic.Hosts.FirstOrDefault(item => item.Id == id);
            RelatedSourceObservation? source = diagnostic.Sources.FirstOrDefault(item => item.Id == id);
            DiagnosticCheck? check = diagnostic.Checks.FirstOrDefault(item => item.Id == id);
            if (candidate is not null)
            {
                text.Line($"观察 {Display(id)}：{Display(candidate.Path)}；{Display(candidate.Reason)}；内容检查 {StatusLabel(candidate.ContentStatus)}：{Display(candidate.ContentDetail)}");
                text.Line($"  磁盘文件 SHA-256：{Display(candidate.Sha256)}；文件核验时间：{Time(candidate.VerifiedAtUtc)}");
            }
            else if (host is not null)
                text.Line($"观察 {Display(id)}：宿主 PID {host.ProcessId}，报告的映像路径 {Display(host.ImagePath)}；进程启动时间 {Time(host.StartedAtUtc)}；{StatusLabel(host.Status)}；{Display(host.Detail)}");
            else if (source is not null)
                text.Line($"观察 {Display(id)}：{Display(source.Kind)}，{Display(source.Location)}；{StatusLabel(source.Status)}；{Display(source.Detail)}");
            else if (check is not null)
                text.Line($"观察 {Display(id)}：{Display(check.Name)}；{StatusLabel(check.Status)}；{Display(check.Detail)}");
            else text.Line($"观察 {Display(id)}：当前快照未找到对应记录，请核对完整报告。");
        }
        if (finding.AssociationObservationIds.Count > 16) text.Omitted();
        text.Line("完整来源、宿主、候选、预算和未完成原因见“组件关联”。加载或启动关系不证明写入者，处理资格仍以原有文件证据为准。");
        return text.ToString();
    }

    private static bool IsIncomplete(DiagnosticReadStatus status) => status is not (DiagnosticReadStatus.Complete or DiagnosticReadStatus.NotPresent);
    private static string SignatureLabel(string status) => status switch
    {
        "Valid" => "本地信任缓存验证通过",
        "Unsigned" => "未取得可验证签名",
        "Failed" => "未完成或未通过",
        "NotChecked" => "未检查",
        _ => Display(status)
    };
    private static string Time(DateTimeOffset? value) => value?.ToString("O") ?? "未取得／尚未结束";
    private static string Bytes(long value) => $"{value:N0} 字节";
    private static string References(IReadOnlyList<string> values) => values.Count == 0 ? "未取得" :
        string.Join("；", values.Take(16).Select(Display)) + (values.Count > 16 ? $"；其余 {values.Count - 16} 项见 JSON" : "");
    private static string Display(string? value) => string.IsNullOrEmpty(value) ? "未取得／空值" :
        value.Length > 32768 ? "[单项文本超过显示上限，见 JSON 记录]" :
        ScriptSignals.Redact(value).Replace("\r", " ").Replace("\n", " ").Replace("\t", " ");

    private sealed class BoundedText(int maximum)
    {
        private readonly StringBuilder _text = new();
        private bool _omitted;
        public bool Full { get; private set; }
        public void Omitted() => _omitted = true;
        public void Line(string value = "")
        {
            if (Full) return;
            int remaining = maximum - OmissionNotice.Length - _text.Length - Environment.NewLine.Length;
            if (value.Length > remaining)
            {
                if (remaining > 0) _text.Append(value.AsSpan(0, remaining));
                Full = true; _omitted = true;
                return;
            }
            _text.AppendLine(value);
        }
        public override string ToString() => _text.ToString() + (_omitted ? OmissionNotice : string.Empty);
    }
}
