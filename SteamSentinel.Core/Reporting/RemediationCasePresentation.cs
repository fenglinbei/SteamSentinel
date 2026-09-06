using System.Text;
using System.Text.Json;
using SteamSentinel.Core.Models;
using SteamSentinel.Core.Remediation;
using SteamSentinel.Core.Inspection;

namespace SteamSentinel.Core.Reporting;

public static class RemediationCasePresentation
{
    public static string Label(CaseReverificationState state) => state switch
    {
        CaseReverificationState.ExecutionUncertain => "执行结果未确定",
        CaseReverificationState.AwaitingSessionChange => "等待重启或重新登录",
        CaseReverificationState.SessionUnknown => "会话身份未确认",
        CaseReverificationState.Incomplete => "复验不完整",
        CaseReverificationState.ResidualDetected => "仍有残留",
        CaseReverificationState.Reappeared => "目标再次出现",
        CaseReverificationState.SelectedTargetsVerified => "所选目标跨会话复验通过",
        _ => "尚未跨会话复验"
    };

    public static string Render(RemediationCaseRecord record)
    {
        StringBuilder text = new();
        text.AppendLine("病例：" + record.CaseId);
        text.AppendLine("用户：" + record.UserSid);
        text.AppendLine("保存时间：" + record.UpdatedAtUtc.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss zzz"));
        bool uncertain = record.PendingPlanIds.Count > 0 || record.ExecutionResults.Concat(record.BatchSession?.Results ?? [])
            .Any(r => r.Disposition == RemediationRunDisposition.ExecutionUnknown || r.Actions.Any(a => a.ExecutionStatus == RemediationExecutionStatus.ExecutionUnknown));
        text.AppendLine("状态：" + Label(uncertain ? CaseReverificationState.ExecutionUncertain : record.Episodes.LastOrDefault()?.State ?? CaseReverificationState.NotChecked));
        text.AppendLine("执行结果未确定的计划：" + record.PendingPlanIds.Count);
        text.AppendLine(record.WriterSummary);
        text.AppendLine("这里只读复验已保存的目标和原范围。旧计划不会重放，记录本身不是管理员处置授权。");
        if (record.BaselineSession is { } baseline)
            text.AppendLine($"处置前会话：启动 {baseline.BootStatus}，交互登录 {baseline.LogonStatus}；{baseline.Detail}");
        foreach (CaseVerificationEpisode episode in record.Episodes.TakeLast(32))
        {
            text.AppendLine();
            text.AppendLine($"{episode.StartedAtUtc.ToLocalTime():yyyy-MM-dd HH:mm:ss zzz} · {Label(episode.State)} · {episode.Transition}");
            text.AppendLine(episode.Summary);
            foreach (DiagnosticCheck check in episode.Checks.Take(256)) text.AppendLine($"检查 {check.Name}：{check.Status}；{check.Detail}");
            foreach (CaseActionVerification target in episode.Targets.Take(256))
                text.AppendLine($"{ReportExporter.ActionLabel(target.Type)} · {target.Target}\n{RemediationVerification.Label(target.Status)}：{target.Message}");
        }
        foreach (string note in record.Notes.TakeLast(32)) text.AppendLine("记录说明：" + note);
        return ScriptSignals.RedactSecrets(text.ToString());
    }

    public static string ActionIdentity(RemediationAction action)
    {
        string identity = (action.ExpectedSha256 ?? action.ExpectedValueData ?? string.Empty) +
            (action.RelatedFilePath is null ? "" : $"\n关联文件：{action.RelatedFilePath}\nSHA-256：{action.RelatedFileSha256}");
        if (action.BoundCertificate is { } certificate)
            identity += $"\n用户：{certificate.TargetUserSid}\n物理证书存储：{certificate.StoreLocation} / {certificate.StoreName}\nDER SHA-256：{certificate.DerSha256}\n公开属性 SHA-256：{certificate.PropertiesSha256}";
        if (action.BoundProxy is { } proxy)
            identity += "\n代理来源、原值、预期值及变更字段：\n" + JsonSerializer.Serialize(proxy, ReportPrivacy.ExportOptions);
        if (action.ConfigurationEvidenceRuleId is { } rule) identity += "\n核验规则：" + rule + "\n修改前备份；配置变化则拒绝执行。";
        if (action.DependsOnActionIds.Count > 0) identity += "\n仅在这些前置动作成功后执行：" + string.Join(", ", action.DependsOnActionIds);
        return ScriptSignals.RedactSecrets(identity);
    }
}
