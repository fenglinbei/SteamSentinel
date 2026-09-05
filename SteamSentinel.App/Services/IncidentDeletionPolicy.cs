using SteamSentinel.Core.Models;

namespace SteamSentinel.App.Services;

internal static class IncidentDeletionPolicy
{
    // This is a UX precondition, not an attestation. Broker independently refuses active records.
    internal static string? RejectionReason(QuarantineManifest incident, ScanReport? report,
        Guid? fullSystemAndContentScanId, DateTimeOffset now, DateTimeOffset currentBoot)
    {
        if (incident.Records.Any(record => !record.RolledBack))
            return "此事件仍有活动隔离记录。当前版本无法由管理员组件验证完整复扫证明，永久删除已禁用，请保留隔离。";
        if (currentBoot <= incident.MachineBootTimeUtc.AddMinutes(1))
            return "隔离事件创建后尚未检测到系统重启，暂不能清理记录。";
        if (report is null || report.ScanId != fullSystemAndContentScanId || report.Mode != ScanMode.Full ||
            report.Coverage != ScanCoverage.Complete || report.RootSummaries.Any(root => root.Coverage != ScanCoverage.Complete) ||
            report.CompletedAtUtc is not { } completed || completed < report.StartedAtUtc || completed > now ||
            report.StartedAtUtc <= incident.CreatedAtUtc || report.StartedAtUtc < currentBoot || now - completed > TimeSpan.FromHours(24))
            return "请在本次重启后，使用全部本地工坊范围完成一次系统、Steam 与内容完整复扫。自定义、快速、旧报告或部分完成的扫描不能用于清理记录。";
        if (report.Findings.Any(finding => finding.IsKnownMalware))
            return "复扫仍含已知恶意项，暂不能清理隔离记录。";
        return null;
    }
}
