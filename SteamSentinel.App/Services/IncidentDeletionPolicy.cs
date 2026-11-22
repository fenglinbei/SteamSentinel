using SteamSentinel.Core.Reporting;
using SteamSentinel.Core.Models;

namespace SteamSentinel.App.Services;

internal static class IncidentDeletionPolicy
{
    /// <summary>
    /// 评估隔离事件是否具备永久删除的基本数据前提；允许用户经确认直接彻底清除尚未回滚的隔离副本。
    /// </summary>
    internal static MessageText? RejectionReason(QuarantineManifest incident, ScanReport? report,
        Guid? fullSystemAndContentScanId, DateTimeOffset now, DateTimeOffset currentBoot)
    {
        _ = report;
        _ = fullSystemAndContentScanId;
        _ = now;
        _ = currentBoot;
        if (incident is null || incident.IncidentId == Guid.Empty || incident.Records.Count == 0)
            return MessageText.Create("Backend.Core.IncidentDeletionPolicy.RejectionReason.01");
        return null;
    }
}
