using SteamSentinel.Core.Reporting;
using SteamSentinel.Core.Models;

namespace SteamSentinel.App.Services;

internal static class IncidentDeletionPolicy
{
    // This is a UX precondition, not an attestation. Broker independently refuses active records.
    internal static MessageText? RejectionReason(QuarantineManifest incident, ScanReport? report,
        Guid? fullSystemAndContentScanId, DateTimeOffset now, DateTimeOffset currentBoot)
    {
        if (incident.Records.Any(record => !record.RolledBack))
            return MessageText.Create("Backend.Core.IncidentDeletionPolicy.RejectionReason.01");
        if (currentBoot <= incident.MachineBootTimeUtc.AddMinutes(1))
            return MessageText.Create("Backend.Core.IncidentDeletionPolicy.RejectionReason.02");
        if (report is null || report.ScanId != fullSystemAndContentScanId || report.Mode != ScanMode.Full ||
            report.ExecutionState != ScanExecutionState.Completed ||
            report.Coverage != ScanCoverage.Complete || report.RootSummaries.Any(root => root.Coverage != ScanCoverage.Complete) ||
            report.CompletedAtUtc is not { } completed || completed < report.StartedAtUtc || completed > now ||
            report.StartedAtUtc <= incident.CreatedAtUtc || report.StartedAtUtc < currentBoot || now - completed > TimeSpan.FromHours(24))
            return MessageText.Create("Backend.Core.IncidentDeletionPolicy.RejectionReason.03");
        if (report.Findings.Any(finding => finding.IsKnownMalware))
            return MessageText.Create("Backend.Core.IncidentDeletionPolicy.RejectionReason.04");
        return null;
    }
}
