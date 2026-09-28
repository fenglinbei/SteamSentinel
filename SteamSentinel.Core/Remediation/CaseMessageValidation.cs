using SteamSentinel.Core.Models;
using SteamSentinel.Core.Reporting;

namespace SteamSentinel.Core.Remediation;

/// <summary>Validate optional display data without making it execution or session evidence.</summary>
internal static class CaseMessageValidation
{
    internal static void Validate(RemediationCaseRecord record, IEnumerable<RemediationPlan> plans,
        IEnumerable<RemediationRunResult> results)
    {
        long characters = 0;
        void Charge(long amount)
        {
            characters = checked(characters + amount);
            if (characters > RemediationCaseStore.MaximumCaseBytes) throw Invalid();
        }
        void Message(DisplayMessage? message) => Charge(message?.Validate() ?? 0);
        Charge(DisplayMessageMap.Validate(record.Notes, record.NoteMessages));
        foreach (RemediationPlan plan in plans)
            foreach (RemediationAction action in plan.Actions)
            {
                Message(action.DisplayNameMessage);
                Message(action.BoundProxy?.Before?.PolicyGuard?.DetailMessage);
                Message(action.BoundProxy?.Desired?.PolicyGuard?.DetailMessage);
            }
        if (record.BatchSession is { } batch)
        {
            Charge(DisplayMessageMap.Validate(batch.Notes, batch.NoteMessages));
            Message(batch.InterruptionMessage);
            foreach (RemediationPreparationNote note in batch.PreparationNotes) Message(note.DetailMessage);
            foreach (RemediationTargetOutcome target in batch.Targets) Message(target.ReasonDetailsMessage);
        }
        foreach (RemediationRunResult result in results)
        {
            Message(result.VerificationSummaryMessage);
            if (result.ErrorMessages is { } errors)
            {
                if (errors.Count > result.Errors.Count) throw Invalid();
                foreach (DisplayMessage? message in errors) Message(message);
            }
            foreach (RemediationActionResult action in result.Actions)
            {
                Message(action.ResultMessage); Message(action.VerificationSummaryMessage);
                Message(action.Occupancy?.DiagnosticMessage);
                foreach (RemediationVerificationObservation observation in action.Verifications) Message(observation.ResultMessage);
            }
        }
        if (record.BaselineSession is { } baseline) Charge(baseline.ValidateDisplayMessages());
        foreach (CaseVerificationEpisode episode in record.Episodes)
        {
            Charge(episode.ValidateDisplayMessages());
            if (episode.Session is { } session) Charge(session.ValidateDisplayMessages());
            foreach (CaseActionVerification target in episode.Targets) Charge(target.ValidateDisplayMessages());
            foreach (DiagnosticCheck check in episode.Checks) Charge(check.ValidateDisplayMessages());
        }
        // Reports are snapshots, not a source of permission. Check every descriptor, including
        // optional indexed metadata, under the existing case storage budget.
        IEnumerable<ScanReport?> reports = new[] { record.OriginalScan }
            .Concat(record.Episodes.SelectMany(e => new[] { e.ContentFollowUp, e.RelatedFollowUp }));
        foreach (ScanReport report in reports.OfType<ScanReport>().Distinct())
        {
            Charge(report.ValidateTextMessages());
            Charge(report.WorkerDiagnostics?.ValidateDisplayMessages() ?? 0);
            foreach (Finding finding in report.Findings) Charge(finding.ValidateDisplayMessages());
            if (report.Containers is { } containers)
            {
                Charge(DisplayMessageMap.Validate(containers.Checks, containers.CheckMessages));
                foreach (ContainerScanNode node in containers.Nodes)
                {
                    Message(node.FormatMessage); Charge(DisplayMessageMap.Validate(node.Details, node.DetailMessages));
                    foreach (ContainerEngineObservation engine in node.Engines) { Message(engine.DetailMessage); Message(engine.EngineMessage); }
                }
            }
            if (report.RelatedComponentDiagnostics is { } related)
            {
                foreach (RelatedSourceObservation source in related.Sources) Charge(source.ValidateDisplayMessages());
                foreach (RelatedHostObservation host in related.Hosts) Charge(host.ValidateDisplayMessages());
                foreach (RelatedComponentCandidate candidate in related.Candidates) Charge(candidate.ValidateDisplayMessages());
                foreach (RelatedScanRound round in related.Rounds) Charge(round.ValidateDisplayMessages());
                foreach (DiagnosticCheck check in related.Checks) Charge(check.ValidateDisplayMessages());
                foreach (DiagnosticRelation relation in related.Relations) Message(relation.EvidenceMessage);
            }
            if (report.TrustProxyDiagnostics is { } trust)
            {
                foreach (ProxyConfigurationObservation proxy in trust.Proxies)
                {
                    Charge(proxy.ValidateDisplayMessages());
                    foreach (DiagnosticConfigurationValue value in proxy.Values) Message(value.ValueMessage);
                }
                foreach (CertificateStoreObservation store in trust.CertificateStores) Charge(store.ValidateDisplayMessages());
                foreach (CertificateObservation certificate in trust.Certificates) Charge(certificate.ValidateDisplayMessages());
                foreach (DiagnosticCheck check in trust.Checks) Charge(check.ValidateDisplayMessages());
                foreach (DiagnosticRelation relation in trust.Relations) Message(relation.EvidenceMessage);
            }
        }
    }
    private static InvalidDataException Invalid() => MessageExceptions.Create(
        MessageText.Create("Backend.Core.RemediationCaseStore.ValidateRecord.12"), text => new InvalidDataException(text));
}
