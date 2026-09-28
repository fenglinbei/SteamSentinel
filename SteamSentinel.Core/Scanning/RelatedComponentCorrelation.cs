using SteamSentinel.Core.Reporting;
using SteamSentinel.Core.Models;
using SteamSentinel.Core.Remediation;
using SteamSentinel.Core.Utilities;

namespace SteamSentinel.Core.Scanning;

public sealed partial class RelatedComponentPipeline
{
    internal static void MergeDiscovery(RelatedComponentDiagnosticReport target, RelatedComponentDiagnosticReport fresh,
        RelatedComponentLimits limits)
    {
        if (target.TargetUserSid != fresh.TargetUserSid)
        { Check(target, "related.merge", MessageText.Create("Backend.Core.RelatedComponentCorrelation.MergeDiscovery.01"), DiagnosticReadStatus.Failed, MessageText.Create("Backend.Core.RelatedComponentCorrelation.MergeDiscovery.02")); return; }
        Dictionary<string, string> ids = new(StringComparer.Ordinal);
        bool truncated = false;
        static void Union(List<string> into, IEnumerable<string> values)
        { foreach (string value in values) if (!into.Contains(value)) into.Add(value); }
        IEnumerable<string> Map(IEnumerable<string> values) => values.Where(ids.ContainsKey).Select(id => ids[id]);
        foreach (RelatedSourceObservation source in fresh.Sources)
        {
            RelatedSourceObservation? old = target.Sources.FirstOrDefault(s => s.Kind == source.Kind && s.Scope == source.Scope &&
                s.Location.Equals(source.Location, StringComparison.OrdinalIgnoreCase) && s.RawCommand == source.RawCommand && s.WorkingDirectory == source.WorkingDirectory);
            if (old is null)
            {
                if (target.Sources.Count >= Math.Min(512, limits.MaximumSources)) { truncated = true; continue; }
                target.Sources.Add(source); old = source;
            }
            ids[source.Id] = old.Id;
            truncated |= RelatedComponentRecordBounds.MergeTargets(old, source.ResolvedTargets);
        }
        foreach (RelatedHostObservation host in fresh.Hosts)
        {
            RelatedHostObservation? old = target.Hosts.FirstOrDefault(h => h.ProcessId == host.ProcessId &&
                h.StartedAtUtc == host.StartedAtUtc && SamePath(h.ImagePath, host.ImagePath));
            if (old is null)
            {
                if (target.Hosts.Count >= Math.Min(32, limits.MaximumHosts)) { truncated = true; continue; }
                old = new()
                {
                    Id = host.Id,
                    ProcessId = host.ProcessId,
                    StartedAtUtc = host.StartedAtUtc,
                    ImagePath = host.ImagePath,
                    CommandLine = host.CommandLine,
                    WorkingDirectory = host.WorkingDirectory,
                    Status = host.Status,
                    DetailText = host.DetailText,
                    ImageSha256 = host.ImageSha256,
                    SignatureStatus = host.SignatureStatus,
                    SignatureDetailText = host.SignatureDetailText
                };
                target.Hosts.Add(old);
            }
            ids[host.Id] = old.Id;
            Union(old.SourceObservationIds, Map(host.SourceObservationIds));
        }
        foreach (RelatedComponentCandidate candidate in fresh.Candidates)
        {
            RelatedComponentCandidate? old = target.Candidates.FirstOrDefault(c => SamePath(c.Path, candidate.Path));
            if (old is null)
            {
                if (target.Candidates.Count >= Math.Min(128, limits.MaximumCandidates)) { truncated = true; continue; }
                old = new() { Id = candidate.Id, Path = candidate.Path, ReasonText = candidate.ReasonText, Status = candidate.Status, DetailText = candidate.DetailText };
                target.Candidates.Add(old);
            }
            ids[candidate.Id] = old.Id;
            Union(old.SourceObservationIds, Map(candidate.SourceObservationIds));
            Union(old.HostObservationIds, Map(candidate.HostObservationIds));
        }
        foreach (DiagnosticCheck check in fresh.Checks)
        {
            string? mapped = check.ObservationId is null ? null : ids.GetValueOrDefault(check.ObservationId);
            if (check.ObservationId is not null && mapped is null) { truncated = true; continue; }
            DiagnosticCheck? old = target.Checks.FirstOrDefault(c => c.Id == check.Id);
            if (old is null)
            {
                if (target.Checks.Count >= 2047) { truncated = true; continue; }
                old = new() { Id = check.Id, CheckCode = check.CheckCode, NameText = check.NameText, Status = check.Status, DetailText = check.DetailText, Required = check.Required, ObservationId = mapped };
                target.Checks.Add(old);
            }
            ids[check.Id] = old.Id;
        }
        foreach (DiagnosticRelation relation in fresh.Relations)
        {
            if (!ids.TryGetValue(relation.FromId, out string? from) || !ids.TryGetValue(relation.ToId, out string? to))
            { truncated = true; continue; }
            DiagnosticRelation mapped = relation with { FromId = from, ToId = to };
            if (target.Relations.Any(item => item.FromId == mapped.FromId && item.ToId == mapped.ToId && item.Kind == mapped.Kind && item.Evidence == mapped.Evidence)) continue;
            if (target.Relations.Count >= 4096) { truncated = true; continue; }
            target.Relations.Add(mapped);
        }
        if (truncated) Check(target, "related.total_observation_limit", MessageText.Create("Backend.Core.RelatedComponentCorrelation.MergeDiscovery.03"), DiagnosticReadStatus.LimitReached,
            MessageText.Create("Backend.Core.RelatedComponentCorrelation.MergeDiscovery.04"));
    }

    internal static void AssociateEvidence(ScanReport report)
    {
        if (report.RelatedComponentDiagnostics is not { } diagnostic) return;
        // This does not add or upgrade actions. Existing content rules retain their own proof requirements.
        foreach (Finding finding in report.Findings.Where(f => f.SourceKind != SourceKind && f.RelatedFilePath is null &&
            f.Category is FindingCategory.File or FindingCategory.Archive && (f.IsKnownMalware || f.Severity >= FindingSeverity.Medium)))
        {
            string? hash = RelatedArtifactRelations.FileHash(finding);
            if (!Validation.IsHexSha256(hash)) continue;
            RelatedComponentCandidate? candidate = diagnostic.Candidates.FirstOrDefault(c => SamePath(c.Path, finding.Target));
            if (candidate is null) continue;
            // Path coincidence alone cannot join an older content hash to a newer module snapshot.
            if (candidate.Status != DiagnosticReadStatus.Complete || candidate.VerifiedAtUtc is null ||
                candidate.Sha256 is null || !candidate.Sha256.Equals(hash, StringComparison.OrdinalIgnoreCase)) continue;
            foreach (string id in new[] { candidate.Id }.Concat(candidate.SourceObservationIds).Concat(candidate.HostObservationIds))
                if (!finding.AssociationObservationIds.Contains(id)) finding.AssociationObservationIds.Add(id);
            finding.AssociationEvidenceTier = finding.IsKnownMalware && RelatedArtifactRelations.IsFileEvidence(finding)
                ? RelatedEvidenceTier.ConfirmedTarget : RelatedEvidenceTier.RelatedRisk;
        }
    }

    private static void ApplySignatureResults(ScanReport report, ScanReport content)
    {
        if (report.RelatedComponentDiagnostics is not { } diagnostic) return;
        foreach (Finding finding in content.Findings.Where(f => f.RuleId == "ASSOCIATION-HOST-SIGNATURE"))
            foreach (RelatedHostObservation host in diagnostic.Hosts.Where(h => SamePath(h.ImagePath, finding.Target)))
            {
                host.ImageSha256 = finding.TargetSha256 ?? finding.Sha256;
                host.SignatureStatus = finding.ConfigurationKind ?? "NotChecked";
                host.SignatureDetailText = finding.DescriptionText + " " + finding.EvidenceText;
                if (host.SignatureStatus is not ("Valid" or "Unsigned"))
                    Check(diagnostic, "related.host_signature", MessageText.Create("Backend.Core.RelatedComponentCorrelation.ApplySignatureResults.01"), DiagnosticReadStatus.NotChecked, host.SignatureDetailText, host.Id);
            }
        content.Findings.RemoveAll(f => f.RuleId == "ASSOCIATION-HOST-SIGNATURE");
    }

    private static async Task RefreshEvidenceIdentitiesAsync(ScanReport report, ScanOptions options, RelatedComponentLimits limits,
        HashSet<string> visited, Func<long> remaining, Action<long> consumed, CancellationToken token)
    {
        RelatedComponentDiagnosticReport diagnostic = report.RelatedComponentDiagnostics!;
        Finding[] risks = report.Findings.Where(f => f.SourceKind != SourceKind && f.RelatedFilePath is null &&
            f.Category is FindingCategory.File or FindingCategory.Archive && (f.IsKnownMalware || f.Severity >= FindingSeverity.Medium) &&
            Validation.IsHexSha256(RelatedArtifactRelations.FileHash(f))).Reverse().ToArray();
        RelatedComponentCandidate[] candidates = risks.Select(f => diagnostic.Candidates.FirstOrDefault(c => SamePath(c.Path, f.Target)))
            .OfType<RelatedComponentCandidate>().DistinctBy(c => c.Id).ToArray();
        int read = 0;
        foreach (RelatedComponentCandidate candidate in candidates)
        {
            Finding[] matching = risks.Where(f => SamePath(f.Target, candidate.Path)).ToArray();
            foreach (Finding finding in matching) { finding.AssociationObservationIds.Clear(); finding.AssociationEvidenceTier = null; }
            string? previousHash = candidate.Sha256;
            bool previousContentComplete = candidate.ContentStatus == DiagnosticReadStatus.Complete;
            candidate.Sha256 = null; candidate.VerifiedAtUtc = null;
            try
            {
                token.ThrowIfCancellationRequested();
                if (++read > 64 || !IsSafeCandidate(candidate.Path, options))
                    throw MessageExceptions.Create(MessageText.Create("Backend.Core.RelatedComponentCorrelation.RefreshEvidenceIdentitiesAsync.01"), sourceText => new RelatedBudgetException(sourceText));
                await using FileStream lease = RelatedArtifactReader.Open(candidate.Path);
                if (lease.Length > limits.MaximumFileBytes || lease.Length > remaining())
                    throw MessageExceptions.Create(MessageText.Create("Backend.Core.RelatedComponentCorrelation.RefreshEvidenceIdentitiesAsync.02"), sourceText => new RelatedBudgetException(sourceText));
                candidate.Length = lease.Length;
                candidate.Sha256 = await Hashing.Sha256StreamAsync(lease, token, bytes => consumed(bytes), maximumBytes: lease.Length);
                RelatedArtifactReader.ValidatePath(lease.SafeFileHandle, System.IO.Path.GetFullPath(candidate.Path));
                candidate.VerifiedAtUtc = DateTimeOffset.UtcNow;
                candidate.Status = DiagnosticReadStatus.Complete;
                candidate.DetailText = MessageText.Create("Backend.Core.RelatedComponentCorrelation.RefreshEvidenceIdentitiesAsync.03");
                if (!matching.Any(f => candidate.Sha256.Equals(RelatedArtifactRelations.FileHash(f), StringComparison.OrdinalIgnoreCase)) &&
                    !(previousContentComplete && candidate.Sha256.Equals(previousHash, StringComparison.OrdinalIgnoreCase)))
                {
                    visited.Remove(candidate.Path);
                    candidate.ContentStatus = DiagnosticReadStatus.NotChecked;
                    candidate.ContentDetailText = MessageText.Create("Backend.Core.RelatedComponentCorrelation.RefreshEvidenceIdentitiesAsync.04");
                    Check(diagnostic, "related.file_changed", MessageText.Create("Backend.Core.RelatedComponentCorrelation.RefreshEvidenceIdentitiesAsync.05"), DiagnosticReadStatus.NotChecked, candidate.ContentDetailText, candidate.Id);
                }
            }
            catch (Exception ex) when (ex is not OperationCanceledException and not OutOfMemoryException)
            {
                candidate.Status = ex is RelatedBudgetException ? DiagnosticReadStatus.LimitReached :
                    ex is UnauthorizedAccessException || ex is System.ComponentModel.Win32Exception { NativeErrorCode: 5 }
                    ? DiagnosticReadStatus.AccessDenied : DiagnosticReadStatus.Failed;
                candidate.DetailText = MessageText.Create("Backend.Core.RelatedComponentCorrelation.RefreshEvidenceIdentitiesAsync.06") + MessageExceptions.Describe(ex);
                Check(diagnostic, "related.content_identity", MessageText.Create("Backend.Core.RelatedComponentCorrelation.RefreshEvidenceIdentitiesAsync.07"), candidate.Status, candidate.DetailText, candidate.Id);
            }
        }
    }
}
