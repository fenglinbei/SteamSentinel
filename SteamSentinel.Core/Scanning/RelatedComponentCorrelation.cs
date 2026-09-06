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
        { Check(target, "关联观察合并", DiagnosticReadStatus.Failed, "目标用户发生变化，拒绝合并该轮观察。"); return; }
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
                    Detail = host.Detail,
                    ImageSha256 = host.ImageSha256,
                    SignatureStatus = host.SignatureStatus,
                    SignatureDetail = host.SignatureDetail
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
                old = new() { Id = candidate.Id, Path = candidate.Path, Reason = candidate.Reason, Status = candidate.Status, Detail = candidate.Detail };
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
            DiagnosticCheck? old = target.Checks.FirstOrDefault(c => c.Name == check.Name && c.Status == check.Status &&
                c.Detail == check.Detail && c.Required == check.Required && c.ObservationId == mapped);
            if (old is null)
            {
                if (target.Checks.Count >= 2047) { truncated = true; continue; }
                old = new() { Id = check.Id, Name = check.Name, Status = check.Status, Detail = check.Detail, Required = check.Required, ObservationId = mapped };
                target.Checks.Add(old);
            }
            ids[check.Id] = old.Id;
        }
        foreach (DiagnosticRelation relation in fresh.Relations)
        {
            if (!ids.TryGetValue(relation.FromId, out string? from) || !ids.TryGetValue(relation.ToId, out string? to))
            { truncated = true; continue; }
            DiagnosticRelation mapped = relation with { FromId = from, ToId = to };
            if (target.Relations.Contains(mapped)) continue;
            if (target.Relations.Count >= 4096) { truncated = true; continue; }
            target.Relations.Add(mapped);
        }
        if (truncated) Check(target, "累计关联观察限额", DiagnosticReadStatus.LimitReached,
            "累计来源、宿主、候选、关系或检查记录达到上限；保留原有记录，其余观察未合并。");
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
                host.SignatureDetail = finding.Description + " " + finding.Evidence;
                if (host.SignatureStatus is not ("Valid" or "Unsigned"))
                    Check(diagnostic, "宿主离线签名", DiagnosticReadStatus.NotChecked, host.SignatureDetail, host.Id);
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
                    throw new RelatedBudgetException("此轮关联身份核验超过64个文件，或目标不在可读的精确文件范围内。");
                await using FileStream lease = RelatedArtifactReader.Open(candidate.Path);
                if (lease.Length > limits.MaximumFileBytes || lease.Length > remaining())
                    throw new RelatedBudgetException("剩余关联字节预算或单文件限额不足，未把旧内容结果连接到新的路径观察。");
                candidate.Length = lease.Length;
                candidate.Sha256 = await Hashing.Sha256StreamAsync(lease, token, bytes => consumed(bytes), maximumBytes: lease.Length);
                RelatedArtifactReader.ValidatePath(lease.SafeFileHandle, System.IO.Path.GetFullPath(candidate.Path));
                candidate.VerifiedAtUtc = DateTimeOffset.UtcNow;
                candidate.Status = DiagnosticReadStatus.Complete;
                candidate.Detail = "关联前已使用拒绝写入和删除的句柄核验当前磁盘文件；加载关系仍是路径快照，不证明进程内存字节相同。";
                if (!matching.Any(f => candidate.Sha256.Equals(RelatedArtifactRelations.FileHash(f), StringComparison.OrdinalIgnoreCase)) &&
                    !(previousContentComplete && candidate.Sha256.Equals(previousHash, StringComparison.OrdinalIgnoreCase)))
                {
                    visited.Remove(candidate.Path);
                    candidate.ContentStatus = DiagnosticReadStatus.NotChecked;
                    candidate.ContentDetail = "当前文件与旧内容结果哈希不同；旧证据不连接到新来源或宿主，此身份需要重新检查。";
                    Check(diagnostic, "关联文件身份变化", DiagnosticReadStatus.NotChecked, candidate.ContentDetail, candidate.Id);
                }
            }
            catch (Exception ex) when (ex is not OperationCanceledException and not OutOfMemoryException)
            {
                candidate.Status = ex is RelatedBudgetException ? DiagnosticReadStatus.LimitReached :
                    ex is UnauthorizedAccessException || ex is System.ComponentModel.Win32Exception { NativeErrorCode: 5 }
                    ? DiagnosticReadStatus.AccessDenied : DiagnosticReadStatus.Failed;
                candidate.Detail = "未取得关联所需的当前文件身份：" + ex.Message;
                Check(diagnostic, "内容与路径观察身份复核", candidate.Status, candidate.Detail, candidate.Id);
            }
        }
    }
}
