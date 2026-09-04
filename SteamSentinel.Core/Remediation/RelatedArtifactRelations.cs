using SteamSentinel.Core.Inspection;
using SteamSentinel.Core.Models;
using SteamSentinel.Core.Steam;
using SteamSentinel.Core.Utilities;

namespace SteamSentinel.Core.Remediation;

/// <summary>Exact identities, never names, parent directories, or archive-member hashes.</summary>
public static class RelatedArtifactRelations
{
    public static bool SamePath(string left, string right) => ContentDiscovery.IsLocalSafePath(left) &&
        ContentDiscovery.IsLocalSafePath(right) && Path.GetFullPath(left).Equals(Path.GetFullPath(right), StringComparison.OrdinalIgnoreCase);

    public static string? FilePath(Finding finding)
    {
        string path = finding.RelatedFilePath ?? finding.Target;
        return ContentDiscovery.IsLocalSafePath(path) && File.Exists(path) ? Path.GetFullPath(path) : null;
    }

    public static string? FileHash(Finding finding) => finding.RelatedFilePath is not null ? finding.RelatedFileSha256 :
        finding.TargetSha256 ?? (finding.ContentPath is null || SamePath(finding.ContentPath, finding.Target) ? finding.Sha256 : null);

    public static bool IsFileEvidence(Finding finding) => finding.CanRemediate &&
        finding.SuggestedActions.Contains(SuggestedActionKind.QuarantineFile) && Validation.IsHexSha256(FileHash(finding)) &&
        finding.RelatedFilePath is null && FilePath(finding) is not null;

    public static bool SupportsHeuristicEntry(Finding finding)
    {
        if (!IsFileEvidence(finding) || finding.IsKnownMalware || finding.Score < 90 ||
            finding.RuleId is not ("HEUR-STEAM-UI-PATCHER" or "HEUR-STEAM-TOKEN-STEALER" or "HEUR-STEAM-CREDENTIAL-PLUGIN") ||
            finding.ContentPath is not null && !SamePath(finding.ContentPath, finding.Target)) return false;
        try { return new FileInfo(finding.Target).Length <= 8L * 1024 * 1024; }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { return false; }
    }

    /// <summary>Close only existing report edges. Live discovery and coverage notes belong to ExpandAsync.</summary>
    public static IReadOnlyList<Finding> SelectForPlan(IEnumerable<Finding> selected, IEnumerable<Finding> allFindings, RuleSet rules)
    {
        Finding[] chosen = selected.Take(257).ToArray(), all = allFindings.Take(20001).ToArray();
        if (chosen.Length > 256 || all.Length > 20000) throw new InvalidDataException("处置关联数量超过上限，请分批选择。");
        HashSet<string> known = rules.KnownHashes.Where(r => r.Malware).Select(r => r.Sha256).ToHashSet(StringComparer.OrdinalIgnoreCase);
        List<Finding> result = [.. chosen];
        Dictionary<string, string> identities = new(StringComparer.OrdinalIgnoreCase);
        void AddIdentity(string path, string hash)
        {
            if (identities.TryGetValue(path, out string? prior) && !prior.Equals(hash, StringComparison.OrdinalIgnoreCase))
                throw new InvalidDataException("所选关联文件存在冲突身份，请重新扫描：" + path);
            identities[path] = hash;
        }
        foreach (Finding finding in chosen)
        {
            string? path = FilePath(finding), hash = FileHash(finding);
            if (path is not null && Validation.IsHexSha256(hash)) AddIdentity(path, hash!);
            // A selected entry can lead only to an existing actionable direct-target file, not arbitrary siblings.
            if (finding.RegistryKey is not null || finding.RuleId.StartsWith("PERSISTENCE-TASK", StringComparison.Ordinal))
                foreach (string target in CommandTargets.Extract(finding.ConfigurationSnapshot ?? finding.Target))
                    foreach (Finding file in all.Where(IsFileEvidence).Where(f => SamePath(f.Target, target)))
                        AddIdentity(Path.GetFullPath(file.Target), FileHash(file)!);
        }
        foreach ((string path, string hash) in identities)
        {
            Finding? file = chosen.Concat(all).FirstOrDefault(f => IsFileEvidence(f) && SamePath(f.Target, path) &&
                hash.Equals(FileHash(f), StringComparison.OrdinalIgnoreCase));
            if (file is null && known.Contains(hash)) file = new Finding
            {
                RuleId = "RELATION-KNOWN-HASH", Category = FindingCategory.File, Severity = FindingSeverity.Critical, Score = 100,
                Title = "隔离关联的已知恶意文件", Target = path, Sha256 = hash, TargetSha256 = hash,
                IsKnownMalware = true, CanRemediate = true, SuggestedActions = [SuggestedActionKind.QuarantineFile]
            };
            if (file is null) continue;
            result.Add(file);
            foreach (Finding related in all.Where(f => f.CanRemediate && f.RelatedFilePath is not null &&
                SamePath(f.RelatedFilePath, path) && hash.Equals(f.RelatedFileSha256, StringComparison.OrdinalIgnoreCase)))
            {
                bool knownBinding = known.Contains(hash);
                bool supported = knownBinding || SupportsHeuristicEntry(file) && related.SuggestedActions.All(a =>
                    a is SuggestedActionKind.RemoveRegistryValue or SuggestedActionKind.RemoveScheduledTask ||
                    a == SuggestedActionKind.StopProcess && SamePath(related.Target, path));
                if (supported) result.Add(related);
            }
        }
        return result.DistinctBy(f => f.Id).ToArray();
    }
}
