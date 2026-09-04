using SteamSentinel.Core.Inspection;
using SteamSentinel.Core.Models;
using SteamSentinel.Core.Steam;

namespace SteamSentinel.Core.Remediation;

public static class FindingReviewTargets
{
    public static List<string> Get(Finding finding)
    {
        List<string> candidates = [finding.Target];
        if (finding.RelatedFilePath is not null) candidates.Add(finding.RelatedFilePath);
        candidates.AddRange(CommandTargets.Extract(finding.ConfigurationSnapshot ?? finding.Target));
        // Only local paths are offered. No URLs, shell commands or archive-member execution.
        return candidates.Where(p => ContentDiscovery.IsLocalSafePath(p) &&
                (File.Exists(p) || Directory.Exists(p)))
            .Select(Path.GetFullPath).Distinct(StringComparer.OrdinalIgnoreCase).Take(32).ToList();
    }
}
