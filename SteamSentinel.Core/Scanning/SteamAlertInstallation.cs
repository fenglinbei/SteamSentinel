using SteamSentinel.Core.Models;
using SteamSentinel.Core.Remediation;
using SteamSentinel.Core.Steam;

namespace SteamSentinel.Core.Scanning;

internal static class SteamAlertInstallation
{
    internal const string LoaderRule = "STEAMALERT-MOD-LOADER";
    internal const string ResidentRule = "STEAMALERT-RESIDENT";
    internal static string ResidentDirectory => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "SteamAlertDemo");

    // Match a physical file, never the identity of a member inside an archive.
    internal static bool IsFamilyFile(Finding finding, IReadOnlyDictionary<string, HashRule> known)
    {
        return finding.RuleId is LoaderRule or ResidentRule &&
            finding.Category == FindingCategory.File && finding.RelatedFilePath is null &&
            finding.Sha256 is { } hash && known.TryGetValue(hash, out HashRule? rule) &&
            rule.Malware && rule.Id == finding.RuleId && finding.CanRemediate &&
            (finding.TargetSha256 is null || hash.Equals(finding.TargetSha256, StringComparison.OrdinalIgnoreCase)) &&
            (finding.ContentPath is null || RelatedArtifactRelations.SamePath(finding.Target, finding.ContentPath)) &&
            ContentDiscovery.IsLocalSafePath(finding.Target) && File.Exists(finding.Target);
    }

    internal static IEnumerable<Finding> InstalledPeers(IEnumerable<Finding> findings, IReadOnlyDictionary<string, HashRule> known,
        SteamLayout layout, string residentDirectory) =>
        findings.Where(f => IsFamilyFile(f, known) && IsInstalled(f.RuleId, f.Target, layout, residentDirectory));

    // The system-only phase may finish before Workshop scanning. These paths are probes:
    // only the exact opposite component hash can add an action to the preview.
    internal static IEnumerable<string> ProbePaths(string targetRole, SteamLayout layout, string residentDirectory)
    {
        if (targetRole == ResidentRule)
        {
            yield return Path.Combine(residentDirectory, "Application Frame Host.exe");
            yield return Path.Combine(residentDirectory, "361.exe");
        }
        else if (targetRole == LoaderRule)
        {
            var roots = layout.WorkshopRoots.Concat(layout.ContentRoots.Where(root => root.Kind == "mod").Select(root => root.Path));
            foreach (string root in roots.Distinct(StringComparer.OrdinalIgnoreCase).Take(256))
            {
                yield return Path.Combine(root, "3835179592", "PWLoader.dll");
                yield return Path.Combine(root, "3835252991", "PWLoader.dll");
            }
        }
    }

    internal static string? InstalledSeedRole(Finding finding, IReadOnlyDictionary<string, HashRule> known)
    {
        if (IsFamilyFile(finding, known)) return finding.RuleId;
        if (finding.Category is not (FindingCategory.Persistence or FindingCategory.Process) ||
            !RemediationEvidencePolicy.CanRemediate(finding)) return null;
        bool directProcess = finding.Category == FindingCategory.Process && finding.RuleId == ResidentRule &&
            finding.ProcessId is not null && finding.RelatedFilePath is null;
        string? hash = directProcess ? finding.Sha256 : finding.RelatedFileSha256;
        string? path = directProcess ? finding.Target : finding.RelatedFilePath;
        return path is not null && hash is not null && known.TryGetValue(hash, out HashRule? rule) &&
            rule.Malware && rule.Id == ResidentRule && ContentDiscovery.IsLocalSafePath(path) ? ResidentRule : null;
    }

    internal static bool IsInstalled(string ruleId, string path, SteamLayout layout, string residentDirectory) => ruleId switch
    {
        ResidentRule => string.Equals(Path.GetDirectoryName(Path.GetFullPath(path)), residentDirectory, StringComparison.OrdinalIgnoreCase),
        LoaderRule => layout.ContentRoots.Any(root => root.Kind == "mod" && ContentDiscovery.IsWithin(path, root.Path)) ||
            ContentDiscovery.IsWorkshopContentPath(path) && layout.WorkshopRoots.Any(root => ContentDiscovery.IsWithin(path, root)),
        _ => false
    };
}
