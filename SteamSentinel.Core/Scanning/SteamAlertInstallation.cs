using SteamSentinel.Core.Models;
using SteamSentinel.Core.Inspection;
using SteamSentinel.Core.Remediation;
using SteamSentinel.Core.Steam;
using SteamSentinel.Core.Utilities;

namespace SteamSentinel.Core.Scanning;

public static class SteamAlertInstallation
{
    public const string LoaderRule = "STEAMALERT-MOD-LOADER";
    public const string ResidentRule = "STEAMALERT-RESIDENT";
    public const string UpdatedResidentRule = "STEAMALERT-RESIDENT-20261117";
    public static string ResidentDirectory => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "SteamAlertDemo");
    public static string UpdaterDirectory => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "SteamAlertUpdater");

    internal static readonly string[] FamilyRoles = [LoaderRule, ResidentRule,
        SteamAlertWatchdog.WatchdogRole, SteamAlertWatchdog.UpdaterRole, SteamAlertWatchdog.LauncherRole];

    internal static string? FamilyRole(string ruleId) => ruleId switch
    {
        LoaderRule => LoaderRule,
        ResidentRule or UpdatedResidentRule or SteamAlertEmbeddedEvidence.RuleId => ResidentRule,
        SteamAlertWatchdog.WatchdogRole or "STEAMALERT-WATCHDOG-NOBOM" => SteamAlertWatchdog.WatchdogRole,
        SteamAlertWatchdog.UpdaterRole or "STEAMALERT-UPDATER-NOBOM" => SteamAlertWatchdog.UpdaterRole,
        SteamAlertWatchdog.LauncherRole or "STEAMALERT-LAUNCHER-NOBOM" => SteamAlertWatchdog.LauncherRole,
        _ => null
    };

    public static IEnumerable<string> UpdaterDirectories(string residentDirectory, string? updaterDirectory = null)
    {
        yield return updaterDirectory ?? UpdaterDirectory;
        yield return Path.Combine(residentDirectory, "Updater");
    }

    // Match a physical file, never the identity of a member inside an archive.
    internal static bool IsFamilyFile(Finding finding, IReadOnlyDictionary<string, HashRule> known)
    {
        bool knownFamily = FamilyRole(finding.RuleId) is not null && finding.Sha256 is { } knownHash &&
            known.TryGetValue(knownHash, out HashRule? rule) && rule.Malware && rule.Id == finding.RuleId;
        bool embedded = finding.RuleId == SteamAlertEmbeddedEvidence.RuleId && finding.ReasonCode == SteamAlertEmbeddedEvidence.ReasonCode &&
            Validation.IsHexSha256(finding.Sha256);
        return (knownFamily || embedded) &&
            finding.Category == FindingCategory.File && finding.RelatedFilePath is null &&
            finding.Sha256 is { } hash && finding.CanRemediate &&
            (finding.TargetSha256 is null || hash.Equals(finding.TargetSha256, StringComparison.OrdinalIgnoreCase)) &&
            (finding.ContentPath is null || RelatedArtifactRelations.SamePath(finding.Target, finding.ContentPath)) &&
            ContentDiscovery.IsLocalSafePath(finding.Target) && File.Exists(finding.Target);
    }

    internal static IEnumerable<Finding> InstalledPeers(IEnumerable<Finding> findings, IReadOnlyDictionary<string, HashRule> known,
        SteamLayout layout, string residentDirectory, string? updaterDirectory = null) =>
        findings.Where(f => IsFamilyFile(f, known) && IsInstalled(f.RuleId, f.Target, layout, residentDirectory, updaterDirectory));

    // The system-only phase may finish before Workshop scanning. These paths are probes:
    // only a verified family component identity can add an action to the preview.
    public static IEnumerable<string> ProbePaths(string targetRole, SteamLayout layout, string residentDirectory, string? updaterDirectory = null)
    {
        if (targetRole == ResidentRule)
        {
            yield return Path.Combine(residentDirectory, "Application Frame Host.exe");
            yield return Path.Combine(residentDirectory, "361.exe");
            yield return Path.Combine(residentDirectory, "Application Frame Host.new.exe");
            yield return Path.Combine(residentDirectory, "Application Frame Host.exe.old");
            yield return Path.Combine(residentDirectory, "Application Frame Host.exe.bak");
            foreach (string directory in UpdaterDirectories(residentDirectory, updaterDirectory))
                yield return Path.Combine(directory, "cache", "new.exe");
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
        else
        {
            string[] names = targetRole switch
            {
                SteamAlertWatchdog.WatchdogRole => ["sa_watch.ps1"],
                SteamAlertWatchdog.UpdaterRole => ["sa_updater.ps1", "update.ps1"],
                SteamAlertWatchdog.LauncherRole => ["sa_launch.ps1"],
                _ => []
            };
            foreach (string directory in UpdaterDirectories(residentDirectory, updaterDirectory))
                foreach (string name in names) yield return Path.Combine(directory, name);
        }
    }

    internal static string? InstalledSeedRole(Finding finding, IReadOnlyDictionary<string, HashRule> known)
    {
        if (IsFamilyFile(finding, known)) return FamilyRole(finding.RuleId);
        if (finding.Category is not (FindingCategory.Persistence or FindingCategory.Process) ||
            !RemediationEvidencePolicy.CanRemediate(finding)) return null;
        bool directProcess = finding.Category == FindingCategory.Process && FamilyRole(finding.RuleId) is not null &&
            finding.ProcessId is not null && finding.RelatedFilePath is null;
        string? hash = directProcess ? finding.Sha256 : finding.RelatedFileSha256;
        string? path = directProcess ? finding.Target : finding.RelatedFilePath;
        if (finding.ReasonCode == SteamAlertEmbeddedEvidence.ReasonCode && path is not null && Validation.IsHexSha256(hash) &&
            ContentDiscovery.IsLocalSafePath(path)) return ResidentRule;
        return path is not null && hash is not null && known.TryGetValue(hash, out HashRule? rule) &&
            rule.Malware && ContentDiscovery.IsLocalSafePath(path) ? FamilyRole(rule.Id) : null;
    }

    public static bool IsInstalled(string ruleId, string path, SteamLayout layout, string residentDirectory,
        string? updaterDirectory = null) => ruleId == SteamAlertEmbeddedEvidence.RuleId
        ? IsInstalledResidentPath(path, residentDirectory) : FamilyRole(ruleId) switch
        {
            ResidentRule => IsInstalledResidentPath(path, residentDirectory) ||
                ProbePaths(ResidentRule, layout, residentDirectory, updaterDirectory).Any(probe => RelatedArtifactRelations.SamePath(path, probe)),
            SteamAlertWatchdog.WatchdogRole or SteamAlertWatchdog.UpdaterRole or SteamAlertWatchdog.LauncherRole =>
                ContentDiscovery.IsLocalSafePath(path) && Path.GetExtension(path).Equals(".ps1", StringComparison.OrdinalIgnoreCase) &&
                UpdaterDirectories(residentDirectory, updaterDirectory).Any(directory =>
                    RelatedArtifactRelations.SamePath(Path.GetDirectoryName(Path.GetFullPath(path))!, directory)),
            LoaderRule => layout.ContentRoots.Any(root => root.Kind == "mod" && ContentDiscovery.IsWithin(path, root.Path)) ||
                ContentDiscovery.IsWorkshopContentPath(path) && layout.WorkshopRoots.Any(root => ContentDiscovery.IsWithin(path, root)),
            _ => false
        };

    public static bool IsInstalledResidentPath(string path, string residentDirectory) => ContentDiscovery.IsLocalSafePath(path) &&
        Path.GetExtension(path).Equals(".exe", StringComparison.OrdinalIgnoreCase) &&
        string.Equals(Path.GetDirectoryName(Path.GetFullPath(path)), Path.GetFullPath(residentDirectory), StringComparison.OrdinalIgnoreCase);
}
