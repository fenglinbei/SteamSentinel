using System.ComponentModel;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using SteamSentinel.Core.Inspection;
using SteamSentinel.Core.Models;
using SteamSentinel.Core.Reporting;
using SteamSentinel.Core.Rules;
using SteamSentinel.Core.Steam;
using SteamSentinel.Core.Utilities;

namespace SteamSentinel.Core.Scanning;

public sealed partial class SteamSecurityScanner
{
    internal const string LoopbackRuleId = "STEAM-UI-LOOPBACK-SCRIPT";
    private const string FamilyEndpointReason = "SteamAlertLoopbackEndpoint";
    private const int MaximumCorrelationScripts = 8;
    private const long MaximumCorrelationBytes = 64L * 1024 * 1024;
    // Only an actual local Steam scan can bind a finding to its enumerated Steam root.
    // Imported reports retain their historical observations but cannot create this proof.
    private static readonly ConditionalWeakTable<Finding, string> ScannedSteamRoots = new();

    private static Finding CreateLoopbackFinding(string steamRoot, string path, string sha256, LoopbackScriptReference script)
    {
        Finding finding = new()
        {
            RuleId = LoopbackRuleId,
            ReasonCode = script.MatchesSteamAlertEndpoint ? FamilyEndpointReason : "SteamUiLoopbackScript",
            Category = FindingCategory.Steam,
            Severity = script.MatchesSteamAlertEndpoint ? FindingSeverity.Medium : FindingSeverity.Low,
            Score = script.MatchesSteamAlertEndpoint ? 55 : 25,
            TitleText = MessageText.Create("Pawnshop.Ui.Title"),
            DescriptionText = MessageText.Create("Pawnshop.Ui.Observation"),
            EvidenceText = MessageText.Create("Pawnshop.Ui.Evidence", script.Endpoint, sha256),
            HandlingDetailsText = MessageText.Create("Pawnshop.Ui.Review"),
            Sha256 = sha256,
            Target = path,
            CanRemediate = false,
            SuggestedActions = [SuggestedActionKind.ReviewOnly]
        };
        if (script.MatchesSteamAlertEndpoint) ScannedSteamRoots.Add(finding, steamRoot);
        return finding;
    }

    internal static bool IsCurrentUserReport(ScanReport report) =>
        string.Equals(report.MachineName, Environment.MachineName, StringComparison.OrdinalIgnoreCase) &&
        string.Equals(report.UserName, Environment.UserName, StringComparison.OrdinalIgnoreCase);

    // Correlation explains a review finding only. Keep the original findings in input reports
    // immutable, and recheck the one allowlisted live resident before attributing a Steam patch.
    internal static void CorrelateLoopbackScripts(ScanReport report, RuleSet? rules = null, string? localAppData = null)
    {
        if (!IsCurrentUserReport(report)) return;
        List<(int Index, Finding Finding)> scripts = [];
        for (int i = 0; i < report.Findings.Count && scripts.Count < MaximumCorrelationScripts; i++)
        {
            Finding finding = report.Findings[i];
            if (finding.ReasonCode == FamilyEndpointReason && ScannedSteamRoots.TryGetValue(finding, out string? steam) &&
                Path.GetExtension(finding.Target).Equals(".js", StringComparison.OrdinalIgnoreCase) &&
                (ContentDiscovery.IsWithin(finding.Target, Path.Combine(steam, "steamui")) ||
                 ContentDiscovery.IsWithin(finding.Target, Path.Combine(steam, "clientui")))) scripts.Add((i, finding));
        }
        if (scripts.Count == 0 || !report.Findings.Any(f => f.RuleId == SteamAlertInstallation.ResidentRule)) return;
        HashRule? rule = (rules ?? RuleLoader.LoadEmbedded()).KnownHashes.FirstOrDefault(
            entry => entry.Id == SteamAlertInstallation.ResidentRule && entry.Malware && Validation.IsHexSha256(entry.Sha256));
        if (rule is null) return;
        string root = localAppData is null ? SteamAlertInstallation.ResidentDirectory : Path.Combine(localAppData, "SteamAlertDemo");
        string prefix = Path.TrimEndingDirectorySeparator(root) + Path.DirectorySeparatorChar;
        IEnumerable<string> residents = report.Findings.Where(finding =>
            finding.RuleId == rule.Id && finding.IsKnownMalware && finding.Category is FindingCategory.File or FindingCategory.Process &&
            finding.RelatedFilePath is null && finding.Target.Length > prefix.Length &&
            finding.Target.StartsWith(prefix, StringComparison.OrdinalIgnoreCase) &&
            finding.Target.AsSpan(prefix.Length).IndexOfAny('\\', '/', ':') < 0 &&
            (finding.ContentPath is null || string.Equals(finding.ContentPath, finding.Target, StringComparison.OrdinalIgnoreCase)) &&
            (finding.TargetSha256 is null || string.Equals(finding.TargetSha256, rule.Sha256, StringComparison.OrdinalIgnoreCase)) &&
            string.Equals(finding.Sha256, rule.Sha256, StringComparison.OrdinalIgnoreCase))
            .Select(finding => finding.Target).Distinct(StringComparer.OrdinalIgnoreCase).Take(4);
        long remaining = MaximumCorrelationBytes;
        string? resident = residents.FirstOrDefault(path => VerifyCurrentHash(path, rule.Sha256, 8 * 1024 * 1024, ref remaining));
        if (resident is null) return;

        Dictionary<string, bool> checks = new(StringComparer.OrdinalIgnoreCase);
        foreach ((int index, Finding original) in scripts)
        {
            string identity = original.Target + "|" + original.Sha256;
            if (!checks.TryGetValue(identity, out bool current))
                checks[identity] = current = VerifyCurrentHash(original.Target, original.Sha256!, MaximumScriptBytes, ref remaining);
            if (!current) continue;
            report.Findings[index] = new Finding
            {
                Id = original.Id,
                DetectedAtUtc = original.DetectedAtUtc,
                RuleId = LoopbackRuleId,
                ReasonCode = "SteamAlertResidentCorrelated",
                Category = FindingCategory.Steam,
                Severity = FindingSeverity.High,
                Score = 85,
                TitleText = original.TitleText,
                DescriptionText = MessageText.Create("Pawnshop.Ui.Correlated", resident),
                EvidenceText = original.EvidenceText,
                HandlingDetailsText = MessageText.Create("Pawnshop.Ui.Repair"),
                Sha256 = original.Sha256,
                Target = original.Target,
                CanRemediate = false,
                SuggestedActions = [SuggestedActionKind.ReviewOnly]
            };
        }
    }

    private static bool VerifyCurrentHash(string path, string expectedHash, long maximumLength, ref long remaining)
    {
        try
        {
            using FileStream stream = RelatedArtifactReader.Open(path);
            long length = stream.Length;
            if (length <= 0 || length > maximumLength || length > remaining) return false;
            remaining -= length;
            string actual = Convert.ToHexString(SHA256.HashData(stream));
            RelatedArtifactReader.ValidatePath(stream.SafeFileHandle, path);
            return actual.Equals(expectedHash, StringComparison.OrdinalIgnoreCase);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or Win32Exception) { return false; }
    }
}
