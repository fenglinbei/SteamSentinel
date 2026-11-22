using System.IO;
using System.Diagnostics;
using Microsoft.Win32;
using SteamSentinel.Core.Models;
using SteamSentinel.Core.Remediation;
using SteamSentinel.Core.Scanning;
using SteamSentinel.Core.Utilities;

namespace SteamSentinel.SelfTest;

internal static partial class Program
{
    private static async Task TestScannedFileContainmentAsync(string root)
    {
        string directory = Path.Combine(root, "scanned-file-containment");
        Directory.CreateDirectory(directory);
        string file = Path.Combine(directory, "inert-never-executed.exe");
        await File.WriteAllTextAsync(file, "SteamSentinel inert containment fixture; not an executable.");
        string hash = await Hashing.Sha256FileAsync(file);
        RuleSet rules = new()
        {
            KnownHashes = [new() { Id = "INERT-CONTAINMENT-TEST", Sha256 = hash, Malware = true, Remediable = true }],
            KnownDomains = ["containment-fixture.invalid"]
        };
        Finding finding = new()
        {
            RuleId = "INERT-CONTAINMENT-TEST",
            Category = FindingCategory.File,
            Target = file,
            Sha256 = hash,
            TargetSha256 = hash,
            IsKnownMalware = true,
            CanRemediate = true,
            Score = 100,
            SuggestedActions = [SuggestedActionKind.QuarantineFile]
        };
        ScanReport Report(ScanMode mode, string customRoot) => new()
        {
            Mode = mode,
            Findings = [finding],
            ContentScanSettings = new()
            {
                Mode = mode,
                CustomRoots = [customRoot],
                IncludeSystem = false,
                IncludeSteam = false,
                IncludeWorkshop = false,
                UseAmsi = false
            }
        };
        RemediationAction[] Actions(RemediationBatchSession session) => session.Plans.SelectMany(plan => plan.Actions).ToArray();
        bool HasQuarantine(RemediationAction[] actions) => actions.Count(action => action.Type == RemediationActionType.QuarantineFile &&
            action.Target == file && action.ExpectedSha256 == hash && action.IsKnownMalware) == 1;

        RemediationBatchSession directoryScan = await new RemediationBatchPlanner(rules, LiveAssociationProbeMode.InertEmptyHost).PrepareAsync(
            [finding], Report(ScanMode.Custom, directory), false);
        RemediationAction[] directoryActions = Actions(directoryScan);
        Check("custom directory sample preparation only quarantines the verified file", directoryActions.Length == 1 &&
            HasQuarantine(directoryActions) && directoryScan.Targets.Single().MissingActions.Count == 0);

        RemediationBatchSession singleFileScan = await new RemediationBatchPlanner(rules, LiveAssociationProbeMode.InertEmptyHost).PrepareAsync(
            [finding], Report(ScanMode.Custom, file), false);
        RemediationAction[] singleFileActions = Actions(singleFileScan);
        Check("custom exact-file sample preparation does not add a program firewall rule", singleFileActions.Length == 1 &&
            HasQuarantine(singleFileActions) && singleFileScan.Targets.Single().MissingActions.Count == 0);

        RemediationAction[] driveActions = Actions(await new RemediationBatchPlanner(rules, LiveAssociationProbeMode.InertEmptyHost).PrepareAsync(
            [finding], Report(ScanMode.Custom, Path.GetPathRoot(file)!), false));
        Check("custom drive root includes its file descendants", driveActions.Length == 1 && HasQuarantine(driveActions));

        RemediationAction[] siblingActions = Actions(await new RemediationBatchPlanner(rules, LiveAssociationProbeMode.InertEmptyHost).PrepareAsync(
            [finding], Report(ScanMode.Custom, directory + "-other"), false));
        Check("custom sample containment does not cross directory boundaries", HasQuarantine(siblingActions) &&
            siblingActions.Any(a => a.Type == RemediationActionType.AddProgramFirewallBlock));

        ScanReport observedAssociation = Report(ScanMode.Custom, directory);
        observedAssociation.Findings.Add(new()
        {
            Category = FindingCategory.Process,
            Target = "an observed script host",
            RelatedFilePath = file,
            RelatedFileSha256 = hash,
            CanRemediate = false,
            SuggestedActions = [SuggestedActionKind.ReviewOnly]
        });
        RemediationAction[] observedActions = Actions(await new RemediationBatchPlanner(rules, LiveAssociationProbeMode.InertEmptyHost).PrepareAsync(
            [finding], observedAssociation, false));
        Check("a review-only live association retains the executable block without authorizing a process stop",
            observedActions.Length == 2 && HasQuarantine(observedActions) &&
            observedActions.Count(a => a.Type == RemediationActionType.AddProgramFirewallBlock) == 1);

        bool inspected = false;
        RemediationAction[] incompleteActions = Actions(await new RemediationBatchPlanner(rules, LiveAssociationProbeMode.InertEmptyHost).PrepareAsync(
            [finding], Report(ScanMode.Custom, directory), false, (candidates, _) =>
            {
                inspected = candidates.Contains(file, StringComparer.OrdinalIgnoreCase);
                return Task.FromResult(new ScanReport { Coverage = ScanCoverage.Partial });
            }));
        Check("incomplete candidate inspection retains containment without inspecting warning text", inspected &&
            HasQuarantine(incompleteActions) && incompleteActions.Any(a => a.Type == RemediationActionType.AddProgramFirewallBlock));

        using Process remaining = Process.GetCurrentProcess();
        HashSet<string> imageNames = new(StringComparer.OrdinalIgnoreCase) { remaining.ProcessName };
        Check("module cap distinguishes a remaining matching image or associated PID from unrelated processes",
            RelatedArtifactScanner.RemainingProgramImagePossible([remaining], imageNames, new HashSet<int>(), default) &&
            RelatedArtifactScanner.RemainingProgramImagePossible([remaining], new HashSet<string>(), new HashSet<int> { remaining.Id }, default) &&
            !RelatedArtifactScanner.RemainingProgramImagePossible([remaining], new HashSet<string>(), new HashSet<int>(), default));

        RemediationBatchSession selectedDomains = await new RemediationBatchPlanner(rules, LiveAssociationProbeMode.InertEmptyHost).PrepareAsync(
            [finding], Report(ScanMode.Custom, file), true);
        RemediationAction[] domainActions = Actions(selectedDomains);
        Check("custom sample preparation preserves an explicitly selected hosts block", domainActions.Length == 2 &&
            HasQuarantine(domainActions) && domainActions.SingleOrDefault(action => action.Type == RemediationActionType.BlockKnownDomains)
                is { Target: "hosts" } hosts && hosts.Domains.SequenceEqual(rules.KnownDomains) &&
            domainActions.All(action => action.Type != RemediationActionType.AddProgramFirewallBlock));

        RemediationBatchSession fullScan = await new RemediationBatchPlanner(rules, LiveAssociationProbeMode.InertEmptyHost).PrepareAsync(
            [finding], Report(ScanMode.Full, directory), false);
        RemediationAction[] fullActions = Actions(fullScan);
        Check("full scan preparation retains automatic program containment", fullActions.Length == 2 && HasQuarantine(fullActions) &&
            fullActions.Count(action => action.Type == RemediationActionType.AddProgramFirewallBlock && action.Target == file &&
                action.ExpectedSha256 == hash) == 1);

        // Exercise real association discovery with a unique inert RunOnce entry. The target
        // contains plain text and is never launched; no prepared remediation is executed.
        const string runKeyPath = @"Software\Microsoft\Windows\CurrentVersion\RunOnce";
        string valueName = "SteamSentinel-Inert-Containment-" + Guid.NewGuid().ToString("N");
        using RegistryKey runKey = Registry.CurrentUser.CreateSubKey(runKeyPath, writable: true)
            ?? throw new InvalidOperationException("Could not create the owned inert RunOnce fixture.");
        try
        {
            runKey.SetValue(valueName, "\"" + file + "\"", RegistryValueKind.String);
            RemediationBatchSession activeEntry = await new RemediationBatchPlanner(rules).PrepareAsync(
                [finding], Report(ScanMode.Custom, directory), false);
            RemediationAction[] activeActions = Actions(activeEntry);
            Check("custom sample preparation retains containment after discovering a live startup association", HasQuarantine(activeActions) &&
                activeActions.Count(action => action.Type == RemediationActionType.AddProgramFirewallBlock && action.Target == file &&
                    action.ExpectedSha256 == hash) == 1 &&
                activeActions.Any(action => action.Type == RemediationActionType.RemoveRegistryValue &&
                    action.RegistryHive == "HKCU" && action.RegistryKey == runKeyPath && action.RegistryValueName == valueName &&
                    action.RelatedFilePath == file && action.RelatedFileSha256 == hash));
            Check("containment preparation leaves the inert file and startup fixture unchanged", File.Exists(file) &&
                await Hashing.Sha256FileAsync(file) == hash && runKey.GetValue(valueName)?.ToString() == "\"" + file + "\"");
        }
        finally { runKey.DeleteValue(valueName, throwOnMissingValue: false); }
    }
}
