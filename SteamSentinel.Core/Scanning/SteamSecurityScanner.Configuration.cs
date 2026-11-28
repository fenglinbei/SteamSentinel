using System.Text.Json;
using Microsoft.Win32;
using Microsoft.Win32.SafeHandles;
using SteamSentinel.Core.Inspection;
using SteamSentinel.Core.Models;
using SteamSentinel.Core.Remediation;
using SteamSentinel.Core.Reporting;
using SteamSentinel.Core.Steam;
using SteamSentinel.Core.Utilities;

namespace SteamSentinel.Core.Scanning;

public sealed partial class SteamSecurityScanner
{
    /// <summary>当 Steam 目录存在官方分包清单时，校验根目录 steam.exe 的 Valve 数字签名及完整性。</summary>
    internal static async Task ScanSteamClientBinaryAsync(
        string steamRoot,
        SteamPackageCatalog? catalog,
        ScanReport report,
        CancellationToken token,
        Func<string, SafeFileHandle?, SignatureResult>? verifyBinarySignature = null)
    {
        if (catalog is null || !ContentDiscovery.IsLocalSafePath(steamRoot))
        {
            return;
        }

        string steamExePath = Path.Combine(steamRoot, "steam.exe");
        if (!ContentDiscovery.IsLocalSafePath(steamExePath))
        {
            ConfigurationScanIncomplete(report, steamExePath);
            return;
        }

        if (!File.Exists(steamExePath))
        {
            report.Findings.Add(new Finding
            {
                RuleId = "STEAM-CLIENT-BINARY-MISSING",
                Category = FindingCategory.Steam,
                Severity = FindingSeverity.High,
                Score = 85,
                TitleText = MessageText.Create("Steam.ClientBinary.MissingTitle"),
                DescriptionText = MessageText.Create("Steam.ClientBinary.MissingDescription"),
                EvidenceText = MessageText.Create("Steam.ClientBinary.MissingEvidence", steamExePath),
                HandlingDetailsText = MessageText.Create("Steam.ClientBinary.FallbackGuidance"),
                Target = Path.GetFullPath(steamExePath),
                IsKnownMalware = false,
                CanRemediate = false,
                SuggestedActions = [SuggestedActionKind.ReviewOnly]
            });
            return;
        }

        try
        {
            await using FileStream stream = RelatedArtifactReader.Open(steamExePath);
            long length = stream.Length;
            bool withinPackageLimit = length is > 0 and <= SteamConfigurationRepair.MaximumPackageRestoreBytes;
            string sha256 = await Hashing.Sha256StreamAsync(
                stream,
                token,
                bytes => report.Metrics.BytesHashed += bytes,
                maximumBytes: SteamPackageArchive.MaximumLocalPackageBytes).ConfigureAwait(false);
            string fullPath = Path.GetFullPath(steamExePath);
            RelatedArtifactReader.ValidatePath(stream.SafeFileHandle, fullPath);

            SignatureResult sig = verifyBinarySignature is not null
                ? verifyBinarySignature(fullPath, stream.SafeFileHandle)
                : AuthenticodeVerifier.VerifyOffline(fullPath, stream.SafeFileHandle);
            bool trustedValve = sig.Status == SignatureStatus.Valid &&
                (sig.IsValveSigner || AuthenticodeVerifier.IsTrustedValveSigner(sig.Status, sig.SignerSubject));
            if (trustedValve)
            {
                return;
            }

            bool canPackageRestore = withinPackageLimit &&
                catalog.IsKnownOfficialRelativePath("steam.exe") &&
                catalog.OrderCandidatePackages("steam.exe").Count > 0;

            report.Findings.Add(new Finding
            {
                RuleId = "STEAM-CLIENT-BINARY-TAMPERED",
                Category = FindingCategory.Steam,
                Severity = FindingSeverity.Critical,
                Score = 95,
                TitleText = MessageText.Create("Steam.ClientBinary.TamperedTitle"),
                DescriptionText = MessageText.Create("Steam.ClientBinary.TamperedDescription"),
                EvidenceText = MessageText.Create("Steam.ClientBinary.TamperedEvidence", sig.DetailText, sig.SignerSubject ?? "-", sha256),
                HandlingDetailsText = MessageText.Create(canPackageRestore ? "SteamConfig.PackageRestoreDescription" : "Steam.ClientBinary.FallbackGuidance"),
                Target = fullPath,
                Sha256 = sha256,
                TargetSha256 = canPackageRestore ? sha256 : null,
                ConfigurationKind = canPackageRestore ? SteamConfigurationRepair.PackageRestore : null,
                IsKnownMalware = false,
                CanRemediate = canPackageRestore,
                SuggestedActions = canPackageRestore ? [SuggestedActionKind.RepairSteamConfiguration] : [SuggestedActionKind.ReviewOnly]
            });
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or System.ComponentModel.Win32Exception or InvalidDataException)
        {
            ConfigurationScanIncomplete(report, steamExePath);
        }
    }
    internal static async Task ScanSteamConfigurationFileAsync(string path, string kind, ScanReport report, CancellationToken token,
        SteamLayout? layout = null)
    {
        if (!File.Exists(path)) return;
        try
        {
            await using FileStream input = RelatedArtifactReader.Open(path);
            byte[] bytes = await SteamConfigurationRepairTarget.ReadBytesAsync(input, token);
            bool repairable = kind == SteamConfigurationRepair.Marker;
            bool paired = false;
            if (kind == SteamConfigurationRepair.Cfg) repairable = SteamConfigurationRepair.TryRepairCfg(bytes, out _, out paired);
            // Most shortcuts are unrelated. Inspect their bounded argument structure before
            // any local PIDL/share verification, and never infer evidence from raw substrings.
            if (kind == SteamConfigurationRepair.Shortcut && !SteamConfigurationRepair.HasDebugShortcutArguments(bytes)) return;
            if (kind == SteamConfigurationRepair.Shortcut)
                repairable = layout is not null && SteamConfigurationRepair.TryRepairShortcut(bytes, layout, out _, out _);
            bool shortcutReview = kind == SteamConfigurationRepair.Shortcut && !repairable;
            RelatedArtifactReader.ValidatePath(input.SafeFileHandle, Path.GetFullPath(path));
            string hash = SteamConfigurationRepair.Hash(bytes);
            report.Metrics.BytesHashed += bytes.Length;
            report.Findings.Add(new()
            {
                RuleId = shortcutReview ? SteamConfigurationRepair.ShortcutReviewRule : kind == SteamConfigurationRepair.Cfg ? paired ? "STEAM-CFG-UPDATE-SUPPRESSION-PAIR" : repairable ? "STEAM-CFG-CONTROL-SETTING" : "STEAM-CFG-PRESENT"
                    : kind == SteamConfigurationRepair.Marker ? "STEAM-DEBUG-MARKER" : "STEAM-SHORTCUT-DEBUG-ARGUMENT",
                Category = FindingCategory.Steam,
                Severity = paired ? FindingSeverity.High : repairable || shortcutReview ? FindingSeverity.Medium : FindingSeverity.Low,
                Score = paired ? 85 : repairable || shortcutReview ? 45 : 15,
                TitleText = MessageText.Create(shortcutReview ? "SteamConfig.ShortcutReviewTitle" : kind == SteamConfigurationRepair.Cfg ? repairable ? "SteamConfig.CfgTitle" : "Backend.Core.SteamSecurityScanner.ScanSensitiveRootFilesAsync.03"
                    : kind == SteamConfigurationRepair.Marker ? "SteamConfig.MarkerTitle" : "SteamConfig.ArgumentsTitle"),
                DescriptionText = MessageText.Create(shortcutReview ? "SteamConfig.ShortcutReviewDescription" : kind == SteamConfigurationRepair.Cfg ? repairable ? "SteamConfig.CfgDescription" : "Backend.Core.SteamSecurityScanner.ScanSensitiveRootFilesAsync.06"
                    : kind == SteamConfigurationRepair.Marker ? "SteamConfig.MarkerDescription" : "SteamConfig.ArgumentsDescription"),
                HandlingDetailsText = repairable ? MessageText.Create("SteamConfig.Handling") : (MessageText)"",
                EvidenceText = MessageText.Create("SteamConfig.Evidence", hash, kind),
                Target = path,
                Sha256 = hash,
                TargetSha256 = hash,
                ConfigurationKind = kind,
                IsKnownMalware = false,
                CanRemediate = repairable,
                SuggestedActions = repairable ? [SuggestedActionKind.RepairSteamConfiguration] : [SuggestedActionKind.ReviewOnly]
            });
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or System.ComponentModel.Win32Exception or System.Security.SecurityException)
        { ConfigurationScanIncomplete(report, path); }
    }

    private static async Task ScanSteamLaunchConfigurationAsync(SteamLayout layout, ScanReport report, CancellationToken token)
    {
        if (layout.SteamRoots.Count == 0) return;
        foreach ((RegistryHive hive, RegistryView view) in new[]
        {
            (RegistryHive.CurrentUser, RegistryView.Default), (RegistryHive.LocalMachine, RegistryView.Registry32),
            (RegistryHive.LocalMachine, RegistryView.Registry64)
        })
            foreach (string keyPath in new[] { @"Software\Microsoft\Windows\CurrentVersion\Run", @"Software\Microsoft\Windows\CurrentVersion\RunOnce" })
            {
                token.ThrowIfCancellationRequested();
                try
                {
                    using RegistryKey baseKey = RegistryKey.OpenBaseKey(hive, view);
                    using RegistryKey? key = baseKey.OpenSubKey(keyPath);
                    if (key is null) continue;
                    string[] names = key.GetValueNames();
                    if (names.Length > 4096) ConfigurationScanIncomplete(report, keyPath);
                    foreach (string name in names.Take(4096))
                    {
                        if (key.GetValue(name, null, RegistryValueOptions.DoNotExpandEnvironmentNames) is not string value ||
                            !SteamConfigurationRepair.TryRepairCommand(value, layout, out string repaired, out string executable)) continue;
                        RegistryValueKind kind = key.GetValueKind(name);
                        if (kind is not (RegistryValueKind.String or RegistryValueKind.ExpandString)) continue;
                        string hiveName = hive == RegistryHive.CurrentUser ? "HKCU" : "HKLM";
                        report.Findings.Add(new()
                        {
                            RuleId = "STEAM-RUN-DEBUG-ARGUMENT",
                            Category = FindingCategory.Steam,
                            Severity = FindingSeverity.Medium,
                            Score = 45,
                            TitleText = MessageText.Create("SteamConfig.ArgumentsTitle"),
                            DescriptionText = MessageText.Create("SteamConfig.ArgumentsDescription"),
                            HandlingDetailsText = MessageText.Create("SteamConfig.Handling"),
                            Target = $"{hiveName}\\{keyPath}\\{name}",
                            RelatedFilePath = executable,
                            ConfigurationKind = SteamConfigurationRepair.Run,
                            ConfigurationSnapshot = JsonSerializer.Serialize(new SteamConfigurationSnapshot(SteamConfigurationRepair.Run, executable, value, repaired, (int)kind)),
                            RegistryHive = hiveName,
                            RegistryView = view.ToString(),
                            RegistryKey = keyPath,
                            RegistryValueName = name,
                            IsKnownMalware = false,
                            CanRemediate = true,
                            SuggestedActions = [SuggestedActionKind.RepairSteamConfiguration]
                        });
                    }
                }
                catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or System.Security.SecurityException)
                { ConfigurationScanIncomplete(report, keyPath); }
            }
        HashSet<string> visited = new(StringComparer.OrdinalIgnoreCase);
        foreach (string root in new[]
        {
            Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory), Environment.GetFolderPath(Environment.SpecialFolder.CommonDesktopDirectory),
            Environment.GetFolderPath(Environment.SpecialFolder.StartMenu), Environment.GetFolderPath(Environment.SpecialFolder.CommonStartMenu),
            Environment.GetFolderPath(Environment.SpecialFolder.Startup), Environment.GetFolderPath(Environment.SpecialFolder.CommonStartup),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), @"Microsoft\Internet Explorer\Quick Launch\User Pinned\TaskBar")
        }.Where(root => !string.IsNullOrWhiteSpace(root) && ContentDiscovery.IsLocalSafePath(root) && Directory.Exists(root)).Distinct(StringComparer.OrdinalIgnoreCase))
        {
            List<string> notes = [];
            foreach (string path in ContentDiscovery.Files(root, notes, 4096, 12, token))
                if (Path.GetExtension(path).Equals(".lnk", StringComparison.OrdinalIgnoreCase) && visited.Add(path))
                    await ScanSteamConfigurationFileAsync(path, SteamConfigurationRepair.Shortcut, report, token, layout);
            if (notes.Count > 0) ConfigurationScanIncomplete(report, root);
        }
    }

    private static void ConfigurationScanIncomplete(ScanReport report, string path)
    {
        report.Coverage = ScanCoverage.Partial;
        report.AddCoverageNote(MessageText.Create("SteamConfig.ScanIncomplete", path));
    }
}
