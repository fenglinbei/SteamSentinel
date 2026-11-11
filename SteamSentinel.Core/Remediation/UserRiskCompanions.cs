using System.ComponentModel;
using System.Diagnostics;
using Microsoft.Win32;
using SteamSentinel.Core.Models;
using SteamSentinel.Core.Reporting;
using SteamSentinel.Core.Scanning;

namespace SteamSentinel.Core.Remediation;

/// <summary>Only exact, live companions of a user-selected file; all are included in the same confirmation.</summary>
internal static class UserRiskCompanions
{
    internal static List<RemediationAction> Discover(RemediationAction file, CancellationToken token)
    {
        List<RemediationAction> actions = [];
        if (!file.UserSelectedRisk || file.Type != RemediationActionType.QuarantineFile) return actions;
        foreach ((RegistryHive hive, RegistryView view) in new[]
        {
            (RegistryHive.CurrentUser, RegistryView.Default),
            (RegistryHive.LocalMachine, RegistryView.Registry32),
            (RegistryHive.LocalMachine, RegistryView.Registry64)
        })
        foreach (string keyName in new[] { @"Software\Microsoft\Windows\CurrentVersion\Run", @"Software\Microsoft\Windows\CurrentVersion\RunOnce" })
        {
            token.ThrowIfCancellationRequested();
            using RegistryKey baseKey = RegistryKey.OpenBaseKey(hive, view);
            using RegistryKey? key = baseKey.OpenSubKey(keyName);
            if (key is null) continue;
            foreach (string name in key.GetValueNames())
            {
                if (key.GetValueKind(name) is not (RegistryValueKind.String or RegistryValueKind.ExpandString) ||
                    key.GetValue(name, null, RegistryValueOptions.DoNotExpandEnvironmentNames) is not string command ||
                    !BoundContentEvidence.IsDirectInvocation(command, file.Target)) continue;
                actions.Add(new()
                {
                    Type = RemediationActionType.RemoveRegistryValue, UserSelectedRisk = true,
                    Target = command, ExpectedValueData = command,
                    RegistryHive = hive == RegistryHive.CurrentUser ? "HKCU" : "HKLM", RegistryView = view.ToString(),
                    RegistryKey = keyName, RegistryValueName = name, RelatedFilePath = file.Target,
                    RelatedFileSha256 = file.ExpectedSha256, ExpectedFileIdentity = file.ExpectedFileIdentity,
                    ExpectedParentIdentity = file.ExpectedParentIdentity,
                    DisplayNameText = MessageText.Create("Remediation.Mode.RemoveSelectedStartup", name),
                    ConfidenceScore = file.ConfidenceScore
                });
            }
        }
        if (!Path.GetExtension(file.Target).Equals(".exe", StringComparison.OrdinalIgnoreCase)) return actions;
        Process[] candidates = Process.GetProcessesByName(Path.GetFileNameWithoutExtension(file.Target));
        try
        {
            foreach (Process candidate in candidates)
            {
                token.ThrowIfCancellationRequested();
                RelatedProcessRead observation = RelatedComponentDiscovery.ProbeProcess(candidate.Id);
                if (observation.Status != DiagnosticReadStatus.Complete || observation.StartedAtUtc is null ||
                    !RelatedArtifactRelations.SamePath(observation.ImagePath ?? string.Empty, file.Target)) continue;
                try { if (candidate.HasExited) continue; }
                catch (InvalidOperationException) { continue; }
                catch (Win32Exception) { continue; }
                actions.Add(new()
                {
                    Type = RemediationActionType.StopProcess, UserSelectedRisk = true, Target = file.Target,
                    ExpectedSha256 = file.ExpectedSha256, ExpectedFileIdentity = file.ExpectedFileIdentity,
                    ExpectedParentIdentity = file.ExpectedParentIdentity,
                    ProcessId = observation.ProcessId, ProcessStartedAtUtc = observation.StartedAtUtc,
                    RelatedFilePath = file.Target, RelatedFileSha256 = file.ExpectedSha256,
                    DisplayNameText = MessageText.Create("Remediation.Mode.StopSelectedProcess", observation.ProcessId),
                    ConfidenceScore = file.ConfidenceScore
                });
            }
        }
        finally { foreach (Process process in candidates) process.Dispose(); }
        return actions;
    }
}
