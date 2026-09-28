using SteamSentinel.Core.Reporting;
using System.Diagnostics;
using System.Text;
using System.Text.Json;
using System.Xml;
using System.Xml.Linq;
using Microsoft.Win32;
using SteamSentinel.Core.Inspection;
using SteamSentinel.Core.Models;
using SteamSentinel.Core.Remediation;
using SteamSentinel.Core.Scanning;
using SteamSentinel.Core.Steam;
using SteamSentinel.Core.Utilities;

namespace SteamSentinel.Broker;

internal sealed partial class BrokerEngine
{
    private readonly Dictionary<Guid, string> _contentProofs = [];

    private bool IsKnownImageHash(string? hash) => _rules.KnownHashes.Any(rule => rule.Malware &&
        string.Equals(rule.Sha256, hash, StringComparison.OrdinalIgnoreCase));

    private bool HasDirectStrongBinding(RemediationAction action) => action.Type == RemediationActionType.StopProcess &&
        !action.IsKnownMalware && action.ConfidenceScore is >= 90 and <= 100 && action.ProcessStartedAtUtc is not null &&
        action.RelatedFilePath is { } path && Validation.IsSafeExactTarget(path) && ContentDiscovery.IsLocalSafePath(path) &&
        PathsEquivalent(path, action.Target) && Validation.IsHexSha256(action.RelatedFileSha256) &&
        string.Equals(action.RelatedFileSha256, action.ExpectedSha256, StringComparison.OrdinalIgnoreCase) &&
        IsAllowedFileTarget(path, action.RelatedFileSha256) &&
        !IsWithin(path, Environment.GetFolderPath(Environment.SpecialFolder.Windows)) && !IsWithin(path, AppContext.BaseDirectory);

    private async Task VerifyDirectProcessContentAsync(RemediationAction action, SecureFileLease image, CancellationToken token)
    {
        if (IsKnownImageHash(action.ExpectedSha256)) return;
        if (!HasDirectStrongBinding(action) || !PathsEquivalent(image.FinalPath, action.Target) ||
            await BoundContentEvidence.VerifyAsync(image.FinalPath, action.ExpectedSha256!, token) is null)
            throw MessageExceptions.Create(MessageText.Create("Backend.Broker.BrokerBoundActions.VerifyDirectProcessContentAsync.01"), sourceText => new UnauthorizedAccessException(sourceText));
    }

    private bool HasPersistenceBinding(RemediationAction action) => HasKnownBinding(action) ||
        action.Type is RemediationActionType.RemoveRegistryValue or RemediationActionType.RemoveScheduledTask &&
        !action.IsKnownMalware && action.ConfidenceScore is >= 90 and <= 100 &&
        action.RelatedFilePath is { } path && Validation.IsSafeExactTarget(path) && ContentDiscovery.IsLocalSafePath(path) &&
        Validation.IsHexSha256(action.RelatedFileSha256) && IsAllowedFileTarget(path, action.RelatedFileSha256) &&
        !IsWithin(path, Environment.GetFolderPath(Environment.SpecialFolder.Windows)) && !IsWithin(path, AppContext.BaseDirectory);

    private bool HasKnownBinding(RemediationAction action) => action.RelatedFilePath is { } path &&
        Validation.IsSafeExactTarget(path) && ContentDiscovery.IsLocalSafePath(path) && Validation.IsHexSha256(action.RelatedFileSha256) &&
        _rules.KnownHashes.Any(rule => rule.Malware && rule.Sha256.Equals(action.RelatedFileSha256, StringComparison.OrdinalIgnoreCase));

    private void ValidateBoundAction(RemediationAction action)
    {
        if (!HasKnownBinding(action)) throw MessageExceptions.Create(MessageText.Create("Backend.Broker.BrokerBoundActions.ValidateBoundAction.01"), sourceText => new UnauthorizedAccessException(sourceText));
        if (action.ConfigurationSnapshot?.Length > 32768) throw MessageExceptions.Create(MessageText.Create("Backend.Broker.BrokerBoundActions.ValidateBoundAction.02"), sourceText => new InvalidDataException(sourceText));
        switch (action.Type)
        {
            case RemediationActionType.StopHostProcess:
                if (action.ProcessId is null or <= 4 || action.ProcessStartedAtUtc is null || !Validation.IsHexSha256(action.ExpectedSha256) ||
                    !ContentDiscovery.IsLocalSafePath(action.Target) ||
                    IsWithin(action.Target, Environment.GetFolderPath(Environment.SpecialFolder.Windows)) ||
                    IsWithin(action.Target, AppContext.BaseDirectory)) throw MessageExceptions.Create(MessageText.Create("Backend.Broker.BrokerBoundActions.ValidateBoundAction.03"), sourceText => new InvalidDataException(sourceText));
                break;
            case RemediationActionType.DisableService:
                if (action.Target.Length is < 1 or > 256 || action.Target.Any(c => char.IsControl(c) || c is '/' or '\\' or ':') ||
                    action.ConfigurationKind is not ("2" or "3" or "4") || string.IsNullOrWhiteSpace(action.ConfigurationSnapshot))
                    throw MessageExceptions.Create(MessageText.Create("Backend.Broker.BrokerBoundActions.ValidateBoundAction.04"), sourceText => new InvalidDataException(sourceText));
                break;
            case RemediationActionType.RemoveRelatedDefenderExclusion:
                string? exclusionSteam = ProtectionConfiguration.PluginRoot(_steamLayout, action.RelatedFilePath!);
                if (exclusionSteam is null || action.ConfigurationKind is not ("ExclusionPath" or "AttackSurfaceReductionOnlyExclusions") ||
                    !ContentDiscovery.IsLocalSafePath(action.Target) || !ProtectionConfiguration.IsRelatedExclusion(exclusionSteam, action.Target) ||
                    action.ConfigurationSnapshot != action.Target) throw MessageExceptions.Create(MessageText.Create("Backend.Broker.BrokerBoundActions.ValidateBoundAction.05"), sourceText => new UnauthorizedAccessException(sourceText));
                break;
            case RemediationActionType.DisableRelatedFirewallRule:
                string? firewallSteam = ProtectionConfiguration.PluginRoot(_steamLayout, action.RelatedFilePath!);
                FirewallSnapshot? snapshot = JsonSerializer.Deserialize<FirewallSnapshot>(action.ConfigurationSnapshot ?? "null");
                if (firewallSteam is null || snapshot is null || snapshot.Name != action.Target ||
                    !ProtectionConfiguration.IsRelatedFirewall(firewallSteam, snapshot)) throw MessageExceptions.Create(MessageText.Create("Backend.Broker.BrokerBoundActions.ValidateBoundAction.06"), sourceText => new UnauthorizedAccessException(sourceText));
                break;
        }
    }

    private async Task<SecureFileLease> OpenBoundLeaseAsync(RemediationAction action, string? command, CancellationToken token)
    {
        if (!HasPersistenceBinding(action)) throw MessageExceptions.Create(MessageText.Create("Backend.Broker.BrokerBoundActions.OpenBoundLeaseAsync.01"), sourceText => new UnauthorizedAccessException(sourceText));
        // Indirect script chains are reported for review, never authorized from a transient text read.
        if (command is not null && !CommandTargets.Extract(command).Any(path => PathsEquivalent(path, action.RelatedFilePath!)))
            throw MessageExceptions.Create(MessageText.Create("Backend.Broker.BrokerBoundActions.OpenBoundLeaseAsync.02"), sourceText => new InvalidOperationException(sourceText));
        if (!HasKnownBinding(action) && (command is null || !BoundContentEvidence.IsDirectInvocation(command, action.RelatedFilePath!)))
            throw MessageExceptions.Create(MessageText.Create("Backend.Broker.BrokerBoundActions.OpenBoundLeaseAsync.03"), sourceText => new InvalidOperationException(sourceText));
        SecureFileLease lease = SecureFileLease.Open(action.RelatedFilePath!);
        try
        {
            if (!(await lease.ComputeSha256Async(token)).Equals(action.RelatedFileSha256, StringComparison.OrdinalIgnoreCase))
                throw MessageExceptions.Create(MessageText.Create("Backend.Broker.BrokerBoundActions.OpenBoundLeaseAsync.04"), sourceText => new InvalidOperationException(sourceText));
            if (!HasKnownBinding(action))
            {
                string? proof = await BoundContentEvidence.VerifyAsync(lease.FinalPath, action.RelatedFileSha256!, token);
                if (proof is null) throw MessageExceptions.Create(MessageText.Create("Backend.Broker.BrokerBoundActions.OpenBoundLeaseAsync.05"), sourceText => new UnauthorizedAccessException(sourceText));
                _contentProofs[action.ActionId] = proof;
            }
            return lease;
        }
        catch { await lease.DisposeAsync(); throw; }
    }

    private static string TaskCommands(string xml)
    {
        using XmlReader reader = XmlReader.Create(new StringReader(xml), new XmlReaderSettings
        { DtdProcessing = DtdProcessing.Prohibit, XmlResolver = null, MaxCharactersInDocument = 2 * 1024 * 1024 });
        XDocument document = XDocument.Load(reader);
        if (document.Root?.Name.LocalName != "Task") throw MessageExceptions.Create(MessageText.Create("Backend.Broker.BrokerBoundActions.TaskCommands.01"), sourceText => new InvalidDataException(sourceText));
        XElement[] commands = document.Root.Elements().Where(element => element.Name.LocalName == "Actions")
            .SelectMany(element => element.Elements()).Where(element => element.Name.LocalName == "Exec").Take(65).ToArray();
        if (commands.Length > 64 || commands.Any(element => element.Elements().Count(child => child.Name.LocalName == "Command") != 1 ||
                element.Elements().Count(child => child.Name.LocalName == "Arguments") > 1))
            throw MessageExceptions.Create(MessageText.Create("Backend.Broker.BrokerBoundActions.TaskCommands.02"), sourceText => new InvalidDataException(sourceText));
        return string.Join("\n", commands
            .Select(e => '"' + (e.Elements().FirstOrDefault(c => c.Name.LocalName == "Command")?.Value ?? "").Trim('"') + "\" " +
                (e.Elements().FirstOrDefault(c => c.Name.LocalName == "Arguments")?.Value ?? "")));
    }

    private bool CommandTargetsAreBound(RemediationAction action, string command) => HasKnownBinding(action)
        ? CommandTargets.Extract(command).Any(path => PathsEquivalent(path, action.RelatedFilePath!))
        : command.Split('\n').Any(invocation => BoundContentEvidence.IsDirectInvocation(invocation, action.RelatedFilePath!));

    internal static void RequireTaskSnapshotHash(string actual, string? expected)
    {
        if (!Validation.IsHexSha256(expected) || !actual.Equals(expected, StringComparison.OrdinalIgnoreCase))
            throw MessageExceptions.Create(MessageText.Create("Backend.Broker.BrokerBoundActions.RequireTaskSnapshotHash.01"), sourceText => new InvalidOperationException(sourceText));
    }

    private static bool HasHeuristicRecord(QuarantineRecord record) =>
        record.Type is RemediationActionType.RemoveRegistryValue or RemediationActionType.RemoveScheduledTask &&
        record.VerifiedContentRuleId is "HEUR-STEAM-UI-PATCHER" or "HEUR-STEAM-TOKEN-STEALER" or "HEUR-STEAM-CREDENTIAL-PLUGIN" &&
        record.RelatedFilePath is { } path && Validation.IsSafeExactTarget(path) && ContentDiscovery.IsLocalSafePath(path) &&
        Validation.IsHexSha256(record.RelatedFileSha256);

    private async Task VerifyRecordedContentAsync(QuarantineRecord record, QuarantineManifest manifest, CancellationToken token)
    {
        if (!HasHeuristicRecord(record)) return;
        // Reprove the protected manifest claim from actual original or same-incident quarantine bytes.
        string path = record.RelatedFilePath!;
        if (!File.Exists(path))
        {
            QuarantineRecord? file = manifest.Records.FirstOrDefault(item => item.Type == RemediationActionType.QuarantineFile &&
                PathsEquivalent(item.OriginalTarget, path) && string.Equals(item.Sha256, record.RelatedFileSha256, StringComparison.OrdinalIgnoreCase));
            path = file?.QuarantinedPath ?? throw MessageExceptions.Create(MessageText.Create("Backend.Broker.BrokerBoundActions.VerifyRecordedContentAsync.01"), sourceText => new InvalidOperationException(sourceText));
        }
        await using SecureFileLease lease = SecureFileLease.Open(path);
        string? proof = await BoundContentEvidence.VerifyAsync(lease.FinalPath, record.RelatedFileSha256!, token);
        if (proof != record.VerifiedContentRuleId) throw MessageExceptions.Create(MessageText.Create("Backend.Broker.BrokerBoundActions.VerifyRecordedContentAsync.02"), sourceText => new InvalidOperationException(sourceText));
        if (record.Type == RemediationActionType.RemoveRegistryValue &&
            !BoundContentEvidence.IsDirectInvocation(record.RegistryValueData ?? "", record.RelatedFilePath!))
            throw MessageExceptions.Create(MessageText.Create("Backend.Broker.BrokerBoundActions.VerifyRecordedContentAsync.03"), sourceText => new InvalidDataException(sourceText));
        if (record.Type == RemediationActionType.RemoveScheduledTask)
        {
            if (record.QuarantinedPath is null || new FileInfo(record.QuarantinedPath).Length > 2 * 1024 * 1024)
                throw MessageExceptions.Create(MessageText.Create("Backend.Broker.BrokerBoundActions.VerifyRecordedContentAsync.04"), sourceText => new InvalidDataException(sourceText));
            string xml = await File.ReadAllTextAsync(record.QuarantinedPath, token);
            if (!TaskCommands(xml).Split('\n').Any(invocation => BoundContentEvidence.IsDirectInvocation(invocation, record.RelatedFilePath!)))
                throw MessageExceptions.Create(MessageText.Create("Backend.Broker.BrokerBoundActions.VerifyRecordedContentAsync.05"), sourceText => new InvalidDataException(sourceText));
        }
    }

    private async Task<MessageText> StopHostAsync(RemediationAction action, CancellationToken token)
    {
        await using SecureFileLease bound = await OpenBoundLeaseAsync(action, null, token);
        using Process host = Process.GetProcessById(action.ProcessId!.Value);
        if (host.StartTime.ToUniversalTime() != action.ProcessStartedAtUtc!.Value.UtcDateTime ||
            !PathsEquivalent(host.MainModule?.FileName ?? "", action.Target) ||
            !host.Modules.Cast<ProcessModule>().Any(module => PathsEquivalent(module.FileName, bound.FinalPath)))
            throw MessageExceptions.Create(MessageText.Create("Backend.Broker.BrokerBoundActions.StopHostAsync.01"), sourceText => new InvalidOperationException(sourceText));
        await using SecureFileLease image = SecureFileLease.Open(action.Target);
        if (!(await image.ComputeSha256Async(token)).Equals(action.ExpectedSha256, StringComparison.OrdinalIgnoreCase))
            throw MessageExceptions.Create(MessageText.Create("Backend.Broker.BrokerBoundActions.StopHostAsync.02"), sourceText => new InvalidOperationException(sourceText));
        host.Kill(entireProcessTree: false);
        using CancellationTokenSource timeout = CancellationTokenSource.CreateLinkedTokenSource(token);
        timeout.CancelAfter(TimeSpan.FromSeconds(15));
        await host.WaitForExitAsync(timeout.Token);
        return MessageText.Create("Backend.Broker.BrokerBoundActions.StopHostAsync.03");
    }

    private async Task<MessageText> DisableServiceAsync(RemediationAction action, CancellationToken token)
    {
        using RegistryKey key = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\" + action.Target, writable: true)
            ?? throw MessageExceptions.Create(MessageText.Create("Backend.Broker.BrokerBoundActions.DisableServiceAsync.01"), sourceText => new InvalidOperationException(sourceText));
        string command = key.GetValue("ImagePath", null, RegistryValueOptions.DoNotExpandEnvironmentNames)?.ToString() ?? "";
        int type = Convert.ToInt32(key.GetValue("Type") ?? 0);
        int start = Convert.ToInt32(key.GetValue("Start") ?? -1);
        if ((type & 0x30) == 0 || (type & 3) != 0 || start.ToString(System.Globalization.CultureInfo.InvariantCulture) != action.ConfigurationKind ||
            command != action.ConfigurationSnapshot) throw MessageExceptions.Create(MessageText.Create("Backend.Broker.BrokerBoundActions.DisableServiceAsync.02"), sourceText => new InvalidOperationException(sourceText));
        await using SecureFileLease bound = await OpenBoundLeaseAsync(action, command, token);
        _manifest.Records.Add(BoundRecord(action));
        await PersistManifestAsync(token);
        ProcessResult configuration = await RunProcessAsync(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "sc.exe"),
            ["config", action.Target, "start=", "disabled"], token);
        if (configuration.ExitCode != 0) throw MessageExceptions.Create(MessageText.Create("Backend.Broker.BrokerBoundActions.DisableServiceAsync.03") + configuration.Error, sourceText => new InvalidOperationException(sourceText));
        _manifest.Records.Last(record => record.ActionId == action.ActionId).MutationConfirmed = true;
        await PersistManifestAsync(token);
        ProcessResult result = await RunProcessAsync(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "sc.exe"),
            ["stop", action.Target], token);
        if (result.ExitCode is not (0 or 1062)) throw MessageExceptions.Create(MessageText.Create("Backend.Broker.BrokerBoundActions.DisableServiceAsync.04") + result.Error, sourceText => new InvalidOperationException(sourceText));
        return MessageText.Create("Backend.Broker.BrokerBoundActions.DisableServiceAsync.05");
    }

    private static async Task RestoreServiceAsync(QuarantineRecord record, CancellationToken token)
    {
        using RegistryKey key = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\" + record.OriginalTarget, writable: true)
            ?? throw MessageExceptions.Create(MessageText.Create("Backend.Broker.BrokerBoundActions.RestoreServiceAsync.01"), sourceText => new InvalidOperationException(sourceText));
        string command = key.GetValue("ImagePath", null, RegistryValueOptions.DoNotExpandEnvironmentNames)?.ToString() ?? "";
        int type = Convert.ToInt32(key.GetValue("Type") ?? 0);
        int start = Convert.ToInt32(key.GetValue("Start") ?? -1);
        int previous = int.Parse(record.ConfigurationKind!, System.Globalization.CultureInfo.InvariantCulture);
        if ((type & 0x30) == 0 || (type & 3) != 0 || command != record.ConfigurationSnapshot || start != 4 && start != previous)
            throw MessageExceptions.Create(MessageText.Create("Backend.Broker.BrokerBoundActions.RestoreServiceAsync.02"), sourceText => new InvalidOperationException(sourceText));
        ProcessResult result = await RunProcessAsync(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "sc.exe"),
            ["config", record.OriginalTarget, "start=", previous == 2 ? "auto" : previous == 3 ? "demand" : "disabled"], token);
        if (result.ExitCode != 0) throw MessageExceptions.Create(MessageText.Create("Backend.Broker.BrokerBoundActions.RestoreServiceAsync.03") + result.Error, sourceText => new InvalidOperationException(sourceText));
        // Never starts a restored service.
    }

    private async Task<MessageText> ChangeRelatedExclusionAsync(RemediationAction action, bool restore, CancellationToken token)
    {
        ValidateBoundAction(action);
        await using SecureFileLease? bound = restore ? null : await OpenBoundLeaseAsync(action, null, token);
        string script = "$ErrorActionPreference='Stop';$s=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($env:SS_CONFIG))|ConvertFrom-Json;" +
            "$p=Get-MpPreference -ErrorAction Stop;$items=@($p.($s.Kind));$present=@($items|Where-Object {$_ -ieq $s.Target}).Count -gt 0;" +
            "if($s.Restore){if($present){exit 0};$args=@{};$args[$s.Kind]=$s.Target;Add-MpPreference @args -ErrorAction Stop}" +
            "else {if(-not $present){throw 'Exclusion changed since scan'};$args=@{};$args[$s.Kind]=$s.Target;Remove-MpPreference @args -ErrorAction Stop}";
        if (!restore) { _manifest.Records.Add(BoundRecord(action)); await PersistManifestAsync(token); }
        ProcessResult result = await RunEncodedPowerShellAsync(script, ConfigEnvironment(new { Kind = action.ConfigurationKind, action.Target, Restore = restore }), token);
        if (result.ExitCode != 0) throw new InvalidOperationException(result.Error);
        if (!restore) { _manifest.Records.Last(record => record.ActionId == action.ActionId).MutationConfirmed = true; await PersistManifestAsync(token); }
        return restore ? MessageText.Create("Backend.Broker.BrokerBoundActions.ChangeRelatedExclusionAsync.01") : MessageText.Create("Backend.Broker.BrokerBoundActions.ChangeRelatedExclusionAsync.02");
    }

    private async Task<MessageText> ChangeRelatedFirewallAsync(RemediationAction action, bool restore, CancellationToken token)
    {
        ValidateBoundAction(action);
        await using SecureFileLease? bound = restore ? null : await OpenBoundLeaseAsync(action, null, token);
        FirewallSnapshot snapshot = JsonSerializer.Deserialize<FirewallSnapshot>(action.ConfigurationSnapshot!)!;
        const string script = "$ErrorActionPreference='Stop';$s=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($env:SS_CONFIG))|ConvertFrom-Json;" +
            "$r=@(Get-NetFirewallRule -PolicyStore PersistentStore -ErrorAction Stop|Where-Object {$_.Name -ceq $s.Rule.Name});if($r.Count -ne 1){throw 'Rule missing or ambiguous'};$r=$r[0];$a=@($r|Get-NetFirewallApplicationFilter -ErrorAction Stop);" +
            "if($a.Count -ne 1 -or $a[0].Program -ine $s.Rule.Program -or $r.DisplayName -cne $s.Rule.DisplayName -or [int]$r.Action -ne $s.Rule.Action -or [int]$r.Direction -ne $s.Rule.Direction -or [int]$r.Profile -ne $s.Rule.Profile){throw 'Rule changed since scan'};" +
            "if($s.Restore){if([int]$r.Enabled -eq 1){exit 0};$r|Enable-NetFirewallRule -ErrorAction Stop}else{if([int]$r.Enabled -ne 1){throw 'Rule state changed'};$r|Disable-NetFirewallRule -ErrorAction Stop}";
        if (!restore) { _manifest.Records.Add(BoundRecord(action)); await PersistManifestAsync(token); }
        ProcessResult result = await RunEncodedPowerShellAsync(script, ConfigEnvironment(new { Rule = snapshot, Restore = restore }), token);
        if (result.ExitCode != 0) throw new InvalidOperationException(result.Error);
        if (!restore) { _manifest.Records.Last(record => record.ActionId == action.ActionId).MutationConfirmed = true; await PersistManifestAsync(token); }
        return restore ? MessageText.Create("Backend.Broker.BrokerBoundActions.ChangeRelatedFirewallAsync.01") : MessageText.Create("Backend.Broker.BrokerBoundActions.ChangeRelatedFirewallAsync.02");
    }

    private static Dictionary<string, string> ConfigEnvironment(object value) => new()
    { ["SS_CONFIG"] = Convert.ToBase64String(Encoding.UTF8.GetBytes(JsonSerializer.Serialize(value))) };

    private static QuarantineRecord BoundRecord(RemediationAction action) => new()
    {
        ActionId = action.ActionId,
        Type = action.Type,
        OriginalTarget = action.Target,
        Sha256 = action.ExpectedSha256,
        RelatedFilePath = action.RelatedFilePath,
        RelatedFileSha256 = action.RelatedFileSha256,
        ConfigurationKind = action.ConfigurationKind,
        ConfigurationSnapshot = action.ConfigurationSnapshot,
        MutationConfirmed = false
    };

    private static RemediationAction FromRecord(QuarantineRecord record) => new()
    {
        ActionId = record.ActionId,
        Type = record.Type,
        Target = record.OriginalTarget,
        ExpectedSha256 = record.Sha256,
        RelatedFilePath = record.RelatedFilePath,
        RelatedFileSha256 = record.RelatedFileSha256,
        ConfigurationKind = record.ConfigurationKind,
        ConfigurationSnapshot = record.ConfigurationSnapshot
    };
}
