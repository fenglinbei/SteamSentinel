using System.Text.Json;
using Microsoft.Win32;
using SteamSentinel.Core.Inspection;
using SteamSentinel.Core.Models;
using SteamSentinel.Core.Reporting;
using SteamSentinel.Core.Scanning;
using SteamSentinel.Core.Steam;
using SteamSentinel.Core.Utilities;

namespace SteamSentinel.Core.Remediation;

public sealed record SteamConfigurationSnapshot(string Kind, string? SteamExecutable = null,
    string? OriginalValue = null, string? RepairedValue = null, int? RegistryValueKind = null);

public static class SteamConfigurationRepairTarget
{
    public static SteamConfigurationSnapshot ReadSnapshot(string? json)
    {
        if (json is null || json.Length > 140_000) throw Denied();
        try { return JsonSerializer.Deserialize<SteamConfigurationSnapshot>(json) ?? throw Denied(); }
        catch (JsonException) { throw Denied(); }
    }

    public static bool IsFileTarget(string path, string? kind, SteamLayout layout)
    {
        if (!ContentDiscovery.IsLocalSafePath(path)) return false;
        string full = Path.GetFullPath(path);
        return kind switch
        {
            SteamConfigurationRepair.Cfg => layout.SteamRoots.Any(root => full.Equals(Path.GetFullPath(Path.Combine(root, "steam.cfg")), StringComparison.OrdinalIgnoreCase)),
            SteamConfigurationRepair.Marker => layout.SteamRoots.Any(root => full.Equals(Path.GetFullPath(Path.Combine(root, ".cef-enable-remote-debugging")), StringComparison.OrdinalIgnoreCase)),
            SteamConfigurationRepair.Shortcut => Path.GetExtension(full).Equals(".lnk", StringComparison.OrdinalIgnoreCase),
            SteamConfigurationRepair.UiFile => IsUiFileTarget(full, layout),
            _ => false
        };
    }

    private static bool IsUiFileTarget(string full, SteamLayout layout)
    {
        if (Path.GetExtension(full).ToLowerInvariant() is not (".js" or ".html" or ".htm" or ".css" or ".mjs" or ".cjs"))
            return false;
        return layout.SteamRoots.Any(root =>
            ContentDiscovery.IsWithin(full, Path.Combine(root, "steamui")) ||
            ContentDiscovery.IsWithin(full, Path.Combine(root, "clientui")));
    }

    public static bool IsRunTarget(string? hive, string? view, string? key, string? name) =>
        hive is "HKCU" or "HKLM" && view is "Default" or "Registry32" or "Registry64" &&
        key is @"Software\Microsoft\Windows\CurrentVersion\Run" or @"Software\Microsoft\Windows\CurrentVersion\RunOnce" &&
        name is { Length: > 0 and <= 16383 } && !name.Contains('\0');

    public static async Task<RemediationAction> CaptureAsync(Finding finding, SteamLayout layout, CancellationToken token = default)
    {
        if (finding.ConfigurationKind == SteamConfigurationRepair.Run)
        {
            if (!IsRunTarget(finding.RegistryHive, finding.RegistryView, finding.RegistryKey, finding.RegistryValueName)) throw Denied();
            SteamConfigurationSnapshot observed = ReadSnapshot(finding.ConfigurationSnapshot);
            using RegistryKey baseKey = RegistryKey.OpenBaseKey(finding.RegistryHive == "HKCU" ? RegistryHive.CurrentUser : RegistryHive.LocalMachine,
                Enum.Parse<RegistryView>(finding.RegistryView!));
            using RegistryKey? key = baseKey.OpenSubKey(finding.RegistryKey!);
            if (key is null || key.GetValue(finding.RegistryValueName!, null, RegistryValueOptions.DoNotExpandEnvironmentNames) is not string value ||
                value != observed.OriginalValue || (int)key.GetValueKind(finding.RegistryValueName!) != observed.RegistryValueKind ||
                !SteamConfigurationRepair.TryRepairCommand(value, layout, out string repairedValue, out string executable)) throw Denied("SteamConfig.Changed");
            if (observed.Kind != SteamConfigurationRepair.Run || observed.SteamExecutable != executable || observed.RepairedValue != repairedValue) throw Denied();
            return new()
            {
                Type = RemediationActionType.RepairSteamConfiguration,
                Target = finding.Target,
                DisplayName = finding.Title,
                ConfigurationKind = SteamConfigurationRepair.Run,
                ConfigurationSnapshot = JsonSerializer.Serialize(observed),
                RegistryHive = finding.RegistryHive,
                RegistryView = finding.RegistryView,
                RegistryKey = finding.RegistryKey,
                RegistryValueName = finding.RegistryValueName,
                ExpectedValueData = value,
                RelatedFilePath = executable,
                RelatedFileSha256 = await CaptureExecutableHashAsync(executable, token),
                IsKnownMalware = false,
                ConfidenceScore = finding.Score
            };
        }
        if (!IsFileTarget(finding.Target, finding.ConfigurationKind, layout) || !FileScopeSafety.EvaluatePath(finding.Target).Allowed ||
            !Validation.IsHexSha256(finding.Sha256)) throw Denied();
        await using FileStream input = RelatedArtifactReader.Open(finding.Target);
        byte[] bytes = await ReadBytesAsync(input, token, SteamConfigurationRepair.MaximumBytesFor(finding.ConfigurationKind));
        string hash = SteamConfigurationRepair.Hash(bytes);
        if (!hash.Equals(finding.Sha256, StringComparison.OrdinalIgnoreCase)) throw Denied("SteamConfig.Changed");
        string? repairedHash = null, target = null;
        if (!SteamConfigurationRepair.IsRemovedOnRepair(finding.ConfigurationKind))
        {
            if (!TryRepair(finding.ConfigurationKind!, bytes, layout, out byte[] repaired, out target)) throw Denied();
            repairedHash = SteamConfigurationRepair.Hash(repaired);
        }
        RelatedArtifactReader.ValidatePath(input.SafeFileHandle, Path.GetFullPath(finding.Target));
        return new()
        {
            Type = RemediationActionType.RepairSteamConfiguration,
            Target = Path.GetFullPath(finding.Target),
            DisplayName = finding.Title,
            ConfigurationKind = finding.ConfigurationKind,
            ConfigurationSnapshot = JsonSerializer.Serialize(new SteamConfigurationSnapshot(finding.ConfigurationKind!, target)),
            ExpectedSha256 = hash,
            RepairedSha256 = repairedHash,
            ExpectedFileIdentity = FileScopeSafety.ReadIdentity(input.SafeFileHandle),
            ExpectedParentIdentity = FileScopeSafety.CaptureIdentity(Path.GetDirectoryName(finding.Target)!, true),
            RelatedFilePath = target,
            RelatedFileSha256 = target is null ? null : await CaptureExecutableHashAsync(target, token),
            IsKnownMalware = false,
            ConfidenceScore = finding.Score
        };
    }

    public static bool TryRepair(string kind, byte[] original, SteamLayout layout, out byte[] repaired, out string? executable)
    {
        executable = null; repaired = [];
        if (kind == SteamConfigurationRepair.Cfg) return SteamConfigurationRepair.TryRepairCfg(original, out repaired, out _);
        if (kind != SteamConfigurationRepair.Shortcut) return false;
        bool changed = SteamConfigurationRepair.TryRepairShortcut(original, layout, out repaired, out string target);
        if (changed) executable = target;
        return changed;
    }

    public static async Task<string> CaptureExecutableHashAsync(string path, CancellationToken token)
    {
        if (!ContentDiscovery.IsLocalSafePath(path) || Validation.ContainsReparsePoint(path)) throw Denied();
        await using FileStream input = RelatedArtifactReader.Open(path);
        if (input.Length is <= 0 or > 64 * 1024 * 1024) throw Denied();
        string hash = await Hashing.Sha256StreamAsync(input, token);
        RelatedArtifactReader.ValidatePath(input.SafeFileHandle, Path.GetFullPath(path));
        return hash;
    }

    public static async Task<bool> IsRepairedAsync(RemediationAction action, SteamLayout layout, CancellationToken token = default)
    {
        if (action.Type != RemediationActionType.RepairSteamConfiguration) return false;
        if (action.ConfigurationKind == SteamConfigurationRepair.Run)
        {
            if (!IsRunTarget(action.RegistryHive, action.RegistryView, action.RegistryKey, action.RegistryValueName)) return false;
            SteamConfigurationSnapshot snapshot = ReadSnapshot(action.ConfigurationSnapshot);
            using RegistryKey baseKey = RegistryKey.OpenBaseKey(action.RegistryHive == "HKCU" ? RegistryHive.CurrentUser : RegistryHive.LocalMachine,
                Enum.Parse<RegistryView>(action.RegistryView!));
            using RegistryKey? key = baseKey.OpenSubKey(action.RegistryKey!);
            return snapshot.Kind == SteamConfigurationRepair.Run && snapshot.OriginalValue is not null &&
                SteamConfigurationRepair.TryRepairCommand(snapshot.OriginalValue, layout, out string repaired, out _) && repaired == snapshot.RepairedValue &&
                key is not null && key.GetValue(action.RegistryValueName!, null, RegistryValueOptions.DoNotExpandEnvironmentNames) is string current &&
                current == repaired && (int)key.GetValueKind(action.RegistryValueName!) == snapshot.RegistryValueKind;
        }
        if (!IsFileTarget(action.Target, action.ConfigurationKind, layout) ||
            FileScopeSafety.CaptureIdentity(Path.GetDirectoryName(action.Target)!, true) != action.ExpectedParentIdentity) return false;
        if (SteamConfigurationRepair.IsRemovedOnRepair(action.ConfigurationKind))
        {
            try { _ = File.GetAttributes(action.Target); return false; }
            catch (FileNotFoundException) { return true; }
            catch (DirectoryNotFoundException) { return false; }
        }
        await using FileStream input = RelatedArtifactReader.Open(action.Target);
        byte[] bytes = await ReadBytesAsync(input, token, SteamConfigurationRepair.MaximumBytesFor(action.ConfigurationKind));
        RelatedArtifactReader.ValidatePath(input.SafeFileHandle, Path.GetFullPath(action.Target));
        return FileScopeSafety.ReadIdentity(input.SafeFileHandle) == action.ExpectedFileIdentity &&
            SteamConfigurationRepair.Hash(bytes).Equals(action.RepairedSha256, StringComparison.OrdinalIgnoreCase) &&
            !TryRepair(action.ConfigurationKind!, bytes, layout, out _, out _);
    }

    internal static async Task<byte[]> ReadBytesAsync(FileStream input, CancellationToken token, int maximumBytes = SteamConfigurationRepair.MaximumBytes)
    {
        if (input.Length < 0 || input.Length > maximumBytes) throw Denied();
        byte[] bytes = new byte[checked((int)input.Length)];
        await input.ReadExactlyAsync(bytes, token);
        if (input.ReadByte() != -1) throw Denied("SteamConfig.Changed");
        return bytes;
    }

    private static Exception Denied(string id = "SteamConfig.InvalidTarget") =>
        MessageExceptions.Create(MessageText.Create(id), text => new InvalidDataException(text));
}
