using System.Diagnostics;
using Microsoft.Win32;
using SteamSentinel.Core.Inspection;
using SteamSentinel.Core.Models;
using SteamSentinel.Core.Remediation;
using SteamSentinel.Core.Reporting;
using SteamSentinel.Core.Steam;
using SteamSentinel.Core.Utilities;

namespace SteamSentinel.Broker;

internal sealed partial class BrokerEngine
{
    private static Exception ConfigDenied(string id = "SteamConfig.Changed") =>
        MessageExceptions.Create(MessageText.Create(id), text => new InvalidOperationException(text));

    internal static void ValidateSteamConfigurationAction(RemediationAction action, SteamLayout layout)
    {
        if (action.Type != RemediationActionType.RepairSteamConfiguration) throw ConfigDenied("SteamConfig.InvalidTarget");
        SteamConfigurationSnapshot snapshot = SteamConfigurationRepairTarget.ReadSnapshot(action.ConfigurationSnapshot);
        if (snapshot.Kind != action.ConfigurationKind) throw ConfigDenied("SteamConfig.InvalidTarget");
        if (snapshot.Kind == SteamConfigurationRepair.Run)
        {
            ValidateSteamRunSnapshot(snapshot, action.RegistryHive, action.RegistryView, action.RegistryKey, action.RegistryValueName, layout);
            if (action.ExpectedValueData != snapshot.OriginalValue) throw ConfigDenied("SteamConfig.InvalidTarget");
        }
        else if (!SteamConfigurationRepairTarget.IsFileTarget(action.Target, action.ConfigurationKind, layout) ||
            !FileScopeSafety.EvaluatePath(action.Target).Allowed || !Validation.IsHexSha256(action.ExpectedSha256) ||
            !FileScopeSafety.IsValidIdentity(action.ExpectedFileIdentity) || !FileScopeSafety.IsValidIdentity(action.ExpectedParentIdentity) ||
            snapshot.Kind != SteamConfigurationRepair.Marker && (!Validation.IsHexSha256(action.RepairedSha256) ||
                action.ExpectedSha256!.Equals(action.RepairedSha256, StringComparison.OrdinalIgnoreCase)))
            throw ConfigDenied("SteamConfig.InvalidTarget");
        if (snapshot.Kind is SteamConfigurationRepair.Run or SteamConfigurationRepair.Shortcut)
        {
            if (!SteamConfigurationRepair.IsSteamExecutable(snapshot.SteamExecutable, layout) ||
                !PathsEquivalent(snapshot.SteamExecutable!, action.RelatedFilePath ?? "") || !Validation.IsHexSha256(action.RelatedFileSha256))
                throw ConfigDenied("SteamConfig.InvalidTarget");
        }
        else if (snapshot.SteamExecutable is not null || snapshot.OriginalValue is not null || snapshot.RepairedValue is not null || snapshot.RegistryValueKind is not null)
            throw ConfigDenied("SteamConfig.InvalidTarget");
        if (snapshot.Kind == SteamConfigurationRepair.Shortcut &&
            (snapshot.OriginalValue is not null || snapshot.RepairedValue is not null || snapshot.RegistryValueKind is not null) ||
            snapshot.Kind == SteamConfigurationRepair.Marker && action.RepairedSha256 is not null)
            throw ConfigDenied("SteamConfig.InvalidTarget");
    }

    private static void ValidateSteamRunSnapshot(SteamConfigurationSnapshot snapshot, string? hive, string? view,
        string? key, string? name, SteamLayout layout)
    {
        if (!SteamConfigurationRepairTarget.IsRunTarget(hive, view, key, name) ||
            snapshot.RegistryValueKind is not ((int)RegistryValueKind.String or (int)RegistryValueKind.ExpandString) ||
            snapshot.OriginalValue is null || !SteamConfigurationRepair.TryRepairCommand(snapshot.OriginalValue, layout, out string repaired, out string executable) ||
            repaired != snapshot.RepairedValue || !PathsEquivalent(executable, snapshot.SteamExecutable ?? ""))
            throw ConfigDenied("SteamConfig.InvalidTarget");
    }

    private static void RequireSteamConfigurationClosed()
    {
        foreach (string name in new[] { "steam", "steamwebhelper" })
        {
            Process[] processes = Process.GetProcessesByName(name);
            try { if (processes.Length != 0) throw ConfigDenied("SteamConfig.CloseSteam"); }
            finally { foreach (Process process in processes) process.Dispose(); }
        }
    }

    private async Task<MessageText> RepairSteamConfigurationAsync(RemediationAction action, CancellationToken token)
    {
        RequireSteamConfigurationClosed();
        ValidateSteamConfigurationAction(action, _steamLayout);
        if (action.RelatedFilePath is not null && !(await SteamConfigurationRepairTarget.CaptureExecutableHashAsync(action.RelatedFilePath, token))
            .Equals(action.RelatedFileSha256, StringComparison.OrdinalIgnoreCase)) throw ConfigDenied();
        async Task Persist(QuarantineRecord record, CancellationToken cancellation)
        {
            if (!_manifest.Records.Contains(record)) _manifest.Records.Add(record);
            await PersistManifestAsync(cancellation);
        }
        if (action.ConfigurationKind == SteamConfigurationRepair.Run)
            await RepairSteamRunValueAsync(action, _steamLayout, Persist, token);
        else
        {
            string itemRoot = Path.Combine(_incidentRoot, "items", action.ActionId.ToString("N"));
            MachineStateSecurity.PreparePayloadDirectory(itemRoot);
            string destination = Path.Combine(itemRoot, SafeName(Path.GetFileName(action.Target)) + ".original");
            if (action.ConfigurationKind == SteamConfigurationRepair.Marker)
                await QuarantineSteamMarkerAsync(action, _steamLayout, destination, Persist, MachineStateSecurity.ProtectPayloadFile, token);
            else await RepairSteamConfigurationFileAsync(action, _steamLayout, destination, Persist, MachineStateSecurity.ProtectPayloadFile, token);
        }
        return MessageText.Create("SteamConfig.Repaired");
    }

    internal static async Task<QuarantineRecord> RepairSteamConfigurationFileAsync(RemediationAction action, SteamLayout layout,
        string destination, Func<QuarantineRecord, CancellationToken, Task> persist, Action<string> protect,
        CancellationToken token, Func<SecureFileLease, byte[], Task>? writeForTest = null)
    {
        ValidateSteamConfigurationAction(action, layout);
        if (action.ConfigurationKind is not (SteamConfigurationRepair.Cfg or SteamConfigurationRepair.Shortcut)) throw ConfigDenied("SteamConfig.InvalidTarget");
        using BrokerDirectoryLease parent = BrokerDirectoryLease.OpenParent(action.Target, action.ExpectedParentIdentity);
        await using SecureFileLease source = SecureFileLease.OpenForUpdate(action.Target);
        RequireConfigurationIdentity(source, action.Target, action.ExpectedFileIdentity!);
        BrokerFileMetadata metadata = BrokerFileMetadata.CaptureLocked(source.Handle);
        byte[] original = await source.ReadBytesAsync(SteamConfigurationRepair.MaximumBytes, token);
        if (!SteamConfigurationRepair.Hash(original).Equals(action.ExpectedSha256, StringComparison.OrdinalIgnoreCase) ||
            !SteamConfigurationRepairTarget.TryRepair(action.ConfigurationKind!, original, layout, out byte[] repaired, out string? executable) ||
            repaired.Length != original.Length || !SteamConfigurationRepair.Hash(repaired).Equals(action.RepairedSha256, StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(executable, action.RelatedFilePath, StringComparison.OrdinalIgnoreCase)) throw ConfigDenied();
        QuarantineRecord record = CreateConfigurationFileRecord(action, source, parent, metadata, destination);
        await persist(record, token);
        await source.CopyToAsync(destination, record.Sha256!, token);
        protect(destination);
        token.ThrowIfCancellationRequested();
        RequireConfigurationIdentity(source, action.Target, record.OriginalFileIdentity!);
        if (BrokerFileMetadata.CaptureLocked(source.Handle) != metadata) throw ConfigDenied();
        record.FileMutationAttempted = true;
        await persist(record, token);
        try
        {
            if (writeForTest is null) await source.WriteSameLengthAsync(repaired, CancellationToken.None);
            else await writeForTest(source, repaired);
            if (!(await source.ComputeSha256Async(CancellationToken.None)).Equals(record.RepairedSha256, StringComparison.OrdinalIgnoreCase))
                throw ConfigDenied("SteamConfig.RepairFailed");
            metadata.ApplyTimesAndAttributes(source.Handle);
            RequireConfigurationIdentity(source, action.Target, record.OriginalFileIdentity!);
        }
        catch (Exception failure)
        {
            record.MutationConfirmed = false;
            try
            {
                await source.WriteSameLengthAsync(original, CancellationToken.None);
                metadata.ApplyTimesAndAttributes(source.Handle);
                if (!(await source.ComputeSha256Async(CancellationToken.None)).Equals(record.Sha256, StringComparison.OrdinalIgnoreCase)) throw ConfigDenied("SteamConfig.RepairFailed");
            }
            catch (Exception recovery)
            { throw MessageExceptions.Create(MessageText.Create("SteamConfig.RepairFailed"), text => new IOException(text, new AggregateException(failure, recovery))); }
            throw;
        }
        record.MutationConfirmed = true;
        await persist(record, CancellationToken.None);
        return record;
    }

    private static QuarantineRecord CreateConfigurationFileRecord(RemediationAction action, SecureFileLease source,
        BrokerDirectoryLease parent, BrokerFileMetadata metadata, string destination) => new()
        {
            ActionId = action.ActionId,
            Type = action.Type,
            OriginalTarget = source.FinalPath,
            QuarantinedPath = destination,
            Sha256 = action.ExpectedSha256,
            RepairedSha256 = action.RepairedSha256,
            OriginalFileIdentity = FileScopeSafety.ReadIdentity(source.Handle),
            OriginalParentIdentity = parent.ParentIdentity,
            OriginalSecurityDescriptor = metadata.SecurityDescriptor,
            OriginalAttributes = metadata.Attributes,
            OriginalCreationTimeUtc = metadata.CreationTimeUtc,
            OriginalLastWriteTimeUtc = metadata.LastWriteTimeUtc,
            ConfigurationKind = action.ConfigurationKind,
            ConfigurationSnapshot = action.ConfigurationSnapshot,
            RelatedFilePath = action.RelatedFilePath,
            RelatedFileSha256 = action.RelatedFileSha256,
            VerifiedContentRuleId = SteamConfigurationRepair.RuleId
        };

    internal static async Task<QuarantineRecord> QuarantineSteamMarkerAsync(RemediationAction action, SteamLayout layout,
        string destination, Func<QuarantineRecord, CancellationToken, Task> persist, Action<string> protect, CancellationToken token)
    {
        ValidateSteamConfigurationAction(action, layout);
        if (action.ConfigurationKind != SteamConfigurationRepair.Marker) throw ConfigDenied("SteamConfig.InvalidTarget");
        using BrokerDirectoryLease parent = BrokerDirectoryLease.OpenParent(action.Target, action.ExpectedParentIdentity);
        await using SecureFileLease source = SecureFileLease.OpenWithSecurity(action.Target);
        RequireConfigurationIdentity(source, action.Target, action.ExpectedFileIdentity!);
        if (source.Length > SteamConfigurationRepair.MaximumBytes || !(await source.ComputeSha256Async(token)).Equals(action.ExpectedSha256, StringComparison.OrdinalIgnoreCase)) throw ConfigDenied();
        BrokerFileMetadata metadata = BrokerFileMetadata.CaptureLocked(source.Handle);
        QuarantineRecord record = CreateConfigurationFileRecord(action, source, parent, metadata, destination);
        await persist(record, token);
        await source.CopyToAsync(destination, record.Sha256!, token);
        protect(destination);
        token.ThrowIfCancellationRequested();
        RequireConfigurationIdentity(source, action.Target, record.OriginalFileIdentity!);
        if (BrokerFileMetadata.CaptureLocked(source.Handle) != metadata) throw ConfigDenied();
        record.FileMutationAttempted = true;
        await persist(record, token);
        source.DeleteOnClose();
        record.MutationConfirmed = true;
        await persist(record, CancellationToken.None);
        return record;
    }

    private static void RequireConfigurationIdentity(SecureFileLease source, string target, string identity)
    {
        FileScopeSafety.ValidateHandlePath(source.Handle, target);
        if (!FileScopeSafety.ReadIdentity(source.Handle).Equals(identity, StringComparison.OrdinalIgnoreCase) ||
            FileScopeSafety.ReadLinkCount(source.Handle) != 1) throw ConfigDenied();
        BrokerFileMetadata.EnsureOnlyDefaultStream(source.Handle);
    }

    internal static async Task<QuarantineRecord> RepairSteamRunValueAsync(RemediationAction action, SteamLayout layout,
        Func<QuarantineRecord, CancellationToken, Task> persist, CancellationToken token, Action<RegistryKey, string, string, RegistryValueKind>? writeForTest = null)
    {
        ValidateSteamConfigurationAction(action, layout);
        if (action.ConfigurationKind != SteamConfigurationRepair.Run) throw ConfigDenied("SteamConfig.InvalidTarget");
        SteamConfigurationSnapshot snapshot = SteamConfigurationRepairTarget.ReadSnapshot(action.ConfigurationSnapshot);
        using RegistryKey baseKey = RegistryKey.OpenBaseKey(action.RegistryHive == "HKCU" ? RegistryHive.CurrentUser : RegistryHive.LocalMachine, Enum.Parse<RegistryView>(action.RegistryView!));
        using RegistryKey key = baseKey.OpenSubKey(action.RegistryKey!, writable: true) ?? throw ConfigDenied();
        RequireRegistryImage(key, action.RegistryValueName!, snapshot.OriginalValue!, snapshot.RegistryValueKind!.Value);
        QuarantineRecord record = new()
        {
            ActionId = action.ActionId,
            Type = action.Type,
            OriginalTarget = action.Target,
            RegistryHive = action.RegistryHive,
            RegistryView = action.RegistryView,
            RegistryKey = action.RegistryKey,
            RegistryValueName = action.RegistryValueName,
            RegistryValueData = snapshot.OriginalValue,
            RegistryValueKind = snapshot.RegistryValueKind,
            ConfigurationKind = action.ConfigurationKind,
            ConfigurationSnapshot = action.ConfigurationSnapshot,
            RelatedFilePath = action.RelatedFilePath,
            RelatedFileSha256 = action.RelatedFileSha256,
            VerifiedContentRuleId = SteamConfigurationRepair.RuleId
        };
        await persist(record, token);
        token.ThrowIfCancellationRequested();
        RequireRegistryImage(key, action.RegistryValueName!, snapshot.OriginalValue!, snapshot.RegistryValueKind.Value);
        record.ConfigurationMutationAttempted = true;
        await persist(record, token);
        try
        {
            RequireRegistryImage(key, action.RegistryValueName!, snapshot.OriginalValue!, snapshot.RegistryValueKind.Value);
            if (writeForTest is null) key.SetValue(action.RegistryValueName!, snapshot.RepairedValue!, (RegistryValueKind)snapshot.RegistryValueKind.Value);
            else writeForTest(key, action.RegistryValueName!, snapshot.RepairedValue!, (RegistryValueKind)snapshot.RegistryValueKind.Value);
            key.Flush();
            RequireRegistryImage(key, action.RegistryValueName!, snapshot.RepairedValue!, snapshot.RegistryValueKind.Value);
        }
        catch
        {
            object? value = key.GetValue(action.RegistryValueName!, null, RegistryValueOptions.DoNotExpandEnvironmentNames);
            if (value is string current && current == snapshot.RepairedValue && (int)key.GetValueKind(action.RegistryValueName!) == snapshot.RegistryValueKind)
            {
                key.SetValue(action.RegistryValueName!, snapshot.OriginalValue!, (RegistryValueKind)snapshot.RegistryValueKind.Value);
                key.Flush(); RequireRegistryImage(key, action.RegistryValueName!, snapshot.OriginalValue!, snapshot.RegistryValueKind.Value);
            }
            throw;
        }
        record.MutationConfirmed = true;
        await persist(record, CancellationToken.None);
        return record;
    }

    private static void RequireRegistryImage(RegistryKey key, string name, string expected, int kind)
    {
        if (key.GetValue(name, null, RegistryValueOptions.DoNotExpandEnvironmentNames) is not string value || value != expected || (int)key.GetValueKind(name) != kind)
            throw ConfigDenied();
    }

    internal static void ValidateSteamConfigurationRecord(QuarantineRecord record, SteamLayout layout)
    {
        if (record.Type != RemediationActionType.RepairSteamConfiguration || record.VerifiedContentRuleId != SteamConfigurationRepair.RuleId)
            throw ConfigDenied("SteamConfig.InvalidTarget");
        SteamConfigurationSnapshot snapshot = SteamConfigurationRepairTarget.ReadSnapshot(record.ConfigurationSnapshot);
        if (snapshot.Kind != record.ConfigurationKind) throw ConfigDenied("SteamConfig.InvalidTarget");
        if (snapshot.Kind == SteamConfigurationRepair.Run)
        {
            ValidateSteamRunSnapshot(snapshot, record.RegistryHive, record.RegistryView, record.RegistryKey, record.RegistryValueName, layout);
            if (record.RegistryValueData != snapshot.OriginalValue || record.RegistryValueKind != snapshot.RegistryValueKind) throw ConfigDenied("SteamConfig.InvalidTarget");
        }
        else
        {
            if (!SteamConfigurationRepairTarget.IsFileTarget(record.OriginalTarget, record.ConfigurationKind, layout) || record.QuarantinedPath is null ||
                !Validation.IsHexSha256(record.Sha256) || !FileScopeSafety.IsValidIdentity(record.OriginalFileIdentity) ||
                !FileScopeSafety.IsValidIdentity(record.OriginalParentIdentity) ||
                snapshot.Kind != SteamConfigurationRepair.Marker && !Validation.IsHexSha256(record.RepairedSha256)) throw ConfigDenied("SteamConfig.InvalidTarget");
            _ = BrokerFileMetadata.FromRecord(record);
        }
        if (snapshot.Kind is SteamConfigurationRepair.Run or SteamConfigurationRepair.Shortcut &&
            (!SteamConfigurationRepair.IsSteamExecutable(snapshot.SteamExecutable, layout) ||
            !string.Equals(record.RelatedFilePath, snapshot.SteamExecutable, StringComparison.OrdinalIgnoreCase) || !Validation.IsHexSha256(record.RelatedFileSha256)))
            throw ConfigDenied("SteamConfig.InvalidTarget");
        if (snapshot.Kind != SteamConfigurationRepair.Run &&
            (snapshot.OriginalValue is not null || snapshot.RepairedValue is not null || snapshot.RegistryValueKind is not null) ||
            snapshot.Kind is SteamConfigurationRepair.Cfg or SteamConfigurationRepair.Marker && snapshot.SteamExecutable is not null ||
            snapshot.Kind == SteamConfigurationRepair.Marker && record.RepairedSha256 is not null)
            throw ConfigDenied("SteamConfig.InvalidTarget");
    }

    internal async Task VerifySteamConfigurationRecordedContentAsync(QuarantineRecord record, CancellationToken token)
    {
        ValidateSteamConfigurationRecord(record, _steamLayout);
        if (record.ConfigurationKind == SteamConfigurationRepair.Run) return;
        // A journal may precede a failed backup; no mutation means no backup is needed to undo it.
        if (!record.FileMutationAttempted && !File.Exists(record.QuarantinedPath)) return;
        _ = await ReadVerifiedSteamConfigurationBackupAsync(record, _steamLayout, token);
    }

    private static async Task<(byte[] Original, byte[] Repaired)> ReadVerifiedSteamConfigurationBackupAsync(QuarantineRecord record, SteamLayout layout, CancellationToken token)
    {
        await using SecureFileLease backup = SecureFileLease.Open(record.QuarantinedPath!);
        if (backup.Length > SteamConfigurationRepair.MaximumBytes || FileScopeSafety.ReadLinkCount(backup.Handle) != 1) throw ConfigDenied("SteamConfig.BackupFailed");
        BrokerFileMetadata.EnsureOnlyDefaultStream(backup.Handle);
        byte[] original = backup.Length == 0 ? [] : await backup.ReadBytesAsync(SteamConfigurationRepair.MaximumBytes, token);
        if (!SteamConfigurationRepair.Hash(original).Equals(record.Sha256, StringComparison.OrdinalIgnoreCase)) throw ConfigDenied("SteamConfig.BackupFailed");
        if (record.ConfigurationKind == SteamConfigurationRepair.Marker) return (original, []);
        if (!SteamConfigurationRepairTarget.TryRepair(record.ConfigurationKind!, original, layout, out byte[] repaired, out string? executable) ||
            !SteamConfigurationRepair.Hash(repaired).Equals(record.RepairedSha256, StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(executable, record.RelatedFilePath, StringComparison.OrdinalIgnoreCase)) throw ConfigDenied("SteamConfig.BackupFailed");
        return (original, repaired);
    }

    private async Task RestoreSteamConfigurationAsync(QuarantineRecord record, CancellationToken token,
        Func<QuarantineRecord, CancellationToken, Task>? persistBeforeWrite = null)
    {
        RequireSteamConfigurationClosed();
        ValidateSteamConfigurationRecord(record, _steamLayout);
        if (record.ConfigurationKind == SteamConfigurationRepair.Run)
            RestoreSteamRunValue(record, _steamLayout);
        else if (record.ConfigurationKind == SteamConfigurationRepair.Marker)
            await RestoreSteamMarkerAsync(record, _steamLayout, token);
        else await RestoreSteamConfigurationFileAsync(record, _steamLayout, token, persistBeforeWrite);
    }

    internal static async Task RestoreSteamConfigurationFileAsync(QuarantineRecord record, SteamLayout layout, CancellationToken token,
        Func<QuarantineRecord, CancellationToken, Task>? persistBeforeWrite = null,
        Func<SecureFileLease, byte[], Task>? writeForTest = null)
    {
        ValidateSteamConfigurationRecord(record, layout);
        if (!record.FileMutationAttempted) return;
        if (record.ConfigurationKind is not (SteamConfigurationRepair.Cfg or SteamConfigurationRepair.Shortcut)) throw ConfigDenied("SteamConfig.InvalidTarget");
        using BrokerDirectoryLease parent = BrokerDirectoryLease.OpenParent(record.OriginalTarget, record.OriginalParentIdentity);
        (byte[] original, byte[] repaired) = await ReadVerifiedSteamConfigurationBackupAsync(record, layout, token);
        await using SecureFileLease target = SecureFileLease.OpenForUpdate(record.OriginalTarget);
        RequireConfigurationIdentity(target, record.OriginalTarget, record.OriginalFileIdentity!);
        BrokerFileMetadata metadata = BrokerFileMetadata.FromRecord(record);
        BrokerFileMetadata currentMetadata = BrokerFileMetadata.CaptureLocked(target.Handle);
        if (currentMetadata.SecurityDescriptor != metadata.SecurityDescriptor || currentMetadata.Attributes != metadata.Attributes ||
            currentMetadata.CreationTimeUtc != metadata.CreationTimeUtc) throw ConfigDenied("SteamConfig.RestoreChanged");
        byte[] current = await target.ReadBytesAsync(SteamConfigurationRepair.MaximumBytes, token);
        string hash = SteamConfigurationRepair.Hash(current);
        bool unchanged = hash.Equals(record.Sha256, StringComparison.OrdinalIgnoreCase);
        bool repairedImage = hash.Equals(record.RepairedSha256, StringComparison.OrdinalIgnoreCase);
        if (!unchanged && !repairedImage &&
            (record.MutationConfirmed && !record.FileRollbackAttempted || !IsInterruptedScriptImage(current, original, repaired)))
            throw ConfigDenied("SteamConfig.RestoreChanged");
        token.ThrowIfCancellationRequested();
        if (!unchanged)
        {
            record.FileRollbackAttempted = true;
            if (persistBeforeWrite is not null) await persistBeforeWrite(record, token);
            try
            {
                if (writeForTest is null) await target.WriteSameLengthAsync(original, CancellationToken.None);
                else await writeForTest(target, original);
                if (!(await target.ComputeSha256Async(CancellationToken.None)).Equals(record.Sha256, StringComparison.OrdinalIgnoreCase)) throw ConfigDenied("SteamConfig.RepairFailed");
            }
            catch { await target.WriteSameLengthAsync(current, CancellationToken.None); throw; }
        }
        metadata.ApplyTimesAndAttributes(target.Handle);
    }

    internal static async Task RestoreSteamMarkerAsync(QuarantineRecord record, SteamLayout layout, CancellationToken token)
    {
        ValidateSteamConfigurationRecord(record, layout);
        if (!record.FileMutationAttempted) return;
        if (record.ConfigurationKind != SteamConfigurationRepair.Marker) throw ConfigDenied("SteamConfig.InvalidTarget");
        using BrokerDirectoryLease parent = BrokerDirectoryLease.OpenParent(record.OriginalTarget, record.OriginalParentIdentity);
        _ = await ReadVerifiedSteamConfigurationBackupAsync(record, layout, token);
        BrokerFileMetadata metadata = BrokerFileMetadata.FromRecord(record);
        if (File.Exists(record.OriginalTarget))
        {
            await using SecureFileLease existing = SecureFileLease.OpenWithSecurity(record.OriginalTarget);
            if (!(await existing.ComputeSha256Async(token)).Equals(record.Sha256, StringComparison.OrdinalIgnoreCase) ||
                BrokerFileMetadata.CaptureLocked(existing.Handle) != metadata) throw ConfigDenied("SteamConfig.RestoreChanged");
            return;
        }
        if (Directory.Exists(record.OriginalTarget)) throw ConfigDenied("SteamConfig.RestoreChanged");
        using BrokerRestorePrivilege security = BrokerRestorePrivilege.EnableSecurity();
        using BrokerRestorePrivilege restore = BrokerRestorePrivilege.EnableWhenAvailable();
        await using SecureFileLease backup = SecureFileLease.Open(record.QuarantinedPath!);
        await backup.CopyToAsync(record.OriginalTarget, record.Sha256!, token, handle => metadata.Apply(handle, record.OriginalTarget));
    }

    internal static void RestoreSteamRunValue(QuarantineRecord record, SteamLayout layout)
    {
        ValidateSteamConfigurationRecord(record, layout);
        if (!record.ConfigurationMutationAttempted) return;
        SteamConfigurationSnapshot snapshot = SteamConfigurationRepairTarget.ReadSnapshot(record.ConfigurationSnapshot);
        using RegistryKey baseKey = RegistryKey.OpenBaseKey(record.RegistryHive == "HKCU" ? RegistryHive.CurrentUser : RegistryHive.LocalMachine, Enum.Parse<RegistryView>(record.RegistryView!));
        using RegistryKey key = baseKey.OpenSubKey(record.RegistryKey!, writable: true) ?? throw ConfigDenied("SteamConfig.RestoreChanged");
        if (key.GetValue(record.RegistryValueName!, null, RegistryValueOptions.DoNotExpandEnvironmentNames) is not string current ||
            (int)key.GetValueKind(record.RegistryValueName!) != snapshot.RegistryValueKind) throw ConfigDenied("SteamConfig.RestoreChanged");
        if (current == snapshot.OriginalValue) return;
        if (current != snapshot.RepairedValue) throw ConfigDenied("SteamConfig.RestoreChanged");
        RequireRegistryImage(key, record.RegistryValueName!, snapshot.RepairedValue!, snapshot.RegistryValueKind!.Value);
        key.SetValue(record.RegistryValueName!, snapshot.OriginalValue!, (RegistryValueKind)snapshot.RegistryValueKind.Value);
        key.Flush();
        RequireRegistryImage(key, record.RegistryValueName!, snapshot.OriginalValue!, snapshot.RegistryValueKind.Value);
    }
}
