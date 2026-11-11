using System.Diagnostics;
using System.Security.Cryptography;
using Microsoft.Win32;
using SteamSentinel.Core.Inspection;
using SteamSentinel.Core.Models;
using SteamSentinel.Core.Remediation;
using SteamSentinel.Core.Reporting;
using SteamSentinel.Core.Scanning;
using SteamSentinel.Core.Steam;
using SteamSentinel.Core.Utilities;

namespace SteamSentinel.Broker;

internal sealed partial class BrokerEngine
{
    private RemediationPlan? _steamScriptPlan;
    private readonly HashSet<string> _steamScriptSourceProcessPaths = new(StringComparer.OrdinalIgnoreCase);

    private static Exception ScriptDenied(string id = "SteamScript.Changed") =>
        MessageExceptions.Create(MessageText.Create(id), text => new InvalidOperationException(text));

    internal static void ValidateSteamScriptAction(RemediationAction action, SteamLayout layout)
    {
        if (action.Type != RemediationActionType.RepairSteamScript ||
            !SteamScriptRepairTarget.IsScriptPath(action.Target, layout) ||
            !FileScopeSafety.EvaluatePath(action.Target).Allowed ||
            !Validation.IsHexSha256(action.ExpectedSha256) || !Validation.IsHexSha256(action.RepairedSha256) ||
            string.Equals(action.ExpectedSha256, action.RepairedSha256, StringComparison.OrdinalIgnoreCase) ||
            !FileScopeSafety.IsValidIdentity(action.ExpectedFileIdentity) ||
            !FileScopeSafety.IsValidIdentity(action.ExpectedParentIdentity))
            throw ScriptDenied("SteamScript.InvalidTarget");
    }

    private void ValidateSteamScriptPlan(RemediationPlan plan)
    {
        _steamScriptPlan = plan;
        RemediationAction[] repairs = plan.Actions.Where(a => a.Type == RemediationActionType.RepairSteamScript).ToArray();
        if (repairs.Length == 0) return;
        RequireSteamClosed();
        var dependencies = RemediationDependencies.Build(plan.Actions);
        Dictionary<string, string> sourceFiles = ExistingSteamAlertComponents(plan)
            .ToDictionary(item => item.Path, item => item.Hash, StringComparer.OrdinalIgnoreCase);
        _steamScriptSourceProcessPaths.Clear();
        _steamScriptSourceProcessPaths.UnionWith(sourceFiles.Keys);
        _steamScriptSourceProcessPaths.UnionWith(SteamAlertInstallation.ProbePaths(SteamAlertInstallation.ResidentRule,
            _steamLayout, SteamAlertInstallation.ResidentDirectory));
        HashSet<string> sourceHashes = SteamScriptRepairTarget.SourceHashes(_rules);
        _steamScriptSourceProcessPaths.UnionWith(plan.Actions.Where(a => sourceHashes.Contains(a.ExpectedSha256 ?? string.Empty) &&
            a.Type is RemediationActionType.QuarantineFile or RemediationActionType.StopProcess).Select(a => a.Target));
        foreach ((string path, string hash) in sourceFiles)
        {
            RemediationAction? removal = plan.Actions.FirstOrDefault(a => a.Type == RemediationActionType.QuarantineFile &&
                PathsEquivalent(a.Target, path) && string.Equals(a.ExpectedSha256, hash, StringComparison.OrdinalIgnoreCase));
            if (removal is null || repairs.Any(repair => !dependencies[repair.ActionId].Contains(removal.ActionId)))
                throw ScriptDenied("SteamScript.Unconfirmed");
            RequireSteamAlertRunDependencies(plan, repairs, path);
        }
        RequireSteamScriptProcessDependencies(plan, sourceFiles, ReadSteamScriptSourceProcesses(sourceFiles.Keys));
    }

    private IEnumerable<(string Path, string Hash)> ExistingSteamAlertComponents(RemediationPlan plan)
    {
        HashSet<string> sourceHashes = SteamScriptRepairTarget.SourceHashes(_rules);
        IEnumerable<string> candidates = SteamAlertInstallation.ProbePaths(SteamAlertInstallation.ResidentRule, _steamLayout,
                SteamAlertInstallation.ResidentDirectory)
            .Concat(SteamAlertInstallation.ProbePaths(SteamAlertInstallation.LoaderRule, _steamLayout,
                SteamAlertInstallation.ResidentDirectory))
            .Concat(plan.Actions.Where(a => a.Type is RemediationActionType.QuarantineFile or RemediationActionType.StopProcess &&
                    sourceHashes.Contains(a.ExpectedSha256 ?? string.Empty))
                .Select(a => a.Target));
        foreach (string path in candidates.Distinct(StringComparer.OrdinalIgnoreCase))
        {
            FileAttributes attributes;
            try { attributes = File.GetAttributes(path); }
            catch (FileNotFoundException) { continue; }
            catch (DirectoryNotFoundException) { continue; }
            if (!ContentDiscovery.IsLocalSafePath(path) || Validation.ContainsReparsePoint(path))
                throw ScriptDenied("SteamScript.Unconfirmed");
            if ((attributes & (FileAttributes.Directory | FileAttributes.ReparsePoint)) != 0)
                throw ScriptDenied("SteamScript.Unconfirmed");
            using FileStream stream = new(path, FileMode.Open, FileAccess.Read, FileShare.Read);
            if (stream.Length > 64 * 1024 * 1024) throw ScriptDenied("SteamScript.Unconfirmed");
            string hash = Convert.ToHexString(SHA256.HashData(stream));
            HashRule? rule = _rules.KnownHashes.FirstOrDefault(rule => rule.Malware &&
                rule.Id is SteamAlertInstallation.LoaderRule or SteamAlertInstallation.ResidentRule &&
                rule.Sha256.Equals(hash, StringComparison.OrdinalIgnoreCase));
            if (rule is not null && SteamAlertInstallation.IsInstalled(rule.Id, path, _steamLayout,
                    SteamAlertInstallation.ResidentDirectory)) yield return (path, hash);
        }
    }

    private static void RequireSteamAlertRunDependencies(RemediationPlan plan, RemediationAction[] repairs, string path)
    {
        var dependencies = RemediationDependencies.Build(plan.Actions);
        // Match the scanner's physical views. HKCU Run is shared and is recorded as Default.
        foreach ((RegistryHive hive, RegistryView view) in new[]
                 {
                     (RegistryHive.CurrentUser, RegistryView.Default),
                     (RegistryHive.LocalMachine, RegistryView.Registry32),
                     (RegistryHive.LocalMachine, RegistryView.Registry64)
                 })
        foreach (string keyName in new[] { @"Software\Microsoft\Windows\CurrentVersion\Run", @"Software\Microsoft\Windows\CurrentVersion\RunOnce" })
        {
            using RegistryKey baseKey = RegistryKey.OpenBaseKey(hive, view);
            using RegistryKey? key = baseKey.OpenSubKey(keyName);
            if (key is null) continue;
            foreach (string name in key.GetValueNames())
            {
                if (key.GetValue(name, null, RegistryValueOptions.DoNotExpandEnvironmentNames) is not string command ||
                    !CommandTargets.Extract(command).Any(target => PathsEquivalent(target, path))) continue;
                RemediationAction? removal = plan.Actions.FirstOrDefault(a => a.Type == RemediationActionType.RemoveRegistryValue &&
                    a.RegistryHive == (hive == RegistryHive.CurrentUser ? "HKCU" : "HKLM") &&
                    a.RegistryView == view.ToString() && a.RegistryKey == keyName && a.RegistryValueName == name &&
                    a.ExpectedValueData == command);
                if (removal is null || repairs.Any(repair => !dependencies[repair.ActionId].Contains(removal.ActionId)))
                    throw ScriptDenied("SteamScript.Unconfirmed");
            }
        }
    }

    private static void RequireSteamClosed()
    {
        foreach (string name in new[] { "steam", "steamwebhelper" })
        {
            Process[] processes = Process.GetProcessesByName(name);
            try { if (processes.Length != 0) throw ScriptDenied("SteamScript.CloseSteam"); }
            finally { foreach (Process process in processes) process.Dispose(); }
        }
    }

    private async Task<MessageText> RepairSteamScriptAsync(RemediationAction action, CancellationToken token)
    {
        RequireSteamClosed();
        if (_steamScriptPlan is null || ExistingSteamAlertComponents(_steamScriptPlan).Any())
            throw ScriptDenied("SteamScript.Unconfirmed");
        RequireSteamScriptProcessesStopped(_steamScriptSourceProcessPaths,
            ReadSteamScriptSourceProcesses(_steamScriptSourceProcessPaths));
        string itemRoot = Path.Combine(_incidentRoot, "items", action.ActionId.ToString("N"));
        MachineStateSecurity.PreparePayloadDirectory(itemRoot);
        string destination = Path.Combine(itemRoot, SafeName(Path.GetFileName(action.Target)) + ".original");
        await RepairSteamScriptFileAsync(action, _steamLayout, destination,
            async (record, cancellation) =>
            {
                if (!_manifest.Records.Contains(record)) _manifest.Records.Add(record);
                await PersistManifestAsync(cancellation);
            }, MachineStateSecurity.ProtectPayloadFile, token);
        return MessageText.Create("SteamScript.Repaired");
    }

    internal static async Task<QuarantineRecord> RepairSteamScriptFileAsync(RemediationAction action, SteamLayout layout,
        string destination, Func<QuarantineRecord, CancellationToken, Task> persist, Action<string> protect,
        CancellationToken token, Func<SecureFileLease, byte[], Task>? writeForTest = null)
    {
        ValidateSteamScriptAction(action, layout);
        using BrokerDirectoryLease parent = BrokerDirectoryLease.OpenParent(action.Target, action.ExpectedParentIdentity);
        await using SecureFileLease source = SecureFileLease.OpenForUpdate(action.Target);
        RequireScriptIdentity(source, action.Target, action.ExpectedFileIdentity!);
        BrokerFileMetadata metadata = BrokerFileMetadata.CaptureLocked(source.Handle);
        byte[] original = await source.ReadBytesAsync(SteamScriptRepair.MaximumBytes, token);
        if (!ScriptHash(original).Equals(action.ExpectedSha256, StringComparison.OrdinalIgnoreCase) ||
            !SteamScriptRepair.TryRepair(original, out byte[] repaired) || repaired.Length != original.Length ||
            !ScriptHash(repaired).Equals(action.RepairedSha256, StringComparison.OrdinalIgnoreCase))
            throw ScriptDenied();
        QuarantineRecord record = new()
        {
            ActionId = action.ActionId, Type = action.Type, OriginalTarget = source.FinalPath,
            QuarantinedPath = destination, Sha256 = ScriptHash(original), RepairedSha256 = ScriptHash(repaired),
            OriginalFileIdentity = FileScopeSafety.ReadIdentity(source.Handle), OriginalParentIdentity = parent.ParentIdentity,
            OriginalSecurityDescriptor = metadata.SecurityDescriptor, OriginalAttributes = metadata.Attributes,
            OriginalCreationTimeUtc = metadata.CreationTimeUtc, OriginalLastWriteTimeUtc = metadata.LastWriteTimeUtc,
            VerifiedContentRuleId = SteamScriptRepair.RuleId
        };
        await persist(record, token);
        await source.CopyToAsync(destination, record.Sha256, token);
        protect(destination);
        token.ThrowIfCancellationRequested();
        RequireScriptIdentity(source, action.Target, record.OriginalFileIdentity);
        if (BrokerFileMetadata.CaptureLocked(source.Handle) != metadata) throw ScriptDenied();
        // This durable marker precedes the first write. Cancellation is honored up to this boundary.
        // After it, completion or restoration must finish even if the caller cancels.
        record.FileMutationAttempted = true;
        await persist(record, token);
        try
        {
            if (writeForTest is null) await source.WriteSameLengthAsync(repaired, CancellationToken.None);
            else await writeForTest(source, repaired);
            if (!(await source.ComputeSha256Async(CancellationToken.None)).Equals(record.RepairedSha256, StringComparison.OrdinalIgnoreCase))
                throw ScriptDenied("SteamScript.RepairFailed");
            metadata.ApplyTimesAndAttributes(source.Handle);
            RequireScriptIdentity(source, action.Target, record.OriginalFileIdentity);
        }
        catch (Exception failure)
        {
            record.MutationConfirmed = false;
            try
            {
                await source.WriteSameLengthAsync(original, CancellationToken.None);
                metadata.ApplyTimesAndAttributes(source.Handle);
                if (!(await source.ComputeSha256Async(CancellationToken.None)).Equals(record.Sha256, StringComparison.OrdinalIgnoreCase))
                    throw ScriptDenied("SteamScript.RepairFailed");
            }
            catch (Exception recovery)
            {
                throw MessageExceptions.Create(MessageText.Create("SteamScript.RepairFailed"),
                    text => new IOException(text, new AggregateException(failure, recovery)));
            }
            throw;
        }
        // Once the new image has been verified, a journal-commit failure must not start
        // a second byte mutation. The durable attempt record already permits recovery
        // from this complete image, whether the final manifest reached disk or not.
        record.MutationConfirmed = true;
        await persist(record, CancellationToken.None);
        return record;
    }

    private static void RequireScriptIdentity(SecureFileLease source, string target, string identity)
    {
        FileScopeSafety.ValidateHandlePath(source.Handle, target);
        if (!FileScopeSafety.ReadIdentity(source.Handle).Equals(identity, StringComparison.OrdinalIgnoreCase) ||
            FileScopeSafety.ReadLinkCount(source.Handle) != 1) throw ScriptDenied();
        BrokerFileMetadata.EnsureOnlyDefaultStream(source.Handle);
    }

    private static string ScriptHash(byte[] bytes) => Convert.ToHexString(SHA256.HashData(bytes));

    internal static void ValidateSteamScriptRecord(QuarantineRecord record, SteamLayout layout)
    {
        if (record.Type != RemediationActionType.RepairSteamScript || record.QuarantinedPath is null ||
            record.VerifiedContentRuleId != SteamScriptRepair.RuleId ||
            !SteamScriptRepairTarget.IsScriptPath(record.OriginalTarget, layout) ||
            !Validation.IsHexSha256(record.Sha256) || !Validation.IsHexSha256(record.RepairedSha256) ||
            !FileScopeSafety.IsValidIdentity(record.OriginalFileIdentity) ||
            !FileScopeSafety.IsValidIdentity(record.OriginalParentIdentity)) throw ScriptDenied("SteamScript.InvalidTarget");
        _ = BrokerFileMetadata.FromRecord(record);
    }

    internal static async Task RestoreSteamScriptFileAsync(QuarantineRecord record, SteamLayout layout, CancellationToken token,
        Func<QuarantineRecord, CancellationToken, Task>? persistBeforeWrite = null,
        Func<SecureFileLease, byte[], Task>? writeForTest = null)
    {
        ValidateSteamScriptRecord(record, layout);
        if (!record.FileMutationAttempted) return;
        using BrokerDirectoryLease parent = BrokerDirectoryLease.OpenParent(record.OriginalTarget, record.OriginalParentIdentity);
        (byte[] original, byte[] repaired) = await ReadVerifiedSteamScriptBackupAsync(record, token);
        await using SecureFileLease target = SecureFileLease.OpenForUpdate(record.OriginalTarget);
        RequireScriptIdentity(target, record.OriginalTarget, record.OriginalFileIdentity!);
        BrokerFileMetadata metadata = BrokerFileMetadata.FromRecord(record);
        BrokerFileMetadata currentMetadata = BrokerFileMetadata.CaptureLocked(target.Handle);
        if (currentMetadata.SecurityDescriptor != metadata.SecurityDescriptor || currentMetadata.Attributes != metadata.Attributes ||
            currentMetadata.CreationTimeUtc != metadata.CreationTimeUtc) throw ScriptDenied("SteamScript.RestoreChanged");
        byte[] current = await target.ReadBytesAsync(SteamScriptRepair.MaximumBytes, token);
        string hash = ScriptHash(current);
        bool unchanged = hash.Equals(record.Sha256, StringComparison.OrdinalIgnoreCase);
        bool repairedImage = hash.Equals(record.RepairedSha256, StringComparison.OrdinalIgnoreCase);
        if (!unchanged && !repairedImage &&
            (record.MutationConfirmed && !record.FileRollbackAttempted || !IsInterruptedScriptImage(current, original, repaired)))
            throw ScriptDenied("SteamScript.RestoreChanged");
        token.ThrowIfCancellationRequested();
        if (!unchanged)
        {
            record.FileRollbackAttempted = true;
            if (persistBeforeWrite is not null) await persistBeforeWrite(record, token);
            try
            {
                if (writeForTest is null) await target.WriteSameLengthAsync(original, CancellationToken.None);
                else await writeForTest(target, original);
                if (!(await target.ComputeSha256Async(CancellationToken.None)).Equals(record.Sha256, StringComparison.OrdinalIgnoreCase))
                    throw ScriptDenied("SteamScript.RepairFailed");
            }
            catch
            {
                await target.WriteSameLengthAsync(current, CancellationToken.None);
                throw;
            }
        }
        metadata.ApplyTimesAndAttributes(target.Handle);
        // Keep the authenticated backup until the incident is explicitly deleted. A crash between
        // restoration and manifest persistence can therefore retry without losing recovery bytes.
    }

    private static async Task<(byte[] Original, byte[] Repaired)> ReadVerifiedSteamScriptBackupAsync(
        QuarantineRecord record, CancellationToken token)
    {
        await using SecureFileLease backup = SecureFileLease.Open(record.QuarantinedPath!);
        byte[] original = await backup.ReadBytesAsync(SteamScriptRepair.MaximumBytes, token);
        if (FileScopeSafety.ReadLinkCount(backup.Handle) != 1 || !ScriptHash(original).Equals(record.Sha256, StringComparison.OrdinalIgnoreCase) ||
            !SteamScriptRepair.TryRepair(original, out byte[] repaired) ||
            !ScriptHash(repaired).Equals(record.RepairedSha256, StringComparison.OrdinalIgnoreCase))
            throw ScriptDenied("SteamScript.BackupFailed");
        return (original, repaired);
    }

    internal static bool IsInterruptedScriptImage(byte[] current, byte[] original, byte[] repaired)
    {
        if (current.Length != original.Length || repaired.Length != original.Length) return false;
        for (int i = 0; i < current.Length; i++)
            if (current[i] != original[i] && current[i] != repaired[i]) return false;
        return true;
    }
}
