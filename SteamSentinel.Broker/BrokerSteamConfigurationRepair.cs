using System.Diagnostics;
using Microsoft.Win32;
using Microsoft.Win32.SafeHandles;
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
            !SteamConfigurationRepair.IsRemovedOnRepair(snapshot.Kind) && (!Validation.IsHexSha256(action.RepairedSha256) ||
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
        if (snapshot.Kind == SteamConfigurationRepair.PackageRestore)
        {
            if (action.RelatedFilePath is not null || action.RelatedFileSha256 is not null)
                throw ConfigDenied("SteamConfig.InvalidTarget");
            ValidatePackageRestoreSnapshot(snapshot, action.Target, layout);
        }
        else if (HasAnyPackageSnapshotField(snapshot))
        {
            throw ConfigDenied("SteamConfig.InvalidTarget");
        }
        if (snapshot.Kind == SteamConfigurationRepair.Shortcut &&
            (snapshot.OriginalValue is not null || snapshot.RepairedValue is not null || snapshot.RegistryValueKind is not null) ||
            (snapshot.Kind is SteamConfigurationRepair.Cfg or SteamConfigurationRepair.UiFile or SteamConfigurationRepair.PackageRestore && snapshot.SteamExecutable is not null) ||
            SteamConfigurationRepair.IsRemovedOnRepair(snapshot.Kind) && action.RepairedSha256 is not null)
            throw ConfigDenied("SteamConfig.InvalidTarget");
    }

    private static bool HasAnyPackageSnapshotField(SteamConfigurationSnapshot snapshot) =>
        snapshot.PackageName is not null ||
        snapshot.PackageRelativePath is not null ||
        snapshot.PackageArchiveFile is not null ||
        snapshot.PackageArchiveSha256 is not null ||
        snapshot.PackageIsVz;

    private static void ValidatePackageRestoreSnapshot(SteamConfigurationSnapshot snapshot, string target, SteamLayout layout)
    {
        if (string.IsNullOrWhiteSpace(snapshot.PackageName) ||
            string.IsNullOrWhiteSpace(snapshot.PackageRelativePath) ||
            string.IsNullOrWhiteSpace(snapshot.PackageArchiveFile) ||
            !Validation.IsHexSha256(snapshot.PackageArchiveSha256) ||
            !SteamPackageCatalog.TryNormalizeRelativePath(snapshot.PackageRelativePath, out string normalizedRelative) ||
            !string.Equals(normalizedRelative, snapshot.PackageRelativePath, StringComparison.OrdinalIgnoreCase) ||
            !SteamPackageCatalog.IsSafePackageFileName(snapshot.PackageArchiveFile) ||
            !SteamConfigurationRepairTarget.TryResolvePackageRestoreRoot(target, layout, out _, out string targetRelative) ||
            !string.Equals(targetRelative, normalizedRelative, StringComparison.OrdinalIgnoreCase))
        {
            throw ConfigDenied("SteamConfig.InvalidTarget");
        }
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

    private async Task EnsureSteamClosedForConfigurationAsync(CancellationToken token)
    {
        try
        {
            _ = await _steamProcessController
                .EnsureClosedAsync(_steamLayout, cancellationToken: token)
                .ConfigureAwait(false);
        }
        catch (InvalidOperationException ex)
        {
            throw MessageExceptions.Create(MessageText.Create("SteamConfig.CloseSteam"), text => new InvalidOperationException(text, ex));
        }
    }

    private async Task<MessageText> RepairSteamConfigurationAsync(RemediationAction action, CancellationToken token)
    {
        await EnsureSteamClosedForConfigurationAsync(token).ConfigureAwait(false);
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
            PreparePayloadDirectory(itemRoot);
            string destination = Path.Combine(itemRoot, SafeName(Path.GetFileName(action.Target)) + ".original");
            if (SteamConfigurationRepair.IsRemovedOnRepair(action.ConfigurationKind))
                await QuarantineSteamMarkerAsync(action, _steamLayout, destination, Persist, ProtectPayloadFile, token);
            else if (action.ConfigurationKind == SteamConfigurationRepair.PackageRestore)
                await RepairSteamPackageRestoreFileAsync(action, _steamLayout, destination, Persist, ProtectPayloadFile, token, _verifySteamPackageExecutable);
            else
                await RepairSteamConfigurationFileAsync(action, _steamLayout, destination, Persist, ProtectPayloadFile, token);
        }
        return MessageText.Create("SteamConfig.Repaired");
    }

    /// <summary>
    /// Broker 独立重新读取本地官方分包清单并校验与解压官方文件（零信任客户端传参），随后在独占句柄上备份原件并完成不等长原位写入。
    /// </summary>
    internal static async Task<QuarantineRecord> RepairSteamPackageRestoreFileAsync(
        RemediationAction action,
        SteamLayout layout,
        string destination,
        Func<QuarantineRecord, CancellationToken, Task> persist,
        Action<string> protect,
        CancellationToken token,
        Func<string, SafeFileHandle?, SignatureResult>? verifyExecutableSignature = null,
        Func<SecureFileLease, byte[], Task>? writeForTest = null)
    {
        ValidateSteamConfigurationAction(action, layout);
        if (action.ConfigurationKind != SteamConfigurationRepair.PackageRestore)
            throw ConfigDenied("SteamConfig.InvalidTarget");

        SteamConfigurationSnapshot snapshot = SteamConfigurationRepairTarget.ReadSnapshot(action.ConfigurationSnapshot);
        if (!SteamConfigurationRepairTarget.TryResolvePackageRestoreRoot(action.Target, layout, out string steamRoot, out string normalizedRel) ||
            !SteamPackageCatalog.TryLoadForSteamRoot(steamRoot, out SteamPackageCatalog? catalog) ||
            (catalog.HasVerifiedInstalledIndex && !catalog.IsKnownOfficialRelativePath(normalizedRel)))
            throw ConfigDenied("SteamConfig.InvalidTarget");

        if (!catalog.TryGetPackage(snapshot.PackageName!, out SteamPackageEntry? packageEntry))
            throw ConfigDenied("SteamConfig.RepairFailed");

        string archiveFileName;
        string expectedArchiveSha256;
        if (snapshot.PackageIsVz)
        {
            if (string.IsNullOrEmpty(packageEntry.ZipVzFile) ||
                string.IsNullOrEmpty(packageEntry.Sha256Vz) ||
                !string.Equals(packageEntry.ZipVzFile, snapshot.PackageArchiveFile, StringComparison.OrdinalIgnoreCase) ||
                !string.Equals(packageEntry.Sha256Vz, snapshot.PackageArchiveSha256, StringComparison.OrdinalIgnoreCase))
                throw ConfigDenied("SteamConfig.InvalidTarget");
            archiveFileName = packageEntry.ZipVzFile;
            expectedArchiveSha256 = packageEntry.Sha256Vz;
        }
        else
        {
            if (!string.Equals(packageEntry.ZipFile, snapshot.PackageArchiveFile, StringComparison.OrdinalIgnoreCase) ||
                !string.Equals(packageEntry.Sha256, snapshot.PackageArchiveSha256, StringComparison.OrdinalIgnoreCase))
                throw ConfigDenied("SteamConfig.InvalidTarget");
            archiveFileName = packageEntry.ZipFile;
            expectedArchiveSha256 = packageEntry.Sha256;
        }

        string archivePath = Path.Combine(catalog.PackageDirectory, archiveFileName);
        if (!ContentDiscovery.IsLocalSafePath(archivePath) || !File.Exists(archivePath))
            throw ConfigDenied("SteamConfig.RepairFailed");

        SteamPackageExtractResult? extracted = snapshot.PackageIsVz
            ? await SteamPackageArchive.ExtractFromVzFileAsync(archivePath, packageEntry, normalizedRel, expectedArchiveSha256, downloaded: false, token).ConfigureAwait(false)
            : await SteamPackageArchive.ExtractFromZipFileAsync(archivePath, packageEntry, normalizedRel, expectedArchiveSha256, downloaded: false, token).ConfigureAwait(false);
        if (extracted is null)
            throw ConfigDenied("SteamConfig.RepairFailed");

        string verifiedExtractedSha256 = SteamConfigurationRepair.Hash(extracted.Content);
        if (!verifiedExtractedSha256.Equals(extracted.Sha256, StringComparison.OrdinalIgnoreCase) ||
            !verifiedExtractedSha256.Equals(action.RepairedSha256, StringComparison.OrdinalIgnoreCase) ||
            verifiedExtractedSha256.Equals(action.ExpectedSha256, StringComparison.OrdinalIgnoreCase))
            throw ConfigDenied("SteamConfig.RepairFailed");

        string verificationRoot = Path.GetDirectoryName(destination)
            ?? throw ConfigDenied("SteamConfig.RepairFailed");
        await SteamConfigurationRepairTarget.VerifyExtractedOfficialContentAsync(
            normalizedRel,
            extracted.Content,
            verificationRoot,
            verifyExecutableSignature,
            token).ConfigureAwait(false);

        using BrokerDirectoryLease parent = BrokerDirectoryLease.OpenParent(action.Target, action.ExpectedParentIdentity);
        await using SecureFileLease source = SecureFileLease.OpenForUpdate(action.Target);
        RequireConfigurationIdentity(source, action.Target, action.ExpectedFileIdentity!);
        BrokerFileMetadata metadata = BrokerFileMetadata.CaptureLocked(source.Handle);
        byte[] original = await source.ReadBytesAsync(SteamConfigurationRepair.MaximumPackageRestoreBytes, token, allowEmpty: true);
        if (!SteamConfigurationRepair.Hash(original).Equals(action.ExpectedSha256, StringComparison.OrdinalIgnoreCase))
            throw ConfigDenied();

        return await CommitLockedFileRepairAsync(
            action,
            source,
            parent,
            metadata,
            destination,
            original,
            extracted.Content,
            useTruncateWrite: true,
            persist,
            protect,
            writeForTest,
            token).ConfigureAwait(false);
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

        return await CommitLockedFileRepairAsync(
            action,
            source,
            parent,
            metadata,
            destination,
            original,
            repaired,
            useTruncateWrite: false,
            persist,
            protect,
            writeForTest,
            token).ConfigureAwait(false);
    }

    private static async Task<QuarantineRecord> CommitLockedFileRepairAsync(
        RemediationAction action,
        SecureFileLease source,
        BrokerDirectoryLease parent,
        BrokerFileMetadata metadata,
        string destination,
        byte[] original,
        byte[] repaired,
        bool useTruncateWrite,
        Func<QuarantineRecord, CancellationToken, Task> persist,
        Action<string> protect,
        Func<SecureFileLease, byte[], Task>? writeForTest,
        CancellationToken token)
    {
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
            if (writeForTest is null)
                await WriteConfigurationBytesAsync(source, repaired, useTruncateWrite, CancellationToken.None);
            else
                await writeForTest(source, repaired);
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
                await WriteConfigurationBytesAsync(source, original, useTruncateWrite, CancellationToken.None);
                metadata.ApplyTimesAndAttributes(source.Handle);
                if (!(await source.ComputeSha256Async(CancellationToken.None)).Equals(record.Sha256, StringComparison.OrdinalIgnoreCase))
                    throw ConfigDenied("SteamConfig.RepairFailed");
            }
            catch (Exception recovery)
            { throw MessageExceptions.Create(MessageText.Create("SteamConfig.RepairFailed"), text => new IOException(text, new AggregateException(failure, recovery))); }
            throw;
        }
        record.MutationConfirmed = true;
        await persist(record, CancellationToken.None);
        return record;
    }

    private static Task WriteConfigurationBytesAsync(SecureFileLease lease, byte[] content, bool useTruncateWrite, CancellationToken token) =>
        useTruncateWrite ? lease.WriteExactBytesWithTruncateAsync(content, token) : lease.WriteSameLengthAsync(content, token);

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
        if (!SteamConfigurationRepair.IsRemovedOnRepair(action.ConfigurationKind)) throw ConfigDenied("SteamConfig.InvalidTarget");
        using BrokerDirectoryLease parent = BrokerDirectoryLease.OpenParent(action.Target, action.ExpectedParentIdentity);
        await using SecureFileLease source = SecureFileLease.OpenWithSecurity(action.Target);
        RequireConfigurationIdentity(source, action.Target, action.ExpectedFileIdentity!);
        if (source.Length > SteamConfigurationRepair.MaximumBytesFor(action.ConfigurationKind) || !(await source.ComputeSha256Async(token)).Equals(action.ExpectedSha256, StringComparison.OrdinalIgnoreCase)) throw ConfigDenied();
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
                !SteamConfigurationRepair.IsRemovedOnRepair(snapshot.Kind) && !Validation.IsHexSha256(record.RepairedSha256)) throw ConfigDenied("SteamConfig.InvalidTarget");
            _ = BrokerFileMetadata.FromRecord(record);
        }
        if (snapshot.Kind is SteamConfigurationRepair.Run or SteamConfigurationRepair.Shortcut &&
            (!SteamConfigurationRepair.IsSteamExecutable(snapshot.SteamExecutable, layout) ||
            !string.Equals(record.RelatedFilePath, snapshot.SteamExecutable, StringComparison.OrdinalIgnoreCase) || !Validation.IsHexSha256(record.RelatedFileSha256)))
            throw ConfigDenied("SteamConfig.InvalidTarget");
        if (snapshot.Kind == SteamConfigurationRepair.PackageRestore)
        {
            if (record.RelatedFilePath is not null || record.RelatedFileSha256 is not null)
                throw ConfigDenied("SteamConfig.InvalidTarget");
            ValidatePackageRestoreSnapshot(snapshot, record.OriginalTarget, layout);
        }
        else if (HasAnyPackageSnapshotField(snapshot))
        {
            throw ConfigDenied("SteamConfig.InvalidTarget");
        }
        if (snapshot.Kind != SteamConfigurationRepair.Run &&
            (snapshot.OriginalValue is not null || snapshot.RepairedValue is not null || snapshot.RegistryValueKind is not null) ||
            snapshot.Kind is SteamConfigurationRepair.Cfg or SteamConfigurationRepair.Marker or SteamConfigurationRepair.UiFile or SteamConfigurationRepair.PackageRestore && snapshot.SteamExecutable is not null ||
            SteamConfigurationRepair.IsRemovedOnRepair(snapshot.Kind) && record.RepairedSha256 is not null)
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
        int maximumBytes = SteamConfigurationRepair.MaximumBytesFor(record.ConfigurationKind);
        if (backup.Length > maximumBytes || FileScopeSafety.ReadLinkCount(backup.Handle) != 1) throw ConfigDenied("SteamConfig.BackupFailed");
        BrokerFileMetadata.EnsureOnlyDefaultStream(backup.Handle);
        byte[] original = backup.Length == 0 ? [] : await backup.ReadBytesAsync(maximumBytes, token);
        if (!SteamConfigurationRepair.Hash(original).Equals(record.Sha256, StringComparison.OrdinalIgnoreCase)) throw ConfigDenied("SteamConfig.BackupFailed");
        if (SteamConfigurationRepair.IsRemovedOnRepair(record.ConfigurationKind) ||
            record.ConfigurationKind == SteamConfigurationRepair.PackageRestore)
            return (original, []);
        if (!SteamConfigurationRepairTarget.TryRepair(record.ConfigurationKind!, original, layout, out byte[] repaired, out string? executable) ||
            !SteamConfigurationRepair.Hash(repaired).Equals(record.RepairedSha256, StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(executable, record.RelatedFilePath, StringComparison.OrdinalIgnoreCase)) throw ConfigDenied("SteamConfig.BackupFailed");
        return (original, repaired);
    }

    private async Task RestoreSteamConfigurationAsync(QuarantineRecord record, CancellationToken token,
        Func<QuarantineRecord, CancellationToken, Task>? persistBeforeWrite = null)
    {
        await EnsureSteamClosedForConfigurationAsync(token).ConfigureAwait(false);
        ValidateSteamConfigurationRecord(record, _steamLayout);
        if (record.ConfigurationKind == SteamConfigurationRepair.Run)
            RestoreSteamRunValue(record, _steamLayout);
        else if (SteamConfigurationRepair.IsRemovedOnRepair(record.ConfigurationKind))
            await RestoreSteamMarkerAsync(record, _steamLayout, token);
        else await RestoreSteamConfigurationFileAsync(record, _steamLayout, token, persistBeforeWrite);
    }

    internal static bool IsInterruptedScriptImage(byte[] current, byte[] original, byte[] repaired)
    {
        if (current.Length != original.Length || repaired.Length != original.Length) return false;
        for (int i = 0; i < current.Length; i++)
            if (current[i] != original[i] && current[i] != repaired[i]) return false;
        return true;
    }

    internal static async Task RestoreSteamConfigurationFileAsync(QuarantineRecord record, SteamLayout layout, CancellationToken token,
        Func<QuarantineRecord, CancellationToken, Task>? persistBeforeWrite = null,
        Func<SecureFileLease, byte[], Task>? writeForTest = null)
    {
        ValidateSteamConfigurationRecord(record, layout);
        if (!record.FileMutationAttempted) return;
        bool isPackageRestore = record.ConfigurationKind == SteamConfigurationRepair.PackageRestore;
        if (record.ConfigurationKind is not (SteamConfigurationRepair.Cfg or SteamConfigurationRepair.Shortcut or SteamConfigurationRepair.PackageRestore))
            throw ConfigDenied("SteamConfig.InvalidTarget");
        using BrokerDirectoryLease parent = BrokerDirectoryLease.OpenParent(record.OriginalTarget, record.OriginalParentIdentity);
        (byte[] original, byte[] repaired) = await ReadVerifiedSteamConfigurationBackupAsync(record, layout, token);
        await using SecureFileLease target = SecureFileLease.OpenForUpdate(record.OriginalTarget);
        RequireConfigurationIdentity(target, record.OriginalTarget, record.OriginalFileIdentity!);
        BrokerFileMetadata metadata = BrokerFileMetadata.FromRecord(record);
        BrokerFileMetadata currentMetadata = BrokerFileMetadata.CaptureLocked(target.Handle);
        if (currentMetadata.SecurityDescriptor != metadata.SecurityDescriptor || currentMetadata.Attributes != metadata.Attributes ||
            currentMetadata.CreationTimeUtc != metadata.CreationTimeUtc) throw ConfigDenied("SteamConfig.RestoreChanged");
        int maximumBytes = SteamConfigurationRepair.MaximumBytesFor(record.ConfigurationKind);
        byte[] current = await target.ReadBytesAsync(maximumBytes, token, allowEmpty: !record.MutationConfirmed || isPackageRestore);
        string hash = SteamConfigurationRepair.Hash(current);
        bool unchanged = hash.Equals(record.Sha256, StringComparison.OrdinalIgnoreCase);
        bool repairedImage = hash.Equals(record.RepairedSha256, StringComparison.OrdinalIgnoreCase);
        if (isPackageRestore)
        {
            // 原位恢复回滚前核验当前文件仍为我们写入的官方版本（或尚未改动），禁止覆盖后续新版文件。
            if (!unchanged && !repairedImage)
                throw ConfigDenied("SteamConfig.RestoreChanged");
        }
        else if (!unchanged && !repairedImage &&
            (record.MutationConfirmed && !record.FileRollbackAttempted || !IsInterruptedScriptImage(current, original, repaired)))
            throw ConfigDenied("SteamConfig.RestoreChanged");
        token.ThrowIfCancellationRequested();
        if (!unchanged)
        {
            record.FileRollbackAttempted = true;
            if (persistBeforeWrite is not null) await persistBeforeWrite(record, token);
            try
            {
                if (writeForTest is null)
                    await WriteConfigurationBytesAsync(target, original, isPackageRestore, CancellationToken.None);
                else
                    await writeForTest(target, original);
                if (!(await target.ComputeSha256Async(CancellationToken.None)).Equals(record.Sha256, StringComparison.OrdinalIgnoreCase)) throw ConfigDenied("SteamConfig.RepairFailed");
            }
            catch
            {
                await WriteConfigurationBytesAsync(target, current, isPackageRestore, CancellationToken.None);
                throw;
            }
        }
        metadata.ApplyTimesAndAttributes(target.Handle);
    }

    internal static async Task RestoreSteamMarkerAsync(QuarantineRecord record, SteamLayout layout, CancellationToken token)
    {
        ValidateSteamConfigurationRecord(record, layout);
        if (!record.FileMutationAttempted) return;
        if (!SteamConfigurationRepair.IsRemovedOnRepair(record.ConfigurationKind)) throw ConfigDenied("SteamConfig.InvalidTarget");
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
