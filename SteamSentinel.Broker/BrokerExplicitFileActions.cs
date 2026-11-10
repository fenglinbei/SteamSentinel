using SteamSentinel.Core.Models;
using SteamSentinel.Core.Remediation;
using SteamSentinel.Core.Utilities;

namespace SteamSentinel.Broker;

internal sealed partial class BrokerEngine
{
    private BrokerFileScopeAuthorization? _preparingFileTargets;
    private BrokerFileScopeAuthorization? _confirmedFileTargets;

    internal async Task<BrokerFileScopeAuthorization?> PrepareForConfirmationAsync(RemediationPlan plan,
        CancellationToken token = default)
    {
        ValidatePlan(plan);
        _confirmedFileTargets = null;
        BrokerFileScopeAuthorization? prepared = plan.ExplicitFileTargetsRequested
            ? await BrokerFileScopeAuthorization.PrepareAsync(plan, _rules, _steamLayout, token) : null;
        _preparingFileTargets = prepared;
        try { ValidateBeforeExecution(plan); }
        finally { _preparingFileTargets = null; }
        return prepared;
    }

    // Only Program calls this after its ordinary final confirmation returns Yes.
    // Neither deserializing a plan nor preparing its preview installs this authority.
    internal void ConfirmFileTargets(RemediationPlan plan, BrokerFileScopeAuthorization? prepared)
    {
        if (!plan.ExplicitFileTargetsRequested)
        {
            if (prepared is not null) throw BrokerScopeText.Denied(BrokerScopeText.NotAuthorized);
            return;
        }
        if (prepared is null) throw BrokerScopeText.Denied(BrokerScopeText.NotAuthorized);
        prepared.ConfirmOnce(plan);
        _confirmedFileTargets = prepared;
    }

    private void RequireFileAuthorization(RemediationPlan plan)
    {
        BrokerFileScopeAuthorization? authorization = _preparingFileTargets ?? _confirmedFileTargets;
        if (!plan.ExplicitFileTargetsRequested)
        {
            if (authorization is not null) throw BrokerScopeText.Denied(BrokerScopeText.NotAuthorized);
            return;
        }
        if (authorization is null) throw BrokerScopeText.Denied(BrokerScopeText.NotAuthorized);
        authorization.RequirePlan(plan);
    }

    private bool IsAllowedActionFileTarget(RemediationAction action, string path, string? hash)
    {
        BrokerFileScopeAuthorization? authorization = _preparingFileTargets ?? _confirmedFileTargets;
        return authorization is null ? IsAllowedFileTarget(path, hash) : authorization.Contains(action, path, hash);
    }

    private static void ValidateExplicitRestoreRecord(QuarantineRecord record)
    {
        if (record.Type != RemediationActionType.QuarantineFile || !Validation.IsHexSha256(record.Sha256) ||
            !FileScopeSafety.IsValidIdentity(record.OriginalFileIdentity) ||
            !FileScopeSafety.IsValidIdentity(record.OriginalParentIdentity))
            throw BrokerScopeText.Invalid(BrokerScopeText.RestoreMetadataInvalid);
        BrokerFileScopeAuthorization.RequireSafePath(record.OriginalTarget);
        _ = BrokerFileMetadata.FromRecord(record);
    }

    internal static async Task<QuarantineRecord> QuarantineExplicitFileAsync(RemediationAction action,
        BrokerFileScopeAuthorization authorization, string destination,
        Func<QuarantineRecord, CancellationToken, Task> persistBeforeMutation, Action<string> protectPayload, CancellationToken token)
    {
        using BrokerDirectoryLease parent = BrokerDirectoryLease.OpenParent(action.Target, action.ExpectedParentIdentity);
        await using SecureFileLease source = authorization.NeedsFullMetadata(action)
            ? SecureFileLease.OpenWithSecurity(action.Target) : SecureFileLease.Open(action.Target);
        VerifiedBrokerFileTarget verified = await authorization.VerifyLockedAsync(action, source, parent, token);
        QuarantineRecord record = new()
        {
            ActionId = action.ActionId,
            Type = RemediationActionType.QuarantineFile,
            OriginalTarget = source.FinalPath,
            QuarantinedPath = destination,
            Sha256 = verified.Sha256,
            ExplicitFileAuthorization = verified.Metadata is not null,
            OriginalFileIdentity = verified.FileIdentity,
            OriginalParentIdentity = verified.ParentIdentity,
            OriginalSecurityDescriptor = verified.Metadata?.SecurityDescriptor,
            OriginalAttributes = verified.Metadata?.Attributes,
            OriginalCreationTimeUtc = verified.Metadata?.CreationTimeUtc,
            OriginalLastWriteTimeUtc = verified.Metadata?.LastWriteTimeUtc
        };
        await persistBeforeMutation(record, token);
        await source.CopyToAsync(destination, verified.Sha256, token);
        protectPayload(destination);
        source.DeleteOnClose();
        try
        {
            // Delete-pending blocks new opens before the last stream/security check. Queries use
            // the already-open handle; on any drift, undo the disposition before closing it.
            // Windows excludes this delete-pending link from NumberOfLinks. Any remaining
            // link means the object acquired another name after the initial one-link check.
            if (FileScopeSafety.ReadLinkCount(source.Handle) != 0)
                throw BrokerScopeText.Denied(BrokerScopeText.HardLinks);
            if (verified.Metadata is not null)
            {
                if (BrokerFileMetadata.CaptureLocked(source.Handle) != verified.Metadata)
                    throw BrokerScopeText.Denied(BrokerScopeText.IdentityChanged);
            }
            else BrokerFileMetadata.EnsureOnlyDefaultStream(source.Handle);
        }
        catch { source.CancelDelete(); throw; }
        return record;
    }

    /// <summary>Only called with a record from LoadTrustedManifestAsync and an explicitly confirmed rollback.</summary>
    internal static async Task RestoreExplicitFileAsync(QuarantineRecord record, CancellationToken token)
    {
        ValidateExplicitRestoreRecord(record);
        if (record.QuarantinedPath is null) throw BrokerScopeText.Invalid(BrokerScopeText.RestoreMetadataInvalid);
        if (File.Exists(record.OriginalTarget) || Directory.Exists(record.OriginalTarget))
            throw BrokerScopeText.Io(BrokerScopeText.IdentityChanged);
        using BrokerDirectoryLease parent = BrokerDirectoryLease.OpenParent(record.OriginalTarget, record.OriginalParentIdentity);
        BrokerFileMetadata metadata = BrokerFileMetadata.FromRecord(record);
        await using SecureFileLease payload = SecureFileLease.Open(record.QuarantinedPath);
        if (FileScopeSafety.ReadLinkCount(payload.Handle) != 1 ||
            !(await payload.ComputeSha256Async(token)).Equals(record.Sha256, StringComparison.OrdinalIgnoreCase))
            throw BrokerScopeText.Invalid(BrokerScopeText.RestoreMetadataInvalid);
        // The privilege only restores the saved metadata to a newly created exact target.
        // It is never enabled while opening or modifying the original scanned file.
        using (BrokerRestorePrivilege security = BrokerRestorePrivilege.EnableSecurity())
        using (BrokerRestorePrivilege privilege = BrokerRestorePrivilege.EnableWhenAvailable())
            await payload.CopyToAsync(record.OriginalTarget, record.Sha256!, token,
                handle => metadata.Apply(handle, record.OriginalTarget));
        payload.DeleteOnClose();
    }
}
