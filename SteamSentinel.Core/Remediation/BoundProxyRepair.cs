using SteamSentinel.Core.Reporting;
using System.Security.Principal;
using SteamSentinel.Core.Models;

namespace SteamSentinel.Core.Remediation;

/// <summary>Only the current token's default/LAN WinINet configuration. No URLs are resolved or fetched.</summary>
public interface IBoundProxySettings
{
    BoundProxySnapshot ReadCurrentUserLan();
    void WriteCurrentUserLan(BoundProxySnapshot desired, IReadOnlyList<BoundProxyField> changedFields);
    void NotifySettingsChanged();
    void RefreshSettings();
}

/// <summary>
/// A bounded configuration adapter, not an authorization source. Broker must independently authorize
/// the exact target, persist Capture's result before Apply, and persist the mutable backup in finally.
/// Windows exposes no atomic compare-and-set here: two reads reduce but cannot eliminate a race
/// between the final comparison and the setter. A mismatched or unreadable readback is never clean.
/// </summary>
public sealed class BoundProxyRepair(IBoundProxySettings settings, Func<string> currentSid)
{
    public const string SupportedSource = "WinInetCurrentUserLan";
    public const int MaximumStringCharacters = 16_384;
    public const int MaximumSnapshotCharacters = 32_768;
    private const uint KnownFlags = 0x0f;

    public BoundProxyBackup Capture(BoundProxyTarget target)
    {
        ValidateTarget(target);
        RequireIdentity(target.TargetUserSid);
        RequireSnapshot(settings.ReadCurrentUserLan(), target.Before, MessageText.Create("Backend.Core.BoundProxyRepair.Capture.01"));
        return new()
        {
            TargetUserSid = target.TargetUserSid,
            Source = target.Source,
            Before = target.Before,
            After = target.Desired,
            ChangedFields = [.. target.ChangedFields],
            MutationState = BoundProxyMutationState.Prepared
        };
    }

    public void Apply(BoundProxyTarget target, BoundProxyBackup backup)
    {
        ValidateTarget(target);
        ValidateBackup(backup);
        if (backup.Source != target.Source || backup.TargetUserSid != target.TargetUserSid ||
            !SnapshotsEqual(backup.Before, target.Before) || !SnapshotsEqual(backup.After, target.Desired) ||
            !backup.ChangedFields.ToHashSet().SetEquals(target.ChangedFields) ||
            backup.WriteAttempted || backup.MutationState != BoundProxyMutationState.Prepared)
            throw MessageExceptions.Create(MessageText.Create("Backend.Core.BoundProxyRepair.Apply.01"), sourceText => new InvalidDataException(sourceText));
        RequireBeforeWrite(target.TargetUserSid, target.Before);
        // Journal must already be durable. Any exception after this point can follow an actual write.
        backup.WriteAttempted = true;
        backup.MutationState = BoundProxyMutationState.Indeterminate;
        try
        {
            settings.WriteCurrentUserLan(backup.After, backup.ChangedFields);
            backup.WriteSucceeded = true;
            ClassifyReadback(backup, restoring: false);
            if (!backup.ReadBackMatched) throw MessageExceptions.Create(MessageText.Create("Backend.Core.BoundProxyRepair.Apply.02"), sourceText => new IOException(sourceText));
            settings.NotifySettingsChanged();
            backup.SettingsChangedNotified = true;
            settings.RefreshSettings();
            backup.RefreshNotified = true;
            ClassifyReadback(backup, restoring: false);
            if (!backup.ReadBackMatched) throw MessageExceptions.Create(MessageText.Create("Backend.Core.BoundProxyRepair.Apply.03"), sourceText => new IOException(sourceText));
            backup.DiagnosticText = MessageText.Create("Backend.Core.BoundProxyRepair.Apply.04");
        }
        catch
        {
            TryClassifyReadback(backup, restoring: false);
            backup.DiagnosticText = MessageText.Create("Backend.Core.BoundProxyRepair.Apply.05");
            throw;
        }
    }

    public void Restore(BoundProxyBackup backup)
    {
        ValidateBackup(backup);
        if (!backup.WriteAttempted || backup.MutationState is not (BoundProxyMutationState.Applied or BoundProxyMutationState.Restored))
            throw MessageExceptions.Create(MessageText.Create("Backend.Core.BoundProxyRepair.Restore.01"), sourceText => new InvalidOperationException(sourceText));
        bool alreadyRestored = backup.MutationState == BoundProxyMutationState.Restored;
        RequireBeforeWrite(backup.TargetUserSid, alreadyRestored ? backup.Before : backup.After);
        backup.RestoreAttempted = true;
        try
        {
            if (!alreadyRestored)
            {
                backup.MutationState = BoundProxyMutationState.Indeterminate;
                settings.WriteCurrentUserLan(backup.Before, backup.ChangedFields);
                backup.RestoreWriteSucceeded = true;
            }
            ClassifyReadback(backup, restoring: true);
            if (!backup.RestoreReadBackMatched) throw MessageExceptions.Create(MessageText.Create("Backend.Core.BoundProxyRepair.Restore.02"), sourceText => new IOException(sourceText));
            settings.NotifySettingsChanged();
            backup.RestoreSettingsChangedNotified = true;
            settings.RefreshSettings();
            backup.RestoreRefreshNotified = true;
            ClassifyReadback(backup, restoring: true);
            if (!backup.RestoreReadBackMatched) throw MessageExceptions.Create(MessageText.Create("Backend.Core.BoundProxyRepair.Restore.03"), sourceText => new IOException(sourceText));
            backup.DiagnosticText = MessageText.Create("Backend.Core.BoundProxyRepair.Restore.04");
        }
        catch
        {
            TryClassifyReadback(backup, restoring: true);
            backup.DiagnosticText = MessageText.Create("Backend.Core.BoundProxyRepair.Restore.05");
            throw;
        }
    }

    public RemediationVerificationObservation Probe(BoundProxyTarget target)
    {
        try
        {
            ValidateTarget(target);
            RequireIdentity(target.TargetUserSid);
            BoundProxySnapshot actual = settings.ReadCurrentUserLan();
            ValidateSnapshot(actual);
            if (!PoliciesEqual(actual.PolicyGuard, target.Desired.PolicyGuard))
                return State(RemediationVerificationStatus.Unknown, MessageText.Create("Backend.Core.BoundProxyRepair.Probe.01"));
            return SnapshotsEqual(actual, target.Desired)
                ? State(RemediationVerificationStatus.Verified, MessageText.Create("Backend.Core.BoundProxyRepair.Probe.02"))
                : State(RemediationVerificationStatus.ResidualDetected, MessageText.Create("Backend.Core.BoundProxyRepair.Probe.03"));
        }
        catch (Exception ex) when (ex is not OutOfMemoryException and not StackOverflowException)
        {
            return State(RemediationVerificationStatus.Unknown, MessageText.Create("Backend.Core.BoundProxyRepair.Probe.04") + ex.GetType().Name + "。");
        }
    }

    public static void ValidateTarget(BoundProxyTarget target)
    {
        ArgumentNullException.ThrowIfNull(target);
        if (target.Source != SupportedSource)
            throw MessageExceptions.Create(MessageText.Create("Backend.Core.BoundProxyRepair.ValidateTarget.01"), sourceText => new NotSupportedException(sourceText));
        ValidateSid(target.TargetUserSid);
        ValidateSnapshot(target.Before);
        ValidateSnapshot(target.Desired);
        if (!PoliciesEqual(target.Before.PolicyGuard, target.Desired.PolicyGuard))
            throw MessageExceptions.Create(MessageText.Create("Backend.Core.BoundProxyRepair.ValidateTarget.02"), sourceText => new InvalidDataException(sourceText));
        if (((target.Before.Flags ^ target.Desired.Flags) & ~KnownFlags) != 0)
            throw MessageExceptions.Create(MessageText.Create("Backend.Core.BoundProxyRepair.ValidateTarget.03"), sourceText => new InvalidDataException(sourceText));
        List<BoundProxyField> difference = [];
        if (target.Before.Flags != target.Desired.Flags) difference.Add(BoundProxyField.Flags);
        if (!StringsEqual(target.Before.ProxyServer, target.Desired.ProxyServer)) difference.Add(BoundProxyField.ProxyServer);
        if (!StringsEqual(target.Before.ProxyBypass, target.Desired.ProxyBypass)) difference.Add(BoundProxyField.ProxyBypass);
        if (!StringsEqual(target.Before.AutoConfigUrl, target.Desired.AutoConfigUrl)) difference.Add(BoundProxyField.AutoConfigUrl);
        if (target.ChangedFields is null || target.ChangedFields.Count is < 1 or > 4 ||
            target.ChangedFields.Any(field => !Enum.IsDefined(field)) ||
            target.ChangedFields.Distinct().Count() != target.ChangedFields.Count ||
            !target.ChangedFields.ToHashSet().SetEquals(difference))
            throw MessageExceptions.Create(MessageText.Create("Backend.Core.BoundProxyRepair.ValidateTarget.04"), sourceText => new InvalidDataException(sourceText));
    }

    public static void ValidateSnapshot(BoundProxySnapshot snapshot)
    {
        ArgumentNullException.ThrowIfNull(snapshot);
        ValidateString(snapshot.ProxyServer);
        ValidateString(snapshot.ProxyBypass);
        ValidateString(snapshot.AutoConfigUrl);
        if ((long)(snapshot.ProxyServer.Value?.Length ?? 0) + (snapshot.ProxyBypass.Value?.Length ?? 0) +
            (snapshot.AutoConfigUrl.Value?.Length ?? 0) > MaximumSnapshotCharacters)
            throw MessageExceptions.Create(MessageText.Create("Backend.Core.BoundProxyRepair.ValidateSnapshot.01"), sourceText => new InvalidDataException(sourceText));
        BoundProxyPolicyGuard guard = snapshot.PolicyGuard ?? throw MessageExceptions.Create(MessageText.Create("Backend.Core.BoundProxyRepair.ValidateSnapshot.02"), sourceText => new InvalidDataException(sourceText));
        guard.DetailMessage?.Validate();
        if (guard.Status != BoundProxyPolicyStatus.Unmanaged)
            throw MessageExceptions.Create(MessageText.Create("Backend.Core.BoundProxyRepair.ValidateSnapshot.03"), sourceText => new NotSupportedException(sourceText));
        if (guard.Fingerprint is null || guard.Fingerprint.Length != 64 || !guard.Fingerprint.All(Uri.IsHexDigit) ||
            guard.Detail is null || guard.Detail.Length > 512)
            throw MessageExceptions.Create(MessageText.Create("Backend.Core.BoundProxyRepair.ValidateSnapshot.04"), sourceText => new InvalidDataException(sourceText));
    }

    public static bool SnapshotsEqual(BoundProxySnapshot? left, BoundProxySnapshot? right) =>
        left is not null && right is not null && left.Flags == right.Flags &&
        StringsEqual(left.ProxyServer, right.ProxyServer) && StringsEqual(left.ProxyBypass, right.ProxyBypass) &&
        StringsEqual(left.AutoConfigUrl, right.AutoConfigUrl) && PoliciesEqual(left.PolicyGuard, right.PolicyGuard);

    private static bool StringsEqual(BoundProxyString? left, BoundProxyString? right) =>
        left is not null && right is not null && left.Present == right.Present && string.Equals(left.Value, right.Value, StringComparison.Ordinal);
    private static bool PoliciesEqual(BoundProxyPolicyGuard? left, BoundProxyPolicyGuard? right) =>
        left is not null && right is not null && left.Status == right.Status &&
        string.Equals(left.Fingerprint, right.Fingerprint, StringComparison.Ordinal);
    private static void ValidateString(BoundProxyString? value)
    {
        if (value is null || value.Present != (value.Value is not null) || value.Value is { Length: > MaximumStringCharacters } ||
            value.Value?.Contains('\0') == true || value.Value is { } text && !HasValidUtf16(text))
            throw MessageExceptions.Create(MessageText.Create("Backend.Core.BoundProxyRepair.ValidateString.01"), sourceText => new InvalidDataException(sourceText));
    }
    private static bool HasValidUtf16(string value)
    {
        for (int index = 0; index < value.Length; index++)
        {
            char character = value[index];
            if (char.IsHighSurrogate(character))
            {
                if (++index >= value.Length || !char.IsLowSurrogate(value[index])) return false;
            }
            else if (char.IsLowSurrogate(character)) return false;
        }
        return true;
    }
    private static void ValidateSid(string sid)
    {
        if (string.IsNullOrEmpty(sid) || sid.Length > 184) throw MessageExceptions.Create(MessageText.Create("Backend.Core.BoundProxyRepair.ValidateSid.01"), sourceText => new InvalidDataException(sourceText));
        try { if (new SecurityIdentifier(sid).Value != sid) throw MessageExceptions.Create(MessageText.Create("Backend.Core.BoundProxyRepair.ValidateSid.02"), sourceText => new InvalidDataException(sourceText)); }
        catch (ArgumentException ex) { throw MessageExceptions.Create(MessageText.Create("Backend.Core.BoundProxyRepair.ValidateSid.03"), sourceText => new InvalidDataException(sourceText, ex)); }
    }
    private void RequireIdentity(string targetSid)
    {
        if (!string.Equals(currentSid(), targetSid, StringComparison.Ordinal))
            throw MessageExceptions.Create(MessageText.Create("Backend.Core.BoundProxyRepair.RequireIdentity.01"), sourceText => new UnauthorizedAccessException(sourceText));
    }
    private void RequireBeforeWrite(string sid, BoundProxySnapshot expected)
    {
        RequireIdentity(sid);
        RequireSnapshot(settings.ReadCurrentUserLan(), expected, MessageText.Create("Backend.Core.BoundProxyRepair.RequireBeforeWrite.01"));
        RequireIdentity(sid);
        RequireSnapshot(settings.ReadCurrentUserLan(), expected, MessageText.Create("Backend.Core.BoundProxyRepair.RequireBeforeWrite.02"));
        RequireIdentity(sid);
    }
    private static void RequireSnapshot(BoundProxySnapshot actual, BoundProxySnapshot expected, MessageText error)
    {
        ValidateSnapshot(actual);
        if (!SnapshotsEqual(actual, expected)) throw MessageExceptions.Create(error, text => new IOException(text));
    }
    public static void ValidateBackup(BoundProxyBackup backup)
    {
        ArgumentNullException.ThrowIfNull(backup);
        backup.DiagnosticMessage?.Validate();
        ValidateTarget(new()
        {
            TargetUserSid = backup.TargetUserSid,
            Source = backup.Source,
            Before = backup.Before,
            Desired = backup.After,
            ChangedFields = backup.ChangedFields
        });
        if (!Enum.IsDefined(backup.MutationState)) throw MessageExceptions.Create(MessageText.Create("Backend.Core.BoundProxyRepair.ValidateBackup.01"), sourceText => new InvalidDataException(sourceText));
    }
    private void ClassifyReadback(BoundProxyBackup backup, bool restoring)
    {
        RequireIdentity(backup.TargetUserSid);
        BoundProxySnapshot actual = settings.ReadCurrentUserLan();
        ValidateSnapshot(actual);
        bool before = SnapshotsEqual(actual, backup.Before);
        bool after = SnapshotsEqual(actual, backup.After);
        backup.MutationState = before ? (restoring ? BoundProxyMutationState.Restored : BoundProxyMutationState.Unchanged) :
            after ? BoundProxyMutationState.Applied : BoundProxyMutationState.Indeterminate;
        if (restoring) backup.RestoreReadBackMatched = before;
        else backup.ReadBackMatched = after;
    }
    private void TryClassifyReadback(BoundProxyBackup backup, bool restoring)
    {
        try { ClassifyReadback(backup, restoring); }
        catch
        {
            backup.MutationState = BoundProxyMutationState.Indeterminate;
            if (restoring) backup.RestoreReadBackMatched = false;
            else backup.ReadBackMatched = false;
        }
    }
    private static RemediationVerificationObservation State(RemediationVerificationStatus status, MessageText message) =>
        new() { Status = status, MessageText = message };
}
