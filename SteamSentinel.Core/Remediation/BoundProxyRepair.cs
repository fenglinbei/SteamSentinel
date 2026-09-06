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
        RequireSnapshot(settings.ReadCurrentUserLan(), target.Before, "LAN 原配置或策略守卫已变化，拒绝准备修复。");
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
            throw new InvalidDataException("代理备份与本次精确目标不一致或已尝试写入。");
        RequireBeforeWrite(target.TargetUserSid, target.Before);
        // Journal must already be durable. Any exception after this point can follow an actual write.
        backup.WriteAttempted = true;
        backup.MutationState = BoundProxyMutationState.Indeterminate;
        try
        {
            settings.WriteCurrentUserLan(backup.After, backup.ChangedFields);
            backup.WriteSucceeded = true;
            ClassifyReadback(backup, restoring: false);
            if (!backup.ReadBackMatched) throw new IOException("代理写入后配置不等于精确期望值，保留日志并拒绝宣称成功。");
            settings.NotifySettingsChanged();
            backup.SettingsChangedNotified = true;
            settings.RefreshSettings();
            backup.RefreshNotified = true;
            ClassifyReadback(backup, restoring: false);
            if (!backup.ReadBackMatched) throw new IOException("代理通知后配置或策略发生变化，修复未通过复核。");
            backup.Diagnostic = "LAN 配置及策略守卫已重读匹配；未验证应用既有会话或实际网络路径。";
        }
        catch
        {
            TryClassifyReadback(backup, restoring: false);
            backup.Diagnostic = "代理写入或通知未全部完成；请按记录的实际变更状态复核，不以异常推断未修改。";
            throw;
        }
    }

    public void Restore(BoundProxyBackup backup)
    {
        ValidateBackup(backup);
        if (!backup.WriteAttempted || backup.MutationState is not (BoundProxyMutationState.Applied or BoundProxyMutationState.Restored))
            throw new InvalidOperationException("代理变更未被完整确认，拒绝自动回滚。");
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
            if (!backup.RestoreReadBackMatched) throw new IOException("代理恢复后不等于原配置，未标记回滚完成。");
            settings.NotifySettingsChanged();
            backup.RestoreSettingsChangedNotified = true;
            settings.RefreshSettings();
            backup.RestoreRefreshNotified = true;
            ClassifyReadback(backup, restoring: true);
            if (!backup.RestoreReadBackMatched) throw new IOException("代理恢复通知后配置发生变化，未标记回滚完成。");
            backup.Diagnostic = "LAN 原配置及策略守卫已恢复并重读匹配；未验证应用既有会话。";
        }
        catch
        {
            TryClassifyReadback(backup, restoring: true);
            backup.Diagnostic = "代理回滚或通知未全部完成；保留原值与实际变更状态，未覆盖冲突配置。";
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
                return State(RemediationVerificationStatus.Unknown, "LAN 策略守卫已变化，不能确认本次目标配置。");
            return SnapshotsEqual(actual, target.Desired)
                ? State(RemediationVerificationStatus.Verified, "当前用户 LAN 配置与精确期望值一致；未验证应用既有会话、PAC 内容或实际网络路径。")
                : State(RemediationVerificationStatus.ResidualDetected, "当前用户 LAN 配置未匹配本次精确期望值。");
        }
        catch (Exception ex) when (ex is not OutOfMemoryException and not StackOverflowException)
        {
            return State(RemediationVerificationStatus.Unknown, "代理只读复核未完成：" + ex.GetType().Name + "。");
        }
    }

    public static void ValidateTarget(BoundProxyTarget target)
    {
        ArgumentNullException.ThrowIfNull(target);
        if (target.Source != SupportedSource)
            throw new NotSupportedException("仅支持当前用户 WinINet 默认/LAN；机器、策略、WinHTTP 及命名 RAS/VPN 作用域不支持自动修复。");
        ValidateSid(target.TargetUserSid);
        ValidateSnapshot(target.Before);
        ValidateSnapshot(target.Desired);
        if (!PoliciesEqual(target.Before.PolicyGuard, target.Desired.PolicyGuard))
            throw new InvalidDataException("代理修复不能更改策略守卫。");
        if (((target.Before.Flags ^ target.Desired.Flags) & ~KnownFlags) != 0)
            throw new InvalidDataException("代理修复不得改变未知连接标志位。");
        List<BoundProxyField> difference = [];
        if (target.Before.Flags != target.Desired.Flags) difference.Add(BoundProxyField.Flags);
        if (!StringsEqual(target.Before.ProxyServer, target.Desired.ProxyServer)) difference.Add(BoundProxyField.ProxyServer);
        if (!StringsEqual(target.Before.ProxyBypass, target.Desired.ProxyBypass)) difference.Add(BoundProxyField.ProxyBypass);
        if (!StringsEqual(target.Before.AutoConfigUrl, target.Desired.AutoConfigUrl)) difference.Add(BoundProxyField.AutoConfigUrl);
        if (target.ChangedFields is null || target.ChangedFields.Count is < 1 or > 4 ||
            target.ChangedFields.Any(field => !Enum.IsDefined(field)) ||
            target.ChangedFields.Distinct().Count() != target.ChangedFields.Count ||
            !target.ChangedFields.ToHashSet().SetEquals(difference))
            throw new InvalidDataException("代理变更字段必须准确等于原值与期望值的差异且不能重复。");
    }

    public static void ValidateSnapshot(BoundProxySnapshot snapshot)
    {
        ArgumentNullException.ThrowIfNull(snapshot);
        ValidateString(snapshot.ProxyServer);
        ValidateString(snapshot.ProxyBypass);
        ValidateString(snapshot.AutoConfigUrl);
        if ((long)(snapshot.ProxyServer.Value?.Length ?? 0) + (snapshot.ProxyBypass.Value?.Length ?? 0) +
            (snapshot.AutoConfigUrl.Value?.Length ?? 0) > MaximumSnapshotCharacters)
            throw new InvalidDataException("代理配置总长度超过修复预算。");
        BoundProxyPolicyGuard guard = snapshot.PolicyGuard ?? throw new InvalidDataException("代理策略守卫缺失。");
        if (guard.Status != BoundProxyPolicyStatus.Unmanaged)
            throw new NotSupportedException("代理策略读取未完成或配置已受策略/机器作用域控制，不支持自动修改。");
        if (guard.Fingerprint is null || guard.Fingerprint.Length != 64 || !guard.Fingerprint.All(Uri.IsHexDigit) ||
            guard.Detail is null || guard.Detail.Length > 512)
            throw new InvalidDataException("代理策略守卫指纹或说明无效。");
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
            throw new InvalidDataException("代理字符串缺失状态、长度或 UTF-16 格式无效。");
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
        if (string.IsNullOrEmpty(sid) || sid.Length > 184) throw new InvalidDataException("代理目标 SID 缺失或超限。");
        try { if (new SecurityIdentifier(sid).Value != sid) throw new InvalidDataException("代理目标 SID 非规范格式。"); }
        catch (ArgumentException ex) { throw new InvalidDataException("代理目标 SID 无效。", ex); }
    }
    private void RequireIdentity(string targetSid)
    {
        if (!string.Equals(currentSid(), targetSid, StringComparison.Ordinal))
            throw new UnauthorizedAccessException("代理目标 SID 与当前令牌不一致，拒绝跨用户操作。");
    }
    private void RequireBeforeWrite(string sid, BoundProxySnapshot expected)
    {
        RequireIdentity(sid);
        RequireSnapshot(settings.ReadCurrentUserLan(), expected, "代理原值或策略已变化，拒绝覆盖当前配置。");
        RequireIdentity(sid);
        RequireSnapshot(settings.ReadCurrentUserLan(), expected, "代理在临写复核期间变化，拒绝覆盖当前配置。");
        RequireIdentity(sid);
    }
    private static void RequireSnapshot(BoundProxySnapshot actual, BoundProxySnapshot expected, string error)
    {
        ValidateSnapshot(actual);
        if (!SnapshotsEqual(actual, expected)) throw new IOException(error);
    }
    public static void ValidateBackup(BoundProxyBackup backup)
    {
        ArgumentNullException.ThrowIfNull(backup);
        ValidateTarget(new()
        {
            TargetUserSid = backup.TargetUserSid,
            Source = backup.Source,
            Before = backup.Before,
            Desired = backup.After,
            ChangedFields = backup.ChangedFields
        });
        if (!Enum.IsDefined(backup.MutationState)) throw new InvalidDataException("代理日志状态无效。");
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
    private static RemediationVerificationObservation State(RemediationVerificationStatus status, string message) =>
        new() { Status = status, Message = message };
}
