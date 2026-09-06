using System.Reflection;
using System.IO;
using System.Runtime.InteropServices;
using System.Text.Json;
using Microsoft.Win32;
using SteamSentinel.Core.Models;
using SteamSentinel.Core.Remediation;
using SteamSentinel.Core.Scanning;

namespace SteamSentinel.SelfTest;

internal static partial class Program
{
    // All configuration IO is a fake; this test never constructs the Windows adapter or changes a proxy.
    private static void TestPhase3ProxyRepair()
    {
        const string sid = "S-1-5-21-100-200-300-1001";
        BoundProxyPolicyGuard guard = new() { Status = BoundProxyPolicyStatus.Unmanaged, Fingerprint = new string('A', 64), Detail = "fixture guard" };
        BoundProxySnapshot before = new()
        {
            Flags = 0x10f,
            ProxyServer = Text("http=fixture.invalid:1234"),
            ProxyBypass = Text("*.corporate.invalid;<local>"),
            AutoConfigUrl = Text("https://pac.fixture.invalid/config.pac?opaque=original"),
            PolicyGuard = guard
        };
        BoundProxySnapshot desired = Copy(before, flags: 0x10d, server: new());
        BoundProxyTarget target = Target(before, desired);
        ProxyFixture fixture = new(before);
        BoundProxyRepair repair = new(fixture, () => sid);
        BoundProxyBackup backup = repair.Capture(target);
        Check("第三批 代理捕获只读且保存原值/期望值", fixture.WriteCalls == 0 && backup.MutationState == BoundProxyMutationState.Prepared &&
            BoundProxyRepair.SnapshotsEqual(backup.Before, before) && BoundProxyRepair.SnapshotsEqual(backup.After, desired));
        repair.Apply(target, backup);
        Check("第三批 代理只提交精确差异字段并保留PAC/绕过/自动检测/未知位", fixture.WriteCalls == 1 &&
            fixture.LastFields.SequenceEqual(target.ChangedFields) && fixture.Value.Flags == 0x10d &&
            fixture.Value.AutoConfigUrl.Value == before.AutoConfigUrl.Value && fixture.Value.ProxyBypass.Value == before.ProxyBypass.Value);
        Check("第三批 代理写入前两次完整读取并逐项通知及复核", fixture.Events.Take(4).SequenceEqual(["read", "read", "read", "write"]) &&
            fixture.Events.SequenceEqual(["read", "read", "read", "write", "read", "settings", "refresh", "read"]) &&
            backup.WriteSucceeded && backup.SettingsChangedNotified && backup.RefreshNotified && backup.ReadBackMatched && backup.MutationState == BoundProxyMutationState.Applied);
        Check("第三批 代理探针仅声明LAN配置匹配", repair.Probe(target).Status == RemediationVerificationStatus.Verified && repair.Probe(target).Message.Contains("未验证"));
        repair.Restore(backup);
        Check("第三批 代理回滚精确还原存在性及原始字符串", fixture.WriteCalls == 2 && BoundProxyRepair.SnapshotsEqual(fixture.Value, before) &&
            backup.RestoreWriteSucceeded && backup.RestoreSettingsChangedNotified && backup.RestoreRefreshNotified && backup.RestoreReadBackMatched && backup.MutationState == BoundProxyMutationState.Restored);

        ProxyFixture wrongIdentity = new(before);
        Check("第三批 代理拒绝其他SID且不读写配置", ProxyThrows(() => new BoundProxyRepair(wrongIdentity, () => "S-1-5-21-100-200-300-1002").Capture(target)) && wrongIdentity.Events.Count == 0);
        string current = sid;
        ProxyFixture identityChanged = new(before);
        BoundProxyRepair identityRepair = new(identityChanged, () => current);
        BoundProxyBackup identityBackup = identityRepair.Capture(target);
        current = "S-1-5-21-100-200-300-1002";
        Check("第三批 代理捕获后SID变化拒绝写入", ProxyThrows(() => identityRepair.Apply(target, identityBackup)) && identityChanged.WriteCalls == 0);
        foreach (string source in new[] { "WinHttpDefault", "WinHttpCurrentUser", "WinInetLocalMachine", "WinINetPolicyRegistry", "WinInetCurrentConnection", "RAS:Fixture" })
        {
            ProxyFixture unsupported = new(before);
            Check("第三批 代理不支持作用域 " + source, ProxyThrows(() => new BoundProxyRepair(unsupported, () => sid).Capture(Target(before, desired, source: source))) && unsupported.Events.Count == 0);
        }

        ProxyFixture race = new(before);
        BoundProxyRepair raceRepair = new(race, () => sid);
        BoundProxyBackup raceBackup = raceRepair.Capture(target);
        race.OnRead = call => call == 3 ? Copy(before, bypass: Text("new-legitimate-bypass.invalid")) : null;
        Check("第三批 代理第二次临写读取发现无关字段变化也拒绝覆盖", ProxyThrows(() => raceRepair.Apply(target, raceBackup)) && race.WriteCalls == 0 && !raceBackup.WriteAttempted);
        ProxyFixture policyRace = new(before);
        BoundProxyRepair policyRepair = new(policyRace, () => sid);
        BoundProxyBackup policyBackup = policyRepair.Capture(target);
        policyRace.Value = Copy(before, policy: new() { Status = BoundProxyPolicyStatus.Unmanaged, Fingerprint = new string('B', 64) });
        Check("第三批 代理策略守卫变化拒绝写入", ProxyThrows(() => policyRepair.Apply(target, policyBackup)) && policyRace.WriteCalls == 0);
        foreach (BoundProxyPolicyStatus policyStatus in new[] { BoundProxyPolicyStatus.Unverified, BoundProxyPolicyStatus.PolicyControlled, BoundProxyPolicyStatus.Unsupported, BoundProxyPolicyStatus.ReadFailed })
        {
            ProxyFixture controlled = new(Copy(before, policy: new() { Status = policyStatus, Fingerprint = new string('A', 64) }));
            BoundProxyRepair controlledRepair = new(controlled, () => sid);
            Check("第三批 代理未知或受控策略拒绝 " + policyStatus, ProxyThrows(() => controlledRepair.Capture(target)) && controlled.WriteCalls == 0 && controlledRepair.Probe(target).Status == RemediationVerificationStatus.Unknown);
        }

        Check("第三批 代理拒绝遗漏/多余/重复或未知变更字段", new List<BoundProxyField>[]
        {
            [BoundProxyField.ProxyServer], [BoundProxyField.Flags, BoundProxyField.ProxyServer, BoundProxyField.AutoConfigUrl],
            [BoundProxyField.Flags, BoundProxyField.ProxyServer, BoundProxyField.ProxyServer], [BoundProxyField.Flags, (BoundProxyField)999]
        }.All(fields => ProxyThrows(() => BoundProxyRepair.ValidateTarget(Target(before, desired, fields)))));
        Check("第三批 代理不得改写未知flags位", ProxyThrows(() => BoundProxyRepair.ValidateTarget(Target(before, Copy(desired, flags: desired.Flags ^ 0x100)))));
        Check("第三批 代理不得更改策略守卫", ProxyThrows(() => BoundProxyRepair.ValidateTarget(Target(before, Copy(desired, policy: new() { Status = BoundProxyPolicyStatus.Unmanaged, Fingerprint = new string('B', 64) })))));
        BoundProxySnapshot absent = Copy(before, server: new());
        BoundProxySnapshot empty = Copy(before, server: Text(""));
        Check("第三批 代理区分空字符串与不存在", !BoundProxyRepair.SnapshotsEqual(absent, empty));
        Check("第三批 代理拒绝错误存在性、NUL、无效UTF16和超限原值", new BoundProxyString[]
        {
            new() { Present = false, Value = "hidden" }, new() { Present = true }, Text("a\0b"), Text("\ud800"),
            Text(new string('x', BoundProxyRepair.MaximumStringCharacters + 1))
        }.All(value => ProxyThrows(() => BoundProxyRepair.ValidateSnapshot(Copy(before, server: value)))));
        Check("第三批 代理完整快照总字符预算受限", ProxyThrows(() => BoundProxyRepair.ValidateSnapshot(new()
        {
            Flags = 1,
            ProxyServer = Text(new string('s', 16384)),
            ProxyBypass = Text(new string('b', 16384)),
            AutoConfigUrl = Text("x"),
            PolicyGuard = guard
        })));
        Check("第三批 代理非法SID在原生读取前拒绝", ProxyThrows(() => BoundProxyRepair.ValidateTarget(new()
        { TargetUserSid = "not-a-sid", Before = before, Desired = desired, ChangedFields = [BoundProxyField.Flags, BoundProxyField.ProxyServer] })));

        ProxyFixture writeFailed = new(before) { OnWrite = (_, _) => throw new IOException("fixture denied before mutation") };
        BoundProxyRepair writeFailedRepair = new(writeFailed, () => sid);
        BoundProxyBackup noMutation = writeFailedRepair.Capture(target);
        Check("第三批 代理setter失败后回读确认未变化", ProxyThrows(() => writeFailedRepair.Apply(target, noMutation)) && noMutation.WriteAttempted &&
            !noMutation.WriteSucceeded && noMutation.MutationState == BoundProxyMutationState.Unchanged && ProxyThrows(() => writeFailedRepair.Restore(noMutation)));
        ProxyFixture writeThenFail = new(before);
        writeThenFail.OnWrite = (value, _) => { writeThenFail.Value = value; throw new IOException("fixture failed after write"); };
        BoundProxyRepair writeThenFailRepair = new(writeThenFail, () => sid);
        BoundProxyBackup changedDespiteError = writeThenFailRepair.Capture(target);
        Check("第三批 代理setter报错但实际完成仍保留可核对变更", ProxyThrows(() => writeThenFailRepair.Apply(target, changedDespiteError)) &&
            changedDespiteError.MutationState == BoundProxyMutationState.Applied && changedDespiteError.ReadBackMatched && !changedDespiteError.WriteSucceeded);
        writeThenFail.OnWrite = null;
        writeThenFailRepair.Restore(changedDespiteError);
        Check("第三批 代理setter报错后已确认变更可安全回滚", BoundProxyRepair.SnapshotsEqual(writeThenFail.Value, before) && changedDespiteError.MutationState == BoundProxyMutationState.Restored);

        ProxyFixture partial = new(before);
        partial.OnWrite = (value, _) => { partial.Value = Copy(before, flags: value.Flags); throw new IOException("fixture partial write"); };
        BoundProxyRepair partialRepair = new(partial, () => sid);
        BoundProxyBackup partialBackup = partialRepair.Capture(target);
        Check("第三批 代理部分写入标未知并拒绝自动回滚", ProxyThrows(() => partialRepair.Apply(target, partialBackup)) &&
            partialBackup.MutationState == BoundProxyMutationState.Indeterminate && !partialBackup.ReadBackMatched && ProxyThrows(() => partialRepair.Restore(partialBackup)) && partial.WriteCalls == 1);
        ProxyFixture unreadable = new(before);
        unreadable.OnWrite = (value, _) => { unreadable.Value = value; unreadable.FailReads = true; };
        BoundProxyRepair unreadableRepair = new(unreadable, () => sid);
        BoundProxyBackup unreadableBackup = unreadableRepair.Capture(target);
        Check("第三批 代理写后不可读不误报成功或自动回滚", ProxyThrows(() => unreadableRepair.Apply(target, unreadableBackup)) &&
            unreadableBackup.WriteSucceeded && unreadableBackup.MutationState == BoundProxyMutationState.Indeterminate && ProxyThrows(() => unreadableRepair.Restore(unreadableBackup)));

        foreach (bool refreshFailure in new[] { false, true })
        {
            ProxyFixture notification = new(before) { FailSettings = !refreshFailure, FailRefresh = refreshFailure };
            BoundProxyRepair notificationRepair = new(notification, () => sid);
            BoundProxyBackup notificationBackup = notificationRepair.Capture(target);
            Check("第三批 代理通知失败保留已确认写入 " + (refreshFailure ? "Refresh" : "SettingsChanged"),
                ProxyThrows(() => notificationRepair.Apply(target, notificationBackup)) && notificationBackup.WriteSucceeded && notificationBackup.MutationState == BoundProxyMutationState.Applied &&
                notificationBackup.ReadBackMatched && notificationBackup.SettingsChangedNotified == refreshFailure && !notificationBackup.RefreshNotified);
            notification.FailSettings = notification.FailRefresh = false;
            notificationRepair.Restore(notificationBackup);
            Check("第三批 代理通知失败后回滚 " + (refreshFailure ? "Refresh" : "SettingsChanged"), notificationBackup.MutationState == BoundProxyMutationState.Restored && BoundProxyRepair.SnapshotsEqual(notification.Value, before));
        }

        ProxyFixture conflict = new(before);
        BoundProxyRepair conflictRepair = new(conflict, () => sid);
        BoundProxyBackup conflictBackup = conflictRepair.Capture(target);
        conflictRepair.Apply(target, conflictBackup);
        conflict.Value = Copy(desired, bypass: Text("later-legitimate-change.invalid"));
        Check("第三批 代理回滚拒绝后来合法修改且不写入", ProxyThrows(() => conflictRepair.Restore(conflictBackup)) && conflict.WriteCalls == 1 && conflict.Value.ProxyBypass.Value == "later-legitimate-change.invalid");
        ProxyFixture restoreNotification = new(before);
        BoundProxyRepair restoreRepair = new(restoreNotification, () => sid);
        BoundProxyBackup restoreBackup = restoreRepair.Capture(target);
        restoreRepair.Apply(target, restoreBackup);
        restoreNotification.FailRefresh = true;
        Check("第三批 代理恢复已写但通知失败记录真实状态", ProxyThrows(() => restoreRepair.Restore(restoreBackup)) && restoreBackup.MutationState == BoundProxyMutationState.Restored &&
            restoreBackup.RestoreWriteSucceeded && restoreBackup.RestoreReadBackMatched && !restoreBackup.RestoreRefreshNotified);
        restoreNotification.FailRefresh = false;
        restoreRepair.Restore(restoreBackup);
        Check("第三批 代理恢复通知重试不重复改写配置", restoreNotification.WriteCalls == 2 && restoreBackup.RestoreRefreshNotified);

        ProxyFixture recreated = new(before);
        BoundProxyRepair recreatedRepair = new(recreated, () => sid);
        BoundProxyBackup recreatedBackup = recreatedRepair.Capture(target);
        recreatedRepair.Apply(target, recreatedBackup);
        recreated.Value = before;
        Check("第三批 代理再次出现由只读探针报告残留", recreatedRepair.Probe(target).Status == RemediationVerificationStatus.ResidualDetected);
        BoundProxyBackup persisted = JsonSerializer.Deserialize<BoundProxyBackup>(JsonSerializer.Serialize(changedDespiteError))!;
        Check("第三批 代理回滚快照JSON往返保留存在性和写入状态", persisted.MutationState == BoundProxyMutationState.Restored &&
            persisted.Before.ProxyServer.Present && !persisted.After.ProxyServer.Present && BoundProxyRepair.SnapshotsEqual(persisted.Before, before));
        Type nativeOption = typeof(WindowsBoundProxySettings).GetNestedType("NativeOption", BindingFlags.NonPublic)!;
        Type nativeList = typeof(WindowsBoundProxySettings).GetNestedType("NativeOptionList", BindingFlags.NonPublic)!;
        Check("第三批 WinINet原生结构匹配SDK指针对齐且不调用系统", Marshal.SizeOf(nativeOption) == (IntPtr.Size == 8 ? 16 : 12) &&
            Marshal.OffsetOf(nativeOption, "Value").ToInt32() == (IntPtr.Size == 8 ? 8 : 4) && Marshal.SizeOf(nativeList) == (IntPtr.Size == 8 ? 32 : 20));
        Type windowsAdapter = typeof(WindowsBoundProxySettings);
        object lanList = windowsAdapter.GetMethod("NewList", BindingFlags.NonPublic | BindingFlags.Static)!.Invoke(null, [new IntPtr(1234), 4])!;
        Check("第三批 WinINet原生列表只指向默认LAN且不支持命名连接参数", (IntPtr)nativeList.GetField("Connection")!.GetValue(lanList)! == IntPtr.Zero &&
            (uint)nativeList.GetField("OptionCount")!.GetValue(lanList)! == 4 &&
            (uint)windowsAdapter.GetField("PerConnectionOption", BindingFlags.NonPublic | BindingFlags.Static)!.GetRawConstantValue()! == 75 &&
            (uint)windowsAdapter.GetField("FlagsUiOption", BindingFlags.NonPublic | BindingFlags.Static)!.GetRawConstantValue()! == 10 &&
            (uint)windowsAdapter.GetField("FlagsOption", BindingFlags.NonPublic | BindingFlags.Static)!.GetRawConstantValue()! == 1);
        MethodInfo query = windowsAdapter.GetMethod("InternetQueryOptionW", BindingFlags.NonPublic | BindingFlags.Static)!;
        DllImportAttribute queryImport = query.GetCustomAttribute<DllImportAttribute>()!;
        Check("第三批 WinINet查询固定W入口及BOOL ABI且未调用原生API", queryImport.Value == "wininet.dll" && queryImport.ExactSpelling && queryImport.SetLastError &&
            query.ReturnParameter.GetCustomAttribute<MarshalAsAttribute>()!.Value == UnmanagedType.Bool);
        TestPhase3ProxyPolicyGuard(sid);

        BoundProxyTarget Target(BoundProxySnapshot original, BoundProxySnapshot after, List<BoundProxyField>? fields = null, string? source = null) =>
            new()
            {
                TargetUserSid = sid,
                Source = source ?? BoundProxyRepair.SupportedSource,
                Before = original,
                Desired = after,
                ChangedFields = fields ?? [BoundProxyField.Flags, BoundProxyField.ProxyServer]
            };
        static BoundProxyString Text(string value) => new() { Present = true, Value = value };
        static BoundProxySnapshot Copy(BoundProxySnapshot original, uint? flags = null, BoundProxyString? server = null,
            BoundProxyString? bypass = null, BoundProxyPolicyGuard? policy = null) => new()
            {
                Flags = flags ?? original.Flags,
                ProxyServer = server ?? original.ProxyServer,
                ProxyBypass = bypass ?? original.ProxyBypass,
                AutoConfigUrl = original.AutoConfigUrl,
                PolicyGuard = policy ?? original.PolicyGuard
            };
    }

    private static void TestPhase3ProxyPolicyGuard(string sid)
    {
        const string internetPolicy = @"Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings";
        const string settings = @"Software\Microsoft\Windows\CurrentVersion\Internet Settings";
        const string control = @"Software\Policies\Microsoft\Internet Explorer\Control Panel";
        ProxyPolicyFixture fixture = new(sid);
        BoundProxyPolicyGuard clear = WindowsBoundProxySettings.ReadPolicyGuard(fixture, true);
        Check("第三批 代理策略守卫覆盖HKU本人与HKLM两种view固定位置", clear.Status == BoundProxyPolicyStatus.Unmanaged && clear.Fingerprint.Length == 64 &&
            fixture.Requests.Count == 12 && fixture.Requests.All(r => r.MaximumCharacters == 1024) &&
            new[] { RegistryView.Registry64, RegistryView.Registry32 }.All(view =>
                fixture.Requests.Any(r => r.View == view && r.Hive == RegistryHive.LocalMachine && r.Key == internetPolicy) &&
                fixture.Requests.Any(r => r.View == view && r.Hive == RegistryHive.Users && r.Key == sid + "\\" + internetPolicy) &&
                fixture.Requests.Any(r => r.View == view && r.Hive == RegistryHive.LocalMachine && r.Key == control) &&
                fixture.Requests.Any(r => r.View == view && r.Hive == RegistryHive.Users && r.Key == sid + "\\" + control)));
        Check("第三批 代理策略守卫同时检查machine/per-user选择项", fixture.Requests.Where(r => r.Key.EndsWith(settings, StringComparison.Ordinal))
            .All(r => r.Names.Contains("ProxySettingsPerUser")) && fixture.Requests.Count(r => r.Key == settings || r.Key == sid + "\\" + settings) == 4);
        ProxyPolicyFixture narrow = new(sid);
        _ = WindowsBoundProxySettings.ReadPolicyGuard(narrow, false);
        Check("第三批 32位系统策略守卫只请求Registry32", narrow.Requests.Count == 6 && narrow.Requests.All(r => r.View == RegistryView.Registry32));
        foreach (RegistryHive hive in new[] { RegistryHive.Users, RegistryHive.LocalMachine })
            foreach (RegistryView view in new[] { RegistryView.Registry32, RegistryView.Registry64 })
            {
                ProxyPolicyFixture controlled = new(sid)
                {
                    ReadOverride = (actualHive, actualView, key, names) =>
                    actualHive == hive && actualView == view && key.EndsWith(internetPolicy, StringComparison.Ordinal)
                        ? Value(names, "ProxyServer", "REG_SZ", "policy.fixture.invalid:1234") : null
                };
                Check("第三批 代理策略任一作用域/view存在配置即拒绝 " + hive + "/" + view,
                    WindowsBoundProxySettings.ReadPolicyGuard(controlled, true).Status == BoundProxyPolicyStatus.PolicyControlled);
            }
        ProxyPolicyFixture perUser = new(sid)
        {
            ReadOverride = (hive, view, key, names) =>
            hive == RegistryHive.LocalMachine && view == RegistryView.Registry64 && key == internetPolicy ? Value(names, "ProxySettingsPerUser", "REG_DWORD", "1") : null
        };
        BoundProxyPolicyGuard userGuard = WindowsBoundProxySettings.ReadPolicyGuard(perUser, true);
        perUser.ReadOverride = (hive, view, key, names) => hive == RegistryHive.LocalMachine && view == RegistryView.Registry64 && key == internetPolicy
            ? Value(names, "ProxySettingsPerUser", "REG_DWORD", "0") : null;
        BoundProxyPolicyGuard machineGuard = WindowsBoundProxySettings.ReadPolicyGuard(perUser, true);
        Check("第三批 HKLM ProxySettingsPerUser 1到0会改变守卫且拒绝机器作用域", userGuard.Status == BoundProxyPolicyStatus.Unmanaged &&
            machineGuard.Status == BoundProxyPolicyStatus.Unsupported && userGuard.Fingerprint != machineGuard.Fingerprint);
        perUser.ReadOverride = (hive, _, key, names) => hive == RegistryHive.LocalMachine && key == internetPolicy
            ? Value(names, "ProxySettingsPerUser", "REG_SZ", "1") : null;
        Check("第三批 ProxySettingsPerUser同文本错误类型拒绝", WindowsBoundProxySettings.ReadPolicyGuard(perUser, true).Status == BoundProxyPolicyStatus.Unsupported);
        perUser.ReadOverride = (hive, _, key, names) => hive == RegistryHive.LocalMachine && key == settings
            ? Value(names, "ProxySettingsPerUser", "REG_DWORD", "0") : null;
        Check("第三批 非Policies机器作用域选择项也拒绝", WindowsBoundProxySettings.ReadPolicyGuard(perUser, true).Status == BoundProxyPolicyStatus.Unsupported);
        ProxyPolicyFixture unreadable = new(sid) { ReadOverride = (_, _, _, _) => new(DiagnosticReadStatus.AccessDenied, "fixture access denied", []) };
        Check("第三批 策略不可读不能当未设置", WindowsBoundProxySettings.ReadPolicyGuard(unreadable, true).Status == BoundProxyPolicyStatus.ReadFailed);
        ProxyPolicyFixture incomplete = new(sid)
        {
            ReadOverride = (_, _, _, names) => new(DiagnosticReadStatus.Complete, "fixture incomplete",
            names.Skip(1).Select(name => new ProxyValueRead(name, "Missing", null, DiagnosticReadStatus.NotPresent, false)).ToArray())
        };
        Check("第三批 策略声称Complete但固定值缺项仍拒绝", WindowsBoundProxySettings.ReadPolicyGuard(incomplete, true).Status == BoundProxyPolicyStatus.ReadFailed);
        ProxyPolicyFixture duplicate = new(sid)
        {
            ReadOverride = (_, _, _, names) => new(DiagnosticReadStatus.Complete, "fixture duplicate",
            names.Select(_ => new ProxyValueRead(names[0], "Missing", null, DiagnosticReadStatus.NotPresent, false)).ToArray())
        };
        Check("第三批 策略固定值重复无法补足完整覆盖", WindowsBoundProxySettings.ReadPolicyGuard(duplicate, true).Status == BoundProxyPolicyStatus.ReadFailed);

        static ProxySourceRead Value(IReadOnlyList<string> names, string selected, string kind, string value) =>
            new(DiagnosticReadStatus.Complete, "fixture policy", names.Select(name => name == selected
                ? new ProxyValueRead(name, kind, value, DiagnosticReadStatus.Complete)
                : new ProxyValueRead(name, "Missing", null, DiagnosticReadStatus.NotPresent, false)).ToArray());
    }

    private static bool ProxyThrows(Action action)
    {
        try { action(); return false; }
        catch (Exception ex) when (ex is InvalidDataException or InvalidOperationException or IOException or UnauthorizedAccessException or NotSupportedException or ArgumentException)
        { return true; }
    }

    private sealed class ProxyFixture(BoundProxySnapshot initial) : IBoundProxySettings
    {
        public BoundProxySnapshot Value { get; set; } = initial;
        public int WriteCalls { get; private set; }
        public int ReadCalls { get; private set; }
        public bool FailReads { get; set; }
        public bool FailSettings { get; set; }
        public bool FailRefresh { get; set; }
        public List<string> Events { get; } = [];
        public List<BoundProxyField> LastFields { get; private set; } = [];
        public Func<int, BoundProxySnapshot?>? OnRead { get; set; }
        public Action<BoundProxySnapshot, IReadOnlyList<BoundProxyField>>? OnWrite { get; set; }
        public BoundProxySnapshot ReadCurrentUserLan()
        {
            Events.Add("read");
            ReadCalls++;
            if (FailReads) throw new IOException("fixture unreadable");
            if (OnRead?.Invoke(ReadCalls) is { } changed) Value = changed;
            return Value;
        }
        public void WriteCurrentUserLan(BoundProxySnapshot desired, IReadOnlyList<BoundProxyField> changedFields)
        {
            Events.Add("write");
            WriteCalls++;
            LastFields = [.. changedFields];
            if (OnWrite is not null) { OnWrite(desired, changedFields); return; }
            Value = new()
            {
                Flags = changedFields.Contains(BoundProxyField.Flags) ? desired.Flags : Value.Flags,
                ProxyServer = changedFields.Contains(BoundProxyField.ProxyServer) ? desired.ProxyServer : Value.ProxyServer,
                ProxyBypass = changedFields.Contains(BoundProxyField.ProxyBypass) ? desired.ProxyBypass : Value.ProxyBypass,
                AutoConfigUrl = changedFields.Contains(BoundProxyField.AutoConfigUrl) ? desired.AutoConfigUrl : Value.AutoConfigUrl,
                PolicyGuard = Value.PolicyGuard
            };
        }
        public void NotifySettingsChanged()
        {
            Events.Add("settings");
            if (FailSettings) throw new IOException("fixture settings notification failed");
        }
        public void RefreshSettings()
        {
            Events.Add("refresh");
            if (FailRefresh) throw new IOException("fixture refresh failed");
        }
    }

    private sealed class ProxyPolicyFixture(string sid) : IProxyConfigurationReader
    {
        public List<(RegistryHive Hive, RegistryView View, string Key, string[] Names, int MaximumCharacters)> Requests { get; } = [];
        public Func<RegistryHive, RegistryView, string, IReadOnlyList<string>, ProxySourceRead?>? ReadOverride { get; set; }
        public string? ReadCurrentUserSid() => sid;
        public ProxySourceRead ReadRegistry(RegistryHive hive, RegistryView view, string subkey, IReadOnlyList<string> names,
            int maximumCharacters, CancellationToken token)
        {
            Requests.Add((hive, view, subkey, names.ToArray(), maximumCharacters));
            return ReadOverride?.Invoke(hive, view, subkey, names) ?? new(DiagnosticReadStatus.NotPresent, "fixture missing key",
                names.Select(name => new ProxyValueRead(name, "Missing", null, DiagnosticReadStatus.NotPresent, false)).ToArray());
        }
        public ProxySourceRead ReadWinHttpDefault(int maximumCharacters, CancellationToken token) => throw new InvalidOperationException("Policy guard must not read WinHTTP.");
        public ProxySourceRead ReadWinInetCurrentUser(int maximumCharacters, CancellationToken token) => throw new InvalidOperationException("Policy guard must not substitute active connection for LAN.");
    }
}
