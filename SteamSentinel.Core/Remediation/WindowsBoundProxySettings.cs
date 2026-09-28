using SteamSentinel.Core.Reporting;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using Microsoft.Win32;
using SteamSentinel.Core.Models;
using SteamSentinel.Core.Scanning;

namespace SteamSentinel.Core.Remediation;

/// <summary>
/// Saved current-user WinINet default/LAN settings only; no PAC fetch, WPAD, DNS, or traffic probe.
/// Native option-list pszConnection is always NULL. Never edits Connections binary blobs, WinHTTP,
/// policy keys, a named RAS connection, another user's hive, or machine proxy configuration.
/// </summary>
public sealed class WindowsBoundProxySettings : IBoundProxySettings
{
    private const uint PerConnectionOption = 75, SettingsChanged = 39, Refresh = 37;
    private const uint FlagsOption = 1, ProxyServerOption = 2, ProxyBypassOption = 3, AutoConfigUrlOption = 4, FlagsUiOption = 10;
    private const string InternetPolicy = @"Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings";
    private const string ControlPanelPolicy = @"Software\Policies\Microsoft\Internet Explorer\Control Panel";
    private const string InternetSettings = @"Software\Microsoft\Windows\CurrentVersion\Internet Settings";
    private static readonly string[] PolicyNames = ["ProxyEnable", "ProxyServer", "ProxyOverride", "AutoConfigURL", "AutoDetect", "ProxySettingsPerUser"];
    private static readonly string[] ControlNames = ["Proxy", "AutoConfig", "ConnectionsTab", "ConnectionSettings"];

    public BoundProxySnapshot ReadCurrentUserLan()
    {
        RequireWindows();
        BoundProxyPolicyGuard firstGuard = ReadPolicyGuard();
        BoundProxySnapshot snapshot;
        try { snapshot = Query(FlagsUiOption); }
        catch (Win32Exception ex) when (ex.NativeErrorCode == 12009) // ERROR_INTERNET_INVALID_OPTION only; never hide access/read failures.
        { snapshot = Query(FlagsOption); }
        BoundProxyPolicyGuard lastGuard = ReadPolicyGuard();
        if (firstGuard.Status != lastGuard.Status || firstGuard.Fingerprint != lastGuard.Fingerprint)
            lastGuard = new()
            {
                Status = BoundProxyPolicyStatus.ReadFailed,
                Fingerprint = lastGuard.Fingerprint,
                DetailText = MessageText.Create("Backend.Core.WindowsBoundProxySettings.ReadCurrentUserLan.01")
            };
        return new()
        {
            Flags = snapshot.Flags,
            ProxyServer = snapshot.ProxyServer,
            ProxyBypass = snapshot.ProxyBypass,
            AutoConfigUrl = snapshot.AutoConfigUrl,
            PolicyGuard = lastGuard
        };
    }

    public void WriteCurrentUserLan(BoundProxySnapshot desired, IReadOnlyList<BoundProxyField> changedFields)
    {
        RequireWindows();
        BoundProxyRepair.ValidateSnapshot(desired);
        if (changedFields is null || changedFields.Count is < 1 or > 4 ||
            changedFields.Any(field => !Enum.IsDefined(field)) || changedFields.Distinct().Count() != changedFields.Count)
            throw MessageExceptions.Create(MessageText.Create("Backend.Core.WindowsBoundProxySettings.WriteCurrentUserLan.01"), sourceText => new InvalidDataException(sourceText));
        BoundProxyPolicyGuard guard = ReadPolicyGuard();
        if (guard.Status != BoundProxyPolicyStatus.Unmanaged || guard.Fingerprint != desired.PolicyGuard.Fingerprint)
            throw MessageExceptions.Create(MessageText.Create("Backend.Core.WindowsBoundProxySettings.WriteCurrentUserLan.02"), sourceText => new NotSupportedException(sourceText));
        List<IntPtr> strings = [];
        IntPtr options = IntPtr.Zero;
        try
        {
            int optionSize = Marshal.SizeOf<NativeOption>();
            options = Marshal.AllocHGlobal(checked(optionSize * changedFields.Count));
            for (int index = 0; index < changedFields.Count; index++)
            {
                NativeOption option = changedFields[index] switch
                {
                    BoundProxyField.Flags => new() { Option = FlagsOption, Value = new() { Dword = desired.Flags } },
                    BoundProxyField.ProxyServer => StringOption(ProxyServerOption, desired.ProxyServer, strings),
                    BoundProxyField.ProxyBypass => StringOption(ProxyBypassOption, desired.ProxyBypass, strings),
                    BoundProxyField.AutoConfigUrl => StringOption(AutoConfigUrlOption, desired.AutoConfigUrl, strings),
                    _ => throw MessageExceptions.Create(MessageText.Create("Backend.Core.WindowsBoundProxySettings.WriteCurrentUserLan.03"), sourceText => new InvalidDataException(sourceText))
                };
                Marshal.StructureToPtr(option, IntPtr.Add(options, index * optionSize), false);
            }
            NativeOptionList list = NewList(options, changedFields.Count);
            if (!InternetSetOptionW(IntPtr.Zero, PerConnectionOption, ref list, list.Size))
            {
                int error = Marshal.GetLastPInvokeError();
                throw MessageExceptions.Create(MessageText.Create("Backend.Core.WindowsBoundProxySettings.WriteCurrentUserLan.04") + list.OptionError + MessageText.Create("Backend.Core.WindowsBoundProxySettings.WriteCurrentUserLan.05"), sourceText => new Win32Exception(error, sourceText));
            }
        }
        finally
        {
            foreach (IntPtr pointer in strings) Marshal.FreeHGlobal(pointer);
            if (options != IntPtr.Zero) Marshal.FreeHGlobal(options);
        }
    }

    public void NotifySettingsChanged() => Notify(SettingsChanged);
    public void RefreshSettings() => Notify(Refresh);

    // WinINet query allocates LPWSTRs with GlobalAlloc; setters receive our own HGlobal strings.
    // https://learn.microsoft.com/windows/win32/api/wininet/ns-wininet-internet_per_conn_optionw
    // https://learn.microsoft.com/windows/win32/api/wininet/ns-wininet-internet_per_conn_option_listw
    private static BoundProxySnapshot Query(uint flagsOption)
    {
        int optionSize = Marshal.SizeOf<NativeOption>();
        IntPtr options = Marshal.AllocHGlobal(checked(optionSize * 4));
        int initialized = 0;
        try
        {
            uint[] names = [flagsOption, ProxyServerOption, ProxyBypassOption, AutoConfigUrlOption];
            for (int index = 0; index < names.Length; index++)
            {
                Marshal.StructureToPtr(new NativeOption { Option = names[index] }, IntPtr.Add(options, index * optionSize), false);
                initialized++;
            }
            NativeOptionList list = NewList(options, 4);
            uint size = list.Size;
            if (!InternetQueryOptionW(IntPtr.Zero, PerConnectionOption, ref list, ref size))
            {
                int error = Marshal.GetLastPInvokeError();
                throw MessageExceptions.Create(MessageText.Create("Backend.Core.WindowsBoundProxySettings.Query.01"), sourceText => new Win32Exception(error, sourceText));
            }
            return new()
            {
                Flags = ReadOption(options, optionSize, 0).Value.Dword,
                ProxyServer = ReadString(ReadOption(options, optionSize, 1).Value.String),
                ProxyBypass = ReadString(ReadOption(options, optionSize, 2).Value.String),
                AutoConfigUrl = ReadString(ReadOption(options, optionSize, 3).Value.String)
            };
        }
        finally
        {
            for (int index = 1; index < initialized; index++)
            {
                IntPtr pointer = ReadOption(options, optionSize, index).Value.String;
                if (pointer != IntPtr.Zero) _ = GlobalFree(pointer);
            }
            Marshal.FreeHGlobal(options);
        }
    }

    private static NativeOption ReadOption(IntPtr options, int optionSize, int index) =>
        Marshal.PtrToStructure<NativeOption>(IntPtr.Add(options, checked(index * optionSize)));
    private static NativeOptionList NewList(IntPtr options, int count) => new()
    {
        Size = (uint)Marshal.SizeOf<NativeOptionList>(),
        Connection = IntPtr.Zero,
        OptionCount = (uint)count,
        OptionError = 0,
        Options = options
    };
    private static NativeOption StringOption(uint name, BoundProxyString value, List<IntPtr> owned)
    {
        IntPtr pointer = value.Present ? Marshal.StringToHGlobalUni(value.Value!) : IntPtr.Zero;
        if (pointer != IntPtr.Zero) owned.Add(pointer);
        return new() { Option = name, Value = new() { String = pointer } };
    }
    private static BoundProxyString ReadString(IntPtr pointer)
    {
        if (pointer == IntPtr.Zero) return new();
        for (int length = 0; length <= BoundProxyRepair.MaximumStringCharacters; length++)
            if (Marshal.ReadInt16(pointer, checked(length * 2)) == 0)
                return new() { Present = true, Value = Marshal.PtrToStringUni(pointer, length) };
        throw MessageExceptions.Create(MessageText.Create("Backend.Core.WindowsBoundProxySettings.ReadString.01"), sourceText => new InvalidDataException(sourceText));
    }

    private static BoundProxyPolicyGuard ReadPolicyGuard() =>
        ReadPolicyGuard(new WindowsProxyConfigurationReader(), Environment.Is64BitOperatingSystem);

    internal static BoundProxyPolicyGuard ReadPolicyGuard(IProxyConfigurationReader reader, bool is64BitOperatingSystem)
    {
        // Fixed known WinINet proxy-policy locations and both registry views. We never infer that
        // absence here describes a browser's custom policy, PAC result, or another proxy subsystem.
        string sid = reader.ReadCurrentUserSid() ?? throw MessageExceptions.Create(MessageText.Create("Backend.Core.WindowsBoundProxySettings.ReadPolicyGuard.01"), sourceText => new UnauthorizedAccessException(sourceText));
        List<PolicyRow> rows = [];
        BoundProxyPolicyStatus status = BoundProxyPolicyStatus.Unmanaged;
        RegistryView[] views = is64BitOperatingSystem ? [RegistryView.Registry64, RegistryView.Registry32] : [RegistryView.Registry32];
        foreach (RegistryView view in views)
        {
            Read(RegistryHive.Users, view, sid + "\\" + InternetPolicy, PolicyNames);
            Read(RegistryHive.LocalMachine, view, InternetPolicy, PolicyNames);
            Read(RegistryHive.Users, view, sid + "\\" + ControlPanelPolicy, ControlNames);
            Read(RegistryHive.LocalMachine, view, ControlPanelPolicy, ControlNames);
            // Refuse malformed or machine-scoped selectors even if an unexpected non-policy copy exists.
            Read(RegistryHive.LocalMachine, view, InternetSettings, ["ProxySettingsPerUser"]);
            Read(RegistryHive.Users, view, sid + "\\" + InternetSettings, ["ProxySettingsPerUser"]);
        }
        string fingerprint = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(JsonSerializer.Serialize(rows))));
        return new()
        {
            Status = status,
            Fingerprint = fingerprint,
            DetailText = status switch
            {
                BoundProxyPolicyStatus.Unmanaged => MessageText.Create("Backend.Core.WindowsBoundProxySettings.ReadPolicyGuard.Unmanaged.01"),
                BoundProxyPolicyStatus.PolicyControlled => MessageText.Create("Backend.Core.WindowsBoundProxySettings.ReadPolicyGuard.PolicyControlled.01"),
                BoundProxyPolicyStatus.Unsupported => MessageText.Create("Backend.Core.WindowsBoundProxySettings.ReadPolicyGuard.Unsupported.01"),
                _ => MessageText.Create("Backend.Core.WindowsBoundProxySettings.ReadPolicyGuard.02")
            }
        };

        void Read(RegistryHive hive, RegistryView view, string key, IReadOnlyList<string> names)
        {
            ProxySourceRead source;
            try { source = reader.ReadRegistry(hive, view, key, names, 1024, CancellationToken.None); }
            catch (Exception ex) when (ProxyConfigurationScanner.IsReadException(ex))
            {
                source = new(ProxyConfigurationScanner.StatusFor(ex), ex.GetType().Name, []);
            }
            if (source.Status is not (DiagnosticReadStatus.Complete or DiagnosticReadStatus.NotPresent))
                status = BoundProxyPolicyStatus.ReadFailed;
            if (source.Values.Count != names.Count || source.Values.Select(value => value.Name).Distinct(StringComparer.Ordinal).Count() != names.Count ||
                !source.Values.Select(value => value.Name).ToHashSet(StringComparer.Ordinal).SetEquals(names))
                status = BoundProxyPolicyStatus.ReadFailed;
            rows.Add(new(hive.ToString(), view.ToString(), key, "", "", source.Status.ToString(), false, null));
            foreach (ProxyValueRead value in source.Values)
            {
                rows.Add(new(hive.ToString(), view.ToString(), key, value.Name, value.Kind, value.Status.ToString(), value.Present, value.Value));
                if (value.Status is not (DiagnosticReadStatus.Complete or DiagnosticReadStatus.NotPresent))
                { status = BoundProxyPolicyStatus.ReadFailed; continue; }
                if (!value.Present) continue;
                if (value.Name == "ProxySettingsPerUser")
                {
                    if (value.Kind != "REG_DWORD" || value.Value != "1")
                        if (status != BoundProxyPolicyStatus.ReadFailed) status = BoundProxyPolicyStatus.Unsupported;
                }
                else if (status == BoundProxyPolicyStatus.Unmanaged) status = BoundProxyPolicyStatus.PolicyControlled;
            }
        }
    }

    // Documented refresh/notification options; every return value is checked separately.
    // https://learn.microsoft.com/windows/win32/wininet/option-flags
    private static void Notify(uint option)
    {
        RequireWindows();
        if (!InternetSetOptionW(IntPtr.Zero, option, IntPtr.Zero, 0))
            throw MessageExceptions.Create(MessageText.Create("Backend.Core.WindowsBoundProxySettings.Notify.01") + option + "。", sourceText => new Win32Exception(Marshal.GetLastPInvokeError(), sourceText));
    }
    private static void RequireWindows()
    {
        if (!OperatingSystem.IsWindows()) throw MessageExceptions.Create(MessageText.Create("Backend.Core.WindowsBoundProxySettings.RequireWindows.01"), sourceText => new PlatformNotSupportedException(sourceText));
        using WindowsIdentity identity = WindowsIdentity.GetCurrent();
        if (!Environment.UserInteractive || identity.IsSystem || identity.User is null || identity.User.Value is "S-1-5-19" or "S-1-5-20")
            throw MessageExceptions.Create(MessageText.Create("Backend.Core.WindowsBoundProxySettings.RequireWindows.02"), sourceText => new NotSupportedException(sourceText));
    }

    private sealed record PolicyRow(string Hive, string View, string Key, string Name, string Kind, string Status, bool Present, string? Value);
    [StructLayout(LayoutKind.Sequential)]
    private struct NativeFileTime { public uint Low; public uint High; }
    [StructLayout(LayoutKind.Explicit)]
    private struct NativeValue
    {
        [FieldOffset(0)] public uint Dword;
        [FieldOffset(0)] public IntPtr String;
        [FieldOffset(0)] public NativeFileTime FileTime;
    }
    [StructLayout(LayoutKind.Sequential)]
    private struct NativeOption { public uint Option; public NativeValue Value; }
    [StructLayout(LayoutKind.Sequential)]
    private struct NativeOptionList { public uint Size; public IntPtr Connection; public uint OptionCount; public uint OptionError; public IntPtr Options; }
    [DllImport("wininet.dll", ExactSpelling = true, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool InternetQueryOptionW(IntPtr internet, uint option, ref NativeOptionList buffer, ref uint bufferLength);
    [DllImport("wininet.dll", ExactSpelling = true, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool InternetSetOptionW(IntPtr internet, uint option, ref NativeOptionList buffer, uint bufferLength);
    [DllImport("wininet.dll", ExactSpelling = true, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool InternetSetOptionW(IntPtr internet, uint option, IntPtr buffer, uint bufferLength);
    [DllImport("kernel32.dll", ExactSpelling = true)]
    private static extern IntPtr GlobalFree(IntPtr memory);
}
