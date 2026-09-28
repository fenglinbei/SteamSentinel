using SteamSentinel.Core.Reporting;
using System.ComponentModel;
using System.Diagnostics;
using System.Globalization;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using Microsoft.Win32;
using Microsoft.Win32.SafeHandles;
using SteamSentinel.Core.Inspection;
using SteamSentinel.Core.Models;

namespace SteamSentinel.Core.Scanning;

/// <summary>A bounded local configuration read; no proxy resolution or network request is performed.</summary>
public sealed class ProxyConfigurationScanner(IProxyConfigurationReader? reader = null)
{
    private readonly IProxyConfigurationReader _reader = reader ?? new WindowsProxyConfigurationReader();
    private const string Settings = @"Software\Microsoft\Windows\CurrentVersion\Internet Settings";
    private const string Policies = @"Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings";
    private const string ControlPanel = @"Software\Policies\Microsoft\Internet Explorer\Control Panel";
    private static readonly string[] SettingNames = ["ProxyEnable", "ProxyServer", "ProxyOverride", "AutoConfigURL", "AutoDetect"];
    private static readonly string[] PolicyNames = [.. SettingNames, "ProxySettingsPerUser"];
    private static readonly string[] ControlNames = ["Proxy", "AutoConfig"];
    private static readonly MessageText ScopeNotice = MessageText.Create("Backend.Core.ProxyConfigurationScanner.ScopeNotice.01");

    public void Collect(TrustProxyDiagnosticReport diagnostic, DiagnosticScanLimits limits, CancellationToken token = default)
    {
        ArgumentNullException.ThrowIfNull(diagnostic);
        ArgumentNullException.ThrowIfNull(limits);
        Stopwatch elapsed = Stopwatch.StartNew();
        int characterLimit = Math.Clamp(limits.MaximumProxyValueCharacters, 0, 65536);
        RegistryView view = Environment.Is64BitOperatingSystem ? RegistryView.Registry64 : RegistryView.Registry32;
        DiagnosticReadStatus identityStatus = DiagnosticReadStatus.Complete;
        MessageText identityDetail;
        try
        {
            token.ThrowIfCancellationRequested();
            if (elapsed.Elapsed >= limits.MaximumDuration) throw new ProxyReadLimitException();
            string? currentSid = _reader.ReadCurrentUserSid();
            bool matches = !string.IsNullOrWhiteSpace(currentSid) &&
                           string.Equals(currentSid, diagnostic.TargetUserSid, StringComparison.OrdinalIgnoreCase);
            identityStatus = matches ? DiagnosticReadStatus.Complete : DiagnosticReadStatus.NotChecked;
            identityDetail = matches ? MessageText.Create("Backend.Core.ProxyConfigurationScanner.Collect.01") :
                MessageText.Create("Backend.Core.ProxyConfigurationScanner.Collect.02");
        }
        catch (Exception ex) when (IsReadException(ex))
        {
            identityStatus = StatusFor(ex);
            identityDetail = Describe(ex);
        }
        diagnostic.Checks.Add(new DiagnosticCheck { Name = "Proxy.TargetUserIdentity", Status = identityStatus, DetailText = identityDetail });

        void ReadSource(string source, string scope, string location, bool userSource, IReadOnlyList<string> names,
            Func<ProxySourceRead> read)
        {
            ProxySourceRead result;
            DiagnosticReadStatus? stopped = token.IsCancellationRequested ? DiagnosticReadStatus.Cancelled :
                elapsed.Elapsed >= limits.MaximumDuration || characterLimit == 0 ? DiagnosticReadStatus.LimitReached : null;
            if (stopped is not null)
                result = Unread(names, stopped.Value, MessageText.Create("Backend.Core.ProxyConfigurationScanner.Collect.03"));
            else if (userSource && identityStatus != DiagnosticReadStatus.Complete)
                result = Unread(names, identityStatus, identityDetail);
            else
            {
                try
                {
                    result = read();
                    if (token.IsCancellationRequested || elapsed.Elapsed >= limits.MaximumDuration)
                        result = result with
                        {
                            Status = token.IsCancellationRequested ? DiagnosticReadStatus.Cancelled : DiagnosticReadStatus.LimitReached,
                            DetailText = result.DetailText + MessageText.Create("Backend.Core.ProxyConfigurationScanner.Collect.04")
                        };
                }
                catch (Exception ex) when (IsReadException(ex)) { result = Unread(names, StatusFor(ex), Describe(ex)); }
            }
            if (result.Status != DiagnosticReadStatus.Complete && result.Values.Count == 0)
                result = Unread(names, result.Status, result.DetailText);
            ProxyConfigurationObservation observation = ConvertObservation(source, scope, location,
                userSource ? diagnostic.TargetUserSid : null, result, characterLimit);
            diagnostic.Proxies.Add(observation);
            diagnostic.Checks.Add(new DiagnosticCheck
            {
                Name = "Proxy." + source + "." + scope,
                ObservationId = observation.Id,
                Status = observation.Status,
                DetailText = observation.DetailText
            });
        }

        void RegistrySource(string source, bool userSource, string subkey, IReadOnlyList<string> names)
        {
            string path = userSource ? diagnostic.TargetUserSid + "\\" + subkey : subkey;
            string location = (userSource ? "HKEY_USERS\\" : "HKEY_LOCAL_MACHINE\\") + path + " [" + view + "]";
            ReadSource(source, userSource ? "CurrentUser" : "LocalMachine", location, userSource, names,
                () => _reader.ReadRegistry(userSource ? RegistryHive.Users : RegistryHive.LocalMachine, view, path, names, characterLimit, token));
        }

        RegistrySource("WinINetRegistry", true, Settings, SettingNames);
        RegistrySource("WinINetRegistry", false, Settings, SettingNames);
        RegistrySource("WinINetPolicyRegistry", true, Policies, PolicyNames);
        RegistrySource("WinINetPolicyRegistry", false, Policies, PolicyNames);
        RegistrySource("InternetExplorerControlPanelPolicy", true, ControlPanel, ControlNames);
        RegistrySource("InternetExplorerControlPanelPolicy", false, ControlPanel, ControlNames);
        ReadSource("WinHttpDefault", "LocalMachine", "WinHttpGetDefaultProxyConfiguration", false,
            ["AccessType", "ProxyServer", "ProxyOverride"], () => _reader.ReadWinHttpDefault(characterLimit, token));
        ReadSource("WinINetCurrentConnection", "CurrentUser", "WinHttpGetIEProxyConfigForCurrentUser", true,
            ["AutoDetect", "AutoConfigURL", "ProxyServer", "ProxyOverride"], () => _reader.ReadWinInetCurrentUser(characterLimit, token));
        diagnostic.Checks.Add(new DiagnosticCheck
        {
            Name = "Proxy.CollectionBoundary",
            Required = false,
            Status = DiagnosticReadStatus.Complete,
            DetailText = MessageText.Create("Backend.Core.ProxyConfigurationScanner.Collect.05", (characterLimit), (view)) +
                MessageText.Create("Backend.Core.ProxyConfigurationScanner.Collect.06") +
                MessageText.Create("Backend.Core.ProxyConfigurationScanner.Collect.07") + ScopeNotice
        });
    }

    private static ProxyConfigurationObservation ConvertObservation(string source, string scope, string location,
        string? sid, ProxySourceRead result, int limit)
    {
        List<DiagnosticConfigurationValue> values = [];
        List<MessageText> details = [result.DetailText, ScopeNotice];
        DiagnosticReadStatus status = result.Status;
        // A reader returns only the fixed requested values. Bound injected/custom providers as well.
        if (result.Values.Count > 16) status = Combine(status, DiagnosticReadStatus.LimitReached);
        foreach (ProxyValueRead value in result.Values.Take(16))
        {
            status = Combine(status, value.Status);
            string? raw = value.Value;
            string? hash = null;
            MessageText? text = null;
            bool redacted = false;
            if (raw is not null)
            {
                if (raw.Length > limit)
                {
                    status = Combine(status, DiagnosticReadStatus.LimitReached);
                    details.Add(value.Name + MessageText.Create("Backend.Core.ProxyConfigurationScanner.ConvertObservation.01"));
                }
                else
                {
                    hash = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(raw))).ToLowerInvariant();
                    text = RedactValue(raw, value.Kind);
                    redacted = !string.Equals(raw, text?.OriginalText, StringComparison.Ordinal);
                    if (redacted) details.Add(value.Name + MessageText.Create("Backend.Core.ProxyConfigurationScanner.ConvertObservation.02"));
                }
            }
            values.Add(new DiagnosticConfigurationValue(value.Name, value.Kind, text?.OriginalText, value.Present, hash, redacted, value.Status) { ValueMessage = text?.Message });
            details.Add(value.Detail is null ? (MessageText)(value.Name + "=" + value.Status) :
                MessageText.Create("Backend.Core.ProxyConfigurationScanner.ValueDetail", value.Name, value.Status, value.DetailText));
        }

        ProxyValueRead? Raw(string name) => result.Values.Take(16).FirstOrDefault(v => v.Name == name && v.Status == DiagnosticReadStatus.Complete && v.Present && v.Value?.Length <= limit);
        bool? Boolean(string name, string expected = "REG_DWORD")
        {
            ProxyValueRead? value = Raw(name);
            if (value is null) return null;
            if (expected == "BOOL" && value.Kind == expected && int.TryParse(value.Value,
                    NumberStyles.Integer, CultureInfo.InvariantCulture, out int nativeBoolean)) return nativeBoolean != 0;
            if (value.Kind == expected && value.Value is "0" or "1") return value.Value == "1";
            status = Combine(status, DiagnosticReadStatus.Failed);
            details.Add(name + MessageText.Create("Backend.Core.ProxyConfigurationScanner.ConvertObservation.03") + expected + MessageText.Create("Backend.Core.ProxyConfigurationScanner.ConvertObservation.04"));
            return null;
        }
        string? StringValue(string name)
        {
            ProxyValueRead? value = Raw(name);
            if (value is null) return null;
            if (value.Kind is "REG_SZ" or "REG_EXPAND_SZ" or "LPWSTR") return values.First(v => v.Name == name).Value;
            status = Combine(status, DiagnosticReadStatus.Failed);
            details.Add(name + MessageText.Create("Backend.Core.ProxyConfigurationScanner.ConvertObservation.05"));
            return null;
        }
        bool? enabled = Boolean("ProxyEnable");
        bool? autoDetect = Boolean("AutoDetect", source == "WinINetCurrentConnection" ? "BOOL" : "REG_DWORD");
        _ = Boolean("ProxySettingsPerUser");
        if (source == "InternetExplorerControlPanelPolicy") { _ = Boolean("Proxy"); _ = Boolean("AutoConfig"); }
        ProxyValueRead? access = Raw("AccessType");
        if (access is not null)
        {
            if (access.Kind == "DWORD" && access.Value is "1" or "3") enabled = access.Value == "3";
            else { status = Combine(status, DiagnosticReadStatus.Failed); details.Add(MessageText.Create("Backend.Core.ProxyConfigurationScanner.ConvertObservation.06")); }
        }
        string? server = StringValue("ProxyServer");
        string? bypass = StringValue("ProxyOverride");
        string? pac = StringValue("AutoConfigURL");
        return new ProxyConfigurationObservation
        {
            Source = source,
            Scope = scope,
            UserSid = sid,
            Location = location,
            Status = status,
            DetailText = MessageText.Join(" ", details.Where(d => !string.IsNullOrWhiteSpace(d.OriginalText))),
            Values = values,
            ProxyEnabled = enabled,
            AutoDetect = autoDetect,
            ProxyServer = server,
            ProxyServerMessage = values.FirstOrDefault(v => v.Name == "ProxyServer")?.ValueMessage,
            ProxyBypass = bypass,
            ProxyBypassMessage = values.FirstOrDefault(v => v.Name == "ProxyOverride")?.ValueMessage,
            AutoConfigUrl = pac,
            AutoConfigUrlMessage = values.FirstOrDefault(v => v.Name == "AutoConfigURL")?.ValueMessage
        };
    }

    private static MessageText RedactValue(string value, string kind)
    {
        // Unexpected binary types may encode secrets; retain only their pre-redaction digest.
        if (kind is "REG_BINARY" or "REG_NONE" || kind.StartsWith("REG_UNKNOWN", StringComparison.Ordinal))
            return MessageText.Create("Backend.Core.ProxyConfigurationScanner.RedactValue.01");
        if (value.Contains('@'))
        {
            if (Uri.TryCreate(value, UriKind.Absolute, out Uri? uri) && !string.IsNullOrEmpty(uri.Host) && !string.IsNullOrEmpty(uri.UserInfo))
            {
                int start = value.IndexOf("://", StringComparison.Ordinal) + 3;
                int end = value.IndexOfAny(['/', '?', '#'], start);
                if (end < 0) end = value.Length;
                int at = value.LastIndexOf('@', end - 1, end - start);
                if (at < start) return MessageText.Create("Backend.Core.ProxyConfigurationScanner.RedactValue.02");
                value = value[..start] + "[REDACTED]@" + value[(at + 1)..];
            }
            else return MessageText.Create("Backend.Core.ProxyConfigurationScanner.RedactValue.03");
        }
        return ScriptSignals.RedactSecrets(value);
    }

    internal static DiagnosticReadStatus Combine(DiagnosticReadStatus first, DiagnosticReadStatus second)
    {
        static int Rank(DiagnosticReadStatus value) => value switch
        {
            DiagnosticReadStatus.Cancelled => 6,
            DiagnosticReadStatus.LimitReached => 5,
            DiagnosticReadStatus.AccessDenied => 4,
            DiagnosticReadStatus.Failed => 3,
            DiagnosticReadStatus.NotChecked => 2,
            DiagnosticReadStatus.NotPresent => 1,
            _ => 0
        };
        // Missing individual values are a complete read of an existing source.
        if (second == DiagnosticReadStatus.NotPresent) return first;
        return Rank(second) > Rank(first) ? second : first;
    }

    private static ProxySourceRead Unread(IReadOnlyList<string> names, DiagnosticReadStatus status, MessageText detail) =>
        new(status, detail, names.Select(name => new ProxyValueRead(name, "NotRead", null, status, false)).ToArray());
    internal static bool IsReadException(Exception ex) => ex is UnauthorizedAccessException or SecurityException or IOException or
        Win32Exception or OperationCanceledException or PlatformNotSupportedException or DllNotFoundException or EntryPointNotFoundException or ProxyReadLimitException;
    internal static DiagnosticReadStatus StatusFor(Exception ex) => ex switch
    {
        OperationCanceledException => DiagnosticReadStatus.Cancelled,
        ProxyReadLimitException => DiagnosticReadStatus.LimitReached,
        UnauthorizedAccessException or SecurityException => DiagnosticReadStatus.AccessDenied,
        Win32Exception { NativeErrorCode: 5 } => DiagnosticReadStatus.AccessDenied,
        PlatformNotSupportedException or DllNotFoundException or EntryPointNotFoundException => DiagnosticReadStatus.NotChecked,
        _ => DiagnosticReadStatus.Failed
    };
    internal static MessageText Describe(Exception ex) => ex is Win32Exception native
        ? MessageText.Create("Backend.Core.ProxyConfigurationScanner.Describe.01", (native.NativeErrorCode)) : MessageText.Create("Backend.Core.ProxyConfigurationScanner.Describe.02") + ex.GetType().Name + "。";
}

/// <summary>Only these read operations are available to the scanner; injectable for harmless fixtures.</summary>
public interface IProxyConfigurationReader
{
    string? ReadCurrentUserSid();
    ProxySourceRead ReadRegistry(RegistryHive hive, RegistryView view, string subkey, IReadOnlyList<string> names, int maximumCharacters, CancellationToken token);
    ProxySourceRead ReadWinHttpDefault(int maximumCharacters, CancellationToken token);
    ProxySourceRead ReadWinInetCurrentUser(int maximumCharacters, CancellationToken token);
}
[method: System.Text.Json.Serialization.JsonConstructor]
public sealed record ProxyValueRead(string Name, string Kind, string? Value, DiagnosticReadStatus Status, bool Present = true, string? Detail = null)
{
    [System.Text.Json.Serialization.JsonIgnore(Condition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull)]
    public SteamSentinel.Core.Models.DisplayMessage? DetailMessage { get => SteamSentinel.Core.Reporting.MessageText.BoundDescriptor(field, Detail); init => field = value; }

    [System.Text.Json.Serialization.JsonIgnore]
    public SteamSentinel.Core.Reporting.MessageText DetailText
    {
        get => new(Detail ?? string.Empty, DetailMessage);
        init
        {
            Detail = value.OriginalText;
            DetailMessage = value.Message;
        }
    }

    public ProxyValueRead(string Name, string Kind, string? Value, DiagnosticReadStatus Status, SteamSentinel.Core.Reporting.MessageText Detail, bool Present = true) : this(Name, Kind, Value, Status, Present, Detail.OriginalText)
    {
        DetailMessage = Detail.Message;
    }
}
[method: System.Text.Json.Serialization.JsonConstructor]
public sealed record ProxySourceRead(DiagnosticReadStatus Status, string Detail, IReadOnlyList<ProxyValueRead> Values)
{
    [System.Text.Json.Serialization.JsonIgnore(Condition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull)]
    public SteamSentinel.Core.Models.DisplayMessage? DetailMessage { get => SteamSentinel.Core.Reporting.MessageText.BoundDescriptor(field, Detail); init => field = value; }

    [System.Text.Json.Serialization.JsonIgnore]
    public SteamSentinel.Core.Reporting.MessageText DetailText
    {
        get => new(Detail ?? string.Empty, DetailMessage);
        init
        {
            Detail = value.OriginalText;
            DetailMessage = value.Message;
        }
    }

    public ProxySourceRead(DiagnosticReadStatus Status, SteamSentinel.Core.Reporting.MessageText Detail, IReadOnlyList<ProxyValueRead> Values) : this(Status, Detail.OriginalText, Values)
    {
        DetailMessage = Detail.Message;
    }
}
internal sealed class ProxyReadLimitException : Exception { }

internal sealed class WindowsProxyConfigurationReader : IProxyConfigurationReader
{
    private static readonly Encoding StrictUnicode = new UnicodeEncoding(false, false, true);
    public string? ReadCurrentUserSid()
    {
        using WindowsIdentity identity = WindowsIdentity.GetCurrent();
        return identity.User?.Value;
    }

    public ProxySourceRead ReadRegistry(RegistryHive hive, RegistryView view, string subkey,
        IReadOnlyList<string> names, int maximumCharacters, CancellationToken token)
    {
        token.ThrowIfCancellationRequested();
        using RegistryKey root = RegistryKey.OpenBaseKey(hive, view);
        using RegistryKey? key = root.OpenSubKey(subkey, writable: false);
        if (key is null) return new ProxySourceRead(DiagnosticReadStatus.NotPresent, MessageText.Create("Backend.Core.ProxyConfigurationScanner.ReadRegistry.01"),
            names.Select(n => new ProxyValueRead(n, "Missing", null, DiagnosticReadStatus.NotPresent, false)).ToArray());
        List<ProxyValueRead> values = [];
        DiagnosticReadStatus status = DiagnosticReadStatus.Complete;
        foreach (string name in names)
        {
            token.ThrowIfCancellationRequested();
            ProxyValueRead value = ReadRegistryValue(key.Handle, name, maximumCharacters);
            values.Add(value);
            status = ProxyConfigurationScanner.Combine(status, value.Status);
        }
        return new ProxySourceRead(status, MessageText.Create("Backend.Core.ProxyConfigurationScanner.ReadRegistry.02"), values);
    }

    private static ProxyValueRead ReadRegistryValue(SafeRegistryHandle key, string name, int maximumCharacters)
    {
        uint size = 0;
        int error = RegQueryValueExW(key, name, IntPtr.Zero, out uint type, null, ref size);
        if (error != 0) return RegistryFailure(name, type, error);
        string kind = RegistryKind(type);
        // Query length before allocating or reading. No unbounded RegistryKey.GetValue allocation.
        uint byteLimit = (uint)((maximumCharacters + 1) * 2);
        if (size > byteLimit || (type is 0 or 3 or > 11) && size * 2UL > (ulong)maximumCharacters)
            return new ProxyValueRead(name, kind, null, DiagnosticReadStatus.LimitReached, Detail: MessageText.Create("Backend.Core.ProxyConfigurationScanner.ReadRegistryValue.01"));
        byte[] bytes = new byte[size];
        error = RegQueryValueExW(key, name, IntPtr.Zero, out type, bytes, ref size);
        if (error != 0) return RegistryFailure(name, type, error);
        if (size > bytes.Length) return new ProxyValueRead(name, RegistryKind(type), null, DiagnosticReadStatus.LimitReached, Detail: MessageText.Create("Backend.Core.ProxyConfigurationScanner.ReadRegistryValue.02"));
        return DecodeRegistryValue(name, type, bytes.AsSpan(0, (int)size), maximumCharacters);
    }

    internal static ProxyValueRead DecodeRegistryValue(string name, uint type, ReadOnlySpan<byte> bytes, int maximumCharacters)
    {
        string kind = RegistryKind(type);
        string raw;
        if (type is 1 or 2 or 7)
        {
            if (bytes.Length % 2 != 0) return new ProxyValueRead(name, kind, null, DiagnosticReadStatus.Failed, Detail: MessageText.Create("Backend.Core.ProxyConfigurationScanner.DecodeRegistryValue.01"));
            try { raw = StrictUnicode.GetString(bytes); }
            catch (DecoderFallbackException)
            {
                return new ProxyValueRead(name, kind, null, DiagnosticReadStatus.Failed, Detail: MessageText.Create("Backend.Core.ProxyConfigurationScanner.DecodeRegistryValue.02"));
            }
            if (raw.EndsWith('\0')) raw = raw[..^1];
        }
        else if (type == 4 && bytes.Length == 4) raw = System.Buffers.Binary.BinaryPrimitives.ReadUInt32LittleEndian(bytes).ToString(CultureInfo.InvariantCulture);
        else if (type == 5 && bytes.Length == 4) raw = System.Buffers.Binary.BinaryPrimitives.ReadUInt32BigEndian(bytes).ToString(CultureInfo.InvariantCulture);
        else if (type == 11 && bytes.Length == 8) raw = System.Buffers.Binary.BinaryPrimitives.ReadUInt64LittleEndian(bytes).ToString(CultureInfo.InvariantCulture);
        else if (type is 4 or 5 or 11) return new ProxyValueRead(name, kind, null, DiagnosticReadStatus.Failed, Detail: MessageText.Create("Backend.Core.ProxyConfigurationScanner.DecodeRegistryValue.03"));
        else raw = Convert.ToHexString(bytes);
        return raw.Length > maximumCharacters
            ? new ProxyValueRead(name, kind, null, DiagnosticReadStatus.LimitReached, Detail: MessageText.Create("Backend.Core.ProxyConfigurationScanner.DecodeRegistryValue.04"))
            : new ProxyValueRead(name, kind, raw, DiagnosticReadStatus.Complete);
    }

    private static string RegistryKind(uint type) => type switch
    {
        0 => "REG_NONE",
        1 => "REG_SZ",
        2 => "REG_EXPAND_SZ",
        3 => "REG_BINARY",
        4 => "REG_DWORD",
        5 => "REG_DWORD_BIG_ENDIAN",
        7 => "REG_MULTI_SZ",
        11 => "REG_QWORD",
        _ => "REG_UNKNOWN_" + type
    };
    private static ProxyValueRead RegistryFailure(string name, uint type, int error) => new(name,
        error is 2 or 3 ? "Missing" : RegistryKind(type), null, error switch
        {
            2 or 3 => DiagnosticReadStatus.NotPresent,
            5 => DiagnosticReadStatus.AccessDenied,
            234 => DiagnosticReadStatus.LimitReached,
            _ => DiagnosticReadStatus.Failed
        }, error is not (2 or 3), "Win32 " + error);

    // SDK: winhttp.h WINHTTP_PROXY_INFO and WINHTTP_CURRENT_USER_IE_PROXY_CONFIG.
    // https://learn.microsoft.com/windows/win32/api/winhttp/nf-winhttp-winhttpgetdefaultproxyconfiguration
    // https://learn.microsoft.com/windows/win32/api/winhttp/nf-winhttp-winhttpgetieproxyconfigforcurrentuser
    // These synchronous APIs read saved configuration. Every returned LPWSTR is released with GlobalFree.
    public ProxySourceRead ReadWinHttpDefault(int maximumCharacters, CancellationToken token)
    {
        token.ThrowIfCancellationRequested();
        WinHttpProxyInfo info = default;
        try
        {
            if (!WinHttpGetDefaultProxyConfiguration(out info)) return NativeFailure(Marshal.GetLastPInvokeError());
            List<ProxyValueRead> values =
            [
                new("AccessType", "DWORD", info.AccessType.ToString(CultureInfo.InvariantCulture), DiagnosticReadStatus.Complete),
                ReadNativeString("ProxyServer", info.Proxy, maximumCharacters),
                ReadNativeString("ProxyOverride", info.Bypass, maximumCharacters)
            ];
            return new ProxySourceRead(DiagnosticReadStatus.Complete, MessageText.Create("Backend.Core.ProxyConfigurationScanner.ReadWinHttpDefault.01"), values);
        }
        finally { Free(info.Proxy); Free(info.Bypass); }
    }

    public ProxySourceRead ReadWinInetCurrentUser(int maximumCharacters, CancellationToken token)
    {
        token.ThrowIfCancellationRequested();
        WinInetProxyConfig info = default;
        try
        {
            if (!WinHttpGetIEProxyConfigForCurrentUser(out info)) return NativeFailure(Marshal.GetLastPInvokeError());
            List<ProxyValueRead> values =
            [
                new("AutoDetect", "BOOL", info.AutoDetect.ToString(CultureInfo.InvariantCulture), DiagnosticReadStatus.Complete),
                ReadNativeString("AutoConfigURL", info.AutoConfigUrl, maximumCharacters),
                ReadNativeString("ProxyServer", info.Proxy, maximumCharacters),
                ReadNativeString("ProxyOverride", info.Bypass, maximumCharacters)
            ];
            return new ProxySourceRead(DiagnosticReadStatus.Complete, MessageText.Create("Backend.Core.ProxyConfigurationScanner.ReadWinInetCurrentUser.01"), values);
        }
        finally { Free(info.AutoConfigUrl); Free(info.Proxy); Free(info.Bypass); }
    }

    private static ProxyValueRead ReadNativeString(string name, IntPtr value, int maximumCharacters)
    {
        if (value == IntPtr.Zero) return new ProxyValueRead(name, "LPWSTR", null, DiagnosticReadStatus.NotPresent, false);
        // Bounded conversion of the null-terminated string supplied by the local Windows API.
        for (int length = 0; length <= maximumCharacters; length++)
            if (Marshal.ReadInt16(value, length * 2) == 0)
                return new ProxyValueRead(name, "LPWSTR", Marshal.PtrToStringUni(value, length), DiagnosticReadStatus.Complete);
        return new ProxyValueRead(name, "LPWSTR", null, DiagnosticReadStatus.LimitReached, Detail: MessageText.Create("Backend.Core.ProxyConfigurationScanner.ReadNativeString.01"));
    }

    private static ProxySourceRead NativeFailure(int error) => new(error switch
    {
        2 => DiagnosticReadStatus.NotPresent,
        5 => DiagnosticReadStatus.AccessDenied,
        _ => DiagnosticReadStatus.Failed
    }, MessageText.Create("Backend.Core.ProxyConfigurationScanner.NativeFailure.01") + error + "。", []);
    private static void Free(IntPtr pointer) { if (pointer != IntPtr.Zero) _ = GlobalFree(pointer); }

    [StructLayout(LayoutKind.Sequential)]
    private struct WinHttpProxyInfo { public uint AccessType; public IntPtr Proxy; public IntPtr Bypass; }
    [StructLayout(LayoutKind.Sequential)]
    private struct WinInetProxyConfig { public int AutoDetect; public IntPtr AutoConfigUrl; public IntPtr Proxy; public IntPtr Bypass; }
    [DllImport("winhttp.dll", ExactSpelling = true, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool WinHttpGetDefaultProxyConfiguration(out WinHttpProxyInfo proxyInfo);
    [DllImport("winhttp.dll", ExactSpelling = true, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool WinHttpGetIEProxyConfigForCurrentUser(out WinInetProxyConfig proxyConfig);
    [DllImport("kernel32.dll", ExactSpelling = true)]
    private static extern IntPtr GlobalFree(IntPtr memory);
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
    private static extern int RegQueryValueExW(SafeRegistryHandle key, string valueName, IntPtr reserved, out uint type,
        [Out] byte[]? data, ref uint dataSize);
}
