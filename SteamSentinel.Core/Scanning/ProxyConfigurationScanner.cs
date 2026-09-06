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
    private const string ScopeNotice = "仅记录此来源的本地配置，不代表 Steam 会话实际采用的代理；不解析 PAC、不执行 WPAD 或 DNS。";

    public void Collect(TrustProxyDiagnosticReport diagnostic, DiagnosticScanLimits limits, CancellationToken token = default)
    {
        ArgumentNullException.ThrowIfNull(diagnostic);
        ArgumentNullException.ThrowIfNull(limits);
        Stopwatch elapsed = Stopwatch.StartNew();
        int characterLimit = Math.Clamp(limits.MaximumProxyValueCharacters, 0, 65536);
        RegistryView view = Environment.Is64BitOperatingSystem ? RegistryView.Registry64 : RegistryView.Registry32;
        DiagnosticReadStatus identityStatus = DiagnosticReadStatus.Complete;
        string identityDetail;
        try
        {
            token.ThrowIfCancellationRequested();
            if (elapsed.Elapsed >= limits.MaximumDuration) throw new ProxyReadLimitException();
            string? currentSid = _reader.ReadCurrentUserSid();
            bool matches = !string.IsNullOrWhiteSpace(currentSid) &&
                           string.Equals(currentSid, diagnostic.TargetUserSid, StringComparison.OrdinalIgnoreCase);
            identityStatus = matches ? DiagnosticReadStatus.Complete : DiagnosticReadStatus.NotChecked;
            identityDetail = matches ? "当前安全令牌 SID 与目标 SID 一致；用户注册表读取显式绑定该 SID。" :
                "当前安全令牌 SID 未能匹配目标 SID，已拒绝读取当前用户注册表与当前用户 WinINet 配置。";
        }
        catch (Exception ex) when (IsReadException(ex))
        {
            identityStatus = StatusFor(ex);
            identityDetail = Describe(ex);
        }
        diagnostic.Checks.Add(new DiagnosticCheck { Name = "Proxy.TargetUserIdentity", Status = identityStatus, Detail = identityDetail });

        void ReadSource(string source, string scope, string location, bool userSource, IReadOnlyList<string> names,
            Func<ProxySourceRead> read)
        {
            ProxySourceRead result;
            DiagnosticReadStatus? stopped = token.IsCancellationRequested ? DiagnosticReadStatus.Cancelled :
                elapsed.Elapsed >= limits.MaximumDuration || characterLimit == 0 ? DiagnosticReadStatus.LimitReached : null;
            if (stopped is not null)
                result = Unread(names, stopped.Value, "采集已取消或达到时间/长度预算，此来源未开始读取。");
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
                            Detail = result.Detail + " 同步读取返回后已取消或超出时间预算，后续来源停止读取。"
                        };
                }
                catch (Exception ex) when (IsReadException(ex)) { result = Unread(names, StatusFor(ex), Describe(ex)); }
            }
            if (result.Status != DiagnosticReadStatus.Complete && result.Values.Count == 0)
                result = Unread(names, result.Status, result.Detail);
            ProxyConfigurationObservation observation = ConvertObservation(source, scope, location,
                userSource ? diagnostic.TargetUserSid : null, result, characterLimit);
            diagnostic.Proxies.Add(observation);
            diagnostic.Checks.Add(new DiagnosticCheck
            {
                Name = "Proxy." + source + "." + scope,
                ObservationId = observation.Id,
                Status = observation.Status,
                Detail = observation.Detail
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
            Detail = $"固定读取 8 个本地来源；每值上限 {characterLimit} 字符；只读注册表视图 {view}。" +
                "每个来源和注册表值前检查取消，来源返回后检查耗时。Windows 同步查询不能在调用内部强制中断；" +
                "WinHTTP 默认配置不包含当前应用会话覆盖，WinINet 查询只反映当前连接的已保存配置。" + ScopeNotice
        });
    }

    private static ProxyConfigurationObservation ConvertObservation(string source, string scope, string location,
        string? sid, ProxySourceRead result, int limit)
    {
        List<DiagnosticConfigurationValue> values = [];
        List<string> details = [result.Detail, ScopeNotice];
        DiagnosticReadStatus status = result.Status;
        // A reader returns only the fixed requested values. Bound injected/custom providers as well.
        if (result.Values.Count > 16) status = Combine(status, DiagnosticReadStatus.LimitReached);
        foreach (ProxyValueRead value in result.Values.Take(16))
        {
            status = Combine(status, value.Status);
            string? raw = value.Value;
            string? hash = null;
            string? text = null;
            bool redacted = false;
            if (raw is not null)
            {
                if (raw.Length > limit)
                {
                    status = Combine(status, DiagnosticReadStatus.LimitReached);
                    details.Add(value.Name + "：值超出字符预算，未保留部分内容或计算哈希。");
                }
                else
                {
                    hash = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(raw))).ToLowerInvariant();
                    text = RedactValue(raw, value.Kind);
                    redacted = !string.Equals(raw, text, StringComparison.Ordinal);
                    if (redacted) details.Add(value.Name + "：已隐藏凭据或敏感内容；SHA256 对应脱敏前值的 UTF-8 表示。");
                }
            }
            values.Add(new DiagnosticConfigurationValue(value.Name, value.Kind, text, value.Present, hash, redacted, value.Status));
            details.Add(value.Name + "=" + value.Status + (value.Detail is null ? "" : " (" + value.Detail + ")"));
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
            details.Add(name + "：类型或数值不符合 0/1 的 " + expected + "，保留原值但不转换为布尔值。");
            return null;
        }
        string? StringValue(string name)
        {
            ProxyValueRead? value = Raw(name);
            if (value is null) return null;
            if (value.Kind is "REG_SZ" or "REG_EXPAND_SZ" or "LPWSTR") return values.First(v => v.Name == name).Value;
            status = Combine(status, DiagnosticReadStatus.Failed);
            details.Add(name + "：不是字符串类型，保留原值但不转换为代理字段。");
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
            else { status = Combine(status, DiagnosticReadStatus.Failed); details.Add("AccessType：未识别的 WinHTTP 访问类型，未推断代理启用状态。"); }
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
            Detail = string.Join(" ", details.Where(d => !string.IsNullOrWhiteSpace(d))),
            Values = values,
            ProxyEnabled = enabled,
            AutoDetect = autoDetect,
            ProxyServer = server,
            ProxyBypass = bypass,
            AutoConfigUrl = pac
        };
    }

    private static string RedactValue(string value, string kind)
    {
        // Unexpected binary types may encode secrets; retain only their pre-redaction digest.
        if (kind is "REG_BINARY" or "REG_NONE" || kind.StartsWith("REG_UNKNOWN", StringComparison.Ordinal))
            return "[REDACTED: 非文本代理配置，仅保留类型与原值摘要]";
        if (value.Contains('@'))
        {
            if (Uri.TryCreate(value, UriKind.Absolute, out Uri? uri) && !string.IsNullOrEmpty(uri.Host) && !string.IsNullOrEmpty(uri.UserInfo))
            {
                int start = value.IndexOf("://", StringComparison.Ordinal) + 3;
                int end = value.IndexOfAny(['/', '?', '#'], start);
                if (end < 0) end = value.Length;
                int at = value.LastIndexOf('@', end - 1, end - start);
                value = at >= start ? value[..start] + "[REDACTED]@" + value[(at + 1)..] : "[REDACTED: 代理凭据]";
            }
            else value = "[REDACTED: 代理字段包含凭据或用户标识]";
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

    private static ProxySourceRead Unread(IReadOnlyList<string> names, DiagnosticReadStatus status, string detail) =>
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
    internal static string Describe(Exception ex) => ex is Win32Exception native
        ? $"本地配置读取失败：Win32 {native.NativeErrorCode}。" : "本地配置读取未完成：" + ex.GetType().Name + "。";
}

/// <summary>Only these read operations are available to the scanner; injectable for harmless fixtures.</summary>
public interface IProxyConfigurationReader
{
    string? ReadCurrentUserSid();
    ProxySourceRead ReadRegistry(RegistryHive hive, RegistryView view, string subkey, IReadOnlyList<string> names, int maximumCharacters, CancellationToken token);
    ProxySourceRead ReadWinHttpDefault(int maximumCharacters, CancellationToken token);
    ProxySourceRead ReadWinInetCurrentUser(int maximumCharacters, CancellationToken token);
}

public sealed record ProxyValueRead(string Name, string Kind, string? Value, DiagnosticReadStatus Status,
    bool Present = true, string? Detail = null);
public sealed record ProxySourceRead(DiagnosticReadStatus Status, string Detail, IReadOnlyList<ProxyValueRead> Values);
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
        if (key is null) return new ProxySourceRead(DiagnosticReadStatus.NotPresent, "注册表键不存在。",
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
        return new ProxySourceRead(status, "只读固定值名；REG_EXPAND_SZ 不展开环境变量，策略值也不推断应用最终优先级。", values);
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
            return new ProxyValueRead(name, kind, null, DiagnosticReadStatus.LimitReached, Detail: "注册表值长度超出预算，未读取内容。");
        byte[] bytes = new byte[size];
        error = RegQueryValueExW(key, name, IntPtr.Zero, out type, bytes, ref size);
        if (error != 0) return RegistryFailure(name, type, error);
        if (size > bytes.Length) return new ProxyValueRead(name, RegistryKind(type), null, DiagnosticReadStatus.LimitReached, Detail: "值在读取期间增长。");
        return DecodeRegistryValue(name, type, bytes.AsSpan(0, (int)size), maximumCharacters);
    }

    internal static ProxyValueRead DecodeRegistryValue(string name, uint type, ReadOnlySpan<byte> bytes, int maximumCharacters)
    {
        string kind = RegistryKind(type);
        string raw;
        if (type is 1 or 2 or 7)
        {
            if (bytes.Length % 2 != 0) return new ProxyValueRead(name, kind, null, DiagnosticReadStatus.Failed, Detail: "UTF-16 值长度无效。");
            try { raw = StrictUnicode.GetString(bytes); }
            catch (DecoderFallbackException)
            {
                return new ProxyValueRead(name, kind, null, DiagnosticReadStatus.Failed, Detail: "UTF-16 值包含无效代理字符，未进行有损转换。");
            }
            if (raw.EndsWith('\0')) raw = raw[..^1];
        }
        else if (type == 4 && bytes.Length == 4) raw = System.Buffers.Binary.BinaryPrimitives.ReadUInt32LittleEndian(bytes).ToString(CultureInfo.InvariantCulture);
        else if (type == 5 && bytes.Length == 4) raw = System.Buffers.Binary.BinaryPrimitives.ReadUInt32BigEndian(bytes).ToString(CultureInfo.InvariantCulture);
        else if (type == 11 && bytes.Length == 8) raw = System.Buffers.Binary.BinaryPrimitives.ReadUInt64LittleEndian(bytes).ToString(CultureInfo.InvariantCulture);
        else if (type is 4 or 5 or 11) return new ProxyValueRead(name, kind, null, DiagnosticReadStatus.Failed, Detail: "整数类型字节长度无效。");
        else raw = Convert.ToHexString(bytes);
        return raw.Length > maximumCharacters
            ? new ProxyValueRead(name, kind, null, DiagnosticReadStatus.LimitReached, Detail: "转换后的原值超出字符预算。")
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
            return new ProxySourceRead(DiagnosticReadStatus.Complete, "WinHTTP 注册表默认配置，不含调用方会话覆盖或现代每用户高级配置。", values);
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
            return new ProxySourceRead(DiagnosticReadStatus.Complete, "当前用户活动连接的 WinINet 配置（可能为 LAN、拨号或 VPN）；不枚举其他连接。API 不返回独立的 ProxyEnable 位。", values);
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
        return new ProxyValueRead(name, "LPWSTR", null, DiagnosticReadStatus.LimitReached, Detail: "Windows 返回的字符串超出预算，未保留部分内容。");
    }

    private static ProxySourceRead NativeFailure(int error) => new(error switch
    {
        2 => DiagnosticReadStatus.NotPresent,
        5 => DiagnosticReadStatus.AccessDenied,
        _ => DiagnosticReadStatus.Failed
    }, "Windows 配置查询返回 Win32 " + error + "。", []);
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
