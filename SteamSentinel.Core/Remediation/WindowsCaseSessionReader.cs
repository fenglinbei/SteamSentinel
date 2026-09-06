using System.ComponentModel;
using System.Globalization;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Xml;
using System.Xml.Linq;
using Microsoft.Win32.SafeHandles;
using SteamSentinel.Core.Models;

namespace SteamSentinel.Core.Remediation;

public interface ICaseSessionReader
{
    Task<CaseSessionObservation> ReadAsync(CancellationToken cancellationToken = default);
}

/// <summary>
/// Reads an existing kernel-start event and the current interactive shell's logon identity.
/// No task registration, log modification, process creation, reboot, or logoff is performed.
/// Missing logs, a noninteractive token, impersonation or inaccessible identity stay unknown.
/// </summary>
public sealed class WindowsCaseSessionReader : ICaseSessionReader
{
    private const int MaximumEventXmlBytes = 64 * 1024;
    public Task<CaseSessionObservation> ReadAsync(CancellationToken cancellationToken = default) =>
        Task.Run(() => ReadCore(cancellationToken), cancellationToken);

    private static CaseSessionObservation ReadCore(CancellationToken token)
    {
        token.ThrowIfCancellationRequested();
        DateTimeOffset captured = DateTimeOffset.UtcNow;
        string sid = string.Empty;
        DiagnosticReadStatus identityStatus = DiagnosticReadStatus.NotChecked;
        BootRead boot = new(DiagnosticReadStatus.NotChecked, null, null, null, "启动事件未读取。");
        LogonRead logon = new(DiagnosticReadStatus.NotChecked, null, null, null, null, "交互登录身份未读取。");
        List<string> notes = [];
        try
        {
            if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException("会话身份只支持 Windows。");
            using WindowsIdentity effective = WindowsIdentity.GetCurrent();
            sid = effective.User?.Value ?? string.Empty;
            using SafeAccessTokenHandle processToken = OpenToken(GetCurrentProcess());
            using WindowsIdentity processIdentity = new(processToken.DangerousGetHandle());
            if (string.IsNullOrWhiteSpace(sid) || processIdentity.User?.Value != sid)
                throw new UnauthorizedAccessException("当前线程和进程用户不一致，未替换目标用户会话。");
            identityStatus = DiagnosticReadStatus.Complete;
            try { boot = ReadBoot(token); }
            catch (Exception ex) when (ex is not OperationCanceledException and not OutOfMemoryException)
            { boot = new(Status(ex), null, null, null, "无法核验系统启动事件：" + ex.Message); }
            token.ThrowIfCancellationRequested();
            try { logon = ReadInteractiveLogon(processToken, sid, token); }
            catch (Exception ex) when (ex is not OperationCanceledException and not OutOfMemoryException)
            { logon = new(Status(ex), null, null, null, null, "无法核验交互登录：" + ex.Message); }
            using WindowsIdentity after = WindowsIdentity.GetCurrent();
            if (after.User?.Value != sid) throw new UnauthorizedAccessException("读取期间用户身份变化。");
        }
        catch (OperationCanceledException)
        {
            identityStatus = DiagnosticReadStatus.Cancelled;
            notes.Add("会话读取已取消；现有字段仅为部分观察，不能认定新启动或新登录。");
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        { identityStatus = Status(ex); notes.Add(ex.Message); }
        return new()
        {
            CapturedAtUtc = captured,
            UserSid = sid,
            IdentityStatus = identityStatus,
            BootStatus = boot.Status,
            BootIdentity = boot.Identity,
            BootStartedAtUtc = boot.Started,
            BootEventRecordId = boot.RecordId,
            LogonStatus = logon.Status,
            InteractiveLogonId = logon.Id,
            InteractiveLogonStartedAtUtc = logon.Started,
            LogonType = logon.Type,
            SessionId = logon.Session,
            Detail = RemediationVerification.Limit(string.Join(" ", notes.Append(boot.Detail).Append(logon.Detail)) +
                " 启动证据来自现存 System/Kernel-General 12 事件；日志缺失或重置不推定新启动。仅证明会话变化，不证明整机已清除。", 4096)
        };
    }

    private static BootRead ReadBoot(CancellationToken token)
    {
        // An event identity stays stable across wall-clock corrections and reopening this app.
        // A reset/truncated log is handled as unknown by comparison, never as reboot proof.
        using SafeEventHandle query = EvtQuery(IntPtr.Zero, "System",
            "*[System[Provider[@Name='Microsoft-Windows-Kernel-General'] and EventID=12]]", 0x201);
        if (query.IsInvalid) throw new Win32Exception(Marshal.GetLastWin32Error());
        IntPtr[] events = new IntPtr[1];
        if (!EvtNext(query, 1, events, 2000, 0, out int returned))
        {
            int error = Marshal.GetLastWin32Error();
            if (error == 259) return new(DiagnosticReadStatus.NotPresent, null, null, null, "没有可读取的系统启动事件，不用当前时间或运行时长猜测新启动。");
            throw new Win32Exception(error);
        }
        if (returned != 1 || events[0] == IntPtr.Zero) throw new InvalidDataException("启动事件读取未返回一个明确对象。");
        using SafeEventHandle item = new(events[0]);
        token.ThrowIfCancellationRequested();
        if (EvtRender(IntPtr.Zero, item, 1, 0, IntPtr.Zero, out int required, out _) ||
            Marshal.GetLastWin32Error() != 122 || required is <= 0 or > MaximumEventXmlBytes)
            throw new InvalidDataException("启动事件 XML 长度无效或超过读取上限。");
        IntPtr buffer = Marshal.AllocHGlobal(required);
        try
        {
            if (!EvtRender(IntPtr.Zero, item, 1, required, buffer, out int used, out _) || used <= 0 || used > required)
                throw new Win32Exception(Marshal.GetLastWin32Error(), "无法渲染启动事件。");
            string xml = Marshal.PtrToStringUni(buffer, used / 2)?.TrimEnd('\0') ?? string.Empty;
            token.ThrowIfCancellationRequested();
            using StringReader text = new(xml);
            using XmlReader reader = XmlReader.Create(text, new() { DtdProcessing = DtdProcessing.Prohibit, XmlResolver = null, MaxCharactersInDocument = MaximumEventXmlBytes });
            XElement root = XElement.Load(reader);
            XNamespace ns = root.Name.Namespace;
            XElement system = root.Element(ns + "System") ?? throw new InvalidDataException("启动事件缺少 System。");
            if ((string?)system.Element(ns + "Provider")?.Attribute("Name") != "Microsoft-Windows-Kernel-General" ||
                (string?)system.Element(ns + "EventID") != "12" ||
                !long.TryParse((string?)system.Element(ns + "EventRecordID"), NumberStyles.None, CultureInfo.InvariantCulture, out long recordId) || recordId <= 0 ||
                !DateTimeOffset.TryParse((string?)system.Element(ns + "TimeCreated")?.Attribute("SystemTime"), CultureInfo.InvariantCulture,
                    DateTimeStyles.AssumeUniversal, out DateTimeOffset eventTime))
                throw new InvalidDataException("启动事件类型、记录 ID 或时间无效。");
            string? start = root.Element(ns + "EventData")?.Elements(ns + "Data").FirstOrDefault(e => (string?)e.Attribute("Name") == "StartTime")?.Value;
            DateTimeOffset started = DateTimeOffset.TryParse(start, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal, out DateTimeOffset parsed) ? parsed : eventTime;
            if (started > DateTimeOffset.UtcNow.AddMinutes(1)) throw new InvalidDataException("启动事件时间位于未来，未采信会话判断。");
            string identity = $"KernelGeneral12:{recordId}:{eventTime.UtcDateTime.Ticks}";
            return new(DiagnosticReadStatus.Complete, identity, started.ToUniversalTime(), recordId, "已读取最近一次现存系统启动事件的记录 ID 和原始时间。");
        }
        finally { Marshal.FreeHGlobal(buffer); }
    }

    private static LogonRead ReadInteractiveLogon(SafeAccessTokenHandle token, string sid, CancellationToken cancellationToken)
    {
        Luid actual = AuthenticationId(token, sid);
        IntPtr shell = GetShellWindow();
        if (shell == IntPtr.Zero || GetWindowThreadProcessId(shell, out uint processId) == 0 || processId == 0)
            return new(DiagnosticReadStatus.NotChecked, null, null, null, null, "当前桌面没有可核验的交互 shell，不把任意进程令牌变化当作重新登录。");
        using SafeProcessHandle process = OpenProcess(0x1000, false, processId);
        if (process.IsInvalid) throw new Win32Exception(Marshal.GetLastWin32Error());
        using SafeAccessTokenHandle shellToken = OpenToken(process.DangerousGetHandle());
        Luid shellId = AuthenticationId(shellToken, sid);
        if (actual.Low != shellId.Low || actual.High != shellId.High)
            return new(DiagnosticReadStatus.NotChecked, null, null, null, null, "进程与交互 shell 的登录身份不同；另开凭据或提权令牌不作为新交互登录证明。");
        cancellationToken.ThrowIfCancellationRequested();
        int status = LsaGetLogonSessionData(ref actual, out IntPtr data);
        if (status != 0 || data == IntPtr.Zero) throw new Win32Exception(checked((int)LsaNtStatusToWinError(status)));
        try
        {
            LogonSessionData session = Marshal.PtrToStructure<LogonSessionData>(data);
            if (session.Size < Marshal.SizeOf<LogonSessionData>() || session.Sid == IntPtr.Zero || new SecurityIdentifier(session.Sid).Value != sid ||
                session.LogonType is not (2 or 10 or 11 or 12) || session.LogonTime <= 0)
                return new(DiagnosticReadStatus.NotChecked, null, null, (int)session.LogonType, (int)session.Session, "未取得同一用户有效的交互/远程交互登录记录。");
            DateTimeOffset started = DateTimeOffset.FromFileTime(session.LogonTime).ToUniversalTime();
            if (started > DateTimeOffset.UtcNow.AddMinutes(1)) throw new InvalidDataException("登录时间位于未来。");
            return new(DiagnosticReadStatus.Complete, $"{unchecked((uint)actual.High):X8}:{actual.Low:X8}", started,
                (int)session.LogonType, (int)session.Session, "已核验当前用户、交互 shell 与 AuthenticationId/LSA 登录时间；重开窗口和切换 UAC 令牌不会单独构成新登录。");
        }
        finally { LsaFreeReturnBuffer(data); }
    }

    private static Luid AuthenticationId(SafeAccessTokenHandle token, string sid)
    {
        using WindowsIdentity identity = new(token.DangerousGetHandle());
        if (identity.User?.Value != sid) throw new UnauthorizedAccessException("交互会话令牌属于另一用户。");
        int elevation = ReadToken<int>(token, 18);
        if (elevation == 2)
        {
            IntPtr linked = ReadToken<IntPtr>(token, 19);
            using SafeAccessTokenHandle linkedToken = new(linked);
            using WindowsIdentity linkedIdentity = new(linkedToken.DangerousGetHandle());
            if (linkedIdentity.User?.Value != sid) throw new UnauthorizedAccessException("关联令牌属于另一用户。");
            return ReadToken<TokenStatistics>(linkedToken, 10).AuthenticationId;
        }
        return ReadToken<TokenStatistics>(token, 10).AuthenticationId;
    }

    private static T ReadToken<T>(SafeAccessTokenHandle token, int kind) where T : struct
    {
        int length = Marshal.SizeOf<T>();
        IntPtr buffer = Marshal.AllocHGlobal(length);
        try
        {
            if (!GetTokenInformation(token, kind, buffer, length, out int returned) || returned < length)
                throw new Win32Exception(Marshal.GetLastWin32Error());
            return Marshal.PtrToStructure<T>(buffer);
        }
        finally { Marshal.FreeHGlobal(buffer); }
    }

    private static SafeAccessTokenHandle OpenToken(IntPtr process)
    {
        if (!OpenProcessToken(process, 8, out SafeAccessTokenHandle token)) throw new Win32Exception(Marshal.GetLastWin32Error());
        return token;
    }
    private static DiagnosticReadStatus Status(Exception ex) => ex is UnauthorizedAccessException || ex is Win32Exception { NativeErrorCode: 5 }
        ? DiagnosticReadStatus.AccessDenied : DiagnosticReadStatus.Failed;
    private sealed record BootRead(DiagnosticReadStatus Status, string? Identity, DateTimeOffset? Started, long? RecordId, string Detail);
    private sealed record LogonRead(DiagnosticReadStatus Status, string? Id, DateTimeOffset? Started, int? Type, int? Session, string Detail);
    [StructLayout(LayoutKind.Sequential)] private struct Luid { public uint Low; public int High; }
    [StructLayout(LayoutKind.Sequential)]
    private struct TokenStatistics
    {
        public Luid TokenId; public Luid AuthenticationId; public long ExpirationTime; public int TokenType; public int ImpersonationLevel;
        public uint DynamicCharged; public uint DynamicAvailable; public uint GroupCount; public uint PrivilegeCount; public Luid ModifiedId;
    }
    [StructLayout(LayoutKind.Sequential)] private struct LsaString { public ushort Length; public ushort MaximumLength; public IntPtr Buffer; }
    [StructLayout(LayoutKind.Sequential)]
    private struct LogonSessionData
    {
        public uint Size; public Luid LogonId; public LsaString UserName; public LsaString LogonDomain; public LsaString AuthenticationPackage;
        public uint LogonType; public uint Session; public IntPtr Sid; public long LogonTime;
    }
    private sealed class SafeEventHandle : SafeHandleZeroOrMinusOneIsInvalid
    {
        public SafeEventHandle() : base(true) { }
        public SafeEventHandle(IntPtr value) : base(true) { SetHandle(value); }
        protected override bool ReleaseHandle() => EvtClose(handle);
    }
    [DllImport("wevtapi.dll", CharSet = CharSet.Unicode, ExactSpelling = true, SetLastError = true)] private static extern SafeEventHandle EvtQuery(IntPtr session, string path, string query, int flags);
    [DllImport("wevtapi.dll", SetLastError = true)][return: MarshalAs(UnmanagedType.Bool)] private static extern bool EvtNext(SafeEventHandle query, int size, [Out] IntPtr[] events, int timeout, int flags, out int returned);
    [DllImport("wevtapi.dll", SetLastError = true)][return: MarshalAs(UnmanagedType.Bool)] private static extern bool EvtRender(IntPtr context, SafeEventHandle item, int flags, int size, IntPtr buffer, out int used, out int count);
    [DllImport("wevtapi.dll")][return: MarshalAs(UnmanagedType.Bool)] private static extern bool EvtClose(IntPtr handle);
    [DllImport("kernel32.dll")] private static extern IntPtr GetCurrentProcess();
    [DllImport("kernel32.dll", SetLastError = true)] private static extern SafeProcessHandle OpenProcess(uint access, [MarshalAs(UnmanagedType.Bool)] bool inherit, uint processId);
    [DllImport("user32.dll")] private static extern IntPtr GetShellWindow();
    [DllImport("user32.dll", SetLastError = true)] private static extern uint GetWindowThreadProcessId(IntPtr window, out uint processId);
    [DllImport("advapi32.dll", SetLastError = true)][return: MarshalAs(UnmanagedType.Bool)] private static extern bool OpenProcessToken(IntPtr process, uint access, out SafeAccessTokenHandle token);
    [DllImport("advapi32.dll", SetLastError = true)][return: MarshalAs(UnmanagedType.Bool)] private static extern bool GetTokenInformation(SafeAccessTokenHandle token, int kind, IntPtr buffer, int length, out int returned);
    [DllImport("secur32.dll")] private static extern int LsaGetLogonSessionData(ref Luid id, out IntPtr data);
    [DllImport("secur32.dll")] private static extern uint LsaNtStatusToWinError(int status);
    [DllImport("secur32.dll")] private static extern int LsaFreeReturnBuffer(IntPtr buffer);
}
