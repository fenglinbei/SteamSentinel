using SteamSentinel.Core.Reporting;
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
        BootRead boot = new(DiagnosticReadStatus.NotChecked, null, null, null, MessageText.Create("Backend.Core.WindowsCaseSessionReader.ReadCore.01"));
        LogonRead logon = new(DiagnosticReadStatus.NotChecked, null, null, null, null, MessageText.Create("Backend.Core.WindowsCaseSessionReader.ReadCore.02"));
        List<MessageText> notes = [];
        try
        {
            if (!OperatingSystem.IsWindows()) throw MessageExceptions.Create(MessageText.Create("Backend.Core.WindowsCaseSessionReader.ReadCore.03"), sourceText => new PlatformNotSupportedException(sourceText));
            using WindowsIdentity effective = WindowsIdentity.GetCurrent();
            sid = effective.User?.Value ?? string.Empty;
            using SafeAccessTokenHandle processToken = OpenToken(GetCurrentProcess());
            using WindowsIdentity processIdentity = new(processToken.DangerousGetHandle());
            if (string.IsNullOrWhiteSpace(sid) || processIdentity.User?.Value != sid)
                throw MessageExceptions.Create(MessageText.Create("Backend.Core.WindowsCaseSessionReader.ReadCore.04"), sourceText => new UnauthorizedAccessException(sourceText));
            identityStatus = DiagnosticReadStatus.Complete;
            try { boot = ReadBoot(token); }
            catch (Exception ex) when (ex is not OperationCanceledException and not OutOfMemoryException)
            { boot = new(Status(ex), null, null, null, MessageText.Create("Backend.Core.WindowsCaseSessionReader.ReadCore.05") + MessageExceptions.Describe(ex)); }
            token.ThrowIfCancellationRequested();
            try { logon = ReadInteractiveLogon(processToken, sid, token); }
            catch (Exception ex) when (ex is not OperationCanceledException and not OutOfMemoryException)
            { logon = new(Status(ex), null, null, null, null, MessageText.Create("Backend.Core.WindowsCaseSessionReader.ReadCore.06") + MessageExceptions.Describe(ex)); }
            using WindowsIdentity after = WindowsIdentity.GetCurrent();
            if (after.User?.Value != sid) throw MessageExceptions.Create(MessageText.Create("Backend.Core.WindowsCaseSessionReader.ReadCore.07"), sourceText => new UnauthorizedAccessException(sourceText));
        }
        catch (OperationCanceledException)
        {
            identityStatus = DiagnosticReadStatus.Cancelled;
            notes.Add(MessageText.Create("Backend.Core.WindowsCaseSessionReader.ReadCore.08"));
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        { identityStatus = Status(ex); notes.Add(MessageExceptions.Describe(ex)); }
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
            DetailText = (MessageText.Join(" ", notes.Append(boot.DetailText).Append(logon.DetailText)) +
                MessageText.Create("Backend.Core.WindowsCaseSessionReader.ReadCore.09")).Limit(4096)
        };
    }

    private static BootRead ReadBoot(CancellationToken token)
    {
        // 同时查询传统冷启动事件（Kernel-General 12）与现代快速启动/冷启动事件（Kernel-Boot 27），兼容默认开启快速启动的 Windows 设备。
        // 日志缺失或重置由比较逻辑判定为 Unknown，绝不凭当前时间猜想重启。
        using SafeEventHandle query = EvtQuery(IntPtr.Zero, "System",
            "*[System[(Provider[@Name='Microsoft-Windows-Kernel-General'] and EventID=12) or (Provider[@Name='Microsoft-Windows-Kernel-Boot'] and EventID=27)]]", 0x201);
        if (query.IsInvalid) throw new Win32Exception(Marshal.GetLastWin32Error());

        const int maxScanned = 8;
        int scanned = 0;
        IntPtr[] batch = new IntPtr[maxScanned];
        while (scanned < maxScanned)
        {
            token.ThrowIfCancellationRequested();
            if (!EvtNext(query, maxScanned - scanned, batch, 2000, 0, out int returned))
            {
                int error = Marshal.GetLastWin32Error();
                if (error == 259)
                    return new(DiagnosticReadStatus.NotPresent, null, null, null, MessageText.Create("Backend.Core.WindowsCaseSessionReader.ReadBoot.01"));
                throw new Win32Exception(error);
            }
            if (returned <= 0 || returned > batch.Length)
                throw MessageExceptions.Create(MessageText.Create("Backend.Core.WindowsCaseSessionReader.ReadBoot.02"), sourceText => new InvalidDataException(sourceText));

            for (int i = 0; i < returned; i++)
            {
                IntPtr rawHandle = batch[i];
                batch[i] = IntPtr.Zero;
                if (rawHandle == IntPtr.Zero) continue;
                using SafeEventHandle item = new(rawHandle);
                scanned++;
                string xml = RenderEventXml(item, token);
                BootRead? candidate = ParseBootEventXml(xml, out bool isNonBootWake);
                if (isNonBootWake) continue;
                for (int rest = i + 1; rest < returned; rest++)
                {
                    if (batch[rest] != IntPtr.Zero)
                    {
                        _ = EvtClose(batch[rest]);
                        batch[rest] = IntPtr.Zero;
                    }
                }
                return candidate!;
            }
        }
        return new(DiagnosticReadStatus.NotPresent, null, null, null, MessageText.Create("Backend.Core.WindowsCaseSessionReader.ReadBoot.01"));
    }

    private static string RenderEventXml(SafeEventHandle item, CancellationToken token)
    {
        token.ThrowIfCancellationRequested();
        if (EvtRender(IntPtr.Zero, item, 1, 0, IntPtr.Zero, out int required, out _) ||
            Marshal.GetLastWin32Error() != 122 || required is <= 0 or > MaximumEventXmlBytes)
            throw MessageExceptions.Create(MessageText.Create("Backend.Core.WindowsCaseSessionReader.ReadBoot.03"), sourceText => new InvalidDataException(sourceText));
        IntPtr buffer = Marshal.AllocHGlobal(required);
        try
        {
            if (!EvtRender(IntPtr.Zero, item, 1, required, buffer, out int used, out _) || used <= 0 || used > required)
                throw MessageExceptions.Create(MessageText.Create("Backend.Core.WindowsCaseSessionReader.ReadBoot.04"), sourceText => new Win32Exception(Marshal.GetLastWin32Error(), sourceText));
            return Marshal.PtrToStringUni(buffer, used / 2)?.TrimEnd('\0') ?? string.Empty;
        }
        finally { Marshal.FreeHGlobal(buffer); }
    }

    internal static (DiagnosticReadStatus Status, string? Identity, DateTimeOffset? Started, long? RecordId) ParseBootEventForTest(
        string xml, out bool isNonBootWake)
    {
        BootRead? read = ParseBootEventXml(xml, out isNonBootWake);
        return read is null ? default : (read.Status, read.Identity, read.Started, read.RecordId);
    }

    private static BootRead? ParseBootEventXml(string xml, out bool isNonBootWake)
    {
        isNonBootWake = false;
        using StringReader text = new(xml);
        using XmlReader reader = XmlReader.Create(text, new() { DtdProcessing = DtdProcessing.Prohibit, XmlResolver = null, MaxCharactersInDocument = MaximumEventXmlBytes });
        XElement root = XElement.Load(reader);
        XNamespace ns = root.Name.Namespace;
        XElement system = root.Element(ns + "System") ?? throw MessageExceptions.Create(MessageText.Create("Backend.Core.WindowsCaseSessionReader.ReadBoot.05"), sourceText => new InvalidDataException(sourceText));

        string? provider = (string?)system.Element(ns + "Provider")?.Attribute("Name");
        string? eventId = (string?)system.Element(ns + "EventID");
        if (!long.TryParse((string?)system.Element(ns + "EventRecordID"), NumberStyles.None, CultureInfo.InvariantCulture, out long recordId) || recordId <= 0 ||
            !DateTimeOffset.TryParse((string?)system.Element(ns + "TimeCreated")?.Attribute("SystemTime"), CultureInfo.InvariantCulture,
                DateTimeStyles.AssumeUniversal, out DateTimeOffset eventTime))
        {
            throw MessageExceptions.Create(MessageText.Create("Backend.Core.WindowsCaseSessionReader.ReadBoot.06"), sourceText => new InvalidDataException(sourceText));
        }

        if (provider == "Microsoft-Windows-Kernel-General" && eventId == "12")
        {
            string? start = root.Element(ns + "EventData")?.Elements(ns + "Data").FirstOrDefault(e => (string?)e.Attribute("Name") == "StartTime")?.Value;
            DateTimeOffset started = DateTimeOffset.TryParse(start, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal, out DateTimeOffset parsed) ? parsed : eventTime;
            if (started > DateTimeOffset.UtcNow.AddMinutes(1)) throw MessageExceptions.Create(MessageText.Create("Backend.Core.WindowsCaseSessionReader.ReadBoot.07"), sourceText => new InvalidDataException(sourceText));
            string identity = $"KernelGeneral12:{recordId}:{eventTime.UtcDateTime.Ticks}";
            return new(DiagnosticReadStatus.Complete, identity, started.ToUniversalTime(), recordId, MessageText.Create("Backend.Core.WindowsCaseSessionReader.ReadBoot.08"));
        }

        if (provider == "Microsoft-Windows-Kernel-Boot" && eventId == "27")
        {
            // BootType: 0 = 冷启动, 1 = 快速启动 (Hiberboot), 2 = 普通 S4 休眠恢复（不视为开机重启）
            string? bootType = root.Element(ns + "EventData")?.Elements(ns + "Data").FirstOrDefault(e => (string?)e.Attribute("Name") == "BootType")?.Value;
            if (bootType is not ("0" or "1"))
            {
                isNonBootWake = true;
                return null;
            }
            if (eventTime > DateTimeOffset.UtcNow.AddMinutes(1)) throw MessageExceptions.Create(MessageText.Create("Backend.Core.WindowsCaseSessionReader.ReadBoot.07"), sourceText => new InvalidDataException(sourceText));
            string identity = $"KernelBoot27:{recordId}:{eventTime.UtcDateTime.Ticks}";
            return new(DiagnosticReadStatus.Complete, identity, eventTime.ToUniversalTime(), recordId, MessageText.Create("Backend.Core.WindowsCaseSessionReader.ReadBoot.08"));
        }

        throw MessageExceptions.Create(MessageText.Create("Backend.Core.WindowsCaseSessionReader.ReadBoot.06"), sourceText => new InvalidDataException(sourceText));
    }

    private static LogonRead ReadInteractiveLogon(SafeAccessTokenHandle token, string sid, CancellationToken cancellationToken)
    {
        Luid actual = AuthenticationId(token, sid);
        IntPtr shell = GetShellWindow();
        if (shell == IntPtr.Zero || GetWindowThreadProcessId(shell, out uint processId) == 0 || processId == 0)
            return new(DiagnosticReadStatus.NotChecked, null, null, null, null, MessageText.Create("Backend.Core.WindowsCaseSessionReader.ReadInteractiveLogon.01"));
        using SafeProcessHandle process = OpenProcess(0x1000, false, processId);
        if (process.IsInvalid) throw new Win32Exception(Marshal.GetLastWin32Error());
        using SafeAccessTokenHandle shellToken = OpenToken(process.DangerousGetHandle());
        Luid shellId = AuthenticationId(shellToken, sid);
        if (actual.Low != shellId.Low || actual.High != shellId.High)
            return new(DiagnosticReadStatus.NotChecked, null, null, null, null, MessageText.Create("Backend.Core.WindowsCaseSessionReader.ReadInteractiveLogon.02"));
        cancellationToken.ThrowIfCancellationRequested();
        int status = LsaGetLogonSessionData(ref actual, out IntPtr data);
        if (status != 0 || data == IntPtr.Zero) throw new Win32Exception(checked((int)LsaNtStatusToWinError(status)));
        try
        {
            LogonSessionData session = Marshal.PtrToStructure<LogonSessionData>(data);
            if (session.Size < Marshal.SizeOf<LogonSessionData>() || session.Sid == IntPtr.Zero || new SecurityIdentifier(session.Sid).Value != sid ||
                session.LogonType is not (2 or 10 or 11 or 12) || session.LogonTime <= 0)
                return new(DiagnosticReadStatus.NotChecked, null, null, (int)session.LogonType, (int)session.Session, MessageText.Create("Backend.Core.WindowsCaseSessionReader.ReadInteractiveLogon.03"));
            DateTimeOffset started = DateTimeOffset.FromFileTime(session.LogonTime).ToUniversalTime();
            if (started > DateTimeOffset.UtcNow.AddMinutes(1)) throw MessageExceptions.Create(MessageText.Create("Backend.Core.WindowsCaseSessionReader.ReadInteractiveLogon.04"), sourceText => new InvalidDataException(sourceText));
            return new(DiagnosticReadStatus.Complete, $"{unchecked((uint)actual.High):X8}:{actual.Low:X8}", started,
                (int)session.LogonType, (int)session.Session, MessageText.Create("Backend.Core.WindowsCaseSessionReader.ReadInteractiveLogon.05"));
        }
        finally { LsaFreeReturnBuffer(data); }
    }

    private static Luid AuthenticationId(SafeAccessTokenHandle token, string sid)
    {
        using WindowsIdentity identity = new(token.DangerousGetHandle());
        if (identity.User?.Value != sid) throw MessageExceptions.Create(MessageText.Create("Backend.Core.WindowsCaseSessionReader.AuthenticationId.01"), sourceText => new UnauthorizedAccessException(sourceText));
        int elevation = ReadToken<int>(token, 18);
        if (elevation == 2)
        {
            IntPtr linked = ReadToken<IntPtr>(token, 19);
            using SafeAccessTokenHandle linkedToken = new(linked);
            using WindowsIdentity linkedIdentity = new(linkedToken.DangerousGetHandle());
            if (linkedIdentity.User?.Value != sid) throw MessageExceptions.Create(MessageText.Create("Backend.Core.WindowsCaseSessionReader.AuthenticationId.02"), sourceText => new UnauthorizedAccessException(sourceText));
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
    [method: System.Text.Json.Serialization.JsonConstructor]
    private sealed record BootRead(DiagnosticReadStatus Status, string? Identity, DateTimeOffset? Started, long? RecordId, string Detail)
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

        public BootRead(DiagnosticReadStatus Status, string? Identity, DateTimeOffset? Started, long? RecordId, SteamSentinel.Core.Reporting.MessageText Detail) : this(Status, Identity, Started, RecordId, Detail.OriginalText)
        {
            DetailMessage = Detail.Message;
        }
    }
    [method: System.Text.Json.Serialization.JsonConstructor]
    private sealed record LogonRead(DiagnosticReadStatus Status, string? Id, DateTimeOffset? Started, int? Type, int? Session, string Detail)
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

        public LogonRead(DiagnosticReadStatus Status, string? Id, DateTimeOffset? Started, int? Type, int? Session, SteamSentinel.Core.Reporting.MessageText Detail) : this(Status, Id, Started, Type, Session, Detail.OriginalText)
        {
            DetailMessage = Detail.Message;
        }
    }
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
