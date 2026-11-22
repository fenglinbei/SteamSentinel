using SteamSentinel.Core.Reporting;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace SteamSentinel.App.Native;

internal sealed class RestrictedProcess : IDisposable
{
    // READ_CONTROL (0x00020000) | DESKTOP_WRITEOBJECTS (0x0080) | DESKTOP_CREATEWINDOW (0x0002) | DESKTOP_READOBJECTS (0x0001)
    // 刻意排除 DESKTOP_SWITCHDESKTOP、DESKTOP_HOOKCONTROL、DESKTOP_JOURNALRECORD、DESKTOP_JOURNALPLAYBACK、DESKTOP_CREATEMENU、DESKTOP_ENUMERATE、WRITE_DAC、WRITE_OWNER、DELETE
    internal const uint IsolatedDesktopAccess = 0x00020083;
    private const int UoiName = 2;

    private readonly SafeKernelHandle _processHandle;
    private readonly SafeDesktopHandle? _desktopHandle;
    private bool _disposed;

    private RestrictedProcess(
        SafeKernelHandle processHandle,
        SafeDesktopHandle? desktopHandle,
        string? isolatedDesktopName,
        StreamWriter standardInput,
        StreamReader standardOutput,
        StreamReader standardError)
    {
        _processHandle = processHandle;
        _desktopHandle = desktopHandle;
        IsolatedDesktopName = isolatedDesktopName;
        StandardInput = standardInput;
        StandardOutput = standardOutput;
        StandardError = standardError;
    }

    public StreamWriter StandardInput { get; }
    public StreamReader StandardOutput { get; }
    public StreamReader StandardError { get; }
    internal string? IsolatedDesktopName { get; }
    public bool HasExited => WaitForSingleObject(_processHandle, 0) switch
    {
        0 => true,
        258 => false,
        _ => throw MessageExceptions.Create(MessageText.Create("Backend.App.RestrictedProcess.HasExited.01"), sourceText => new Win32Exception(Marshal.GetLastWin32Error(), sourceText))
    };
    public int ExitCode
    {
        get
        {
            if (!HasExited) throw MessageExceptions.Create(MessageText.Create("Backend.App.RestrictedProcess.ExitCode.01"), sourceText => new InvalidOperationException(sourceText));
            if (!GetExitCodeProcess(_processHandle, out uint code))
                throw MessageExceptions.Create(MessageText.Create("Backend.App.RestrictedProcess.ExitCode.02"), sourceText => new Win32Exception(Marshal.GetLastWin32Error(), sourceText));
            return unchecked((int)code);
        }
    }

    public static RestrictedProcess Start(string executable, string workingDirectory, JobObject job)
    {
        string fullExecutable = Path.GetFullPath(executable);
        string fullWorkingDirectory = Path.GetFullPath(workingDirectory);
        Directory.CreateDirectory(fullWorkingDirectory);

        SecurityAttributes inheritable = new()
        {
            Length = Marshal.SizeOf<SecurityAttributes>(),
            InheritHandle = true
        };
        SafeFileHandle? childStdin = null, parentStdin = null, childStdout = null,
            parentStdout = null, childStderr = null, parentStderr = null;

        SafeKernelHandle? processHandle = null;
        SafeKernelHandle? threadHandle = null;
        SafeDesktopHandle? desktopHandle = null;
        IntPtr environment = IntPtr.Zero;
        IntPtr attributes = IntPtr.Zero, inheritedHandles = IntPtr.Zero;
        bool attributesInitialized = false;
        try
        {
            CreatePipePair(inheritable, childReads: true, out childStdin, out parentStdin);
            CreatePipePair(inheritable, childReads: false, out childStdout, out parentStdout);
            CreatePipePair(inheritable, childReads: false, out childStderr, out parentStderr);
            using SafeAccessTokenHandle restrictedToken = CreateLowIntegrityToken();
            _ = TryCreateIsolatedDesktop(restrictedToken, out desktopHandle, out string? isolatedDesktopName);
            environment = BuildEnvironmentBlock(fullWorkingDirectory);
            nuint attributeBytes = 0;
            InitializeProcThreadAttributeList(IntPtr.Zero, 1, 0, ref attributeBytes);
            if (attributeBytes == 0) throw MessageExceptions.Create(MessageText.Create("Backend.App.RestrictedProcess.Start.01"), sourceText => new Win32Exception(Marshal.GetLastWin32Error(), sourceText));
            attributes = Marshal.AllocHGlobal(checked((nint)attributeBytes));
            if (!InitializeProcThreadAttributeList(attributes, 1, 0, ref attributeBytes))
                throw MessageExceptions.Create(MessageText.Create("Backend.App.RestrictedProcess.Start.02"), sourceText => new Win32Exception(Marshal.GetLastWin32Error(), sourceText));
            attributesInitialized = true;
            inheritedHandles = Marshal.AllocHGlobal(3 * IntPtr.Size);
            Marshal.WriteIntPtr(inheritedHandles, 0, childStdin.DangerousGetHandle());
            Marshal.WriteIntPtr(inheritedHandles, IntPtr.Size, childStdout.DangerousGetHandle());
            Marshal.WriteIntPtr(inheritedHandles, 2 * IntPtr.Size, childStderr.DangerousGetHandle());
            if (!UpdateProcThreadAttribute(attributes, 0, 0x00020002, inheritedHandles,
                    (nuint)(3 * IntPtr.Size), IntPtr.Zero, IntPtr.Zero))
                throw MessageExceptions.Create(MessageText.Create("Backend.App.RestrictedProcess.Start.03"), sourceText => new Win32Exception(Marshal.GetLastWin32Error(), sourceText));
            StartupInfoEx startup = new()
            {
                Info = new StartupInfo
                {
                    Size = Marshal.SizeOf<StartupInfoEx>(),
                    Desktop = isolatedDesktopName,
                    Flags = StartfUseStdHandles,
                    StandardInput = childStdin.DangerousGetHandle(),
                    StandardOutput = childStdout.DangerousGetHandle(),
                    StandardError = childStderr.DangerousGetHandle()
                },
                AttributeList = attributes
            };
            StringBuilder commandLine = new($"\"{fullExecutable}\"");
            uint flags = CreateSuspended | CreateNoWindow | CreateUnicodeEnvironment | 0x00080000;
            if (!CreateProcessAsUser(
                    restrictedToken,
                    fullExecutable,
                    commandLine,
                    IntPtr.Zero,
                    IntPtr.Zero,
                    inheritHandles: true,
                    flags,
                    environment,
                    fullWorkingDirectory,
                    ref startup,
                    out ProcessInformation information))
            {
                throw MessageExceptions.Create(MessageText.Create("Backend.App.RestrictedProcess.Start.04"), sourceText => new Win32Exception(Marshal.GetLastWin32Error(), sourceText));
            }

            processHandle = new SafeKernelHandle(information.Process, ownsHandle: true);
            threadHandle = new SafeKernelHandle(information.Thread, ownsHandle: true);
            job.Assign(processHandle.DangerousGetHandle());
            if (ResumeThread(threadHandle) == uint.MaxValue)
            {
                int error = Marshal.GetLastWin32Error();
                TerminateProcess(processHandle, 1);
                throw MessageExceptions.Create(MessageText.Create("Backend.App.RestrictedProcess.Start.05"), sourceText => new Win32Exception(error, sourceText));
            }

            childStdin.Dispose();
            childStdout.Dispose();
            childStderr.Dispose();
            threadHandle.Dispose();
            threadHandle = null;

            FileStream stdinStream = new(parentStdin, FileAccess.Write, 4096, isAsync: false);
            FileStream stdoutStream = new(parentStdout, FileAccess.Read, 4096, isAsync: false);
            FileStream stderrStream = new(parentStderr, FileAccess.Read, 4096, isAsync: false);
            StreamWriter input = new(stdinStream, new UTF8Encoding(false)) { AutoFlush = false };
            StreamReader output = new(stdoutStream, Encoding.UTF8, detectEncodingFromByteOrderMarks: true);
            StreamReader errorReader = new(stderrStream, Encoding.UTF8, detectEncodingFromByteOrderMarks: true);
            RestrictedProcess result = new(processHandle, desktopHandle, isolatedDesktopName, input, output, errorReader);
            processHandle = null; // Ownership transfers only after all streams are ready.
            desktopHandle = null;
            return result;
        }
        catch
        {
            // A failed Job assignment or stream setup must not leave a suspended orphan.
            if (processHandle is not null && !processHandle.IsInvalid) TerminateProcess(processHandle, 1);
            childStdin?.Dispose();
            childStdout?.Dispose();
            childStderr?.Dispose();
            parentStdin?.Dispose();
            parentStdout?.Dispose();
            parentStderr?.Dispose();
            processHandle?.Dispose();
            threadHandle?.Dispose();
            desktopHandle?.Dispose();
            throw;
        }
        finally
        {
            if (attributesInitialized) DeleteProcThreadAttributeList(attributes);
            if (attributes != IntPtr.Zero) Marshal.FreeHGlobal(attributes);
            if (inheritedHandles != IntPtr.Zero) Marshal.FreeHGlobal(inheritedHandles);
            if (environment != IntPtr.Zero) Marshal.FreeHGlobal(environment);
        }
    }

    public async Task WaitForExitAsync(CancellationToken cancellationToken)
    {
        // Query the original handle, never reopen a possibly exited/reused PID.
        while (!HasExited) await Task.Delay(25, cancellationToken).ConfigureAwait(false);
    }

    public void Kill()
    {
        if (!HasExited && !TerminateProcess(_processHandle, 1) && !HasExited)
            throw MessageExceptions.Create(MessageText.Create("Backend.App.RestrictedProcess.Kill.01"), sourceText => new Win32Exception(Marshal.GetLastWin32Error(), sourceText));
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        try { Kill(); } catch { }
        // 等待被终止的子进程完成内核对象清理并释放隔离桌面引用，防止关闭桌面时产生竞争
        if (!_processHandle.IsInvalid)
        {
            try { _ = WaitForSingleObject(_processHandle, 200); } catch { }
        }
        StandardInput.Dispose();
        StandardOutput.Dispose();
        StandardError.Dispose();
        _processHandle.Dispose();
        _desktopHandle?.Dispose();
    }

    private static void CreatePipePair(
        SecurityAttributes attributes,
        bool childReads,
        out SafeFileHandle child,
        out SafeFileHandle parent)
    {
        if (!CreatePipe(out SafeFileHandle read, out SafeFileHandle write, ref attributes, 0))
            throw MessageExceptions.Create(MessageText.Create("Backend.App.RestrictedProcess.CreatePipePair.01"), sourceText => new Win32Exception(Marshal.GetLastWin32Error(), sourceText));

        child = childReads ? read : write;
        parent = childReads ? write : read;
        if (!SetHandleInformation(parent, HandleFlagInherit, 0))
        {
            read.Dispose();
            write.Dispose();
            throw MessageExceptions.Create(MessageText.Create("Backend.App.RestrictedProcess.CreatePipePair.02"), sourceText => new Win32Exception(Marshal.GetLastWin32Error(), sourceText));
        }
    }

    internal static SafeAccessTokenHandle CreateLowIntegrityToken()
    {
        uint access = TokenAssignPrimary | TokenDuplicate | TokenQuery | TokenAdjustDefault | TokenAdjustSessionId;
        if (!OpenProcessToken(GetCurrentProcess(), access, out SafeAccessTokenHandle current))
            throw MessageExceptions.Create(MessageText.Create("Backend.App.RestrictedProcess.CreateLowIntegrityToken.01"), sourceText => new Win32Exception(Marshal.GetLastWin32Error(), sourceText));
        using (current) return CreateLowIntegrityToken(current);
    }

    internal static SafeAccessTokenHandle CreateLowIntegrityToken(SafeAccessTokenHandle current)
    {
        if (!CreateRestrictedToken(
                current,
                DisableMaxPrivilege | LuaToken,
                0,
                IntPtr.Zero,
                0,
                IntPtr.Zero,
                0,
                IntPtr.Zero,
                out SafeAccessTokenHandle restricted))
        {
            throw MessageExceptions.Create(MessageText.Create("Backend.App.RestrictedProcess.CreateLowIntegrityToken.02"), sourceText => new Win32Exception(Marshal.GetLastWin32Error(), sourceText));
        }

        try
        {
            SetLowIntegrity(restricted);
            RestrictedTokenSecurity.ConfigureDefaultObjects(restricted);
            return restricted;
        }
        catch
        {
            restricted.Dispose();
            throw;
        }
    }

    private static void SetLowIntegrity(SafeAccessTokenHandle token)
    {
        if (!ConvertStringSidToSid("S-1-16-4096", out IntPtr sid))
            throw MessageExceptions.Create(MessageText.Create("Backend.App.RestrictedProcess.SetLowIntegrity.01"), sourceText => new Win32Exception(Marshal.GetLastWin32Error(), sourceText));
        try
        {
            TokenMandatoryLabel label = new()
            {
                Label = new SidAndAttributes { Sid = sid, Attributes = SeGroupIntegrity }
            };
            int size = Marshal.SizeOf<TokenMandatoryLabel>();
            IntPtr buffer = Marshal.AllocHGlobal(size);
            try
            {
                Marshal.StructureToPtr(label, buffer, false);
                uint totalSize = checked((uint)size + GetLengthSid(sid));
                if (!SetTokenInformation(token, TokenIntegrityLevel, buffer, totalSize))
                    throw MessageExceptions.Create(MessageText.Create("Backend.App.RestrictedProcess.SetLowIntegrity.02"), sourceText => new Win32Exception(Marshal.GetLastWin32Error(), sourceText));
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }
        }
        finally
        {
            LocalFree(sid);
        }
    }

    /// <summary>
    /// 构造带受保护 DACL（D:P）与 Low 强制标签（S:(ML;;NW;;;LW)）的隔离桌面 SDDL。
    /// 仅授予受限 Worker 用户最小桌面权限与 SYSTEM 完全访问权限。
    /// </summary>
    internal static string BuildIsolatedDesktopSddl(SecurityIdentifier user)
    {
        if (user.IsWellKnown(WellKnownSidType.LocalSystemSid))
            return "D:P(A;;GA;;;SY)S:(ML;;NW;;;LW)";
        return $"D:P(A;;0x{IsolatedDesktopAccess:X8};;;{user.Value})(A;;GA;;;SY)S:(ML;;NW;;;LW)";
    }

    /// <summary>
    /// 为受限子进程创建不可见的 Low Integrity 专属隔离桌面；若当前会话禁止创建桌面则优雅回退。
    /// </summary>
    private static bool TryCreateIsolatedDesktop(
        SafeAccessTokenHandle restrictedToken,
        out SafeDesktopHandle? desktopHandle,
        out string? desktopPath)
    {
        desktopHandle = null;
        desktopPath = null;
        try
        {
            IntPtr windowStation = GetProcessWindowStation();
            if (windowStation == IntPtr.Zero) return false;

            _ = GetUserObjectInformation(windowStation, UoiName, null, 0, out uint needed);
            if (needed is < 2 or > 4096) return false;
            byte[] nameBuffer = new byte[needed];
            if (!GetUserObjectInformation(windowStation, UoiName, nameBuffer, needed, out _)) return false;

            string windowStationName = Encoding.Unicode.GetString(nameBuffer).TrimEnd('\0');
            if (string.IsNullOrWhiteSpace(windowStationName) ||
                windowStationName.Contains('\\') ||
                windowStationName.Contains('\0'))
            {
                return false;
            }

            SecurityIdentifier user = RestrictedTokenSecurity.GetTokenUser(restrictedToken);
            string sddl = BuildIsolatedDesktopSddl(user);
            if (!ConvertStringSecurityDescriptorToSecurityDescriptor(sddl, 1, out IntPtr securityDescriptor, out _))
                return false;

            try
            {
                SecurityAttributes desktopAttributes = new()
                {
                    Length = Marshal.SizeOf<SecurityAttributes>(),
                    SecurityDescriptor = securityDescriptor,
                    // 绝不将父进程桌面的顶层句柄继承给 Low Integrity 子进程
                    InheritHandle = false
                };
                string desktopName = "SteamSentinelWkr_" + Guid.NewGuid().ToString("N")[..16];
                IntPtr rawDesktop = CreateDesktop(desktopName, null, IntPtr.Zero, 0, IsolatedDesktopAccess, ref desktopAttributes);
                if (rawDesktop == IntPtr.Zero) return false;

                desktopHandle = new SafeDesktopHandle(rawDesktop, ownsHandle: true);
                desktopPath = $"{windowStationName}\\{desktopName}";
                return true;
            }
            finally
            {
                LocalFree(securityDescriptor);
            }
        }
        catch
        {
            desktopHandle?.Dispose();
            desktopHandle = null;
            desktopPath = null;
            return false;
        }
    }

    private static IntPtr BuildEnvironmentBlock(string temporaryDirectory)
    {
        Dictionary<string, string> values = new(StringComparer.OrdinalIgnoreCase)
        {
            ["SystemRoot"] = Environment.GetFolderPath(Environment.SpecialFolder.Windows),
            ["WINDIR"] = Environment.GetFolderPath(Environment.SpecialFolder.Windows),
            // The Defender AMSI provider needs this even in a Low-integrity process.
            // Derive it from the Windows directory; do not inherit a caller-supplied value.
            ["SystemDrive"] = Path.GetPathRoot(Environment.GetFolderPath(Environment.SpecialFolder.Windows))!.TrimEnd('\\'),
            ["COMSPEC"] = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "cmd.exe"),
            ["PATH"] = Environment.GetFolderPath(Environment.SpecialFolder.System),
            ["TEMP"] = temporaryDirectory,
            ["TMP"] = temporaryDirectory,
            ["USERPROFILE"] = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
            ["APPDATA"] = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            ["LOCALAPPDATA"] = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            ["PROGRAMDATA"] = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            ["ProgramFiles"] = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
            ["ProgramFiles(x86)"] = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86),
            ["DOTNET_EnableDiagnostics"] = "0",
            ["COMPlus_EnableDiagnostics"] = "0",
            ["DOTNET_CLI_TELEMETRY_OPTOUT"] = "1"
        };
        string block = string.Concat(values.OrderBy(pair => pair.Key, StringComparer.OrdinalIgnoreCase)
            .Select(pair => $"{pair.Key}={pair.Value}\0")) + "\0";
        return Marshal.StringToHGlobalUni(block);
    }

    private const uint TokenAssignPrimary = 0x0001;
    private const uint TokenDuplicate = 0x0002;
    private const uint TokenQuery = 0x0008;
    private const uint TokenAdjustDefault = 0x0080;
    private const uint TokenAdjustSessionId = 0x0100;
    private const uint DisableMaxPrivilege = 0x00000001;
    private const uint LuaToken = 0x00000004;
    private const uint SeGroupIntegrity = 0x00000020;
    private const int TokenIntegrityLevel = 25;
    private const uint StartfUseStdHandles = 0x00000100;
    private const uint CreateSuspended = 0x00000004;
    private const uint CreateUnicodeEnvironment = 0x00000400;
    private const uint CreateNoWindow = 0x08000000;
    private const uint HandleFlagInherit = 0x00000001;

    [StructLayout(LayoutKind.Sequential)]
    private struct SecurityAttributes
    {
        public int Length;
        public IntPtr SecurityDescriptor;
        [MarshalAs(UnmanagedType.Bool)] public bool InheritHandle;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct StartupInfo
    {
        public int Size;
        public string? Reserved;
        public string? Desktop;
        public string? Title;
        public uint X;
        public uint Y;
        public uint XSize;
        public uint YSize;
        public uint XCountChars;
        public uint YCountChars;
        public uint FillAttribute;
        public uint Flags;
        public ushort ShowWindow;
        public ushort Reserved2;
        public IntPtr Reserved2Pointer;
        public IntPtr StandardInput;
        public IntPtr StandardOutput;
        public IntPtr StandardError;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct StartupInfoEx
    {
        public StartupInfo Info;
        public IntPtr AttributeList;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct ProcessInformation
    {
        public IntPtr Process;
        public IntPtr Thread;
        public uint ProcessId;
        public uint ThreadId;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct SidAndAttributes
    {
        public IntPtr Sid;
        public uint Attributes;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct TokenMandatoryLabel
    {
        public SidAndAttributes Label;
    }

    private sealed class SafeKernelHandle : SafeHandleZeroOrMinusOneIsInvalid
    {
        public SafeKernelHandle() : base(true) { }
        public SafeKernelHandle(IntPtr preexistingHandle, bool ownsHandle) : base(ownsHandle) =>
            SetHandle(preexistingHandle);
        protected override bool ReleaseHandle() => CloseHandle(handle);
    }

    private sealed class SafeDesktopHandle : SafeHandleZeroOrMinusOneIsInvalid
    {
        public SafeDesktopHandle() : base(true) { }
        public SafeDesktopHandle(IntPtr preexistingHandle, bool ownsHandle) : base(ownsHandle) =>
            SetHandle(preexistingHandle);
        protected override bool ReleaseHandle() => CloseDesktop(handle);
    }

    [DllImport("user32.dll", SetLastError = true)]
    private static extern IntPtr GetProcessWindowStation();

    [DllImport("user32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetUserObjectInformation(
        IntPtr objectHandle,
        int index,
        [Out] byte[]? info,
        uint length,
        out uint lengthNeeded);

    [DllImport("user32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr CreateDesktop(
        string desktop,
        string? device,
        IntPtr devmode,
        uint flags,
        uint desiredAccess,
        ref SecurityAttributes securityAttributes);

    [DllImport("user32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseDesktop(IntPtr desktop);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool ConvertStringSecurityDescriptorToSecurityDescriptor(
        string stringSecurityDescriptor,
        uint stringSdRevision,
        out IntPtr securityDescriptor,
        out uint securityDescriptorSize);

    [DllImport("kernel32.dll")]
    private static extern IntPtr GetCurrentProcess();

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern uint WaitForSingleObject(SafeKernelHandle handle, uint milliseconds);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetExitCodeProcess(SafeKernelHandle process, out uint exitCode);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CreatePipe(
        out SafeFileHandle readPipe,
        out SafeFileHandle writePipe,
        ref SecurityAttributes pipeAttributes,
        uint size);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetHandleInformation(SafeFileHandle handle, uint mask, uint flags);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool OpenProcessToken(
        IntPtr processHandle,
        uint desiredAccess,
        out SafeAccessTokenHandle tokenHandle);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CreateRestrictedToken(
        SafeAccessTokenHandle existingTokenHandle,
        uint flags,
        uint disableSidCount,
        IntPtr sidsToDisable,
        uint deletePrivilegeCount,
        IntPtr privilegesToDelete,
        uint restrictedSidCount,
        IntPtr sidsToRestrict,
        out SafeAccessTokenHandle newTokenHandle);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CreateProcessAsUser(
        SafeAccessTokenHandle token,
        string applicationName,
        StringBuilder commandLine,
        IntPtr processAttributes,
        IntPtr threadAttributes,
        [MarshalAs(UnmanagedType.Bool)] bool inheritHandles,
        uint creationFlags,
        IntPtr environment,
        string currentDirectory,
        ref StartupInfoEx startupInfo,
        out ProcessInformation processInformation);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool InitializeProcThreadAttributeList(IntPtr list, int count, int flags, ref nuint size);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool UpdateProcThreadAttribute(IntPtr list, uint flags, nuint attribute,
        IntPtr value, nuint size, IntPtr previous, IntPtr returnSize);

    [DllImport("kernel32.dll")]
    private static extern void DeleteProcThreadAttributeList(IntPtr list);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool ConvertStringSidToSid(string stringSid, out IntPtr sid);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern uint GetLengthSid(IntPtr sid);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetTokenInformation(
        SafeAccessTokenHandle tokenHandle,
        int tokenInformationClass,
        IntPtr tokenInformation,
        uint tokenInformationLength);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern uint ResumeThread(SafeKernelHandle thread);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool TerminateProcess(SafeKernelHandle process, uint exitCode);

    [DllImport("kernel32.dll")]
    private static extern IntPtr LocalFree(IntPtr memory);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseHandle(IntPtr handle);
}
