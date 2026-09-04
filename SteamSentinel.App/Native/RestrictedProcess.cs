using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace SteamSentinel.App.Native;

internal sealed class RestrictedProcess : IDisposable
{
    private readonly SafeKernelHandle _processHandle;
    private bool _disposed;

    private RestrictedProcess(
        SafeKernelHandle processHandle,
        StreamWriter standardInput,
        StreamReader standardOutput,
        StreamReader standardError)
    {
        _processHandle = processHandle;
        StandardInput = standardInput;
        StandardOutput = standardOutput;
        StandardError = standardError;
    }

    public StreamWriter StandardInput { get; }
    public StreamReader StandardOutput { get; }
    public StreamReader StandardError { get; }
    public bool HasExited => WaitForSingleObject(_processHandle, 0) switch
    {
        0 => true,
        258 => false,
        _ => throw new Win32Exception(Marshal.GetLastWin32Error(), "无法读取扫描组件的进程状态。")
    };
    public int ExitCode
    {
        get
        {
            if (!HasExited) throw new InvalidOperationException("扫描组件尚未退出。");
            if (!GetExitCodeProcess(_processHandle, out uint code))
                throw new Win32Exception(Marshal.GetLastWin32Error(), "无法读取扫描组件的退出码。");
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
        IntPtr environment = IntPtr.Zero;
        try
        {
            CreatePipePair(inheritable, childReads: true, out childStdin, out parentStdin);
            CreatePipePair(inheritable, childReads: false, out childStdout, out parentStdout);
            CreatePipePair(inheritable, childReads: false, out childStderr, out parentStderr);
            using SafeAccessTokenHandle restrictedToken = CreateLowIntegrityToken();
            environment = BuildEnvironmentBlock(fullWorkingDirectory);
            StartupInfo startup = new()
            {
                Size = Marshal.SizeOf<StartupInfo>(),
                Flags = StartfUseStdHandles,
                StandardInput = childStdin.DangerousGetHandle(),
                StandardOutput = childStdout.DangerousGetHandle(),
                StandardError = childStderr.DangerousGetHandle()
            };
            StringBuilder commandLine = new($"\"{fullExecutable}\"");
            uint flags = CreateSuspended | CreateNoWindow | CreateUnicodeEnvironment;
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
                throw new Win32Exception(Marshal.GetLastWin32Error(), "无法以受限令牌启动压缩包扫描进程。");
            }

            processHandle = new SafeKernelHandle(information.Process, ownsHandle: true);
            threadHandle = new SafeKernelHandle(information.Thread, ownsHandle: true);
            job.Assign(processHandle.DangerousGetHandle());
            if (ResumeThread(threadHandle) == uint.MaxValue)
            {
                int error = Marshal.GetLastWin32Error();
                TerminateProcess(processHandle, 1);
                throw new Win32Exception(error, "无法恢复受限扫描进程。");
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
            RestrictedProcess result = new(processHandle, input, output, errorReader);
            processHandle = null; // Ownership transfers only after all streams are ready.
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
            throw;
        }
        finally
        {
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
            throw new Win32Exception(Marshal.GetLastWin32Error(), "无法结束扫描组件。");
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        try { Kill(); } catch { }
        StandardInput.Dispose();
        StandardOutput.Dispose();
        StandardError.Dispose();
        _processHandle.Dispose();
    }

    private static void CreatePipePair(
        SecurityAttributes attributes,
        bool childReads,
        out SafeFileHandle child,
        out SafeFileHandle parent)
    {
        if (!CreatePipe(out SafeFileHandle read, out SafeFileHandle write, ref attributes, 0))
            throw new Win32Exception(Marshal.GetLastWin32Error(), "无法创建受限进程通信管道。");

        child = childReads ? read : write;
        parent = childReads ? write : read;
        if (!SetHandleInformation(parent, HandleFlagInherit, 0))
        {
            read.Dispose();
            write.Dispose();
            throw new Win32Exception(Marshal.GetLastWin32Error(), "无法限制通信管道继承。");
        }
    }

    internal static SafeAccessTokenHandle CreateLowIntegrityToken()
    {
        uint access = TokenAssignPrimary | TokenDuplicate | TokenQuery | TokenAdjustDefault | TokenAdjustSessionId;
        if (!OpenProcessToken(GetCurrentProcess(), access, out SafeAccessTokenHandle current))
            throw new Win32Exception(Marshal.GetLastWin32Error(), "无法打开当前进程令牌。");
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
            throw new Win32Exception(Marshal.GetLastWin32Error(), "无法创建受限扫描令牌。");
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
            throw new Win32Exception(Marshal.GetLastWin32Error(), "无法创建 Low Integrity SID。");
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
                    throw new Win32Exception(Marshal.GetLastWin32Error(), "无法将扫描令牌降至 Low Integrity。");
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

    private static IntPtr BuildEnvironmentBlock(string temporaryDirectory)
    {
        Dictionary<string, string> values = new(StringComparer.OrdinalIgnoreCase)
        {
            ["SystemRoot"] = Environment.GetFolderPath(Environment.SpecialFolder.Windows),
            ["WINDIR"] = Environment.GetFolderPath(Environment.SpecialFolder.Windows),
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
        ref StartupInfo startupInfo,
        out ProcessInformation processInformation);

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
