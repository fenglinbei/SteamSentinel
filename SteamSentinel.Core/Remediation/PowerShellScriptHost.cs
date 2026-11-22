using System.ComponentModel;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using Microsoft.Win32.SafeHandles;
using SteamSentinel.Core.Utilities;

namespace SteamSentinel.Core.Remediation;

public enum ScriptHostReadStatus { Readable, Exited, AccessDenied, Unsupported, IdentityChanged, Failed }

public sealed record PowerShellScriptInvocation(
    string CommandLine, string ScriptPath, string? InstallDir, string? TaskDir, IReadOnlyList<string> Arguments);

public sealed record PowerShellScriptHostSnapshot
{
    public int ProcessId { get; init; }
    public DateTimeOffset? StartedAtUtc { get; init; }
    public string? ImagePath { get; init; }
    public string? CommandLine { get; init; }
    public int? ParentProcessId { get; init; }
    public ScriptHostReadStatus Status { get; init; }
    public string? Error { get; init; }
    /// <summary>
    /// 指示因权限受限而无法读取命令行的目标是否为系统服务账户（SYSTEM/LocalService/NetworkService）或受保护内核进程（PPL）。
    /// </summary>
    public bool IsProtectedSystemProcess { get; init; }
    public bool IsReadable => Status == ScriptHostReadStatus.Readable && ProcessId > 0 &&
        StartedAtUtc is not null && ImagePath is not null && CommandLine is not null;
}

/// <summary>
/// Reads a bounded command line through the existing process handle. It never starts a shell,
/// evaluates text, or treats a process name as proof of a trusted interpreter or malicious script.
/// </summary>
public static class PowerShellScriptHost
{
    private const int MaximumCommandCharacters = 32768;
    private const int MaximumNativeBytes = 128 * 1024;
    private const int MaximumProcesses = 4096;
    private const uint QueryLimitedInformation = 0x1000;
    private const uint Synchronize = 0x00100000;
    private const uint StillActive = 259;
    private const uint WaitSignaled = 0;
    private const uint WaitTimeout = 258;
    private const uint WaitFailed = 0xFFFFFFFF;
    private const int ProcessCommandLineInformation = 60;
    private const int ProcessProtectionInformation = 61;

    public static bool IsTrustedHostPath(string? path) => IsTrustedImagePath(path);

    public static bool IsTrustedImagePath(string? path)
    {
        if (!TryLocalPath(path, out string full)) return false;
        string windows = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        if (string.IsNullOrWhiteSpace(windows)) return false;
        bool expected = new[] { "System32", "SysWOW64" }.Any(system =>
            full.Equals(Path.Combine(windows, system, "WindowsPowerShell", "v1.0", "powershell.exe"), StringComparison.OrdinalIgnoreCase));
        if (!expected) return false;
        try { return !Validation.ContainsReparsePoint(full); }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException or ArgumentException) { return false; }
    }

    /// <summary>Conservative -File syntax, including only literal, explicitly supported sample parameters.</summary>
    public static bool TryParse(string? commandLine, [NotNullWhen(true)] out PowerShellScriptInvocation? invocation)
    {
        invocation = null;
        if (!TryArguments(commandLine, out List<string> parts) || parts.Count < 3) return false;
        string executable = parts[0];
        if (!executable.Equals("powershell.exe", StringComparison.OrdinalIgnoreCase) &&
            !executable.Equals("powershell", StringComparison.OrdinalIgnoreCase) && !IsTrustedImagePath(executable)) return false;
        HashSet<string> options = new(StringComparer.OrdinalIgnoreCase);
        int index = 1;
        while (index < parts.Count)
        {
            string option = parts[index++].ToLowerInvariant();
            if (option is "-file" or "-f") break;
            if (!options.Add(option)) return false;
            if (option is "-noprofile" or "-noninteractive" or "-nologo") continue;
            if (index >= parts.Count) return false;
            string value = parts[index++];
            if (option == "-windowstyle" && IsWindowStyle(value)) continue;
            if (option == "-executionpolicy" && new[] { "Bypass", "RemoteSigned", "AllSigned", "Restricted", "Unrestricted", "Default", "Undefined" }
                .Contains(value, StringComparer.OrdinalIgnoreCase)) continue;
            return false;
        }
        if (index >= parts.Count || parts[index - 1].ToLowerInvariant() is not ("-file" or "-f") ||
            !TryLocalPath(parts[index++], out string script) || !Path.GetExtension(script).Equals(".ps1", StringComparison.OrdinalIgnoreCase)) return false;
        string? install = null, task = null;
        string[] arguments = parts.Skip(index).ToArray();
        HashSet<string> parameters = new(StringComparer.OrdinalIgnoreCase);
        while (index < parts.Count)
        {
            string parameter = parts[index++].ToLowerInvariant();
            if (!parameters.Add(parameter)) return false;
            if (parameter == "-dryrun") continue;
            if (index >= parts.Count) return false;
            string value = parts[index++];
            switch (parameter)
            {
                case "-installdir":
                    if (!TryLocalPath(value, out install)) return false;
                    break;
                case "-taskdir":
                    if (!TryLocalPath(value, out task)) return false;
                    break;
                case "-everymin":
                case "-maxtry":
                    if (!int.TryParse(value, NumberStyles.None, CultureInfo.InvariantCulture, out int count) || count <= 0) return false;
                    break;
                case "-exename":
                    if (value != Path.GetFileName(value) || value.IndexOfAny([':', '/', '\\']) >= 0 ||
                        !value.EndsWith(".exe", StringComparison.OrdinalIgnoreCase)) return false;
                    break;
                case "-procname":
                    if (value.Length == 0 || value.IndexOfAny([':', '/', '\\']) >= 0) return false;
                    break;
                case "-base":
                    if (!Uri.TryCreate(value, UriKind.Absolute, out Uri? uri) || uri.Scheme is not ("https" or "http") ||
                        uri.UserInfo.Length != 0 || uri.Fragment.Length != 0) return false;
                    break;
                case "-key":
                    if (value.Length == 0 || value[0] == '-') return false;
                    break;
                default: return false;
            }
        }
        invocation = new(commandLine!, script, install, task, Array.AsReadOnly(arguments));
        return true;
    }

    internal static bool IsWindowStyle(string value) =>
        new[] { "Hidden", "Normal", "Minimized", "Maximized" }.Contains(value, StringComparer.OrdinalIgnoreCase);

    private static bool TryArguments(string? command, out List<string> arguments)
    {
        arguments = [];
        if (string.IsNullOrWhiteSpace(command) || command.Length > MaximumCommandCharacters ||
            command.Any(value => char.IsControl(value) && value != '\t') ||
            command.IndexOfAny(['&', '|', ';', '`', '>', '<', '\'', '$', '(', ')', '{', '}']) >= 0) return false;
        int index = 0;
        while (index < command.Length)
        {
            while (index < command.Length && command[index] is ' ' or '\t') index++;
            if (index == command.Length) break;
            if (arguments.Count >= 64) return false;
            int start;
            string argument;
            if (command[index] == '"')
            {
                start = ++index;
                while (index < command.Length && command[index] != '"') index++;
                if (index == command.Length || index == start || command[index - 1] == '\\') return false;
                argument = command[start..index++];
                if (index < command.Length && command[index] is not (' ' or '\t')) return false;
            }
            else
            {
                start = index;
                while (index < command.Length && command[index] is not (' ' or '\t'))
                {
                    if (command[index] == '"' || char.IsWhiteSpace(command[index])) return false;
                    index++;
                }
                argument = command[start..index];
            }
            arguments.Add(argument);
        }
        return arguments.Count != 0;
    }

    private static bool TryLocalPath(string? value, out string full)
    {
        full = string.Empty;
        if (string.IsNullOrWhiteSpace(value) || value.Length > 32767 || value.Any(char.IsControl) ||
            value.Length < 4 || !char.IsAsciiLetter(value[0]) || value[1] != ':' || value[2] != '\\' ||
            value.IndexOfAny(['/', '*', '?', '"', '<', '>', '|']) >= 0 || value[2..].Contains(':')) return false;
        try
        {
            full = Path.GetFullPath(value);
            if (!full.Equals(value, StringComparison.OrdinalIgnoreCase)) return false;
            string[] segments = full[3..].Split('\\');
            return segments.All(segment => segment.Length > 0 && segment is not ("." or "..") &&
                !segment.EndsWith('.') && !segment.EndsWith(' '));
        }
        catch (Exception error) when (error is ArgumentException or NotSupportedException or PathTooLongException) { return false; }
    }

    public static bool SameIdentity(PowerShellScriptHostSnapshot expected, PowerShellScriptHostSnapshot actual) =>
        SameRawIdentity(expected, actual) && IsTrustedImagePath(expected.ImagePath) && IsTrustedImagePath(actual.ImagePath);

    public static bool SameRawIdentity(PowerShellScriptHostSnapshot expected, PowerShellScriptHostSnapshot actual) =>
        expected.IsReadable && actual.IsReadable && expected.ProcessId == actual.ProcessId &&
        expected.StartedAtUtc == actual.StartedAtUtc &&
        string.Equals(expected.ImagePath, actual.ImagePath, StringComparison.OrdinalIgnoreCase) &&
        string.Equals(expected.CommandLine, actual.CommandLine, StringComparison.Ordinal);

    public static PowerShellScriptHostSnapshot Read(int processId) => RequirePowerShell(ReadRaw(processId));

    public static PowerShellScriptHostSnapshot Read(SafeProcessHandle handle, int processId) => RequirePowerShell(ReadRaw(handle, processId));

    private static PowerShellScriptHostSnapshot RequirePowerShell(PowerShellScriptHostSnapshot observation) =>
        observation.IsReadable && !IsTrustedImagePath(observation.ImagePath)
            ? observation with { Status = ScriptHostReadStatus.Unsupported, Error = "The image is not a supported system Windows PowerShell host." }
            : observation;

    /// <summary>Identity collection only; callers must separately authorize the interpreter's exact image path.</summary>
    public static PowerShellScriptHostSnapshot ReadRaw(int processId)
    {
        if (!OperatingSystem.IsWindows() || processId <= 0)
            return Failure(processId, ScriptHostReadStatus.Unsupported, "Windows process identity is unavailable.");
        using SafeProcessHandle handle = OpenProcess(QueryLimitedInformation | Synchronize, false, processId);
        if (handle.IsInvalid)
        {
            int error = Marshal.GetLastWin32Error();
            return Win32Failure(processId, error, error == 5 && ProbeProtectedSystemProcess(processId));
        }
        return ReadRaw(handle, processId);
    }

    public static PowerShellScriptHostSnapshot ReadRaw(SafeProcessHandle handle, int processId)
    {
        if (!OperatingSystem.IsWindows() || handle.IsInvalid || handle.IsClosed || processId <= 0)
            return Failure(processId, ScriptHostReadStatus.Unsupported, "A live Windows process handle is required.");
        try
        {
            if (GetProcessId(handle) != (uint)processId)
                return Failure(processId, ScriptHostReadStatus.IdentityChanged, "The handle refers to a different process.");
            if (!TryIdentity(handle, out DateTimeOffset started, out string image, out bool exited))
            {
                int error = Marshal.GetLastWin32Error();
                return Win32Failure(processId, error, error == 5 && IsProtectedSystemHandle(handle));
            }
            if (exited) return Failure(processId, ScriptHostReadStatus.Exited, "The process has exited.");
            PowerShellScriptHostSnapshot observation = new() { ProcessId = processId, StartedAtUtc = started, ImagePath = image };
            string command = ReadCommandLine(handle);
            int? parent = ReadParentProcessId(handle);
            string finalCommand = ReadCommandLine(handle);
            if (!TryIdentity(handle, out DateTimeOffset endedStart, out string endedImage, out exited))
            {
                int error = Marshal.GetLastWin32Error();
                return Win32Failure(processId, error, error == 5 && IsProtectedSystemHandle(handle));
            }
            if (exited) return observation with { Status = ScriptHostReadStatus.Exited, Error = "The process exited during inspection." };
            if (GetProcessId(handle) != (uint)processId || started != endedStart || !image.Equals(endedImage, StringComparison.OrdinalIgnoreCase) ||
                !command.Equals(finalCommand, StringComparison.Ordinal))
                return observation with { Status = ScriptHostReadStatus.IdentityChanged, Error = "The process identity or command line changed during inspection." };
            return observation with { CommandLine = command, ParentProcessId = parent, Status = ScriptHostReadStatus.Readable };
        }
        catch (Win32Exception error)
        {
            return Win32Failure(processId, error.NativeErrorCode,
                error.NativeErrorCode == 5 && (IsProtectedSystemHandle(handle) || ProbeProtectedSystemProcess(processId)));
        }
        catch (Exception error) when (error is ArgumentException or InvalidOperationException or IOException or OverflowException)
        { return Failure(processId, ScriptHostReadStatus.Failed, error.Message); }
    }

    public static IReadOnlyList<PowerShellScriptHostSnapshot> ReadAll(CancellationToken cancellationToken = default) =>
        ReadAllByNames(["powershell"], cancellationToken).Select(RequirePowerShell).ToArray();

    public static IReadOnlyList<PowerShellScriptHostSnapshot> ReadAllByNames(IEnumerable<string> processNames, CancellationToken cancellationToken = default)
    {
        List<PowerShellScriptHostSnapshot> results = [];
        if (!OperatingSystem.IsWindows()) return [Failure(0, ScriptHostReadStatus.Unsupported, "Windows is required.")];
        Process[] processes;
        List<Process> collected = [];
        try
        {
            string[] names = processNames.Distinct(StringComparer.OrdinalIgnoreCase).Take(9).ToArray();
            if (names.Length > 8 || names.Any(name => string.IsNullOrWhiteSpace(name) || name.Length > 64 ||
                name.Any(character => !char.IsAsciiLetterOrDigit(character) && character is not ('-' or '_'))))
                return [Failure(0, ScriptHostReadStatus.Unsupported, "Process names must be bounded executable base names.")];
            foreach (string name in names)
            {
                cancellationToken.ThrowIfCancellationRequested();
                collected.AddRange(Process.GetProcessesByName(name));
            }
            processes = collected.ToArray();
        }
        catch (Exception error) when (error is Win32Exception or InvalidOperationException)
        {
            foreach (Process process in collected) process.Dispose();
            return [Failure(0, ScriptHostReadStatus.Failed, error.Message)];
        }
        catch { foreach (Process process in collected) process.Dispose(); throw; }
        try
        {
            foreach (Process process in processes.Take(MaximumProcesses))
            {
                cancellationToken.ThrowIfCancellationRequested();
                try { results.Add(ReadRaw(process.Id)); }
                catch (InvalidOperationException error) { results.Add(Failure(0, ScriptHostReadStatus.Exited, error.Message)); }
            }
            if (processes.Length > MaximumProcesses)
                results.Add(Failure(0, ScriptHostReadStatus.Failed, "The process enumeration limit was reached."));
        }
        finally { foreach (Process process in processes) process.Dispose(); }
        return results;
    }

    private static bool TryIdentity(SafeProcessHandle handle, out DateTimeOffset started, out string image, out bool exited)
    {
        started = default; image = string.Empty; exited = false;
        if (!GetProcessTimes(handle, out long created, out long exit, out _, out _)) return false;
        started = DateTimeOffset.FromFileTime(created).ToUniversalTime();
        if (!GetExitCodeProcess(handle, out uint exitCode)) return false;
        // TerminateProcess publishes its exit status before ExitTime and the process
        // object's signal necessarily become visible. WaitForExitAsync can complete in
        // that interval, so an empty ExitTime alone does not prove a live interpreter.
        exited = exit != 0 || exitCode != StillActive;
        if (exited) return true;
        // 259 is also a legal explicit exit code. A zero-time wait distinguishes it
        // from a live process. Missing SYNCHRONIZE rights must remain unreadable.
        uint wait = WaitForSingleObject(handle, 0);
        if (wait == WaitSignaled) { exited = true; return true; }
        if (wait == WaitFailed) return false;
        if (wait != WaitTimeout) { Marshal.SetLastPInvokeError(13); return false; }
        StringBuilder buffer = new(32768);
        int length = buffer.Capacity;
        if (!QueryFullProcessImageName(handle, 0, buffer, ref length)) return false;
        image = buffer.ToString();
        return length > 0;
    }

    private static string ReadCommandLine(SafeProcessHandle handle)
    {
        int status = NtQueryInformationProcess(handle, ProcessCommandLineInformation, IntPtr.Zero, 0, out int required);
        if (status == unchecked((int)0xC0000022)) throw new Win32Exception(5);
        if (required < Marshal.SizeOf<NativeUnicodeString>() || required > MaximumNativeBytes)
            throw new IOException("The command line size is unavailable or exceeds the read limit.");
        IntPtr allocation = Marshal.AllocHGlobal(required);
        try
        {
            status = NtQueryInformationProcess(handle, ProcessCommandLineInformation, allocation, required, out int returned);
            if (status == unchecked((int)0xC0000022)) throw new Win32Exception(5);
            if (status != 0 || returned < Marshal.SizeOf<NativeUnicodeString>() || returned > required)
                throw new IOException("The native command line read failed or changed size.");
            NativeUnicodeString text = Marshal.PtrToStructure<NativeUnicodeString>(allocation);
            long offset = text.Buffer.ToInt64() - allocation.ToInt64();
            if ((text.Length & 1) != 0 || text.Length > text.MaximumLength || text.Length / 2 > MaximumCommandCharacters ||
                offset < Marshal.SizeOf<NativeUnicodeString>() || offset > returned || text.Length > returned - offset)
                throw new IOException("The command line buffer has invalid bounds.");
            return Marshal.PtrToStringUni(text.Buffer, text.Length / 2) ?? throw new IOException("The command line is unavailable.");
        }
        finally { Marshal.FreeHGlobal(allocation); }
    }

    private static int? ReadParentProcessId(SafeProcessHandle handle)
    {
        int size = IntPtr.Size * 6;
        IntPtr buffer = Marshal.AllocHGlobal(size);
        try
        {
            if (NtQueryInformationProcess(handle, 0, buffer, size, out int returned) != 0 || returned != size) return null;
            long parent = Marshal.ReadIntPtr(buffer, IntPtr.Size * 5).ToInt64();
            return parent is > 0 and <= int.MaxValue ? (int)parent : null;
        }
        finally { Marshal.FreeHGlobal(buffer); }
    }

    /// <summary>
    /// 使用只读受限查询句柄安全读取进程映像路径与启动时间，避免受保护系统进程因 Module 枚举或缺乏同步权而误熔断。
    /// </summary>
    public static bool TryReadProcessImage(int processId, out string? imagePath, out DateTimeOffset startedAtUtc,
        out bool exited, out bool isProtectedSystemProcess)
    {
        imagePath = null;
        startedAtUtc = default;
        exited = false;
        isProtectedSystemProcess = false;
        if (!OperatingSystem.IsWindows() || processId <= 0) return false;
        using SafeProcessHandle handle = OpenProcess(QueryLimitedInformation, false, processId);
        if (handle.IsInvalid)
        {
            int err = Marshal.GetLastWin32Error();
            if (err is 87 or 1168) { exited = true; return false; }
            return false;
        }
        isProtectedSystemProcess = IsProtectedSystemHandle(handle);
        if (!GetProcessTimes(handle, out long created, out long exit, out _, out _) ||
            !GetExitCodeProcess(handle, out uint exitCode))
        {
            return false;
        }
        if (exit != 0 || exitCode != StillActive)
        {
            exited = true;
            return false;
        }
        startedAtUtc = DateTimeOffset.FromFileTime(created).ToUniversalTime();
        StringBuilder buffer = new(32768);
        int length = buffer.Capacity;
        if (!QueryFullProcessImageName(handle, 0, buffer, ref length) || length <= 0) return false;
        imagePath = buffer.ToString();
        return true;
    }

    private static bool ProbeProtectedSystemProcess(int processId)
    {
        if (!OperatingSystem.IsWindows() || processId <= 0) return false;
        using SafeProcessHandle probe = OpenProcess(QueryLimitedInformation, false, processId);
        return !probe.IsInvalid && IsProtectedSystemHandle(probe);
    }

    private static bool IsProtectedSystemHandle(SafeProcessHandle handle)
    {
        if (handle.IsInvalid || handle.IsClosed) return false;
        // 检查内核 PPL/Protected 标志位（PS_PROTECTION.Level != 0）
        if (NtQueryInformationProcess(handle, ProcessProtectionInformation, out byte protection, 1, out int ret) == 0 &&
            ret >= 1 && (protection & 0x07) != 0)
        {
            return true;
        }
        // 检查目标进程令牌是否运行于系统服务身份（SYSTEM / LocalService / NetworkService）
        if (OpenProcessToken(handle, 0x0008, out SafeAccessTokenHandle token))
        {
            using (token)
            {
                try
                {
                    using WindowsIdentity identity = new(token.DangerousGetHandle());
                    string? sid = identity.User?.Value;
                    if (sid is "S-1-5-18" or "S-1-5-19" or "S-1-5-20") return true;
                }
                catch { }
            }
        }
        return false;
    }

    private static PowerShellScriptHostSnapshot Win32Failure(int id, int error, bool isProtectedSystemProcess = false) =>
        new()
        {
            ProcessId = id,
            Status = error == 5 ? ScriptHostReadStatus.AccessDenied : error is 87 or 1168 ? ScriptHostReadStatus.Exited : ScriptHostReadStatus.Failed,
            Error = new Win32Exception(error).Message,
            IsProtectedSystemProcess = error == 5 && isProtectedSystemProcess
        };

    private static PowerShellScriptHostSnapshot Failure(int id, ScriptHostReadStatus status, string error) =>
        new() { ProcessId = id, Status = status, Error = error };

    [StructLayout(LayoutKind.Sequential)]
    private struct NativeUnicodeString { public ushort Length; public ushort MaximumLength; public IntPtr Buffer; }

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern SafeProcessHandle OpenProcess(uint desiredAccess, [MarshalAs(UnmanagedType.Bool)] bool inheritHandle, int processId);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern uint GetProcessId(SafeProcessHandle handle);
    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetProcessTimes(SafeProcessHandle handle, out long creation, out long exit, out long kernel, out long user);
    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetExitCodeProcess(SafeProcessHandle handle, out uint exitCode);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern uint WaitForSingleObject(SafeProcessHandle handle, uint milliseconds);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool QueryFullProcessImageName(SafeProcessHandle handle, int flags, StringBuilder image, ref int length);
    [DllImport("ntdll.dll")]
    private static extern int NtQueryInformationProcess(SafeProcessHandle handle, int informationClass, IntPtr information, int length, out int returnLength);
    [DllImport("ntdll.dll")]
    private static extern int NtQueryInformationProcess(SafeProcessHandle handle, int informationClass, out byte information, int length, out int returnLength);
    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool OpenProcessToken(SafeProcessHandle processHandle, uint desiredAccess, out SafeAccessTokenHandle tokenHandle);
}
