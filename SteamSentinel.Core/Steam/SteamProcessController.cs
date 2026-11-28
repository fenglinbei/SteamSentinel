using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;
using SteamSentinel.Core.Inspection;
using SteamSentinel.Core.Utilities;

namespace SteamSentinel.Core.Steam;

/// <summary>正在运行的 Steam 相关进程候选快照。</summary>
public sealed record SteamProcessCandidate(int Pid, string ProcessName, string? ImagePath);

/// <summary>Steam 进程安全关停结果。</summary>
public sealed record SteamProcessShutdownResult(
    bool HadRunningProcesses,
    bool GracefullyExited,
    int ForceTerminatedCount);

/// <summary>可注入的 Steam 进程查询、验签与关停环境抽象，便于安全单元测试与隔离模拟。</summary>
public interface ISteamProcessEnvironment
{
    /// <summary>枚举当前系统（或模拟环境）中的 Steam 候选进程。</summary>
    IReadOnlyList<SteamProcessCandidate> ListCandidateProcesses();

    /// <summary>校验指定路径可执行文件的 Authenticode 签名。</summary>
    SignatureResult VerifyExecutable(string path);

    /// <summary>向指定官方 steam.exe 发送优雅退出信号（-shutdown）。</summary>
    bool StartShutdown(string steamExePath);

    /// <summary>在复核映像路径与预期一致后强制终止指定 PID 的进程。</summary>
    bool TerminateProcess(int pid, string expectedImagePath);

    /// <summary>异步等待指定的轮询间隔。</summary>
    Task DelayAsync(TimeSpan delay, CancellationToken cancellationToken);
}

/// <summary>基于 Windows 受限查询句柄与映像路径复核的真实 Steam 进程环境实现。</summary>
public sealed class WindowsSteamProcessEnvironment : ISteamProcessEnvironment
{
    private const uint ProcessTerminate = 0x0001;
    private const uint ProcessQueryLimitedInformation = 0x1000;
    private const uint Synchronize = 0x00100000;
    private const int ErrorInvalidParameter = 87;
    private const int ErrorNotFound = 1168;
    private const int ErrorAccessDenied = 5;

    private static readonly HashSet<string> TargetProcessNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "steam",
        "steamwebhelper",
        "gameoverlayui",
        "gameoverlayui64",
        "steamerrorreporter",
        "steamerrorreporter64"
    };

    /// <inheritdoc />
    public IReadOnlyList<SteamProcessCandidate> ListCandidateProcesses()
    {
        if (!OperatingSystem.IsWindows())
        {
            return [];
        }

        int currentPid = Environment.ProcessId;
        Process[] processes = Process.GetProcesses();
        List<SteamProcessCandidate> candidates = [];

        foreach (Process process in processes)
        {
            try
            {
                int pid = process.Id;
                // 严格跳过当前进程自身与系统空闲/无效 PID。
                if (pid <= 0 || pid == currentPid)
                {
                    continue;
                }

                string processName = process.ProcessName;
                if (string.IsNullOrWhiteSpace(processName) || !TargetProcessNames.Contains(processName))
                {
                    continue;
                }

                if (!TryQueryProcessImage(pid, out string? imagePath, out bool exited))
                {
                    if (!exited)
                    {
                        candidates.Add(new SteamProcessCandidate(pid, processName, null));
                    }
                    continue;
                }

                candidates.Add(new SteamProcessCandidate(pid, processName, imagePath));
            }
            catch
            {
                // 个别进程在枚举过程中已退出或无法读取，忽略后继续枚举其余进程。
            }
            finally
            {
                process.Dispose();
            }
        }

        return candidates;
    }

    /// <inheritdoc />
    public SignatureResult VerifyExecutable(string path)
    {
        if (string.IsNullOrWhiteSpace(path) ||
            !ContentDiscovery.IsLocalSafePath(path) ||
            Validation.IsRedirectingReparsePoint(path))
        {
            return new SignatureResult(SignatureStatus.Error, "可执行文件路径不安全或包含重解析点。");
        }

        string fullPath = Path.GetFullPath(path);
        if (!File.Exists(fullPath))
        {
            return new SignatureResult(SignatureStatus.Error, "目标可执行文件不存在。");
        }

        try
        {
            // 使用只读共享锁打开文件并把同一文件句柄传给离线验签，避免 TOCTOU 替换风险。
            using FileStream stream = new(fullPath, FileMode.Open, FileAccess.Read, FileShare.Read);
            if (Validation.IsRedirectingReparseHandle(stream.SafeFileHandle))
            {
                return new SignatureResult(SignatureStatus.Error, "拒绝验证重定向重解析点句柄。");
            }

            return AuthenticodeVerifier.VerifyOffline(fullPath, stream.SafeFileHandle);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or Win32Exception)
        {
            return new SignatureResult(SignatureStatus.Error, $"读取目标可执行文件失败：{ex.Message}");
        }
    }

    /// <inheritdoc />
    public bool StartShutdown(string steamExePath)
    {
        if (!OperatingSystem.IsWindows() ||
            string.IsNullOrWhiteSpace(steamExePath) ||
            !ContentDiscovery.IsLocalSafePath(steamExePath) ||
            Validation.IsRedirectingReparsePoint(steamExePath))
        {
            return false;
        }

        string fullPath = Path.GetFullPath(steamExePath);
        if (!File.Exists(fullPath) ||
            !string.Equals(Path.GetFileName(fullPath), "steam.exe", StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        try
        {
            ProcessStartInfo startInfo = new(fullPath)
            {
                UseShellExecute = false,
                CreateNoWindow = true,
                WorkingDirectory = Path.GetDirectoryName(fullPath) ?? string.Empty
            };
            startInfo.ArgumentList.Add("-shutdown");

            using Process? process = Process.Start(startInfo);
            return process is not null;
        }
        catch (Exception ex) when (ex is Win32Exception or IOException or InvalidOperationException or UnauthorizedAccessException)
        {
            return false;
        }
    }

    /// <inheritdoc />
    public bool TerminateProcess(int pid, string expectedImagePath)
    {
        if (!OperatingSystem.IsWindows() || pid <= 0 || pid == Environment.ProcessId)
        {
            return false;
        }

        if (string.IsNullOrWhiteSpace(expectedImagePath) || !ContentDiscovery.IsLocalSafePath(expectedImagePath))
        {
            return false;
        }

        string expectedFull = NormalizeWin32Path(expectedImagePath);
        bool hasSynchronize = true;
        SafeProcessHandle handle = OpenProcess(ProcessTerminate | ProcessQueryLimitedInformation | Synchronize, false, pid);
        if (handle.IsInvalid && Marshal.GetLastWin32Error() == ErrorAccessDenied)
        {
            handle.Dispose();
            hasSynchronize = false;
            handle = OpenProcess(ProcessTerminate | ProcessQueryLimitedInformation, false, pid);
        }

        if (handle.IsInvalid)
        {
            handle.Dispose();
            return false;
        }

        using (handle)
        {
            if (GetProcessId(handle) != unchecked((uint)pid) || pid == Environment.ProcessId)
            {
                return false;
            }

            // 持有进程句柄期间校验退出状态与完整映像路径，防止 PID 复用导致误杀无关进程。
            if (!GetProcessTimes(handle, out _, out long exitTime, out _, out _) || exitTime != 0)
            {
                return false;
            }

            if (!TryQueryHandleImagePath(handle, out string? actualImage) || string.IsNullOrWhiteSpace(actualImage))
            {
                return false;
            }

            string actualFull = NormalizeWin32Path(actualImage);
            if (!string.Equals(actualFull, expectedFull, StringComparison.OrdinalIgnoreCase))
            {
                return false;
            }

            if (!NativeTerminateProcess(handle, 1))
            {
                return false;
            }

            if (hasSynchronize)
            {
                _ = WaitForSingleObject(handle, 2000);
            }

            return true;
        }
    }

    /// <inheritdoc />
    public Task DelayAsync(TimeSpan delay, CancellationToken cancellationToken) =>
        Task.Delay(delay, cancellationToken);

    private static bool TryQueryProcessImage(int pid, out string? imagePath, out bool exited)
    {
        imagePath = null;
        exited = false;

        using SafeProcessHandle handle = OpenProcess(ProcessQueryLimitedInformation, false, pid);
        if (handle.IsInvalid)
        {
            int error = Marshal.GetLastWin32Error();
            if (error is ErrorInvalidParameter or ErrorNotFound)
            {
                exited = true;
            }
            return false;
        }

        if (!GetProcessTimes(handle, out _, out long exitTime, out _, out _) || exitTime != 0)
        {
            exited = true;
            return false;
        }

        return TryQueryHandleImagePath(handle, out imagePath);
    }

    private static bool TryQueryHandleImagePath(SafeProcessHandle handle, out string? imagePath)
    {
        imagePath = null;
        StringBuilder buffer = new(4096);
        uint length = (uint)buffer.Capacity;
        if (!QueryFullProcessImageName(handle, 0, buffer, ref length))
        {
            int error = Marshal.GetLastWin32Error();
            if (error == 122 && length > buffer.Capacity && length <= 32768)
            {
                buffer = new StringBuilder((int)length + 1);
                length = (uint)buffer.Capacity;
                if (!QueryFullProcessImageName(handle, 0, buffer, ref length))
                {
                    return false;
                }
            }
            else
            {
                return false;
            }
        }

        if (length == 0)
        {
            return false;
        }

        imagePath = NormalizeWin32Path(buffer.ToString());
        return true;
    }

    private static string NormalizeWin32Path(string path)
    {
        string trimmed = path.StartsWith(@"\\?\", StringComparison.Ordinal) ? path[4..] : path;
        return Path.GetFullPath(trimmed);
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern SafeProcessHandle OpenProcess(
        uint desiredAccess,
        [MarshalAs(UnmanagedType.Bool)] bool inheritHandle,
        int processId);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern uint GetProcessId(SafeProcessHandle handle);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetProcessTimes(
        SafeProcessHandle handle,
        out long creation,
        out long exit,
        out long kernel,
        out long user);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, EntryPoint = "QueryFullProcessImageNameW", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool QueryFullProcessImageName(
        SafeProcessHandle process,
        uint flags,
        StringBuilder imageName,
        ref uint size);

    [DllImport("kernel32.dll", EntryPoint = "TerminateProcess", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool NativeTerminateProcess(SafeProcessHandle process, uint exitCode);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern uint WaitForSingleObject(SafeProcessHandle handle, uint milliseconds);
}

/// <summary>
/// 严格按 <see cref="SteamLayout.SteamRoots"/> 隔离并控制 Steam 客户端及子进程的优雅退出与精准终止。
/// </summary>
public sealed class SteamProcessController
{
    /// <summary>默认优雅退出等待超时（6 秒）。</summary>
    public static readonly TimeSpan DefaultGracefulTimeout = TimeSpan.FromSeconds(6);

    private static readonly TimeSpan PollInterval = TimeSpan.FromMilliseconds(200);

    private static readonly HashSet<string> AllowedProcessNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "steam",
        "steamwebhelper",
        "gameoverlayui",
        "gameoverlayui64",
        "steamerrorreporter",
        "steamerrorreporter64"
    };

    private readonly ISteamProcessEnvironment _environment;

    /// <summary>使用真实 Windows 进程环境初始化控制器。</summary>
    public SteamProcessController() : this(new WindowsSteamProcessEnvironment())
    {
    }

    /// <summary>使用自定义或模拟进程环境初始化控制器。</summary>
    public SteamProcessController(ISteamProcessEnvironment environment)
    {
        _environment = environment ?? throw new ArgumentNullException(nameof(environment));
    }

    /// <summary>支持识别与控制的 Steam 进程名白名单（不含 .exe，不区分大小写）。</summary>
    public static IReadOnlySet<string> TargetProcessNames => AllowedProcessNames;

    /// <summary>查找映像位于 <paramref name="layout"/> 安全 Steam 根目录下的所有正在运行的 Steam 目标进程。</summary>
    public IReadOnlyList<SteamProcessCandidate> FindRunningProcesses(SteamLayout layout)
    {
        ArgumentNullException.ThrowIfNull(layout);

        string[] safeRoots = ExtractSafeRoots(layout);
        if (safeRoots.Length == 0)
        {
            return [];
        }

        IReadOnlyList<SteamProcessCandidate> candidates = _environment.ListCandidateProcesses();
        if (candidates.Count == 0)
        {
            return [];
        }

        int currentPid = Environment.ProcessId;
        HashSet<int> seenPids = [];
        List<SteamProcessCandidate> matched = [];

        foreach (SteamProcessCandidate candidate in candidates)
        {
            if (candidate.Pid <= 0 || candidate.Pid == currentPid)
            {
                continue;
            }

            if (string.IsNullOrWhiteSpace(candidate.ProcessName) ||
                !AllowedProcessNames.Contains(candidate.ProcessName))
            {
                continue;
            }

            if (string.IsNullOrWhiteSpace(candidate.ImagePath) ||
                !ContentDiscovery.IsLocalSafePath(candidate.ImagePath))
            {
                continue;
            }

            string normalizedImage;
            try
            {
                normalizedImage = Path.GetFullPath(candidate.ImagePath);
            }
            catch (Exception ex) when (ex is ArgumentException or NotSupportedException or PathTooLongException)
            {
                continue;
            }

            if (!string.Equals(Path.GetExtension(normalizedImage), ".exe", StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            string imageProcessName = Path.GetFileNameWithoutExtension(normalizedImage);
            if (!AllowedProcessNames.Contains(imageProcessName) ||
                !string.Equals(imageProcessName, candidate.ProcessName, StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            if (!IsStrictlyWithinAnyRoot(normalizedImage, safeRoots))
            {
                continue;
            }

            if (seenPids.Add(candidate.Pid))
            {
                matched.Add(new SteamProcessCandidate(candidate.Pid, candidate.ProcessName, normalizedImage));
            }
        }

        return matched;
    }

    /// <summary>检查 <paramref name="layout"/> 安全 Steam 根目录下是否存在正在运行的 Steam 相关进程。</summary>
    public bool IsAnyRunning(SteamLayout layout) => FindRunningProcesses(layout).Count > 0;

    /// <summary>
    /// 确保 <paramref name="layout"/> 中所有安全 Steam 根目录下的目标进程全部退出。
    /// 先尝试向合法 Valve 签名的 steam.exe 发送 -shutdown 并等待；若超时或缺失/不可信，则精准强杀并二次核实。
    /// </summary>
    public async Task<SteamProcessShutdownResult> EnsureClosedAsync(
        SteamLayout layout,
        TimeSpan? gracefulTimeout = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(layout);
        TimeSpan timeout = gracefulTimeout ?? DefaultGracefulTimeout;
        if (timeout < TimeSpan.Zero)
        {
            throw new ArgumentOutOfRangeException(nameof(gracefulTimeout), "优雅等待超时时间不能为负数。");
        }

        cancellationToken.ThrowIfCancellationRequested();

        IReadOnlyList<SteamProcessCandidate> initial = FindRunningProcesses(layout);
        if (initial.Count == 0)
        {
            return new SteamProcessShutdownResult(
                HadRunningProcesses: false,
                GracefullyExited: true,
                ForceTerminatedCount: 0);
        }

        string[] safeRoots = ExtractSafeRoots(layout);
        bool shutdownDispatched = TryDispatchGracefulShutdown(initial, safeRoots);

        if (shutdownDispatched)
        {
            TimeSpan elapsed = TimeSpan.Zero;
            Stopwatch wallClock = Stopwatch.StartNew();

            while (true)
            {
                cancellationToken.ThrowIfCancellationRequested();
                IReadOnlyList<SteamProcessCandidate> current = FindRunningProcesses(layout);
                if (current.Count == 0)
                {
                    return new SteamProcessShutdownResult(
                        HadRunningProcesses: true,
                        GracefullyExited: true,
                        ForceTerminatedCount: 0);
                }

                TimeSpan effectiveElapsed = wallClock.Elapsed > elapsed ? wallClock.Elapsed : elapsed;
                if (effectiveElapsed >= timeout)
                {
                    break;
                }

                TimeSpan remaining = timeout - effectiveElapsed;
                TimeSpan step = remaining < PollInterval ? remaining : PollInterval;
                if (step <= TimeSpan.Zero)
                {
                    break;
                }

                await _environment.DelayAsync(step, cancellationToken).ConfigureAwait(false);
                elapsed += step;
            }
        }

        IReadOnlyList<SteamProcessCandidate> remainingProcesses = FindRunningProcesses(layout);
        if (remainingProcesses.Count == 0)
        {
            return new SteamProcessShutdownResult(
                HadRunningProcesses: true,
                GracefullyExited: shutdownDispatched,
                ForceTerminatedCount: 0);
        }

        int forceTerminatedCount = 0;
        foreach (SteamProcessCandidate candidate in remainingProcesses)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (string.IsNullOrWhiteSpace(candidate.ImagePath))
            {
                continue;
            }

            if (_environment.TerminateProcess(candidate.Pid, candidate.ImagePath))
            {
                forceTerminatedCount++;
            }
        }

        // 二次核实目标目录下确实已无任何 Steam 相关残留进程。
        IReadOnlyList<SteamProcessCandidate> stubborn = FindRunningProcesses(layout);
        if (stubborn.Count > 0)
        {
            string summary = string.Join("，", stubborn.Select(item => $"{item.ProcessName}(PID={item.Pid})"));
            throw new InvalidOperationException($"未能完全结束目标 Steam 目录下的残留进程：{summary}。");
        }

        return new SteamProcessShutdownResult(
            HadRunningProcesses: true,
            GracefullyExited: shutdownDispatched && forceTerminatedCount == 0,
            ForceTerminatedCount: forceTerminatedCount);
    }

    private bool TryDispatchGracefulShutdown(IReadOnlyList<SteamProcessCandidate> running, string[] safeRoots)
    {
        bool dispatched = false;
        foreach (string root in safeRoots)
        {
            bool rootHasRunning = running.Any(candidate =>
                candidate.ImagePath is not null && IsStrictlyWithinRoot(candidate.ImagePath, root));
            if (!rootHasRunning)
            {
                continue;
            }

            string steamExe = Path.Combine(root, "steam.exe");
            if (!ContentDiscovery.IsLocalSafePath(steamExe) || Validation.IsRedirectingReparsePoint(steamExe))
            {
                continue;
            }

            SignatureResult signature = _environment.VerifyExecutable(steamExe);
            bool trustedValve = signature.Status == SignatureStatus.Valid &&
                (signature.IsValveSigner || AuthenticodeVerifier.IsTrustedValveSigner(signature.Status, signature.SignerSubject));
            if (!trustedValve)
            {
                continue;
            }

            if (_environment.StartShutdown(steamExe))
            {
                dispatched = true;
            }
        }

        return dispatched;
    }

    private static string[] ExtractSafeRoots(SteamLayout layout)
    {
        List<string> roots = [];
        HashSet<string> seen = new(StringComparer.OrdinalIgnoreCase);

        foreach (string rawRoot in layout.SteamRoots)
        {
            if (string.IsNullOrWhiteSpace(rawRoot) ||
                !ContentDiscovery.IsLocalSafePath(rawRoot) ||
                !Validation.IsSafeExactTarget(rawRoot))
            {
                continue;
            }

            try
            {
                string normalized = Path.TrimEndingDirectorySeparator(Path.GetFullPath(rawRoot));
                if (seen.Add(normalized))
                {
                    roots.Add(normalized);
                }
            }
            catch (Exception ex) when (ex is ArgumentException or NotSupportedException or PathTooLongException)
            {
                // 忽略格式异常的根目录路径。
            }
        }

        return roots.ToArray();
    }

    private static bool IsStrictlyWithinAnyRoot(string fullImagePath, string[] safeRoots)
    {
        foreach (string root in safeRoots)
        {
            if (IsStrictlyWithinRoot(fullImagePath, root))
            {
                return true;
            }
        }

        return false;
    }

    private static bool IsStrictlyWithinRoot(string fullImagePath, string normalizedRoot) =>
        !string.Equals(fullImagePath, normalizedRoot, StringComparison.OrdinalIgnoreCase) &&
        ContentDiscovery.IsWithin(fullImagePath, normalizedRoot);
}
