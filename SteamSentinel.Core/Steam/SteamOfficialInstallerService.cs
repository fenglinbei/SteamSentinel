using System.Buffers;
using System.ComponentModel;
using System.Diagnostics;
using System.Net;
using System.Net.Http;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Principal;
using System.Text;
using Microsoft.Win32.SafeHandles;
using SteamSentinel.Core.Inspection;
using SteamSentinel.Core.Utilities;

namespace SteamSentinel.Core.Steam;

/// <summary>官方安装器内嵌时间戳及时间戳证书链校验结果。</summary>
public sealed record InstallerTimestampResult(
    bool IsValid,
    string Detail,
    DateTimeOffset? TimestampUtc = null,
    string? SignerSubject = null);

/// <summary>已通过安全下载、独占锁验签与时间戳校验的临时官方安装器包。</summary>
public sealed record DownloadedSteamInstaller(
    string InstallerDirectory,
    string InstallerPath,
    string SourceUrl,
    long FileSizeBytes,
    string Sha256,
    SignatureResult Signature,
    InstallerTimestampResult Timestamp) : IDisposable
{
    private int _disposed;

    /// <summary>彻底删除独立临时安装包目录。</summary>
    public void Dispose()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0)
        {
            return;
        }

        SteamOfficialInstallerService.CleanupTemporaryDirectory(InstallerDirectory);
    }
}

/// <summary>调用官方安装器执行覆盖修复的请求参数。</summary>
public sealed record SteamInstallerExecutionRequest(
    string InstallerPath,
    string TargetSteamRoot,
    string Arguments);

/// <summary>官方安装器执行结果。</summary>
public sealed record SteamInstallerExecutionResult(int ExitCode, string? Detail = null);

/// <summary>官方安装器一键修复实时阶段通知。</summary>
public enum SteamOfficialRepairStage
{
    DownloadingInstaller,
    VerifyingSignature,
    ClosingSteam,
    RunningInstaller
}

/// <summary>官方安装器覆盖修复完整闭环结果。</summary>
public sealed record SteamOfficialRepairResult(
    bool Succeeded,
    string TargetSteamRoot,
    string SourceUrl,
    string InstallerSha256,
    SteamProcessShutdownResult ShutdownResult,
    int InstallerExitCode,
    string Detail);

/// <summary>安全拉起本地正版 steam.exe 的最终状态。</summary>
public enum SteamClientLaunchStatus
{
    LaunchedDirect,
    LaunchedDeElevated,
    RefusedInvalidPath,
    RefusedUntrustedSignature,
    RefusedElevatedWithoutStandardToken,
    LaunchFailed
}

/// <summary>本地正版 steam.exe 启动请求上下文。</summary>
public sealed record SteamClientLaunchRequest(
    string ExecutablePath,
    string WorkingDirectory,
    IReadOnlyList<string> Arguments,
    bool DeElevated);

/// <summary>本地正版 steam.exe 安全拉起结果。</summary>
public sealed record SteamClientLaunchResult(
    SteamClientLaunchStatus Status,
    bool Launched,
    bool UsedDeElevation,
    int? ProcessId,
    SignatureResult? Signature,
    string Message);

/// <summary>本地 steam.exe 启动与降权抽象，便于测试提权拒绝与交互式 Shell 令牌降权分支。</summary>
public interface ISteamClientProcessLauncher
{
    /// <summary>判断当前进程是否处于管理员高权限状态。</summary>
    bool IsCurrentProcessElevated();

    /// <summary>在普通权限下直接启动已验签的 steam.exe。</summary>
    bool TryLaunchDirect(SteamClientLaunchRequest request, out int? processId, out string? errorMessage);

    /// <summary>在提权管理员状态下尝试通过交互式桌面 Shell 的普通权限令牌降权启动 steam.exe。</summary>
    bool TryLaunchDeElevated(SteamClientLaunchRequest request, out int? processId, out string? errorMessage);
}

/// <summary>基于委托的可测试启动适配器，便于自测快速注入模拟状态。</summary>
public sealed class DelegateSteamClientProcessLauncher : ISteamClientProcessLauncher
{
    private readonly Func<bool> _isElevated;
    private readonly Func<SteamClientLaunchRequest, (bool Succeeded, int? ProcessId, string? Error)> _direct;
    private readonly Func<SteamClientLaunchRequest, (bool Succeeded, int? ProcessId, string? Error)> _deElevated;

    /// <summary>构造基于委托的启动器。</summary>
    public DelegateSteamClientProcessLauncher(
        Func<bool> isElevated,
        Func<SteamClientLaunchRequest, (bool Succeeded, int? ProcessId, string? Error)> direct,
        Func<SteamClientLaunchRequest, (bool Succeeded, int? ProcessId, string? Error)> deElevated)
    {
        _isElevated = isElevated ?? throw new ArgumentNullException(nameof(isElevated));
        _direct = direct ?? throw new ArgumentNullException(nameof(direct));
        _deElevated = deElevated ?? throw new ArgumentNullException(nameof(deElevated));
    }

    /// <inheritdoc />
    public bool IsCurrentProcessElevated() => _isElevated();

    /// <inheritdoc />
    public bool TryLaunchDirect(SteamClientLaunchRequest request, out int? processId, out string? errorMessage)
    {
        (bool succeeded, int? pid, string? error) = _direct(request);
        processId = pid;
        errorMessage = error;
        return succeeded;
    }

    /// <inheritdoc />
    public bool TryLaunchDeElevated(SteamClientLaunchRequest request, out int? processId, out string? errorMessage)
    {
        (bool succeeded, int? pid, string? error) = _deElevated(request);
        processId = pid;
        errorMessage = error;
        return succeeded;
    }
}

/// <summary>Windows 真实环境下本地 steam.exe 的安全启动与交互式 Shell 降权实现。</summary>
public sealed class WindowsSteamClientProcessLauncher : ISteamClientProcessLauncher
{
    private const uint ProcessQueryLimitedInformation = 0x1000;
    private const uint TokenDuplicate = 0x0002;
    private const uint TokenQuery = 0x0008;
    private const uint TokenAssignPrimary = 0x0001;
    private const uint TokenAdjustDefault = 0x0080;
    private const uint TokenAdjustSessionId = 0x0100;
    private const int TokenElevationClass = 20;
    private const int SecurityImpersonationLevel = 2;
    private const int TokenTypePrimary = 1;
    private const uint StartfUseShowWindow = 0x00000001;
    private const ushort SwShowNormal = 1;

    /// <inheritdoc />
    public bool IsCurrentProcessElevated()
    {
        if (!OperatingSystem.IsWindows())
        {
            return false;
        }

        using WindowsIdentity identity = WindowsIdentity.GetCurrent();
        if (new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator))
        {
            return true;
        }

        if (GetTokenInformation(identity.AccessToken, TokenElevationClass, out int elevated, sizeof(int), out _) &&
            elevated != 0)
        {
            return true;
        }

        return ProcessIntegrity.GetCurrent() >= ProcessIntegrityLevel.High;
    }

    /// <inheritdoc />
    public bool TryLaunchDirect(SteamClientLaunchRequest request, out int? processId, out string? errorMessage)
    {
        processId = null;
        errorMessage = null;

        try
        {
            ProcessStartInfo startInfo = new(request.ExecutablePath)
            {
                UseShellExecute = false,
                WorkingDirectory = request.WorkingDirectory
            };
            foreach (string argument in request.Arguments)
            {
                startInfo.ArgumentList.Add(argument);
            }

            using Process? process = Process.Start(startInfo);
            if (process is null)
            {
                errorMessage = "系统未返回已启动的 steam.exe 进程句柄。";
                return false;
            }

            processId = process.Id;
            return true;
        }
        catch (Exception ex) when (ex is Win32Exception or IOException or InvalidOperationException or UnauthorizedAccessException)
        {
            errorMessage = ex.Message;
            return false;
        }
    }

    /// <inheritdoc />
    public bool TryLaunchDeElevated(SteamClientLaunchRequest request, out int? processId, out string? errorMessage)
    {
        processId = null;
        errorMessage = null;

        if (!OperatingSystem.IsWindows())
        {
            errorMessage = "当前平台不支持交互式 Shell 令牌降权启动。";
            return false;
        }

        IntPtr shellWindow = GetShellWindow();
        if (shellWindow == IntPtr.Zero || GetWindowThreadProcessId(shellWindow, out uint shellPid) == 0 || shellPid == 0)
        {
            errorMessage = "未找到活动的桌面 Shell 窗口，无法获取普通权限交互式令牌。";
            return false;
        }

        using SafeProcessHandle shellProcess = OpenProcess(ProcessQueryLimitedInformation, false, shellPid);
        if (shellProcess.IsInvalid)
        {
            errorMessage = $"无法查询桌面 Shell 进程（Win32={Marshal.GetLastWin32Error()}）。";
            return false;
        }

        if (!IsTrustedExplorerShellProcess(shellProcess))
        {
            errorMessage = "当前桌面 Shell 窗口所属进程不是受信任的系统 explorer.exe。";
            return false;
        }

        if (!OpenProcessToken(shellProcess, TokenDuplicate | TokenQuery, out SafeAccessTokenHandle shellToken))
        {
            errorMessage = $"无法打开桌面 Shell 进程令牌（Win32={Marshal.GetLastWin32Error()}）。";
            return false;
        }

        using (shellToken)
        {
            if (!IsSafeStandardUserToken(shellToken, out string? tokenReason))
            {
                errorMessage = tokenReason ?? "桌面 Shell 令牌不是同用户的普通权限令牌。";
                return false;
            }

            uint desiredAccess = TokenAssignPrimary | TokenDuplicate | TokenQuery | TokenAdjustDefault | TokenAdjustSessionId;
            if (!DuplicateTokenEx(
                    shellToken,
                    desiredAccess,
                    IntPtr.Zero,
                    SecurityImpersonationLevel,
                    TokenTypePrimary,
                    out SafeAccessTokenHandle primaryToken))
            {
                errorMessage = $"复制桌面 Shell 主令牌失败（Win32={Marshal.GetLastWin32Error()}）。";
                return false;
            }

            using (primaryToken)
            {
                StringBuilder commandLine = BuildCommandLine(request.ExecutablePath, request.Arguments);
                StartupInfo startupInfo = new()
                {
                    Size = Marshal.SizeOf<StartupInfo>(),
                    Flags = StartfUseShowWindow,
                    ShowWindow = SwShowNormal
                };

                if (!CreateProcessWithTokenW(
                        primaryToken,
                        0,
                        request.ExecutablePath,
                        commandLine,
                        0,
                        IntPtr.Zero,
                        request.WorkingDirectory,
                        ref startupInfo,
                        out ProcessInformation processInfo))
                {
                    errorMessage = $"降权启动 steam.exe 失败：{new Win32Exception(Marshal.GetLastWin32Error()).Message}";
                    return false;
                }

                try
                {
                    processId = unchecked((int)processInfo.ProcessId);
                    return true;
                }
                finally
                {
                    if (processInfo.Thread != IntPtr.Zero)
                    {
                        _ = CloseHandle(processInfo.Thread);
                    }
                    if (processInfo.Process != IntPtr.Zero)
                    {
                        _ = CloseHandle(processInfo.Process);
                    }
                }
            }
        }
    }

    private static bool IsTrustedExplorerShellProcess(SafeProcessHandle shellProcess)
    {
        StringBuilder buffer = new(4096);
        uint length = (uint)buffer.Capacity;
        if (!QueryFullProcessImageName(shellProcess, 0, buffer, ref length) || length == 0)
        {
            return false;
        }

        string expectedExplorer = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.Windows),
            "explorer.exe");
        return string.Equals(Path.GetFullPath(buffer.ToString()), Path.GetFullPath(expectedExplorer), StringComparison.OrdinalIgnoreCase);
    }

    private static bool IsSafeStandardUserToken(SafeAccessTokenHandle candidateToken, out string? reason)
    {
        reason = null;

        using WindowsIdentity currentUser = WindowsIdentity.GetCurrent();
        using WindowsIdentity candidateIdentity = new(candidateToken.DangerousGetHandle());
        if (currentUser.User is null || candidateIdentity.User is null ||
            !currentUser.User.Equals(candidateIdentity.User))
        {
            reason = "桌面 Shell 令牌所属用户 SID 与当前用户不一致。";
            return false;
        }

        if (new WindowsPrincipal(candidateIdentity).IsInRole(WindowsBuiltInRole.Administrator))
        {
            reason = "桌面 Shell 令牌仍包含管理员特权，拒绝用于降权启动。";
            return false;
        }

        if (!GetTokenInformation(candidateToken, TokenElevationClass, out int tokenElevated, sizeof(int), out _) ||
            tokenElevated != 0)
        {
            reason = "桌面 Shell 令牌处于提权状态，找不到普通权限令牌。";
            return false;
        }

        ProcessIntegrityLevel integrity = ReadTokenIntegrityLevel(candidateToken);
        if (integrity != ProcessIntegrityLevel.Medium)
        {
            reason = $"桌面 Shell 令牌完整性级别为 {integrity}，要求 Medium 普通用户权限。";
            return false;
        }

        return true;
    }

    private static ProcessIntegrityLevel ReadTokenIntegrityLevel(SafeAccessTokenHandle token)
    {
        const int TokenIntegrityLevelClass = 25;
        _ = GetTokenInformation(token, TokenIntegrityLevelClass, IntPtr.Zero, 0, out int size);
        if (size <= 0)
        {
            return ProcessIntegrityLevel.Unknown;
        }

        IntPtr buffer = Marshal.AllocHGlobal(size);
        try
        {
            if (!GetTokenInformation(token, TokenIntegrityLevelClass, buffer, size, out _))
            {
                return ProcessIntegrityLevel.Unknown;
            }

            TokenMandatoryLabel label = Marshal.PtrToStructure<TokenMandatoryLabel>(buffer);
            if (label.Label.Sid == IntPtr.Zero)
            {
                return ProcessIntegrityLevel.Unknown;
            }

            SecurityIdentifier sid = new(label.Label.Sid);
            int rid = int.Parse(sid.Value.Split('-')[^1], System.Globalization.CultureInfo.InvariantCulture);
            return rid switch
            {
                < 0x1000 => ProcessIntegrityLevel.Untrusted,
                < 0x2000 => ProcessIntegrityLevel.Low,
                < 0x3000 => ProcessIntegrityLevel.Medium,
                < 0x4000 => ProcessIntegrityLevel.High,
                _ => ProcessIntegrityLevel.System
            };
        }
        catch
        {
            return ProcessIntegrityLevel.Unknown;
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }

    private static StringBuilder BuildCommandLine(string executablePath, IReadOnlyList<string> arguments)
    {
        StringBuilder builder = new();
        builder.Append('"').Append(executablePath).Append('"');
        foreach (string arg in arguments)
        {
            builder.Append(' ');
            if (arg.Length == 0 || arg.Any(ch => char.IsWhiteSpace(ch) || ch == '"'))
            {
                builder.Append('"');
                int backslashes = 0;
                foreach (char ch in arg)
                {
                    if (ch == '\\')
                    {
                        backslashes++;
                        continue;
                    }
                    if (ch == '"')
                    {
                        builder.Append('\\', backslashes * 2 + 1).Append('"');
                        backslashes = 0;
                        continue;
                    }
                    if (backslashes > 0)
                    {
                        builder.Append('\\', backslashes);
                        backslashes = 0;
                    }
                    builder.Append(ch);
                }
                if (backslashes > 0)
                {
                    builder.Append('\\', backslashes * 2);
                }
                builder.Append('"');
            }
            else
            {
                builder.Append(arg);
            }
        }
        return builder;
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

    [DllImport("user32.dll")]
    private static extern IntPtr GetShellWindow();

    [DllImport("user32.dll", SetLastError = true)]
    private static extern uint GetWindowThreadProcessId(IntPtr window, out uint processId);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern SafeProcessHandle OpenProcess(
        uint desiredAccess,
        [MarshalAs(UnmanagedType.Bool)] bool inheritHandle,
        uint processId);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, EntryPoint = "QueryFullProcessImageNameW", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool QueryFullProcessImageName(
        SafeProcessHandle process,
        uint flags,
        StringBuilder imageName,
        ref uint size);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool OpenProcessToken(
        SafeProcessHandle processHandle,
        uint desiredAccess,
        out SafeAccessTokenHandle tokenHandle);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetTokenInformation(
        SafeAccessTokenHandle tokenHandle,
        int tokenInformationClass,
        out int tokenInformation,
        int tokenInformationLength,
        out int returnLength);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetTokenInformation(
        SafeAccessTokenHandle tokenHandle,
        int tokenInformationClass,
        IntPtr tokenInformation,
        int tokenInformationLength,
        out int returnLength);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool DuplicateTokenEx(
        SafeAccessTokenHandle existingToken,
        uint desiredAccess,
        IntPtr tokenAttributes,
        int impersonationLevel,
        int tokenType,
        out SafeAccessTokenHandle newToken);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CreateProcessWithTokenW(
        SafeAccessTokenHandle token,
        uint logonFlags,
        string? applicationName,
        StringBuilder? commandLine,
        uint creationFlags,
        IntPtr environment,
        string? currentDirectory,
        ref StartupInfo startupInfo,
        out ProcessInformation processInformation);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseHandle(IntPtr handle);
}

/// <summary>
/// 提供 Steam 官方 SteamSetup.exe 受控下载、句柄锁强验签、覆盖修复与本地正版 steam.exe 安全拉起能力。
/// </summary>
public sealed class SteamOfficialInstallerService
{
    /// <summary>官方安装器主 CDN HTTPS 地址。</summary>
    public const string PrimaryInstallerUrl = "https://cdn.akamai.steamstatic.com/client/installer/SteamSetup.exe";

    /// <summary>官方安装器备用 CDN HTTPS 地址。</summary>
    public const string FallbackInstallerUrl = "https://steamcdn-a.akamaihd.net/client/installer/SteamSetup.exe";

    /// <summary>官方安装器允许的最大体积上限（16 MiB）。</summary>
    public const long MaximumInstallerBytes = 16L * 1024 * 1024;

    /// <summary>每个官方案例地址最多允许跟进的重定向次数。</summary>
    public const int MaximumRedirectsPerEndpoint = 1;

    private const string TimeStampingEkuOid = "1.3.6.1.5.5.7.3.8";
    private const uint SgnrTypeTimestamp = 0x00000010;
    private static readonly Guid GenericVerifyV2 = new("00AAC56B-CD44-11D0-8CC2-00C04FC295EE");

    private static readonly HashSet<string> AllowedHosts = new(StringComparer.OrdinalIgnoreCase)
    {
        "cdn.akamai.steamstatic.com",
        "steamcdn-a.akamaihd.net"
    };

    private readonly SteamProcessController _processController;
    private readonly HttpMessageHandler? _httpMessageHandler;
    private readonly Func<string, SafeFileHandle, SignatureResult> _verifySignature;
    private readonly Func<string, SafeFileHandle, InstallerTimestampResult> _verifyTimestamp;
    private readonly Func<SteamInstallerExecutionRequest, CancellationToken, Task<SteamInstallerExecutionResult>> _runInstaller;
    private readonly ISteamClientProcessLauncher _clientLauncher;
    private readonly string? _temporaryRootOverride;

    /// <summary>初始化官方安装器与本地客户端启动服务（支持注入测试桩）。</summary>
    public SteamOfficialInstallerService(
        SteamProcessController? processController = null,
        HttpMessageHandler? httpMessageHandler = null,
        Func<string, SafeFileHandle, SignatureResult>? verifySignature = null,
        Func<string, SafeFileHandle, InstallerTimestampResult>? verifyTimestamp = null,
        Func<SteamInstallerExecutionRequest, CancellationToken, Task<SteamInstallerExecutionResult>>? runInstaller = null,
        ISteamClientProcessLauncher? clientLauncher = null,
        string? temporaryRoot = null)
    {
        _processController = processController ?? new SteamProcessController();
        _httpMessageHandler = httpMessageHandler;
        _verifySignature = verifySignature ?? ((path, handle) => AuthenticodeVerifier.VerifyOffline(path, handle));
        _verifyTimestamp = verifyTimestamp ?? VerifyEmbeddedTimestampOffline;
        _runInstaller = runInstaller ?? ExecuteInstallerProcessAsync;
        _clientLauncher = clientLauncher ?? new WindowsSteamClientProcessLauncher();
        _temporaryRootOverride = temporaryRoot;
    }

    /// <summary>从固定官方 HTTPS 地址受控下载 SteamSetup.exe，并以独占读锁完成防 TOCTOU 验签与时间戳证书校验。</summary>
    public async Task<DownloadedSteamInstaller> DownloadAndVerifyInstallerAsync(
        CancellationToken cancellationToken = default,
        IProgress<(long BytesRead, long? TotalBytes)>? downloadProgress = null,
        IProgress<SteamOfficialRepairStage>? stageProgress = null)
    {
        string installerDir = CreateIsolatedInstallerDirectory();
        string installerPath = Path.Combine(installerDir, "SteamSetup.exe");

        try
        {
            stageProgress?.Report(SteamOfficialRepairStage.DownloadingInstaller);
            (string sourceUrl, long fileSize) = await DownloadWithFallbackAsync(
                installerPath,
                cancellationToken,
                downloadProgress).ConfigureAwait(false);

            stageProgress?.Report(SteamOfficialRepairStage.VerifyingSignature);
            string sha256;
            SignatureResult signatureResult;
            InstallerTimestampResult timestampResult;

            // 重新以 FileShare.Read 独占读共享锁打开，防止下载完成后到验签之间被篡改（TOCTOU）。
            await using (FileStream verifyStream = new(
                installerPath,
                FileMode.Open,
                FileAccess.Read,
                FileShare.Read,
                bufferSize: 4096,
                FileOptions.SequentialScan))
            {
                ValidateLockedFileHandle(verifyStream.SafeFileHandle, installerPath);
                sha256 = await Hashing.Sha256StreamAsync(
                    verifyStream,
                    cancellationToken,
                    maximumBytes: MaximumInstallerBytes).ConfigureAwait(false);
                verifyStream.Position = 0;

                signatureResult = _verifySignature(installerPath, verifyStream.SafeFileHandle);
                timestampResult = _verifyTimestamp(installerPath, verifyStream.SafeFileHandle);
            }

            bool trustedValve = signatureResult.Status == SignatureStatus.Valid &&
                (signatureResult.IsValveSigner ||
                 AuthenticodeVerifier.IsTrustedValveSigner(signatureResult.Status, signatureResult.SignerSubject));
            if (!trustedValve)
            {
                CleanupTemporaryDirectory(installerDir);
                throw new SecurityException(
                    $"官方安装器签名校验失败：Status={signatureResult.Status}，Signer={signatureResult.SignerSubject ?? "<none>"}，Detail={signatureResult.Detail}");
            }

            if (!timestampResult.IsValid)
            {
                CleanupTemporaryDirectory(installerDir);
                throw new SecurityException($"官方安装器内嵌时间戳证书校验失败：{timestampResult.Detail}");
            }

            return new DownloadedSteamInstaller(
                installerDir,
                installerPath,
                sourceUrl,
                fileSize,
                sha256,
                signatureResult,
                timestampResult);
        }
        catch
        {
            CleanupTemporaryDirectory(installerDir);
            throw;
        }
    }

    /// <summary>
    /// 下载并强验签官方 SteamSetup.exe，随后关停目标 Steam 根目录进程并执行覆盖修复（保留 steamapps 游戏库），完成后彻底清理临时安装包目录。
    /// </summary>
    public async Task<SteamOfficialRepairResult> RunOfficialRepairAsync(
        string targetSteamRoot,
        SteamLayout layout,
        TimeSpan? gracefulShutdownTimeout = null,
        CancellationToken cancellationToken = default,
        IProgress<(long BytesRead, long? TotalBytes)>? downloadProgress = null,
        IProgress<SteamOfficialRepairStage>? stageProgress = null)
    {
        ArgumentNullException.ThrowIfNull(layout);
        string normalizedTargetRoot = ValidateTargetSteamRoot(targetSteamRoot);

        using DownloadedSteamInstaller downloaded = await DownloadAndVerifyInstallerAsync(
            cancellationToken,
            downloadProgress,
            stageProgress).ConfigureAwait(false);

        // 仅针对目标 Steam 根目录关停进程，避免误触其他无关安装目录。
        stageProgress?.Report(SteamOfficialRepairStage.ClosingSteam);
        SteamLayout scopedLayout = new();
        scopedLayout.SteamRoots.Add(normalizedTargetRoot);
        SteamProcessShutdownResult shutdownResult = await _processController.EnsureClosedAsync(
            scopedLayout,
            gracefulShutdownTimeout,
            cancellationToken).ConfigureAwait(false);

        stageProgress?.Report(SteamOfficialRepairStage.RunningInstaller);
        string arguments = $"/S /D={normalizedTargetRoot}";
        SteamInstallerExecutionRequest request = new(downloaded.InstallerPath, normalizedTargetRoot, arguments);
        SteamInstallerExecutionResult execResult = await _runInstaller(request, cancellationToken).ConfigureAwait(false);

        bool succeeded = execResult.ExitCode == 0;
        string detail = succeeded
            ? $"官方安装器覆盖修复完成（来源：{downloaded.SourceUrl}，退出码：0）。"
            : $"官方安装器执行返回非零退出码 {execResult.ExitCode}：{execResult.Detail ?? "未知错误"}";

        return new SteamOfficialRepairResult(
            succeeded,
            normalizedTargetRoot,
            downloaded.SourceUrl,
            downloaded.Sha256,
            shutdownResult,
            execResult.ExitCode,
            detail);
    }

    /// <summary>
    /// 校验本地 <paramref name="steamRoot"/>\steam.exe 路径安全与 Valve 官方签名，并在普通权限或降权 Shell 令牌下安全拉起 Steam。
    /// </summary>
    public SteamClientLaunchResult LaunchVerifiedSteam(string steamRoot, IReadOnlyList<string>? arguments = null)
    {
        if (string.IsNullOrWhiteSpace(steamRoot) ||
            !ContentDiscovery.IsLocalSafePath(steamRoot) ||
            !Validation.IsSafeExactTarget(steamRoot))
        {
            return new SteamClientLaunchResult(
                SteamClientLaunchStatus.RefusedInvalidPath,
                false,
                false,
                null,
                null,
                "Steam 根目录路径无效或不满足安全本地路径要求。");
        }

        string normalizedRoot = Path.TrimEndingDirectorySeparator(Path.GetFullPath(steamRoot));
        if (!Directory.Exists(normalizedRoot) || Validation.ContainsReparsePoint(normalizedRoot))
        {
            return new SteamClientLaunchResult(
                SteamClientLaunchStatus.RefusedInvalidPath,
                false,
                false,
                null,
                null,
                "Steam 根目录不存在或包含不安全的重解析点。");
        }

        string steamExePath = Path.Combine(normalizedRoot, "steam.exe");
        if (!ContentDiscovery.IsLocalSafePath(steamExePath) ||
            !File.Exists(steamExePath) ||
            Validation.IsRedirectingReparsePoint(steamExePath))
        {
            return new SteamClientLaunchResult(
                SteamClientLaunchStatus.RefusedInvalidPath,
                false,
                false,
                null,
                null,
                "目标 steam.exe 不存在或包含不安全的重解析点。");
        }

        IReadOnlyList<string> safeArguments = arguments ?? [];
        foreach (string arg in safeArguments)
        {
            if (arg is null || arg.Any(ch => ch is '\r' or '\n' or '\0'))
            {
                return new SteamClientLaunchResult(
                    SteamClientLaunchStatus.RefusedInvalidPath,
                    false,
                    false,
                    null,
                    null,
                    "启动参数包含非法控制字符。");
            }
        }

        SignatureResult signature;
        try
        {
            using FileStream stream = new(
                steamExePath,
                FileMode.Open,
                FileAccess.Read,
                FileShare.Read,
                bufferSize: 4096,
                FileOptions.SequentialScan);
            ValidateLockedFileHandle(stream.SafeFileHandle, steamExePath);
            signature = _verifySignature(steamExePath, stream.SafeFileHandle);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or SecurityException or Win32Exception)
        {
            return new SteamClientLaunchResult(
                SteamClientLaunchStatus.RefusedUntrustedSignature,
                false,
                false,
                null,
                null,
                $"校验本地 steam.exe 文件锁定与签名时失败：{ex.Message}");
        }

        bool trustedValve = signature.Status == SignatureStatus.Valid &&
            (signature.IsValveSigner || AuthenticodeVerifier.IsTrustedValveSigner(signature.Status, signature.SignerSubject));
        if (!trustedValve)
        {
            return new SteamClientLaunchResult(
                SteamClientLaunchStatus.RefusedUntrustedSignature,
                false,
                false,
                null,
                signature,
                $"拒绝启动未经 Valve 官方合法签名的 steam.exe（状态：{signature.Status}，签名者：{signature.SignerSubject ?? "<none>"}）。");
        }

        if (_clientLauncher.IsCurrentProcessElevated())
        {
            SteamClientLaunchRequest deElevatedRequest = new(steamExePath, normalizedRoot, safeArguments, DeElevated: true);
            if (_clientLauncher.TryLaunchDeElevated(deElevatedRequest, out int? deElevatedPid, out string? deElevateError))
            {
                return new SteamClientLaunchResult(
                    SteamClientLaunchStatus.LaunchedDeElevated,
                    true,
                    true,
                    deElevatedPid,
                    signature,
                    "已通过桌面 Shell 普通权限令牌降权拉起正版 Steam 客户端。");
            }

            // 严禁在找不到安全普通权限令牌时回退为高权限直接运行 steam.exe。
            return new SteamClientLaunchResult(
                SteamClientLaunchStatus.RefusedElevatedWithoutStandardToken,
                false,
                false,
                null,
                signature,
                $"当前工具处于管理员提权状态且未能获取安全的普通权限桌面令牌，已拒绝以高权限启动 steam.exe。请从普通桌面手动启动 Steam。（原因：{deElevateError ?? "无可用普通权限令牌"}）");
        }

        SteamClientLaunchRequest directRequest = new(steamExePath, normalizedRoot, safeArguments, DeElevated: false);
        if (_clientLauncher.TryLaunchDirect(directRequest, out int? directPid, out string? directError))
        {
            return new SteamClientLaunchResult(
                SteamClientLaunchStatus.LaunchedDirect,
                true,
                false,
                directPid,
                signature,
                "已验证 Valve 官方签名并安全启动本地 Steam 客户端。");
        }

        return new SteamClientLaunchResult(
            SteamClientLaunchStatus.LaunchFailed,
            false,
            false,
            null,
            signature,
            $"拉起已验签的 steam.exe 失败：{directError ?? "未知错误"}");
    }

    private async Task<(string SourceUrl, long BytesWritten)> DownloadWithFallbackAsync(
        string installerPath,
        CancellationToken cancellationToken,
        IProgress<(long BytesRead, long? TotalBytes)>? downloadProgress = null)
    {
        HttpClientHandler? ownedHandler = null;
        HttpMessageHandler handlerToUse = _httpMessageHandler ?? (ownedHandler = new HttpClientHandler
        {
            AllowAutoRedirect = false,
            AutomaticDecompression = DecompressionMethods.None
        });

        using HttpClient client = new(handlerToUse, disposeHandler: false)
        {
            Timeout = TimeSpan.FromSeconds(60)
        };

        try
        {
            Uri[] endpoints = [new Uri(PrimaryInstallerUrl), new Uri(FallbackInstallerUrl)];
            Exception? lastTransientFailure = null;

            foreach (Uri endpoint in endpoints)
            {
                try
                {
                    return await DownloadFromSingleEndpointAsync(client, endpoint, installerPath, cancellationToken, downloadProgress)
                        .ConfigureAwait(false);
                }
                catch (SecurityException)
                {
                    // 遇到越权跳转、HTTPS 降级、超限体积等安全违例时立即闭锁拒绝，绝不静默回退。
                    throw;
                }
                catch (Exception ex) when (
                    ex is HttpRequestException or IOException or InvalidDataException ||
                    (ex is TaskCanceledException && !cancellationToken.IsCancellationRequested))
                {
                    DeleteFileIfExists(installerPath);
                    lastTransientFailure = ex;
                }
            }

            throw new HttpRequestException(
                $"无法从官方主/备地址下载 SteamSetup.exe：{lastTransientFailure?.Message ?? "未知网络错误"}",
                lastTransientFailure);
        }
        finally
        {
            ownedHandler?.Dispose();
        }
    }

    private static async Task<(string SourceUrl, long BytesWritten)> DownloadFromSingleEndpointAsync(
        HttpClient client,
        Uri initialUri,
        string installerPath,
        CancellationToken cancellationToken,
        IProgress<(long BytesRead, long? TotalBytes)>? downloadProgress = null)
    {
        ValidateOfficialHttpsUri(initialUri);

        Uri currentUri = initialUri;
        int redirectCount = 0;

        while (true)
        {
            cancellationToken.ThrowIfCancellationRequested();

            using HttpRequestMessage request = new(HttpMethod.Get, currentUri);
            using HttpResponseMessage response = await client.SendAsync(
                request,
                HttpCompletionOption.ResponseHeadersRead,
                cancellationToken).ConfigureAwait(false);

            if (response.RequestMessage?.RequestUri is Uri actualUri)
            {
                ValidateOfficialHttpsUri(actualUri);
            }

            if (IsRedirectStatusCode(response.StatusCode))
            {
                if (redirectCount >= MaximumRedirectsPerEndpoint)
                {
                    throw new SecurityException(
                        $"官方安装器下载重定向次数超过允许上限（最多 {MaximumRedirectsPerEndpoint} 次）。");
                }

                Uri? location = response.Headers.Location
                    ?? throw new SecurityException("官方安装器重定向响应缺少 Location 目标地址。");
                Uri nextUri = location.IsAbsoluteUri ? location : new Uri(currentUri, location);
                ValidateOfficialHttpsUri(nextUri);

                currentUri = nextUri;
                redirectCount++;
                continue;
            }

            if (!response.IsSuccessStatusCode)
            {
                throw new HttpRequestException(
                    $"下载官方安装器失败：HTTP {(int)response.StatusCode} ({response.ReasonPhrase})。",
                    null,
                    response.StatusCode);
            }

            if (response.Content.Headers.ContentLength is long declaredLength && declaredLength > MaximumInstallerBytes)
            {
                throw new SecurityException(
                    $"官方安装器响应头声明体积 {declaredLength} 字节超过上限 {MaximumInstallerBytes} 字节。");
            }

            await using Stream networkStream = await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
            await using FileStream fileStream = new(
                installerPath,
                FileMode.CreateNew,
                FileAccess.Write,
                FileShare.None,
                bufferSize: 81920,
                useAsync: true);

            byte[] buffer = ArrayPool<byte>.Shared.Rent(81920);
            long totalBytes = 0;
            long? declaredOrContentLength = response.Content.Headers.ContentLength;
            long lastReportedBytes = -1;
            long lastReportTickMs = Environment.TickCount64;
            downloadProgress?.Report((0, declaredOrContentLength));
            try
            {
                while (true)
                {
                    int read = await networkStream.ReadAsync(buffer.AsMemory(0, buffer.Length), cancellationToken)
                        .ConfigureAwait(false);
                    if (read == 0)
                    {
                        break;
                    }

                    totalBytes += read;
                    if (totalBytes > MaximumInstallerBytes)
                    {
                        throw new SecurityException(
                            $"官方安装器流式下载体积超过上限 {MaximumInstallerBytes} 字节。");
                    }

                    await fileStream.WriteAsync(buffer.AsMemory(0, read), cancellationToken).ConfigureAwait(false);

                    long nowTickMs = Environment.TickCount64;
                    if (totalBytes - lastReportedBytes >= 65_536 || nowTickMs - lastReportTickMs >= 80)
                    {
                        lastReportedBytes = totalBytes;
                        lastReportTickMs = nowTickMs;
                        downloadProgress?.Report((totalBytes, declaredOrContentLength));
                    }
                }
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(buffer, clearArray: true);
            }

            if (totalBytes == 0)
            {
                throw new InvalidDataException("官方安装器下载返回空文件。");
            }

            if (totalBytes != lastReportedBytes)
            {
                downloadProgress?.Report((totalBytes, declaredOrContentLength ?? totalBytes));
            }

            await fileStream.FlushAsync(cancellationToken).ConfigureAwait(false);
            return (currentUri.AbsoluteUri, totalBytes);
        }
    }

    private static void ValidateOfficialHttpsUri(Uri uri)
    {
        if (!uri.IsAbsoluteUri)
        {
            throw new SecurityException("官方安装器 URL 必须是绝对地址。");
        }

        if (!string.Equals(uri.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase))
        {
            throw new SecurityException($"拒绝非 HTTPS 协议请求：{uri.Scheme}");
        }

        if (!uri.IsDefaultPort)
        {
            throw new SecurityException($"拒绝非标准 HTTPS 端口：{uri.Port}");
        }

        if (!string.IsNullOrEmpty(uri.UserInfo))
        {
            throw new SecurityException("拒绝包含 UserInfo 的官方安装器 URL。");
        }

        if (!AllowedHosts.Contains(uri.Host))
        {
            throw new SecurityException($"拒绝跳转或访问白名单之外的主机：{uri.Host}");
        }
    }

    private static bool IsRedirectStatusCode(HttpStatusCode statusCode) => (int)statusCode is 301 or 302 or 303 or 307 or 308;

    private string CreateIsolatedInstallerDirectory()
    {
        string baseRoot = string.IsNullOrWhiteSpace(_temporaryRootOverride)
            ? Path.Combine(Path.GetTempPath(), "SteamSentinel-OfficialInstaller")
            : Path.GetFullPath(_temporaryRootOverride);

        if (!ContentDiscovery.IsLocalSafePath(baseRoot) || Validation.ContainsReparsePoint(baseRoot))
        {
            throw new SecurityException("临时安装器工作根目录路径不安全或包含重解析点。");
        }

        Directory.CreateDirectory(baseRoot);
        if (Validation.ContainsReparsePoint(baseRoot))
        {
            throw new SecurityException("临时安装器工作根目录包含不安全的重解析点。");
        }

        string candidate = Path.Combine(baseRoot, Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(candidate);
        string physicalCandidate = ResolveExistingDirectoryPhysicalPath(candidate);
        if (!ContentDiscovery.IsLocalSafePath(physicalCandidate) ||
            Validation.ContainsReparsePoint(physicalCandidate))
        {
            CleanupTemporaryDirectory(physicalCandidate);
            throw new SecurityException("临时安装器子目录物理路径校验失败。");
        }

        return physicalCandidate;
    }

    private static string ResolveExistingDirectoryPhysicalPath(string directory)
    {
        string full = Path.TrimEndingDirectorySeparator(Path.GetFullPath(directory));
        // 使用 LocalNativePath.Encode 支持长路径下的只读属性句柄与物理路径核对，避免 248 字符上限触发 Win32(206)。
        using SafeFileHandle handle = CreateFile(
            LocalNativePath.Encode(full),
            0x80,
            3,
            IntPtr.Zero,
            3,
            0x02000000 | 0x00200000,
            IntPtr.Zero);
        if (handle.IsInvalid)
        {
            throw new Win32Exception(Marshal.GetLastWin32Error(), "无法打开临时安装器目录句柄。");
        }

        if (Validation.IsRedirectingReparseHandle(handle))
        {
            throw new SecurityException("临时安装器子目录句柄指向重解析点。");
        }

        string physical = ReadFinalPath(handle);
        if (!ContentDiscovery.IsLocalSafePath(physical))
        {
            throw new SecurityException("临时安装器子目录解析后的物理路径不安全。");
        }

        return Path.TrimEndingDirectorySeparator(physical);
    }

    private static string ValidateTargetSteamRoot(string targetSteamRoot)
    {
        if (string.IsNullOrWhiteSpace(targetSteamRoot) ||
            !ContentDiscovery.IsLocalSafePath(targetSteamRoot) ||
            !Validation.IsSafeExactTarget(targetSteamRoot))
        {
            throw new ArgumentException("目标 Steam 根目录不安全或无效。", nameof(targetSteamRoot));
        }

        string full = Path.TrimEndingDirectorySeparator(Path.GetFullPath(targetSteamRoot));
        if (full.Any(ch => ch is '"' or '\r' or '\n' or '\0'))
        {
            throw new ArgumentException("目标 Steam 根目录包含非法字符。", nameof(targetSteamRoot));
        }

        if (Directory.Exists(full) && Validation.ContainsReparsePoint(full))
        {
            throw new SecurityException("目标 Steam 根目录包含不安全的重解析点。");
        }

        return full;
    }

    private static void ValidateLockedFileHandle(SafeFileHandle handle, string expectedPath)
    {
        if (Validation.IsRedirectingReparseHandle(handle))
        {
            throw new SecurityException("拒绝验证指向重解析点的文件句柄。");
        }

        string finalPath = ReadFinalPath(handle);
        if (!string.Equals(Path.GetFullPath(finalPath), Path.GetFullPath(expectedPath), StringComparison.OrdinalIgnoreCase))
        {
            throw new SecurityException("锁定文件句柄最终路径与预期不一致，存在路径劫持风险。");
        }
    }

    private static string ReadFinalPath(SafeFileHandle handle)
    {
        StringBuilder buffer = new(4096);
        uint length = GetFinalPathNameByHandle(handle, buffer, (uint)buffer.Capacity, 0);
        if (length >= buffer.Capacity && length < 32768)
        {
            buffer = new StringBuilder((int)length + 1);
            length = GetFinalPathNameByHandle(handle, buffer, (uint)buffer.Capacity, 0);
        }

        if (length == 0 || length >= buffer.Capacity)
        {
            throw new IOException("无法读取锁定句柄的最终物理路径。");
        }

        string finalPath = buffer.ToString();
        return finalPath.StartsWith(@"\\?\", StringComparison.Ordinal) ? finalPath[4..] : finalPath;
    }

    private static async Task<SteamInstallerExecutionResult> ExecuteInstallerProcessAsync(
        SteamInstallerExecutionRequest request,
        CancellationToken cancellationToken)
    {
        if (!ContentDiscovery.IsLocalSafePath(request.InstallerPath) ||
            !File.Exists(request.InstallerPath) ||
            Validation.IsRedirectingReparsePoint(request.InstallerPath))
        {
            throw new SecurityException("待执行的官方安装器不存在或包含不安全的重解析点。");
        }

        ProcessStartInfo startInfo = new(request.InstallerPath)
        {
            Arguments = request.Arguments,
            UseShellExecute = false,
            CreateNoWindow = true,
            WorkingDirectory = Path.GetDirectoryName(request.InstallerPath) ?? string.Empty
        };

        using Process process = Process.Start(startInfo)
            ?? throw new InvalidOperationException("启动官方安装器进程失败。");

        using CancellationTokenSource timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeoutCts.CancelAfter(TimeSpan.FromMinutes(5));
        try
        {
            await process.WaitForExitAsync(timeoutCts.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            try
            {
                if (!process.HasExited)
                {
                    process.Kill(entireProcessTree: true);
                }
            }
            catch
            {
                // 尽力终止超时安装进程。
            }
            throw;
        }

        return new SteamInstallerExecutionResult(process.ExitCode);
    }

    /// <summary>
    /// 基于已锁定只读文件句柄离线校验 Authenticode 内嵌时间戳签名与时间戳证书链（仅信任本地缓存与系统根证书）。
    /// </summary>
    public static InstallerTimestampResult VerifyEmbeddedTimestampOffline(string filePath, SafeFileHandle fileHandle)
    {
        if (!OperatingSystem.IsWindows())
        {
            return new InstallerTimestampResult(false, "当前平台不支持 WinVerifyTrust 内嵌时间戳验证。");
        }

        if (!Path.IsPathFullyQualified(filePath) || fileHandle.IsInvalid || fileHandle.IsClosed)
        {
            return new InstallerTimestampResult(false, "时间戳校验参数或文件句柄无效。");
        }

        WinTrustFileInfo? fileInfo = null;
        SafeFileHandle? syncHandle = null;
        IntPtr fileInfoPtr = IntPtr.Zero;
        WinTrustData data = default;
        bool handleReferenced = false;
        bool verificationRequested = false;
        bool structureWritten = false;

        try
        {
            fileHandle.DangerousAddRef(ref handleReferenced);
            // 与 AuthenticodeVerifier 一致，通过 ReOpenFile 将句柄重新映射为同步只读句柄供 WinTrust 读取。
            syncHandle = ReOpenFile(fileHandle, 0x80000000, 1, 0x00200000 | 0x08000000);
            if (syncHandle.IsInvalid)
            {
                return new InstallerTimestampResult(false, $"ReOpenFile 失败（Win32={Marshal.GetLastWin32Error()}）。");
            }

            fileInfo = new WinTrustFileInfo(filePath) { FileHandle = syncHandle.DangerousGetHandle() };
            fileInfoPtr = Marshal.AllocHGlobal(Marshal.SizeOf<WinTrustFileInfo>());
            Marshal.StructureToPtr(fileInfo, fileInfoPtr, false);
            structureWritten = true;

            data = new WinTrustData(fileInfoPtr)
            {
                ProviderFlags = AuthenticodeVerifier.OfflineProviderFlags,
                StateAction = 1
            };

            verificationRequested = true;
            int trustResult = WinVerifyTrust(new IntPtr(-1), GenericVerifyV2, ref data);
            if (trustResult != 0 || data.StateData == IntPtr.Zero)
            {
                return new InstallerTimestampResult(false, $"WinVerifyTrust 主签名验证失败（0x{trustResult:X8}）。");
            }

            IntPtr provData = WTHelperProvDataFromStateData(data.StateData);
            if (provData == IntPtr.Zero)
            {
                return new InstallerTimestampResult(false, "无法获取 WinTrust 状态提供者数据。");
            }

            IntPtr primarySignerPtr = WTHelperGetProvSignerFromChain(provData, 0, false, 0);
            if (primarySignerPtr == IntPtr.Zero)
            {
                return new InstallerTimestampResult(false, "无法获取主签名者链信息。");
            }

            CryptProviderSgnr primarySigner = Marshal.PtrToStructure<CryptProviderSgnr>(primarySignerPtr);
            if (primarySigner.DwError != 0 || primarySigner.CsCertChain == 0)
            {
                return new InstallerTimestampResult(false, $"主签名者链状态无效（0x{primarySigner.DwError:X8}）。");
            }

            using X509Certificate2? primaryCert = TryExtractChainCertificate(primarySignerPtr, 0, out _);
            if (primaryCert is null)
            {
                return new InstallerTimestampResult(false, "无法提取主签名叶证书。");
            }

            if (primarySigner.CsCounterSigners == 0)
            {
                return new InstallerTimestampResult(false, "可执行文件缺少内嵌时间戳副签名（CounterSigner）。");
            }

            string lastReason = "未找到有效的内嵌时间戳证书链。";
            for (uint i = 0; i < primarySigner.CsCounterSigners; i++)
            {
                IntPtr counterSignerPtr = WTHelperGetProvSignerFromChain(provData, 0, true, i);
                if (counterSignerPtr == IntPtr.Zero)
                {
                    continue;
                }

                CryptProviderSgnr counterSigner = Marshal.PtrToStructure<CryptProviderSgnr>(counterSignerPtr);
                if ((counterSigner.DwSignerType & SgnrTypeTimestamp) == 0)
                {
                    lastReason = $"副签名[{i}] 类型非时间戳签名（0x{counterSigner.DwSignerType:X}）。";
                    continue;
                }

                if (counterSigner.DwError != 0 || counterSigner.CsCertChain == 0)
                {
                    lastReason = $"时间戳副签名[{i}] 验证出错（0x{counterSigner.DwError:X8}）。";
                    continue;
                }

                long fileTime = ((long)counterSigner.SftVerifyAsOf.DwHighDateTime << 32) |
                    counterSigner.SftVerifyAsOf.DwLowDateTime;
                if (fileTime <= 0)
                {
                    lastReason = "时间戳时间字段无效。";
                    continue;
                }

                DateTimeOffset timestampUtc = DateTimeOffset.FromFileTime(fileTime).ToUniversalTime();
                bool chainValid = true;
                bool hasTrustedRoot = false;
                for (uint j = 0; j < counterSigner.CsCertChain; j++)
                {
                    IntPtr certPtr = WTHelperGetProvCertFromChain(counterSignerPtr, j);
                    if (certPtr == IntPtr.Zero)
                    {
                        chainValid = false;
                        lastReason = $"无法读取时间戳证书链节点[{j}]。";
                        break;
                    }

                    CryptProviderCert provCert = Marshal.PtrToStructure<CryptProviderCert>(certPtr);
                    if (provCert.DwError != 0 || provCert.FTestCert || provCert.PCert == IntPtr.Zero)
                    {
                        chainValid = false;
                        lastReason = $"时间戳证书链节点[{j}] 存在错误（0x{provCert.DwError:X8}）或为测试证书。";
                        break;
                    }

                    if (provCert.FTrustedRoot)
                    {
                        hasTrustedRoot = true;
                    }
                }

                if (!chainValid || !hasTrustedRoot)
                {
                    if (chainValid && !hasTrustedRoot)
                    {
                        lastReason = "时间戳证书链未链接到受信任根证书。";
                    }
                    continue;
                }

                using X509Certificate2? tsLeafCert = TryExtractChainCertificate(counterSignerPtr, 0, out _);
                if (tsLeafCert is null)
                {
                    lastReason = "无法提取时间戳叶证书。";
                    continue;
                }

                if (!HasTimeStampingEku(tsLeafCert))
                {
                    lastReason = "时间戳叶证书缺少 Time Stamping EKU (1.3.6.1.5.5.7.3.8)。";
                    continue;
                }

                if (timestampUtc < tsLeafCert.NotBefore.ToUniversalTime() ||
                    timestampUtc > tsLeafCert.NotAfter.ToUniversalTime())
                {
                    lastReason = "内嵌时间戳超出时间戳证书有效期。";
                    continue;
                }

                if (timestampUtc < primaryCert.NotBefore.ToUniversalTime() ||
                    timestampUtc > primaryCert.NotAfter.ToUniversalTime())
                {
                    lastReason = "内嵌时间戳超出主代码签名证书有效期。";
                    continue;
                }

                return new InstallerTimestampResult(
                    true,
                    "内嵌时间戳签名与时间戳证书链校验通过。",
                    timestampUtc,
                    tsLeafCert.Subject);
            }

            return new InstallerTimestampResult(false, lastReason);
        }
        catch (Exception ex)
        {
            return new InstallerTimestampResult(false, $"内嵌时间戳验证异常：{ex.Message}");
        }
        finally
        {
            if (verificationRequested)
            {
                data.StateAction = 2;
                try
                {
                    _ = WinVerifyTrust(new IntPtr(-1), GenericVerifyV2, ref data);
                }
                catch
                {
                    // 清理阶段不引入信任判断。
                }
            }

            if (fileInfoPtr != IntPtr.Zero)
            {
                if (structureWritten)
                {
                    Marshal.DestroyStructure<WinTrustFileInfo>(fileInfoPtr);
                }
                Marshal.FreeHGlobal(fileInfoPtr);
            }

            fileInfo?.ReleasePathMemory();
            syncHandle?.Dispose();
            if (handleReferenced)
            {
                fileHandle.DangerousRelease();
            }
        }
    }

    private static X509Certificate2? TryExtractChainCertificate(IntPtr signerPtr, uint index, out CryptProviderCert provCert)
    {
        provCert = default;
        IntPtr certPtr = WTHelperGetProvCertFromChain(signerPtr, index);
        if (certPtr == IntPtr.Zero)
        {
            return null;
        }

        provCert = Marshal.PtrToStructure<CryptProviderCert>(certPtr);
        if (provCert.PCert == IntPtr.Zero)
        {
            return null;
        }

        NativeCertContext context = Marshal.PtrToStructure<NativeCertContext>(provCert.PCert);
        if (context.PbCertEncoded == IntPtr.Zero || context.CbCertEncoded == 0 || context.CbCertEncoded > 1024 * 1024)
        {
            return null;
        }

        byte[] raw = new byte[context.CbCertEncoded];
        Marshal.Copy(context.PbCertEncoded, raw, 0, raw.Length);
        return X509CertificateLoader.LoadCertificate(raw);
    }

    private static bool HasTimeStampingEku(X509Certificate2 certificate)
    {
        foreach (X509Extension extension in certificate.Extensions)
        {
            if (extension is X509EnhancedKeyUsageExtension eku)
            {
                foreach (Oid oid in eku.EnhancedKeyUsages)
                {
                    if (string.Equals(oid.Value, TimeStampingEkuOid, StringComparison.Ordinal))
                    {
                        return true;
                    }
                }
            }
        }

        return false;
    }

    internal static void CleanupTemporaryDirectory(string directory)
    {
        try
        {
            if (string.IsNullOrWhiteSpace(directory))
            {
                return;
            }

            string full = Path.GetFullPath(directory);
            if (Directory.Exists(full) && !Validation.ContainsReparsePoint(full))
            {
                Directory.Delete(full, recursive: true);
            }
        }
        catch
        {
            // 清理临时目录失败不阻断原始异常或已完成的修复结果。
        }
    }

    private static void DeleteFileIfExists(string filePath)
    {
        try
        {
            if (File.Exists(filePath) && !Validation.IsRedirectingReparsePoint(filePath))
            {
                File.Delete(filePath);
            }
        }
        catch
        {
            // 忽略残留删除错误。
        }
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true, EntryPoint = "CreateFileW")]
    private static extern SafeFileHandle CreateFile(
        string path,
        uint access,
        uint share,
        IntPtr security,
        uint disposition,
        uint flags,
        IntPtr template);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true, EntryPoint = "GetFinalPathNameByHandleW")]
    private static extern uint GetFinalPathNameByHandle(
        SafeFileHandle handle,
        StringBuilder path,
        uint size,
        uint flags);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern SafeFileHandle ReOpenFile(
        SafeFileHandle original,
        uint access,
        uint share,
        uint flags);

    [DllImport("wintrust.dll", ExactSpelling = true, SetLastError = true)]
    private static extern int WinVerifyTrust(
        IntPtr hwnd,
        [MarshalAs(UnmanagedType.LPStruct)] Guid actionId,
        ref WinTrustData data);

    [DllImport("wintrust.dll", ExactSpelling = true)]
    private static extern IntPtr WTHelperProvDataFromStateData(IntPtr stateData);

    [DllImport("wintrust.dll", ExactSpelling = true)]
    private static extern IntPtr WTHelperGetProvSignerFromChain(
        IntPtr provData,
        uint idxSigner,
        [MarshalAs(UnmanagedType.Bool)] bool fCounterSigner,
        uint idxCounterSigner);

    [DllImport("wintrust.dll", ExactSpelling = true)]
    private static extern IntPtr WTHelperGetProvCertFromChain(IntPtr sgnr, uint idxCert);

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private sealed class WinTrustFileInfo
    {
        public int StructSize = Marshal.SizeOf<WinTrustFileInfo>();
        public IntPtr FilePath;
        public IntPtr FileHandle = IntPtr.Zero;
        public IntPtr KnownSubject = IntPtr.Zero;

        public WinTrustFileInfo(string filePath)
        {
            FilePath = Marshal.StringToCoTaskMemUni(filePath);
        }

        public void ReleasePathMemory()
        {
            if (FilePath != IntPtr.Zero)
            {
                Marshal.FreeCoTaskMem(FilePath);
                FilePath = IntPtr.Zero;
            }
        }
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct WinTrustData
    {
        public int StructSize;
        public IntPtr PolicyCallbackData;
        public IntPtr SIPClientData;
        public uint UIChoice;
        public uint RevocationChecks;
        public uint UnionChoice;
        public IntPtr FileInfoPointer;
        public uint StateAction;
        public IntPtr StateData;
        public string? URLReference;
        public uint ProviderFlags;
        public uint UIContext;
        public IntPtr SignatureSettings;

        public WinTrustData(IntPtr fileInfoPointer)
        {
            StructSize = Marshal.SizeOf<WinTrustData>();
            PolicyCallbackData = IntPtr.Zero;
            SIPClientData = IntPtr.Zero;
            UIChoice = 2;
            RevocationChecks = 0;
            UnionChoice = 1;
            FileInfoPointer = fileInfoPointer;
            StateAction = 0;
            StateData = IntPtr.Zero;
            URLReference = null;
            ProviderFlags = AuthenticodeVerifier.OfflineProviderFlags;
            UIContext = 0;
            SignatureSettings = IntPtr.Zero;
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct NativeFileTime
    {
        public uint DwLowDateTime;
        public uint DwHighDateTime;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct CryptProviderSgnr
    {
        public uint CbStruct;
        public NativeFileTime SftVerifyAsOf;
        public uint CsCertChain;
        public IntPtr PasCertChain;
        public uint DwSignerType;
        public IntPtr PsSigner;
        public uint DwError;
        public uint CsCounterSigners;
        public IntPtr PasCounterSigners;
        public IntPtr PChainContext;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct CryptProviderCert
    {
        public uint CbStruct;
        public IntPtr PCert;
        [MarshalAs(UnmanagedType.Bool)]
        public bool FCommercial;
        [MarshalAs(UnmanagedType.Bool)]
        public bool FTrustedRoot;
        [MarshalAs(UnmanagedType.Bool)]
        public bool FSelfSigned;
        [MarshalAs(UnmanagedType.Bool)]
        public bool FTestCert;
        public uint DwRevokedReason;
        public uint DwConfidence;
        public uint DwError;
        public IntPtr PTrustListContext;
        [MarshalAs(UnmanagedType.Bool)]
        public bool FTrustListSignerCert;
        public IntPtr PCtlContext;
        public uint DwCtlError;
        [MarshalAs(UnmanagedType.Bool)]
        public bool FIsCyclic;
        public IntPtr PChainElement;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct NativeCertContext
    {
        public uint DwCertEncodingType;
        public IntPtr PbCertEncoded;
        public uint CbCertEncoded;
        public IntPtr PCertInfo;
        public IntPtr HCertStore;
    }
}
