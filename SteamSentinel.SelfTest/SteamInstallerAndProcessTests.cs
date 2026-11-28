using System.IO;
using System.Net;
using System.Net.Http;
using System.Security;
using Microsoft.Win32.SafeHandles;
using SteamSentinel.Core.Inspection;
using SteamSentinel.Core.Reporting;
using SteamSentinel.Core.Steam;

namespace SteamSentinel.SelfTest;

internal static partial class Program
{
    /// <summary>
    /// 验证 Steam 安全进程控制与官方安装器兜底服务全路径（严禁触碰宿主机真实 Steam 进程）。
    /// </summary>
    internal static async Task TestSteamInstallerAndProcessAsync(string root)
    {
        string work = Path.Combine(root, "sip-" + Guid.NewGuid().ToString("N")[..8]);
        Directory.CreateDirectory(work);

        try
        {
            await VerifyProcessIsolationAndLifecycleAsync(work);
            await VerifyInstallerDownloadAndSignatureAsync(work);
            await VerifyOfficialRepairFlowAsync(work);
            VerifyLocalClientLaunchSecurity(work);
        }
        finally
        {
            try
            {
                if (Directory.Exists(work))
                {
                    Directory.Delete(work, recursive: true);
                }
            }
            catch
            {
                // 清理测试夹具目录失败不影响测试结果归集。
            }
        }
    }

    private static async Task VerifyProcessIsolationAndLifecycleAsync(string work)
    {
        string steamRootA = Path.Combine(work, "SteamA");
        string steamRootSiblingPrefix = Path.Combine(work, "SteamA_Evil");
        string otherDir = Path.Combine(work, "OtherSteam");
        Directory.CreateDirectory(Path.Combine(steamRootA, "bin", "cef"));
        Directory.CreateDirectory(steamRootSiblingPrefix);
        Directory.CreateDirectory(otherDir);

        string steamExeA = Path.Combine(steamRootA, "steam.exe");
        await File.WriteAllBytesAsync(steamExeA, "MZ_DUMMY_VALVE"u8.ToArray());

        SteamLayout layout = new();
        layout.SteamRoots.Add(steamRootA);

        // 1. 跨目录隔离、前缀目录欺骗拦截、白名单进程过滤与当前进程 PID 严格跳过
        MockSteamProcessEnvironment env = new()
        {
            VerifyFunc = path => string.Equals(path, steamExeA, StringComparison.OrdinalIgnoreCase)
                ? TrustedValveResult()
                : new SignatureResult(SignatureStatus.Unsigned, (MessageText)"unsigned")
        };
        env.RunningProcesses.AddRange(
        [
            new(1001, "steam", steamExeA),
            new(1002, "steamwebhelper", Path.Combine(steamRootA, "bin", "cef", "steamwebhelper.exe")),
            new(1003, "gameoverlayui64", Path.Combine(steamRootA, "gameoverlayui64.exe")),
            new(1004, "steamerrorreporter", Path.Combine(steamRootA, "steamerrorreporter.exe")),
            new(2001, "steam", Path.Combine(steamRootSiblingPrefix, "steam.exe")),
            new(2002, "steamwebhelper", Path.Combine(otherDir, "steamwebhelper.exe")),
            new(2003, "notepad", Path.Combine(steamRootA, "notepad.exe")),
            new(2004, "steam", null),
            new(Environment.ProcessId, "steam", steamExeA)
        ]);

        SteamProcessController controller = new(env);
        IReadOnlyList<SteamProcessCandidate> found = controller.FindRunningProcesses(layout);
        Check("ProcCtrl 严格隔离非目标根目录/前缀欺骗目录/非白名单进程与当前进程自身",
            controller.IsAnyRunning(layout) &&
            found.Count == 4 &&
            found.Select(p => p.Pid).OrderBy(x => x).SequenceEqual([1001, 1002, 1003, 1004]));

        // 真实 WindowsSteamProcessEnvironment 只读枚举也必须跳过自身且不匹配隔离测试目录
        WindowsSteamProcessEnvironment realEnv = new();
        SteamProcessController realController = new(realEnv);
        Check("ProcCtrl 真实Windows环境枚举跳过自身PID且隔离测试目录不匹配宿主机进程",
            realEnv.ListCandidateProcesses().All(p => p.Pid != Environment.ProcessId) &&
            !realController.IsAnyRunning(layout) &&
            !realEnv.TerminateProcess(Environment.ProcessId, steamExeA));

        // 2. 无进程时直接成功返回
        SteamLayout emptyLayout = new();
        emptyLayout.SteamRoots.Add(otherDir);
        env.RunningProcesses.RemoveAll(p => p.Pid == 2002);
        SteamProcessShutdownResult emptyResult = await controller.EnsureClosedAsync(emptyLayout);
        Check("ProcCtrl 目标目录无运行进程时直接返回成功结果且不触发关闭操作",
            !emptyResult.HadRunningProcesses &&
            emptyResult.GracefullyExited &&
            emptyResult.ForceTerminatedCount == 0 &&
            env.ShutdownCalls.Count == 0 &&
            env.TerminateCalls.Count == 0);

        // 3. 合法 Valve 签名 steam.exe 发送 -shutdown 后优雅退出分支
        env.ShutdownAction = _ =>
        {
            env.PollsRemainingBeforeExit = 2;
            return true;
        };
        SteamProcessShutdownResult graceful = await controller.EnsureClosedAsync(
            layout,
            TimeSpan.FromSeconds(6));
        Check("ProcCtrl 校验Valve签名后发送-shutdown并轮询等待优雅退出",
            graceful.HadRunningProcesses &&
            graceful.GracefullyExited &&
            graceful.ForceTerminatedCount == 0 &&
            env.ShutdownCalls.SequenceEqual([steamExeA]) &&
            env.TerminateCalls.Count == 0 &&
            env.RunningProcesses.Any(p => p.Pid == 2001));

        // 4. 优雅超时精准强杀分支（仅杀目标根目录残留进程，保留外部进程）
        env.ResetCalls();
        env.RunningProcesses.Add(new(3001, "steam", steamExeA));
        env.RunningProcesses.Add(new(3002, "steamwebhelper", Path.Combine(steamRootA, "bin", "cef", "steamwebhelper.exe")));
        env.ShutdownAction = _ => true; // 模拟进程无视 -shutdown，直到超时
        env.TerminateBehavior = (pid, _) =>
        {
            env.RunningProcesses.RemoveAll(p => p.Pid == pid);
            return true;
        };

        SteamProcessShutdownResult timedOutResult = await controller.EnsureClosedAsync(
            layout,
            TimeSpan.FromMilliseconds(500));
        Check("ProcCtrl -shutdown超时后精准强杀目标目录残留进程且不波及外部进程",
            timedOutResult.HadRunningProcesses &&
            !timedOutResult.GracefullyExited &&
            timedOutResult.ForceTerminatedCount == 2 &&
            env.ShutdownCalls.Count == 1 &&
            env.TerminateCalls.Count == 2 &&
            env.TerminateCalls.All(c => c.Pid is 3001 or 3002) &&
            env.RunningProcesses.Any(p => p.Pid == 2001));

        // 5. steam.exe 缺失或不可信时跳过 -shutdown 直接安全终止
        env.ResetCalls();
        env.VerifyFunc = _ => new SignatureResult(SignatureStatus.Unsigned, (MessageText)"untrusted");
        env.RunningProcesses.Add(new(4001, "gameoverlayui", Path.Combine(steamRootA, "gameoverlayui.exe")));
        SteamProcessShutdownResult untrustedResult = await controller.EnsureClosedAsync(layout);
        Check("ProcCtrl steam.exe不可信时禁止发送-shutdown并直接精准强杀",
            untrustedResult.HadRunningProcesses &&
            !untrustedResult.GracefullyExited &&
            untrustedResult.ForceTerminatedCount == 1 &&
            env.ShutdownCalls.Count == 0 &&
            env.TerminateCalls.SequenceEqual([(4001, Path.Combine(steamRootA, "gameoverlayui.exe"))]));

        // 6. 强杀后二次核实仍存在顽固进程时抛出 InvalidOperationException
        env.ResetCalls();
        env.RunningProcesses.Add(new(5001, "steamerrorreporter64", Path.Combine(steamRootA, "steamerrorreporter64.exe")));
        env.TerminateBehavior = (_, _) => false;
        bool stubbornThrew = false;
        try
        {
            _ = await controller.EnsureClosedAsync(layout, TimeSpan.FromMilliseconds(100));
        }
        catch (InvalidOperationException ex)
        {
            stubbornThrew = ex.Message.Contains("5001", StringComparison.Ordinal);
        }
        Check("ProcCtrl 顽固进程未退出时二次核实抛出带描述的InvalidOperationException", stubbornThrew);
    }

    private static async Task VerifyInstallerDownloadAndSignatureAsync(string work)
    {
        string tempRoot = Path.Combine(work, "it");
        Directory.CreateDirectory(tempRoot);
        byte[] dummyInstallerBytes = "MZ_INERT_STEAMSETUP_FIXTURE"u8.ToArray();

        // 1. 拒绝 HTTP 降级跳转并清理临时目录
        using (MockHttpHandler httpDowngrade = new(_ => RedirectResponse("http://cdn.akamai.steamstatic.com/client/installer/SteamSetup.exe")))
        {
            SteamOfficialInstallerService svc = new(
                httpMessageHandler: httpDowngrade,
                verifySignature: (_, _) => TrustedValveResult(),
                verifyTimestamp: (_, _) => ValidTimestampResult(),
                temporaryRoot: tempRoot);

            bool rejected = false;
            try
            {
                await svc.DownloadAndVerifyInstallerAsync();
            }
            catch (SecurityException)
            {
                rejected = true;
            }

            Check("Installer 拒绝HTTP降级跳转并彻底清理临时目录",
                rejected && Directory.GetFileSystemEntries(tempRoot).Length == 0);
        }

        // 2. 拒绝跨站越权跳转
        using (MockHttpHandler crossHost = new(_ => RedirectResponse("https://evil.example.invalid/SteamSetup.exe")))
        {
            SteamOfficialInstallerService svc = new(
                httpMessageHandler: crossHost,
                verifySignature: (_, _) => TrustedValveResult(),
                verifyTimestamp: (_, _) => ValidTimestampResult(),
                temporaryRoot: tempRoot);

            bool rejected = false;
            try
            {
                await svc.DownloadAndVerifyInstallerAsync();
            }
            catch (SecurityException)
            {
                rejected = true;
            }

            Check("Installer 拒绝白名单之外域名的HTTPS重定向并清理临时目录",
                rejected && Directory.GetFileSystemEntries(tempRoot).Length == 0);
        }

        // 3. 拒绝超过 1 次连续重定向
        using (MockHttpHandler multiRedirect = new(req =>
            req.RequestUri!.Host == "cdn.akamai.steamstatic.com"
                ? RedirectResponse("https://steamcdn-a.akamaihd.net/step1/SteamSetup.exe")
                : RedirectResponse("https://cdn.akamai.steamstatic.com/step2/SteamSetup.exe")))
        {
            SteamOfficialInstallerService svc = new(
                httpMessageHandler: multiRedirect,
                verifySignature: (_, _) => TrustedValveResult(),
                verifyTimestamp: (_, _) => ValidTimestampResult(),
                temporaryRoot: tempRoot);

            bool rejected = false;
            try
            {
                await svc.DownloadAndVerifyInstallerAsync();
            }
            catch (SecurityException)
            {
                rejected = true;
            }

            Check("Installer 限制单地址最多跟进1次官方重定向",
                rejected && Directory.GetFileSystemEntries(tempRoot).Length == 0);
        }

        // 4. 允许白名单内单次 HTTPS 重定向并在失败主源时切备用源
        using (MockHttpHandler singleAllowedRedirect = new(req =>
            req.RequestUri!.AbsoluteUri == SteamOfficialInstallerService.PrimaryInstallerUrl
                ? RedirectResponse(SteamOfficialInstallerService.FallbackInstallerUrl)
                : BinaryResponse(dummyInstallerBytes)))
        {
            bool sawExclusiveReadLock = false;
            SteamOfficialInstallerService svc = new(
                httpMessageHandler: singleAllowedRedirect,
                verifySignature: (path, handle) =>
                {
                    sawExclusiveReadLock = !handle.IsInvalid && !handle.IsClosed && IsWriteBlocked(path);
                    return TrustedValveResult();
                },
                verifyTimestamp: (_, _) => ValidTimestampResult(),
                temporaryRoot: tempRoot);

            using DownloadedSteamInstaller pkg = await svc.DownloadAndVerifyInstallerAsync();
            bool existedBeforeDispose = File.Exists(pkg.InstallerPath);
            string dir = pkg.InstallerDirectory;
            pkg.Dispose();

            Check("Installer 允许官方白名单单次HTTPS跳转且验签全程持有FileShare.Read锁，释放后删档",
                existedBeforeDispose &&
                sawExclusiveReadLock &&
                pkg.SourceUrl == SteamOfficialInstallerService.FallbackInstallerUrl &&
                pkg.FileSizeBytes == dummyInstallerBytes.Length &&
                !Directory.Exists(dir));
        }

        // 5. 拒绝流式超过 16 MiB 的安装包（无 Content-Length 声明头）
        byte[] oversizedChunk = new byte[1024 * 1024];
        using (MockHttpHandler oversizedHandler = new(_ => new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StreamContent(new RepeatedByteStream(oversizedChunk, 17))
        }))
        {
            SteamOfficialInstallerService svc = new(
                httpMessageHandler: oversizedHandler,
                verifySignature: (_, _) => TrustedValveResult(),
                verifyTimestamp: (_, _) => ValidTimestampResult(),
                temporaryRoot: tempRoot);

            bool rejected = false;
            try
            {
                await svc.DownloadAndVerifyInstallerAsync();
            }
            catch (SecurityException)
            {
                rejected = true;
            }

            Check("Installer 拒绝流式体积超过16MiB的安装包并清理残留",
                rejected && Directory.GetFileSystemEntries(tempRoot).Length == 0);
        }

        // 6. 损坏/非Valve签名自动关闭句柄并删档拒绝
        using (MockHttpHandler badSigHttp = new(_ => BinaryResponse(dummyInstallerBytes)))
        {
            SteamOfficialInstallerService svc = new(
                httpMessageHandler: badSigHttp,
                verifySignature: (_, _) => new SignatureResult(SignatureStatus.HashMismatch, (MessageText)"hash mismatch"),
                verifyTimestamp: (_, _) => ValidTimestampResult(),
                temporaryRoot: tempRoot);

            bool rejected = false;
            try
            {
                await svc.DownloadAndVerifyInstallerAsync();
            }
            catch (SecurityException)
            {
                rejected = true;
            }

            Check("Installer 签名损坏时立即释放锁并自动删除临时安装包",
                rejected && Directory.GetFileSystemEntries(tempRoot).Length == 0);
        }

        // 7. 即使主签名有效但内嵌时间戳证书校验失败也必须自动删档拒绝
        using (MockHttpHandler badTsHttp = new(_ => BinaryResponse(dummyInstallerBytes)))
        {
            SteamOfficialInstallerService svc = new(
                httpMessageHandler: badTsHttp,
                verifySignature: (_, _) => TrustedValveResult(),
                verifyTimestamp: (_, _) => new InstallerTimestampResult(false, "missing timestamp"),
                temporaryRoot: tempRoot);

            bool rejected = false;
            try
            {
                await svc.DownloadAndVerifyInstallerAsync();
            }
            catch (SecurityException)
            {
                rejected = true;
            }

            Check("Installer 内嵌时间戳证书无效时自动删档并拒绝",
                rejected && Directory.GetFileSystemEntries(tempRoot).Length == 0);
        }

        // 8. 主源 503 自动回退官方备用源并放行合法签名与时间戳
        using (MockHttpHandler fallbackHttp = new(req =>
            req.RequestUri!.AbsoluteUri == SteamOfficialInstallerService.PrimaryInstallerUrl
                ? new HttpResponseMessage(HttpStatusCode.ServiceUnavailable)
                : BinaryResponse(dummyInstallerBytes)))
        {
            SteamOfficialInstallerService svc = new(
                httpMessageHandler: fallbackHttp,
                verifySignature: (_, _) => TrustedValveResult(),
                verifyTimestamp: (_, _) => ValidTimestampResult(),
                temporaryRoot: tempRoot);

            using DownloadedSteamInstaller ok = await svc.DownloadAndVerifyInstallerAsync();
            Check("Installer 主CDN不可用时自动切换官方备用CDN并校验放行",
                ok.SourceUrl == SteamOfficialInstallerService.FallbackInstallerUrl &&
                File.Exists(ok.InstallerPath));
        }

        // 9. 验证真实默认时间戳校验器面对伪造无签名文件稳健拒绝
        string unsignedProbe = Path.Combine(work, "unsigned-probe.exe");
        await File.WriteAllBytesAsync(unsignedProbe, dummyInstallerBytes);
        using (FileStream probeStream = new(unsignedProbe, FileMode.Open, FileAccess.Read, FileShare.Read))
        {
            InstallerTimestampResult realTsCheck = SteamOfficialInstallerService.VerifyEmbeddedTimestampOffline(
                unsignedProbe,
                probeStream.SafeFileHandle);
            Check("Installer 默认离线时间戳校验器拒绝无签名二进制文件", !realTsCheck.IsValid);
        }
    }

    private static async Task VerifyOfficialRepairFlowAsync(string work)
    {
        string tempRoot = Path.Combine(work, "rt");
        string targetSteamRoot = Path.Combine(work, "TargetSteam");
        string otherSteamRoot = Path.Combine(work, "OtherSteamRoot");
        string steamAppsDir = Path.Combine(targetSteamRoot, "steamapps");
        Directory.CreateDirectory(steamAppsDir);
        Directory.CreateDirectory(otherSteamRoot);

        string targetSteamExe = Path.Combine(targetSteamRoot, "steam.exe");
        string acfPath = Path.Combine(steamAppsDir, "appmanifest_730.acf");
        await File.WriteAllBytesAsync(targetSteamExe, "MZ_TARGET_STEAM"u8.ToArray());
        await File.WriteAllTextAsync(acfPath, "\"AppState\" { \"appid\" \"730\" }");

        SteamLayout layout = new();
        layout.SteamRoots.Add(targetSteamRoot);
        layout.SteamRoots.Add(otherSteamRoot);

        MockSteamProcessEnvironment env = new()
        {
            VerifyFunc = path => string.Equals(path, targetSteamExe, StringComparison.OrdinalIgnoreCase)
                ? TrustedValveResult()
                : new SignatureResult(SignatureStatus.Unsigned, (MessageText)"unsigned")
        };

        env.ShutdownAction = _ =>
        {
            env.PollsRemainingBeforeExit = 1;
            return true;
        };
        env.RunningProcesses.Add(new(6001, "steam", targetSteamExe));
        env.RunningProcesses.Add(new(6002, "steam", Path.Combine(otherSteamRoot, "steam.exe")));

        byte[] installerBytes = "MZ_OFFICIAL_STEAMSETUP"u8.ToArray();
        using MockHttpHandler httpHandler = new(_ => BinaryResponse(installerBytes));

        bool closedBeforeRun = false;
        bool installerExistedDuringRun = false;
        string? capturedArgs = null;
        string? capturedInstallerDir = null;

        SteamOfficialInstallerService service = new(
            processController: new SteamProcessController(env),
            httpMessageHandler: httpHandler,
            verifySignature: (_, _) => TrustedValveResult(),
            verifyTimestamp: (_, _) => ValidTimestampResult(),
            runInstaller: (req, _) =>
            {
                closedBeforeRun = env.RunningProcesses.All(p => p.Pid != 6001);
                installerExistedDuringRun = File.Exists(req.InstallerPath);
                capturedArgs = req.Arguments;
                capturedInstallerDir = Path.GetDirectoryName(req.InstallerPath);
                return Task.FromResult(new SteamInstallerExecutionResult(0));
            },
            temporaryRoot: tempRoot);

        SteamOfficialRepairResult result = await service.RunOfficialRepairAsync(targetSteamRoot, layout);

        Check("Repair 运行安装器前关停目标根目录进程、保留steamapps游戏库并在完成后彻底清理临时目录",
            result.Succeeded &&
            closedBeforeRun &&
            installerExistedDuringRun &&
            capturedArgs == $"/S /D={targetSteamRoot}" &&
            result.ShutdownResult.HadRunningProcesses &&
            result.ShutdownResult.GracefullyExited &&
            env.RunningProcesses.Any(p => p.Pid == 6002) &&
            File.Exists(acfPath) &&
            capturedInstallerDir is not null &&
            !Directory.Exists(capturedInstallerDir) &&
            Directory.GetFileSystemEntries(tempRoot).Length == 0);
    }

    private static void VerifyLocalClientLaunchSecurity(string work)
    {
        string steamRoot = Path.Combine(work, "LaunchSteam");
        Directory.CreateDirectory(steamRoot);
        string steamExe = Path.Combine(steamRoot, "steam.exe");
        File.WriteAllBytes(steamExe, "MZ_LOCAL_STEAM"u8.ToArray());

        // 1. 缺失或无效路径拒绝执行
        int launchCalls = 0;
        DelegateSteamClientProcessLauncher nonElevatedLauncher = new(
            isElevated: () => false,
            direct: req => { launchCalls++; return (true, 7001, null); },
            deElevated: req => { launchCalls++; return (true, 7002, null); });

        SteamOfficialInstallerService missingSvc = new(
            verifySignature: (_, _) => TrustedValveResult(),
            clientLauncher: nonElevatedLauncher);
        SteamClientLaunchResult missingRes = missingSvc.LaunchVerifiedSteam(Path.Combine(work, "DoesNotExist"));
        Check("Launch 拒绝不存在的Steam目录且绝不调用启动委托",
            missingRes.Status == SteamClientLaunchStatus.RefusedInvalidPath &&
            !missingRes.Launched &&
            launchCalls == 0);

        // 2. 签名未通过拒绝拉起
        SteamOfficialInstallerService unsignedSvc = new(
            verifySignature: (_, _) => new SignatureResult(SignatureStatus.Invalid, (MessageText)"tampered"),
            clientLauncher: nonElevatedLauncher);
        SteamClientLaunchResult unsignedRes = unsignedSvc.LaunchVerifiedSteam(steamRoot);
        Check("Launch 拒绝非Valve合法签名steam.exe且绝不调用启动委托",
            unsignedRes.Status == SteamClientLaunchStatus.RefusedUntrustedSignature &&
            !unsignedRes.Launched &&
            launchCalls == 0);

        // 3. 普通权限 + Valve 签名 -> 直接拉起
        SteamClientLaunchRequest? capturedDirect = null;
        DelegateSteamClientProcessLauncher directLauncher = new(
            isElevated: () => false,
            direct: req => { capturedDirect = req; return (true, 7003, null); },
            deElevated: _ => (false, null, "unexpected"));
        SteamOfficialInstallerService directSvc = new(
            verifySignature: (_, _) => TrustedValveResult(),
            clientLauncher: directLauncher);
        SteamClientLaunchResult directRes = directSvc.LaunchVerifiedSteam(steamRoot);
        Check("Launch 普通权限且Valve验签通过时直接安全拉起steam.exe",
            directRes.Status == SteamClientLaunchStatus.LaunchedDirect &&
            directRes.Launched &&
            !directRes.UsedDeElevation &&
            directRes.ProcessId == 7003 &&
            capturedDirect is { DeElevated: false } &&
            string.Equals(capturedDirect.ExecutablePath, steamExe, StringComparison.OrdinalIgnoreCase));

        // 4. 管理员提权状态 + 可用交互式 Shell 普通令牌 -> 降权拉起
        bool directCalledWhileElevated = false;
        SteamClientLaunchRequest? capturedDeElevated = null;
        DelegateSteamClientProcessLauncher deElevatedLauncher = new(
            isElevated: () => true,
            direct: _ => { directCalledWhileElevated = true; return (true, 7004, null); },
            deElevated: req => { capturedDeElevated = req; return (true, 7005, null); });
        SteamOfficialInstallerService deElevatedSvc = new(
            verifySignature: (_, _) => TrustedValveResult(),
            clientLauncher: deElevatedLauncher);
        SteamClientLaunchResult deElevatedRes = deElevatedSvc.LaunchVerifiedSteam(steamRoot);
        Check("Launch 提权管理员状态下优先通过交互式Shell令牌降权拉起steam.exe",
            deElevatedRes.Status == SteamClientLaunchStatus.LaunchedDeElevated &&
            deElevatedRes.Launched &&
            deElevatedRes.UsedDeElevation &&
            deElevatedRes.ProcessId == 7005 &&
            !directCalledWhileElevated &&
            capturedDeElevated is { DeElevated: true });

        // 5. 管理员提权状态 + 找不到普通权限 Shell 令牌 -> 拒绝高权限直启并返回明确状态
        bool fallbackDirectCalled = false;
        DelegateSteamClientProcessLauncher noTokenLauncher = new(
            isElevated: () => true,
            direct: _ => { fallbackDirectCalled = true; return (true, 7006, null); },
            deElevated: _ => (false, null, "no standard shell token"));
        SteamOfficialInstallerService refusedElevatedSvc = new(
            verifySignature: (_, _) => TrustedValveResult(),
            clientLauncher: noTokenLauncher);
        SteamClientLaunchResult refusedElevatedRes = refusedElevatedSvc.LaunchVerifiedSteam(steamRoot);
        Check("Launch 提权态找不到普通权限令牌时拒绝高权限直接运行并返回明确提示状态",
            refusedElevatedRes.Status == SteamClientLaunchStatus.RefusedElevatedWithoutStandardToken &&
            !refusedElevatedRes.Launched &&
            !refusedElevatedRes.UsedDeElevation &&
            !fallbackDirectCalled &&
            refusedElevatedRes.Message.Contains("高权限", StringComparison.Ordinal));
    }

    private static SignatureResult TrustedValveResult() =>
        new(SignatureStatus.Valid, (MessageText)"valid")
        {
            IsValveSigner = true,
            SignerSubject = "CN=Valve Corp., O=Valve Corp."
        };

    private static InstallerTimestampResult ValidTimestampResult() =>
        new(true, "valid timestamp", DateTimeOffset.UtcNow.AddDays(-10), "CN=DigiCert Timestamp Authority");

    private static HttpResponseMessage RedirectResponse(string location)
    {
        HttpResponseMessage response = new(HttpStatusCode.Redirect);
        response.Headers.Location = new Uri(location, UriKind.RelativeOrAbsolute);
        return response;
    }

    private static HttpResponseMessage BinaryResponse(byte[] bytes) =>
        new(HttpStatusCode.OK) { Content = new ByteArrayContent(bytes) };

    private static bool IsWriteBlocked(string filePath)
    {
        try
        {
            using FileStream _ = new(filePath, FileMode.Open, FileAccess.Write, FileShare.ReadWrite);
            return false;
        }
        catch (IOException)
        {
            return true;
        }
    }

    private sealed class MockSteamProcessEnvironment : ISteamProcessEnvironment
    {
        public List<SteamProcessCandidate> RunningProcesses { get; } = [];
        public List<string> ShutdownCalls { get; } = [];
        public List<(int Pid, string ImagePath)> TerminateCalls { get; } = [];
        public Func<string, SignatureResult>? VerifyFunc { get; set; }
        public Func<string, bool>? ShutdownAction { get; set; }
        public Func<int, string, bool>? TerminateBehavior { get; set; }
        public int PollsRemainingBeforeExit { get; set; }

        public void ResetCalls()
        {
            ShutdownCalls.Clear();
            TerminateCalls.Clear();
            PollsRemainingBeforeExit = 0;
        }

        public IReadOnlyList<SteamProcessCandidate> ListCandidateProcesses() => [.. RunningProcesses];

        public SignatureResult VerifyExecutable(string path) =>
            VerifyFunc?.Invoke(path) ?? new SignatureResult(SignatureStatus.Unsigned, (MessageText)"mock unsigned");

        public bool StartShutdown(string steamExePath)
        {
            ShutdownCalls.Add(steamExePath);
            return ShutdownAction?.Invoke(steamExePath) ?? true;
        }

        public bool TerminateProcess(int pid, string expectedImagePath)
        {
            TerminateCalls.Add((pid, expectedImagePath));
            return TerminateBehavior?.Invoke(pid, expectedImagePath) ?? false;
        }

        public Task DelayAsync(TimeSpan delay, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (PollsRemainingBeforeExit > 0)
            {
                PollsRemainingBeforeExit--;
                if (PollsRemainingBeforeExit == 0)
                {
                    RunningProcesses.RemoveAll(p =>
                        p.ImagePath is not null &&
                        (p.ImagePath.Contains($"{Path.DirectorySeparatorChar}SteamA{Path.DirectorySeparatorChar}", StringComparison.OrdinalIgnoreCase) ||
                         p.ImagePath.Contains($"{Path.DirectorySeparatorChar}TargetSteam{Path.DirectorySeparatorChar}", StringComparison.OrdinalIgnoreCase)));
                }
            }
            return Task.CompletedTask;
        }
    }

    private sealed class MockHttpHandler(Func<HttpRequestMessage, HttpResponseMessage> responder) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            HttpResponseMessage response = responder(request);
            response.RequestMessage ??= request;
            return Task.FromResult(response);
        }
    }

    private sealed class RepeatedByteStream(byte[] chunk, int repeatCount) : Stream
    {
        private int _remainingChunks = repeatCount;
        private int _offset;

        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
        public override void Flush() => throw new NotSupportedException();
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();

        public override int Read(byte[] buffer, int offset, int count)
        {
            if (_remainingChunks <= 0)
            {
                return 0;
            }

            int available = chunk.Length - _offset;
            int toCopy = Math.Min(count, available);
            Array.Copy(chunk, _offset, buffer, offset, toCopy);
            _offset += toCopy;
            if (_offset >= chunk.Length)
            {
                _offset = 0;
                _remainingChunks--;
            }
            return toCopy;
        }
    }
}
