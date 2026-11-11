using System.ComponentModel;
using System.IO;
using System.Security.Principal;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using Microsoft.Win32;
using SteamSentinel.Broker;
using SteamSentinel.Core.Inspection;
using SteamSentinel.Core.Models;
using SteamSentinel.Core.Remediation;
using SteamSentinel.Core.Scanning;
using SteamSentinel.Core.Steam;

namespace SteamSentinel.SelfTest;

internal static partial class Program
{
    private static async Task TestSteamConfigurationRepairAsync(string root)
    {
        const string cfg = "# user settings\r\nBootStrapperInhibitAll=1\r\nBootStrapperInhibitV3=1\r\nForceOfflineMode=true # preserve comment\r\nBootStrapperForceSelfUpdate=0\r\nUnrelated=中文\r\nForceOfflineMode=0\r\n";
        foreach (Encoding encoding in new Encoding[] { new UTF8Encoding(false, true), new UTF8Encoding(true, true), new UnicodeEncoding(false, true, true), new UnicodeEncoding(true, true, true) })
        {
            byte[] bytes = [.. encoding.GetPreamble(), .. encoding.GetBytes(cfg)];
            bool changed = SteamConfigurationRepair.TryRepairCfg(bytes, out byte[] repaired, out bool paired);
            string text = encoding.GetString(repaired.AsSpan(encoding.GetPreamble().Length));
            Check("Steam配置保留编码及其他设置 " + encoding.WebName + encoding.GetPreamble().Length,
                changed && paired && bytes.Length == repaired.Length && text.Contains("Unrelated=中文\r\nForceOfflineMode=0") &&
                text.Contains("# preserve comment") && !text.Contains("BootStrapperInhibitV3") && text.StartsWith("# user settings\r\n"));
            Check("Steam配置修复幂等 " + encoding.WebName, !SteamConfigurationRepair.TryRepairCfg(repaired, out _, out _));
        }
        foreach (string single in new[] { "BootStrapperInhibitAll=enabled", "BootStrapperInhibitV3=true", "ForceOfflineMode=1", "BootStrapperForceSelfUpdate=disabled" })
            Check("Steam配置单项可以明确恢复 " + single, SteamConfigurationRepair.TryRepairCfg(Encoding.UTF8.GetBytes(single), out _, out bool paired) && !paired);
        foreach (string benign in new[] { "BootStrapperInhibitAll=0", "BootStrapperInhibitV3=false", "ForceOfflineMode=0", "BootStrapperForceSelfUpdate=1", "# ForceOfflineMode=1", "Other=ForceOfflineMode=1", "ForceOfflineMode=true unknown", "ForceOfflineMode=1\0" })
            Check("Steam配置保留非目标设置 " + benign.Replace('\0', '_'), !SteamConfigurationRepair.TryRepairCfg(Encoding.UTF8.GetBytes(benign), out _, out _));
        Check("Steam配置拒绝不支持字节", !SteamConfigurationRepair.TryRepairCfg([0xff, 0x31], out _, out _));
        Check("Steam配置有输入大小上限", !SteamConfigurationRepair.TryRepairCfg(new byte[SteamConfigurationRepair.MaximumBytes + 1], out _, out _));

        string directory = Path.Combine(root, "steam-config-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        SteamLayout layout = new(); layout.SteamRoots.Add(directory);
        string executable = Path.Combine(directory, "steam.exe");
        await File.WriteAllTextAsync(executable, "inert target identity fixture; never executed");
        string command = $"\"{executable}\" -silent \"-cef-enable-debugging\" -language english -cef-enable-debugging";
        Check("Steam启动参数只清除精确开关", SteamConfigurationRepair.TryRepairCommand(command, layout, out string repairedCommand, out string exe) &&
            exe == executable && command.Length == repairedCommand.Length && repairedCommand.Contains("-silent") && repairedCommand.Contains("-language english") &&
            !repairedCommand.Contains("-cef-enable-debugging"));
        foreach (string other in new[] { $"cmd.exe /c \"{executable}\" -cef-enable-debugging", $"\"{executable}\" -cef-enable-debugging-extra", $"\"{executable}\" --comment=-cef-enable-debugging", $"\"{executable}\" \"quoted -cef-enable-debugging value\"", $"\"{executable}\" -cef-enable-debugging\nother" })
            Check("Steam启动参数拒绝包装命令和非独立开关 " + other, !SteamConfigurationRepair.TryRepairCommand(other, layout, out _, out _));
        byte[] shortcut = SteamConfigShortcutFixture(executable, "-silent -cef-enable-debugging -language english");
        Check("Steam快捷方式精确编辑且保留其他字节", SteamConfigurationRepair.TryRepairShortcut(shortcut, layout, out byte[] repairedShortcut, out string shortcutExe) &&
            shortcutExe == executable && shortcut.Length == repairedShortcut.Length && ShortcutInspector.Inspect(repairedShortcut).Arguments!.Contains("-language english") &&
            !ShortcutInspector.Inspect(repairedShortcut).Arguments!.Contains("-cef-enable-debugging"));
        Check("Steam快捷方式拒绝其他程序", !SteamConfigurationRepair.TryRepairShortcut(SteamConfigShortcutFixture(Path.Combine(directory, "other.exe"), "-cef-enable-debugging"), layout, out _, out _));
        byte[] redirected = shortcut.ToArray(); redirected[21] |= 2;
        Check("Steam快捷方式拒绝环境目标", !SteamConfigurationRepair.TryRepairShortcut(redirected, layout, out _, out _));
        Check("Steam快捷方式拒绝截短", !SteamConfigurationRepair.TryRepairShortcut(shortcut[..^1], layout, out _, out _));
        string realShortcutPath = Path.Combine(directory, "system-created-steam.lnk");
        CreateSteamConfigSystemShortcut(realShortcutPath, executable, "-silent -cef-enable-debugging -language english");
        byte[] realShortcut = await File.ReadAllBytesAsync(realShortcutPath);
        Check("Steam系统生成的含IDList快捷方式可精确修复", (realShortcut[20] & 1) != 0 &&
            SteamConfigurationRepair.TryRepairShortcut(realShortcut, layout, out byte[] realRepaired, out _) && realRepaired.Length == realShortcut.Length);
        int infoPosition = 78 + BitConverter.ToUInt16(realShortcut, 76);
        if ((BitConverter.ToUInt32(realShortcut, 20) & 2) != 0 && (BitConverter.ToUInt32(realShortcut, infoPosition + 8) & 2) != 0)
        {
            int networkPosition = infoPosition + checked((int)BitConverter.ToUInt32(realShortcut, infoPosition + 20));
            int networkNamePosition = networkPosition + checked((int)BitConverter.ToUInt32(realShortcut, networkPosition + 8));
            byte[] remote = realShortcut.ToArray(); remote[networkNamePosition + 2] = remote[networkNamePosition + 2] == 'Z' ? (byte)'Q' : (byte)'Z';
            Check("Steam快捷方式拒绝远程共享回退", !SteamConfigurationRepair.TryRepairShortcut(remote, layout, out _, out _));
            int shareStart = networkNamePosition + 2;
            while (shareStart < realShortcut.Length && realShortcut[shareStart] != '\\' && realShortcut[shareStart] != 0) shareStart++;
            shareStart++;
            byte[] differentShare = realShortcut.ToArray(); differentShare[shareStart] = differentShare[shareStart] == 'Z' ? (byte)'Q' : (byte)'Z';
            Check("Steam快捷方式拒绝本机其他共享冲突", !SteamConfigurationRepair.TryRepairShortcut(differentShare, layout, out _, out _));
        }
        string otherExecutable = Path.Combine(directory, "other.exe"); await File.WriteAllTextAsync(otherExecutable, "inert alternate target fixture");
        byte[] unverified = SteamConfigShortcutFixture(otherExecutable, "-silent -cef-enable-debugging");
        string reviewPath = Path.Combine(directory, "unverified-target.lnk"); await File.WriteAllBytesAsync(reviewPath, unverified);
        ScanReport reviewReport = new();
        await SteamSecurityScanner.ScanSteamConfigurationFileAsync(reviewPath, SteamConfigurationRepair.Shortcut, reviewReport, CancellationToken.None, layout);
        Finding review = reviewReport.Findings.Single();
        Check("Steam未确认目标的结构化调试参数保守仅复核且保留实体hash", review.RuleId == SteamConfigurationRepair.ShortcutReviewRule &&
            !review.IsKnownMalware && !review.CanRemediate && review.SuggestedActions.SequenceEqual([SuggestedActionKind.ReviewOnly]) &&
            review.Sha256 == SteamConfigurationRepair.Hash(unverified) && review.TargetSha256 == review.Sha256 &&
            !RemediationModePolicy.ProjectFinding(review, RemediationMode.Conservative).CanRemediate);
        Finding selectedRisk = RemediationModePolicy.ProjectFinding(review, RemediationMode.Aggressive);
        Check("Steam未确认快捷方式允许激进显式隔离而非参数修复", selectedRisk.UserSelectedRisk && !selectedRisk.IsKnownMalware &&
            selectedRisk.SuggestedActions.SequenceEqual([SuggestedActionKind.QuarantineFile]));
        Check("Steam快捷方式复核不把任意字符串当结构证据", !SteamConfigurationRepair.HasDebugShortcutArguments(Encoding.UTF8.GetBytes("text -cef-enable-debugging")) &&
            !SteamConfigurationRepair.HasDebugShortcutArguments(SteamConfigShortcutFixture(otherExecutable, "\"text -cef-enable-debugging text\"")) &&
            !SteamConfigurationRepair.HasDebugShortcutArguments(unverified[..^1]));
        string otherShortcutPath = Path.Combine(directory, "system-created-other.lnk");
        CreateSteamConfigSystemShortcut(otherShortcutPath, otherExecutable, "-cef-enable-debugging");
        byte[] otherShortcut = await File.ReadAllBytesAsync(otherShortcutPath);
        int oldListSize = BitConverter.ToUInt16(realShortcut, 76), newListSize = BitConverter.ToUInt16(otherShortcut, 76);
        byte[] conflict = [.. realShortcut.AsSpan(0, 76), .. otherShortcut.AsSpan(76, newListSize + 2), .. realShortcut.AsSpan(78 + oldListSize)];
        Check("Steam快捷方式拒绝IDList与LinkInfo目标冲突", !SteamConfigurationRepair.TryRepairShortcut(conflict, layout, out _, out _));
        string knownRoot = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "SteamSentinel-Inert-Shortcut-Test");
        SteamLayout knownLayout = new(); knownLayout.SteamRoots.Add(knownRoot);
        string knownShortcutPath = Path.Combine(directory, "system-created-known-folder.lnk");
        CreateSteamConfigSystemShortcut(knownShortcutPath, Path.Combine(knownRoot, "steam.exe"), "-silent -cef-enable-debugging");
        byte[] knownShortcut = await File.ReadAllBytesAsync(knownShortcutPath);
        Check("Steam系统生成的ProgramFiles已知目录快捷方式可精确修复", SteamConfigurationRepair.TryRepairShortcut(knownShortcut, knownLayout, out _, out _));

        string path = Path.Combine(directory, "steam.cfg"); byte[] original = Encoding.UTF8.GetBytes(cfg);
        await File.WriteAllBytesAsync(path, original);
        ScanReport report = new();
        await SteamSecurityScanner.ScanSteamConfigurationFileAsync(path, SteamConfigurationRepair.Cfg, report, CancellationToken.None);
        Finding finding = report.Findings.Single();
        Check("Steam配置扫描新组合可修复但不标恶意", finding.RuleId == "STEAM-CFG-UPDATE-SUPPRESSION-PAIR" && finding.CanRemediate && !finding.IsKnownMalware &&
            finding.SuggestedActions.Contains(SuggestedActionKind.RepairSteamConfiguration));
        RemediationAction action = await SteamConfigurationRepairTarget.CaptureAsync(finding, layout);
        BrokerEngine.ValidateSteamConfigurationAction(action, layout);
        await File.WriteAllBytesAsync(path, Encoding.UTF8.GetBytes(cfg + "Later=1"));
        bool staleDenied = false;
        try { _ = await SteamConfigurationRepairTarget.CaptureAsync(finding, layout); } catch (InvalidDataException) { staleDenied = true; }
        Check("Steam配置计划拒绝扫描后变化", staleDenied);
        await File.WriteAllBytesAsync(path, original);
        action = await SteamConfigurationRepairTarget.CaptureAsync(finding, layout);
        string marker = Path.Combine(directory, ".cef-enable-remote-debugging"); await File.WriteAllBytesAsync(marker, []);
        ScanReport markerReport = new();
        await SteamSecurityScanner.ScanSteamConfigurationFileAsync(marker, SteamConfigurationRepair.Marker, markerReport, CancellationToken.None);
        Finding markerFinding = markerReport.Findings.Single();
        Check("Steam调试空标记允许备份隔离但不标恶意", markerFinding.CanRemediate && !markerFinding.IsKnownMalware);
        await TestSteamRunConfigurationAsync(layout, executable, command, realShortcutPath);

        using WindowsIdentity user = WindowsIdentity.GetCurrent();
        if (!new WindowsPrincipal(user).IsInRole(WindowsBuiltInRole.Administrator))
        {
            bool denied = false;
            try { await BrokerEngine.RepairSteamConfigurationFileAsync(action, layout, path + ".backup", (_, _) => Task.CompletedTask, _ => { }, CancellationToken.None); }
            catch (Exception ex) when (ex is Win32Exception or UnauthorizedAccessException) { denied = true; }
            Check("Steam配置权限不足保持原件", denied && File.ReadAllBytes(path).SequenceEqual(original));
            return;
        }
        int persistence = 0; bool backupBeforeWrite = false;
        QuarantineRecord record = await BrokerEngine.RepairSteamConfigurationFileAsync(action, layout, path + ".backup",
            (saved, _) => { persistence++; if (saved.FileMutationAttempted && !saved.MutationConfirmed) backupBeforeWrite = File.ReadAllBytes(saved.QuarantinedPath!).SequenceEqual(original); return Task.CompletedTask; },
            _ => { }, CancellationToken.None);
        Check("Steam配置持久备份先于写入且保留文件身份", persistence == 3 && backupBeforeWrite && record.MutationConfirmed &&
            FileScopeSafety.CaptureIdentity(path) == action.ExpectedFileIdentity && await SteamConfigurationRepairTarget.IsRepairedAsync(action, layout));
        await BrokerEngine.RestoreSteamConfigurationFileAsync(record, layout, CancellationToken.None);
        await BrokerEngine.RestoreSteamConfigurationFileAsync(record, layout, CancellationToken.None);
        Check("Steam配置受信回滚保留原文件并可重试", File.ReadAllBytes(path).SequenceEqual(original) && File.Exists(record.QuarantinedPath));
        action = await SteamConfigurationRepairTarget.CaptureAsync(finding, layout);
        bool failure = false;
        try
        {
            await BrokerEngine.RepairSteamConfigurationFileAsync(action, layout, path + ".failure-backup", (_, _) => Task.CompletedTask, _ => { }, CancellationToken.None,
                async (lease, bytes) => { await lease.WriteSameLengthAsync(bytes, CancellationToken.None); throw new IOException("injected write failure"); });
        }
        catch (IOException) { failure = true; }
        Check("Steam配置写后异常自动恢复原件", failure && File.ReadAllBytes(path).SequenceEqual(original));
        QuarantineRecord? uncommitted = null;
        try
        {
            await BrokerEngine.RepairSteamConfigurationFileAsync(action, layout, path + ".commit-backup", (saved, _) =>
            { uncommitted = saved; return saved.MutationConfirmed ? Task.FromException(new IOException("injected commit failure")) : Task.CompletedTask; }, _ => { }, CancellationToken.None);
        }
        catch (IOException) { }
        Check("Steam配置提交失败不执行第二轮修改", uncommitted?.MutationConfirmed == true && await SteamConfigurationRepairTarget.IsRepairedAsync(action, layout));
        await File.WriteAllBytesAsync(path, Encoding.UTF8.GetBytes(cfg));
        byte[] altered = File.ReadAllBytes(path); altered[0] ^= 1; await File.WriteAllBytesAsync(path, altered);
        bool restoreDenied = false;
        try { await BrokerEngine.RestoreSteamConfigurationFileAsync(uncommitted!, layout, CancellationToken.None); } catch (InvalidOperationException) { restoreDenied = true; }
        Check("Steam配置回滚不覆盖后续更改", restoreDenied && File.ReadAllBytes(path).SequenceEqual(altered));

        RemediationAction markerAction = await SteamConfigurationRepairTarget.CaptureAsync(markerFinding, layout);
        QuarantineRecord markerRecord = await BrokerEngine.QuarantineSteamMarkerAsync(markerAction, layout, marker + ".backup", (_, _) => Task.CompletedTask, _ => { }, CancellationToken.None);
        Check("Steam调试标记只隔离单文件并保留空备份", !File.Exists(marker) && File.Exists(markerRecord.QuarantinedPath) && await SteamConfigurationRepairTarget.IsRepairedAsync(markerAction, layout));
        await BrokerEngine.RestoreSteamMarkerAsync(markerRecord, layout, CancellationToken.None);
        await BrokerEngine.RestoreSteamMarkerAsync(markerRecord, layout, CancellationToken.None);
        Check("Steam调试空标记可受信恢复并重试", File.Exists(marker) && new FileInfo(marker).Length == 0 && File.Exists(markerRecord.QuarantinedPath));
    }

    private static byte[] SteamConfigShortcutFixture(string target, string arguments)
    {
        byte[] ansi = Encoding.ASCII.GetBytes(target + '\0'); byte[] unicode = Encoding.Unicode.GetBytes(target + '\0');
        int ansiOffset = 53, suffixOffset = ansiOffset + ansi.Length, unicodeOffset = suffixOffset + 1, unicodeSuffix = unicodeOffset + unicode.Length;
        using MemoryStream output = new(); using BinaryWriter writer = new(output, Encoding.UTF8, true);
        writer.Write(76); writer.Write(new Guid("00021401-0000-0000-c000-000000000046").ToByteArray());
        writer.Write(2u | 32u | 128u); writer.Write(new byte[52]);
        writer.Write(unicodeSuffix + 2); writer.Write(36); writer.Write(1u); writer.Write(36); writer.Write(ansiOffset); writer.Write(0); writer.Write(suffixOffset); writer.Write(unicodeOffset); writer.Write(unicodeSuffix);
        writer.Write(17); writer.Write(3); writer.Write(0); writer.Write(16); writer.Write((byte)0);
        writer.Write(ansi); writer.Write((byte)0); writer.Write(unicode); writer.Write((ushort)0);
        writer.Write(checked((ushort)arguments.Length)); writer.Write(Encoding.Unicode.GetBytes(arguments)); writer.Write(0);
        return output.ToArray();
    }

    private static void CreateSteamConfigSystemShortcut(string path, string target, string arguments)
    {
        object shell = Activator.CreateInstance(Type.GetTypeFromProgID("WScript.Shell")!)!;
        object? shortcut = null;
        try
        {
            dynamic factory = shell;
            shortcut = factory.CreateShortcut(path);
            dynamic link = shortcut;
            link.TargetPath = target; link.Arguments = arguments;
            link.WorkingDirectory = Path.GetDirectoryName(target)!; link.Description = "Steam configuration inert regression fixture";
            link.Save();
        }
        finally
        {
            if (shortcut is not null) Marshal.FinalReleaseComObject(shortcut);
            Marshal.FinalReleaseComObject(shell);
        }
    }

    private static async Task TestSteamRunConfigurationAsync(SteamLayout layout, string executable, string command, string shortcutPath)
    {
        const string keyPath = @"Software\Microsoft\Windows\CurrentVersion\Run";
        string name = "SteamSentinel-Inert-Configuration-Test-" + Guid.NewGuid().ToString("N");
        using RegistryKey key = Registry.CurrentUser.CreateSubKey(keyPath, writable: true);
        try
        {
            key.SetValue(name, command, RegistryValueKind.ExpandString);
            _ = SteamConfigurationRepair.TryRepairCommand(command, layout, out string repaired, out _);
            RuleSet rules = new();
            ScanReport scanned = new();
            await new SteamSecurityScanner(rules).ScanAsync(layout, scanned);
            await SteamSecurityScanner.ScanSteamConfigurationFileAsync(shortcutPath, SteamConfigurationRepair.Shortcut, scanned, CancellationToken.None, layout);
            Finding finding = scanned.Findings.Single(f => f.ConfigurationKind == SteamConfigurationRepair.Run && f.RegistryValueName == name);
            Finding[] selected = scanned.Findings.Where(f => f.ConfigurationKind is SteamConfigurationRepair.Cfg or SteamConfigurationRepair.Marker or SteamConfigurationRepair.Shortcut ||
                f.ConfigurationKind == SteamConfigurationRepair.Run && f.RegistryValueName == name).ToArray();
            Check("Steam配置扫描输出包含cfg标记Run和快捷方式四种类型", selected.Select(f => f.ConfigurationKind).Distinct().Count() == 4 &&
                selected.All(f => f.CanRemediate && !f.IsKnownMalware));
            RemediationPlan direct = await new RemediationPlanBuilder(rules, layout).BuildAsync(selected, false);
            Check("Steam配置扫描结果可直接准备精确动作", direct.Actions.Count == 4 && direct.Actions.All(a => a.Type == RemediationActionType.RepairSteamConfiguration) &&
                direct.Actions.Where(a => a.ConfigurationKind is SteamConfigurationRepair.Run or SteamConfigurationRepair.Shortcut).All(a => a.RelatedFileSha256 is { Length: 64 }));
            foreach (RemediationAction prepared in direct.Actions) BrokerEngine.ValidateSteamConfigurationAction(prepared, layout);
            RemediationBatchSession batch = await new RemediationBatchPlanner(rules, layout, Path.Combine(Path.GetDirectoryName(executable)!, "unused-resident"))
                .PrepareAsync(selected, scanned, false);
            Check("Steam配置完整批量准备保留四种动作且无需恶意关联", batch.Plans.SelectMany(plan => plan.Actions).Count() == 4 &&
                batch.Plans.SelectMany(plan => plan.Actions).All(a => a.Type == RemediationActionType.RepairSteamConfiguration) &&
                batch.Targets.Count(t => t.State == RemediationTargetState.Ready) == 4);
            string roundTrip = JsonSerializer.Serialize(direct, SteamSentinel.Core.Utilities.JsonFile.Options);
            RemediationPlan loaded = JsonSerializer.Deserialize<RemediationPlan>(roundTrip, SteamSentinel.Core.Utilities.JsonFile.Options)!;
            Check("Steam配置计划快照参与身份并可JSON往返", RemediationPlanIdentity.Fingerprint(direct) == RemediationPlanIdentity.Fingerprint(loaded) &&
                loaded.Actions.Single(a => a.ConfigurationKind == SteamConfigurationRepair.Run).ExpectedValueData == command);
            RemediationAction action = await SteamConfigurationRepairTarget.CaptureAsync(finding, layout);
            bool backedUp = false; int persists = 0;
            QuarantineRecord record = await BrokerEngine.RepairSteamRunValueAsync(action, layout, (saved, _) =>
            {
                persists++;
                if (saved.ConfigurationMutationAttempted && !saved.MutationConfirmed)
                    backedUp = saved.RegistryValueData == command && key.GetValue(name, null, RegistryValueOptions.DoNotExpandEnvironmentNames) as string == command;
                return Task.CompletedTask;
            }, CancellationToken.None);
            Check("Steam Run先备份原值再精确修改且保留类型", persists == 3 && backedUp && key.GetValueKind(name) == RegistryValueKind.ExpandString &&
                key.GetValue(name, null, RegistryValueOptions.DoNotExpandEnvironmentNames) as string == repaired && await SteamConfigurationRepairTarget.IsRepairedAsync(action, layout));
            BrokerEngine.RestoreSteamRunValue(record, layout);
            BrokerEngine.RestoreSteamRunValue(record, layout);
            Check("Steam Run受信回滚恢复原值可重试", key.GetValue(name, null, RegistryValueOptions.DoNotExpandEnvironmentNames) as string == command);
            bool failure = false;
            try
            {
                await BrokerEngine.RepairSteamRunValueAsync(action, layout, (_, _) => Task.CompletedTask, CancellationToken.None,
                    (opened, valueName, value, kind) => { opened.SetValue(valueName, value, kind); throw new IOException("injected registry write failure"); });
            }
            catch (IOException) { failure = true; }
            Check("Steam Run写后失败自动恢复", failure && key.GetValue(name, null, RegistryValueOptions.DoNotExpandEnvironmentNames) as string == command);
            record = await BrokerEngine.RepairSteamRunValueAsync(action, layout, (_, _) => Task.CompletedTask, CancellationToken.None);
            key.SetValue(name, command + " -later-user-setting", RegistryValueKind.ExpandString);
            bool denied = false;
            try { BrokerEngine.RestoreSteamRunValue(record, layout); } catch (InvalidOperationException) { denied = true; }
            Check("Steam Run回滚不覆盖后续用户参数", denied && (key.GetValue(name, null, RegistryValueOptions.DoNotExpandEnvironmentNames) as string)!.EndsWith("-later-user-setting"));
            bool captureDenied = false;
            try { _ = await SteamConfigurationRepairTarget.CaptureAsync(finding, layout); } catch (InvalidDataException) { captureDenied = true; }
            Check("Steam Run计划拒绝原值变化", captureDenied);
        }
        finally { key.DeleteValue(name, throwOnMissingValue: false); }
    }
}
