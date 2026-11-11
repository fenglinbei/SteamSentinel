using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using SteamSentinel.Broker;
using SteamSentinel.Core.Inspection;
using SteamSentinel.Core.Models;
using SteamSentinel.Core.Remediation;
using SteamSentinel.Core.Rules;
using SteamSentinel.Core.Scanning;
using SteamSentinel.Core.Steam;
using SteamSentinel.Core.Utilities;

namespace SteamSentinel.SelfTest;

internal static partial class Program
{
    private static async Task TestBrokerSteamScriptRepairAsync(string root)
    {
        const string loader = ";try{var s=document.createElement(\"script\");s.src=\"http://127.0.0.1:8137/x.js?\"+Date.now();document.head.append(s)}catch{}";
        byte[] original = Encoding.UTF8.GetBytes("(()=>{window.fixture=1;})();\n" + loader + new string(' ', 64));
        Check("Steam脚本Broker合成fixture精确识别", SteamScriptRepair.TryRepair(original, out byte[] repaired));
        byte[] mixed = original.ToArray();
        Array.Copy(repaired, mixed, original.Length / 2);
        Check("Steam脚本中断恢复只接受等长原始修复字节混合", BrokerEngine.IsInterruptedScriptImage(mixed, original, repaired));
        mixed[0] ^= 1;
        Check("Steam脚本中断恢复拒绝业务正文变化", !BrokerEngine.IsInterruptedScriptImage(mixed, original, repaired));
        Check("Steam脚本中断恢复拒绝截短", !BrokerEngine.IsInterruptedScriptImage(original[..^1], original, repaired));

        string directory = Path.Combine(root, "broker-script-" + Guid.NewGuid().ToString("N"));
        string ui = Path.Combine(directory, "steamui");
        Directory.CreateDirectory(ui);
        SteamLayout layout = new();
        layout.SteamRoots.Add(directory);
        string path = Path.Combine(ui, "fixture.js");
        await File.WriteAllBytesAsync(path, original);
        RemediationAction action = await BrokerScriptActionAsync(path, layout);
        BrokerEngine.ValidateSteamScriptAction(action, layout);
        Check("Steam脚本Broker接受绑定路径与双hash", true);
        TestBrokerScriptProcessPrerequisites(ui);
        foreach (RemediationAction bad in new[]
        {
            BrokerScriptActionCopy(action, identity: "invalid"),
            BrokerScriptActionCopy(action, target: Path.Combine(directory, "outside.js")),
            BrokerScriptActionCopy(action, repairedHash: action.ExpectedSha256)
        })
        {
            bool denied = false;
            try { BrokerEngine.ValidateSteamScriptAction(bad, layout); }
            catch (InvalidOperationException) { denied = true; }
            Check("Steam脚本Broker拒绝无效元数据或范围 " + bad.Target + "/" + bad.ExpectedFileIdentity, denied);
        }

        using WindowsIdentity user = WindowsIdentity.GetCurrent();
        bool elevated = new WindowsPrincipal(user).IsInRole(WindowsBuiltInRole.Administrator);
        if (!elevated)
        {
            bool denied = false;
            try
            {
                await BrokerEngine.RepairSteamScriptFileAsync(action, layout, path + ".backup",
                    (_, _) => Task.CompletedTask, _ => { }, CancellationToken.None);
            }
            catch (Exception ex) when (ex is Win32Exception or UnauthorizedAccessException) { denied = true; }
            Check("Steam脚本非管理员不降级元数据权限且保留原件", denied && File.ReadAllBytes(path).SequenceEqual(original));
            return;
        }

        int persistence = 0;
        bool locked = false, beforeMutation = false, backupDurable = false;
        QuarantineRecord record = await BrokerEngine.RepairSteamScriptFileAsync(action, layout, path + ".backup",
            (saved, _) =>
            {
                persistence++;
                if (persistence == 1)
                {
                    try { using FileStream other = new(path, FileMode.Open, FileAccess.Write, FileShare.ReadWrite | FileShare.Delete); }
                    catch (IOException) { locked = true; }
                    beforeMutation = !saved.FileMutationAttempted && !saved.MutationConfirmed;
                }
                if (saved.FileMutationAttempted && !saved.MutationConfirmed)
                    backupDurable = File.ReadAllBytes(saved.QuarantinedPath!).SequenceEqual(original);
                return Task.CompletedTask;
            }, _ => { }, CancellationToken.None);
        Check("Steam脚本备份及attempt持久化先于修复并持锁", persistence == 3 && locked && beforeMutation && backupDurable);
        Check("Steam脚本只移除固定尾部并保留文件identity", File.ReadAllBytes(path).SequenceEqual(repaired) &&
            FileScopeSafety.CaptureIdentity(path) == record.OriginalFileIdentity && record.MutationConfirmed && record.FileMutationAttempted);
        Check("Steam脚本备份保存全部原件且记录双hash", File.ReadAllBytes(path + ".backup").SequenceEqual(original) &&
            record.Sha256 == Convert.ToHexString(SHA256.HashData(original)) && record.RepairedSha256 == Convert.ToHexString(SHA256.HashData(repaired)));
        await BrokerEngine.RestoreSteamScriptFileAsync(record, layout, CancellationToken.None);
        await BrokerEngine.RestoreSteamScriptFileAsync(record, layout, CancellationToken.None);
        Check("Steam脚本回滚可幂等重试且保留备份", File.ReadAllBytes(path).SequenceEqual(original) && File.Exists(path + ".backup"));

        await File.WriteAllBytesAsync(path, original);
        action = await BrokerScriptActionAsync(path, layout);
        QuarantineRecord? finalJournal = null;
        bool finalCommitFailed = false;
        try
        {
            await BrokerEngine.RepairSteamScriptFileAsync(action, layout, path + ".final-commit-failed",
                (saved, _) =>
                {
                    if (saved.MutationConfirmed)
                    {
                        // Model an atomic manifest replacement followed by trust-store commit failure.
                        finalJournal = JsonSerializer.Deserialize<QuarantineRecord>(JsonSerializer.Serialize(saved, JsonFile.Options), JsonFile.Options);
                        throw new IOException("Inert final manifest commit failure after atomic replacement.");
                    }
                    return Task.CompletedTask;
                }, _ => { }, CancellationToken.None);
        }
        catch (IOException) { finalCommitFailed = true; }
        Check("Steam脚本最终manifest提交失败保留已验证修复图像与备份", finalCommitFailed &&
            finalJournal is { MutationConfirmed: true, FileMutationAttempted: true, FileRollbackAttempted: false } &&
            File.ReadAllBytes(path).SequenceEqual(repaired) && File.ReadAllBytes(path + ".final-commit-failed").SequenceEqual(original));
        BrokerEngine rollbackEngine = new(new FixtureTrustStore(null), new FixtureIncidentStateSecurity());
        SteamLayout rollbackLayout = (SteamLayout)typeof(BrokerEngine).GetField("_steamLayout",
            System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic)!.GetValue(rollbackEngine)!;
        rollbackLayout.SteamRoots.Add(directory);
        QuarantineManifest rollbackManifest = new() { IncidentId = Guid.NewGuid(), Records = [finalJournal!] };
        await rollbackEngine.ValidateRollbackManifestAsync(rollbackManifest, directory, rollbackManifest.IncidentId, CancellationToken.None);
        Check("Steam脚本正常回滚入口先认证新类型备份且预检不写目标", File.ReadAllBytes(path).SequenceEqual(repaired));
        await File.WriteAllBytesAsync(path + ".final-commit-failed", new byte[] { 1, 2, 3 });
        bool entryRejected = false;
        try { await rollbackEngine.ValidateRollbackManifestAsync(rollbackManifest, directory, rollbackManifest.IncidentId, CancellationToken.None); }
        catch (InvalidOperationException) { entryRejected = true; }
        Check("Steam脚本正常回滚入口在任何还原前拒绝篡改备份", entryRejected && File.ReadAllBytes(path).SequenceEqual(repaired));
        await File.WriteAllBytesAsync(path + ".final-commit-failed", original);
        await BrokerEngine.RestoreSteamScriptFileAsync(finalJournal!, layout, CancellationToken.None);
        Check("Steam脚本最终提交失败的持久记录随后仍可回滚", File.ReadAllBytes(path).SequenceEqual(original) &&
            File.ReadAllBytes(path + ".final-commit-failed").SequenceEqual(original));
        bool hashDenied = false;
        try
        {
            await BrokerEngine.RepairSteamScriptFileAsync(BrokerScriptActionCopy(action, repairedHash: new string('0', 64)),
                layout, path + ".wrong-hash", (_, _) => Task.CompletedTask, _ => { }, CancellationToken.None);
        }
        catch (InvalidOperationException) { hashDenied = true; }
        Check("Steam脚本Broker独立推导修复hash拒绝请求篡改", hashDenied && !File.Exists(path + ".wrong-hash") && File.ReadAllBytes(path).SequenceEqual(original));

        QuarantineRecord? interrupted = null;
        bool failed = false;
        try
        {
            await BrokerEngine.RepairSteamScriptFileAsync(action, layout, path + ".partial",
                (saved, _) => { interrupted = saved; return Task.CompletedTask; }, _ => { }, CancellationToken.None,
                async (lease, output) =>
                {
                    byte[] partial = original.ToArray();
                    Array.Copy(output, partial, original.Length / 2);
                    await lease.WriteSameLengthAsync(partial, CancellationToken.None);
                    throw new IOException("Inert injected partial write failure.");
                });
        }
        catch (IOException) { failed = true; }
        Check("Steam脚本局部写失败在同一锁定句柄恢复", failed && File.ReadAllBytes(path).SequenceEqual(original) &&
            interrupted is { FileMutationAttempted: true, MutationConfirmed: false } && File.Exists(path + ".partial"));
        byte[] partialImage = original.ToArray();
        Array.Copy(repaired, partialImage, original.Length / 2);
        await File.WriteAllBytesAsync(path, partialImage);
        await BrokerEngine.RestoreSteamScriptFileAsync(interrupted!, layout, CancellationToken.None);
        Check("Steam脚本中断attempt可以从认证备份回滚", File.ReadAllBytes(path).SequenceEqual(original));

        action = await BrokerScriptActionAsync(path, layout);
        QuarantineRecord rollback = await BrokerEngine.RepairSteamScriptFileAsync(action, layout, path + ".rollback-interrupted",
            (_, _) => Task.CompletedTask, _ => { }, CancellationToken.None);
        bool rollbackMarker = false, rollbackFailed = false;
        try
        {
            await BrokerEngine.RestoreSteamScriptFileAsync(rollback, layout, CancellationToken.None,
                (saved, _) => { rollbackMarker = saved.FileRollbackAttempted; return Task.CompletedTask; },
                async (lease, output) =>
                {
                    byte[] partial = repaired.ToArray();
                    Array.Copy(output, partial, original.Length / 2);
                    await lease.WriteSameLengthAsync(partial, CancellationToken.None);
                    throw new IOException("Inert injected rollback write failure.");
                });
        }
        catch (IOException) { rollbackFailed = true; }
        Check("Steam脚本回滚写前持久化intent且失败恢复修复后图像", rollbackMarker && rollbackFailed && File.ReadAllBytes(path).SequenceEqual(repaired));
        await File.WriteAllBytesAsync(path, partialImage);
        await BrokerEngine.RestoreSteamScriptFileAsync(rollback, layout, CancellationToken.None);
        Check("Steam脚本回滚中断可以用durable intent恢复", File.ReadAllBytes(path).SequenceEqual(original));

        await File.WriteAllBytesAsync(path, original);
        action = await BrokerScriptActionAsync(path, layout);
        QuarantineRecord updated = await BrokerEngine.RepairSteamScriptFileAsync(action, layout, path + ".updated",
            (_, _) => Task.CompletedTask, _ => { }, CancellationToken.None);
        byte[] steamUpdate = repaired.ToArray(); steamUpdate[0] ^= 1;
        await File.WriteAllBytesAsync(path, steamUpdate);
        bool updateDenied = false;
        try { await BrokerEngine.RestoreSteamScriptFileAsync(updated, layout, CancellationToken.None); }
        catch (InvalidOperationException) { updateDenied = true; }
        Check("Steam脚本回滚不覆盖同identity的Steam更新", updateDenied && File.ReadAllBytes(path).SequenceEqual(steamUpdate));
        File.Delete(path);
        await File.WriteAllBytesAsync(path, repaired);
        bool replacementDenied = false;
        try { await BrokerEngine.RestoreSteamScriptFileAsync(updated, layout, CancellationToken.None); }
        catch (InvalidOperationException) { replacementDenied = true; }
        Check("Steam脚本回滚不覆盖同内容的新文件identity", replacementDenied && File.ReadAllBytes(path).SequenceEqual(repaired));

        await File.WriteAllBytesAsync(path, original);
        action = await BrokerScriptActionAsync(path, layout);
        using CancellationTokenSource cancellation = new();
        bool canceled = false;
        try
        {
            await BrokerEngine.RepairSteamScriptFileAsync(action, layout, path + ".canceled",
                (_, _) => Task.CompletedTask, _ => cancellation.Cancel(), cancellation.Token);
        }
        catch (OperationCanceledException) { canceled = true; }
        Check("Steam脚本写前取消保留原件", canceled && File.ReadAllBytes(path).SequenceEqual(original));

        using CancellationTokenSource afterAttempt = new();
        QuarantineRecord complete = await BrokerEngine.RepairSteamScriptFileAsync(action, layout, path + ".cancel-after",
            (saved, _) => { if (saved.FileMutationAttempted) afterAttempt.Cancel(); return Task.CompletedTask; },
            _ => { }, afterAttempt.Token);
        Check("Steam脚本attempt后取消仍完成一致事务", complete.MutationConfirmed && File.ReadAllBytes(path).SequenceEqual(repaired));

        await File.WriteAllBytesAsync(path + ".cancel-after", new byte[] { 1, 2, 3 });
        bool backupDenied = false;
        try { await BrokerEngine.RestoreSteamScriptFileAsync(complete, layout, CancellationToken.None); }
        catch (InvalidOperationException) { backupDenied = true; }
        Check("Steam脚本回滚拒绝被修改的备份且保留修复文件", backupDenied && File.ReadAllBytes(path).SequenceEqual(repaired));

        await File.WriteAllBytesAsync(path, original);
        action = await BrokerScriptActionAsync(path, layout);
        string alias = Path.Combine(ui, "hardlink.js");
        bool linked = ScopeCreateHardLink(alias, path, IntPtr.Zero), linkDenied = false;
        try
        {
            if (linked)
                await BrokerEngine.RepairSteamScriptFileAsync(action, layout, path + ".hardlink",
                    (_, _) => Task.CompletedTask, _ => { }, CancellationToken.None);
        }
        catch (InvalidOperationException) { linkDenied = true; }
        finally { if (linked) File.Delete(alias); }
        Check("Steam脚本Broker拒绝多硬链接以免改写范围外副本", linked && linkDenied && File.ReadAllBytes(path).SequenceEqual(original));
        bool readonlyDenied = false, readonlyRetained = false;
        File.SetAttributes(path, FileAttributes.ReadOnly);
        try
        {
            await BrokerEngine.RepairSteamScriptFileAsync(action, layout, path + ".readonly",
                (_, _) => Task.CompletedTask, _ => { }, CancellationToken.None);
        }
        catch (Exception ex) when (ex is Win32Exception or UnauthorizedAccessException) { readonlyDenied = true; }
        finally { readonlyRetained = File.GetAttributes(path).HasFlag(FileAttributes.ReadOnly); File.SetAttributes(path, FileAttributes.Normal); }
        Check("Steam脚本只读文件拒绝写入且保留原件和属性", readonlyDenied && readonlyRetained &&
            !File.Exists(path + ".readonly") && File.ReadAllBytes(path).SequenceEqual(original));
        QuarantineRecord legacy = JsonSerializer.Deserialize<QuarantineRecord>("{\"Type\":4,\"OriginalTarget\":\"legacy\"}", JsonFile.Options)!;
        Check("Steam脚本新增manifest字段兼容旧隔离记录", legacy.Type == RemediationActionType.QuarantineFile &&
            !legacy.FileMutationAttempted && legacy.RepairedSha256 is null);
    }

    private static async Task<RemediationAction> BrokerScriptActionAsync(string path, SteamLayout layout)
    {
        SteamScriptRepairSnapshot capture = await SteamScriptRepairTarget.CaptureAsync(path, await Hashing.Sha256FileAsync(path), layout);
        return new RemediationAction
        {
            Type = RemediationActionType.RepairSteamScript, Target = path,
            ExpectedSha256 = capture.OriginalSha256, RepairedSha256 = capture.RepairedSha256,
            ExpectedFileIdentity = capture.FileIdentity, ExpectedParentIdentity = capture.ParentIdentity
        };
    }

    private static RemediationAction BrokerScriptActionCopy(RemediationAction action, string? target = null,
        string? identity = null, string? repairedHash = null) => new()
    {
        ActionId = action.ActionId, Type = action.Type, Target = target ?? action.Target,
        ExpectedSha256 = action.ExpectedSha256, RepairedSha256 = repairedHash ?? action.RepairedSha256,
        ExpectedFileIdentity = identity ?? action.ExpectedFileIdentity, ExpectedParentIdentity = action.ExpectedParentIdentity
    };

    private static void TestBrokerScriptProcessPrerequisites(string fixture)
    {
        string source = Path.Combine(fixture, "inert-resident.exe");
        string hash = SteamScriptRepairTarget.SourceHashes(RuleLoader.LoadEmbedded()).First();
        DateTimeOffset started = DateTimeOffset.UtcNow.AddSeconds(-5);
        RelatedProcessRead running = new(123456, started, source, DiagnosticReadStatus.Complete, "inert process identity");
        RemediationAction repair = new() { Type = RemediationActionType.RepairSteamScript, Target = Path.Combine(fixture, "fixture.js") };
        RemediationAction Stop(DateTimeOffset? start = null, string? path = null, int? pid = null) => new()
        {
            Type = RemediationActionType.StopProcess, Target = path ?? source, ExpectedSha256 = hash,
            ProcessId = pid ?? running.ProcessId, ProcessStartedAtUtc = start ?? started
        };
        Dictionary<string, string> proof = new(StringComparer.OrdinalIgnoreCase) { [source] = hash };
        static bool Denied(Action check)
        {
            try { check(); return false; }
            catch (InvalidOperationException) { return true; }
        }
        RemediationPlan valid = new() { Actions = [Stop(), repair] };
        BrokerEngine.RequireSteamScriptProcessDependencies(valid, proof, [running]);
        Check("Steam脚本Broker重建匹配PID启动时间的结束进程依赖", RemediationDependencies.Build(valid.Actions)[repair.ActionId].Contains(valid.Actions[0].ActionId) &&
            repair.DependsOnActionIds.Count == 0);
        Check("Steam脚本Broker拒绝省略结束已知源进程", Denied(() => BrokerEngine.RequireSteamScriptProcessDependencies(
            new() { Actions = [repair] }, proof, [running])));
        Check("Steam脚本Broker拒绝错误进程启动时间", Denied(() => BrokerEngine.RequireSteamScriptProcessDependencies(
            new() { Actions = [Stop(started.AddSeconds(-1)), repair] }, proof, [running])));
        Check("Steam脚本Broker拒绝错误PID", Denied(() => BrokerEngine.RequireSteamScriptProcessDependencies(
            new() { Actions = [Stop(pid: running.ProcessId + 1), repair] }, proof, [running])));
        Check("Steam脚本Broker拒绝同名不同路径的结束动作", Denied(() => BrokerEngine.RequireSteamScriptProcessDependencies(
            new() { Actions = [Stop(path: Path.Combine(fixture, "other", "inert-resident.exe")), repair] }, proof, [running])));
        Check("Steam脚本源文件已移除仍拒绝活进程", !File.Exists(source) && Denied(() => BrokerEngine.RequireSteamScriptProcessesStopped([source], [running])));
        BrokerEngine.RequireSteamScriptProcessesStopped([source], []);
        Check("Steam脚本全部源进程结束才允许后序", true);
        RelatedProcessRead unrelated = running with { ImagePath = Path.Combine(fixture, "other", "inert-resident.exe") };
        BrokerEngine.RequireSteamScriptProcessesStopped([source], [unrelated]);
        Check("Steam脚本进程检查不阻断同名不同路径进程", true);
        RelatedProcessRead inaccessible = running with { Status = DiagnosticReadStatus.AccessDenied, Detail = "inert-probe-denied" };
        bool uncertain = false;
        try { BrokerEngine.RequireSteamScriptProcessesStopped([source], [inaccessible]); }
        catch (InvalidOperationException ex) { uncertain = ex.Message.Contains("inert-probe-denied", StringComparison.Ordinal); }
        Check("Steam脚本相关进程权限未知保留真实原因并阻断", uncertain);
        BrokerEngine.RequireSteamScriptProcessesStopped([source], [inaccessible with { ImagePath = unrelated.ImagePath }]);
        Check("Steam脚本不把已识别无关路径的权限失败扩大为阻断", true);
        string currentImage = Environment.ProcessPath!;
        IReadOnlyList<RelatedProcessRead> actual = BrokerEngine.ReadSteamScriptSourceProcesses([currentImage]);
        using Process current = Process.GetCurrentProcess();
        Check("Steam脚本限定查询读取无害当前进程的精确路径与启动时间", actual.Any(process => process.ProcessId == Environment.ProcessId &&
            process.Status == DiagnosticReadStatus.Complete && process.StartedAtUtc?.UtcDateTime == current.StartTime.ToUniversalTime() &&
            Path.GetFullPath(process.ImagePath).Equals(Path.GetFullPath(currentImage), StringComparison.OrdinalIgnoreCase)));
    }
}
