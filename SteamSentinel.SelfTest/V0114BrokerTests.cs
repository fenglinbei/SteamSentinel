using System.Diagnostics;
using System.Collections.Concurrent;
using System.IO;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using SteamSentinel.Broker;
using SteamSentinel.Core.Models;
using SteamSentinel.Core.Remediation;
using SteamSentinel.Core.Utilities;

namespace SteamSentinel.SelfTest;

internal static partial class Program
{
    // No ExecuteAsync, real persistence mutations, security setters or process termination in this suite.
    private static async Task TestV0114BrokerAsync(string root)
    {
        string folder = Path.Combine(root, "v0114-broker"); Directory.CreateDirectory(folder);
        RemediationAction run = new() { Type = RemediationActionType.RemoveRegistryValue, Target = "inert Run fixture" };
        RemediationAction task = new() { Type = RemediationActionType.RemoveScheduledTask, Target = @"\InertFixture" };
        RemediationAction file = new() { Type = RemediationActionType.QuarantineFile, Target = Path.Combine(folder, "gone.dll") };
        RemediationAction service = new() { Type = RemediationActionType.DisableService, Target = "InertFixtureService" };
        RemediationAction security = new() { Type = RemediationActionType.RestoreSecurityControls, Target = "Windows Security" };
        RemediationPlan plan = new() { Actions = [run, task, file, service, security] };
        ConcurrentDictionary<Guid, int> calls = new();
        RemediationVerification verifier = new(new V0114FixtureProbe((action, _) =>
        {
            int count = calls.AddOrUpdate(action.ActionId, 1, (_, previous) => previous + 1);
            RemediationVerificationStatus status = action == service ? RemediationVerificationStatus.PendingReboot :
                action == security ? RemediationVerificationStatus.Unknown :
                (action == run || action == task) && count == 2 ? RemediationVerificationStatus.ResidualDetected : RemediationVerificationStatus.NoResidual;
            return Task.FromResult(new RemediationVerificationObservation { Status = status, Message = new string('中', 4096) });
        }));
        RemediationRunResult result = new() { PlanId = plan.PlanId, Success = true };
        foreach (RemediationAction action in plan.Actions)
        {
            RemediationActionResult outcome = new() { ActionId = action.ActionId, Type = action.Type, Target = action.Target, Success = true, Message = "执行成功" };
            result.Actions.Add(outcome);
            await verifier.ObserveAsync(action, outcome, 1);
        }
        await verifier.CompleteAsync(plan, result, secondPassDelay: TimeSpan.Zero);
        Check("v0.1.14 执行成功与复验结论分离", result.Success && result.Actions.All(item => item.Success) && result.VerificationStatus == RemediationVerificationStatus.Reappeared);
        Check("v0.1.14 首次无残留后二次出现单独标记", result.Actions[0].VerificationStatus == RemediationVerificationStatus.Reappeared && result.Actions[0].Verifications[0].Status == RemediationVerificationStatus.NoResidual);
        Check("v0.1.14 任务复生无需实际注册任务测试", result.Actions[1].VerificationStatus == RemediationVerificationStatus.Reappeared);
        Check("v0.1.14 每动作恰好两次且诊断有界", calls.Values.All(count => count == 2) && result.Actions.All(item => item.Verifications.Count == 2 && item.Verifications.All(observation => observation.Message.Length <= 512)));
        Check("v0.1.14 待重启与未知不冒充清除", result.Actions[3].VerificationStatus == RemediationVerificationStatus.PendingReboot && result.Actions[4].VerificationStatus == RemediationVerificationStatus.Unknown);
        Check("v0.1.14 UI 汇总使用中文标签", result.VerificationSummary.Contains("再次出现") && !result.VerificationSummary.Contains("Reappeared") && !result.VerificationSummary.Contains('；'));

        RemediationActionResult failure = new() { ActionId = file.ActionId, Success = false, Message = "隔离失败" };
        RemediationVerification unknown = new(new V0114FixtureProbe((_, _) => throw new UnauthorizedAccessException("fixture denial")));
        await unknown.ObserveAsync(file, failure, 1);
        Check("v0.1.14 拒绝访问为未知，保留动作失败", failure.VerificationStatus == RemediationVerificationStatus.Unknown && !failure.Success && failure.Message == "隔离失败");
        using (CancellationTokenSource cancelled = new())
        {
            cancelled.Cancel();
            await unknown.ObserveAsync(file, failure, 2, cancelled.Token);
            Check("v0.1.14 有界复验取消不能伪装成功", failure.Verifications.Count == 2 && failure.VerificationStatus == RemediationVerificationStatus.Unknown);
        }
        RemediationActionResult lateUnknown = new() { Success = true };
        int sequence = 0;
        RemediationVerification uncertain = new(new V0114FixtureProbe((_, _) => Task.FromResult(new RemediationVerificationObservation
            { Status = ++sequence == 1 ? RemediationVerificationStatus.NoResidual : RemediationVerificationStatus.Unknown })));
        await uncertain.ObserveAsync(file, lateUnknown, 1); await uncertain.ObserveAsync(file, lateUnknown, 2);
        Check("v0.1.14 第二次探测未知覆盖旧的无残留断言", lateUnknown.VerificationStatus == RemediationVerificationStatus.Unknown);
        RemediationActionResult timed = new(); Stopwatch timer = Stopwatch.StartNew();
        RemediationVerification timeout = new(new V0114FixtureProbe(async (_, token) =>
        {
            await Task.Delay(Timeout.InfiniteTimeSpan, token);
            return new() { Status = RemediationVerificationStatus.Verified };
        }));
        await timeout.ObserveAsync(file, timed, 1);
        Check("v0.1.14 只读探测在固定期限内终止为未知", timed.VerificationStatus == RemediationVerificationStatus.Unknown && timer.Elapsed < TimeSpan.FromSeconds(7));

        DateTimeOffset started = DateTimeOffset.UtcNow.AddMinutes(-2);
        Check("v0.1.14 PID 复用不误判原进程仍运行", WindowsRemediationStateProbe.AssessProcessIdentity(started, started.AddMinutes(1), true).Status == RemediationVerificationStatus.NoResidual);
        Check("v0.1.14 PID 与启动时间均相同时仍有残留", WindowsRemediationStateProbe.AssessProcessIdentity(started, started, true).Status == RemediationVerificationStatus.ResidualDetected);
        Check("v0.1.14 缺少启动时间不猜测身份", WindowsRemediationStateProbe.AssessProcessIdentity(null, started, true).Status == RemediationVerificationStatus.Unknown);
        Check("v0.1.14 路径不存在可验证", WindowsRemediationStateProbe.PathState(file.Target).Status == RemediationVerificationStatus.NoResidual);
        Directory.CreateDirectory(file.Target);
        Check("v0.1.14 文件原路径换成目录也算残留", WindowsRemediationStateProbe.PathState(file.Target).Status == RemediationVerificationStatus.ResidualDetected);

        RemediationVerificationStatus Security(string mode = "Normal", bool? antivirus = true, bool? realtime = true,
            bool? behavior = true, bool thirdParty = false, bool known = true, bool error = false, int profiles = 3, bool reboot = false)
        {
            JsonElement state = JsonSerializer.SerializeToElement(new { Mode = mode, Antivirus = antivirus, Realtime = realtime, Behavior = behavior,
                ThirdParty = thirdParty, ThirdPartyKnown = known, DefenderError = error, FirewallError = false,
                FirewallCount = 3, FirewallEnabled = profiles, RebootRequired = reboot });
            return WindowsRemediationStateProbe.AssessSecurity(state).Status;
        }
        Check("v0.1.14 实际安全状态全部开启才验证", Security() == RemediationVerificationStatus.Verified);
        Check("v0.1.14 Defender 设置错误不被防火墙成功掩盖", Security(error: true) == RemediationVerificationStatus.Unknown);
        Check("v0.1.14 被动模式与第三方杀软保持未知", Security(mode: "Passive Mode", realtime: false) == RemediationVerificationStatus.Unknown && Security(thirdParty: true) == RemediationVerificationStatus.Unknown && Security(known: false) == RemediationVerificationStatus.Unknown);
        Check("v0.1.14 实际实时监控未恢复报告残留", Security(realtime: false) == RemediationVerificationStatus.ResidualDetected);
        Check("v0.1.14 系统明确要求重启才能待重启", Security(realtime: false, reboot: true) == RemediationVerificationStatus.PendingReboot);
        Check("v0.1.14 防火墙活动配置仍关闭报告残留", Security(profiles: 2) == RemediationVerificationStatus.ResidualDetected);
        Check("v0.1.14 缺字段不能假装开启", Security(behavior: null) == RemediationVerificationStatus.Unknown);
        Check("v0.1.14 hosts 精确双栈域名行验证", WindowsRemediationStateProbe.AssessHosts("0.0.0.0 inert.invalid\n:: inert.invalid # fixture", ["inert.invalid"]).Status == RemediationVerificationStatus.Verified);
        Check("v0.1.14 hosts 注释不能冒充阻断", WindowsRemediationStateProbe.AssessHosts("# 0.0.0.0 inert.invalid\n:: inert.invalid", ["inert.invalid"]).Status == RemediationVerificationStatus.ResidualDetected);
        Check("v0.1.14 hosts 冲突映射不能验证", WindowsRemediationStateProbe.AssessHosts("0.0.0.0 inert.invalid\n:: inert.invalid\n192.0.2.1 inert.invalid", ["inert.invalid"]).Status == RemediationVerificationStatus.ResidualDetected);

        List<string> scripts = [];
        WindowsRemediationStateProbe mockedWindows = new((script, _) => { scripts.Add(script); return Task.FromResult<string?>("NoResidual"); });
        await mockedWindows.ObserveAsync(task, default);
        await mockedWindows.ObserveAsync(service, default);
        Check("v0.1.14 任务和服务状态仅发出只读请求", scripts[0].Contains("GetTasks(1)") && scripts[1].Contains("Get-CimInstance") && !scripts.Any(script => script.Contains("Set-") || script.Contains("Remove-") || script.Contains("Stop-")));
        Guid networkIncident = Guid.NewGuid();
        RemediationAction firewall = new() { Type = RemediationActionType.AddProgramFirewallBlock, Target = Path.Combine(folder, "inert.exe") };
        string networkScript = "";
        WindowsRemediationStateProbe network = new((script, _) => { networkScript = script; return Task.FromResult<string?>("Verified"); }, networkIncident);
        Check("v0.1.14 程序阻断有实际只读验证路径", (await network.ObserveAsync(firewall, default)).Status == RemediationVerificationStatus.Verified &&
            networkScript.Contains("ActiveStore") && networkScript.Contains("Get-NetFirewallApplicationFilter") && networkScript.Contains("Get-NetFirewallPortFilter") &&
            networkScript.Contains(Convert.ToBase64String(Encoding.UTF8.GetBytes($"SteamSentinel-{networkIncident:N}-{firewall.ActionId:N}"))));
        RemediationRunResult old = JsonSerializer.Deserialize<RemediationRunResult>("{\"Success\":true,\"Actions\":[{\"Success\":true,\"Message\":\"legacy\"}]}", JsonFile.Options)!;
        Check("v0.1.14 旧结果兼容但不自动宣称已验证", old.Success && old.VerificationStatus == RemediationVerificationStatus.NotChecked && old.Actions[0].Verifications.Count == 0);
        string serialized = JsonSerializer.Serialize(result, JsonFile.Options);
        RemediationRunResult roundtrip = JsonSerializer.Deserialize<RemediationRunResult>(serialized, JsonFile.Options)!;
        Check("v0.1.14 双验证结果 JSON 往返", roundtrip.Actions[0].Verifications.Count == 2 && roundtrip.VerificationStatus == RemediationVerificationStatus.Reappeared && serialized.Length < 64 * 1024);

        string[] textFixtures = ["steam://open/supportalert SupportMessages HelpFrontPage steamhelper bSupportPopupMessage",
            "SteamKey20260310 CryptUnprotectData steam.exe /downloadlog/",
            "steam_save_mafile steam_outbox_list proconnector.cfd password"];
        string[] ruleIds = ["HEUR-STEAM-UI-PATCHER", "HEUR-STEAM-TOKEN-STEALER", "HEUR-STEAM-CREDENTIAL-PLUGIN"];
        BrokerEngine broker = new();
        MethodInfo openBound = typeof(BrokerEngine).GetMethod("OpenBoundLeaseAsync", BindingFlags.Instance | BindingFlags.NonPublic)!;
        MethodInfo proveProcess = typeof(BrokerEngine).GetMethod("VerifyDirectProcessContentAsync", BindingFlags.Instance | BindingFlags.NonPublic)!;
        async Task<bool> AllowsDirectProcess(string path, string hash, string? relatedPath = null)
        {
            RemediationAction action = new() { Type = RemediationActionType.StopProcess, Target = path, RelatedFilePath = relatedPath ?? path,
                ExpectedSha256 = hash, RelatedFileSha256 = hash, ProcessId = 123456, ProcessStartedAtUtc = started, ConfidenceScore = 99, IsKnownMalware = false };
            try
            {
                await using SecureFileLease lease = SecureFileLease.Open(path);
                await (Task)proveProcess.Invoke(broker, [action, lease, CancellationToken.None])!;
                return true;
            }
            catch (Exception ex) when (ex is UnauthorizedAccessException or TargetInvocationException) { return false; }
        }
        async Task<bool> Allows(RemediationAction action, string? command)
        {
            try
            {
                await using SecureFileLease lease = await (Task<SecureFileLease>)openBound.Invoke(broker, [action, command, CancellationToken.None])!;
                return true;
            }
            catch (Exception ex) when (ex is UnauthorizedAccessException or InvalidOperationException or TargetInvocationException) { return false; }
        }
        RemediationAction Binding(string path, string hash, int score = 99) => new()
        {
            Type = RemediationActionType.RemoveRegistryValue, RelatedFilePath = path, RelatedFileSha256 = hash,
            IsKnownMalware = false, ConfidenceScore = score, RegistryHive = "HKCU", RegistryView = "Default",
            RegistryKey = @"Software\Microsoft\Windows\CurrentVersion\Run", RegistryValueName = "InertFixture"
        };
        for (int index = 0; index < textFixtures.Length; index++)
        {
            string path = Path.Combine(folder, "strong" + index + ".js");
            await File.WriteAllTextAsync(path, textFixtures[index], index == 1 ? Encoding.Unicode : Encoding.UTF8);
            string hash = await Hashing.Sha256FileExclusiveAsync(path);
            RemediationAction binding = Binding(path, hash);
            Check("v0.1.14 独立强内容证明 " + ruleIds[index], await BoundContentEvidence.VerifyAsync(path, hash) == ruleIds[index]);
            Check("v0.1.14 安全 lease 下允许直接强特征绑定 " + index, await Allows(binding, '"' + path + '"') && !binding.IsKnownMalware);
            Check("v0.1.14 直接映像停止资格独立证明不实际停止 " + index, await AllowsDirectProcess(path, hash));
            Check("v0.1.14 关联 DLL 不授权关闭未知宿主 " + index, !await AllowsDirectProcess(path, hash, cleanPathForMismatch()));
            Check("v0.1.14 强特征路径只是 echo 文本也拒绝 " + index, !await Allows(binding, "cmd.exe /c echo \"" + path + "\""));
            await File.AppendAllTextAsync(path, " changed");
            Check("v0.1.14 内容仍强但哈希变化必须拒绝 " + index, !await Allows(binding, '"' + path + '"'));
            Check("v0.1.14 进程映像内容变化后停止资格拒绝 " + index, !await AllowsDirectProcess(path, hash));
        }
        string clean = Path.Combine(folder, "clean.js"); await File.WriteAllTextAsync(clean, "inert clean fixture");
        string cleanHash = await Hashing.Sha256FileExclusiveAsync(clean);
        Check("v0.1.14 恶意请求 99 分干净内容拒绝", !await Allows(Binding(clean, cleanHash), '"' + clean + '"'));
        Check("v0.1.14 恶意请求 99 分干净进程映像拒绝", !await AllowsDirectProcess(clean, cleanHash));
        string loader = Path.Combine(folder, "loader.py"); await File.WriteAllTextAsync(loader, "bootstrap_secret KEY_ENC payload.bin marshal decompress");
        Check("v0.1.14 80 分加载链不能冒充高置信绑定", await BoundContentEvidence.VerifyAsync(loader, await Hashing.Sha256FileExclusiveAsync(loader)) is null);
        string archive = Path.Combine(folder, "container.js"); await File.WriteAllBytesAsync(archive, [0x50, 0x4b, 3, 4, .. Encoding.UTF8.GetBytes(textFixtures[0])]);
        Check("v0.1.14 容器中的明文强特征不授予绑定", await BoundContentEvidence.VerifyAsync(archive, await Hashing.Sha256FileExclusiveAsync(archive)) is null);
        string large = Path.Combine(folder, "large.js");
        await using (FileStream stream = File.Create(large)) { stream.SetLength(BoundContentEvidence.MaximumBytes + 1); await stream.WriteAsync(Encoding.UTF8.GetBytes(textFixtures[0])); }
        Check("v0.1.14 超过 8MiB 不做无界管理员内容分析", await BoundContentEvidence.VerifyAsync(large, await Hashing.Sha256FileExclusiveAsync(large)) is null);
        Check("v0.1.14 明确脚本宿主参数支持", BoundContentEvidence.IsDirectInvocation("powershell.exe -NoProfile -File \"" + clean + "\"", clean));
        Check("v0.1.14 编码命令或命令表达式不猜测", !BoundContentEvidence.IsDirectInvocation("powershell.exe -Command echo \"" + clean + "\"", clean));
        Check("v0.1.14 相邻引号拼接不能伪造独立路径参数", !BoundContentEvidence.IsDirectInvocation('"' + clean + "\"suffix", clean));
        MethodInfo taskCommands = typeof(BrokerEngine).GetMethod("TaskCommands", BindingFlags.Static | BindingFlags.NonPublic)!;
        string xmlMention = "<Task><Data><Exec><Command>" + System.Security.SecurityElement.Escape(clean) +
            "</Command></Exec></Data><Actions><Exec><Command>C:\\inert.exe</Command></Exec></Actions></Task>";
        Check("v0.1.14 任务 Data 文本伪装 Exec 不可授权", !((string)taskCommands.Invoke(null, [xmlMention])!).Contains(clean, StringComparison.Ordinal));
        bool staleRejected = false;
        try { BrokerEngine.RequireTaskSnapshotHash(new string('a', 64), new string('b', 64)); }
        catch (InvalidOperationException) { staleRejected = true; }
        Check("v0.1.14 任务原始字节哈希变化仍明确拒绝", staleRejected);
        MethodInfo validate = typeof(BrokerEngine).GetMethod("ValidateAction", BindingFlags.Instance | BindingFlags.NonPublic)!;
        bool arbitraryRejected = false;
        try { validate.Invoke(broker, [new RemediationAction { Type = RemediationActionType.RemoveScheduledTask, TaskName = @"\Arbitrary", ExpectedSha256 = cleanHash, ConfidenceScore = 99 }]); }
        catch (TargetInvocationException) { arbitraryRejected = true; }
        Check("v0.1.14 99 分不授权任意任务名", arbitraryRejected);

        // Only query a synthetic fixture, not system resources. Verify the owner's handle remains open.
        await using (FileStream locked = new(clean, FileMode.Open, FileAccess.Read, FileShare.None))
        {
            FileOccupancyResult occupancy = FileOccupancy.Inspect(clean);
            Console.WriteLine("V0114_OCCUPANCY=" + occupancy.Status + ": " + FileOccupancy.Describe(occupancy));
            Check("v0.1.14 占用查询保留句柄并返回有界诊断", locked.CanRead && occupancy.Processes.Count <= FileOccupancy.MaximumProcesses && !string.IsNullOrWhiteSpace(occupancy.Diagnostic));
            Check("v0.1.14 占用信息包含 PID 与名称或说明不可确认", occupancy.Processes.All(process => process.ProcessId > 0) && FileOccupancy.Describe(occupancy).Length <= 900);
        }
        string[] nativeEntries = typeof(FileOccupancy).GetMethods(BindingFlags.NonPublic | BindingFlags.Static)
            .Select(method => method.GetCustomAttribute<DllImportAttribute>()?.EntryPoint).OfType<string>().ToArray();
        Check("v0.1.14 Restart Manager 只含会话与查询 API", nativeEntries.Length == 4 && nativeEntries.All(name => name is "RmStartSession" or "RmRegisterResources" or "RmGetList" or "RmEndSession"));

        string cleanPathForMismatch() => Path.Combine(folder, "different-module.dll");
    }

    private sealed class V0114FixtureProbe(Func<RemediationAction, CancellationToken, Task<RemediationVerificationObservation>> observe) : IRemediationStateProbe
    {
        public Task<RemediationVerificationObservation> ObserveAsync(RemediationAction action, CancellationToken cancellationToken) => observe(action, cancellationToken);
    }
}
