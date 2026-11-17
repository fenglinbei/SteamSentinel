using System.IO;
using System.Text.Json;
using System.Text.Json.Nodes;
using SteamSentinel.Broker;
using SteamSentinel.Core.Models;
using SteamSentinel.Core.Remediation;

namespace SteamSentinel.SelfTest;

internal static partial class Program
{
    // All termination is mocked. No sample, script, registry write or task is executed.
    private static async Task TestSteamAlertWatchdogBrokerAsync(string root)
    {
        string script = Path.Combine(root, "sa_watch.ps1");
        string host = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "WindowsPowerShell", "v1.0", "powershell.exe");
        string command = $"\"{host}\" -NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File \"{script}\" -InstallDir \"{root}\"";
        string imageHash = new('A', 64);
        DateTimeOffset started = DateTimeOffset.Parse("2026-11-17T12:00:00Z");
        RemediationAction stop = new()
        {
            Type = RemediationActionType.StopHostProcess,
            ConfigurationKind = SteamAlertWatchdog.ScriptHostKind,
            ConfigurationSnapshot = command,
            Target = host,
            ExpectedSha256 = imageHash,
            RelatedFilePath = script,
            RelatedFileSha256 = SteamAlertWatchdog.WatchdogHash,
            ProcessId = 51001,
            ProcessStartedAtUtc = started,
            IsKnownMalware = false,
            ConfidenceScore = 100
        };
        PowerShellScriptHostSnapshot live = new()
        {
            ProcessId = stop.ProcessId.Value,
            StartedAtUtc = started,
            ImagePath = host,
            CommandLine = command,
            Status = ScriptHostReadStatus.Readable
        };
        RemediationAction Change(string key, JsonNode? value)
        {
            JsonObject data = JsonSerializer.SerializeToNode(stop)!.AsObject();
            data[key] = value;
            return data.Deserialize<RemediationAction>()!;
        }
        async Task Denied(string label, RemediationAction request, PowerShellScriptHostSnapshot first,
            PowerShellScriptHostSnapshot? second = null, string? actualScriptHash = null, string? actualImageHash = null)
        {
            WatchdogFakeProcess process = new(first, second ?? first);
            bool denied = false;
            try
            {
                await SteamAlertScriptHostStopper.StopAsync(request, process,
                actualScriptHash ?? SteamAlertWatchdog.WatchdogHash, actualImageHash ?? imageHash, default);
            }
            catch (UnauthorizedAccessException) { denied = true; }
            Check("watchdog Broker " + label, denied && process.Kills == 0);
        }
        WatchdogFakeProcess approved = new(live, live);
        await SteamAlertScriptHostStopper.StopAsync(stop, approved, SteamAlertWatchdog.WatchdogHash, imageHash, default);
        Check("watchdog Broker 精确双读身份后仅终止批准实例", approved.Reads == 2 && approved.Kills == 1 && approved.Waits == 1);
        await Denied("伪造专用kind不授权", Change(nameof(stop.ConfigurationKind), "OtherHost"), live);
        await Denied("非宿主动作不借kind授权", Change(nameof(stop.Type), (int)RemediationActionType.StopProcess), live);
        await Denied("用户风险选择不借专用终止授权", Change(nameof(stop.UserSelectedRisk), true), live);
        await Denied("系统PowerShell映像不得被标为恶意", Change(nameof(stop.IsKnownMalware), true), live);
        await Denied("未知脚本hash拒绝", Change(nameof(stop.RelatedFileSha256), new string('B', 64)), live);
        await Denied("非系统宿主拒绝", Change(nameof(stop.Target), Path.Combine(root, "powershell.exe")), live);
        await Denied("脚本路径与命令不符拒绝", Change(nameof(stop.RelatedFilePath), Path.Combine(root, "other.ps1")), live);
        await Denied("表达式命令不借路径字符串授权", Change(nameof(stop.ConfigurationSnapshot), $"\"{host}\" -Command Write-Output \"{script}\""), live);
        await Denied("脚本字节被替换拒绝", stop, live, actualScriptHash: new string('C', 64));
        await Denied("宿主字节被替换拒绝", stop, live, actualImageHash: new string('D', 64));
        await Denied("不同PID拒绝", stop, live with { ProcessId = live.ProcessId + 1 });
        await Denied("PID复用拒绝", stop, live with { StartedAtUtc = started.AddSeconds(2) });
        await Denied("实时宿主路径被替换拒绝", stop, live with { ImagePath = Path.Combine(root, "powershell.exe") });
        await Denied("首次命令已改变拒绝", stop, live with { CommandLine = command + " -EveryMin 5" });
        await Denied("最后一次读取命令改变拒绝", stop, live, live with { CommandLine = command + " -EveryMin 5" });
        await Denied("不可读实时命令拒绝", stop, live with { CommandLine = null, Status = ScriptHostReadStatus.AccessDenied });
        await Denied("正常PowerShell命令不误杀", stop, live with { CommandLine = $"\"{host}\" -NoProfile -Command Get-Date" });
        WatchdogFakeProcess cancelled = new(live, live);
        using (CancellationTokenSource cancellation = new())
        {
            cancellation.Cancel();
            try { await SteamAlertScriptHostStopper.StopAsync(stop, cancelled, SteamAlertWatchdog.WatchdogHash, imageHash, cancellation.Token); }
            catch (OperationCanceledException) { }
        }
        Check("watchdog Broker 取消不终止", cancelled.Kills == 0);
        Check("watchdog Run 精确File绑定", BrokerEngine.IsBoundWatchdogInvocation(command, script));
        Check("watchdog Run 任意出现脚本路径不授权", !BrokerEngine.IsBoundWatchdogInvocation($"\"{host}\" -Command Write-Output \"{script}\"", script));
        RemediationAction? runTarget = BrokerEngine.WatchdogObservationTarget(new()
        {
            Type = RemediationActionType.RemoveRegistryValue,
            Target = command,
            RelatedFilePath = script,
            RelatedFileSha256 = SteamAlertWatchdog.WatchdogHash
        });
        Check("watchdog 仅删除Run也建立绑定脚本的只读观察目标", runTarget?.Target == script &&
            runTarget.ExpectedSha256 == SteamAlertWatchdog.WatchdogHash && runTarget.ProcessId is null);

        WatchdogFakeStateSource source = new() { Hash = SteamAlertWatchdog.WatchdogHash };
        SteamAlertWatchdogStateProbe observer = new(source);
        Check("watchdog 旧实例退出且无替代才无残留", (await observer.ObserveAsync(stop)).Status == RemediationVerificationStatus.NoResidual);
        source.Hosts = [live];
        Check("watchdog 同实例仍存活为残留", (await observer.ObserveAsync(stop)).Status == RemediationVerificationStatus.ResidualDetected);
        Check("watchdog 边界允许尚待批准Stop的原实例", (await observer.ObserveUnexpectedInstancesAsync(stop, [stop])).Status == RemediationVerificationStatus.NoResidual);
        source.Hosts = [live, live with { ProcessId = live.ProcessId + 2 }];
        Check("watchdog 边界不把新PID吸收到尚待Stop授权", (await observer.ObserveUnexpectedInstancesAsync(stop, [stop])).Status == RemediationVerificationStatus.Reappeared);
        source.Hosts = [live with { CommandLine = command + " -EveryMin 3" }];
        Check("watchdog 边界不豁免已改变command的待停实例", (await observer.ObserveUnexpectedInstancesAsync(stop, [stop])).Status == RemediationVerificationStatus.ResidualDetected);
        source.Hosts = [live with { ProcessId = live.ProcessId + 1, StartedAtUtc = started.AddSeconds(1) }];
        Check("watchdog 新PID复活被识别", (await observer.ObserveAsync(stop)).Status == RemediationVerificationStatus.Reappeared);
        source.Hosts = [live with { StartedAtUtc = started.AddSeconds(1) }];
        Check("watchdog 同PID新创建时间也为复活", (await observer.ObserveAsync(stop)).Status == RemediationVerificationStatus.Reappeared);
        source.Hash = null;
        Check("watchdog 脚本已删除但解释器存活不报干净", (await observer.ObserveAsync(stop)).Status == RemediationVerificationStatus.Reappeared);
        source.Hash = new string('E', 64);
        Check("watchdog 脚本替换后仍有宿主保留未知", (await observer.ObserveAsync(stop)).Status == RemediationVerificationStatus.Unknown);
        source.Hosts = [live with { CommandLine = command.Replace("sa_watch.ps1", "innocent.ps1", StringComparison.Ordinal) }];
        Check("watchdog 相同PID无关脚本不当恶意残留", (await observer.ObserveAsync(stop)).Status == RemediationVerificationStatus.NoResidual);
        source.Hosts = [live with { CommandLine = $"\"{host}\" -NoProfile -Command Get-Date" }];
        Check("watchdog 正常交互命令不当残留", (await observer.ObserveAsync(stop)).Status == RemediationVerificationStatus.NoResidual);
        source.Hosts = [live with { Status = ScriptHostReadStatus.AccessDenied, CommandLine = null }];
        Check("watchdog 不可读宿主不能断言干净", (await observer.ObserveAsync(stop)).Status == RemediationVerificationStatus.Unknown);
        source.Hosts = [live with { CommandLine = command + " -Unsupported 1" }];
        Check("watchdog 指向目标的未知语法保留未知", (await observer.ObserveAsync(stop)).Status == RemediationVerificationStatus.Unknown);
        source.Hosts = Enumerable.Repeat(live, SteamAlertWatchdogStateProbe.MaximumInstances + 1).ToArray();
        Check("watchdog 枚举超限不报干净", (await observer.ObserveAsync(stop)).Status == RemediationVerificationStatus.Unknown);

        source.Hash = null;
        source.Hosts = [live with { ProcessId = live.ProcessId + 1 }];
        RemediationAction quarantinedScript = new()
        {
            Type = RemediationActionType.QuarantineFile,
            Target = script,
            ExpectedSha256 = SteamAlertWatchdog.WatchdogHash
        };
        WindowsRemediationStateProbe windows = new((_, _) => Task.FromResult<string?>(null), watchdogProbe: observer);
        Check("watchdog 仅隔离文件计划也检查后来出现宿主", (await windows.ObserveAsync(quarantinedScript, default)).Status == RemediationVerificationStatus.Reappeared);
        source.Hosts = [];
        await File.WriteAllTextAsync(script, "# inert self-test fixture; never executed");
        Check("watchdog 无宿主但文件仍存在保持残留", (await windows.ObserveAsync(quarantinedScript, default)).Status == RemediationVerificationStatus.ResidualDetected);

        string payload = Path.Combine(root, "Application Frame Host.exe");
        RemediationAction stopPayload = new()
        {
            Type = RemediationActionType.StopProcess,
            Target = payload,
            ExpectedSha256 = SteamAlertWatchdog.ResidentHash,
            ProcessId = 52001,
            ProcessStartedAtUtc = started
        };
        source.Hash = SteamAlertWatchdog.ResidentHash;
        source.Images = [new(stopPayload.ProcessId.Value, started, payload, true)];
        Check("watchdog 边界允许尚待Stop的精确payload实例", (await observer.ObserveUnexpectedInstancesAsync(stopPayload, [stopPayload])).Status == RemediationVerificationStatus.NoResidual);
        source.Images = [new(stopPayload.ProcessId.Value, started, payload, true), new(52002, started.AddSeconds(1), payload, true)];
        Check("watchdog 边界仍拒绝原payload之外新增实例", (await observer.ObserveUnexpectedInstancesAsync(stopPayload, [stopPayload])).Status == RemediationVerificationStatus.Reappeared);
        source.Images = [new(52002, started.AddSeconds(1), payload, true)];
        Check("watchdog payload新PID复活被识别", (await observer.ObserveAsync(stopPayload)).Status == RemediationVerificationStatus.Reappeared);
        source.Hash = null;
        Check("watchdog payload文件移除仍有实例不报干净", (await observer.ObserveAsync(stopPayload)).Status == RemediationVerificationStatus.Reappeared);
        source.Hash = new string('F', 64);
        Check("watchdog payload路径被替换保留未知", (await observer.ObserveAsync(stopPayload)).Status == RemediationVerificationStatus.Unknown);
        source.Images = [new(52002, null, null, false)];
        Check("watchdog payload同名不可读不报干净", (await observer.ObserveAsync(stopPayload)).Status == RemediationVerificationStatus.Unknown);
        source.Images = [];
        Check("watchdog payload无新实例才无残留", (await observer.ObserveAsync(stopPayload)).Status == RemediationVerificationStatus.NoResidual);

        source.Hash = SteamAlertWatchdog.WatchdogHash;
        source.Hosts = [live with { ProcessId = live.ProcessId + 1 }];
        RemediationVerification verifier = new(windows);
        RemediationActionResult outcome = new() { ActionId = stop.ActionId, Success = true, ExecutionStatus = RemediationExecutionStatus.Succeeded };
        await verifier.ObserveAsync(stop, outcome, 1);
        source.Hosts = [];
        await verifier.ObserveAsync(stop, outcome, 2);
        Check("watchdog 本轮曾复活不能被最后瞬时消失抹掉", outcome.VerificationStatus == RemediationVerificationStatus.Reappeared);

        RemediationAction payloadAfter = new()
        {
            Type = RemediationActionType.StopProcess,
            Target = payload,
            ExpectedSha256 = SteamAlertWatchdog.ResidentHash,
            DependsOnActionIds = [stop.ActionId]
        };
        RemediationPlan plan = new() { Actions = [stop, payloadAfter] };
        RemediationRunResult run = new();
        List<Guid> executed = [];
        source.Hosts = [live with { ProcessId = live.ProcessId + 2 }];
        await BrokerActionSequencer.RunAsync(plan, run, new Dictionary<Guid, string>(),
            (action, _) => { executed.Add(action.ActionId); return Task.FromResult("inert successful stop"); },
            async (action, result, token) => { result.VerificationStatus = (await observer.ObserveAsync(action, token)).Status; },
            _ => Task.CompletedTask);
        Check("watchdog 前置复活阻断后续payload动作", executed.SequenceEqual([stop.ActionId]) &&
            run.Actions.Last().ExecutionStatus == RemediationExecutionStatus.SkippedDependency);
    }

    private sealed class WatchdogFakeProcess(params PowerShellScriptHostSnapshot[] snapshots) : ISteamAlertScriptHostProcess
    {
        public int Reads { get; private set; }
        public int Kills { get; private set; }
        public int Waits { get; private set; }
        public PowerShellScriptHostSnapshot Read() => snapshots[Math.Min(Reads++, snapshots.Length - 1)];
        public void Kill() => Kills++;
        public Task WaitForExitAsync(CancellationToken token) { Waits++; return Task.CompletedTask; }
    }

    private sealed class WatchdogFakeStateSource : ISteamAlertWatchdogStateSource
    {
        public IReadOnlyList<PowerShellScriptHostSnapshot> Hosts { get; set; } = [];
        public IReadOnlyList<PowerShellScriptHostSnapshot> HandoffHosts { get; set; } = [];
        public IReadOnlyList<SteamAlertImageObservation> Images { get; set; } = [];
        public string? Hash { get; set; }
        public IReadOnlyList<PowerShellScriptHostSnapshot> ReadScriptHosts(CancellationToken token) => Hosts;
        public IReadOnlyList<PowerShellScriptHostSnapshot> ReadHandoffHosts(CancellationToken token) => HandoffHosts;
        public IReadOnlyList<SteamAlertImageObservation> ReadImageInstances(string exactPath, CancellationToken token) => Images;
        public Task<string?> ReadFileHashAsync(string exactPath, CancellationToken token) => Task.FromResult(Hash);
    }
}
