using System.IO;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Nodes;
using SteamSentinel.Broker;
using SteamSentinel.Core.Models;
using SteamSentinel.Core.Remediation;

namespace SteamSentinel.SelfTest;

internal static partial class Program
{
    // The positive termination path uses an injected process. No CMD or sample is run.
    private static async Task TestSteamAlertHandoffBrokerAsync(string root)
    {
        string script = Path.Combine(root, "sa_update_53001.cmd");
        string host = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "cmd.exe");
        string target = Path.Combine(root, "Application Frame Host.exe");
        SteamAlertUpdateHandoffDescriptor descriptor = new(script, 53001, target,
            Path.Combine(root, "Application Frame Host.new.exe"), target + ".bak");
        string command = $"\"{host}\" /c \"{script}\"";
        string scriptHash = new('B', 64), imageHash = new('A', 64);
        DateTimeOffset started = DateTimeOffset.Parse("2026-11-17T12:00:00Z");
        RemediationAction stop = new()
        {
            Type = RemediationActionType.StopHostProcess,
            ConfigurationKind = SteamAlertUpdateHandoff.ScriptHostKind,
            ContentEvidenceRuleId = SteamAlertUpdateHandoff.RuleId,
            ConfigurationSnapshot = command,
            Target = host,
            ExpectedSha256 = imageHash,
            RelatedFilePath = script,
            RelatedFileSha256 = scriptHash,
            ProcessId = 54001,
            ProcessStartedAtUtc = started,
            IsKnownMalware = false,
            ConfidenceScore = 100
        };
        SteamAlertUpdateHandoffProof proof = new(descriptor, scriptHash, [new(target, SteamAlertWatchdog.ResidentHash)]);
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
            PowerShellScriptHostSnapshot? second = null, SteamAlertUpdateHandoffProof? boundProof = null, string? actualImageHash = null)
        {
            WatchdogFakeProcess process = new(first, second ?? first);
            bool denied = false;
            try { await SteamAlertHandoffStopper.StopAsync(request, process, boundProof ?? proof, actualImageHash ?? imageHash, default); }
            catch (UnauthorizedAccessException) { denied = true; }
            Check("handoff Broker " + label, denied && process.Kills == 0);
        }
        WatchdogFakeProcess approved = new(live, live);
        await SteamAlertHandoffStopper.StopAsync(stop, approved, proof, imageHash, default);
        Check("handoff Broker 双读绑定后仅结束已批准CMD实例", approved.Reads == 2 && approved.Kills == 1 && approved.Waits == 1);
        await Denied("通用或PowerShell kind不能借用CMD", Change(nameof(stop.ConfigurationKind), SteamAlertWatchdog.ScriptHostKind), live);
        await Denied("错误内容证明规则不能授权", Change(nameof(stop.ContentEvidenceRuleId), "HEUR-OTHER"), live);
        await Denied("正版cmd映像不能标成恶意", Change(nameof(stop.IsKnownMalware), true), live);
        await Denied("用户风险选择不授权系统CMD", Change(nameof(stop.UserSelectedRisk), true), live);
        await Denied("非系统cmd拒绝", Change(nameof(stop.Target), Path.Combine(root, "cmd.exe")), live);
        await Denied("串联命令拒绝", Change(nameof(stop.ConfigurationSnapshot), command + " & echo harmless"), live);
        await Denied("普通echo命令不授权", Change(nameof(stop.ConfigurationSnapshot), $"\"{host}\" /c echo \"{script}\""), live);
        await Denied("伪造script hash拒绝", stop, live, boundProof: proof with { ScriptSha256 = new string('C', 64) });
        await Denied("证明指向其他script拒绝", stop, live, boundProof: proof with { Descriptor = descriptor with { ScriptPath = Path.Combine(root, "sa_update_53002.cmd") } });
        await Denied("没有恶意payload强绑定拒绝", stop, live, boundProof: proof with { Payloads = [] });
        await Denied("未知payload hash拒绝", stop, live, boundProof: proof with { Payloads = [new(target, new string('D', 64))] });
        await Denied("已知hash但payload路径不在模板拒绝", stop, live, boundProof: proof with { Payloads = [new(Path.Combine(root, "unrelated.exe"), SteamAlertWatchdog.ResidentHash)] });
        await Denied("宿主映像字节改变拒绝", stop, live, actualImageHash: new string('E', 64));
        await Denied("PID复用拒绝", stop, live with { StartedAtUtc = started.AddSeconds(1) });
        await Denied("执行前command改变拒绝", stop, live, live with { CommandLine = $"\"{host}\" /c echo harmless" });
        await Denied("command不可读拒绝", stop, live with { CommandLine = null, Status = ScriptHostReadStatus.AccessDenied });
        await Denied("实际宿主路径被替换拒绝", stop, live with { ImagePath = Path.Combine(root, "cmd.exe") });
        Check("handoff 双重proof比对不接受payload集合漂移", !BrokerEngine.SameHandoffProof(proof,
            proof with { Payloads = [new(descriptor.StagedExe, SteamAlertWatchdog.ResidentHash)] }));
        Check("handoff 双重proof比对不接受模板路径漂移", !BrokerEngine.SameHandoffProof(proof,
            proof with { Descriptor = descriptor with { BackupExe = Path.Combine(root, "changed.bak") } }));
        Check("handoff 双重proof比对完全一致通过", BrokerEngine.SameHandoffProof(proof, proof));

        // A named temporary command file alone is never evidence. The production lease
        // verifier must reject this harmless content even when its supplied hash is exact.
        await File.WriteAllTextAsync(script, "@echo off\r\nexit /b 0\r\n");
        string benignHash = Convert.ToHexString(SHA256.HashData(await File.ReadAllBytesAsync(script)));
        bool invalidTemplateDenied = false;
        try { await using SteamAlertHandoffLease ignored = await BrokerEngine.OpenHandoffProofLeaseAsync(script, benignHash, default); }
        catch (UnauthorizedAccessException) { invalidTemplateDenied = true; }
        Check("handoff 真实文件lease拒绝只有同名但无模板的文件", invalidTemplateDenied);

        WatchdogFakeStateSource source = new() { Hash = scriptHash, HandoffHosts = [live] };
        SteamAlertWatchdogStateProbe observer = new(source);
        Check("handoff 原CMD实例仍在为残留", (await observer.ObserveAsync(stop)).Status == RemediationVerificationStatus.ResidualDetected);
        Check("handoff 边界允许尚待Stop的精确CMD实例", (await observer.ObserveUnexpectedInstancesAsync(stop, [stop])).Status == RemediationVerificationStatus.NoResidual);
        source.HandoffHosts = [live, live with { ProcessId = live.ProcessId + 2 }];
        Check("handoff 边界不把新CMD吸收到原授权", (await observer.ObserveUnexpectedInstancesAsync(stop, [stop])).Status == RemediationVerificationStatus.Reappeared);
        source.HandoffHosts = [live with { ProcessId = live.ProcessId + 1 }];
        Check("handoff 新CMD实例为复活", (await observer.ObserveAsync(stop)).Status == RemediationVerificationStatus.Reappeared);
        source.Hash = null;
        Check("handoff cmd文件已删但进程仍在不报干净", (await observer.ObserveAsync(stop)).Status == RemediationVerificationStatus.Reappeared);
        source.Hash = new string('F', 64);
        Check("handoff cmd内容被替换仍有进程保留未知", (await observer.ObserveAsync(stop)).Status == RemediationVerificationStatus.Unknown);
        source.HandoffHosts = [live with { CommandLine = $"\"{host}\" /c echo harmless" }];
        Check("handoff 普通CMD不算绑定残留", (await observer.ObserveAsync(stop)).Status == RemediationVerificationStatus.NoResidual);
        source.HandoffHosts = [live with { Status = ScriptHostReadStatus.AccessDenied, CommandLine = null }];
        Check("handoff 无法读取CMD不报干净", (await observer.ObserveAsync(stop)).Status == RemediationVerificationStatus.Unknown);
        source.HandoffHosts = [live with { ProcessId = live.ProcessId + 2 }]; source.Hash = null;
        RemediationAction quarantine = new()
        {
            Type = RemediationActionType.QuarantineFile,
            Target = script,
            ExpectedSha256 = scriptHash,
            ContentEvidenceRuleId = SteamAlertUpdateHandoff.RuleId
        };
        WindowsRemediationStateProbe windows = new((_, _) => Task.FromResult<string?>(null), watchdogProbe: observer);
        Check("handoff 单独隔离cmd也检查后来的宿主", (await windows.ObserveAsync(quarantine, default)).Status == RemediationVerificationStatus.Reappeared);
    }
}
