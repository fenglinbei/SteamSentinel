using System.ComponentModel;
using System.IO;
using System.Security.Principal;
using System.Text.Json;
using System.Text.Json.Nodes;
using SteamSentinel.Broker;
using SteamSentinel.Core.Models;
using SteamSentinel.Core.Remediation;
using SteamSentinel.Core.Reporting;
using SteamSentinel.Core.Utilities;

namespace SteamSentinel.SelfTest;

internal static partial class Program
{
    private static async Task TestV030EndedResultsAsync(string root)
    {
        string directory = Path.Combine(root, "v030-ended-results");
        Directory.CreateDirectory(directory);
        string sid = WindowsIdentity.GetCurrent().User?.Value ?? throw new InvalidOperationException("A Windows user is required.");
        RemediationPlan plan = new()
        {
            RequestedBySid = sid,
            Actions = [new RemediationAction { Type = RemediationActionType.DeleteIncident, Target = "inert identity only; never executed" }]
        };
        RemediationRunResult unknown = V030EndedUnknown(plan);
        string reservedPath = Path.Combine(directory, $"reserved-{Guid.NewGuid():N}.json");
        int protectionChecks = 0;
        bool deniedWrite = false, deniedDelete = false;
        void CheckProtection()
        {
            if (++protectionChecks != 2) return;
            // These operations target only the inert fixture. Both must fail while the reader
            // retains its real Windows handle, including the second protection check.
            try { using FileStream writer = new(reservedPath, FileMode.Open, FileAccess.Write, FileShare.ReadWrite | FileShare.Delete); }
            catch (IOException ex) when ((ex.HResult & 0xffff) is 32 or 33) { deniedWrite = true; }
            try { File.Move(reservedPath, reservedPath + ".unexpected-move"); }
            catch (IOException ex) when ((ex.HResult & 0xffff) is 32 or 33) { deniedDelete = true; }
        }
        Task<RemediationRunResult?> ReadReserved() => ProtectedRemediationResultReader.TryReadFinishedForTestingAsync(
            plan, reservedPath, sid, () => { });

        await using (BrokerResultChannel channel = BrokerResultChannel.CreateForTesting(reservedPath))
        {
            Check("0.3.0 未写入但仍占用的 Broker 结果通道拒绝恢复", await V030EndedSharingDeniedAsync(ReadReserved));
            await channel.WriteAsync(unknown);
            Check("0.3.0 已刷盘但尚未关闭的 Broker 结果通道仍拒绝恢复", channel.HasWritten && await V030EndedSharingDeniedAsync(ReadReserved));
        }
        RemediationRunResult? closed = await ProtectedRemediationResultReader.TryReadFinishedForTestingAsync(
            plan, reservedPath, sid, CheckProtection);
        Check("0.3.0 已关闭结果通道可读取且保留真实未知结果",
            closed is { Disposition: RemediationRunDisposition.ExecutionUnknown, Success: false, Actions.Count: 0, Errors.Count: 1 } &&
            closed.PlanId == plan.PlanId && closed.PlanIdentitySha256 == unknown.PlanIdentitySha256 &&
            closed.StartedAtUtc == unknown.StartedAtUtc && closed.CompletedAtUtc == unknown.CompletedAtUtc &&
            closed.Errors.SequenceEqual(unknown.Errors));
        Check("0.3.0 恢复读取前后校验保护且读句柄始终排斥写入和删除", protectionChecks == 2 && deniedWrite && deniedDelete);
        Check("0.3.0 已结束未知结果仍被原严格结果校验拒绝", V030EndedRejected(() => ProtectedRemediationResultReader.Validate(plan, closed!)));
        bool replayDenied = false;
        try { await using BrokerResultChannel replay = BrokerResultChannel.CreateForTesting(reservedPath); }
        catch (IOException) { replayDenied = true; }
        Check("0.3.0 恢复读取不删除占位也不允许同计划重放", replayDenied && File.Exists(reservedPath));

        Check("0.3.0 结束结果恢复拒绝错误用户 SID", await V030EndedReadRejectedAsync(() =>
            ProtectedRemediationResultReader.TryReadFinishedForTestingAsync(plan, reservedPath, "S-1-5-21-1-2-3-9999", () => { })));
        Check("0.3.0 结束结果恢复拒绝缺失当前用户身份", await V030EndedReadRejectedAsync(() =>
            ProtectedRemediationResultReader.TryReadFinishedForTestingAsync(plan, reservedPath, null, () => { })));
        Check("0.3.0 结束结果恢复保留前置 ACL 拒绝", await V030EndedReadRejectedAsync(() =>
            ProtectedRemediationResultReader.TryReadFinishedForTestingAsync(plan, reservedPath, sid,
                () => throw new UnauthorizedAccessException("inert ACL rejection"))));
        int rejectingChecks = 0;
        Check("0.3.0 结束结果恢复保留读取后 ACL 拒绝", await V030EndedReadRejectedAsync(() =>
            ProtectedRemediationResultReader.TryReadFinishedForTestingAsync(plan, reservedPath, sid,
                () => { if (++rejectingChecks == 2) throw new UnauthorizedAccessException("inert post-read ACL rejection"); })) && rejectingChecks == 2);

        string wirePath = Path.Combine(directory, $"wire-{Guid.NewGuid():N}.json");
        Task<RemediationRunResult?> ReadWire() => ProtectedRemediationResultReader.TryReadFinishedForTestingAsync(plan, wirePath, sid, () => { });
        Check("0.3.0 缺失结果不推断原执行已结束", await ReadWire() is null);
        foreach ((string label, string text) in new[]
        {
            ("空占位", ""), ("截断", "{\"PlanId\":"), ("JSON null", "null"),
            ("超出长度上限", new string(' ', ProtectedRemediationResultReader.MaximumBytes + 1))
        })
        {
            await File.WriteAllTextAsync(wirePath, text);
            Check($"0.3.0 {label}结果不推断原执行已结束", await ReadWire() is null);
        }

        JsonObject wire = JsonSerializer.SerializeToNode(unknown, JsonFile.Options)!.AsObject();
        foreach (string field in new[] { "PlanId", "PlanIdentitySha256", "StartedAtUtc", "CompletedAtUtc", "Success", "Actions", "Errors", "VerificationStatus" })
        {
            JsonObject missing = (JsonObject)wire.DeepClone();
            missing.Remove(field);
            await File.WriteAllTextAsync(wirePath, missing.ToJsonString(JsonFile.Options));
            Check($"0.3.0 未知结果缺少 {field} 不采用模型默认值恢复", await V030EndedReadRejectedAsync(ReadWire));
        }
        string serialized = wire.ToJsonString(JsonFile.Options);
        await File.WriteAllTextAsync(wirePath, serialized.Insert(serialized.LastIndexOf('}'), ",\"success\":false"));
        Check("0.3.0 未知结果拒绝大小写冲突的重复 JSON 字段", await V030EndedReadRejectedAsync(ReadWire));

        (string Label, Action<JsonObject> Alter)[] invalid =
        [
            ("伪造计划指纹", value => value["PlanIdentitySha256"] = new string('A', 64)),
            ("其他计划 ID", value => value["PlanId"] = Guid.NewGuid()),
            ("空开始时间", value => value["StartedAtUtc"] = default(DateTimeOffset)),
            ("缺失结束时间", value => value["CompletedAtUtc"] = null),
            ("倒序结束时间", value => value["CompletedAtUtc"] = unknown.StartedAtUtc.AddSeconds(-1)),
            ("成功宣称", value => value["Success"] = true),
            ("空操作图", value => value["Actions"] = null),
            ("部分操作结果", value => value["Actions"] = JsonSerializer.SerializeToNode(new[] { new RemediationActionResult() }, JsonFile.Options)),
            ("空错误图", value => value["Errors"] = null),
            ("无错误原因", value => value["Errors"] = new JsonArray()),
            ("空白错误原因", value => value["Errors"] = new JsonArray(" ")),
            ("过长错误原因", value => value["Errors"] = new JsonArray(new string('x', 8193))),
            ("伪称已验证", value => value["VerificationStatus"] = "Verified"),
            ("伪称无残留", value => value["VerificationStatus"] = "NoResidual"),
            ("无效验证状态", value => value["VerificationStatus"] = 98765),
            ("关联清单", value => value["ManifestPath"] = "inert-manifest.json"),
            ("验证完成时间", value => value["VerificationCompletedAtUtc"] = unknown.CompletedAtUtc),
            ("验证结论文本", value => value["VerificationSummary"] = "Claimed clean"),
            ("错误描述数量不一致", value => value["ErrorMessages"] = new JsonArray()),
            ("无效错误描述 ID", value => value["ErrorMessages"] = JsonSerializer.SerializeToNode(new[] { new DisplayMessage("invalid id", []) }, JsonFile.Options)),
            ("错误描述空参数图", value => value["ErrorMessages"] = JsonSerializer.SerializeToNode(new[] { new DisplayMessage("Fixture.Error", null!) }, JsonFile.Options)),
            ("错误描述过深", value => value["ErrorMessages"] = JsonSerializer.SerializeToNode(new[] { V030EndedDeepMessage() }, JsonFile.Options))
        ];
        foreach ((string label, Action<JsonObject> alter) in invalid)
        {
            JsonObject changed = (JsonObject)wire.DeepClone();
            alter(changed);
            await File.WriteAllTextAsync(wirePath, changed.ToJsonString(JsonFile.Options));
            Check($"0.3.0 未知结束结果拒绝{label}", await V030EndedReadRejectedAsync(ReadWire));
        }

        RemediationPlan anotherSid = new()
        {
            PlanId = plan.PlanId,
            CreatedAtUtc = plan.CreatedAtUtc,
            ExpiresAtUtc = plan.ExpiresAtUtc,
            RequestedBy = plan.RequestedBy,
            RequestedBySid = "S-1-5-21-1-2-3-9999",
            Actions = plan.Actions
        };
        Check("0.3.0 结构校验中的计划指纹也绑定原请求 SID", V030EndedRejected(() => ProtectedRemediationResultReader.ValidateFinished(anotherSid, unknown)));
        RemediationRunResult unknownVerification = V030EndedUnknown(plan);
        unknownVerification.VerificationStatus = RemediationVerificationStatus.Unknown;
        ProtectedRemediationResultReader.ValidateFinished(plan, unknownVerification);
        Check("0.3.0 允许未检查或未知验证状态且不改写结果", unknownVerification.Disposition == RemediationRunDisposition.ExecutionUnknown &&
            !unknownVerification.Success && unknownVerification.VerificationStatus == RemediationVerificationStatus.Unknown);

        RemediationRunResult completed = new()
        {
            PlanId = plan.PlanId,
            PlanIdentitySha256 = RemediationPlanIdentity.Fingerprint(plan),
            StartedAtUtc = unknown.StartedAtUtc,
            CompletedAtUtc = unknown.CompletedAtUtc,
            Disposition = RemediationRunDisposition.Completed,
            Success = true,
            Actions = [new RemediationActionResult
            {
                ActionId = plan.Actions[0].ActionId, Type = plan.Actions[0].Type, Target = plan.Actions[0].Target,
                Success = true, ExecutionStatus = RemediationExecutionStatus.Succeeded
            }]
        };
        ProtectedRemediationResultReader.Validate(plan, completed);
        ProtectedRemediationResultReader.ValidateFinished(plan, completed);
        await JsonFile.WriteAtomicAsync(wirePath, completed);
        Check("0.3.0 普通成功结果沿用原严格校验与读取语义", await ReadWire() is { Disposition: RemediationRunDisposition.Completed, Success: true });
        completed.Actions[0].ExecutionStatus = RemediationExecutionStatus.ExecutionUnknown;
        Check("0.3.0 动作级未知不被已结束恢复协议放宽",
            V030EndedRejected(() => ProtectedRemediationResultReader.Validate(plan, completed)) &&
            V030EndedRejected(() => ProtectedRemediationResultReader.ValidateFinished(plan, completed)));
        completed.Actions.Clear();
        Check("0.3.0 普通成功结果缺少计划动作仍被两条校验拒绝",
            V030EndedRejected(() => ProtectedRemediationResultReader.Validate(plan, completed)) &&
            V030EndedRejected(() => ProtectedRemediationResultReader.ValidateFinished(plan, completed)));
        RemediationRunResult notStarted = V030EndedUnknown(plan);
        notStarted.Disposition = RemediationRunDisposition.NotStarted;
        ProtectedRemediationResultReader.Validate(plan, notStarted);
        ProtectedRemediationResultReader.ValidateFinished(plan, notStarted);
        Check("0.3.0 明确未开始结果仍沿用原严格校验", !notStarted.Success && notStarted.Disposition == RemediationRunDisposition.NotStarted);

        await JsonFile.WriteAtomicAsync(wirePath, unknown);
        using CancellationTokenSource cancelled = new();
        cancelled.Cancel();
        bool cancellationPreserved = false;
        try { _ = await ProtectedRemediationResultReader.TryReadFinishedForTestingAsync(plan, wirePath, sid, () => { }, cancelled.Token); }
        catch (OperationCanceledException) { cancellationPreserved = true; }
        Check("0.3.0 已结束结果读取响应取消且不改变原证据", cancellationPreserved && File.Exists(reservedPath));
    }

    private static RemediationRunResult V030EndedUnknown(RemediationPlan plan)
    {
        DateTimeOffset started = DateTimeOffset.UtcNow.AddMinutes(-1);
        RemediationRunResult result = new()
        {
            PlanId = plan.PlanId,
            PlanIdentitySha256 = RemediationPlanIdentity.Fingerprint(plan),
            StartedAtUtc = started,
            CompletedAtUtc = started.AddSeconds(1),
            Disposition = RemediationRunDisposition.ExecutionUnknown,
            Success = false
        };
        result.AddError(MessageText.Create("Backend.Exception", "IOException", "inert Broker exception fixture"));
        return result;
    }

    private static DisplayMessage V030EndedDeepMessage()
    {
        DisplayMessage value = new("Fixture.Error", []);
        for (int depth = 0; depth < DisplayMessage.MaximumDepth; depth++)
            value = new("Fixture.Error", [new DisplayArgument("inert nested descriptor", value)]);
        return value;
    }

    private static bool V030EndedRejected(Action action)
    {
        try { action(); return false; }
        catch (InvalidDataException) { return true; }
    }

    private static async Task<bool> V030EndedReadRejectedAsync(Func<Task<RemediationRunResult?>> action)
    {
        try { _ = await action(); return false; }
        catch (InvalidDataException) { return true; }
        catch (UnauthorizedAccessException) { return true; }
    }

    private static async Task<bool> V030EndedSharingDeniedAsync(Func<Task<RemediationRunResult?>> action)
    {
        try { _ = await action(); return false; }
        catch (Win32Exception ex) when (ex.NativeErrorCode is 32 or 33) { return true; }
        catch (IOException ex) when ((ex.HResult & 0xffff) is 32 or 33) { return true; }
    }
}
