using System.Security.Principal;
using System.Text.Json;
using SteamSentinel.Core.Models;
using SteamSentinel.Core.Scanning;
using SteamSentinel.Core.Utilities;

namespace SteamSentinel.Core.Remediation;

public static class ProtectedRemediationResultReader
{
    public const int MaximumBytes = 1024 * 1024;
    public static async Task<RemediationRunResult?> TryReadAsync(RemediationPlan plan, CancellationToken token = default)
    {
        if (plan.PlanId == Guid.Empty || plan.RequestedBySid != WindowsIdentity.GetCurrent().User?.Value)
            throw new UnauthorizedAccessException("病例计划身份与当前用户不一致。");
        string path = Path.Combine(AppPaths.ResultsRoot, $"result-{plan.PlanId:N}.json");
        if (!File.Exists(path)) return null;
        MachineStateSecurity.EnsureProtectedPath(AppPaths.MachineStateRoot);
        MachineStateSecurity.EnsureProtectedPath(AppPaths.ResultsRoot);
        MachineStateSecurity.EnsureProtectedPath(path);
        await using FileStream stream = RelatedArtifactReader.Open(path);
        if (stream.Length is <= 0 or > MaximumBytes) return null;
        RemediationRunResult? result;
        try { result = await JsonSerializer.DeserializeAsync<RemediationRunResult>(stream, JsonFile.Options, token).ConfigureAwait(false); }
        catch (JsonException) { return null; }
        RelatedArtifactReader.ValidatePath(stream.SafeFileHandle, Path.GetFullPath(path));
        MachineStateSecurity.EnsureProtectedPath(path);
        if (result is null) return null;
        Validate(plan, result);
        return result;
    }

    public static void Validate(RemediationPlan plan, RemediationRunResult result)
    {
        if (result.Actions is null || result.Errors is null) throw new InvalidDataException("管理员结果列表缺失。");
        if (!Validation.IsHexSha256(result.PlanIdentitySha256) ||
            !result.PlanIdentitySha256.Equals(RemediationPlanIdentity.Fingerprint(plan), StringComparison.OrdinalIgnoreCase) ||
            result.PlanId != plan.PlanId || result.CompletedAtUtc is null || result.StartedAtUtc == default ||
            result.Disposition == RemediationRunDisposition.ExecutionUnknown || !Enum.IsDefined(result.Disposition) ||
            result.Disposition == RemediationRunDisposition.NotStarted && (result.Success || result.Actions.Count != 0 || result.Errors.Count == 0) ||
            result.Disposition != RemediationRunDisposition.NotStarted && result.Actions.Count != plan.Actions.Count ||
            result.CompletedAtUtc < result.StartedAtUtc || result.Actions is null || result.Errors is null ||
            result.Actions.Count > 64 || result.Errors.Count > 128 ||
            result.Actions.Select(a => a.ActionId).Distinct().Count() != result.Actions.Count ||
            result.Actions.Any(a => a.ExecutionStatus == RemediationExecutionStatus.ExecutionUnknown || !Enum.IsDefined(a.ExecutionStatus)) ||
            result.Actions.Any(r => !plan.Actions.Any(a => a.ActionId == r.ActionId && a.Type == r.Type && a.Target == r.Target)) ||
            result.Success && (result.Actions.Count != plan.Actions.Count || result.Errors.Count > 0 || result.Actions.Any(a => !a.Success)))
            throw new InvalidDataException("管理员结果与原计划不匹配或尚未完整返回；保持执行状态未知。");
    }
}
