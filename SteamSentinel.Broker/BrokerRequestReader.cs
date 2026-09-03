using System.Security.Principal;
using SteamSentinel.Core.Models;
using SteamSentinel.Core.Utilities;

namespace SteamSentinel.Broker;

internal static class BrokerRequestReader
{
    private const long MaximumPlanBytes = 1024 * 1024;

    public static async Task<RemediationPlan> ReadAsync(
        string planPath,
        string expectedSha256,
        CancellationToken cancellationToken = default)
    {
        if (!Validation.IsHexSha256(expectedSha256))
            throw new InvalidDataException("处置计划缺少有效的 SHA-256 绑定值。");

        string fullPath = ValidatePlanPath(planPath);
        await using SecureFileLease planLease = SecureFileLease.Open(
            fullPath,
            allowPackagedLocalAppDataRedirection: true);
        if (planLease.Length is <= 0 or > MaximumPlanBytes)
            throw new InvalidDataException("处置计划不存在或大小异常。");
        string actualSha256 = await planLease.ComputeSha256Async(cancellationToken).ConfigureAwait(false);
        if (!actualSha256.Equals(expectedSha256, StringComparison.OrdinalIgnoreCase))
            throw new InvalidDataException("处置计划在 UAC 前后发生变化，已拒绝执行。");

        RemediationPlan plan = await planLease.ReadJsonAsync<RemediationPlan>(cancellationToken).ConfigureAwait(false);
        string expectedName = $"plan-{plan.PlanId:N}.json";
        if (!Path.GetFileName(fullPath).Equals(expectedName, StringComparison.OrdinalIgnoreCase))
            throw new InvalidDataException("处置计划文件名与计划 ID 不一致。");

        string currentSid = WindowsIdentity.GetCurrent().User?.Value ?? string.Empty;
        if (string.IsNullOrWhiteSpace(plan.RequestedBySid) ||
            !plan.RequestedBySid.Equals(currentSid, StringComparison.OrdinalIgnoreCase))
        {
            throw new UnauthorizedAccessException("处置计划请求者与当前 UAC 身份不一致。");
        }

        return plan;
    }

    private static string ValidatePlanPath(string path)
    {
        string root = Path.TrimEndingDirectorySeparator(Path.GetFullPath(AppPaths.PlansRoot));
        string full = Path.GetFullPath(path);
        if (!full.StartsWith(root + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase) ||
            !Path.GetFileName(full).StartsWith("plan-", StringComparison.OrdinalIgnoreCase) ||
            !full.EndsWith(".json", StringComparison.OrdinalIgnoreCase))
        {
            throw new UnauthorizedAccessException("处置计划必须位于 SteamSentinel 用户计划目录。");
        }

        if (Validation.ContainsReparsePoint(Path.GetDirectoryName(full)!))
            throw new UnauthorizedAccessException("处置计划目录不能包含重解析点。");
        return full;
    }
}
