using System.Security.Principal;
using SteamSentinel.Core.Models;
using SteamSentinel.Core.Utilities;

namespace SteamSentinel.Broker;

internal static class Program
{
    [STAThread]
    private static async Task<int> Main(string[] args)
    {
        if (args.Length != 2) return 2;
        string planPath = args[0];
        string resultPath = args[1];
        RemediationRunResult? result = null;

        try
        {
            if (!IsAdministrator()) throw new UnauthorizedAccessException("处置 Broker 必须通过 UAC 以管理员身份运行。");
            EnsurePlanPath(planPath);
            EnsurePlanPath(resultPath);
            RemediationPlan plan = await JsonFile.ReadAsync<RemediationPlan>(planPath);
            BrokerEngine engine = new();
            result = await engine.ExecuteAsync(plan);
            await JsonFile.WriteAtomicAsync(resultPath, result);
            return result.Success ? 0 : 1;
        }
        catch (Exception ex)
        {
            result ??= new RemediationRunResult
            {
                PlanId = Guid.Empty,
                Success = false,
                CompletedAtUtc = DateTimeOffset.UtcNow,
                Errors = { $"{ex.GetType().Name}: {ex.Message}" }
            };
            try
            {
                string fullResult = Path.GetFullPath(resultPath);
                Directory.CreateDirectory(Path.GetDirectoryName(fullResult)!);
                await JsonFile.WriteAtomicAsync(fullResult, result);
            }
            catch
            {
                // The caller will detect a missing result file.
            }
            return 1;
        }
    }

    private static bool IsAdministrator()
    {
        using WindowsIdentity identity = WindowsIdentity.GetCurrent();
        return new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
    }

    private static void EnsurePlanPath(string path)
    {
        string root = Path.TrimEndingDirectorySeparator(Path.GetFullPath(AppPaths.PlansRoot));
        string full = Path.GetFullPath(path);
        if (!full.StartsWith(root + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase) ||
            !full.EndsWith(".json", StringComparison.OrdinalIgnoreCase))
        {
            throw new UnauthorizedAccessException("计划与结果文件必须位于 SteamSentinel 用户计划目录。");
        }

        if (Validation.ContainsReparsePoint(Path.GetDirectoryName(full)!))
        {
            throw new UnauthorizedAccessException("计划目录不能包含重解析点。");
        }
    }
}
