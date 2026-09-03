using System.Security.Principal;
using SteamSentinel.Core.Models;
using SteamSentinel.Core.Utilities;

namespace SteamSentinel.Broker;

internal static class Program
{
    private const int ResultChannelUnavailableExitCode = 10;

    [STAThread]
    private static async Task<int> Main(string[] args)
    {
        if (args.Length != 2) return 2;
        string planPath = args[0];
        string expectedPlanSha256 = args[1];
        string? resultPath = null;
        Guid boundPlanId = Guid.Empty;
        RemediationRunResult? result = null;

        try
        {
            if (!IsAdministrator()) throw new UnauthorizedAccessException("处置 Broker 必须通过 UAC 以管理员身份运行。");
            InstallationSecurityStatus installation = InstallationSecurity.Evaluate();
            if (!installation.IsProtected) throw new UnauthorizedAccessException(installation.Message);

            RemediationPlan plan = await BrokerRequestReader.ReadAsync(planPath, expectedPlanSha256);
            boundPlanId = plan.PlanId;
            MachineStateSecurity.EnsureProtectedRoots();
            resultPath = Path.Combine(AppPaths.ResultsRoot, $"result-{plan.PlanId:N}.json");
            if (File.Exists(resultPath) || Directory.Exists(resultPath))
                return ResultChannelUnavailableExitCode;
            if (!ConfirmPlan(plan))
            {
                result = new RemediationRunResult
                {
                    PlanId = plan.PlanId,
                    Success = false,
                    CompletedAtUtc = DateTimeOffset.UtcNow,
                    Errors = { "用户在管理员确认窗口取消了处置。" }
                };
                if (!await TryWriteResultAsync(resultPath, result))
                    return ResultChannelUnavailableExitCode;
                return 3;
            }

            BrokerEngine engine = new();
            result = await engine.ExecuteAsync(plan);
            if (!await TryWriteResultAsync(resultPath, result))
                return ResultChannelUnavailableExitCode;
            return result.Success ? 0 : 1;
        }
        catch (Exception ex)
        {
            result ??= new RemediationRunResult
            {
                PlanId = boundPlanId,
                Success = false,
                CompletedAtUtc = DateTimeOffset.UtcNow,
                Errors = { $"{ex.GetType().Name}: {ex.Message}" }
            };
            if (resultPath is not null && !await TryWriteResultAsync(resultPath, result))
                return ResultChannelUnavailableExitCode;
            return 1;
        }
    }

    private static async Task<bool> TryWriteResultAsync(string path, RemediationRunResult result)
    {
        try
        {
            await JsonFile.WriteNewAsync(path, result);
            return true;
        }
        catch
        {
            return false;
        }
    }

    private static bool IsAdministrator()
    {
        using WindowsIdentity identity = WindowsIdentity.GetCurrent();
        return new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
    }

    private static bool ConfirmPlan(RemediationPlan plan)
    {
        int heuristicQuarantines = plan.Actions.Count(action =>
            action.Type is RemediationActionType.QuarantineFile or RemediationActionType.QuarantineDirectory &&
            !action.IsKnownMalware);
        string heuristicText = heuristicQuarantines == 0
            ? "其中没有启发式隔离项。"
            : $"其中 {heuristicQuarantines} 项属于启发式判断，可能存在误报，请确认目标路径。";
        string[] visibleActions = plan.Actions.Take(12)
            .Select(action => $"• {action.Type}: {SanitizeForDialog(action.Target)}")
            .ToArray();
        string omitted = plan.Actions.Count > visibleActions.Length
            ? $"\n• 另有 {plan.Actions.Count - visibleActions.Length} 项，请返回主窗口分批核对"
            : string.Empty;
        string message = $"SteamSentinel 将执行 {plan.Actions.Count} 项管理员操作。\n\n{heuristicText}\n\n" +
                         string.Join("\n", visibleActions) + omitted + "\n\n" +
                         "文件与目录将先进入可回滚隔离区，不会立即永久删除。是否继续？";
        return System.Windows.Forms.MessageBox.Show(
            message,
            "SteamSentinel 管理员处置确认",
            System.Windows.Forms.MessageBoxButtons.YesNo,
            System.Windows.Forms.MessageBoxIcon.Warning,
            System.Windows.Forms.MessageBoxDefaultButton.Button2) == System.Windows.Forms.DialogResult.Yes;
    }

    private static string SanitizeForDialog(string value)
    {
        string clean = new(value.Select(character => char.IsControl(character) ? ' ' : character).ToArray());
        return clean.Length <= 180 ? clean : clean[..177] + "...";
    }
}
