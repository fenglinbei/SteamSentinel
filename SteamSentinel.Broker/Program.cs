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
        BrokerResultChannel? resultChannel = null;
        BrokerMutationLease? mutationLease = null;

        try
        {
            if (!IsAdministrator()) throw new UnauthorizedAccessException("处置 Broker 必须通过 UAC 以管理员身份运行。");
            InstallationSecurityStatus installation = InstallationSecurity.Evaluate();
            if (!installation.IsProtected) throw new UnauthorizedAccessException(installation.Message);

            RemediationPlan plan = await BrokerRequestReader.ReadAsync(planPath, expectedPlanSha256);
            boundPlanId = plan.PlanId;
            MachineStateSecurity.EnsureProtectedRoots();
            resultPath = Path.Combine(AppPaths.ResultsRoot, $"result-{plan.PlanId:N}.json");
            if (Directory.Exists(resultPath))
                return ResultChannelUnavailableExitCode;
            try
            {
                // FileMode.CreateNew is the PlanId execution reservation. It is held with FileShare.None
                // until the final result is durable, so concurrent elevated brokers cannot both execute.
                resultChannel = BrokerResultChannel.Create(resultPath, plan.RequestedBySid);
            }
            catch (IOException)
            {
                return ResultChannelUnavailableExitCode;
            }
            catch (UnauthorizedAccessException)
            {
                return ResultChannelUnavailableExitCode;
            }
            if (!BrokerMutationLease.TryAcquire(out mutationLease))
            {
                result = new RemediationRunResult
                {
                    PlanId = plan.PlanId,
                    Success = false,
                    CompletedAtUtc = DateTimeOffset.UtcNow,
                    Errors = { "另一个 SteamSentinel 管理员处置仍在运行；本计划尚未执行任何动作，请等待其完成后重新扫描。" }
                };
                if (!await TryWriteResultAsync(resultChannel, result))
                    return ResultChannelUnavailableExitCode;
                return 1;
            }
            if (!ConfirmPlan(plan))
            {
                result = new RemediationRunResult
                {
                    PlanId = plan.PlanId,
                    Success = false,
                    CompletedAtUtc = DateTimeOffset.UtcNow,
                    Errors = { "用户在管理员确认窗口取消了处置。" }
                };
                if (!await TryWriteResultAsync(resultChannel, result))
                    return ResultChannelUnavailableExitCode;
                return 3;
            }

            BrokerEngine engine = new();
            result = await engine.ExecuteAsync(plan);
            if (!await TryWriteResultAsync(resultChannel, result))
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
            if (resultChannel is not null && resultChannel.CanWrite &&
                !await TryWriteResultAsync(resultChannel, result))
                return ResultChannelUnavailableExitCode;
            return 1;
        }
        finally
        {
            mutationLease?.Dispose();
            if (resultChannel is not null) await resultChannel.DisposeAsync();
        }
    }

    private static async Task<bool> TryWriteResultAsync(BrokerResultChannel channel, RemediationRunResult result)
    {
        try
        {
            await channel.WriteAsync(result);
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
        return System.Windows.Forms.MessageBox.Show(
            BuildConfirmationMessage(plan),
            "SteamSentinel 管理员处置确认",
            System.Windows.Forms.MessageBoxButtons.YesNo,
            System.Windows.Forms.MessageBoxIcon.Warning,
            System.Windows.Forms.MessageBoxDefaultButton.Button2) == System.Windows.Forms.DialogResult.Yes;
    }

    internal static string BuildConfirmationMessage(RemediationPlan plan)
    {
        if (plan.Actions.Count == 1 && plan.Actions[0].Type == RemediationActionType.DeleteIncident)
        {
            return $"SteamSentinel 将永久删除隔离事件 {SanitizeForDialog(plan.Actions[0].Target)} 的事件记录与剩余备份。\n\n" +
                   "此操作无法撤销。Broker 仅允许清理所有记录均已回滚、已无活动隔离内容的事件；" +
                   "不要为了删除事件而回滚可疑样本。如有疑问，请选择“否”并保留隔离。\n\n是否继续？";
        }

        if (plan.Actions.Count == 1 && plan.Actions[0].Type == RemediationActionType.RollbackIncident)
        {
            return $"SteamSentinel 将尝试回滚隔离事件 {SanitizeForDialog(plan.Actions[0].Target)}。\n\n" +
                   "回滚可能重新启用曾被隔离的恶意文件、启动项、任务或网络配置。为防原目录父路径在管理员操作期间被替换，" +
                   "当前版本不会自动恢复整目录记录；遇到此类记录会停止并保留隔离副本。\n\n确认要继续回滚其余受支持记录吗？";
        }

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
        return message;
    }

    private static string SanitizeForDialog(string value)
    {
        string clean = new(value.Select(character => char.IsControl(character) ? ' ' : character).ToArray());
        return clean.Length <= 180 ? clean : clean[..177] + "...";
    }
}
