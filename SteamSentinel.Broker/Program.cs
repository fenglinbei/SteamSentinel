using SteamSentinel.Core.Reporting;
using System.Security.Principal;
using SteamSentinel.Core.Models;
using SteamSentinel.Core.Remediation;
using SteamSentinel.Core.Utilities;

namespace SteamSentinel.Broker;

internal static class Program
{
    private const int ResultChannelUnavailableExitCode = 10;

    [STAThread]
    private static async Task<int> Main(string[] args)
    {
        if (!TryInitializeDisplayLanguage(args)) return 2;
        string planPath = args[0];
        string expectedPlanSha256 = args[1];
        string? resultPath = null;
        Guid boundPlanId = Guid.Empty;
        string boundPlanIdentity = string.Empty;
        RemediationRunResult? result = null;
        BrokerResultChannel? resultChannel = null;
        BrokerMutationLease? mutationLease = null;

        try
        {
            if (!IsAdministrator()) throw MessageExceptions.Create(MessageText.Create("Backend.Broker.Program.Main.01"), sourceText => new UnauthorizedAccessException(sourceText));
            InstallationSecurityStatus installation = InstallationSecurity.Evaluate();
            if (!installation.IsProtected) throw SteamSentinel.Core.Reporting.MessageExceptions.Create(installation.MessageText, text => new UnauthorizedAccessException(text));

            RemediationPlan plan = await BrokerRequestReader.ReadAsync(planPath, expectedPlanSha256);
            boundPlanId = plan.PlanId;
            boundPlanIdentity = RemediationPlanIdentity.Fingerprint(plan);
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
                    PlanIdentitySha256 = boundPlanIdentity,
                    Success = false,
                    Disposition = RemediationRunDisposition.NotStarted,
                    CompletedAtUtc = DateTimeOffset.UtcNow
                };
                result.AddError(MessageText.Create("Backend.Broker.Program.Main.02"));
                if (!await TryWriteResultAsync(resultChannel, result))
                    return ResultChannelUnavailableExitCode;
                return 1;
            }
            if (!ConfirmPlan(plan))
            {
                result = new RemediationRunResult
                {
                    PlanId = plan.PlanId,
                    PlanIdentitySha256 = boundPlanIdentity,
                    Success = false,
                    Disposition = RemediationRunDisposition.NotStarted,
                    CompletedAtUtc = DateTimeOffset.UtcNow
                };
                result.AddError(MessageText.Create("Backend.Broker.Program.Main.03"));
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
                PlanIdentitySha256 = boundPlanIdentity,
                Success = false,
                Disposition = RemediationRunDisposition.ExecutionUnknown,
                CompletedAtUtc = DateTimeOffset.UtcNow
            };
            result.AddError(MessageText.Create("Backend.Exception", ex.GetType().Name, MessageExceptions.Describe(ex)).Limit(1700));
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

    internal static bool TryInitializeDisplayLanguage(string[] args)
    {
        if (args.Length is not (2 or 4)) return false;
        if (args.Length == 4 && (args[2] != "--ui-language" || args[3] is not ("en" or "zh-Hans"))) return false;
        DisplayText.InitializeApplicationCulture(args.Length == 4
            ? args[3] == "en" ? DisplayText.English : DisplayText.Chinese
            : DisplayText.Resolve(System.Globalization.CultureInfo.CurrentUICulture));
        return true;
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
            DisplayText.Get("Backend.Broker.Program.ConfirmPlan.01"),
            System.Windows.Forms.MessageBoxButtons.YesNo,
            System.Windows.Forms.MessageBoxIcon.Warning,
            System.Windows.Forms.MessageBoxDefaultButton.Button2) == System.Windows.Forms.DialogResult.Yes;
    }

    internal static string BuildConfirmationMessage(RemediationPlan plan)
    {
        if (plan.Actions.Count == 1 && plan.Actions[0].Type == RemediationActionType.DeleteIncident)
        {
            return DisplayText.Format("Backend.Broker.Program.BuildConfirmationMessage.01", (SanitizeForDialog(plan.Actions[0].Target))) +
                   DisplayText.Get("Backend.Broker.Program.BuildConfirmationMessage.02") +
                   DisplayText.Get("Backend.Broker.Program.BuildConfirmationMessage.03");
        }

        if (plan.Actions.Count == 1 && plan.Actions[0].Type == RemediationActionType.RollbackIncident)
        {
            return DisplayText.Format("Backend.Broker.Program.BuildConfirmationMessage.04", (SanitizeForDialog(plan.Actions[0].Target))) +
                   DisplayText.Get("Backend.Broker.Program.BuildConfirmationMessage.05") +
                   DisplayText.Get("Backend.Broker.Program.BuildConfirmationMessage.06");
        }

        int heuristicQuarantines = plan.Actions.Count(action =>
            action.Type is RemediationActionType.QuarantineFile or RemediationActionType.QuarantineDirectory &&
            !action.IsKnownMalware);
        string heuristicText = heuristicQuarantines == 0
            ? DisplayText.Get("Backend.Broker.Program.BuildConfirmationMessage.07")
            : DisplayText.Format("Backend.Broker.Program.BuildConfirmationMessage.08", (heuristicQuarantines));
        string[] visibleActions = plan.Actions.Take(12)
            .Select(action => $"• {action.Type}: {SanitizeForDialog(action.Target)}")
            .ToArray();
        string omitted = plan.Actions.Count > visibleActions.Length
            ? DisplayText.Format("Backend.Broker.Program.BuildConfirmationMessage.09", (plan.Actions.Count - visibleActions.Length))
            : string.Empty;
        string message = DisplayText.Format("Backend.Broker.Program.BuildConfirmationMessage.10", (plan.Actions.Count), (heuristicText)) +
                         string.Join("\n", visibleActions) + omitted + "\n\n" +
                         DisplayText.Get("Backend.Broker.Program.BuildConfirmationMessage.11");
        return message;
    }

    private static string SanitizeForDialog(string value)
    {
        string clean = new(value.Select(character => char.IsControl(character) ? ' ' : character).ToArray());
        return clean.Length <= 180 ? clean : clean[..177] + "...";
    }
}
