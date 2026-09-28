using System.Globalization;
using System.Text;
using SteamSentinel.Core.Inspection;
using SteamSentinel.Core.Models;
using SteamSentinel.Core.Remediation;

namespace SteamSentinel.Core.Reporting;

/// <summary>Execution and verification remain independent; recorded free text is never parsed.</summary>
public static class RemediationResultPresentation
{
    public static string ExecutionLabel(RemediationExecutionStatus status, CultureInfo? culture = null)
    {
        using IDisposable scope = DisplayText.UseCulture(culture);
        return DisplayText.Get(Enum.IsDefined(status) ? "Execution." + status : "Common.Unknown");
    }
    public static string RunLabel(RemediationRunDisposition disposition, CultureInfo? culture = null)
    {
        using IDisposable scope = DisplayText.UseCulture(culture);
        return DisplayText.Get(Enum.IsDefined(disposition) ? "Run." + disposition : "Common.Unknown");
    }
    public static string SessionLabel(CaseSessionTransition transition, CultureInfo? culture = null)
    {
        using IDisposable scope = DisplayText.UseCulture(culture);
        return DisplayText.Get(Enum.IsDefined(transition) ? "Session." + transition : "Common.Unknown");
    }
    public static string Describe(RemediationActionResult result, CultureInfo? culture = null)
    {
        using IDisposable scope = DisplayText.UseCulture(culture);
        StringBuilder text = new(DisplayText.Format("Result.Action", ReportExporter.ActionLabel(result.Type), result.Target,
            ExecutionLabel(result.ExecutionStatus), RemediationVerification.Label(result.VerificationStatus)));
        text.AppendLine();
        text.AppendLine(DisplayText.Format(result.ResultMessage is null ? "Result.OriginalExecution" : "Result.ExecutionDetail", result.MessageText.Display));
        text.AppendLine(DisplayText.Format(result.VerificationSummaryMessage is null ? "Result.OriginalVerification" : "Result.VerificationDetail", result.VerificationSummaryText.Display));
        foreach (RemediationVerificationObservation observation in result.Verifications)
            text.AppendLine(DisplayText.Format("Result.VerificationPass", observation.Pass,
                RemediationVerification.Label(observation.Status), observation.MessageText.Display));
        text.AppendLine(DisplayText.Get("Result.Boundary"));
        return ScriptSignals.RedactSecrets(text.ToString());
    }
    public static string Describe(RemediationRunResult result, CultureInfo? culture = null)
    {
        using IDisposable scope = DisplayText.UseCulture(culture);
        StringBuilder text = new(DisplayText.Format("Result.Run", result.PlanId, result.IncidentId,
            RunLabel(result.Disposition), RemediationVerification.Label(result.VerificationStatus)));
        text.AppendLine();
        foreach (RemediationActionResult action in result.Actions) text.AppendLine(Describe(action));
        foreach (string error in result.DisplayErrors) text.AppendLine(error);
        return ScriptSignals.RedactSecrets(text.ToString());
    }
}
