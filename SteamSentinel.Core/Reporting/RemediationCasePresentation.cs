using System.Text;
using System.Text.Json;
using SteamSentinel.Core.Models;
using SteamSentinel.Core.Remediation;
using SteamSentinel.Core.Inspection;

namespace SteamSentinel.Core.Reporting;

public static class RemediationCasePresentation
{
    public static string Render(RemediationCaseRecord record, System.Globalization.CultureInfo culture)
    {
        using IDisposable scope = DisplayText.UseCulture(culture);
        return Render(record);
    }

    public static string Label(CaseReverificationState state, System.Globalization.CultureInfo culture)
    {
        using IDisposable scope = DisplayText.UseCulture(culture);
        return Label(state);
    }

    public static string ActionIdentity(RemediationAction action, System.Globalization.CultureInfo culture)
    {
        using IDisposable scope = DisplayText.UseCulture(culture);
        return ActionIdentity(action);
    }

    public static string Label(CaseReverificationState state) => state switch
    {
        CaseReverificationState.ExecutionUncertain => DisplayText.Get("RemediationCase.Label.ExecutionUncertain.01"),
        CaseReverificationState.AwaitingSessionChange => DisplayText.Get("RemediationCase.Label.AwaitingSessionChange.01"),
        CaseReverificationState.SessionUnknown => DisplayText.Get("RemediationCase.Label.SessionUnknown.01"),
        CaseReverificationState.Incomplete => DisplayText.Get("RemediationCase.Label.Incomplete.01"),
        CaseReverificationState.ResidualDetected => DisplayText.Get("RemediationCase.Label.ResidualDetected.01"),
        CaseReverificationState.Reappeared => DisplayText.Get("RemediationCase.Label.Reappeared.01"),
        CaseReverificationState.SelectedTargetsVerified => DisplayText.Get("RemediationCase.Label.SelectedTargetsVerified.01"),
        CaseReverificationState.NotChecked => DisplayText.Get("RemediationCase.Label.01"),
        _ => DisplayText.Get("Common.Unknown")
    };

    public static string Render(RemediationCaseRecord record)
    {
        StringBuilder text = new();
        text.AppendLine(DisplayText.Get("RemediationCase.Render.01") + record.CaseId);
        text.AppendLine(DisplayText.Get("RemediationCase.Render.02") + record.UserSid);
        text.AppendLine(DisplayText.Get("RemediationCase.Render.03") + record.UpdatedAtUtc.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss zzz"));
        bool uncertain = record.PendingPlanIds.Count > 0 || record.ExecutionResults.Concat(record.BatchSession?.Results ?? [])
            .Any(r => r.Disposition == RemediationRunDisposition.ExecutionUnknown || r.Actions.Any(a => a.ExecutionStatus == RemediationExecutionStatus.ExecutionUnknown));
        text.AppendLine(DisplayText.Get("RemediationCase.Render.04") + Label(uncertain ? CaseReverificationState.ExecutionUncertain : record.Episodes.LastOrDefault()?.State ?? CaseReverificationState.NotChecked));
        text.AppendLine(DisplayText.Get("RemediationCase.Render.05") + record.PendingPlanIds.Count);
        text.AppendLine(DisplayText.Get("Case.WriterUnconfirmed"));
        text.AppendLine(DisplayText.Get("RemediationCase.Render.06"));
        if (record.BaselineSession is { } baseline)
            text.AppendLine(DisplayText.Format("RemediationCase.Render.07", (baseline.BootStatus), (baseline.LogonStatus), (baseline.DetailText.Display)));
        foreach (CaseVerificationEpisode episode in record.Episodes.TakeLast(32))
        {
            text.AppendLine();
            text.AppendLine($"{episode.StartedAtUtc.ToLocalTime():yyyy-MM-dd HH:mm:ss zzz} · {Label(episode.State)} · {RemediationResultPresentation.SessionLabel(episode.Transition)}");
            text.AppendLine(episode.SummaryText.Display);
            foreach (DiagnosticCheck check in episode.Checks.Take(256)) text.AppendLine(DisplayText.Format("RemediationCase.Render.08", (check.NameText.Display), (check.Status), (check.DetailText.Display)));
            foreach (CaseActionVerification target in episode.Targets.Take(256))
                text.AppendLine($"{ReportExporter.ActionLabel(target.Type)} · {target.Target}\n" + DisplayText.Format("Common.LabelValue", RemediationVerification.Label(target.Status), target.MessageText.Display));
        }
        foreach (MessageText note in record.NoteTexts.TakeLast(32)) text.AppendLine(DisplayText.Get("RemediationCase.Render.09") + note.Display);
        return ScriptSignals.RedactSecrets(text.ToString());
    }

    public static string ActionIdentity(RemediationAction action)
    {
        string identity = (action.ExpectedSha256 ?? action.ExpectedValueData ?? string.Empty) +
            (action.RelatedFilePath is null ? "" : DisplayText.Format("RemediationCase.ActionIdentity.01", (action.RelatedFilePath), (action.RelatedFileSha256)));
        if (action.BoundCertificate is { } certificate)
            identity += DisplayText.Format("RemediationCase.ActionIdentity.02", (certificate.TargetUserSid), (certificate.StoreLocation), (certificate.StoreName), (certificate.DerSha256), (certificate.PropertiesSha256));
        if (action.BoundProxy is { } proxy)
            identity += DisplayText.Get("RemediationCase.ActionIdentity.03") + JsonSerializer.Serialize(proxy, ReportPrivacy.ExportOptions);
        if (action.ConfigurationEvidenceRuleId is { } rule) identity += DisplayText.Get("RemediationCase.ActionIdentity.04") + rule + DisplayText.Get("RemediationCase.ActionIdentity.05");
        if (action.DependsOnActionIds.Count > 0) identity += DisplayText.Get("RemediationCase.ActionIdentity.06") + string.Join(", ", action.DependsOnActionIds);
        return ScriptSignals.RedactSecrets(identity);
    }
}
