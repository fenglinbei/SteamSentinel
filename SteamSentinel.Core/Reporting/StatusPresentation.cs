using System.Globalization;
using System.Resources;
using SteamSentinel.Core.Models;

namespace SteamSentinel.Core.Reporting;

/// <summary>The only direction is codes to text. No caller may parse the result.</summary>
public static class StatusPresentation
{
    private static readonly ResourceManager Resources = new("SteamSentinel.Core.Reporting.StatusMessages", typeof(StatusPresentation).Assembly);
    public static CultureInfo DefaultCulture => DisplayText.Culture;
    internal static string? Template(string id, CultureInfo culture) => Resources.GetString(id, culture);

    public static MessageText BatchText(RemediationBatchSession session)
    {
        static string Number(int value) => value.ToString("N0", DisplayText.Chinese);
        MessageText targets = MessageText.Status("Batch.Targets", Number(session.SelectedTargetCount));
        if (session.Targets.Count > session.SelectedTargetCount)
            targets += MessageText.Status("Batch.Associated", Number(session.Targets.Count - session.SelectedTargetCount));
        return targets + (!session.ExecutionStarted
            ? MessageText.Status("Batch.Preview", Number(session.PlannedCount), Number(session.Targets.Count(t => t.MissingActions.Count > 0 || t.ActionIds.Count == 0)), Number(session.Plans.Count))
            : MessageText.Status("Batch.Results", Number(session.CompletedCount), Number(session.ReviewRequiredCount), Number(session.FailedCount), Number(session.UnfinishedCount)));
    }

    public static string Format(StatusMessage message, CultureInfo? culture = null)
    {
        message.Validate();
        culture = culture is null ? DefaultCulture : DisplayText.Resolve(culture);
        string? template = Resources.GetString(message.MessageId, culture);
        if (template is null) return string.Format(culture, Resources.GetString("Message.Unknown", culture)!, message.MessageId);
        try { return string.Format(culture, template, message.Arguments.Cast<object>().ToArray()); }
        catch (FormatException) { return string.Format(culture, Resources.GetString("Message.Unknown", culture)!, message.MessageId); }
    }

    public static string Text(string id, CultureInfo? culture = null, params string[] arguments) =>
        Format(StatusMessage.Create(id, arguments), culture);

    public static StatusMessage ScanMessage(ScanReport report) => StatusMessage.Create(report.ExecutionState switch
    {
        ScanExecutionState.NotStarted => "Scan.NotStarted",
        ScanExecutionState.Running => "Scan.Running",
        ScanExecutionState.Cancelled => "Scan.Cancelled",
        ScanExecutionState.Failed => "Scan.Failed",
        ScanExecutionState.Completed when report.CompletedAtUtc is null => "Scan.Running",
        ScanExecutionState.Completed when report.Coverage == ScanCoverage.Complete => "Scan.Completed",
        ScanExecutionState.Completed => "Scan.CompletedWithGaps",
        _ => "Scan.Unknown"
    });

    public static string Scan(ScanReport report, CultureInfo? culture = null) => Format(ScanMessage(report), culture);
    public static string Target(RemediationTargetState state, CultureInfo? culture = null) =>
        Text("Target." + (Enum.IsDefined(state) ? state : RemediationTargetState.Unknown), culture);

    public static string Batch(RemediationBatchSession session, CultureInfo? culture = null)
    {
        culture = culture is null ? DefaultCulture : DisplayText.Resolve(culture);
        string Number(int value) => value.ToString("N0", culture);
        string targets = Text("Batch.Targets", culture, Number(session.SelectedTargetCount));
        if (session.Targets.Count > session.SelectedTargetCount)
            targets += Text("Batch.Associated", culture, Number(session.Targets.Count - session.SelectedTargetCount));
        return targets + (!session.ExecutionStarted
            ? Text("Batch.Preview", culture, Number(session.PlannedCount), Number(session.Targets.Count(t => t.MissingActions.Count > 0 || t.ActionIds.Count == 0)), Number(session.Plans.Count))
            : Text("Batch.Results", culture, Number(session.CompletedCount), Number(session.ReviewRequiredCount), Number(session.FailedCount), Number(session.UnfinishedCount)));
    }
}
