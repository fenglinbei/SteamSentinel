using System.Windows;
using System.Windows.Data;
using System.ComponentModel;
using SteamSentinel.Core.Models;
using SteamSentinel.Core.Reporting;

namespace SteamSentinel.App.Dialogs;

public partial class RemediationPreviewWindow : Window
{
    public RemediationPreviewWindow(RemediationPlan plan, IReadOnlyList<string>? notes = null)
    {
        InitializeComponent();
        DialogLayout.ConstrainToWorkArea(this);
        Plan = plan;
        PlanNotes = notes is { Count: > 0 } ? string.Join("\n", notes.Take(12)) + (notes.Count > 12 ? "\n更多说明请查看导出记录。" : "") : "已核对关联目标，下面列出本次实际将执行的动作。";
        Actions = plan.Actions
            .Select(action => new RemediationActionDisplayItem(
                ReportExporter.ActionLabel(action.Type),
                ConfidenceLabel(action),
                action.DisplayName,
                action.Target,
                (action.ExpectedSha256 ?? action.ExpectedValueData ?? string.Empty) +
                (action.RelatedFilePath is null ? "" : $"\n关联文件：{action.RelatedFilePath}\nSHA-256：{action.RelatedFileSha256}"),
                action.RelatedFilePath ?? action.Target))
            .ToArray();
        GroupedActions = CollectionViewSource.GetDefaultView(Actions);
        DataContext = this;
    }

    public RemediationPlan Plan { get; }
    public RemediationPreviewWindow(RemediationBatchSession batch) : this(new RemediationPlan
    { Actions = batch.Plans.SelectMany(p => p.Actions).ToList() }, batch.Notes)
    {
        Summary = batch.Summary + " 下面列出全部批次，一次确认后依次执行。Windows 可能逐批请求授权，取消或失败时暂停后续批次。";
        OmittedTargets = batch.Targets.Where(t => t.MissingActions.Count > 0 || t.ActionIds.Count == 0).ToArray();
        Actions = batch.Plans.SelectMany((p, i) => p.Actions.Select(action => new RemediationActionDisplayItem(
            ReportExporter.ActionLabel(action.Type), ConfidenceLabel(action), action.DisplayName, action.Target,
            (action.ExpectedSha256 ?? action.ExpectedValueData ?? string.Empty) +
            (action.RelatedFilePath is null ? "" : $"\n关联文件：{action.RelatedFilePath}\nSHA-256：{action.RelatedFileSha256}"),
            action.RelatedFilePath ?? action.Target, i + 1))).ToArray();
        GroupedActions = CollectionViewSource.GetDefaultView(Actions);
        DataContext = null; DataContext = this;
        if (OmittedTargets.Count > 0) PreviewTabs.SelectedIndex = 1;
    }

    public string Summary { get; } = "请核对本次列出的处置动作；未纳入方案的动作不会执行。";
    public IReadOnlyList<RemediationTargetOutcome> OmittedTargets { get; } = [];
    public string PlanNotes { get; }
    public IReadOnlyList<RemediationActionDisplayItem> Actions { get; }
    public ICollectionView GroupedActions { get; }

    private void PreviewLayout_SizeChanged(object sender, SizeChangedEventArgs e)
    {
        // Keep the plan's action order and batch labels instead of a second visual grouping.
        // The full action description and associated target remain available in row detail.
        PreviewActionsGrid.Tag = e.NewSize.Height < 440 ? "compact" : null;
    }

    private void ConfirmCheckBox_Changed(object sender, RoutedEventArgs e) =>
        ExecuteButton.IsEnabled = ConfirmCheckBox.IsChecked == true;

    private void Execute_Click(object sender, RoutedEventArgs e) => DialogResult = true;
    private void Cancel_Click(object sender, RoutedEventArgs e) => DialogResult = false;

    private static string ConfidenceLabel(RemediationAction action) => action.Type switch
    {
        RemediationActionType.QuarantineFile or RemediationActionType.QuarantineDirectory =>
            action.IsKnownMalware ? "已知恶意" : $"启发式 {action.ConfidenceScore}",
        _ => action.IsKnownMalware ? "已知关联" : action.RelatedFilePath is not null ? $"启发式关联 {action.ConfidenceScore}" : "配置处置"
    };
}

public sealed record RemediationActionDisplayItem(
    string Type,
    string Confidence,
    string DisplayName,
    string Target,
    string ExpectedIdentity,
    string Group,
    int Batch = 1);
