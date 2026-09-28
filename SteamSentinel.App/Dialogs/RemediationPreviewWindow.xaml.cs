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
        PlanNotes = notes is { Count: > 0 } ? string.Join("\n", notes.Take(12)) + (notes.Count > 12 ? DisplayText.Get("Ui.RemediationPreviewWindow.xaml.Constructor.01") : "") : DisplayText.Get("Ui.RemediationPreviewWindow.xaml.Constructor.02");
        Actions = plan.Actions
            .Select(action => new RemediationActionDisplayItem(
                ReportExporter.ActionLabel(action.Type),
                ConfidenceLabel(action),
                action.DisplayNameText.Display,
                action.Target,
                RemediationCasePresentation.ActionIdentity(action),
                action.RelatedFilePath ?? action.Target))
            .ToArray();
        GroupedActions = CollectionViewSource.GetDefaultView(Actions);
        DataContext = this;
    }

    public RemediationPlan Plan { get; }
    public RemediationPreviewWindow(RemediationBatchSession batch) : this(new RemediationPlan
    { Actions = batch.Plans.SelectMany(p => p.Actions).ToList() }, batch.NoteTexts.Select(note => note.Display).ToArray())
    {
        Summary = batch.Summary + DisplayText.Get("Ui.RemediationPreviewWindow.xaml.Constructor.03");
        OmittedTargets = batch.Targets.Where(t => t.MissingActions.Count > 0 || t.ActionIds.Count == 0).ToArray();
        Actions = batch.Plans.SelectMany((p, i) => p.Actions.Select(action => new RemediationActionDisplayItem(
            ReportExporter.ActionLabel(action.Type), ConfidenceLabel(action), action.DisplayNameText.Display, action.Target,
            RemediationCasePresentation.ActionIdentity(action),
            action.RelatedFilePath ?? action.Target, i + 1))).ToArray();
        GroupedActions = CollectionViewSource.GetDefaultView(Actions);
        DataContext = null; DataContext = this;
        if (OmittedTargets.Count > 0) PreviewTabs.SelectedIndex = 1;
    }

    public string Summary { get; } = DisplayText.Get("Ui.RemediationPreviewWindow.xaml.Summary.01");
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
            action.IsKnownMalware ? DisplayText.Get("Ui.RemediationPreviewWindow.xaml.ConfidenceLabel.01") : DisplayText.Format("Ui.RemediationPreviewWindow.xaml.ConfidenceLabel.02", (action.ConfidenceScore)),
        _ => action.IsKnownMalware ? DisplayText.Get("Ui.RemediationPreviewWindow.xaml.ConfidenceLabel.03") : action.RelatedFilePath is not null ? DisplayText.Format("Ui.RemediationPreviewWindow.xaml.ConfidenceLabel.04", (action.ConfidenceScore)) : DisplayText.Get("Ui.RemediationPreviewWindow.xaml.ConfidenceLabel.05")
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
