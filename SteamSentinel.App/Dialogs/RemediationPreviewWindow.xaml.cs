using System.Windows;
using System.Windows.Data;
using System.ComponentModel;
using SteamSentinel.Core.Models;
using SteamSentinel.Core.Reporting;
using SteamSentinel.Core.Remediation;
using SteamSentinel.Core.Steam;

namespace SteamSentinel.App.Dialogs;

public partial class RemediationPreviewWindow : Window
{
    public RemediationPreviewWindow(RemediationPlan plan, IReadOnlyList<string>? notes = null,
        RuleSet? rules = null, SteamLayout? layout = null) : this(plan, notes, rules, layout, null) { }

    private RemediationPreviewWindow(RemediationPlan plan, IReadOnlyList<string>? notes, RuleSet? rules,
        SteamLayout? layout, IEnumerable<(RemediationAction Action, int Batch, bool Explicit)>? entries)
    {
        InitializeComponent();
        DialogLayout.ConstrainToWorkArea(this);
        Plan = plan;
        PlanNotes = notes is { Count: > 0 } ? string.Join("\n", notes.Take(12)) + (notes.Count > 12 ? DisplayText.Get("Ui.RemediationPreviewWindow.xaml.Constructor.01") : "") : DisplayText.Get("Ui.RemediationPreviewWindow.xaml.Constructor.02");
        Actions = (entries ?? plan.Actions.Select(action => (action, 1, plan.ExplicitFileTargetsRequested)))
            .Select(entry => CreateDisplayItem(entry.Action, entry.Batch, entry.Explicit, rules, layout))
            .ToArray();
        NoticeText = DisplayText.Get("Ui.Xaml.RemediationPreviewWindow.003") + (plan.ExplicitFileTargetsRequested
            ? "\n" + DisplayText.Get("Scope.Ui.PreviewNotice") : string.Empty);
        ConfirmationText = DisplayText.Get(plan.ExplicitFileTargetsRequested ? "Scope.Ui.PreviewConfirm" : "Ui.Xaml.RemediationPreviewWindow.020");
        ScopeSummary = plan.ExplicitFileTargetsRequested ? DisplayText.Format("Scope.Ui.PreviewCounts",
            Actions.Count(action => action.ScopeStatus == FileScopeStatus.RequiresConsent),
            Actions.Count(action => action.IsSensitive),
            Actions.Count(action => action.ScopeStatus == FileScopeStatus.NeedsVerification && !action.IsSensitive)) : string.Empty;
        GroupedActions = CollectionViewSource.GetDefaultView(Actions);
        DataContext = this;
    }

    public RemediationPlan Plan { get; }
    public RemediationPreviewWindow(RemediationBatchSession batch, RuleSet? rules = null, SteamLayout? layout = null) : this(new RemediationPlan
    {
        Actions = batch.Plans.SelectMany(p => p.Actions).ToList(),
        ExplicitFileTargetsRequested = batch.Plans.Any(plan => plan.ExplicitFileTargetsRequested)
    }, batch.NoteTexts.Select(note => note.Display).ToArray(), rules, layout,
        batch.Plans.SelectMany((plan, index) => plan.Actions.Select(action => (action, index + 1, plan.ExplicitFileTargetsRequested))))
    {
        Summary = batch.Summary + DisplayText.Get("Ui.RemediationPreviewWindow.xaml.Constructor.03");
        OmittedTargets = batch.Targets.Where(t => t.MissingActions.Count > 0 || t.ActionIds.Count == 0).ToArray();
        DataContext = null; DataContext = this;
        if (OmittedTargets.Count > 0) PreviewTabs.SelectedIndex = 1;
    }

    public string Summary { get; } = DisplayText.Get("Ui.RemediationPreviewWindow.xaml.Summary.01");
    public IReadOnlyList<RemediationTargetOutcome> OmittedTargets { get; } = [];
    public string PlanNotes { get; }
    public string NoticeText { get; }
    public string ConfirmationText { get; }
    public string ScopeSummary { get; }
    public IReadOnlyList<RemediationActionDisplayItem> Actions { get; }
    public ICollectionView GroupedActions { get; }

    private static RemediationActionDisplayItem CreateDisplayItem(RemediationAction action, int batch,
        bool explicitTargets, RuleSet? rules, SteamLayout? layout)
    {
        FileScopeAssessment? scope = explicitTargets && action.Type == RemediationActionType.QuarantineFile &&
            rules is not null && layout is not null ? FileRemediationScope.Assess(action.Target, action.ExpectedSha256, rules, layout) : null;
        string label = scope?.Status switch
        {
            FileScopeStatus.RequiresConsent => DisplayText.Get("Scope.Ui.RequiresConsent.Label"),
            FileScopeStatus.SensitiveRequiresConsent => DisplayText.Get("Scope.Ui.Sensitive.Label"),
            FileScopeStatus.NeedsVerification => DisplayText.Get(scope.Sensitive ? "Scope.Ui.Sensitive.Label" : "Scope.Ui.NeedsVerification.Label"),
            FileScopeStatus.Blocked => DisplayText.Get("Scope.Ui.Blocked.Label"),
            _ => string.Empty
        };
        return new(ReportExporter.ActionLabel(action.Type), ConfidenceLabel(action), action.DisplayNameText.Display,
            action.Target, RemediationCasePresentation.ActionIdentity(action), action.RelatedFilePath ?? action.Target,
            batch, label, scope?.Message.Display ?? string.Empty, scope?.Status, scope?.Sensitive ?? false);
    }

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
    int Batch = 1,
    string ScopeLabel = "",
    string ScopeDetails = "",
    FileScopeStatus? ScopeStatus = null,
    bool IsSensitive = false);
