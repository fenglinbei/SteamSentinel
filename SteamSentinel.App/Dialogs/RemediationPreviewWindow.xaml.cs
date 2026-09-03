using System.Windows;
using SteamSentinel.Core.Models;
using SteamSentinel.Core.Reporting;

namespace SteamSentinel.App.Dialogs;

public partial class RemediationPreviewWindow : Window
{
    public RemediationPreviewWindow(RemediationPlan plan)
    {
        InitializeComponent();
        Plan = plan;
        Actions = plan.Actions
            .Select(action => new RemediationActionDisplayItem(
                ReportExporter.ActionLabel(action.Type),
                ConfidenceLabel(action),
                action.DisplayName,
                action.Target,
                action.ExpectedSha256 ?? action.ExpectedValueData ?? string.Empty))
            .ToArray();
        DataContext = this;
    }

    public RemediationPlan Plan { get; }
    public IReadOnlyList<RemediationActionDisplayItem> Actions { get; }

    private void ConfirmCheckBox_Changed(object sender, RoutedEventArgs e) =>
        ExecuteButton.IsEnabled = ConfirmCheckBox.IsChecked == true;

    private void Execute_Click(object sender, RoutedEventArgs e) => DialogResult = true;
    private void Cancel_Click(object sender, RoutedEventArgs e) => DialogResult = false;

    private static string ConfidenceLabel(RemediationAction action) => action.Type switch
    {
        RemediationActionType.QuarantineFile or RemediationActionType.QuarantineDirectory =>
            action.IsKnownMalware ? "已知恶意" : $"启发式 {action.ConfidenceScore}",
        _ => action.IsKnownMalware ? "已知关联" : "配置处置"
    };
}

public sealed record RemediationActionDisplayItem(
    string Type,
    string Confidence,
    string DisplayName,
    string Target,
    string ExpectedIdentity);
