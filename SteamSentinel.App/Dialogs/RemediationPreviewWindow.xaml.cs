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
                action.DisplayName,
                action.Target))
            .ToArray();
        DataContext = this;
    }

    public RemediationPlan Plan { get; }
    public IReadOnlyList<RemediationActionDisplayItem> Actions { get; }

    private void ConfirmCheckBox_Changed(object sender, RoutedEventArgs e) =>
        ExecuteButton.IsEnabled = ConfirmCheckBox.IsChecked == true;

    private void Execute_Click(object sender, RoutedEventArgs e) => DialogResult = true;
    private void Cancel_Click(object sender, RoutedEventArgs e) => DialogResult = false;
}

public sealed record RemediationActionDisplayItem(string Type, string DisplayName, string Target);
