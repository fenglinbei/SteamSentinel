using System.Windows;
using System.Windows.Automation;
using SteamSentinel.App.Services;
using SteamSentinel.Core.Models;
using SteamSentinel.Core.Remediation;
using SteamSentinel.Core.Reporting;

namespace SteamSentinel.App;

public partial class MainWindow
{
    internal enum RemediationAvailabilityState
    {
        Ready, Busy, RestartRequired, RecoveryUnavailable, PreviousExecutionUnresolved,
        RescanRequired, EndedUnknownRescanRequired, ScanRequired, NoActionableFindings, ReviewRequired,
        InstallationUnavailable, EndedUnknown, EndedUnknownNoActionableFindings
    }

    internal enum RemediationAvailabilityAction { None, CheckRecovery, Rescan, CheckInstallation, ViewRecords }

    internal readonly record struct RemediationAvailability(
        RemediationAvailabilityState State, RemediationAvailabilityAction Action, bool CanRemediate);

    internal RemediationAvailability GetRemediationAvailability() =>
        GetRemediationAvailability(FindingHandlingPresentation.Count(VisibleRemediationFindings.Select(item => item.Handling)));

    private RemediationAvailability GetRemediationAvailability(FindingHandlingCounts counts)
    {
        if (_busy) return new(RemediationAvailabilityState.Busy, RemediationAvailabilityAction.None, false);
        if (_recoveryRequired) return new(RemediationAvailabilityState.RestartRequired, RemediationAvailabilityAction.ViewRecords, false);
        if (_caseRecoveryUnavailable) return new(RemediationAvailabilityState.RecoveryUnavailable, RemediationAvailabilityAction.CheckRecovery, false);
        if (_remediationClient.HasUnresolvedExecution)
            return new(RemediationAvailabilityState.PreviousExecutionUnresolved, RemediationAvailabilityAction.CheckRecovery, false);
        if (_reportNeedsRefresh) return _lastReport is null
            ? new(RemediationAvailabilityState.ScanRequired, RemediationAvailabilityAction.None, false)
            : new(_hasEndedUnknownExecution ? RemediationAvailabilityState.EndedUnknownRescanRequired : RemediationAvailabilityState.RescanRequired,
                RemediationAvailabilityAction.Rescan, false);
        if (counts.SelectableCount == 0)
        {
            if (_hasEndedUnknownExecution) return new(RemediationAvailabilityState.EndedUnknownNoActionableFindings, RemediationAvailabilityAction.ViewRecords, false);
            return new(_lastReport is null ? RemediationAvailabilityState.ScanRequired
                : counts.AttentionCount > 0 ? RemediationAvailabilityState.ReviewRequired : RemediationAvailabilityState.NoActionableFindings,
                RemediationAvailabilityAction.None, false);
        }
        if (!_installationSecurity.CanRemediate)
            return new(RemediationAvailabilityState.InstallationUnavailable, RemediationAvailabilityAction.CheckInstallation, false);
        return _hasEndedUnknownExecution
            ? new(RemediationAvailabilityState.EndedUnknown, RemediationAvailabilityAction.ViewRecords, true)
            : new(RemediationAvailabilityState.Ready, RemediationAvailabilityAction.None, true);
    }

    private static string RemediationAvailabilityText(RemediationAvailabilityState state) => state switch
    {
        RemediationAvailabilityState.Busy => DisplayText.Get("Ui.TrustProxy.UpdateRemediationEligibility.01"),
        RemediationAvailabilityState.RestartRequired => DisplayText.Get("Ui.RemediationAvailability.RestartRequired"),
        RemediationAvailabilityState.RecoveryUnavailable => DisplayText.Get("Ui.RemediationAvailability.RecoveryUnavailable"),
        RemediationAvailabilityState.PreviousExecutionUnresolved => DisplayText.Get("Ui.TrustProxy.UpdateRemediationEligibility.02"),
        RemediationAvailabilityState.RescanRequired => DisplayText.Get("Ui.TrustProxy.UpdateRemediationEligibility.03"),
        RemediationAvailabilityState.EndedUnknownRescanRequired => DisplayText.Get("Ui.RemediationAvailability.EndedUnknownRescanRequired"),
        RemediationAvailabilityState.ScanRequired => DisplayText.Get("Ui.RemediationAvailability.ScanRequired"),
        RemediationAvailabilityState.NoActionableFindings => DisplayText.Get("Ui.TrustProxy.UpdateRemediationEligibility.05"),
        RemediationAvailabilityState.ReviewRequired => DisplayText.Get("Ui.TrustProxy.UpdateRemediationEligibility.04"),
        RemediationAvailabilityState.InstallationUnavailable => DisplayText.Get("Ui.RemediationAvailability.InstallationUnavailable"),
        RemediationAvailabilityState.EndedUnknown => DisplayText.Get("Ui.RemediationAvailability.EndedUnknown"),
        RemediationAvailabilityState.EndedUnknownNoActionableFindings => DisplayText.Get("Ui.RemediationAvailability.EndedUnknownNoActionableFindings"),
        _ => DisplayText.Get("Ui.RemediationAvailability.Ready")
    };

    private static readonly System.Windows.Media.Brush SubtleAvailabilityForeground = FreezeBrush(0x64, 0x74, 0x8B);
    private static readonly System.Windows.Media.Brush BlockedAvailabilityBackground = FreezeBrush(0xF8, 0xFA, 0xFC);
    private static readonly System.Windows.Media.Brush BlockedAvailabilityBorder = FreezeBrush(0xCB, 0xD5, 0xE1);
    private static readonly System.Windows.Media.Brush BlockedAvailabilityForeground = FreezeBrush(0x33, 0x41, 0x55);

    private void UpdateRemediationAvailabilityPresentation(RemediationAvailability availability)
    {
        if (RemediationAvailabilityTextBlock is null || RemediationAvailabilityActionButton is null) return;
        // Routine guidance needs only one subtle text line. While the activity banner is visible,
        // it already explains a busy operation; do not reserve a duplicate footer row.
        // Recovery, rescan and installation blockers keep their full inline explanation/action.
        bool compact = availability.Action == RemediationAvailabilityAction.None;
        RemediationAvailabilityPanel.Tag = ReferenceFindings.Count > 0 && PriorityFindings.Count == 0 &&
            availability.State is RemediationAvailabilityState.NoActionableFindings or RemediationAvailabilityState.ReviewRequired
                ? "reference-only" : (object)(availability.State == RemediationAvailabilityState.Busy);
        RemediationAvailabilityPanel.Background = compact ? System.Windows.Media.Brushes.Transparent : BlockedAvailabilityBackground;
        RemediationAvailabilityPanel.BorderBrush = BlockedAvailabilityBorder;
        RemediationAvailabilityPanel.Margin = compact ? new Thickness(0, 3, 0, 0) : new Thickness(0, 4, 0, 0);
        RemediationAvailabilityPanel.Padding = compact ? new Thickness(2, 2, 2, 0) : new Thickness(10, 5, 10, 5);
        RemediationAvailabilityPanel.BorderThickness = new Thickness(compact ? 0 : 1);
        RemediationAvailabilityTextBlock.Foreground = compact ? SubtleAvailabilityForeground : BlockedAvailabilityForeground;
        RemediationAvailabilityTextBlock.Text = RemediationAvailabilityText(availability.State);
        string label = availability.Action switch
        {
            RemediationAvailabilityAction.CheckRecovery => DisplayText.Get("Ui.RemediationAvailability.CheckRecovery"),
            RemediationAvailabilityAction.Rescan => DisplayText.Get("Ui.RemediationAvailability.Rescan"),
            RemediationAvailabilityAction.CheckInstallation => DisplayText.Get("Ui.RemediationAvailability.CheckInstallation"),
            RemediationAvailabilityAction.ViewRecords => DisplayText.Get("Ui.RemediationAvailability.ViewRecords"),
            _ => string.Empty
        };
        RemediationAvailabilityActionButton.Content = label;
        AutomationProperties.SetName(RemediationAvailabilityActionButton, label);
        RemediationAvailabilityActionButton.Visibility = availability.Action == RemediationAvailabilityAction.None ? Visibility.Collapsed : Visibility.Visible;
        RemediationAvailabilityActionButton.IsEnabled = !_busy;
    }

    private async void RemediationAvailabilityAction_Click(object sender, RoutedEventArgs e) =>
        await RunRemediationAvailabilityActionAsync();

    // Hidden STA fixtures substitute only read-only checks/scans. This entry never executes a saved plan.
    internal async Task RunRemediationAvailabilityActionAsync(Func<Task>? recoveryCheck = null,
        Func<ScanMode, List<string>, ScanOptions?, Task>? rescan = null, Func<Task>? installationCheck = null)
    {
        Dispatcher.VerifyAccess();
        if (_busy) return;
        RemediationAvailabilityAction action = GetRemediationAvailability().Action;
        try
        {
            switch (action)
            {
                case RemediationAvailabilityAction.CheckRecovery:
                    SetBusy(true);
                    try { await (recoveryCheck ?? RefreshRemediationRecoveryAsync)(); }
                    catch (Exception ex)
                    {
                        _caseRecoveryUnavailable = true;
                        AppErrorLog.Write("RemediationAvailabilityRecovery", ex);
                    }
                    finally { SetBusy(false); }
                    break;
                case RemediationAvailabilityAction.Rescan when _lastReport is not null:
                    var request = CreateRemediationRescanRequest(_lastReport);
                    if (rescan is not null) await rescan(request.Mode, request.Roots, request.Settings);
                    else await StartScanAsync(request.Mode, request.Roots, suppliedContentOptions: request.Settings);
                    break;
                case RemediationAvailabilityAction.CheckInstallation:
                    await (installationCheck ?? RefreshInstallationSecurityAsync)();
                    break;
                case RemediationAvailabilityAction.ViewRecords:
                    MainTabs.SelectedIndex = 0;
                    UpdateAdvancedTabsVisibility(CasesTab);
                    ResultTabs.SelectedItem = CasesTab;
                    break;
            }
        }
        catch (Exception ex)
        {
            AppErrorLog.Write("RemediationAvailabilityAction", ex);
            FooterText.Text = MessageExceptions.Display(ex);
        }
        finally { UpdateRemediationEligibility(); }
    }

    internal static (ScanMode Mode, List<string> Roots, ScanOptions? Settings) CreateRemediationRescanRequest(ScanReport report)
    {
        // CloneOptions deep-copies settings and removes one-time recovery export authorization.
        ScanOptions? settings = RemediationBatchPlanner.CloneOptions(report.ContentScanSettings);
        List<string> roots = report.Mode == ScanMode.Custom
            ? [.. settings?.CustomRoots ?? report.Roots] : [];
        return (report.Mode, roots, settings);
    }
}
