using System.Windows;
using SteamSentinel.App.Dialogs;

namespace SteamSentinel.App;

public partial class MainWindow
{
    private bool? _compactLayout;

    private void ScanPage_SizeChanged(object sender, SizeChangedEventArgs e)
    {
        if (FindingDetailCard is null || FindingDetailScroll is null) return;
        // Base the breakpoint on the stable viewport, not the page whose height
        // changes when the header and optional panels are compacted.
        bool compact = WindowLayout.ActualHeight < 680;
        bool shortViewport = WindowLayout.ActualHeight < 540;
        // On very short windows the active-operation banner replaces branding;
        // retain the result count, live scan status, and all operation controls.
        UpdateCompactHeader();
        MainTabs.Margin = shortViewport ? new Thickness(6, 4, 6, 4) : new Thickness(12, 8, 12, 8);
        ScanPage.Margin = new Thickness(shortViewport ? 6 : 10);
        ScanControlsCard.Padding = shortViewport ? new Thickness(8, 4, 8, 4) : new Thickness(10, 8, 10, 8);
        ScanOptionsContainer.Margin = new Thickness(0, shortViewport ? 2 : 5, 0, 0);
        InstallationControls.Margin = new Thickness(0, shortViewport ? 2 : 5, 0, 0);
        ScanProgressSummary.Margin = new Thickness(0, shortViewport ? 4 : 7, 0, shortViewport ? 4 : 7);
        FindingDetailCard.Margin = new Thickness(0, shortViewport ? 3 : 7, 0, 0);
        SelectionActionsBar.Margin = new Thickness(0, shortViewport ? 4 : 8, 0, 0);
        FindingDetailScroll.Height = compact ? 48 : 100;
        ScanOptionsScroll.MaxHeight = Math.Clamp(e.NewSize.Height - 310, 48, 126);
        // Collapse optional evidence on entering a short viewport, not on every
        // layout pass. The user may still open it without hiding the action bar.
        if (_compactLayout != compact)
        {
            _compactLayout = compact;
            HeaderCard.Padding = compact ? new Thickness(12, 6, 12, 6) : new Thickness(16, 10, 16, 10);
            ProductTagline.Visibility = compact ? Visibility.Collapsed : Visibility.Visible;
            FindingDetailCard.IsExpanded = !compact;
            ElevationHintText.Visibility = compact ? Visibility.Collapsed : Visibility.Visible;
            ActivityDetailText.Visibility = compact ? Visibility.Collapsed : Visibility.Visible;
        }
    }

    private void ScanOptions_Expanded(object sender, RoutedEventArgs e)
    {
        if (FindingDetailCard is not null) FindingDetailCard.IsExpanded = false;
    }

    private void UpdateCompactHeader() => HeaderCard.Visibility =
        WindowLayout.ActualHeight is > 0 and < 540 && ActivityPanel.Visibility == Visibility.Visible
            ? Visibility.Collapsed : Visibility.Visible;

    private void WindowLayout_SizeChanged(object sender, SizeChangedEventArgs e) => UpdateCompactHeader();

    private void FindingDetails_Expanded(object sender, RoutedEventArgs e)
    {
        if (ScanOptionsExpander is not null) ScanOptionsExpander.IsExpanded = false;
    }

    private void FollowUpDetails_Click(object sender, RoutedEventArgs e) =>
        new TextDetailsWindow("完整复查说明（只读）", BatchSummaryText.Text + "\n\n" + BatchFollowUpText.Text)
        { Owner = this }.ShowDialog();
}
