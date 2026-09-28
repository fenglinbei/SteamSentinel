using SteamSentinel.Core.Reporting;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;
using System.Windows.Media;
using SteamSentinel.App.Dialogs;

namespace SteamSentinel.App;

public partial class MainWindow
{
    private bool? _compactLayout;
    private OptionalLayoutInputs? _optionalLayoutInputs;
    private double _optionalHeightBudget;

    private readonly record struct OptionalLayoutInputs(double Width, double Height, double Scale, double Minimum,
        ScrollViewer Panel, int ResultTab, double RowHeight, double ActionsHeight,
        double InstallationHeight, double SummaryHeight, double FooterHeight);

    private void ScanPage_SizeChanged(object sender, SizeChangedEventArgs e)
    {
        if (FindingDetailCard is null || FindingDetailScroll is null) return;
        // Base the breakpoint on the stable viewport, not the page whose height
        // changes when the header and optional panels are compacted.
        bool compact = WindowLayout.ActualHeight < 680;
        bool shortViewport = WindowLayout.ActualHeight < 540;
        // Keep the eligibility counts alongside the stage on constrained viewports.
        // The detailed progress instruction remains available in the header and its tooltip.
        bool condensedSummary = shortViewport || compact && ActivityPanel.Visibility == Visibility.Visible;
        ProgressStageText.MaxWidth = condensedSummary ? 100 : 200;
        ProgressItemText.Visibility = condensedSummary ? Visibility.Collapsed : Visibility.Visible;
        Grid.SetRow(FindingHandlingSummaryText, condensedSummary ? 0 : 2);
        Grid.SetColumnSpan(FindingHandlingSummaryText, condensedSummary ? 1 : 2);
        FindingHandlingSummaryText.Margin = condensedSummary ? new Thickness(110, 0, 0, 0) : new Thickness(0, 4, 0, 0);
        FindingHandlingSummaryText.VerticalAlignment = VerticalAlignment.Center;
        TrustProxyPage.Margin = new Thickness(shortViewport ? 4 : 8);
        TrustProxyScopeText.Margin = shortViewport ? new Thickness(0, 3, 0, 3) : new Thickness(0, 5, 0, 6);
        RelatedComponentsPage.Margin = new Thickness(shortViewport ? 4 : 8);
        RelatedComponentsScopeText.Margin = shortViewport ? new Thickness(0, 3, 0, 3) : new Thickness(0, 5, 0, 6);
        ContainerPage.Margin = new Thickness(shortViewport ? 4 : 8);
        ContainerActionsBar.Margin = shortViewport ? new Thickness(0, 3, 0, 2) : new Thickness(0, 5, 0, 4);
        // On very short windows, operations and expanded panels take priority over branding.
        UpdateCompactHeader();
        MainTabs.Margin = shortViewport ? new Thickness(6, 4, 6, 4) : new Thickness(12, 8, 12, 8);
        ScanPage.Margin = new Thickness(shortViewport ? 6 : 10);
        ScanControlsCard.Padding = shortViewport ? new Thickness(8, 4, 8, 4) : new Thickness(10, 8, 10, 8);
        ScanOptionsContainer.Margin = new Thickness(0, shortViewport ? 2 : 5, 0, 0);
        InstallationControls.Margin = new Thickness(0, shortViewport ? 2 : 5, 0, 0);
        ScanProgressSummary.Margin = new Thickness(0, shortViewport ? 4 : 7, 0, shortViewport ? 4 : 7);
        FindingDetailCard.Margin = new Thickness(0, shortViewport ? 3 : 7, 0, 0);
        SelectionActionsBar.Margin = new Thickness(0, shortViewport ? 4 : 8, 0, 0);
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

    private void ScanPage_LayoutUpdated(object? sender, EventArgs e)
    {
        if (_windowClosed || ScanPage is null || ResultTabs is null) return;
        UpdateCompactHeader();
        if (MainTabs.SelectedIndex != 0 ||
            ScanPage.ActualHeight <= 0 || PresentationSource.FromVisual(ScanPage) is null) return;
        ScrollViewer? optional = ScanOptionsExpander.IsExpanded ? ScanOptionsScroll
            : FindingDetailCard.IsExpanded && FindingDetailCard.Visibility == Visibility.Visible ? FindingDetailScroll : null;
        if (optional is null) { _optionalLayoutInputs = null; return; }
        if (!ScanPage.IsMeasureValid || !ScanPage.IsArrangeValid) return;
        DataGrid? grid = FindScanVisual<DataGrid>(ResultTabs);
        ScrollContentPresenter? viewport = grid is null ? null : FindScanVisual<ScrollContentPresenter>(grid);
        if (grid is null || viewport is null) return;

        bool compact = WindowLayout.ActualHeight < 680;
        double preferred = optional == ScanOptionsScroll ? (compact ? 90 : 126)
            : WindowLayout.ActualHeight < 540 ? 30 : compact ? 48 : 100;
        DataGridRow? row = FindScanVisual<DataGridRow>(grid);
        // Keep a complete summary row. Exceptionally long batch reasons are already
        // pixel-scrollable; they must not consume the entire optional-panel budget.
        double rowHeight = Math.Max(grid.MinRowHeight, row?.ActualHeight ?? 0);
        if (grid == BatchResultsGrid) rowHeight = Math.Min(rowHeight, grid.FontSize * 4);
        double scale = VisualTreeHelper.GetDpi(ScanPage).DpiScaleY;
        // A scrollable options panel must fit an entire interactive row. Scrolling
        // cannot make a 23-DIP control visible inside a 17-DIP viewport.
        double minimum = optional == ScanOptionsScroll
            ? new Control[] { WorkshopScopeComboBox, DownloadLocationsCheckBox, ExecutionHistoryCheckBox,
                ArchiveCheckBox, DeepSignatureCheckBox, DomainBlockCheckBox }
                .Max(control => control.DesiredSize.Height)
            : FindingDetailScroll.FontSize * 1.5;
        minimum = Math.Ceiling(minimum * scale) / scale + 1 / scale;
        preferred = Math.Max(preferred, minimum);

        // A new size, DPI or fixed-content measurement starts one allocation round.
        // Do not include either optional.ActualHeight or the result viewport in this
        // key: both change as a consequence of the allocation itself.
        OptionalLayoutInputs inputs = new(ScanPage.ActualWidth, ScanPage.ActualHeight, scale, minimum,
            optional, ResultTabs.SelectedIndex, rowHeight, ScanActionsBar.ActualHeight,
            InstallationControls.ActualHeight, ScanProgressSummary.ActualHeight, SelectionActionsBar.ActualHeight);
        if (_optionalLayoutInputs != inputs)
        {
            _optionalLayoutInputs = inputs;
            _optionalHeightBudget = preferred;
        }
        // The measured viewport already excludes tab/header/border heights and reflects
        // wrapped buttons, progress and language. Return the optional panel's current
        // space to the budget, reserve a row plus one physical pixel, then allocate it.
        double available = optional.ActualHeight + viewport.ActualHeight - rowHeight - 1 / scale;
        // Rounded measure/arrange passes can return a pixel more than the previous
        // pass. Never give it back within the same round, which otherwise can keep
        // LayoutUpdated/UpdateLayout oscillating at fractional DPI.
        double height = Math.Min(_optionalHeightBudget,
            Math.Max(minimum, Math.Floor(Math.Min(preferred, available) * scale + 1e-6) / scale));
        _optionalHeightBudget = height;
        double previous = optional == ScanOptionsScroll ? optional.MaxHeight : optional.Height;
        // Quantize to pixels and avoid invalidating an already stable layout.
        if (Math.Abs(previous - height) * scale < 0.5) return;
        if (optional == ScanOptionsScroll) optional.MaxHeight = height;
        else optional.Height = height;
    }

    private static T? FindScanVisual<T>(DependencyObject parent) where T : DependencyObject
    {
        for (int i = 0; i < VisualTreeHelper.GetChildrenCount(parent); i++)
        {
            DependencyObject child = VisualTreeHelper.GetChild(parent, i);
            if (child is T match) return match;
            if (FindScanVisual<T>(child) is { } descendant) return descendant;
        }
        return null;
    }

    private void ScanOptions_Expanded(object sender, RoutedEventArgs e)
    {
        if (FindingDetailCard is not null) FindingDetailCard.IsExpanded = false;
    }

    private void UpdateCompactHeader()
    {
        if (HeaderCard is null || ScanOptionsExpander is null || FindingDetailCard is null || MainTabs is null) return;
        bool needsRoom = MainTabs.SelectedIndex == 0 && (ActivityPanel.Visibility == Visibility.Visible ||
            ScanOptionsExpander.IsExpanded || FindingDetailCard.Visibility == Visibility.Visible && FindingDetailCard.IsExpanded);
        HeaderCard.Visibility = WindowLayout.ActualHeight is > 0 and < 540 && needsRoom
            ? Visibility.Collapsed : Visibility.Visible;
    }

    private void WindowLayout_SizeChanged(object sender, SizeChangedEventArgs e) => UpdateCompactHeader();

    private void FindingDetails_Expanded(object sender, RoutedEventArgs e)
    {
        if (ScanOptionsExpander is not null) ScanOptionsExpander.IsExpanded = false;
    }

    private void FollowUpDetails_Click(object sender, RoutedEventArgs e) =>
        new TextDetailsWindow(DisplayText.Get("Ui.Layout.FollowUpDetails_Click.01"), BatchSummaryText.Text + "\n\n" + BatchFollowUpText.Text)
        { Owner = this }.ShowDialog();
}
