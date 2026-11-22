using System.Windows;
using SteamSentinel.App.ViewModels;
using SteamSentinel.Core.Reporting;

namespace SteamSentinel.App;

public partial class MainWindow
{
    private FindingItemViewModel? SelectedFinding =>
        ReferenceFindingsGrid?.SelectedItem as FindingItemViewModel ?? FindingsGrid?.SelectedItem as FindingItemViewModel;

    private IEnumerable<FindingItemViewModel> VisibleRemediationFindings =>
        Findings.Where(item => !item.IsReference || ReferenceFindingsExpander.IsExpanded);

    private void ClearFindingGroups()
    {
        PriorityFindings.Clear();
        ReferenceFindings.Clear();
        ReferenceFindingsExpander.IsExpanded = false;
        ReferenceFindingsExpander.Visibility = Visibility.Collapsed;
        PriorityFindingsEmptyText.Visibility = Visibility.Collapsed;
        FindingsGrid.Visibility = Visibility.Visible;
        PriorityFindingsRow.Height = new GridLength(1, GridUnitType.Star);
        ReferenceFindingsRow.Height = GridLength.Auto;
        UpdateScanStageOverlayVisibility();
    }

    private void UpdateFindingGroupsLayout()
    {
        if (ReferenceFindingsExpander is null || PriorityFindings is null || ReferenceFindings is null) return;
        bool hasPriority = PriorityFindings.Count > 0;
        bool expanded = ReferenceFindingsExpander.IsExpanded && ReferenceFindings.Count > 0;
        ReferenceFindingsExpander.Visibility = ReferenceFindings.Count > 0 ? Visibility.Visible : Visibility.Collapsed;
        // 主表为空时按是否存在折叠参考项区分友好空态提示，避免无折叠组时误提示“下方已收起”。
        PriorityFindingsEmptyText.Text = DisplayText.Get(ReferenceFindings.Count > 0
            ? "FindingPriority.Empty" : "FindingPriority.EmptyNoReference");
        PriorityFindingsEmptyText.Visibility = hasPriority ? Visibility.Collapsed : Visibility.Visible;
        FindingsGrid.Visibility = hasPriority ? Visibility.Visible : Visibility.Collapsed;
        if (ResultTabs.SelectedIndex == 0 && SelectedFinding is null) FindingDetailCard.Visibility = Visibility.Collapsed;
        PriorityFindingsRow.Height = !hasPriority ? GridLength.Auto : new GridLength(1, GridUnitType.Star);
        ReferenceFindingsRow.Height = expanded ? new GridLength(1, GridUnitType.Star) : GridLength.Auto;
        UpdateScanStageOverlayVisibility();
    }

    private void ReferenceFindings_ExpansionChanged(object sender, RoutedEventArgs e)
    {
        if (ReferenceFindingsGrid is null || ReferenceFindings is null) return;
        if (!ReferenceFindingsExpander.IsExpanded)
        {
            // Collapsing the reference group must never leave hidden remediation selections.
            foreach (FindingItemViewModel item in ReferenceFindings) item.IsSelected = false;
            ReferenceFindingsGrid.SelectedItem = null;
        }
        UpdateFindingGroupsLayout();
        UpdateRemediationEligibility();
    }
}
