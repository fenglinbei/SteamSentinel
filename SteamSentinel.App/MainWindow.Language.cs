using System.Globalization;
using System.Windows;
using SteamSentinel.App.Dialogs;
using SteamSentinel.App.Localization;
using SteamSentinel.App.ViewModels;
using SteamSentinel.Core.Models;
using SteamSentinel.Core.Reporting;
using SteamSentinel.Core.Steam;

namespace SteamSentinel.App;

public partial class MainWindow
{
    private CultureInfo? ChooseExportLanguage()
    {
        ExportLanguageDialog dialog = new(DisplayText.Culture) { Owner = this };
        return dialog.ShowDialog() == true ? dialog.SelectedCulture : null;
    }

    private void ShowStartupLanguageNotice()
    {
        if (System.Windows.Application.Current is not App { LanguageStartup: { } startup }) return;
        if (startup.SettingsError != LanguageSettingsError.None)
            FooterText.Text += " " + LanguageSettings.ErrorText(startup.SettingsError);
        if (startup.IgnoredArguments) FooterText.Text += " " + DisplayText.Get("Ui.Language.ArgumentsIgnored");
    }

    private void OnLanguageChanged(object? sender, EventArgs e)
    {
        if (_windowClosed) return;
        RefreshLocalizedUi();
    }

    /// <summary>在显示语言热切换后同步刷新主窗口所有运行时生成文本与列表绑定，保留当前状态与勾选项。</summary>
    internal void RefreshLocalizedUi()
    {
        ScanSettingsButton.Content = _scanSettingsLoadError is not null
            ? DisplayText.Get("Ui.xaml.Constructor.01")
            : DisplayText.Get("Ui.Xaml.MainWindow.013");
        ScopeOptions_Changed(this, new RoutedEventArgs());
        RemediationModeComboBox.ToolTip = RemediationModePresentation.Description(CurrentRemediationMode);
        RefreshWorkshopScopeItems(preserveSelection: true);
        ApplyInstallationSecurityStatus();
        RefreshActivityLocalizedText();

        if (_busy)
        {
            _pendingLanguageRefresh = true;
            return;
        }

        foreach (QuarantineItemViewModel item in QuarantineItems)
            item.RefreshLocalizedText();
        UpdateQuarantineActions();

        if (_lastReport is not null)
        {
            foreach (FindingItemViewModel item in Findings)
                item.RefreshLocalizedText();
            FindingCountText.Text = DisplayText.Format("FindingPriority.Counts", PriorityFindings.Count, ReferenceFindings.Count);
            FindingHandlingSummaryText.Text = FindingHandlingPresentation.Count(PriorityFindings.Select(item => item.Handling)).Summary;
            FindingCountText.ToolTip = FindingHandlingSummaryText.Text;
            ReferenceFindingsExpander.Header = DisplayText.Format("FindingPriority.ReferenceGroup", ReferenceFindings.Count);
            UpdateFindingGroupsLayout();
            UpdateSummary(_lastReport);
            RefreshCoveragePresentation(_lastReport, preserveSelection: true);
            DisplayTrustProxyDiagnostics(_lastReport.TrustProxyDiagnostics);
            DisplayRelatedComponentDiagnostics(_lastReport.RelatedComponentDiagnostics);
            DisplayContainers(_lastReport.Containers);
            UpdateRemediationEligibility();
            UpdateFindingActions();
            RefreshCurrentSelectionDetails();
        }
        else
        {
            HeaderStatusText.Text = _recoveryRequired
                ? DisplayText.Get("Ui.xaml.EnterRecoveryMode.01")
                : DisplayText.Get("Ui.Xaml.MainWindow.004");
            HeaderDetailText.Text = DisplayText.Format("Ui.xaml.Constructor.03", _coordinator.Rules.Version);
            UpdateHeaderStatusTone(_recoveryRequired ? HeaderStatusTone.Danger : HeaderStatusTone.Neutral);
            ProgressStageText.Text = DisplayText.Get("Ui.Xaml.MainWindow.033");
            ProgressItemText.Text = string.Empty;
            FindingCountText.Text = DisplayText.Get("Ui.Xaml.MainWindow.034");
            FindingHandlingSummaryText.Text = DisplayText.Get("Ui.Xaml.MainWindow.035");
            FindingCountText.ToolTip = null;
            CoverageTab.Header = DisplayText.Get("Ui.Xaml.MainWindow.044");
            CoverageStatusText.Text = DisplayText.Get("Ui.Xaml.MainWindow.045");
            DisplayTrustProxyDiagnostics(null);
            DisplayRelatedComponentDiagnostics(null);
            DisplayContainers(null);
            UpdateRemediationEligibility();
            UpdateFindingActions();
            if (_recoveryRequired)
            {
                FooterText.Text = DisplayText.Get("Ui.xaml.EnterRecoveryMode.02");
            }
            else if (Application.Current is App { AdministratorWindowRequested: true } && IsLoaded)
            {
                FooterText.Text = _elevationContext.IsElevated
                    ? DisplayText.Get("Ui.xaml.MainWindow_Loaded.04")
                    : DisplayText.Get("Ui.xaml.MainWindow_Loaded.05");
                ShowStartupLanguageNotice();
            }
            else
            {
                FooterText.Text = DisplayText.Get("Ui.Xaml.MainWindow.123");
                ShowStartupLanguageNotice();
            }
        }

        if (_caseBatch is not null)
        {
            UpdateBatchResults();
            RefreshBatchFollowUpLanguage();
        }
        else
        {
            BatchResultsTab.Header = DisplayText.Get("Ui.Xaml.MainWindow.049");
            BatchSummaryText.Text = DisplayText.Get("Ui.Xaml.MainWindow.050");
            BatchFollowUpText.Text = DisplayText.Get("Ui.Xaml.MainWindow.051");
        }

        RefreshCaseRecordsLanguage();
    }

    private void RefreshWorkshopScopeItems(bool preserveSelection)
    {
        string? selectedAppId = preserveSelection ? WorkshopScopeComboBox.SelectedValue as string : null;
        string rootLabel = _findingScopeLayout.WorkshopRoots.Count == 0 && !IsLoaded
            ? DisplayText.Get("Ui.xaml.Constructor.02")
            : DisplayText.Get("Ui.xaml.MainWindow_Loaded.02");
        List<WorkshopScopeItem> scopes = [new(string.Empty, rootLabel)];
        foreach (string appId in _findingScopeLayout.WorkshopRoots.Select(ContentDiscovery.WorkshopAppId).Where(id => id.Length > 0).Distinct())
        {
            string name = _findingScopeLayout.Games.FirstOrDefault(game => game.AppId == appId)?.Name
                ?? (appId == "431960" ? "Wallpaper Engine" : DisplayText.Get("Ui.xaml.MainWindow_Loaded.03"));
            scopes.Add(new(appId, $"{name} · {appId}"));
        }
        WorkshopScopeComboBox.ItemsSource = scopes;
        if (preserveSelection && selectedAppId is not null)
        {
            int matchedIndex = scopes.FindIndex(item => string.Equals(item.AppId, selectedAppId, StringComparison.Ordinal));
            WorkshopScopeComboBox.SelectedIndex = matchedIndex >= 0 ? matchedIndex : 0;
        }
        else
        {
            WorkshopScopeComboBox.SelectedIndex = 0;
        }
    }

    private IReadOnlyList<CoverageGroup> RefreshCoveragePresentation(ScanReport report, bool preserveSelection)
    {
        int selectedIndex = preserveSelection ? CoverageGrid.SelectedIndex : -1;
        IReadOnlyList<CoverageGroup> groups = CoveragePresentation.Groups(report);
        CoverageGrid.ItemsSource = groups;
        CoverageTab.Header = groups.Count > 0 ? DisplayText.Format("Ui.xaml.PopulateFindings.02", (groups.Count)) :
            report.Coverage == ScanCoverage.Complete ? DisplayText.Get("Ui.xaml.PopulateFindings.03") : DisplayText.Get("Ui.xaml.PopulateFindings.04");
        CoverageStatusText.Text = groups.Count > 0
            ? DisplayText.Format("Ui.xaml.PopulateFindings.05", (groups.Count))
            : report.Coverage == ScanCoverage.Complete
                ? DisplayText.Get("Ui.xaml.PopulateFindings.06")
                : DisplayText.Get("Ui.xaml.PopulateFindings.07");
        if (report.ResourceAudit is { } resourceAudit)
            CoverageStatusText.Text += "\n" + ScanResourcePresentation.Summary(resourceAudit);
        if (preserveSelection && selectedIndex >= 0 && selectedIndex < groups.Count)
            CoverageGrid.SelectedIndex = selectedIndex;
        return groups;
    }

    private void RefreshCurrentSelectionDetails()
    {
        if (ResultTabs.SelectedIndex == 0) UpdateSelectedFindingDetails();
        else if (ResultTabs.SelectedIndex == 1)
        {
            if (CoverageGrid.SelectedIndex < 0 && CoverageGrid.Items.Count > 0) CoverageGrid.SelectedIndex = 0;
            UpdateCoverageSelectionDetails();
        }
    }

    private void RefreshBatchFollowUpLanguage()
    {
        if (_caseBatch is null || (_caseContentFollowUp is null && _caseFollowUp is null))
        {
            BatchFollowUpText.Text = DisplayText.Get("Ui.Xaml.MainWindow.051");
            return;
        }
        List<string> messages = [];
        if (_caseContentFollowUp is not null)
            messages.Add(ContentFollowUpSummary(_caseContentFollowUp));
        else if (_caseBatch.OriginalContentSettings is not { } s || (!s.IncludeWorkshop && !s.IncludeRelatedContent && s.CustomRoots.Count == 0))
            messages.Add(DisplayText.Get("Remediation.RunBatchFollowUpAsync.04"));
        if (_caseFollowUp is not null)
            messages.Add(SystemFollowUpSummary(_caseFollowUp));
        BatchFollowUpText.Text = messages.Count > 0
            ? string.Join("\n", messages)
            : DisplayText.Get("Ui.Xaml.MainWindow.051");
    }

    private void RefreshCaseRecordsLanguage()
    {
        if (CaseListComboBox.ItemsSource is CaseListItem[] caseItems && caseItems.Length > 0)
        {
            Guid? selectedCaseId = (CaseListComboBox.SelectedItem as CaseListItem)?.Summary.CaseId;
            CaseListItem[] refreshed = caseItems.Select(item => new CaseListItem(item.Summary)).ToArray();
            CaseListComboBox.ItemsSource = refreshed;
            CaseListComboBox.SelectedItem = refreshed.FirstOrDefault(item => item.Summary.CaseId == selectedCaseId) ?? refreshed[0];
        }
        if (_remediationClient.HasUnresolvedExecution)
            CaseDetailsText.Text = DisplayText.Get("Ui.Cases.RefreshCaseRecordsAsync.04");
        else if (_loadedCase is not null)
            DisplayCaseRecord(_loadedCase);
        else if (CaseListComboBox.Items.Count == 0)
            CaseDetailsText.Text = DisplayText.Get("Ui.Cases.RefreshCaseRecordsAsync.03");
    }
}
