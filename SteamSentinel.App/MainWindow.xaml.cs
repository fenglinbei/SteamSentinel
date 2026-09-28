using System.Collections.ObjectModel;
using System.Diagnostics;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using Microsoft.Win32;
using SteamSentinel.App.Dialogs;
using SteamSentinel.App.Services;
using SteamSentinel.App.ViewModels;
using SteamSentinel.Core.Models;
using SteamSentinel.Core.Remediation;
using SteamSentinel.Core.Reporting;
using SteamSentinel.Core.Scanning;
using SteamSentinel.Core.Steam;
using SteamSentinel.Core.Utilities;
using Validation = SteamSentinel.Core.Utilities.Validation;

namespace SteamSentinel.App;

public partial class MainWindow : Window
{
    private readonly ScanCoordinator _coordinator = new();
    private readonly ArchiveWorkerClient _workerClient = new();
    private readonly RemediationClient _remediationClient = new();
    private InstallationSecurityStatus _installationSecurity = new(false, DisplayText.Get("Ui.xaml._installationSecurity.01"));
    private ElevationContext _elevationContext = ElevationContext.Read();
    private CancellationTokenSource? _scanCancellation;
    private ScanReport? _lastReport;
    private ScanReport? _caseScan;
    private RemediationPlan? _casePlan;
    private RemediationRunResult? _caseResult;
    private ScanReport? _caseFollowUp;
    private bool _reportNeedsRefresh;
    private bool _busy;
    private ScanLimitSettings _scanLimits = new();
    private string? _scanSettingsLoadError;
    private bool _recoveryRequired;
    private Guid? _lastFullSystemAndContentScanId;

    public MainWindow()
    {
        InitializeComponent();
        try { _scanLimits = ScanSettingsStore.Load(ScanSettingsStore.DefaultPath); }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or System.Text.Json.JsonException)
        { _scanSettingsLoadError = SteamSentinel.Core.Reporting.MessageExceptions.Display(ex); ScanSettingsButton.Content = DisplayText.Get("Ui.xaml.Constructor.01"); }
        Width = Math.Min(Width, SystemParameters.WorkArea.Width);
        Height = Math.Min(Height, SystemParameters.WorkArea.Height);
        MinWidth = Math.Min(MinWidth, SystemParameters.WorkArea.Width);
        MinHeight = Math.Min(MinHeight, SystemParameters.WorkArea.Height);
        WorkshopScopeComboBox.ItemsSource = new[] { new WorkshopScopeItem("", DisplayText.Get("Ui.xaml.Constructor.02")) };
        WorkshopScopeComboBox.SelectedIndex = 0;
        Findings = [];
        QuarantineItems = [];
        DataContext = this;
        SetBusy(true);
        HeaderDetailText.Text = DisplayText.Format("Ui.xaml.Constructor.03", (_coordinator.Rules.Version));
        Loaded += MainWindow_Loaded;
        Closing += MainWindow_Closing;
        Closed += MainWindow_Closed;
    }

    public ObservableCollection<FindingItemViewModel> Findings { get; }
    public ObservableCollection<QuarantineItemViewModel> QuarantineItems { get; }

    private async void MainWindow_Loaded(object sender, RoutedEventArgs e)
    {
        try
        {
            await RefreshInstallationSecurityAsync();
            SetBusy(true);
            ShowActivity(ActivityPhase.Working, DisplayText.Get("Ui.xaml.MainWindow_Loaded.01"));
            SteamLayout layout = await Task.Run(SteamLocator.Discover);
            List<WorkshopScopeItem> scopes = [new("", DisplayText.Get("Ui.xaml.MainWindow_Loaded.02"))];
            foreach (string appId in layout.WorkshopRoots.Select(ContentDiscovery.WorkshopAppId).Where(id => id.Length > 0).Distinct())
                scopes.Add(new(appId, (layout.Games.FirstOrDefault(game => game.AppId == appId)?.Name ?? (appId == "431960" ? "Wallpaper Engine" : DisplayText.Get("Ui.xaml.MainWindow_Loaded.03"))) + " · " + appId));
            WorkshopScopeComboBox.ItemsSource = scopes;
            WorkshopScopeComboBox.SelectedIndex = 0;
            if (Application.Current is App { AdministratorWindowRequested: true })
                FooterText.Text = _elevationContext.IsElevated
                    ? DisplayText.Get("Ui.xaml.MainWindow_Loaded.04")
                    : DisplayText.Get("Ui.xaml.MainWindow_Loaded.05");
            await RefreshQuarantineItemsAsync();
            try { await RefreshCaseRecordsAsync(restorePending: true); }
            catch (Exception ex) { _caseRecoveryUnavailable = true; CaseDetailsText.Text = DisplayText.Get("Ui.xaml.MainWindow_Loaded.06") + SteamSentinel.Core.Reporting.MessageExceptions.Display(ex); }
        }
        catch (Exception ex)
        {
            AppErrorLog.Write("InitializeWindow", ex);
            HeaderDetailText.Text = DisplayText.Get("Ui.xaml.MainWindow_Loaded.07");
            FooterText.Text = SteamSentinel.Core.Reporting.MessageExceptions.Display(ex);
        }
        finally { SetBusy(false); ShowStartupLanguageNotice(); }
    }

    private void ScanSettings_Click(object sender, RoutedEventArgs e)
    {
        if (_busy) return;
        ScanLimitsDialog dialog = new(_scanLimits, _scanSettingsLoadError) { Owner = this };
        if (dialog.ShowDialog() == true)
        {
            _scanLimits = dialog.Settings; _scanSettingsLoadError = null;
            ScanSettingsButton.Content = DisplayText.Get("Ui.xaml.ScanSettings_Click.01");
            FooterText.Text = DisplayText.Get("Ui.xaml.ScanSettings_Click.02");
        }
    }

    private async void QuickScan_Click(object sender, RoutedEventArgs e) =>
        await StartScanAsync(ScanMode.Quick, []);

    private async void FullScan_Click(object sender, RoutedEventArgs e)
    {
        ArchiveCheckBox.IsChecked = true;
        await StartScanAsync(ScanMode.Full, []);
    }

    private void ScopeOptions_Changed(object sender, RoutedEventArgs e)
    {
        if (ScanScopeText is null || DownloadLocationsCheckBox is null) return;
        ScanScopeText.Text = DisplayText.Get("Ui.xaml.ScopeOptions_Changed.01") +
            (DownloadLocationsCheckBox.IsChecked == true ? DisplayText.Get("Ui.xaml.ScopeOptions_Changed.02") : DisplayText.Get("Ui.xaml.ScopeOptions_Changed.03"));
    }

    private void CoverageGrid_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (CoverageGrid.SelectedItem is not CoverageGroup group)
        {
            CoverSelectedButton.IsEnabled = false;
            DetailDescriptionText.Text = DisplayText.Get("Ui.xaml.CoverageGrid_SelectionChanged.01");
            DetailEvidenceText.Text = string.Empty;
            DetailHashText.Text = string.Empty;
            DetailWorkshopText.Text = string.Empty;
            return;
        }
        DetailDescriptionText.Text = group.NextStep;
        DetailEvidenceText.Text = string.Join(Environment.NewLine + Environment.NewLine, group.Entries.Take(50).Select(i => i.TargetDisplay + "\n" + i.Detail)) +
            (group.Count > 50 ? DisplayText.Format("Ui.xaml.CoverageGrid_SelectionChanged.02", (group.Count)) : "");
        DetailHashText.Text = DisplayText.Get("Ui.xaml.CoverageGrid_SelectionChanged.03");
        DetailWorkshopText.Text = DisplayText.Get("Ui.xaml.CoverageGrid_SelectionChanged.04");
        CoverSelectedButton.IsEnabled = !_busy && group.CanFullScan && CoverageTargets(group).Count > 0;
    }

    private void ResultTabs_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (!ReferenceEquals(e.Source, ResultTabs) || DetailDescriptionText is null) return;
        FindingDetailCard.Visibility = ResultTabs.SelectedIndex is 2 or 3 or 4 or 5 or 6 ? Visibility.Collapsed : Visibility.Visible;
        SelectionActionsBar.Visibility = ResultTabs.SelectedIndex is 5 or 6 ? Visibility.Collapsed : Visibility.Visible;
        if (ResultTabs.SelectedIndex == 0) FindingsGrid_SelectionChanged(FindingsGrid, e);
        else if (ResultTabs.SelectedIndex == 1)
        {
            if (CoverageGrid.SelectedIndex < 0 && CoverageGrid.Items.Count > 0) CoverageGrid.SelectedIndex = 0;
            CoverageGrid_SelectionChanged(CoverageGrid, e);
        }
        UpdateFindingActions();
    }

    internal static List<string> CoverageTargets(CoverageGroup group) => group.Entries.Select(i => i.Target)
        .Where(p => ContentDiscovery.IsLocalSafePath(p) && (File.Exists(p) || Directory.Exists(p)))
        .Distinct(StringComparer.OrdinalIgnoreCase).ToList();

    private async void CoverSelected_Click(object sender, RoutedEventArgs e)
    {
        if (_busy || CoverageGrid.SelectedItem is not CoverageGroup { CanFullScan: true } group) return;
        List<string> targets = CoverageTargets(group);
        if (targets.Count == 0) return;
        if (MessageBox.Show(this, DisplayText.Format("Ui.xaml.CoverSelected_Click.01", (targets.Count)),
            DisplayText.Get("Ui.xaml.CoverSelected_Click.02"), MessageBoxButton.OKCancel, MessageBoxImage.Information) != MessageBoxResult.OK) return;
        ArchiveCheckBox.IsChecked = true;
        await StartScanAsync(ScanMode.Custom, targets);
    }

    private async void FileScan_Click(object sender, RoutedEventArgs e)
    {
        OpenFileDialog dialog = new() { Title = DisplayText.Get("Ui.xaml.FileScan_Click.01"), CheckFileExists = true };
        if (dialog.ShowDialog(this) == true) await StartScanAsync(ScanMode.Custom, [dialog.FileName]);
    }

    private async void FolderScan_Click(object sender, RoutedEventArgs e)
    {
        OpenFolderDialog dialog = new() { Title = DisplayText.Get("Ui.xaml.FolderScan_Click.01"), Multiselect = false };
        if (dialog.ShowDialog(this) == true) await StartScanAsync(ScanMode.Custom, [dialog.FolderName]);
    }

    private void CancelScan_Click(object sender, RoutedEventArgs e)
    {
        if (_scanCancellation is null || _operationCommitted) return;
        _scanCancellation.Cancel();
        CancelScanButton.IsEnabled = false;
        ShowActivity(ActivityPhase.Cancelling);
    }

    private async void RetryPasswords_Click(object sender, RoutedEventArgs e)
    {
        if (_busy || _lastReport is null) return;
        List<string> targets = GetPasswordRetryTargets(_lastReport);
        if (targets.Count == 0) return;
        if (MessageBox.Show(this, DisplayText.Format("Ui.xaml.RetryPasswords_Click.01", (targets.Count)),
            DisplayText.Get("Ui.xaml.RetryPasswords_Click.02"), MessageBoxButton.OKCancel, MessageBoxImage.Information) != MessageBoxResult.OK) return;
        ArchiveCheckBox.IsChecked = true;
        await StartScanAsync(ScanMode.Custom, targets);
    }

    internal static List<string> GetPasswordRetryTargets(ScanReport report) => report.Findings
        .Where(f => f.Category == FindingCategory.Coverage && f.RuleId is
            "ARCHIVE-PASSWORD-FAILED" or "ARCHIVE-ENCRYPTED-NOT-SCANNED" or "ARCHIVE-ENCRYPTED-DEFERRED")
        .Select(f => f.Target).Where(File.Exists).Distinct(StringComparer.OrdinalIgnoreCase).ToList();

    private async Task StartScanAsync(ScanMode mode, List<string> customRoots, bool reviewRelated = false,
        ScanOptions? suppliedContentOptions = null,
        Func<ScanOptions, IProgress<ScanProgress>, CancellationToken, Task<ScanReport>>? contentRunner = null)
    {
        if (_busy) return;
        SetBusy(true);
        ShowActivity(ActivityPhase.Scanning);
        Findings.Clear();
        CoverageGrid.ItemsSource = null;
        CoverageTab.Header = DisplayText.Get("Ui.xaml.StartScanAsync.01");
        CoverageStatusText.Text = DisplayText.Get("Ui.xaml.StartScanAsync.02");
        CoverSelectedButton.IsEnabled = false;
        ResultTabs.SelectedIndex = 0;
        _lastReport = null;
        _trustProxyBaseReport = null;
        _trustProxyMergedReport = null;
        DisplayTrustProxyDiagnostics(null);
        DisplayRelatedComponentDiagnostics(null);
        DisplayContainers(null);
        _lastFullSystemAndContentScanId = null;
        _reportNeedsRefresh = false;
        HeaderStatusText.Text = DisplayText.Get("Ui.xaml.StartScanAsync.03");
        HeaderDetailText.Text = mode switch
        {
            ScanMode.Quick => DisplayText.Get("Ui.xaml.StartScanAsync.Quick.01"),
            ScanMode.Full => DisplayText.Get("Ui.xaml.StartScanAsync.Full.01"),
            _ => DisplayText.Get("Ui.xaml.StartScanAsync.04")
        };
        FindingCountText.Text = DisplayText.Get("Ui.xaml.StartScanAsync.05");
        FindingHandlingSummaryText.Text = DisplayText.Get("Ui.xaml.StartScanAsync.06");
        ScanProgressBar.IsIndeterminate = true;
        ScanProgressBar.Value = 0;
        _scanCancellation = new CancellationTokenSource();
        CancelScanButton.IsEnabled = true;
        CancellationToken token = _scanCancellation.Token;
        using DispatcherProgress<ScanProgress> progress = CreateUiProgress(UpdateProgress);
        ScanReport? systemReport = null;
        bool contentAttempted = false;

        try
        {
            if (mode != ScanMode.Custom || reviewRelated)
            {
                ScanOptions systemOptions = new()
                {
                    Mode = mode,
                    IncludeSystem = true,
                    IncludeSteam = true,
                    IncludeWorkshop = false,
                    IncludeRelatedContent = false,
                    IncludeExecutionHistory = ExecutionHistoryCheckBox.IsChecked == true,
                    InspectArchives = false,
                    UseAmsi = false,
                    ExcludedRoots = [AppPaths.MachineStateRoot, AppPaths.TemporaryRoot, AppPaths.WorkerTemporaryRoot]
                };
                systemReport = await Task.Run(
                    () => _coordinator.RunAsync(systemOptions, null, progress, token, checkpoint: state => systemReport = state), token);
                if (systemReport.Findings.Any(f => f.IsKnownMalware && f.Category == FindingCategory.Process && f.CanRemediate) &&
                    MessageBox.Show(this, DisplayText.Get("Ui.xaml.StartScanAsync.07"),
                        DisplayText.Get("Ui.xaml.StartScanAsync.08"), MessageBoxButton.YesNo, MessageBoxImage.Warning, MessageBoxResult.Yes) == MessageBoxResult.Yes)
                {
                    systemReport.Coverage = ScanCoverage.Partial;
                    ScanExecution.AddNotice(systemReport, ReasonCodes.ContentNotStarted, DisplayText.Get("Ui.xaml.StartScanAsync.09"));
                    _lastReport = systemReport; PopulateFindings(systemReport); UpdateSummary(systemReport); return;
                }
            }

            ScanOptions contentOptions = suppliedContentOptions ?? new()
            {
                Mode = mode,
                IncludeSystem = false,
                IncludeSteam = false,
                IncludeWorkshop = mode != ScanMode.Custom,
                WorkshopAppIds = WorkshopScopeComboBox.SelectedValue is string { Length: > 0 } appId ? [appId] : [],
                IncludeRelatedContent = mode != ScanMode.Custom,
                IncludeDownloadLocations = mode != ScanMode.Custom && DownloadLocationsCheckBox.IsChecked == true,
                RelatedRoots = mode != ScanMode.Custom ? systemReport?.CandidateRoots ?? [] : [],
                InspectArchives = ArchiveCheckBox.IsChecked == true,
                UseAmsi = ScanEnhancements.AmsiAvailable && AmsiCheckBox.IsChecked == true,
                InspectDeepSignatures = DeepSignatureCheckBox.IsChecked == true,
                HashEveryFile = mode != ScanMode.Quick,
                MaximumContentBytes = mode == ScanMode.Quick ? 1024L * 1024 * 1024 : long.MaxValue,
                CustomRoots = customRoots,
                ExcludedRoots = [AppPaths.MachineStateRoot, AppPaths.TemporaryRoot, AppPaths.WorkerTemporaryRoot, AppContext.BaseDirectory]
            };

            contentOptions = _scanLimits.Apply(contentOptions);
            contentAttempted = true;
            _resourceScanMode = mode;
            _resourceSaveChoices.Clear();
            contentRunner ??= (settings, reporter, cancellation) => _workerClient.RunAsync(settings, RequestPasswordAsync, reporter, cancellation, RequestResourcesAsync);
            ScanReport contentReport = await contentRunner(contentOptions, progress, token);
            _lastReport = systemReport is null ? contentReport : ScanReportMerger.Merge(systemReport, contentReport);
            if (_lastReport.RelatedComponentDiagnostics is not null)
            {
                using DispatcherProgress<ScanProgress> relatedProgress = CreateUiProgress(p =>
                {
                    ProgressStageText.Text = p.DisplayStage;
                    ProgressItemText.Text = p.DisplayCurrentItem;
                    ActivityDetailText.Text = p.DisplayDetail;
                });
                _lastReport = await Task.Run(() => new RelatedComponentPipeline(_coordinator.Rules).CompleteAsync(_lastReport,
                    contentOptions, async (options, workerProgress, workerToken) =>
                    {
                        try { return await _workerClient.RunAsync(options, RequestPasswordAsync, workerProgress, workerToken, RequestResourcesAsync); }
                        catch (Exception ex) when (ex is not OutOfMemoryException)
                        {
                            return ScanFailureReports.PreserveSystemResults(null, ScanMode.Custom, options.CustomRoots,
                            _coordinator.Rules.Version, ex, workerToken.IsCancellationRequested);
                        }
                    }, relatedProgress, token));
                token.ThrowIfCancellationRequested();
            }
            if (mode != ScanMode.Custom)
                await ScanFailureReports.CollectSupplementAsync(_lastReport,
                    () => Task.Run(() => ProtectionConfiguration.CollectAsync(SteamLocator.Discover(), _lastReport, token), token));
            if (mode == ScanMode.Full && systemReport is { Coverage: ScanCoverage.Complete } &&
                contentReport.Coverage == ScanCoverage.Complete && _lastReport.Coverage == ScanCoverage.Complete &&
                contentOptions.IncludeWorkshop && contentOptions.IncludeRelatedContent && contentOptions.InspectArchives &&
                contentOptions.HashEveryFile && contentOptions.WorkshopAppIds.Count == 0 && !token.IsCancellationRequested)
                _lastFullSystemAndContentScanId = _lastReport.ScanId;
            PopulateFindings(_lastReport);
            UpdateSummary(_lastReport);
        }
        catch (OperationCanceledException ex)
        {
            if (contentAttempted) PreserveScanFailure(_lastReport ?? systemReport, mode, customRoots, ex, cancelled: true);
            else PreserveSystemStageFailure(systemReport, mode, ex, cancelled: true);
            HeaderStatusText.Text = DisplayText.Get("Ui.xaml.StartScanAsync.10");
            HeaderDetailText.Text = contentAttempted ? DisplayText.Get("Ui.xaml.StartScanAsync.11") : DisplayText.Get("Ui.xaml.StartScanAsync.12");
            FooterText.Text = DisplayText.Get("Ui.xaml.StartScanAsync.13");
        }
        catch (Exception ex)
        {
            if (contentAttempted) PreserveScanFailure(_lastReport ?? systemReport, mode, customRoots, ex, cancelled: false);
            else PreserveSystemStageFailure(systemReport, mode, ex, cancelled: false);
            AppErrorLog.Write("Scan", ex);
            if (!_closeWhenIdle) MessageBox.Show(this, SteamSentinel.Core.Reporting.MessageExceptions.Display(ex), DisplayText.Get("Ui.xaml.StartScanAsync.14"), MessageBoxButton.OK, MessageBoxImage.Error);
        }
        finally
        {
            SaveResourceChoices(_lastReport);
            _resourceSaveChoices.Clear();
            ScanProgressBar.IsIndeterminate = false;
            SetBusy(false);
            _scanCancellation?.Dispose();
            _scanCancellation = null;
        }
    }

    private void PreserveScanFailure(ScanReport? systemReport, ScanMode mode, IReadOnlyList<string> roots,
        Exception failure, bool cancelled)
    {
        _lastReport = ScanFailureReports.PreserveSystemResults(systemReport, mode, roots, _coordinator.Rules.Version, failure, cancelled);
        PopulateFindings(_lastReport);
        UpdateSummary(_lastReport);
        if (!_lastReport.Findings.Any(f => f.Category != FindingCategory.Coverage && f.Severity >= FindingSeverity.Medium))
            HeaderStatusText.Text = cancelled ? DisplayText.Get("Ui.xaml.PreserveScanFailure.01") : DisplayText.Get("Ui.xaml.PreserveScanFailure.02");
        HeaderDetailText.Text = DisplayText.Get("Ui.xaml.PreserveScanFailure.03");
        ProgressStageText.Text = cancelled ? DisplayText.Get("Ui.xaml.PreserveScanFailure.04") : DisplayText.Get("Ui.xaml.PreserveScanFailure.05");
        ScanProgressBar.Value = 0;
        ProgressItemText.Text = _lastReport.WorkerDiagnostics is { LastPath.Length: > 0 } diagnostic
            ? DisplayText.Format("Ui.xaml.PreserveScanFailure.06", (diagnostic.LastPath), (diagnostic.Stage))
            : DisplayText.Get("Ui.xaml.PreserveScanFailure.07");
    }

    private Task<ArchivePasswordResponse> RequestPasswordAsync(ArchivePasswordRequest request, CancellationToken cancellationToken)
    {
        return Dispatcher.InvokeAsync(() =>
        {
            cancellationToken.ThrowIfCancellationRequested();
            PasswordDialog dialog = new(request) { Owner = this };
            try
            {
                bool accepted = dialog.ShowDialog() == true;
                return new ArchivePasswordResponse(
                    request.RequestId,
                    !accepted,
                    accepted ? dialog.EnteredPassword : null,
                    false, dialog.ReuseScope,
                    Passwords: accepted ? dialog.EnteredPasswords?.ToArray() : null,
                    SkipAllEncrypted: dialog.SkipAllEncrypted);
            }
            finally { dialog.ClearReturnedPasswords(); }
        }).Task;
    }

    private void UpdateProgress(ScanProgress progress)
    {
        if (_lastReport is not null) return;
        ProgressStageText.Text = progress.DisplayStage + " · " + progress.DisplayDetail;
        ProgressItemText.Text = progress.DisplayCurrentItem;
        FooterText.Text = DisplayText.Format("Ui.xaml.UpdateProgress.01", (progress.Completed), (progress.DisplayCurrentItem));
    }

    private void PopulateFindings(ScanReport report)
    {
        Findings.Clear();
        foreach (Finding finding in report.Findings.Where(f => f.Category != FindingCategory.Coverage)) Findings.Add(new FindingItemViewModel(finding));
        FindingCountText.Text = DisplayText.Format("Ui.xaml.PopulateFindings.01", (Findings.Count));
        FindingHandlingSummaryText.Text = FindingHandlingPresentation.Count(report.Findings).Summary;
        DisplayTrustProxyDiagnostics(report.TrustProxyDiagnostics);
        DisplayRelatedComponentDiagnostics(report.RelatedComponentDiagnostics);
        DisplayContainers(report.Containers);
        IReadOnlyList<CoverageGroup> groups = CoveragePresentation.Groups(report);
        CoverageGrid.ItemsSource = groups;
        CoverageTab.Header = groups.Count > 0 ? DisplayText.Format("Ui.xaml.PopulateFindings.02", (groups.Count)) :
            report.Coverage == ScanCoverage.Complete ? DisplayText.Get("Ui.xaml.PopulateFindings.03") : DisplayText.Get("Ui.xaml.PopulateFindings.04");
        CoverageStatusText.Text = groups.Count > 0
            ? DisplayText.Format("Ui.xaml.PopulateFindings.05", (groups.Count))
            : report.Coverage == ScanCoverage.Complete
                ? DisplayText.Get("Ui.xaml.PopulateFindings.06")
                : DisplayText.Get("Ui.xaml.PopulateFindings.07");
        if (report.ResourceAudit is { } resourceAudit) CoverageStatusText.Text += "\n" + ScanResourcePresentation.Summary(resourceAudit);
        ExportButton.IsEnabled = true;
        UpdateRemediationEligibility();
        if (Findings.Count > 0) FindingsGrid.SelectedIndex = 0;
    }

    private void UpdateSummary(ScanReport report)
    {
        bool confirmed = report.Findings.Any(finding => finding.IsKnownMalware);
        bool suspicious = report.Findings.Any(finding => finding.Category != FindingCategory.Coverage && finding.Severity >= FindingSeverity.Medium);
        FindingHandlingCounts handling = FindingHandlingPresentation.Count(report.Findings);
        if (confirmed)
        {
            bool hostEvidence = report.Findings.Any(f => f.Category is FindingCategory.Process or FindingCategory.Persistence or FindingCategory.Steam && f.Severity >= FindingSeverity.High);
            HeaderStatusText.Text = hostEvidence ? DisplayText.Get("Ui.xaml.UpdateSummary.01") : DisplayText.Get("Ui.xaml.UpdateSummary.02");
            HeaderDetailText.Text = DisplayText.Get("Ui.xaml.UpdateSummary.03");
        }
        else if (suspicious)
        {
            HeaderStatusText.Text = DisplayText.Get("Ui.xaml.UpdateSummary.04");
            HeaderDetailText.Text = DisplayText.Get("Ui.xaml.UpdateSummary.05");
        }
        else if (report.Coverage == ScanCoverage.Skipped)
        {
            HeaderStatusText.Text = DisplayText.Get("Ui.xaml.UpdateSummary.06");
            HeaderDetailText.Text = DisplayText.Get("Ui.xaml.UpdateSummary.07");
        }
        else if (handling.AttentionCount > 0)
        {
            HeaderStatusText.Text = DisplayText.Format("Ui.xaml.UpdateSummary.08", (handling.AttentionCount));
            HeaderDetailText.Text = DisplayText.Format("Ui.xaml.UpdateSummary.09", (handling.NeedsReview), (handling.Unsupported), (handling.Blocked));
        }
        else if (handling.Actionable > 0)
        {
            HeaderStatusText.Text = DisplayText.Get("Ui.xaml.UpdateSummary.10");
            HeaderDetailText.Text = DisplayText.Format("Ui.xaml.UpdateSummary.11", (handling.Actionable));
        }
        else if (report.TrustProxyDiagnostics is { } diagnostic && (diagnostic.CompletedAtUtc is null ||
            !diagnostic.Checks.Any(check => check.Required) || IncompleteDiagnosticChecks(diagnostic) > 0))
        {
            HeaderStatusText.Text = DisplayText.Get("Ui.xaml.UpdateSummary.12");
            HeaderDetailText.Text = DisplayText.Get("Ui.xaml.UpdateSummary.13");
        }
        else if (report.Coverage == ScanCoverage.Complete)
        {
            HeaderStatusText.Text = DisplayText.Get("Ui.xaml.UpdateSummary.14");
            HeaderDetailText.Text = DisplayText.Get("Ui.xaml.UpdateSummary.15");
        }
        else
        {
            HeaderStatusText.Text = DisplayText.Get("Ui.xaml.UpdateSummary.16");
            HeaderDetailText.Text = report.Mode == ScanMode.Quick
                ? DisplayText.Get("Ui.xaml.UpdateSummary.17")
                : DisplayText.Get("Ui.xaml.UpdateSummary.18");
        }

        if (confirmed || suspicious || report.Coverage != ScanCoverage.Skipped && (handling.AttentionCount > 0 || handling.Actionable > 0))
            HeaderDetailText.Text += report.Coverage == ScanCoverage.Complete
                ? DisplayText.Get("Ui.xaml.UpdateSummary.19") : DisplayText.Get("Ui.xaml.UpdateSummary.20");
        string scanName = report.Mode == ScanMode.Quick ? DisplayText.Get("Ui.xaml.UpdateSummary.21") : DisplayText.Get("Ui.xaml.UpdateSummary.22");
        ProgressStageText.Text = report.Coverage == ScanCoverage.Skipped ? DisplayText.Get("Ui.xaml.UpdateSummary.23") :
            scanName + (report.Coverage == ScanCoverage.Complete ? DisplayText.Get("Ui.xaml.UpdateSummary.24") : DisplayText.Get("Ui.xaml.UpdateSummary.25"));
        ProgressItemText.Text = report.Coverage == ScanCoverage.Complete
            ? DisplayText.Get("Ui.xaml.UpdateSummary.26")
            : DisplayText.Get("Ui.xaml.UpdateSummary.27");
        ScanProgressBar.Value = 100;
        FooterText.Text = DisplayText.Format("Ui.xaml.UpdateSummary.28", (report.Metrics.FilesVisited), (report.Metrics.WorkshopItemsVisited), (report.Metrics.ArchiveEntriesVisited), (ReportExporter.CoverageLabel(report.Coverage)));
    }

    private void FindingsGrid_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        FindingItemViewModel? item = FindingsGrid.SelectedItem as FindingItemViewModel;
        DetailDescriptionText.Text = item is null ? string.Empty : item.Title + "\n" + item.Description + "\n" + item.HandlingDetails +
            (RelatedComponentReportPresentation.IsRelatedFinding(item.Finding)
                ? "\n" + RelatedComponentReportPresentation.DescribeFinding(item.Finding, _lastReport?.RelatedComponentDiagnostics) : string.Empty);
        DetailEvidenceText.Text = item?.Evidence ?? string.Empty;
        DetailHashText.Text = item is null ? string.Empty : DisplayText.Format("Ui.xaml.FindingsGrid_SelectionChanged.01", (item.Sha256), (item.Finding.TargetSha256 ?? DisplayText.Get("Ui.xaml.FindingsGrid_SelectionChanged.02")), (item.Finding.ContentPath ?? item.Target));
        DetailWorkshopText.Text = item?.WorkshopId ?? string.Empty;
        UpdateFindingActions();
    }

    private async void Occupancy_Click(object sender, RoutedEventArgs e)
    {
        if (_busy || FindingsGrid.SelectedItem is not FindingItemViewModel item || item.IsTrustProxyFinding ||
            RelatedComponentReportPresentation.IsRelatedFinding(item.Finding)) return;
        SetBusy(true);
        ShowActivity(ActivityPhase.Inspecting, DisplayText.Get("Ui.xaml.Occupancy_Click.01"));
        try
        {
            List<string> paths = FindingReviewTargets.Get(item.Finding);
            if (paths.Count == 0) paths.AddRange(await Task.Run(() => new RelatedArtifactScanner(_coordinator.Rules).GetCandidatePathsAsync(item.Finding)));
            if (paths.Count == 0)
            {
                MessageBox.Show(this, DisplayText.Get("Ui.xaml.Occupancy_Click.02"), DisplayText.Get("Ui.xaml.Occupancy_Click.03"), MessageBoxButton.OK, MessageBoxImage.Information);
                return;
            }
            List<string> details = [];
            foreach (string path in paths.Take(4))
            {
                FileOccupancyResult occupancy = await Task.Run(() => FileOccupancy.Inspect(path, Directory.Exists(path)))
                    .WaitAsync(TimeSpan.FromSeconds(15));
                details.Add(path + "\n" + FileOccupancy.Describe(occupancy));
            }
            details.Add(DisplayText.Get("Ui.xaml.Occupancy_Click.04"));
            DetailEvidenceText.Text = string.Join("\n\n", details);
            new TextDetailsWindow(DisplayText.Get("Ui.xaml.Occupancy_Click.05"), DetailEvidenceText.Text) { Owner = this }.ShowDialog();
        }
        catch (Exception ex) { MessageBox.Show(this, DisplayText.Get("Ui.xaml.Occupancy_Click.06") + SteamSentinel.Core.Reporting.MessageExceptions.Display(ex), DisplayText.Get("Ui.xaml.Occupancy_Click.07"), MessageBoxButton.OK, MessageBoxImage.Information); }
        finally { SetBusy(false); }
    }

    private async void ReviewFinding_Click(object sender, RoutedEventArgs e)
    {
        if (_busy || FindingsGrid.SelectedItem is not FindingItemViewModel item) return;
        if (item.IsTrustProxyFinding)
        {
            await RunTrustProxyDiagnosticsAsync();
            return;
        }
        if (RelatedComponentReportPresentation.IsRelatedFinding(item.Finding) && GetRelatedFindingReviewTargets(item.Finding).Count == 0) return;
        List<string> targets;
        SetBusy(true);
        ShowActivity(ActivityPhase.Inspecting);
        try
        {
            targets = RelatedComponentReportPresentation.IsRelatedFinding(item.Finding) ? GetRelatedFindingReviewTargets(item.Finding)
                : (await Task.Run(() => new RelatedArtifactScanner(_coordinator.Rules).GetCandidatePathsAsync(item.Finding)))
                .Concat(FindingReviewTargets.Get(item.Finding).Where(Directory.Exists))
                .Distinct(StringComparer.OrdinalIgnoreCase).ToList();
        }
        catch (Exception ex) { MessageBox.Show(this, SteamSentinel.Core.Reporting.MessageExceptions.Display(ex), DisplayText.Get("Ui.xaml.ReviewFinding_Click.01"), MessageBoxButton.OK, MessageBoxImage.Information); return; }
        finally { SetBusy(false); }
        if (MessageBox.Show(this, DisplayText.Get("Ui.xaml.ReviewFinding_Click.02") +
            (targets.Count == 0 ? DisplayText.Get("Ui.xaml.ReviewFinding_Click.03") : DisplayText.Format("Ui.xaml.ReviewFinding_Click.04", (targets.Count))),
            DisplayText.Get("Ui.xaml.ReviewFinding_Click.05"), MessageBoxButton.OKCancel, MessageBoxImage.Information) != MessageBoxResult.OK) return;
        ArchiveCheckBox.IsChecked = true;
        await StartScanAsync(ScanMode.Custom, targets, reviewRelated: true);
    }

    private void SelectAll_Click(object sender, RoutedEventArgs e)
    {
        foreach (FindingItemViewModel item in Findings.Where(item => item.CanSelect)) item.IsSelected = true;
    }

    private void ClearSelection_Click(object sender, RoutedEventArgs e)
    {
        foreach (FindingItemViewModel item in Findings) item.IsSelected = false;
    }

    private async void Remediate_Click(object sender, RoutedEventArgs e) =>
        await ExecuteSelectedRemediationAsync();

    private async void Export_Click(object sender, RoutedEventArgs e)
    {
        if (_lastReport is null) return;
        SaveFileDialog dialog = new()
        {
            Title = _caseResult is null ? DisplayText.Get("Ui.xaml.Export_Click.01") : DisplayText.Get("Ui.xaml.Export_Click.02"),
            Filter = DisplayText.Get("Ui.xaml.Export_Click.03"),
            FileName = $"SteamSentinel-{_lastReport.ScanId:N}.md"
        };
        if (dialog.ShowDialog(this) != true) return;
        System.Globalization.CultureInfo? exportCulture = null;
        if (ExportLanguageDialog.RequiredForPath(dialog.FileName))
        {
            exportCulture = ChooseExportLanguage();
            if (exportCulture is null) return;
        }
        SetBusy(true);
        ShowActivity(ActivityPhase.Exporting);
        try
        {
            string extension = Path.GetExtension(dialog.FileName);
            if (extension.Equals(".zip", StringComparison.OrdinalIgnoreCase))
                await Task.Run(() => CaseBundleExporter.ExportAsync(dialog.FileName, _caseScan ?? _lastReport, _casePlan, _caseResult, _caseFollowUp,
                    batches: _caseBatch, contentFollowUp: _caseContentFollowUp, latestDiagnostics: _lastReport.TrustProxyDiagnostics,
                    latestRelatedDiagnostics: _lastReport.RelatedComponentDiagnostics, persistedCase: _persistedCase, culture: exportCulture));
            else if (extension.Equals(".json", StringComparison.OrdinalIgnoreCase))
                await Task.Run(() => ReportExporter.ExportJsonAsync(_lastReport, dialog.FileName));
            else await Task.Run(() => ReportExporter.ExportMarkdownAsync(_lastReport, dialog.FileName, exportCulture!));
            FooterText.Text = DisplayText.Format("Ui.xaml.Export_Click.04", (dialog.FileName));
        }
        catch (Exception ex) { MessageBox.Show(this, SteamSentinel.Core.Reporting.MessageExceptions.Display(ex), DisplayText.Get("Ui.xaml.Export_Click.05"), MessageBoxButton.OK, MessageBoxImage.Warning); }
        finally { SetBusy(false); }
    }

    private async void RefreshQuarantine_Click(object sender, RoutedEventArgs e)
    {
        if (_busy) return;
        SetBusy(true);
        ShowActivity(ActivityPhase.Working, DisplayText.Get("Ui.xaml.RefreshQuarantine_Click.01"));
        try { await RefreshQuarantineItemsAsync(); }
        finally { SetBusy(false); }
    }

    private async Task RefreshQuarantineItemsAsync()
    {
        QuarantineItems.Clear();
        if (!Directory.Exists(AppPaths.QuarantineRoot)) return;

        string[] incidentPaths;
        try
        {
            incidentPaths = await Task.Run(() => Directory.EnumerateDirectories(AppPaths.QuarantineRoot).Take(2049).ToArray());
            if (incidentPaths.Length > 2048) FooterText.Text = DisplayText.Get("Ui.xaml.RefreshQuarantineItemsAsync.01");
        }
        catch (Exception ex)
        {
            FooterText.Text = DisplayText.Format("Ui.xaml.RefreshQuarantineItemsAsync.02", (SteamSentinel.Core.Reporting.MessageExceptions.Display(ex)));
            return;
        }

        using System.Security.Principal.WindowsIdentity identity = System.Security.Principal.WindowsIdentity.GetCurrent();
        foreach (string incidentPath in incidentPaths.Take(2048))
        {
            if (!Guid.TryParseExact(Path.GetFileName(incidentPath), "D", out Guid incidentId) &&
                !Guid.TryParseExact(Path.GetFileName(incidentPath), "N", out incidentId)) continue;
            string manifestPath = Path.Combine(incidentPath, "manifest.json");
            try
            {
                if (Validation.ContainsReparsePoint(manifestPath) || new FileInfo(manifestPath).Length > 2 * 1024 * 1024)
                    throw new InvalidDataException(DisplayText.Get("Ui.xaml.RefreshQuarantineItemsAsync.03"));
                QuarantineManifest manifest = await JsonFile.ReadAsync<QuarantineManifest>(manifestPath);
                if (!string.Equals(manifest.RequestedBySid, identity.User?.Value, StringComparison.Ordinal))
                {
                    if (string.IsNullOrEmpty(manifest.RequestedBySid))
                        QuarantineItems.Add(new QuarantineItemViewModel
                        {
                            Manifest = new() { IncidentId = incidentId },
                            ManifestPath = manifestPath,
                            ReadError = DisplayText.Get("Ui.xaml.RefreshQuarantineItemsAsync.04")
                        });
                    continue;
                }
                QuarantineItems.Add(new QuarantineItemViewModel { Manifest = manifest, ManifestPath = manifestPath });
            }
            catch (UnauthorizedAccessException)
            {
                // Another user's event is intentionally not readable or displayed.
            }
            catch (Exception ex)
            {
                AppErrorLog.Write("ReadQuarantineManifest", ex);
                QuarantineItems.Add(new QuarantineItemViewModel
                {
                    Manifest = new() { IncidentId = incidentId },
                    ManifestPath = manifestPath,
                    ReadError = DisplayText.Get("Ui.xaml.RefreshQuarantineItemsAsync.05")
                });
            }
        }
    }

    private void OpenQuarantine_Click(object sender, RoutedEventArgs e)
    {
        if (!Directory.Exists(AppPaths.QuarantineRoot))
        {
            MessageBox.Show(this, DisplayText.Get("Ui.xaml.OpenQuarantine_Click.01"), "SteamSentinel", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }
        Process.Start(new ProcessStartInfo("explorer.exe", AppPaths.QuarantineRoot) { UseShellExecute = true });
    }

    private async void Rollback_Click(object sender, RoutedEventArgs e)
    {
        if (QuarantineGrid.SelectedItem is not QuarantineItemViewModel selected) return;
        if (selected.ReadError is not null) { MessageBox.Show(this, selected.ReadError, DisplayText.Get("Ui.xaml.Rollback_Click.01")); return; }
        if (MessageBox.Show(this,
                DisplayText.Get("Ui.xaml.Rollback_Click.02"),
                DisplayText.Get("Ui.xaml.Rollback_Click.03"), MessageBoxButton.YesNo, MessageBoxImage.Warning) != MessageBoxResult.Yes) return;
        await RunIncidentActionAsync(RemediationActionType.RollbackIncident, selected.IncidentId);
    }

    private async void DeleteIncident_Click(object sender, RoutedEventArgs e)
    {
        if (QuarantineGrid.SelectedItem is not QuarantineItemViewModel selected) return;
        if (selected.ReadError is not null) { MessageBox.Show(this, selected.ReadError, DisplayText.Get("Ui.xaml.DeleteIncident_Click.01")); return; }
        MessageText? rejection = IncidentDeletionPolicy.RejectionReason(selected.Manifest, _lastReport,
            _lastFullSystemAndContentScanId, DateTimeOffset.UtcNow,
            DateTimeOffset.UtcNow - TimeSpan.FromMilliseconds(Environment.TickCount64));
        if (rejection is not null)
        {
            MessageBox.Show(this, rejection.Display, DisplayText.Get("Ui.xaml.DeleteIncident_Click.02"), MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }
        if (MessageBox.Show(this,
                DisplayText.Get("Ui.xaml.DeleteIncident_Click.03"),
                DisplayText.Get("Ui.xaml.DeleteIncident_Click.04"), MessageBoxButton.YesNo, MessageBoxImage.Stop, MessageBoxResult.No) != MessageBoxResult.Yes) return;
        await RunIncidentActionAsync(RemediationActionType.DeleteIncident, selected.IncidentId);
    }

    private async Task RunIncidentActionAsync(RemediationActionType type, string incidentId)
    {
        if (_busy) return;
        if (!await EnsureRemediationAvailableAsync()) return;
        SetBusy(true);
        _operationCommitted = true;
        ShowActivity(ActivityPhase.Applying, type == RemediationActionType.RollbackIncident
            ? DisplayText.Get("Ui.xaml.RunIncidentActionAsync.01")
            : DisplayText.Get("Ui.xaml.RunIncidentActionAsync.02"));
        try
        {
            RemediationPlan plan = new()
            {
                Actions =
                {
                    new RemediationAction
                    {
                        Type = type,
                        DisplayName = type == RemediationActionType.RollbackIncident ? DisplayText.Get("Ui.xaml.RunIncidentActionAsync.03") : DisplayText.Get("Ui.xaml.RunIncidentActionAsync.04"),
                        Target = incidentId,
                        IncidentId = incidentId
                    }
                }
            };
            RemediationCaseRecord incidentCase = new()
            {
                UserSid = plan.RequestedBySid,
                Plans = [plan],
                RequireContentFollowUp = false,
                RequireRelatedFollowUp = false,
                Notes = [DisplayText.Get("Ui.xaml.RunIncidentActionAsync.05")]
            };
            await _caseStore.SaveAsync(incidentCase);
            RemediationRunResult result = await Task.Run(() => ExecuteRecordedPlanAsync(plan, incidentCase));
            DisplayCaseRecord(incidentCase);
            await RefreshCaseRecordsAsync();
            HideActivity();
            MessageBox.Show(this,
                string.Join(Environment.NewLine,
                    result.Actions.Select(action => action.Message).Concat(result.Errors.Select(error => DisplayText.Get("Ui.xaml.RunIncidentActionAsync.06") + error))),
                result.Success ? DisplayText.Get("Ui.xaml.RunIncidentActionAsync.07") : DisplayText.Get("Ui.xaml.RunIncidentActionAsync.08"),
                MessageBoxButton.OK,
                result.Success ? MessageBoxImage.Information : MessageBoxImage.Error);
            await RefreshQuarantineItemsAsync();
        }
        catch (OperationCanceledException) { }
        catch (Exception ex)
        {
            MessageBox.Show(this, SteamSentinel.Core.Reporting.MessageExceptions.Display(ex), DisplayText.Get("Ui.xaml.RunIncidentActionAsync.09"), MessageBoxButton.OK, MessageBoxImage.Error);
        }
        finally
        {
            _operationCommitted = false;
            SetBusy(false);
        }
    }

    private void SetBusy(bool busy)
    {
        bool wasBusy = _busy;
        _busy = busy;
        if (busy && !wasBusy) ShowActivity(ActivityPhase.Working);
        if (!busy) HideActivity();
        QuickScanButton.IsEnabled = !busy;
        ScanSettingsButton.IsEnabled = !busy;
        WorkshopScopeComboBox.IsEnabled = !busy;
        DownloadLocationsCheckBox.IsEnabled = !busy;
        ExecutionHistoryCheckBox.IsEnabled = !busy;
        FullScanButton.IsEnabled = !busy;
        FileScanButton.IsEnabled = !busy;
        FolderScanButton.IsEnabled = !busy;
        ArchiveCheckBox.IsEnabled = !busy;
        DomainBlockCheckBox.IsEnabled = !busy;
        AmsiCheckBox.IsEnabled = !busy && ScanEnhancements.AmsiAvailable;
        DeepSignatureCheckBox.IsEnabled = !busy;
        CoverSelectedButton.IsEnabled = !busy && CoverageGrid.SelectedItem is CoverageGroup { CanFullScan: true } group && CoverageTargets(group).Count > 0;
        RetryPasswordsButton.IsEnabled = !busy && _lastReport is not null && GetPasswordRetryTargets(_lastReport).Count > 0;
        CancelScanButton.IsEnabled = busy && _scanCancellation is not null;
        UpdateRemediationEligibility();
        ExportButton.IsEnabled = !busy && _lastReport is not null;
        UpdateFindingActions();
        TrustProxyScanButton.IsEnabled = !busy && !_remediationClient.HasUnresolvedExecution;
        CaseRefreshButton.IsEnabled = !busy;
        CaseRecheckButton.IsEnabled = !busy && CaseListComboBox.Items.Count > 0;
        CaseExportButton.IsEnabled = !busy && CaseListComboBox.Items.Count > 0;
        CaseListComboBox.IsEnabled = !busy;
        UpdateContainerActions();
        RollbackButton.IsEnabled = !busy && !_recoveryRequired && !_caseRecoveryUnavailable && !_remediationClient.HasUnresolvedExecution && _installationSecurity.IsProtected;
        DeleteIncidentButton.IsEnabled = !busy && !_recoveryRequired && !_caseRecoveryUnavailable && !_remediationClient.HasUnresolvedExecution && _installationSecurity.IsProtected;
        ElevateButton.IsEnabled = !busy && _installationSecurity.IsProtected && !_elevationContext.IsElevated;
        RefreshInstallationButton.IsEnabled = !busy;
        if (!busy && _closeWhenIdle && !_windowClosed)
        {
            _closeWhenIdle = false;
            Dispatcher.BeginInvoke(new Action(Close));
        }
    }

    private async Task<bool> EnsureRemediationAvailableAsync()
    {
        if (_recoveryRequired || _caseRecoveryUnavailable || _remediationClient.HasUnresolvedExecution)
        {
            MessageBox.Show(this, DisplayText.Get("Ui.xaml.EnsureRemediationAvailableAsync.01"), DisplayText.Get("Ui.xaml.EnsureRemediationAvailableAsync.02"), MessageBoxButton.OK, MessageBoxImage.Warning);
            return false;
        }
        await RefreshInstallationSecurityAsync();
        if (_installationSecurity.IsProtected)
        {
            if (_elevationContext.CanElevateSameUser) return true;
            // Broker plans remain bound to one SID. A different administrator must rescan.
            await OpenAdministratorWindowAsync();
            return false;
        }
        MessageBox.Show(this,
            _installationSecurity.MessageText.Display + DisplayText.Get("Ui.xaml.EnsureRemediationAvailableAsync.03"),
            DisplayText.Get("Ui.xaml.EnsureRemediationAvailableAsync.04"),
            MessageBoxButton.OK,
            MessageBoxImage.Warning);
        return false;
    }

    internal void EnterRecoveryMode()
    {
        _recoveryRequired = true;
        _reportNeedsRefresh = true;
        if (!_operationCommitted) _scanCancellation?.Cancel();
        RemediateButton.IsEnabled = false;
        RollbackButton.IsEnabled = false;
        DeleteIncidentButton.IsEnabled = false;
        HeaderStatusText.Text = DisplayText.Get("Ui.xaml.EnterRecoveryMode.01");
        FooterText.Text = DisplayText.Get("Ui.xaml.EnterRecoveryMode.02");
    }

    private void ApplyInstallationSecurityStatus()
    {
        InstallationSecurityText.Text = _installationSecurity.IsProtected
            ? (_elevationContext.IsElevated ? DisplayText.Get("Ui.xaml.ApplyInstallationSecurityStatus.01") : DisplayText.Get("Ui.xaml.ApplyInstallationSecurityStatus.02"))
            : DisplayText.Format("Ui.xaml.ApplyInstallationSecurityStatus.03", (_installationSecurity.MessageText.Display));
        ElevationHintText.Text = !_installationSecurity.IsProtected
            ? DisplayText.Get("Ui.xaml.ApplyInstallationSecurityStatus.04")
            : _elevationContext.IsElevated
                ? DisplayText.Get("Ui.xaml.ApplyInstallationSecurityStatus.05")
                : _elevationContext.CanElevateSameUser
                    ? DisplayText.Get("Ui.xaml.ApplyInstallationSecurityStatus.06")
                    : DisplayText.Get("Ui.xaml.ApplyInstallationSecurityStatus.07");
        ElevateButton.Content = _elevationContext.IsElevated ? DisplayText.Get("Ui.xaml.ApplyInstallationSecurityStatus.08") : DisplayText.Get("Ui.xaml.ApplyInstallationSecurityStatus.09");
        ElevateButton.ToolTip = DisplayText.Get("Ui.xaml.ApplyInstallationSecurityStatus.10");
        RefreshInstallationButton.ToolTip = DisplayText.Get("Ui.xaml.ApplyInstallationSecurityStatus.11");
        InstallationSecurityText.Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString(
            _installationSecurity.IsProtected ? "#027A48" : "#B54708"));
        string tooltip = _installationSecurity.IsProtected ? DisplayText.Get("Ui.xaml.ApplyInstallationSecurityStatus.12") : _installationSecurity.MessageText.Display;
        RollbackButton.ToolTip = tooltip;
        DeleteIncidentButton.ToolTip = tooltip;
        SetBusy(_busy);
    }

    private async Task RefreshInstallationSecurityAsync()
    {
        SetBusy(true);
        try
        {
            _installationSecurity = await Task.Run(() => InstallationSecurity.Evaluate());
            _elevationContext = ElevationContext.Read();
            ApplyInstallationSecurityStatus();
        }
        finally { SetBusy(false); }
    }

    private async void RefreshInstallation_Click(object sender, RoutedEventArgs e)
    {
        if (_busy) return;
        try
        {
            RemediationRunResult? recovered = await _remediationClient.TryRecoverResultAsync();
            if (recovered is not null)
            {
                _caseResult = recovered;
                await RecordRecoveredResultAsync(recovered);
                if (_caseBatch is not null && !_caseBatch.Results.Any(item => item.PlanId == recovered.PlanId))
                    _caseBatch.Results.Add(recovered);
                _reportNeedsRefresh = true;
                UpdateBatchResults();
                FooterText.Text = DisplayText.Get("Ui.xaml.RefreshInstallation_Click.01");
            }
            else if (_remediationClient.HasUnresolvedExecution)
                FooterText.Text = DisplayText.Get("Ui.xaml.RefreshInstallation_Click.02");
            await RefreshInstallationSecurityAsync();
        }
        catch (Exception ex) { AppErrorLog.Write("RecoverBrokerResult", ex); FooterText.Text = SteamSentinel.Core.Reporting.MessageExceptions.Display(ex); }
    }

    private async void Elevate_Click(object sender, RoutedEventArgs e)
    {
        if (!_busy) await OpenAdministratorWindowAsync();
    }

    private async Task OpenAdministratorWindowAsync()
    {
        if (_elevationContext.IsElevated) return;
        if (MessageBox.Show(this,
                DisplayText.Get("Ui.xaml.OpenAdministratorWindowAsync.01"),
                DisplayText.Get("Ui.xaml.OpenAdministratorWindowAsync.02"), MessageBoxButton.OKCancel, MessageBoxImage.Information) != MessageBoxResult.OK) return;
        SetBusy(true);
        try
        {
            ElevationOutcome outcome = await Task.Run(() => new ElevationService().OpenAdministratorWindow());
            FooterText.Text = outcome == ElevationOutcome.Cancelled
                ? DisplayText.Get("Ui.xaml.OpenAdministratorWindowAsync.03")
                : DisplayText.Get("Ui.xaml.OpenAdministratorWindowAsync.04");
        }
        catch (Exception ex)
        {
            MessageBox.Show(this, DisplayText.Format("Ui.xaml.OpenAdministratorWindowAsync.05", (SteamSentinel.Core.Reporting.MessageExceptions.Display(ex))),
                DisplayText.Get("Ui.xaml.OpenAdministratorWindowAsync.06"), MessageBoxButton.OK, MessageBoxImage.Warning);
        }
        finally { SetBusy(false); }
    }

    private static bool IsSteamRunning()
    {
        foreach (Process process in Process.GetProcesses())
        {
            using (process)
            {
                try
                {
                    if (IsSteamClientProcessName(process.ProcessName)) return true;
                }
                catch { }
            }
        }
        return false;
    }

    internal static bool IsSteamClientProcessName(string processName) =>
        processName.Equals("steam", StringComparison.OrdinalIgnoreCase) ||
        processName.Equals("steamwebhelper", StringComparison.OrdinalIgnoreCase);
}

public sealed record WorkshopScopeItem(string AppId, string Label);
