using System.Windows;
using SteamSentinel.Core.Models;
using SteamSentinel.Core.Reporting;
using SteamSentinel.Core.Utilities;
using SteamSentinel.App.ViewModels;

namespace SteamSentinel.App;

public partial class MainWindow
{
    private ScanReport? _trustProxyBaseReport;
    private ScanReport? _trustProxyMergedReport;
    private static string DiagnosticScopePrefix => DisplayText.Get("Ui.TrustProxy.DiagnosticScopePrefix.01");
    private const int MaximumDiagnosticDisplayCharacters = 256_000;

    private void PreserveSystemStageFailure(ScanReport? checkpoint, ScanMode mode, Exception failure, bool cancelled)
    {
        _lastReport = Services.ScanFailureReports.PreserveSystemStage(checkpoint, mode, _coordinator.Rules.Version, failure, cancelled);
        _lastFullSystemAndContentScanId = null;
        PopulateFindings(_lastReport);
        UpdateSummary(_lastReport);
        HeaderStatusText.Text = cancelled ? DisplayText.Get("Ui.TrustProxy.PreserveSystemStageFailure.01") : DisplayText.Get("Ui.TrustProxy.PreserveSystemStageFailure.02");
        HeaderDetailText.Text = DisplayText.Get("Ui.TrustProxy.PreserveSystemStageFailure.03");
        ProgressStageText.Text = DisplayText.Get("Ui.TrustProxy.PreserveSystemStageFailure.04");
        ScanProgressBar.Value = 0;
    }

    private void UpdateRemediationEligibility()
    {
        if (RemediateButton is null || SelectAllButton is null || Findings is null) return;
        FindingHandlingCounts counts = FindingHandlingPresentation.Count(Findings.Select(item => item.Finding));
        bool available = counts.Actionable > 0;
        RemediationAvailability availability = GetRemediationAvailability(counts);
        RemediateButton.IsEnabled = availability.CanRemediate;
        RemediateButton.ToolTip = availability.State == RemediationAvailabilityState.InstallationUnavailable
            ? _installationSecurity.MessageText.Display + DisplayText.Get("Ui.TrustProxy.UpdateRemediationEligibility.06")
            : availability.CanRemediate ? DisplayText.Get("Ui.TrustProxy.UpdateRemediationEligibility.07")
            : RemediationAvailabilityText(availability.State);
        UpdateRemediationAvailabilityPresentation(availability);
        SelectAllButton.IsEnabled = !_busy && !_reportNeedsRefresh && available;
        SelectAllButton.ToolTip = !available ? DisplayText.Get("Ui.TrustProxy.UpdateRemediationEligibility.08") + (counts.AttentionCount > 0 ? DisplayText.Get("Ui.TrustProxy.UpdateRemediationEligibility.09") : DisplayText.Get("Ui.TrustProxy.UpdateRemediationEligibility.10"))
            : _busy ? DisplayText.Get("Ui.TrustProxy.UpdateRemediationEligibility.11")
            : _reportNeedsRefresh ? DisplayText.Get("Ui.TrustProxy.UpdateRemediationEligibility.12") : DisplayText.Format("Ui.TrustProxy.UpdateRemediationEligibility.13", (counts.Actionable));
    }

    private void UpdateFindingActions()
    {
        if (ReviewFindingButton is null || OccupancyButton is null || FindingsGrid is null) return;
        FindingItemViewModel? item = FindingsGrid.SelectedItem as FindingItemViewModel;
        bool diagnostic = item?.IsTrustProxyFinding == true;
        bool related = item is not null && RelatedComponentReportPresentation.IsRelatedFinding(item.Finding);
        bool relatedFileAvailable = !related || GetRelatedFindingReviewTargets(item!.Finding).Count > 0;
        bool visiblePage = ResultTabs.SelectedIndex == 0;
        ReviewFindingButton.Content = diagnostic ? DisplayText.Get("Ui.TrustProxy.UpdateFindingActions.01") : DisplayText.Get("Ui.TrustProxy.UpdateFindingActions.02");
        ReviewFindingButton.ToolTip = diagnostic
            ? DisplayText.Get("Ui.TrustProxy.UpdateFindingActions.03")
            : related && !relatedFileAvailable ? DisplayText.Get("Ui.TrustProxy.UpdateFindingActions.04")
            : DisplayText.Get("Ui.TrustProxy.UpdateFindingActions.05");
        ReviewFindingButton.IsEnabled = !_busy && visiblePage && item is not null &&
            relatedFileAvailable && (!diagnostic || !_remediationClient.HasUnresolvedExecution);
        OccupancyButton.Visibility = diagnostic || related ? Visibility.Collapsed : Visibility.Visible;
        OccupancyButton.IsEnabled = !_busy && visiblePage && item is not null && !diagnostic && !related;
    }

    private async void TrustProxyScan_Click(object sender, RoutedEventArgs e) => await RunTrustProxyDiagnosticsAsync();

    // The optional runner lets hidden STA fixtures exercise the real UI lifecycle using inert data.
    // It only substitutes local, read-only collection and never provides remediation authority.
    internal async Task RunTrustProxyDiagnosticsAsync(
        Func<IProgress<ScanProgress>?, CancellationToken, Task<ScanReport>>? runner = null)
    {
        Dispatcher.VerifyAccess();
        if (_busy || _remediationClient.HasUnresolvedExecution) return;
        DateTimeOffset started = DateTimeOffset.UtcNow;
        SetBusy(true);
        ShowActivity(ActivityPhase.Inspecting, DisplayText.Get("Ui.TrustProxy.RunTrustProxyDiagnosticsAsync.01"));
        ResultTabs.SelectedItem = TrustProxyTab;
        TrustProxyStatusText.Text = DisplayText.Get("Ui.TrustProxy.RunTrustProxyDiagnosticsAsync.02");
        _scanCancellation = new CancellationTokenSource();
        CancellationToken cancellation = _scanCancellation.Token;
        CancelScanButton.IsEnabled = true;
        using var progress = CreateUiProgress(p =>
        {
            TrustProxyStatusText.Text = p.DisplayStage + " · " + p.DisplayCurrentItem;
            ActivityDetailText.Text = p.DisplayDetail;
        });
        try
        {
            runner ??= (reporter, token) => _coordinator.RunTrustProxyDiagnosticsAsync(reporter, token);
            ScanReport diagnostic = await Task.Run(() => runner(progress, cancellation));
            ApplyTrustProxyDiagnosticReport(diagnostic);
        }
        catch (Exception ex)
        {
            DiagnosticCheck failed = new()
            {
                NameText = MessageText.Create("Ui.TrustProxy.RunTrustProxyDiagnosticsAsync.03"),
                Status = ex is OperationCanceledException ? DiagnosticReadStatus.Cancelled : DiagnosticReadStatus.Failed,
                DetailText = MessageText.Create("Ui.TrustProxy.RunTrustProxyDiagnosticsAsync.04") + MessageExceptions.Describe(ex)
            };
            TrustProxyDiagnosticReport diagnostic = new() { StartedAtUtc = started, CompletedAtUtc = DateTimeOffset.UtcNow, Checks = [failed] };
            ApplyTrustProxyDiagnosticReport(new ScanReport
            {
                StartedAtUtc = started,
                StatusSchemaVersion = ScanExecution.SchemaVersion,
                ExecutionState = ex is OperationCanceledException ? ScanExecutionState.Cancelled : ScanExecutionState.Failed,
                ExecutionReasonCode = ReasonCodes.ForFailureType(ex.GetType().Name),
                CompletedAtUtc = diagnostic.CompletedAtUtc,
                Mode = ScanMode.Custom,
                Coverage = ScanCoverage.Partial,
                RuleSetVersion = _coordinator.Rules.Version,
                TrustProxyDiagnostics = diagnostic,
                ScopeNotes = [DiagnosticScopePrefix + DisplayText.Get("Ui.TrustProxy.RunTrustProxyDiagnosticsAsync.05")],
                Findings = [new Finding
                {
                    RuleId = "TRUST-PROXY-DIAGNOSTIC-FAILED", Category = FindingCategory.Coverage,
                    SourceKind = "trust-proxy-diagnostics", DiagnosticObservationIds = [failed.Id],
                    Title = DisplayText.Get("Ui.TrustProxy.RunTrustProxyDiagnosticsAsync.06"), Target = DisplayText.Get("Ui.TrustProxy.RunTrustProxyDiagnosticsAsync.07"), Description = failed.Detail,
                    HandlingReason = FindingHandlingReason.IncompleteInspection
                }]
            });
        }
        finally
        {
            _scanCancellation.Dispose();
            _scanCancellation = null;
            SetBusy(false);
        }
    }

    internal void ApplyTrustProxyDiagnosticReport(ScanReport diagnostic)
    {
        Dispatcher.VerifyAccess();
        if (!ReferenceEquals(_lastReport, _trustProxyMergedReport)) _trustProxyBaseReport = _lastReport;
        _trustProxyMergedReport = MergeTrustProxyDiagnosticReport(_trustProxyBaseReport, diagnostic);
        _lastReport = _trustProxyMergedReport;
        // A diagnostic refresh is not a new full-system/content rescan or a cleanup attestation.
        _lastFullSystemAndContentScanId = null;
        PopulateFindings(_lastReport);
        UpdateSummary(_lastReport);
        ResultTabs.SelectedItem = TrustProxyTab;
        FooterText.Text = DisplayText.Get("Ui.TrustProxy.ApplyTrustProxyDiagnosticReport.01");
    }

    internal static ScanReport MergeTrustProxyDiagnosticReport(ScanReport? basis, ScanReport diagnostic)
    {
        if (diagnostic.TrustProxyDiagnostics is null)
            throw new InvalidDataException(DisplayText.Get("Ui.TrustProxy.MergeTrustProxyDiagnosticReport.01"));
        if (basis is null) return diagnostic;
        return new ScanReport
        {
            ProductVersion = basis.ProductVersion,
            StatusSchemaVersion = basis.StatusSchemaVersion,
            ExecutionState = basis.ExecutionState,
            ExecutionReasonCode = basis.ExecutionReasonCode,
            LegacyExecutionStatus = basis.LegacyExecutionStatus,
            BuildIdentity = basis.BuildIdentity,
            RuleSetVersion = basis.RuleSetVersion,
            StartedAtUtc = basis.StartedAtUtc,
            CompletedAtUtc = basis.CompletedAtUtc,
            MachineName = basis.MachineName,
            UserName = basis.UserName,
            Mode = basis.Mode,
            Coverage = basis.Coverage == ScanCoverage.Complete && diagnostic.Coverage == ScanCoverage.Complete
                ? ScanCoverage.Complete : ScanCoverage.Partial,
            Roots = [.. basis.Roots],
            CoverageNotes = [.. basis.CoverageNotes],
            CoverageNotices = [.. basis.CoverageNotices],
            CoverageAggregates = [.. basis.CoverageAggregates],
            Findings = [.. basis.Findings.Where(f => !FindingHandlingPresentation.IsTrustProxyFinding(f)), .. diagnostic.Findings],
            RootSummaries = [.. basis.RootSummaries],
            CandidateRoots = [.. basis.CandidateRoots],
            ContentSources = [.. basis.ContentSources],
            Metrics = basis.Metrics,
            ContentScanSettings = basis.ContentScanSettings,
            WorkerDiagnostics = basis.WorkerDiagnostics,
            TrustProxyDiagnostics = diagnostic.TrustProxyDiagnostics,
            RelatedComponentDiagnostics = basis.RelatedComponentDiagnostics,
            // Retain original evidence regardless of its display language. The caller keeps
            // the original base report, so repeated refreshes do not accumulate merged notes.
            ScopeNotes = [.. basis.ScopeNotes, .. diagnostic.ScopeNotes,
                DiagnosticScopePrefix + DisplayText.Format("Ui.TrustProxy.MergeTrustProxyDiagnosticReport.02", (basis.ScanId))]
        };
    }

    internal static int IncompleteDiagnosticChecks(TrustProxyDiagnosticReport diagnostic) => diagnostic.Checks.Count(check =>
        check.Required && check.Status is not (DiagnosticReadStatus.Complete or DiagnosticReadStatus.NotPresent));

    private void DisplayTrustProxyDiagnostics(TrustProxyDiagnosticReport? diagnostic)
    {
        if (TrustProxyDetailsText is null) return;
        if (diagnostic is null)
        {
            TrustProxyStatusText.Text = DisplayText.Get("Ui.TrustProxy.DisplayTrustProxyDiagnostics.01");
            TrustProxyDetailsText.Text = DisplayText.Get("Ui.TrustProxy.DisplayTrustProxyDiagnostics.02");
            return;
        }
        int incomplete = IncompleteDiagnosticChecks(diagnostic);
        string state = diagnostic.CompletedAtUtc is null ? DisplayText.Get("Ui.TrustProxy.DisplayTrustProxyDiagnostics.03") : incomplete > 0
            ? DisplayText.Format("Ui.TrustProxy.DisplayTrustProxyDiagnostics.04", (incomplete)) : diagnostic.Checks.Any(check => check.Required) ? DisplayText.Get("Ui.TrustProxy.DisplayTrustProxyDiagnostics.05") : DisplayText.Get("Ui.TrustProxy.DisplayTrustProxyDiagnostics.06");
        string time = (diagnostic.CompletedAtUtc ?? diagnostic.StartedAtUtc).ToLocalTime().ToString("MM-dd HH:mm:ss");
        TrustProxyStatusText.Text = DisplayText.Format("Ui.TrustProxy.DisplayTrustProxyDiagnostics.07", (state), (diagnostic.Proxies.Count), (diagnostic.Certificates.Count), (time));
        string details = TrustProxyReportPresentation.Describe(diagnostic);
        TrustProxyDetailsText.Text = details.Length <= MaximumDiagnosticDisplayCharacters ? details
            : details[..MaximumDiagnosticDisplayCharacters] + DisplayText.Get("Ui.TrustProxy.DisplayTrustProxyDiagnostics.08");
        TrustProxyDetailsText.ScrollToHome();
    }
}
