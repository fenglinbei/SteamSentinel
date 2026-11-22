using SteamSentinel.Core.Reporting;
using System.Windows;
using System.Windows.Controls;
using SteamSentinel.App.Dialogs;
using SteamSentinel.App.Services;
using SteamSentinel.App.ViewModels;
using SteamSentinel.Core.Models;
using SteamSentinel.Core.Remediation;
using SteamSentinel.Core.Scanning;
using SteamSentinel.Core.Utilities;

namespace SteamSentinel.App;

public partial class MainWindow
{
    private RemediationBatchSession? _caseBatch;
    private ScanReport? _caseContentFollowUp;

    internal RemediationMode CurrentRemediationMode => RemediationModeComboBox?.SelectedIndex == 1
        ? RemediationMode.Aggressive : RemediationMode.Conservative;

    private void RemediationMode_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (RemediationModeComboBox is null || FindingsGrid is null || _busy) return;
        RemediationModeComboBox.ToolTip = RemediationModePresentation.Description(CurrentRemediationMode);
        if (_lastReport is null) return;
        string? selectedId = SelectedFinding?.Finding.Id;
        bool referenceExpanded = ReferenceFindingsExpander.IsExpanded;
        PopulateFindings(_lastReport);
        foreach (FindingItemViewModel item in Findings) item.IsSelected = false;
        ReferenceFindingsExpander.IsExpanded = referenceExpanded && ReferenceFindings.Count > 0;
        FindingItemViewModel? selected = Findings.FirstOrDefault(item => item.Finding.Id == selectedId);
        if (selected?.IsReference == true && ReferenceFindingsExpander.IsExpanded) ReferenceFindingsGrid.SelectedItem = selected;
        else FindingsGrid.SelectedItem = PriorityFindings.FirstOrDefault(item => item.Finding.Id == selectedId) ?? PriorityFindings.FirstOrDefault();
        UpdateSummary(_lastReport);
        FooterText.Text = DisplayText.Get("RemediationMode.SelectionCleared");
    }

    private async Task ExecuteSelectedRemediationAsync()
    {
        if (_busy || _lastReport is null) return;
        if (_reportNeedsRefresh)
        {
            MessageBox.Show(this, DisplayText.Get("Remediation.ExecuteSelectedRemediationAsync.01"), DisplayText.Get("Remediation.ExecuteSelectedRemediationAsync.02"), MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }
        if (!await EnsureRemediationAvailableAsync()) return;
        FindingItemViewModel? retiredSelection = Findings.FirstOrDefault(item => item.IsSelected &&
            !item.UserSelectedRisk && RemediationEvidencePolicy.IsReviewOnlyEvidence(item.Finding));
        if (retiredSelection is not null)
        {
            MessageBox.Show(this, RemediationEvidencePolicy.ReviewOnlyMessage(retiredSelection.Finding).Display,
                "SteamSentinel", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }
        Finding[] selected = VisibleRemediationFindings.Where(i => i.IsSelected && i.CanSelect).Select(i => i.Finding).ToArray();
        if (selected.Length == 0) { MessageBox.Show(this, DisplayText.Get("Remediation.ExecuteSelectedRemediationAsync.03"), "SteamSentinel"); return; }
        if (selected.Any(f => f.Category == FindingCategory.Steam) && IsSteamRunning())
        { MessageBox.Show(this, DisplayText.Get("Remediation.ExecuteSelectedRemediationAsync.04"), DisplayText.Get("Remediation.ExecuteSelectedRemediationAsync.05")); return; }
        ScanReport original = _lastReport;
        RemediationMode remediationMode = CurrentRemediationMode;
        bool amsi = ScanEnhancements.AmsiAvailable && AmsiCheckBox.IsChecked == true, block = DomainBlockCheckBox.IsChecked == true;
        try
        {
            SetBusy(true); ShowActivity(ActivityPhase.Preparing, DisplayText.Get("Remediation.ExecuteSelectedRemediationAsync.06"));
            _scanCancellation = new(); CancelScanButton.IsEnabled = true;
            using DispatcherProgress<ScanProgress> progress = CreateUiProgress(p =>
            { ProgressStageText.Text = p.DisplayStage; ProgressItemText.Text = p.DisplayCurrentItem; HeaderDetailText.Text = p.DisplayDetail; });
            async Task<ScanReport> Inspect(IReadOnlyList<string> paths, CancellationToken token)
            {
                try
                {
                    return await _workerClient.RunAsync(new ScanOptions
                    {
                        Mode = ScanMode.Custom,
                        IncludeSystem = false,
                        IncludeSteam = false,
                        IncludeWorkshop = false,
                        CustomRoots = paths.ToList(),
                        InspectArchives = false,
                        UseAmsi = amsi,
                        HashEveryFile = true,
                        MaximumFiles = 2000,
                        MaximumContentBytes = RemediationBatchPlanner.PreparationBatchBytes,
                        ExcludedRoots = [AppPaths.MachineStateRoot, AppPaths.TemporaryRoot, AppPaths.WorkerTemporaryRoot, AppContext.BaseDirectory]
                    }, RequestPasswordAsync, progress, token);
                }
                catch (WorkerFailureException ex)
                { return ScanFailureReports.PreserveSystemResults(null, ScanMode.Custom, paths, _coordinator.Rules.Version, ex, false); }
            }
            RemediationBatchSession batch = await Task.Run(() => new RemediationBatchPlanner(_coordinator.Rules)
                .PrepareAsync(selected, original, block, Inspect, progress, _scanCancellation.Token,
                    requestExplicitFileTargets: true, remediationMode: remediationMode));
            _caseBatch = batch; _caseScan = original; _casePlan = null; _caseResult = null; _caseFollowUp = null; _caseContentFollowUp = null;
            UpdateBatchResults();
            if (batch.Plans.Count == 0)
            {
                HeaderStatusText.Text = DisplayText.Get("Remediation.ExecuteSelectedRemediationAsync.07"); HeaderDetailText.Text = batch.Summary;
                MessageBox.Show(this, batch.Summary + DisplayText.Get("Remediation.ExecuteSelectedRemediationAsync.08"), DisplayText.Get("Remediation.ExecuteSelectedRemediationAsync.09"), MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }
            bool repairsSteamConfig = batch.Plans.SelectMany(plan => plan.Actions)
                .Any(action => action.Type == RemediationActionType.RepairSteamConfiguration);
            if (repairsSteamConfig && IsSteamRunning())
            {
                MessageBox.Show(this, DisplayText.Get("SteamConfig.CloseSteam"),
                    DisplayText.Get("Remediation.ExecuteSelectedRemediationAsync.05"), MessageBoxButton.OK, MessageBoxImage.Information);
                return;
            }
            ShowActivity(ActivityPhase.Confirmation);
            RemediationPreviewWindow preview = new(batch, _coordinator.Rules, _findingScopeLayout,
                isPortableInstallation: _installationSecurity.Mode == InstallationTrustMode.Portable)
            { Owner = this };
            if (preview.ShowDialog() != true) { batch.AddNote(MessageText.Create("Remediation.ExecuteSelectedRemediationAsync.10")); return; }
            await BeginPersistentCaseAsync(batch, original);
            _scanCancellation.Dispose(); _scanCancellation = null; CancelScanButton.IsEnabled = false;
            _operationCommitted = true; _reportNeedsRefresh = true;
            ShowActivity(ActivityPhase.Applying, DisplayText.Get("Remediation.ExecuteSelectedRemediationAsync.11"));
            await Task.Run(() => RemediationBatchPlanner.ExecuteAsync(batch, plan => ExecuteRecordedPlanAsync(plan, approvedInUi: true), progress));
            await _caseStore.SaveAsync(_persistedCase!);
            DisplayCaseRecord(_persistedCase!);
            // Legacy exports retain the single-plan fields only for truly single-plan sessions.
            if (batch.Plans.Count == 1) { _casePlan = batch.Plans[0]; _caseResult = batch.Results.FirstOrDefault(); }
            UpdateBatchResults();
            if (_remediationClient.HasUnresolvedExecution)
            {
                HeaderStatusText.Text = DisplayText.Get("Remediation.ExecuteSelectedRemediationAsync.12");
                HeaderDetailText.Text = DisplayText.Get("Remediation.ExecuteSelectedRemediationAsync.13");
                return;
            }
            await RunBatchFollowUpAsync(batch, original);
            if (_closeWhenIdle) return;
            string guidance = SteamSentinel.Core.Steam.SteamRecoveryGuide.BuildGuidance(_findingScopeLayout, batch, original);
            HeaderStatusText.Text = batch.InterruptionReasonCode is not null || batch.Targets.Any(t => t.State != RemediationTargetState.Completed) ? DisplayText.Get("Remediation.ExecuteSelectedRemediationAsync.14") : DisplayText.Get("Remediation.ExecuteSelectedRemediationAsync.15");
            HeaderDetailText.Text = batch.Summary;
            string details = HeaderDetailText.Text + "\n" + batch.InterruptionText.Display + "\n" + BatchFollowUpText.Text + guidance;
            if (batch.Results.SelectMany(r => r.Actions).Any(a => a.Success &&
                a.Type is RemediationActionType.QuarantineFile or RemediationActionType.QuarantineDirectory &&
                original.Findings.Any(f => f.Category == FindingCategory.Steam && string.Equals(f.Target, a.Target, StringComparison.OrdinalIgnoreCase))))
                details += DisplayText.Get("Remediation.ExecuteSelectedRemediationAsync.16");
            details += DisplayText.Get("Remediation.ExecuteSelectedRemediationAsync.17");
            HideActivity();
            new TextDetailsWindow(HeaderStatusText.Text, details) { Owner = this }.ShowDialog();
            FooterText.Text = DisplayText.Get("Remediation.ExecuteSelectedRemediationAsync.18");
            await RefreshQuarantineItemsAsync();
        }
        catch (OperationCanceledException) { HeaderStatusText.Text = DisplayText.Get("Remediation.ExecuteSelectedRemediationAsync.19"); }
        catch (Exception ex)
        {
            AppErrorLog.Write("BatchRemediation", ex);
            HeaderStatusText.Text = _operationCommitted ? DisplayText.Get("Remediation.ExecuteSelectedRemediationAsync.20") : DisplayText.Get("Remediation.ExecuteSelectedRemediationAsync.21");
            if (!_closeWhenIdle) MessageBox.Show(this, SteamSentinel.Core.Reporting.MessageExceptions.Display(ex), HeaderStatusText.Text, MessageBoxButton.OK, MessageBoxImage.Warning);
        }
        finally
        {
            if (_persistedCase is { } savedCase && savedCase.BatchSession == _caseBatch)
            {
                try { await _caseStore.SaveAsync(savedCase); await RefreshCaseRecordsAsync(); }
                catch (Exception ex) { AppErrorLog.Write("SaveCaseAfterRemediation", ex); FooterText.Text = DisplayText.Get("Remediation.ExecuteSelectedRemediationAsync.22") + SteamSentinel.Core.Reporting.MessageExceptions.Display(ex); }
            }
            UpdateBatchResults(); _operationCommitted = false;
            _scanCancellation?.Dispose(); _scanCancellation = null; SetBusy(false);
        }
    }

    private void UpdateBatchResults()
    {
        if (_caseBatch is null) return;
        string? selectedKey = (BatchResultsGrid.SelectedItem as RemediationTargetOutcome)?.Key;
        BatchSummaryText.Text = _caseBatch.Summary;
        BatchResultsGrid.ItemsSource = null; BatchResultsGrid.ItemsSource = _caseBatch.Targets;
        BatchResultsGrid.SelectedItem = _caseBatch.Targets.FirstOrDefault(target => target.Key == selectedKey)
            ?? _caseBatch.Targets.FirstOrDefault();
        UpdateBatchActionDetailsAvailability();
        BatchResultsTab.Header = DisplayText.Format("Remediation.UpdateBatchResults.01", (_caseBatch.Targets.Count));
    }

    private void BatchResults_SelectionChanged(object sender, SelectionChangedEventArgs e) => UpdateBatchActionDetailsAvailability();

    private void UpdateBatchActionDetailsAvailability()
    {
        if (BatchActionDetailsButton is not null)
            BatchActionDetailsButton.IsEnabled = _caseBatch is not null && BatchResultsGrid.SelectedItem is RemediationTargetOutcome;
    }

    internal TextDetailsWindow? CreateBatchActionDetailsWindow() =>
        _caseBatch is not null && BatchResultsGrid.SelectedItem is RemediationTargetOutcome target
            ? new(DisplayText.Get("Ui.Xaml.MainWindow.083"), RemediationResultPresentation.DescribeTarget(_caseBatch, target))
            : null;

    private void BatchActionDetails_Click(object sender, RoutedEventArgs e)
    {
        if (CreateBatchActionDetailsWindow() is not { } details) return;
        details.Owner = this;
        details.ShowDialog();
    }

    internal async Task<ScanReport> RunOriginalContentCheckAsync(ScanOptions options, CancellationToken token,
        Func<ScanOptions, IProgress<ScanProgress>, CancellationToken, Task<ScanReport>>? runner = null)
    {
        Dispatcher.VerifyAccess();
        ShowActivity(ActivityPhase.ContentFollowUp);
        using DispatcherProgress<ScanProgress> progress = CreateUiProgress(p =>
        { ProgressStageText.Text = DisplayText.Get("Remediation.RunOriginalContentCheckAsync.01") + p.DisplayStage; ProgressItemText.Text = p.DisplayCurrentItem; });
        runner ??= (settings, reporter, cancellation) => _workerClient.RunAsync(settings, RequestPasswordAsync, reporter, cancellation);
        return await Task.Run(() => runner(options, progress, token), token);
    }

    private async Task RunBatchFollowUpAsync(RemediationBatchSession batch, ScanReport original)
    {
        List<string> messages = [];
        ScanOptions? settings = batch.OriginalContentSettings;
        if (settings is not null && (settings.IncludeWorkshop || settings.IncludeRelatedContent || settings.CustomRoots.Count > 0))
        {
            _scanCancellation = new(TimeSpan.FromMinutes(2));
            // Mutations have returned. Cancellation now only stops the read-only original-scope scan.
            _operationCommitted = false; CancelScanButton.IsEnabled = true;
            try
            {
                _caseContentFollowUp = await RunOriginalContentCheckAsync(settings, _scanCancellation.Token);
                _caseContentFollowUp.AddScopeNote(MessageText.Create("Remediation.RunBatchFollowUpAsync.01"));
                _lastReport = _caseContentFollowUp; PopulateFindings(_lastReport);
                messages.Add(ContentFollowUpSummary(_caseContentFollowUp));
            }
            catch (Exception ex)
            {
                _caseContentFollowUp = ScanFailureReports.PreserveSystemResults(null, settings.Mode, settings.CustomRoots, _coordinator.Rules.Version, ex, ex is OperationCanceledException);
                _lastReport = _caseContentFollowUp; PopulateFindings(_lastReport);
                messages.Add(DisplayText.Get("Remediation.RunBatchFollowUpAsync.02") + SteamSentinel.Core.Reporting.MessageExceptions.Display(ex));
            }
            finally { _scanCancellation.Dispose(); _scanCancellation = null; CancelScanButton.IsEnabled = false; }
            if (_closeWhenIdle) { BatchFollowUpText.Text = string.Join("\n", messages) + DisplayText.Get("Remediation.RunBatchFollowUpAsync.03"); return; }
        }
        else messages.Add(DisplayText.Get("Remediation.RunBatchFollowUpAsync.04"));
        _operationCommitted = true;
        try
        {
            using CancellationTokenSource timeout = new(TimeSpan.FromMinutes(2));
            _caseFollowUp = await RunPostRemediationCheckAsync(timeout.Token);
            _caseFollowUp.AddScopeNote(MessageText.Create("Remediation.RunBatchFollowUpAsync.05"));
            messages.Add(SystemFollowUpSummary(_caseFollowUp));
            // Never silently replace a content result with the unrelated system findings.
            if (_caseContentFollowUp is null) { _lastReport = _caseFollowUp; PopulateFindings(_lastReport); }
        }
        catch (Exception ex)
        {
            AppErrorLog.Write("PostRemediationCheck", ex);
            _caseFollowUp = new() { Coverage = ScanCoverage.Partial, CompletedAtUtc = DateTimeOffset.UtcNow, StatusSchemaVersion = ScanExecution.SchemaVersion, ExecutionState = ScanExecutionState.Failed, ExecutionReasonCode = ReasonCodes.ComponentFailed };
            _caseFollowUp.AddCoverageNote(MessageText.Create("Remediation.RunBatchFollowUpAsync.06") + MessageExceptions.Describe(ex));
            messages.Add(DisplayText.Get("Remediation.RunBatchFollowUpAsync.07") + SteamSentinel.Core.Reporting.MessageExceptions.Display(ex));
        }
        BatchFollowUpText.Text = string.Join("\n", messages);
        ResultTabs.SelectedItem = BatchResultsTab;
    }

    internal static string ContentFollowUpSummary(ScanReport report) => DisplayText.Get("Remediation.ContentFollowUpSummary.01") +
        (report.Findings.Any(f => f.CanRemediate || f.IsKnownMalware) ? DisplayText.Get("Remediation.ContentFollowUpSummary.02") : DisplayText.Get("Remediation.ContentFollowUpSummary.03")) +
        (HasUnresolvedSteamSource(report) ? " " + DisplayText.Get("RemediationMode.UnresolvedSource") : "") +
        (report.Coverage != ScanCoverage.Complete ? DisplayText.Get("Remediation.ContentFollowUpSummary.04") : DisplayText.Get("Remediation.ContentFollowUpSummary.05"));
    internal static string SystemFollowUpSummary(ScanReport report) => DisplayText.Get("Remediation.SystemFollowUpSummary.01") +
        (report.Findings.Any(f => f.RuleId is "STEAMALERT-UI-INJECTION" or "STEAMALERT-EMBEDDED-CORE-HOST" ||
            f.IsKnownMalware && f.Category is FindingCategory.Process or FindingCategory.Persistence or FindingCategory.Steam)
            ? DisplayText.Get("Remediation.SystemFollowUpSummary.02") : HasUnresolvedSteamSource(report)
                ? DisplayText.Get("RemediationMode.UnresolvedSource") : DisplayText.Get("Remediation.SystemFollowUpSummary.03")) +
        (report.Findings.Any(f => f.RuleId == "SECURITY-CONTROLS-DISABLED") ? DisplayText.Get("Remediation.SystemFollowUpSummary.04") : "") +
        (report.Findings.Any(f => f.RuleId is "STEAMALERT-UI-INJECTION" or "STEAM-UI-EXTERNAL-SCRIPT" or "STEAM-UI-SEMANTIC-TAMPERING") ? DisplayText.Get("SteamConfig.UiFileFollowUp") : "") +
        (report.Findings.Any(f => f.RuleId == "STEAM-UI-LOOPBACK-SCRIPT") ? DisplayText.Get("SteamConfig.LoopbackFollowUpReview") : "") +
        (report.Coverage != ScanCoverage.Complete ? DisplayText.Get("Remediation.SystemFollowUpSummary.05") : "");

    internal static bool HasUnresolvedSteamSource(ScanReport report) => report.Findings.Any(f =>
        f.Severity >= FindingSeverity.High && f.RuleId is
            "MANAGED-STEAM-CEF-HOST" or "MANAGED-STEAM-CEF-CORE" or "MANAGED-MOD-DOWNLOAD-LAUNCH");
}
