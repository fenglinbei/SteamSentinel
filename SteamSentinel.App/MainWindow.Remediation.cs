using SteamSentinel.Core.Reporting;
using System.Windows;
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

    private async Task ExecuteSelectedRemediationAsync()
    {
        if (_busy || _lastReport is null) return;
        if (_reportNeedsRefresh)
        {
            MessageBox.Show(this, DisplayText.Get("Remediation.ExecuteSelectedRemediationAsync.01"), DisplayText.Get("Remediation.ExecuteSelectedRemediationAsync.02"), MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }
        if (!await EnsureRemediationAvailableAsync()) return;
        Finding[] selected = Findings.Where(i => i.IsSelected && i.CanSelect).Select(i => i.Finding).ToArray();
        if (selected.Length == 0) { MessageBox.Show(this, DisplayText.Get("Remediation.ExecuteSelectedRemediationAsync.03"), "SteamSentinel"); return; }
        if (selected.Any(f => f.Category == FindingCategory.Steam) && IsSteamRunning())
        { MessageBox.Show(this, DisplayText.Get("Remediation.ExecuteSelectedRemediationAsync.04"), DisplayText.Get("Remediation.ExecuteSelectedRemediationAsync.05")); return; }
        ScanReport original = _lastReport;
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
                .PrepareAsync(selected, original, block, Inspect, progress, _scanCancellation.Token));
            _caseBatch = batch; _caseScan = original; _casePlan = null; _caseResult = null; _caseFollowUp = null; _caseContentFollowUp = null;
            UpdateBatchResults();
            if (batch.Plans.Count == 0)
            {
                HeaderStatusText.Text = DisplayText.Get("Remediation.ExecuteSelectedRemediationAsync.07"); HeaderDetailText.Text = batch.Summary;
                MessageBox.Show(this, batch.Summary + DisplayText.Get("Remediation.ExecuteSelectedRemediationAsync.08"), DisplayText.Get("Remediation.ExecuteSelectedRemediationAsync.09"), MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }
            ShowActivity(ActivityPhase.Confirmation);
            RemediationPreviewWindow preview = new(batch) { Owner = this };
            if (preview.ShowDialog() != true) { batch.AddNote(MessageText.Create("Remediation.ExecuteSelectedRemediationAsync.10")); return; }
            await BeginPersistentCaseAsync(batch, original);
            _scanCancellation.Dispose(); _scanCancellation = null; CancelScanButton.IsEnabled = false;
            _operationCommitted = true; _reportNeedsRefresh = true;
            ShowActivity(ActivityPhase.Applying, DisplayText.Get("Remediation.ExecuteSelectedRemediationAsync.11"));
            await Task.Run(() => RemediationBatchPlanner.ExecuteAsync(batch, ExecuteRecordedPlanAsync, progress));
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
            HeaderStatusText.Text = batch.InterruptionReasonCode is not null || batch.Targets.Any(t => t.State != RemediationTargetState.Completed) ? DisplayText.Get("Remediation.ExecuteSelectedRemediationAsync.14") : DisplayText.Get("Remediation.ExecuteSelectedRemediationAsync.15");
            HeaderDetailText.Text = batch.Summary;
            string details = batch.Summary + "\n" + batch.InterruptionText.Display + "\n" + BatchFollowUpText.Text;
            if (selected.Any(f => f.Category == FindingCategory.Steam) && batch.Results.SelectMany(r => r.Actions).Any(a => a.Success &&
                a.Type is RemediationActionType.QuarantineFile or RemediationActionType.QuarantineDirectory))
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
        BatchSummaryText.Text = _caseBatch.Summary;
        BatchResultsGrid.ItemsSource = null; BatchResultsGrid.ItemsSource = _caseBatch.Targets;
        BatchResultsTab.Header = DisplayText.Format("Remediation.UpdateBatchResults.01", (_caseBatch.Targets.Count));
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
        (report.Coverage != ScanCoverage.Complete ? DisplayText.Get("Remediation.ContentFollowUpSummary.04") : DisplayText.Get("Remediation.ContentFollowUpSummary.05"));
    internal static string SystemFollowUpSummary(ScanReport report) => DisplayText.Get("Remediation.SystemFollowUpSummary.01") +
        (report.Findings.Any(f => f.IsKnownMalware && f.Category is FindingCategory.Process or FindingCategory.Persistence or FindingCategory.Steam)
            ? DisplayText.Get("Remediation.SystemFollowUpSummary.02") : DisplayText.Get("Remediation.SystemFollowUpSummary.03")) +
        (report.Findings.Any(f => f.RuleId == "SECURITY-CONTROLS-DISABLED") ? DisplayText.Get("Remediation.SystemFollowUpSummary.04") : "") +
        (report.Coverage != ScanCoverage.Complete ? DisplayText.Get("Remediation.SystemFollowUpSummary.05") : "");
}
