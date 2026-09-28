using System.Security.Principal;
using System.Windows;
using SteamSentinel.App.Services;
using SteamSentinel.Core.Models;
using SteamSentinel.Core.Remediation;
using SteamSentinel.Core.Reporting;
using SteamSentinel.Core.Scanning;
using SteamSentinel.Core.Utilities;

namespace SteamSentinel.App;

public partial class MainWindow
{
    private readonly RemediationCaseStore _caseStore = new();
    private RemediationCaseRecord? _persistedCase;
    private RemediationCaseRecord? _loadedCase;
    private bool _caseRecoveryUnavailable;

    private sealed record CaseListItem(RemediationCaseSummary Summary)
    {
        public override string ToString() => $"{Summary.UpdatedAtUtc.ToLocalTime():MM-dd HH:mm} · {RemediationCasePresentation.Label(Summary.State)} · {Summary.CaseId.ToString("N")[..8]}";
    }

    private async Task RefreshCaseRecordsAsync(bool restorePending = false)
    {
        IReadOnlyList<RemediationCaseSummary> summaries = await Task.Run(() => _caseStore.ListAsync());
        Guid? selected = (CaseListComboBox.SelectedItem as CaseListItem)?.Summary.CaseId;
        CaseListItem[] items = summaries.Select(s => new CaseListItem(s)).ToArray();
        CaseListComboBox.ItemsSource = items;
        CaseListComboBox.SelectedItem = items.FirstOrDefault(i => i.Summary.CaseId == selected) ?? items.FirstOrDefault();
        if (restorePending)
        {
            long recoveryBytes = 0;
            foreach (RemediationCaseSummary summary in summaries)
            {
                string casePath = Path.Combine(_caseStore.RootDirectory, summary.CaseId.ToString("N"), "case.json");
                recoveryBytes = checked(recoveryBytes + new FileInfo(casePath).Length);
                if (recoveryBytes > 128L * 1024 * 1024)
                    throw new InvalidDataException(DisplayText.Get("Ui.Cases.RefreshCaseRecordsAsync.01"));
                RemediationCaseRecord? record = await _caseStore.LoadAsync(summary.CaseId);
                if (record is null) throw new InvalidDataException(DisplayText.Get("Ui.Cases.RefreshCaseRecordsAsync.02"));
                foreach (RemediationPlan plan in CasePlans(record).Where(p => record.PendingPlanIds.Contains(p.PlanId)))
                    _remediationClient.RestoreUnresolvedPlan(plan);
            }
        }
        if (items.Length == 0) CaseDetailsText.Text = DisplayText.Get("Ui.Cases.RefreshCaseRecordsAsync.03");
        if (_remediationClient.HasUnresolvedExecution)
            CaseDetailsText.Text = DisplayText.Get("Ui.Cases.RefreshCaseRecordsAsync.04");
        CaseRecheckButton.IsEnabled = !_busy && items.Length > 0;
    }

    private async Task BeginPersistentCaseAsync(RemediationBatchSession batch, ScanReport original)
    {
        string sid = WindowsIdentity.GetCurrent().User?.Value ?? throw new UnauthorizedAccessException(DisplayText.Get("Ui.Cases.BeginPersistentCaseAsync.01"));
        CaseSessionObservation baseline;
        using (CancellationTokenSource timeout = new(TimeSpan.FromSeconds(6)))
        {
            try { baseline = await new WindowsCaseSessionReader().ReadAsync(timeout.Token).WaitAsync(timeout.Token); }
            catch (Exception ex) when (ex is not OutOfMemoryException)
            { baseline = new() { UserSid = sid, DetailText = MessageText.Create("Ui.Cases.BeginPersistentCaseAsync.02") + MessageExceptions.Describe(ex) }; }
        }
        RemediationCaseRecord record = new()
        {
            UserSid = sid,
            BaselineSession = baseline,
            OriginalScan = original,
            OriginalContentSettings = RemediationBatchPlanner.CloneOptions(batch.OriginalContentSettings),
            BatchSession = batch
        };
        await _caseStore.SaveAsync(record);
        _persistedCase = record;
        DisplayCaseRecord(record);
    }

    private async Task<RemediationRunResult> ExecuteRecordedPlanAsync(RemediationPlan plan)
    {
        RemediationCaseRecord record = _persistedCase ?? throw new InvalidOperationException(DisplayText.Get("Ui.Cases.ExecuteRecordedPlanAsync.01"));
        return await ExecuteRecordedPlanAsync(plan, record).ConfigureAwait(false);
    }

    private async Task<RemediationRunResult> ExecuteRecordedPlanAsync(RemediationPlan plan, RemediationCaseRecord record)
    {
        try
        {
            RemediationRunResult result = await _remediationClient.ExecuteAsync(plan, beforeLaunch: async (pending, token) =>
            {
                if (!record.PendingPlanIds.Contains(pending.PlanId)) record.PendingPlanIds.Add(pending.PlanId);
                await _caseStore.SaveAsync(record, token).ConfigureAwait(false);
            }).ConfigureAwait(false);
            record.ExecutionResults.RemoveAll(r => r.PlanId == result.PlanId);
            record.ExecutionResults.Add(result);
            record.PendingPlanIds.Remove(plan.PlanId);
            await _caseStore.SaveAsync(record).ConfigureAwait(false);
            return result;
        }
        catch
        {
            if (!_remediationClient.IsUnresolved(plan.PlanId)) record.PendingPlanIds.Remove(plan.PlanId);
            await _caseStore.SaveAsync(record).ConfigureAwait(false);
            throw;
        }
    }

    private static RemediationPlan[] CasePlans(RemediationCaseRecord record) =>
        record.Plans.Concat(record.BatchSession?.Plans ?? []).GroupBy(p => p.PlanId).Select(g => g.First()).ToArray();

    private async Task RecoverCaseResultsAsync(RemediationCaseRecord record, CancellationToken token = default)
    {
        _loadedCase = record;
        if (_persistedCase?.CaseId == record.CaseId) _persistedCase = record;
        // A saved Success field is only historical text. Always rehydrate from the protected Broker channel.
        List<RemediationRunResult> trusted = [];
        foreach (RemediationPlan plan in CasePlans(record))
        {
            token.ThrowIfCancellationRequested();
            RemediationRunResult? result;
            try { result = await ProtectedRemediationResultReader.TryReadAsync(plan, token); }
            catch (Exception ex) when (ex is IOException or InvalidDataException or System.ComponentModel.Win32Exception or UnauthorizedAccessException)
            {
                if (record.Notes.Count < 2048) record.AddNote((MessageText.Create("Ui.Cases.RecoverCaseResultsAsync.01") + plan.PlanId + "：" + MessageExceptions.Describe(ex)).Limit(2048));
                result = null;
            }
            if (result is not null) { trusted.Add(result); record.PendingPlanIds.Remove(plan.PlanId); }
            else if (record.ExecutionResults.Any(r => r.PlanId == plan.PlanId) || record.BatchSession?.Results.Any(r => r.PlanId == plan.PlanId) == true)
            {
                if (!record.PendingPlanIds.Contains(plan.PlanId)) record.PendingPlanIds.Add(plan.PlanId);
                _remediationClient.RestoreUnresolvedPlan(plan);
            }
        }
        record.ExecutionResults.Clear(); record.ExecutionResults.AddRange(trusted);
        if (record.BatchSession is { } batch)
        {
            batch.Results.Clear(); batch.Results.AddRange(trusted);
            if (record.PendingPlanIds.Count == 0 && batch.ExecutionStarted) batch.ExecutionFinished = true;
            RemediationBatchPlanner.RefreshOutcomes(batch);
        }
        while (await _remediationClient.TryRecoverResultAsync() is { } recovered)
            await RecordRecoveredResultAsync(recovered);
    }

    private async Task RecordRecoveredResultAsync(RemediationRunResult recovered)
    {
        IReadOnlyList<RemediationCaseSummary> summaries = await _caseStore.ListAsync();
        long recoveryBytes = 0;
        foreach (RemediationCaseSummary summary in summaries)
        {
            recoveryBytes = checked(recoveryBytes + new FileInfo(Path.Combine(_caseStore.RootDirectory, summary.CaseId.ToString("N"), "case.json")).Length);
            if (recoveryBytes > 128L * 1024 * 1024) throw new InvalidDataException(DisplayText.Get("Ui.Cases.RecordRecoveredResultAsync.01"));
            RemediationCaseRecord? record = _persistedCase?.CaseId == summary.CaseId ? _persistedCase :
                _loadedCase?.CaseId == summary.CaseId ? _loadedCase : await _caseStore.LoadAsync(summary.CaseId);
            if (record is null) continue;
            RemediationPlan? matching = CasePlans(record).SingleOrDefault(p => p.PlanId == recovered.PlanId);
            if (matching is null) continue;
            ProtectedRemediationResultReader.Validate(matching, recovered);
            record.ExecutionResults.RemoveAll(r => r.PlanId == recovered.PlanId); record.ExecutionResults.Add(recovered);
            record.PendingPlanIds.Remove(recovered.PlanId);
            if (record.BatchSession is { } batch)
            {
                batch.Results.RemoveAll(r => r.PlanId == recovered.PlanId); batch.Results.Add(recovered);
                if (record.PendingPlanIds.Count == 0 && batch.ExecutionStarted) batch.ExecutionFinished = true;
                RemediationBatchPlanner.RefreshOutcomes(batch);
            }
            await _caseStore.SaveAsync(record);
        }
    }

    internal void DisplayCaseRecord(RemediationCaseRecord record)
    {
        _loadedCase = record;
        CaseDetailsText.Text = RemediationCasePresentation.Render(record);
    }

    private async void CaseRefresh_Click(object sender, RoutedEventArgs e)
    {
        if (_busy) return;
        SetBusy(true);
        try
        {
            await RefreshCaseRecordsAsync(restorePending: true);
            if (CaseListComboBox.SelectedItem is CaseListItem selected && await _caseStore.LoadAsync(selected.Summary.CaseId) is { } record)
            {
                _loadedCase = record;
                await RecoverCaseResultsAsync(record);
                await _caseStore.SaveAsync(record);
                DisplayCaseRecord(record);
            }
            _caseRecoveryUnavailable = false;
        }
        catch (Exception ex) { _caseRecoveryUnavailable = true; CaseDetailsText.Text = DisplayText.Get("Ui.Cases.CaseRefresh_Click.01") + SteamSentinel.Core.Reporting.MessageExceptions.Display(ex); }
        finally { SetBusy(false); }
    }

    private async void CaseRecheck_Click(object sender, RoutedEventArgs e)
    {
        if (_busy || CaseListComboBox.SelectedItem is not CaseListItem selected) return;
        SetBusy(true); _scanCancellation = new(TimeSpan.FromMinutes(2)); CancelScanButton.IsEnabled = true;
        ShowActivity(ActivityPhase.FollowUp, DisplayText.Get("Ui.Cases.CaseRecheck_Click.01"));
        try
        {
            RemediationCaseRecord record = await _caseStore.LoadAsync(selected.Summary.CaseId, _scanCancellation.Token)
                ?? throw new FileNotFoundException(DisplayText.Get("Ui.Cases.CaseRecheck_Click.02"));
            _loadedCase = record;
            await RecoverCaseResultsAsync(record, _scanCancellation.Token);
            await new RemediationCaseReverification().RecheckAsync(record, RunCaseFollowUpAsync, _scanCancellation.Token);
            await _caseStore.SaveAsync(record);
            DisplayCaseRecord(record);
            await RefreshCaseRecordsAsync();
        }
        catch (Exception ex) { AppErrorLog.Write("CaseRecheck", ex); CaseDetailsText.Text = DisplayText.Get("Ui.Cases.CaseRecheck_Click.03") + SteamSentinel.Core.Reporting.MessageExceptions.Display(ex); }
        finally { _scanCancellation.Dispose(); _scanCancellation = null; SetBusy(false); }
    }

    private async void CaseExport_Click(object sender, RoutedEventArgs e)
    {
        if (_busy || CaseListComboBox.SelectedItem is not CaseListItem selected) return;
        Microsoft.Win32.SaveFileDialog dialog = new()
        {
            Filter = DisplayText.Get("Ui.Cases.CaseExport_Click.01"),
            FileName = "SteamSentinel-case-" + selected.Summary.CaseId.ToString("N") + ".zip"
        };
        if (dialog.ShowDialog(this) != true) return;
        System.Globalization.CultureInfo? exportCulture = ChooseExportLanguage();
        if (exportCulture is null) return;
        SetBusy(true);
        try
        {
            RemediationCaseRecord record = await _caseStore.LoadAsync(selected.Summary.CaseId)
                ?? throw new FileNotFoundException(DisplayText.Get("Ui.Cases.CaseExport_Click.02"));
            await CaseBundleExporter.ExportAsync(dialog.FileName, record.OriginalScan ?? new ScanReport { Coverage = ScanCoverage.Partial },
                null, null, null, batches: record.BatchSession, persistedCase: record, culture: exportCulture);
            CaseDetailsText.Text = RemediationCasePresentation.Render(record) + DisplayText.Get("Ui.Cases.CaseExport_Click.03");
        }
        catch (Exception ex) { AppErrorLog.Write("CaseExport", ex); CaseDetailsText.Text = DisplayText.Get("Ui.Cases.CaseExport_Click.04") + SteamSentinel.Core.Reporting.MessageExceptions.Display(ex); }
        finally { SetBusy(false); }
    }

    private async Task<CaseFollowUpResult> RunCaseFollowUpAsync(RemediationCaseRecord record, CancellationToken token)
    {
        if (!Dispatcher.CheckAccess())
            return await Dispatcher.InvokeAsync(() => RunCaseFollowUpAsync(record, token)).Task.Unwrap();
        using DispatcherProgress<ScanProgress> progress = CreateUiProgress(p =>
        { ProgressStageText.Text = DisplayText.Get("Ui.Cases.RunCaseFollowUpAsync.01") + p.DisplayStage; ProgressItemText.Text = p.DisplayCurrentItem; });
        ScanReport system = await Task.Run(() => _coordinator.RunAsync(new ScanOptions
        {
            Mode = ScanMode.Quick,
            IncludeSystem = true,
            IncludeSteam = true,
            IncludeWorkshop = false,
            IncludeRelatedContent = false,
            InspectArchives = false,
            UseAmsi = false
        }, progress: progress, cancellationToken: token), token);
        ScanOptions? contentSettings = RemediationBatchPlanner.CloneOptions(record.OriginalContentSettings);
        ScanReport? content = null;
        if (contentSettings is not null)
        {
            try { content = await _workerClient.RunAsync(contentSettings, RequestPasswordAsync, progress, token); }
            catch (Exception ex) when (ex is not OutOfMemoryException)
            { content = ScanFailureReports.PreserveSystemResults(null, contentSettings.Mode, contentSettings.CustomRoots, _coordinator.Rules.Version, ex, token.IsCancellationRequested); }
        }
        ScanReport related = content is null ? system : ScanReportMerger.Merge(system, content);
        ScanOptions settings = contentSettings ?? new() { IncludeSystem = false, IncludeSteam = false, IncludeWorkshop = false, IncludeRelatedContent = true };
        await Task.Run(() => new RelatedComponentPipeline(_coordinator.Rules).CompleteAsync(related, settings,
            async (options, reporter, cancellation) =>
            {
                try { return await _workerClient.RunAsync(options, RequestPasswordAsync, reporter, cancellation); }
                catch (Exception ex) when (ex is not OutOfMemoryException)
                { return ScanFailureReports.PreserveSystemResults(null, options.Mode, options.CustomRoots, _coordinator.Rules.Version, ex, cancellation.IsCancellationRequested); }
            }, progress, token), token);
        return new()
        {
            ContentReport = content,
            RelatedReport = related,
            DetailText = MessageText.Create("Ui.Cases.RunCaseFollowUpAsync.02")
        };
    }
}
