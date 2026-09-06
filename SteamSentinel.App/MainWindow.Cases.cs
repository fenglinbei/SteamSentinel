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
                    throw new InvalidDataException("启动病例恢复超过 128 MiB 读取预算，未确认剩余执行状态；请先导出并管理已有病例。");
                RemediationCaseRecord? record = await _caseStore.LoadAsync(summary.CaseId);
                if (record is null) throw new InvalidDataException("未决病例索引对应的记录缺失，不能确认上次执行状态。");
                foreach (RemediationPlan plan in CasePlans(record).Where(p => record.PendingPlanIds.Contains(p.PlanId)))
                    _remediationClient.RestoreUnresolvedPlan(plan);
            }
        }
        if (items.Length == 0) CaseDetailsText.Text = "尚无已保存病例。确认处置后会保存计划与会话基线，供重启或重新登录后只读复验。";
        if (_remediationClient.HasUnresolvedExecution)
            CaseDetailsText.Text = "存在尚未返回确定结果的管理员操作。已暂停新的处置；读取病例可尝试恢复受保护结果。旧计划不会自动重提。";
        CaseRecheckButton.IsEnabled = !_busy && items.Length > 0;
    }

    private async Task BeginPersistentCaseAsync(RemediationBatchSession batch, ScanReport original)
    {
        string sid = WindowsIdentity.GetCurrent().User?.Value ?? throw new UnauthorizedAccessException("无法读取病例用户身份。");
        CaseSessionObservation baseline;
        using (CancellationTokenSource timeout = new(TimeSpan.FromSeconds(6)))
        {
            try { baseline = await new WindowsCaseSessionReader().ReadAsync(timeout.Token).WaitAsync(timeout.Token); }
            catch (Exception ex) when (ex is not OutOfMemoryException)
            { baseline = new() { UserSid = sid, Detail = "处置前会话身份未读完，后续不能据此宣称跨会话验收通过：" + ex.Message }; }
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
        RemediationCaseRecord record = _persistedCase ?? throw new InvalidOperationException("病例未可靠保存，未启动管理员处置。");
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
                if (record.Notes.Count < 2048) record.Notes.Add(RemediationVerification.Limit("无法确认受保护结果 " + plan.PlanId + "：" + ex.Message, 2048));
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
            if (recoveryBytes > 128L * 1024 * 1024) throw new InvalidDataException("病例结果恢复读取超过 128 MiB，未覆盖尚未核对的记录。");
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
        catch (Exception ex) { _caseRecoveryUnavailable = true; CaseDetailsText.Text = "病例读取未完成：" + ex.Message; }
        finally { SetBusy(false); }
    }

    private async void CaseRecheck_Click(object sender, RoutedEventArgs e)
    {
        if (_busy || CaseListComboBox.SelectedItem is not CaseListItem selected) return;
        SetBusy(true); _scanCancellation = new(TimeSpan.FromMinutes(2)); CancelScanButton.IsEnabled = true;
        ShowActivity(ActivityPhase.FollowUp, "只读核对会话身份与原病例目标；不会重新处置或自动重启。");
        try
        {
            RemediationCaseRecord record = await _caseStore.LoadAsync(selected.Summary.CaseId, _scanCancellation.Token)
                ?? throw new FileNotFoundException("所选病例已不存在。");
            _loadedCase = record;
            await RecoverCaseResultsAsync(record, _scanCancellation.Token);
            await new RemediationCaseReverification().RecheckAsync(record, RunCaseFollowUpAsync, _scanCancellation.Token);
            await _caseStore.SaveAsync(record);
            DisplayCaseRecord(record);
            await RefreshCaseRecordsAsync();
        }
        catch (Exception ex) { AppErrorLog.Write("CaseRecheck", ex); CaseDetailsText.Text = "病例复验未完成：" + ex.Message; }
        finally { _scanCancellation.Dispose(); _scanCancellation = null; SetBusy(false); }
    }

    private async void CaseExport_Click(object sender, RoutedEventArgs e)
    {
        if (_busy || CaseListComboBox.SelectedItem is not CaseListItem selected) return;
        Microsoft.Win32.SaveFileDialog dialog = new()
        {
            Filter = "病例记录包 (*.zip)|*.zip",
            FileName = "SteamSentinel-case-" + selected.Summary.CaseId.ToString("N") + ".zip"
        };
        if (dialog.ShowDialog(this) != true) return;
        SetBusy(true);
        try
        {
            RemediationCaseRecord record = await _caseStore.LoadAsync(selected.Summary.CaseId)
                ?? throw new FileNotFoundException("所选病例已不存在。");
            await CaseBundleExporter.ExportAsync(dialog.FileName, record.OriginalScan ?? new ScanReport { Coverage = ScanCoverage.Partial },
                null, null, null, batches: record.BatchSession, persistedCase: record);
            CaseDetailsText.Text = RemediationCasePresentation.Render(record) + "\n已导出病例记录；备份载荷不会加入此包。";
        }
        catch (Exception ex) { AppErrorLog.Write("CaseExport", ex); CaseDetailsText.Text = "病例导出失败：" + ex.Message; }
        finally { SetBusy(false); }
    }

    private async Task<CaseFollowUpResult> RunCaseFollowUpAsync(RemediationCaseRecord record, CancellationToken token)
    {
        if (!Dispatcher.CheckAccess())
            return await Dispatcher.InvokeAsync(() => RunCaseFollowUpAsync(record, token)).Task.Unwrap();
        using DispatcherProgress<ScanProgress> progress = CreateUiProgress(p =>
        { ProgressStageText.Text = "病例复验 · " + p.Stage; ProgressItemText.Text = p.CurrentItem; });
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
            Detail = "已按当前入口与模块重新关联，并使用受限进程检查内容；旧 PID 消失不单独作为组件已排除的依据。"
        };
    }
}
