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
            MessageBox.Show(this, "请先重新扫描，再核对新的处理方案，不能重复提交旧结果。", "请先重新扫描", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }
        if (!await EnsureRemediationAvailableAsync()) return;
        Finding[] selected = Findings.Where(i => i.IsSelected && i.CanSelect).Select(i => i.Finding).ToArray();
        if (selected.Length == 0) { MessageBox.Show(this, "请先勾选至少一项可处置发现。", "SteamSentinel"); return; }
        if (selected.Any(f => f.Category == FindingCategory.Steam) && IsSteamRunning())
        { MessageBox.Show(this, "所选动作包含 Steam 恢复，请先从 Steam 菜单完整退出客户端，再生成处置方案。", "请先退出 Steam"); return; }
        ScanReport original = _lastReport;
        bool amsi = AmsiCheckBox.IsChecked == true, block = DomainBlockCheckBox.IsChecked == true;
        try
        {
            SetBusy(true); ShowActivity(ActivityPhase.Preparing, "按文件去重核验，并按关联组准备批次，尚未修改文件，可取消。");
            _scanCancellation = new(); CancelScanButton.IsEnabled = true;
            using DispatcherProgress<ScanProgress> progress = CreateUiProgress(p =>
            { ProgressStageText.Text = p.Stage; ProgressItemText.Text = p.CurrentItem; HeaderDetailText.Text = p.Message; });
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
                HeaderStatusText.Text = "所选目标尚未处置"; HeaderDetailText.Text = batch.Summary;
                MessageBox.Show(this, batch.Summary + "\n请查看“处置结果”中的逐项原因，没有执行处置。", "没有可执行方案", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }
            ShowActivity(ActivityPhase.Confirmation);
            RemediationPreviewWindow preview = new(batch) { Owner = this };
            if (preview.ShowDialog() != true) { batch.Notes.Add("用户未确认，没有执行任何批次。"); return; }
            _scanCancellation.Dispose(); _scanCancellation = null; CancelScanButton.IsEnabled = false;
            _operationCommitted = true; _reportNeedsRefresh = true;
            ShowActivity(ActivityPhase.Applying, "按关联组依次执行，出现 Windows 授权时请确认，遇到失败或身份变化会暂停后续批次。");
            await Task.Run(() => RemediationBatchPlanner.ExecuteAsync(batch, p => _remediationClient.ExecuteAsync(p), progress));
            // Legacy exports retain the single-plan fields only for truly single-plan sessions.
            if (batch.Plans.Count == 1) { _casePlan = batch.Plans[0]; _caseResult = batch.Results.FirstOrDefault(); }
            UpdateBatchResults();
            if (_remediationClient.HasUnresolvedExecution)
            {
                HeaderStatusText.Text = "管理员操作尚未返回确定结果";
                HeaderDetailText.Text = "已暂停后续处置与复查，可导出记录。点击重新检查可读取迟到的结果。";
                return;
            }
            await RunBatchFollowUpAsync(batch, original);
            if (_closeWhenIdle) return;
            HeaderStatusText.Text = batch.Interruption is not null || batch.Targets.Any(t => t.Status != "已完成") ? "处置尚未全部完成" : "所选动作已完成，请查看复查结果";
            HeaderDetailText.Text = batch.Summary;
            string details = batch.Summary + "\n" + (batch.Interruption ?? "") + "\n" + BatchFollowUpText.Text;
            if (selected.Any(f => f.Category == FindingCategory.Steam) && batch.Results.SelectMany(r => r.Actions).Any(a => a.Success &&
                a.Type is RemediationActionType.QuarantineFile or RemediationActionType.QuarantineDirectory))
                details += "\nSteam 恢复文件已准备，请从原快捷方式启动官方客户端补全组件，必要时使用官方安装包覆盖安装。";
            details += "\n\n请重启后复扫。仍在订阅的工坊项目可能重新下载，涉及窃密时请从可信设备处理账户安全。";
            HideActivity();
            new TextDetailsWindow(HeaderStatusText.Text, details) { Owner = this }.ShowDialog();
            FooterText.Text = "逐项结果在“处置结果”，导出完整记录包可保留所有批次、原扫描范围复查及系统复查。";
            await RefreshQuarantineItemsAsync();
        }
        catch (OperationCanceledException) { HeaderStatusText.Text = "方案准备已取消，未开始处置"; }
        catch (Exception ex)
        {
            AppErrorLog.Write("BatchRemediation", ex);
            HeaderStatusText.Text = _operationCommitted ? "操作未全部完成，请导出记录" : "处置方案未完成";
            if (!_closeWhenIdle) MessageBox.Show(this, ex.Message, HeaderStatusText.Text, MessageBoxButton.OK, MessageBoxImage.Warning);
        }
        finally
        {
            UpdateBatchResults(); _operationCommitted = false;
            _scanCancellation?.Dispose(); _scanCancellation = null; SetBusy(false);
        }
    }

    private void UpdateBatchResults()
    {
        if (_caseBatch is null) return;
        BatchSummaryText.Text = _caseBatch.Summary;
        BatchResultsGrid.ItemsSource = null; BatchResultsGrid.ItemsSource = _caseBatch.Targets;
        BatchResultsTab.Header = $"处置结果（{_caseBatch.Targets.Count}）";
    }

    internal async Task<ScanReport> RunOriginalContentCheckAsync(ScanOptions options, CancellationToken token,
        Func<ScanOptions, IProgress<ScanProgress>, CancellationToken, Task<ScanReport>>? runner = null)
    {
        Dispatcher.VerifyAccess();
        ShowActivity(ActivityPhase.ContentFollowUp);
        using DispatcherProgress<ScanProgress> progress = CreateUiProgress(p =>
        { ProgressStageText.Text = "原扫描范围复查 · " + p.Stage; ProgressItemText.Text = p.CurrentItem; });
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
                _caseContentFollowUp.ScopeNotes.Add("处置后原扫描范围复查，沿用原范围、模式和安全限制，不自动进行第二轮处置。");
                _lastReport = _caseContentFollowUp; PopulateFindings(_lastReport);
                messages.Add(ContentFollowUpSummary(_caseContentFollowUp));
            }
            catch (Exception ex)
            {
                _caseContentFollowUp = ScanFailureReports.PreserveSystemResults(null, settings.Mode, settings.CustomRoots, _coordinator.Rules.Version, ex, ex is OperationCanceledException);
                _lastReport = _caseContentFollowUp; PopulateFindings(_lastReport);
                messages.Add("原扫描范围复查未完成或已取消，不能据此判断已清除，可稍后手动复扫。" + ex.Message);
            }
            finally { _scanCancellation.Dispose(); _scanCancellation = null; CancelScanButton.IsEnabled = false; }
            if (_closeWhenIdle) { BatchFollowUpText.Text = string.Join("\n", messages) + "\n系统与 Steam 复查未进行，窗口正在关闭。"; return; }
        }
        else messages.Add("原扫描范围：无法恢复原内容扫描设置，本次未复查原目录，请手动重新扫描。");
        _operationCommitted = true;
        try
        {
            using CancellationTokenSource timeout = new(TimeSpan.FromMinutes(2));
            _caseFollowUp = await RunPostRemediationCheckAsync(timeout.Token);
            _caseFollowUp.ScopeNotes.Add("单独的系统与 Steam 状态复查，不替代原目录内容复查。系统防护提示不表示样本重新出现。");
            messages.Add(SystemFollowUpSummary(_caseFollowUp));
            // Never silently replace a content result with the unrelated system findings.
            if (_caseContentFollowUp is null) { _lastReport = _caseFollowUp; PopulateFindings(_lastReport); }
        }
        catch (Exception ex)
        {
            AppErrorLog.Write("PostRemediationCheck", ex);
            _caseFollowUp = new() { Coverage = ScanCoverage.Partial, CompletedAtUtc = DateTimeOffset.UtcNow };
            _caseFollowUp.CoverageNotes.Add("系统与 Steam 复查未完成：" + ex.Message);
            messages.Add("系统与 Steam 复查未完成，不能判定安全。" + ex.Message);
        }
        BatchFollowUpText.Text = string.Join("\n", messages);
        ResultTabs.SelectedItem = BatchResultsTab;
    }

    internal static string ContentFollowUpSummary(ScanReport report) => "原扫描范围：" +
        (report.Findings.Any(f => f.CanRemediate || f.IsKnownMalware) ? "仍有可处置的项目或已知威胁，请查看“风险与提示”。" : "在已完成的内容检查中，未发现可处置的项目或已知威胁。") +
        (report.Coverage != ScanCoverage.Complete ? "仍有未检查内容，不代表全部清除。" : "结论仅适用于本次已完成的检查范围，不代表电脑绝对安全。");
    internal static string SystemFollowUpSummary(ScanReport report) => "系统与 Steam：" +
        (report.Findings.Any(f => f.IsKnownMalware && f.Category is FindingCategory.Process or FindingCategory.Persistence or FindingCategory.Steam)
            ? "仍有活动威胁或篡改证据，请导出记录进一步处理。" : "在已完成的检查中，未发现已知活动威胁。") +
        (report.Findings.Any(f => f.RuleId == "SECURITY-CONTROLS-DISABLED") ? "Windows 安全防护未完全开启，这是配置提示，不是样本复活。" : "") +
        (report.Coverage != ScanCoverage.Complete ? "仍有未完成的系统或 Steam 检查，请查看报告中的原因。" : "");
}
