using System.IO;
using System.Windows;
using System.Windows.Automation;
using System.Windows.Controls;
using System.Windows.Media;
using SteamSentinel.App.Dialogs;
using SteamSentinel.App.Services;
using SteamSentinel.App.ViewModels;
using SteamSentinel.Core.Inspection;
using SteamSentinel.Core.Models;
using SteamSentinel.Core.Remediation;
using SteamSentinel.Core.Reporting;
using SteamSentinel.Core.Scanning;
using SteamSentinel.Core.Steam;
using SteamSentinel.Core.Utilities;

namespace SteamSentinel.App;

public partial class MainWindow
{
    private RemediationBatchSession? _caseBatch;
    private ScanReport? _caseContentFollowUp;

    // 处置模式切换入口已从普通用户界面隐藏（默认锁定保守模式），正常流程不会展示 AggressiveModeBadge；
    // 保留此属性与回调以兼容后端策略与内部 UI 回归测试显式切换 SelectedIndex = 1 的校验路径。
    internal RemediationMode CurrentRemediationMode => RemediationModeComboBox?.SelectedIndex == 1
        ? RemediationMode.Aggressive : RemediationMode.Conservative;

    private void RemediationMode_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (RemediationModeComboBox is null || FindingsGrid is null || _busy) return;
        if (AggressiveModeBadge is not null)
            AggressiveModeBadge.Visibility = CurrentRemediationMode == RemediationMode.Aggressive ? Visibility.Visible : Visibility.Collapsed;
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

    private Task ExecuteSelectedRemediationAsync() => ExecuteSelectedRemediationAsync(null);

    internal async Task ExecuteSelectedRemediationAsync(
        Func<IReadOnlyList<string>, CancellationToken, Task<ScanReport>>? inspectTargetRunner,
        Func<RemediationPreviewWindow, bool>? confirmPreview = null,
        Func<RemediationPlan, Task<RemediationRunResult>>? executePlanRunner = null,
        Func<CancellationToken, Task<ScanReport>>? postRemediationRunner = null,
        Action<string, string>? onDetailsPresented = null,
        Action<string, string>? onAlertShown = null)
    {
        if (_busy || _lastReport is null) return;
        if (_reportNeedsRefresh)
        {
            ShowRemediationAlert(onAlertShown, DisplayText.Get("Remediation.ExecuteSelectedRemediationAsync.01"), DisplayText.Get("Remediation.ExecuteSelectedRemediationAsync.02"), MessageBoxImage.Information);
            return;
        }
        if (executePlanRunner is null && !await EnsureRemediationAvailableAsync()) return;
        FindingItemViewModel? retiredSelection = Findings.FirstOrDefault(item => item.IsSelected &&
            !item.UserSelectedRisk && RemediationEvidencePolicy.IsReviewOnlyEvidence(item.Finding));
        if (retiredSelection is not null)
        {
            ShowRemediationAlert(onAlertShown, RemediationEvidencePolicy.ReviewOnlyMessage(retiredSelection.Finding).Display, "SteamSentinel", MessageBoxImage.Information);
            return;
        }
        Finding[] selected = VisibleRemediationFindings.Where(i => i.IsSelected && i.CanSelect).Select(i => i.Finding).ToArray();
        if (selected.Length == 0) { ShowRemediationAlert(onAlertShown, DisplayText.Get("Remediation.ExecuteSelectedRemediationAsync.03"), "SteamSentinel", MessageBoxImage.Information); return; }
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
                if (inspectTargetRunner is not null)
                    return await inspectTargetRunner(paths, token);
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
            RemediationBatchSession batch = await Task.Run(() => CreateBatchPlanner()
                .PrepareAsync(selected, original, block, Inspect, progress, _scanCancellation.Token,
                    requestExplicitFileTargets: true, remediationMode: remediationMode));
            _lastPreparationFailedSteamPackage = HasSteamPackageUnavailableNote(batch);
            _steamUiFileRemovedInActiveBatch = false;
            _caseBatch = batch; _caseScan = original; _casePlan = null; _caseResult = null; _caseFollowUp = null; _caseContentFollowUp = null;
            UpdateBatchResults();
            if (batch.Plans.Count == 0)
            {
                HeaderStatusText.Text = DisplayText.Get("Remediation.ExecuteSelectedRemediationAsync.07"); HeaderDetailText.Text = batch.Summary;
                UpdateHeaderStatusTone(HeaderStatusTone.Warning);
                UpdateSteamRecoveryActions();
                ShowRemediationAlert(onAlertShown, batch.Summary + DisplayText.Get("Remediation.ExecuteSelectedRemediationAsync.08"), DisplayText.Get("Remediation.ExecuteSelectedRemediationAsync.09"), MessageBoxImage.Warning);
                return;
            }
            ShowActivity(ActivityPhase.Confirmation);
            RemediationPreviewWindow preview = CreateRemediationPreviewWindow(batch, selected);
            bool confirmed = confirmPreview is not null ? confirmPreview(preview) : preview.ShowDialog() == true;
            if (!confirmed) { batch.AddNote(MessageText.Create("Remediation.ExecuteSelectedRemediationAsync.10")); return; }
            if (executePlanRunner is null)
                await BeginPersistentCaseAsync(batch, original);
            _scanCancellation.Dispose(); _scanCancellation = null; CancelScanButton.IsEnabled = false;
            _operationCommitted = true; _reportNeedsRefresh = true;

            ResultTabs.SelectedIndex = 0;
            bool hasPackageRestore = batch.Plans.SelectMany(p => p.Actions)
                .Any(a => a.Type == RemediationActionType.RepairSteamConfiguration &&
                          a.ConfigurationKind == SteamConfigurationRepair.PackageRestore);
            BeginRepairStageInternal(ActiveRepairFlow.StandardRemediation, GetStandardRemediationStepLabels());
            ReportRepairStep(0, 12,
                DisplayText.Get("Ui.RepairStage.Std.Step0Title"),
                null,
                DisplayText.Get("Ui.RepairStage.Std.Step0Hint"));
            ReportRepairStep(1, 20,
                DisplayText.Get("Ui.RepairStage.Std.Step1Title"),
                null,
                DisplayText.Get("Ui.RepairStage.Std.Step1Hint"));

            using DispatcherProgress<ScanProgress> executeProgress = CreateUiProgress(p =>
            {
                double ratio = p.Total is > 0 and long total && total > 0
                    ? Math.Clamp((double)p.Completed / total, 0.0, 1.0)
                    : 0.5;
                double mapped = 20.0 + 54.0 * ratio;
                bool inRestorePhase = hasPackageRestore && ratio >= 0.45;
                int stepIdx = inRestorePhase ? 2 : 1;
                string title = DisplayText.Get(inRestorePhase ? "Ui.RepairStage.Std.Step2Title" : "Ui.RepairStage.Std.Step1Title");
                string hint = DisplayText.Get(inRestorePhase ? "Ui.RepairStage.Std.Step2Hint" : "Ui.RepairStage.Std.Step1Hint");
                string? friendlyItem = string.IsNullOrWhiteSpace(p.DisplayCurrentItem)
                    ? null
                    : FormatFriendlyScanTarget(p.DisplayCurrentItem, null);
                ReportRepairStep(stepIdx, Math.Max(_repairStepPercent, mapped), title, friendlyItem, hint);
            });

            await Task.Run(() => RemediationBatchPlanner.ExecuteAsync(
                batch,
                executePlanRunner ?? (plan => ExecuteRecordedPlanAsync(plan, approvedInUi: true)),
                executeProgress));
            if (executePlanRunner is null)
            {
                await _caseStore.SaveAsync(_persistedCase!);
                DisplayCaseRecord(_persistedCase!);
            }
            // Legacy exports retain the single-plan fields only for truly single-plan sessions.
            if (batch.Plans.Count == 1) { _casePlan = batch.Plans[0]; _caseResult = batch.Results.FirstOrDefault(); }
            HashSet<Guid> steamUiActionIds = batch.Plans
                .SelectMany(plan => plan.Actions)
                .Where(action => action.Type == RemediationActionType.RepairSteamConfiguration &&
                                 action.ConfigurationKind == SteamConfigurationRepair.UiFile)
                .Select(action => action.ActionId)
                .ToHashSet();
            _steamUiFileRemovedInActiveBatch = batch.ExecutionFinished && batch.Results
                .SelectMany(result => result.Actions)
                .Any(action => action.Success &&
                    (steamUiActionIds.Contains(action.ActionId) ||
                     (action.Type is RemediationActionType.QuarantineFile or RemediationActionType.QuarantineDirectory &&
                      IsSteamUiRemediationTarget(action.Target, original))));
            _steamBatchFollowUpActive = batch.ExecutionFinished;
            _lastSteamExeUntrustedOnLaunch = false;
            if (hasPackageRestore)
            {
                ReportRepairStep(2, Math.Max(_repairStepPercent, 74),
                    DisplayText.Get("Ui.RepairStage.Std.Step2Title"),
                    null,
                    DisplayText.Get("Ui.RepairStage.Std.Step2Hint"));
            }
            UpdateBatchResults();
            if (executePlanRunner is null && _remediationClient.HasUnresolvedExecution)
            {
                HeaderStatusText.Text = DisplayText.Get("Remediation.ExecuteSelectedRemediationAsync.12");
                HeaderDetailText.Text = DisplayText.Get("Remediation.ExecuteSelectedRemediationAsync.13");
                UpdateHeaderStatusTone(HeaderStatusTone.Warning);
                return;
            }
            await RunBatchFollowUpAsync(batch, original, inspectTargetRunner, postRemediationRunner);
            if (_closeWhenIdle) return;
            string guidance = SteamRecoveryGuide.BuildGuidance(
                _findingScopeLayout,
                batch,
                _caseFollowUp ?? original,
                _verifySteamExecutableSignature is null ? null : VerifyExecutableSignatureForGuide);
            bool incompleteBatch = batch.InterruptionReasonCode is not null || batch.Targets.Any(t => t.State != RemediationTargetState.Completed);
            bool remainingHighRisk = HasRemainingRiskAfterBatch();
            HeaderStatusText.Text = incompleteBatch ? DisplayText.Get("Remediation.ExecuteSelectedRemediationAsync.14") : DisplayText.Get("Remediation.ExecuteSelectedRemediationAsync.15");
            HeaderDetailText.Text = batch.Summary;
            UpdateHeaderStatusTone(incompleteBatch ? HeaderStatusTone.Warning : HeaderStatusTone.Success);
            string details = HeaderDetailText.Text + "\n" + batch.InterruptionText.Display + "\n" + BatchFollowUpText.Text + guidance;
            if (batch.Results.SelectMany(r => r.Actions).Any(a => a.Success &&
                a.Type is RemediationActionType.QuarantineFile or RemediationActionType.QuarantineDirectory &&
                original.Findings.Any(f => f.Category == FindingCategory.Steam && string.Equals(f.Target, a.Target, StringComparison.OrdinalIgnoreCase))))
                details += DisplayText.Get("Remediation.ExecuteSelectedRemediationAsync.16");
            details += DisplayText.Get("Remediation.ExecuteSelectedRemediationAsync.17");
            UpdateBatchResults();
            HideActivity();
            if (onDetailsPresented is not null)
            {
                onDetailsPresented(HeaderStatusText.Text, details);
            }
            else if (incompleteBatch || remainingHighRisk)
            {
                new TextDetailsWindow(HeaderStatusText.Text, details) { Owner = this }.ShowDialog();
            }
            else
            {
                MessageBox.Show(this, DisplayText.Get("Ui.BatchOutcome.SuccessModalBody"), HeaderStatusText.Text, MessageBoxButton.OK, MessageBoxImage.Information);
            }
            FooterText.Text = DisplayText.Get("Remediation.ExecuteSelectedRemediationAsync.18");
            if (executePlanRunner is null)
                await RefreshQuarantineItemsAsync();
        }
        catch (OperationCanceledException)
        {
            HeaderStatusText.Text = DisplayText.Get("Remediation.ExecuteSelectedRemediationAsync.19");
            UpdateHeaderStatusTone(HeaderStatusTone.Warning);
        }
        catch (Exception ex)
        {
            AppErrorLog.Write("BatchRemediation", ex);
            HeaderStatusText.Text = _operationCommitted ? DisplayText.Get("Remediation.ExecuteSelectedRemediationAsync.20") : DisplayText.Get("Remediation.ExecuteSelectedRemediationAsync.21");
            UpdateHeaderStatusTone(HeaderStatusTone.Warning);
            if (!_closeWhenIdle) ShowRemediationAlert(onAlertShown, MessageExceptions.Display(ex), HeaderStatusText.Text, MessageBoxImage.Warning);
        }
        finally
        {
            if (_persistedCase is { } savedCase && savedCase.BatchSession == _caseBatch)
            {
                try { await _caseStore.SaveAsync(savedCase); await RefreshCaseRecordsAsync(); }
                catch (Exception ex) { AppErrorLog.Write("SaveCaseAfterRemediation", ex); FooterText.Text = DisplayText.Get("Remediation.ExecuteSelectedRemediationAsync.22") + MessageExceptions.Display(ex); }
            }
            UpdateBatchResults(); _operationCommitted = false;
            _scanCancellation?.Dispose(); _scanCancellation = null; SetBusy(false);
            UpdateSteamRecoveryActions();
        }
    }

    private static readonly Brush BatchSuccessBackground = FreezeBrush(0xEC, 0xFD, 0xF5);
    private static readonly Brush BatchSuccessBorder = FreezeBrush(0xA7, 0xF3, 0xD0);
    private static readonly Brush BatchSuccessTitleForeground = FreezeBrush(0x06, 0x5F, 0x46);
    private static readonly Brush BatchSuccessDetailForeground = FreezeBrush(0x04, 0x78, 0x57);
    private static readonly Brush BatchWarningBackground = FreezeBrush(0xFF, 0xFB, 0xEB);
    private static readonly Brush BatchWarningBorder = FreezeBrush(0xFD, 0xE6, 0x8A);
    private static readonly Brush BatchWarningTitleForeground = FreezeBrush(0x92, 0x40, 0x0E);
    private static readonly Brush BatchWarningDetailForeground = FreezeBrush(0xB4, 0x53, 0x09);

    private bool HasRemainingRiskAfterBatch() =>
        (_caseFollowUp?.Findings.Any(f => f.CanRemediate || f.IsKnownMalware || IsRemainingSteamRecoveryFinding(f)) == true) ||
        (_caseContentFollowUp?.Findings.Any(f => f.CanRemediate || f.IsKnownMalware) == true);

    private void UpdateBatchResults()
    {
        if (_caseBatch is null)
        {
            UpdateBatchOutcomeBanner();
            return;
        }
        string? selectedKey = (BatchResultsGrid.SelectedItem as RemediationTargetOutcome)?.Key;
        BatchSummaryText.Text = _caseBatch.Summary;
        BatchResultsGrid.ItemsSource = null; BatchResultsGrid.ItemsSource = _caseBatch.Targets;
        BatchResultsGrid.SelectedItem = _caseBatch.Targets.FirstOrDefault(target => target.Key == selectedKey)
            ?? _caseBatch.Targets.FirstOrDefault();
        UpdateBatchActionDetailsAvailability();
        UpdateSteamRecoveryActions();
        UpdateBatchOutcomeBanner();
        BatchResultsTab.Header = DisplayText.Format("Remediation.UpdateBatchResults.01", (_caseBatch.Targets.Count));
    }

    internal void UpdateBatchOutcomeBanner()
    {
        if (BatchOutcomeBanner is null || BatchOutcomeTitleText is null || BatchOutcomeDetailText is null || BatchOutcomeActionButton is null)
            return;
        if (_caseBatch is not { ExecutionFinished: true })
        {
            BatchOutcomeBanner.Visibility = Visibility.Collapsed;
            BatchOutcomeActionButton.Visibility = Visibility.Collapsed;
            return;
        }

        bool incomplete = _caseBatch.InterruptionReasonCode is not null ||
                          _caseBatch.Targets.Any(t => t.State != RemediationTargetState.Completed);
        bool remainingHighRisk = HasRemainingRiskAfterBatch();
        bool isSuccess = !incomplete && !remainingHighRisk;

        BatchOutcomeBanner.Background = isSuccess ? BatchSuccessBackground : BatchWarningBackground;
        BatchOutcomeBanner.BorderBrush = isSuccess ? BatchSuccessBorder : BatchWarningBorder;
        BatchOutcomeTitleText.Foreground = isSuccess ? BatchSuccessTitleForeground : BatchWarningTitleForeground;
        BatchOutcomeDetailText.Foreground = isSuccess ? BatchSuccessDetailForeground : BatchWarningDetailForeground;

        BatchOutcomeTitleText.Text = DisplayText.Get(isSuccess ? "Ui.BatchOutcome.SuccessTitle" : "Ui.BatchOutcome.WarningTitle");
        if (isSuccess)
        {
            BatchOutcomeDetailText.Text = DisplayText.Get(ShouldShowLaunchSteamSelfCheck()
                ? "Ui.BatchOutcome.SuccessSteamSelfCheckDetail"
                : "Ui.BatchOutcome.SuccessDetail");
        }
        else
        {
            BatchOutcomeDetailText.Text = DisplayText.Get("Ui.BatchOutcome.WarningDetail");
        }

        if (ShouldShowLaunchSteamSelfCheck())
        {
            BatchOutcomeActionButton.Content = DisplayText.Get("Ui.SteamRepair.LaunchSelfCheckButton");
            BatchOutcomeActionButton.Tag = "launch-self-check";
            BatchOutcomeActionButton.Visibility = Visibility.Visible;
        }
        else if (ShouldShowOfficialSteamRepair())
        {
            BatchOutcomeActionButton.Content = DisplayText.Get("Ui.SteamRepair.OfficialButton");
            BatchOutcomeActionButton.Tag = "official-repair";
            BatchOutcomeActionButton.Visibility = Visibility.Visible;
        }
        else if (_caseBatch.Targets.Count > 0)
        {
            BatchOutcomeActionButton.Content = DisplayText.Get("Ui.BatchOutcome.ViewDetails");
            BatchOutcomeActionButton.Tag = "view-details";
            BatchOutcomeActionButton.Visibility = Visibility.Visible;
        }
        else
        {
            BatchOutcomeActionButton.Visibility = Visibility.Collapsed;
        }

        BatchOutcomeActionButton.IsEnabled = !_busy;
        BatchOutcomeBanner.Visibility = Visibility.Visible;
    }

    private async void BatchOutcomeAction_Click(object sender, RoutedEventArgs e)
    {
        if (BatchOutcomeActionButton?.Tag is not string actionTag) return;
        switch (actionTag)
        {
            case "launch-self-check":
                await ExecuteLaunchSteamSelfCheckAsync();
                break;
            case "official-repair":
                await ExecuteOfficialSteamRepairAsync();
                break;
            case "view-details":
                if (BatchResultsGrid.SelectedItem is null && _caseBatch?.Targets.Count > 0)
                    BatchResultsGrid.SelectedItem = _caseBatch.Targets[0];
                BatchActionDetails_Click(sender, e);
                break;
        }
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
        if (_repairStageActive)
        {
            _activityPhase = ActivityPhase.ContentFollowUp;
            ReportRepairStep(3, Math.Max(_repairStepPercent, 78),
                DisplayText.Get("Ui.RepairStage.Std.Step3Title"), null,
                DisplayText.Get("Ui.RepairStage.Std.Step3Hint"));
        }
        else
        {
            ShowActivity(ActivityPhase.ContentFollowUp);
        }
        using DispatcherProgress<ScanProgress> progress = CreateUiProgress(p =>
        {
            ProgressStageText.Text = DisplayText.Get("Remediation.RunOriginalContentCheckAsync.01") + p.DisplayStage;
            ProgressItemText.Text = p.DisplayCurrentItem;
            if (_repairStageActive)
            {
                double ratio = p.Total is > 0 and long total
                    ? Math.Clamp((double)p.Completed / total, 0.0, 1.0)
                    : 0.5;
                double mapped = Math.Max(_repairStepPercent, 78.0 + 10.0 * ratio);
                ReportRepairStep(3, mapped, DisplayText.Get("Ui.RepairStage.Std.Step3Title"),
                    p.DisplayCurrentItem, DisplayText.Get("Ui.RepairStage.Std.Step3Hint"));
            }
        });
        runner ??= (settings, reporter, cancellation) => _workerClient.RunAsync(settings, RequestPasswordAsync, reporter, cancellation);
        return await Task.Run(() => runner(options, progress, token), token);
    }

    private async Task RunBatchFollowUpAsync(RemediationBatchSession batch, ScanReport original,
        Func<IReadOnlyList<string>, CancellationToken, Task<ScanReport>>? customInspectRunner = null,
        Func<CancellationToken, Task<ScanReport>>? postRemediationRunner = null)
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
                _caseContentFollowUp = customInspectRunner is not null
                    ? await RunOriginalContentCheckAsync(settings, _scanCancellation.Token,
                        (opt, _, token) => customInspectRunner(opt.CustomRoots, token))
                    : await RunOriginalContentCheckAsync(settings, _scanCancellation.Token);
                _caseContentFollowUp.AddScopeNote(MessageText.Create("Remediation.RunBatchFollowUpAsync.01"));
                _lastReport = _caseContentFollowUp; PopulateFindings(_lastReport);
                messages.Add(ContentFollowUpSummary(_caseContentFollowUp));
            }
            catch (Exception ex)
            {
                _caseContentFollowUp = ScanFailureReports.PreserveSystemResults(null, settings.Mode, settings.CustomRoots, _coordinator.Rules.Version, ex, ex is OperationCanceledException);
                _lastReport = _caseContentFollowUp; PopulateFindings(_lastReport);
                messages.Add(DisplayText.Get("Remediation.RunBatchFollowUpAsync.02") + MessageExceptions.Display(ex));
            }
            finally { _scanCancellation.Dispose(); _scanCancellation = null; CancelScanButton.IsEnabled = false; }
            if (_closeWhenIdle) { BatchFollowUpText.Text = string.Join("\n", messages) + DisplayText.Get("Remediation.RunBatchFollowUpAsync.03"); return; }
        }
        else messages.Add(DisplayText.Get("Remediation.RunBatchFollowUpAsync.04"));
        _operationCommitted = true;
        try
        {
            using CancellationTokenSource timeout = new(TimeSpan.FromMinutes(2));
            _caseFollowUp = postRemediationRunner is not null
                ? await postRemediationRunner(timeout.Token)
                : await RunPostRemediationCheckAsync(timeout.Token);
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
            messages.Add(DisplayText.Get("Remediation.RunBatchFollowUpAsync.07") + MessageExceptions.Display(ex));
        }
        if (_repairStageActive)
        {
            ReportRepairStep(3, 99,
                DisplayText.Get("Ui.RepairStage.Std.Step3Title"), null,
                DisplayText.Get("Ui.RepairStage.Std.Step3Hint"));
        }
        BatchFollowUpText.Text = string.Join("\n", messages);
        ResultTabs.SelectedItem = BatchResultsTab;
        UpdateSteamRecoveryActions();
        UpdateScanStageOverlayVisibility();
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

    private SignatureResult VerifyExecutableSignatureForGuide(string executablePath)
    {
        if (_verifySteamExecutableSignature is null || !File.Exists(executablePath))
            return AuthenticodeVerifier.Verify(executablePath);
        using var handle = File.OpenHandle(executablePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
        return _verifySteamExecutableSignature(executablePath, handle);
    }

    private RemediationBatchPlanner CreateBatchPlanner() => new(
        _coordinator.Rules,
        _findingScopeLayout,
        _allowPackageDownload,
        _packageHttpMessageHandler,
        _verifySteamExecutableSignature);

    internal RemediationPreviewWindow CreateRemediationPreviewWindow(
        RemediationBatchSession batch, IReadOnlyList<Finding> selected) =>
        new(batch, _coordinator.Rules, _findingScopeLayout,
            isPortableInstallation: _installationSecurity.Mode == InstallationTrustMode.Portable,
            willAutoCloseSteam: ShouldAutoCloseSteamForBatch(batch, selected));

    private bool ShouldAutoCloseSteamForBatch(RemediationBatchSession batch, IReadOnlyList<Finding> selected)
    {
        bool touchesSteam = batch.Plans.SelectMany(plan => plan.Actions).Any(action =>
            action.Type == RemediationActionType.RepairSteamConfiguration ||
            (action.Type is RemediationActionType.QuarantineFile or RemediationActionType.QuarantineDirectory &&
             (selected.Any(finding => finding.Category == FindingCategory.Steam &&
                  string.Equals(finding.Target, action.Target, StringComparison.OrdinalIgnoreCase)) ||
              IsUnderKnownSteamRoot(action.Target))));
        return touchesSteam && IsSteamRunningForLayout(_findingScopeLayout);
    }

    private bool IsUnderKnownSteamRoot(string? path)
    {
        if (string.IsNullOrWhiteSpace(path)) return false;
        foreach (string root in EnumerateKnownSteamRoots())
        {
            if (IsPathWithinRoot(path, root)) return true;
        }
        return false;
    }

    private static bool IsPathWithinRoot(string candidatePath, string rootPath)
    {
        try
        {
            string fullRoot = Path.GetFullPath(rootPath).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar) + Path.DirectorySeparatorChar;
            string fullCandidate = Path.GetFullPath(candidatePath);
            return fullCandidate.StartsWith(fullRoot, StringComparison.OrdinalIgnoreCase);
        }
        catch
        {
            return false;
        }
    }

    private static bool HasSteamPackageUnavailableNote(RemediationBatchSession batch)
    {
        string unavailableDisplay = DisplayText.Get("SteamConfig.PackageUnavailable");
        static bool MatchesUnavailable(MessageText text, string localizedText) =>
            text.Message?.MessageId == "SteamConfig.PackageUnavailable" ||
            (!string.IsNullOrEmpty(localizedText) && text.OriginalText.Contains(localizedText, StringComparison.Ordinal));

        return batch.PreparationNotes.Any(note => MatchesUnavailable(note.DetailText, unavailableDisplay)) ||
               batch.NoteTexts.Any(note => MatchesUnavailable(note, unavailableDisplay)) ||
               batch.Targets.Any(target => MatchesUnavailable(target.ReasonDetailsText, unavailableDisplay));
    }

    private static bool IsSteamUiRemediationTarget(string target, ScanReport report) =>
        report.Findings.Any(f => string.Equals(f.Target, target, StringComparison.OrdinalIgnoreCase) &&
            f.RuleId is "STEAM-UI-SEMANTIC-TAMPERING" or "STEAM-UI-EXTERNAL-SCRIPT" or
                "STEAM-UI-LOOPBACK-SCRIPT" or "STEAM-UI-CSS-SUPPRESSION" or "STEAMALERT-UI-INJECTION") ||
        target.Contains("\\steamui\\", StringComparison.OrdinalIgnoreCase) ||
        target.Contains("\\clientui\\", StringComparison.OrdinalIgnoreCase);

    private static bool IsSteamBinaryUnrecoverableFinding(Finding finding) =>
        finding.RuleId == "STEAM-CLIENT-BINARY-MISSING" ||
        (finding.RuleId == "STEAM-CLIENT-BINARY-TAMPERED" && !finding.CanRemediate);

    private static bool IsRemainingSteamRecoveryFinding(Finding finding) =>
        finding.Category == FindingCategory.Steam &&
        finding.RuleId is
            "STEAM-CLIENT-BINARY-MISSING" or
            "STEAM-CLIENT-BINARY-TAMPERED" or
            "STEAM-UI-SEMANTIC-TAMPERING" or
            "STEAM-UI-EXTERNAL-SCRIPT" or
            "STEAM-UI-LOOPBACK-SCRIPT" or
            "STEAM-UI-CSS-SUPPRESSION" or
            "STEAMALERT-UI-INJECTION" or
            "STEAM-PROXY-DLL-HIJACK" or
            "STEAM-DLL-VERSION-FORWARDER";

    private bool HasSteamBinaryAnomalyInActiveReport() =>
        _steamBatchFollowUpActive
            ? (_caseFollowUp ?? _lastReport)?.Findings.Any(f => f.RuleId is "STEAM-CLIENT-BINARY-MISSING" or "STEAM-CLIENT-BINARY-TAMPERED") == true
            : _lastReport?.Findings.Any(f => f.RuleId is "STEAM-CLIENT-BINARY-MISSING" or "STEAM-CLIENT-BINARY-TAMPERED") == true;

    internal bool ShouldShowOfficialSteamRepair()
    {
        if (_lastReport?.Findings.Any(IsSteamBinaryUnrecoverableFinding) == true ||
            (_steamBatchFollowUpActive && _caseFollowUp?.Findings.Any(IsSteamBinaryUnrecoverableFinding) == true) ||
            _lastPreparationFailedSteamPackage ||
            _lastSteamExeUntrustedOnLaunch)
            return true;

        if (!_steamBatchFollowUpActive || _caseBatch is not { ExecutionFinished: true })
            return false;

        if (_caseBatch.Targets.Any(target => target.State != RemediationTargetState.Completed &&
                target.RequiredActions.Any(action => action.Contains("RepairSteamConfiguration", StringComparison.OrdinalIgnoreCase))))
            return true;

        return _caseFollowUp?.Findings.Any(IsRemainingSteamRecoveryFinding) == true ||
               (_caseContentFollowUp is null && _lastReport?.Findings.Any(IsRemainingSteamRecoveryFinding) == true);
    }

    internal bool ShouldShowLaunchSteamSelfCheck()
    {
        if (!_steamUiFileRemovedInActiveBatch || _lastSteamExeUntrustedOnLaunch || HasSteamBinaryAnomalyInActiveReport())
            return false;

        string? steamRoot = ResolveTargetSteamRoot();
        return IsLocalSteamExeValveSigned(steamRoot);
    }

    private IEnumerable<string> EnumerateKnownSteamRoots()
    {
        foreach (string root in _findingScopeLayout.SteamRoots)
        {
            if (!string.IsNullOrWhiteSpace(root))
                yield return root;
        }
    }

    private string? ResolveTargetSteamRoot()
    {
        foreach (string candidate in EnumerateKnownSteamRoots())
        {
            if (!ContentDiscovery.IsLocalSafePath(candidate)) continue;
            string full = Path.GetFullPath(candidate);
            if (Directory.Exists(full)) return full;
        }
        return null;
    }

    private bool IsLocalSteamExeValveSigned(string? steamRoot)
    {
        if (string.IsNullOrWhiteSpace(steamRoot) || !ContentDiscovery.IsLocalSafePath(steamRoot))
            return false;
        string steamExe = Path.Combine(steamRoot, "steam.exe");
        if (!ContentDiscovery.IsLocalSafePath(steamExe) || !File.Exists(steamExe))
            return false;

        DateTime lastWriteUtc = File.GetLastWriteTimeUtc(steamExe);
        if (_steamExeSignatureCache.TryGetValue(steamExe, out var cached) && cached.LastWriteUtc == lastWriteUtc)
            return cached.IsTrusted;

        SignatureResult verification;
        if (_verifySteamExecutableSignature is not null)
        {
            using var handle = File.OpenHandle(steamExe, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            verification = _verifySteamExecutableSignature(steamExe, handle);
        }
        else
        {
            verification = AuthenticodeVerifier.Verify(steamExe);
        }

        bool isTrusted = verification.IsValveSigner ||
                         AuthenticodeVerifier.IsTrustedValveSigner(verification.Status, verification.SignerSubject);
        _steamExeSignatureCache[steamExe] = (lastWriteUtc, isTrusted);
        return isTrusted;
    }

    private void RefreshSteamRecoveryButtonsLocalizedText()
    {
        if (OfficialSteamRepairButton is not null)
        {
            string label = DisplayText.Get("Ui.SteamRepair.OfficialButton");
            OfficialSteamRepairButton.Content = label;
            OfficialSteamRepairButton.ToolTip = DisplayText.Get("Ui.SteamRepair.OfficialTip");
            AutomationProperties.SetName(OfficialSteamRepairButton, label);
        }
        if (LaunchSteamSelfCheckButton is not null)
        {
            string label = DisplayText.Get("Ui.SteamRepair.LaunchSelfCheckButton");
            LaunchSteamSelfCheckButton.Content = label;
            LaunchSteamSelfCheckButton.ToolTip = DisplayText.Get("Ui.SteamRepair.LaunchSelfCheckTip");
            AutomationProperties.SetName(LaunchSteamSelfCheckButton, label);
        }
    }

    internal void UpdateSteamRecoveryActions()
    {
        if (SteamRecoveryActionsBar is null || OfficialSteamRepairButton is null || LaunchSteamSelfCheckButton is null || ResultTabs is null)
            return;

        bool visibleTab = ResultTabs.SelectedIndex is 0 or 2;
        bool showOfficial = visibleTab && ShouldShowOfficialSteamRepair();
        bool showSelfCheck = visibleTab && ShouldShowLaunchSteamSelfCheck();

        OfficialSteamRepairButton.Visibility = showOfficial ? Visibility.Visible : Visibility.Collapsed;
        OfficialSteamRepairButton.IsEnabled = !_busy;
        LaunchSteamSelfCheckButton.Visibility = showSelfCheck ? Visibility.Visible : Visibility.Collapsed;
        LaunchSteamSelfCheckButton.IsEnabled = !_busy;
        SteamRecoveryActionsBar.Visibility = showOfficial || showSelfCheck ? Visibility.Visible : Visibility.Collapsed;
    }

    private void ShowRemediationAlert(Action<string, string>? alertSink, string message, string title, MessageBoxImage icon)
    {
        if (alertSink is not null) alertSink(message, title);
        else MessageBox.Show(this, message, title, MessageBoxButton.OK, icon);
    }

    private void ShowSteamRecoveryNotice(Action<string, string, MessageBoxImage>? notifyDialog, string message, string title, MessageBoxImage icon)
    {
        if (notifyDialog is not null) notifyDialog(message, title, icon);
        else MessageBox.Show(this, message, title, MessageBoxButton.OK, icon);
    }

    private async void OfficialSteamRepair_Click(object sender, RoutedEventArgs e) =>
        await ExecuteOfficialSteamRepairAsync();

    /// <summary>
    /// 在用户明确确认后，从官方 HTTPS 下载并校验 Valve 签名的 SteamSetup.exe 执行保留游戏库的原位修复，并在结束后自动复扫。
    /// </summary>
    internal async Task ExecuteOfficialSteamRepairAsync(
        Func<string, string, bool>? confirmPrompt = null,
        Func<ScanMode, List<string>, ScanOptions?, Task>? rescanRunner = null,
        Action<string, string, MessageBoxImage>? notifyDialog = null)
    {
        Dispatcher.VerifyAccess();
        if (_busy) return;

        string title = DisplayText.Get("Ui.SteamRepair.OfficialTitle");
        string? targetRoot = ResolveTargetSteamRoot();
        if (string.IsNullOrWhiteSpace(targetRoot))
        {
            ShowSteamRecoveryNotice(notifyDialog, DisplayText.Get("Ui.SteamRepair.NoSteamRoot"), title, MessageBoxImage.Warning);
            return;
        }

        string confirmBody = DisplayText.Format("Ui.SteamRepair.OfficialConfirmBody", targetRoot);
        bool confirmed = confirmPrompt is not null
            ? confirmPrompt(confirmBody, title)
            : MessageBox.Show(this, confirmBody, title, MessageBoxButton.OKCancel, MessageBoxImage.Information) == MessageBoxResult.OK;
        if (!confirmed) return;

        bool triggerRescan = false;
        ResultTabs.SelectedIndex = 0;
        SetBusy(true);
        _scanCancellation = new();
        BeginRepairStageInternal(ActiveRepairFlow.OfficialInstaller, GetOfficialRepairStepLabels());
        CancelScanButton.IsEnabled = true;
        ReportRepairStep(0, 5,
            DisplayText.Get("Ui.RepairStage.Official.Step0Title"),
            "SteamSetup.exe",
            DisplayText.Format("Ui.SteamRepair.OfficialProgress", targetRoot));
        _steamExeSignatureCache.Clear();

        void DispatchUiAction(Action action)
        {
            if (_windowClosed || Dispatcher.HasShutdownStarted) return;
            try
            {
                if (Dispatcher.CheckAccess()) action();
                else Dispatcher.Invoke(action);
            }
            catch (OperationCanceledException) { }
            catch (InvalidOperationException) { }
        }

        IProgress<(long BytesRead, long? TotalBytes)> downloadProgress = new ImmediateProgress<(long BytesRead, long? TotalBytes)>(entry =>
        {
            DispatchUiAction(() =>
            {
                if (_windowClosed || !_repairStageActive) return;
                double pct;
                string hint;
                if (entry.TotalBytes is > 0 and long total)
                {
                    double ratio = Math.Clamp((double)entry.BytesRead / total, 0.0, 1.0);
                    pct = Math.Max(_repairStepPercent, 5.0 + 43.0 * ratio);
                    hint = DisplayText.Format("Ui.RepairStage.Official.DownloadProgress",
                        entry.BytesRead / (1024.0 * 1024.0), total / (1024.0 * 1024.0));
                }
                else
                {
                    pct = Math.Clamp(Math.Max(_repairStepPercent, 5.0 + (entry.BytesRead / (1024.0 * 1024.0)) * 8.0), 5.0, 46.0);
                    hint = DisplayText.Format("Ui.RepairStage.Official.DownloadUnknownTotal", entry.BytesRead / (1024.0 * 1024.0));
                }
                ReportRepairStep(0, pct, DisplayText.Get("Ui.RepairStage.Official.Step0Title"), "SteamSetup.exe", hint);
            });
        });

        IProgress<SteamOfficialRepairStage> stageProgress = new ImmediateProgress<SteamOfficialRepairStage>(stage =>
        {
            DispatchUiAction(() =>
            {
                if (_windowClosed || !_repairStageActive) return;
                switch (stage)
                {
                    case SteamOfficialRepairStage.DownloadingInstaller:
                        ReportRepairStep(0, Math.Max(_repairStepPercent, 5),
                            DisplayText.Get("Ui.RepairStage.Official.Step0Title"), "SteamSetup.exe",
                            DisplayText.Format("Ui.SteamRepair.OfficialProgress", targetRoot));
                        break;
                    case SteamOfficialRepairStage.VerifyingSignature:
                        ReportRepairStep(1, Math.Max(_repairStepPercent, 56),
                            DisplayText.Get("Ui.RepairStage.Official.Step1Title"), "SteamSetup.exe",
                            DisplayText.Get("Ui.RepairStage.Official.Step1Hint"));
                        break;
                    case SteamOfficialRepairStage.ClosingSteam:
                        ReportRepairStep(2, Math.Max(_repairStepPercent, 64),
                            DisplayText.Get("Ui.RepairStage.Official.Step2CloseTitle"), null,
                            DisplayText.Get("Ui.RepairStage.Official.Step2CloseHint"));
                        break;
                    case SteamOfficialRepairStage.RunningInstaller:
                        ReportRepairStep(2, Math.Max(_repairStepPercent, 72),
                            DisplayText.Get("Ui.RepairStage.Official.Step2RunTitle"), "SteamSetup.exe",
                            DisplayText.Get("Ui.RepairStage.Official.Step2RunHint"));
                        break;
                }
            });
        });

        try
        {
            SteamLayout repairLayout = new();
            repairLayout.SteamRoots.Add(targetRoot);
            SteamOfficialRepairResult repairResult = await _steamInstallerService.RunOfficialRepairAsync(
                targetRoot, repairLayout, cancellationToken: _scanCancellation.Token,
                downloadProgress: downloadProgress, stageProgress: stageProgress);

            if (repairResult.Succeeded)
            {
                string hashPrefix = string.IsNullOrWhiteSpace(repairResult.InstallerSha256)
                    ? "-"
                    : repairResult.InstallerSha256[..Math.Min(12, repairResult.InstallerSha256.Length)];
                string completed = DisplayText.Format("Ui.SteamRepair.OfficialCompleted", hashPrefix);
                ReportRepairStep(3, 86,
                    DisplayText.Get("Ui.RepairStage.Official.Step3Title"),
                    targetRoot,
                    DisplayText.Get("Ui.RepairStage.Official.Step3Hint"));
                HeaderStatusText.Text = title;
                HeaderDetailText.Text = completed;
                FooterText.Text = completed;
                UpdateHeaderStatusTone(HeaderStatusTone.Success);
                _lastPreparationFailedSteamPackage = false;
                _steamUiFileRemovedInActiveBatch = false;
                _steamBatchFollowUpActive = false;
                _lastSteamExeUntrustedOnLaunch = false;
                triggerRescan = true;
            }
            else
            {
                string failed = DisplayText.Format("Ui.SteamRepair.OfficialFailed", repairResult.Detail);
                HeaderStatusText.Text = title;
                HeaderDetailText.Text = failed;
                FooterText.Text = failed;
                UpdateHeaderStatusTone(HeaderStatusTone.Warning);
                HideActivity();
                ShowSteamRecoveryNotice(notifyDialog, failed, title, MessageBoxImage.Warning);
            }
        }
        catch (OperationCanceledException)
        {
            HeaderStatusText.Text = DisplayText.Get("Remediation.ExecuteSelectedRemediationAsync.19");
            UpdateHeaderStatusTone(HeaderStatusTone.Warning);
            HideActivity();
        }
        catch (Exception ex)
        {
            AppErrorLog.Write("OfficialSteamRepair", ex);
            string failed = DisplayText.Format("Ui.SteamRepair.OfficialFailed", MessageExceptions.Display(ex));
            HeaderStatusText.Text = title;
            HeaderDetailText.Text = failed;
            FooterText.Text = failed;
            UpdateHeaderStatusTone(HeaderStatusTone.Warning);
            HideActivity();
            if (!_closeWhenIdle)
                ShowSteamRecoveryNotice(notifyDialog, failed, title, MessageBoxImage.Warning);
        }
        finally
        {
            _scanCancellation?.Dispose();
            _scanCancellation = null;
            SetBusy(false);
        }

        if (triggerRescan && !_closeWhenIdle)
        {
            var request = _lastReport is not null
                ? CreateRemediationRescanRequest(_lastReport)
                : (Mode: ScanMode.Quick, Roots: new List<string>(), Settings: (ScanOptions?)null);
            if (rescanRunner is not null)
            {
                await rescanRunner(request.Mode, request.Roots, request.Settings);
                if (_repairStageActive)
                    ReportRepairStep(3, 99, DisplayText.Get("Ui.RepairStage.Official.Step3Title"), targetRoot, DisplayText.Get("Ui.RepairStage.Official.Step3Hint"));
                HideActivity();
            }
            else
            {
                await StartScanAsync(request.Mode, request.Roots, suppliedContentOptions: request.Settings);
            }
        }
    }

    private sealed class ImmediateProgress<T>(Action<T> report) : IProgress<T>
    {
        public void Report(T value) => report(value);
    }

    private async void LaunchSteamSelfCheck_Click(object sender, RoutedEventArgs e) =>
        await ExecuteLaunchSteamSelfCheckAsync();

    /// <summary>
    /// 验签通过后以安全降权或标准权限启动正版 steam.exe，以触发 Steam 客户端自检补齐已清除的 UI 资源。
    /// </summary>
    internal Task ExecuteLaunchSteamSelfCheckAsync(Action<string, string, MessageBoxImage>? notifyDialog = null)
    {
        Dispatcher.VerifyAccess();
        if (_busy) return Task.CompletedTask;

        string title = DisplayText.Get("Ui.SteamRepair.LaunchTitle");
        string? targetRoot = ResolveTargetSteamRoot();
        if (string.IsNullOrWhiteSpace(targetRoot) || !File.Exists(Path.Combine(targetRoot, "steam.exe")))
        {
            ShowSteamRecoveryNotice(notifyDialog, DisplayText.Get("Ui.SteamRepair.NoVerifiedSteamExe"), title, MessageBoxImage.Warning);
            return Task.CompletedTask;
        }

        SteamClientLaunchResult result = _steamInstallerService.LaunchVerifiedSteam(targetRoot);
        (string message, HeaderStatusTone tone, MessageBoxImage icon) = result.Status switch
        {
            SteamClientLaunchStatus.LaunchedDirect => (
                DisplayText.Format("Ui.SteamRepair.LaunchResult.Direct", result.ProcessId ?? 0),
                HeaderStatusTone.Success,
                MessageBoxImage.Information),
            SteamClientLaunchStatus.LaunchedDeElevated => (
                DisplayText.Format("Ui.SteamRepair.LaunchResult.DeElevated", result.ProcessId ?? 0),
                HeaderStatusTone.Success,
                MessageBoxImage.Information),
            SteamClientLaunchStatus.RefusedElevatedWithoutStandardToken => (
                DisplayText.Format("Ui.SteamRepair.LaunchResult.RefusedElevated", result.Message),
                HeaderStatusTone.Warning,
                MessageBoxImage.Warning),
            SteamClientLaunchStatus.RefusedUntrustedSignature => (
                DisplayText.Format("Ui.SteamRepair.LaunchResult.RefusedSignature", result.Message),
                HeaderStatusTone.Warning,
                MessageBoxImage.Warning),
            _ => (
                DisplayText.Format("Ui.SteamRepair.LaunchResult.Failed", result.Message),
                HeaderStatusTone.Warning,
                MessageBoxImage.Warning)
        };

        HeaderStatusText.Text = title;
        HeaderDetailText.Text = message;
        FooterText.Text = message;
        UpdateHeaderStatusTone(tone);
        if (result.Status == SteamClientLaunchStatus.RefusedUntrustedSignature)
        {
            _lastSteamExeUntrustedOnLaunch = true;
            _steamExeSignatureCache.Clear();
        }
        UpdateSteamRecoveryActions();
        ShowSteamRecoveryNotice(notifyDialog, message, title, icon);
        return Task.CompletedTask;
    }
}
