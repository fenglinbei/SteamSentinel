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
    private const string DiagnosticScopePrefix = "证书与代理诊断：";
    private const int MaximumDiagnosticDisplayCharacters = 256_000;

    private void PreserveSystemStageFailure(ScanReport? checkpoint, ScanMode mode, Exception failure, bool cancelled)
    {
        _lastReport = Services.ScanFailureReports.PreserveSystemStage(checkpoint, mode, _coordinator.Rules.Version, failure, cancelled);
        _lastFullSystemAndContentScanId = null;
        PopulateFindings(_lastReport);
        UpdateSummary(_lastReport);
        HeaderStatusText.Text = cancelled ? "系统检查已取消" : "系统检查未完成";
        HeaderDetailText.Text = "已保留已读取的系统发现及代理与证书记录，后续内容检查尚未开始，可导出报告。";
        ProgressStageText.Text = "系统检查未完成";
        ScanProgressBar.Value = 0;
    }

    private void UpdateRemediationEligibility()
    {
        if (RemediateButton is null || SelectAllButton is null || Findings is null) return;
        FindingHandlingCounts counts = FindingHandlingPresentation.Count(Findings.Select(item => item.Finding));
        bool available = counts.Actionable > 0;
        string unavailable = _busy ? "正在执行其他操作，请等待结束。"
            : _recoveryRequired || _caseRecoveryUnavailable || _remediationClient.HasUnresolvedExecution ? "上次操作的结果尚未确认，暂不能再次处置。"
            : _reportNeedsRefresh ? "请先重新扫描，再核对新的处置方案。"
            : !available ? counts.AttentionCount > 0
                ? "当前没有可处理项。仍有待确认、暂不支持或条件未满足的项目，请查看处理状态与原因。"
                : "当前没有可处理项；普通信息提示无需选择处理。"
            : !_installationSecurity.IsProtected ? _installationSecurity.Message + "。请先修复安装环境；只读诊断与导出仍可用。"
            : string.Empty;
        RemediateButton.IsEnabled = unavailable.Length == 0;
        RemediateButton.ToolTip = unavailable.Length > 0 ? unavailable : "先核对处理预览；执行时会请求 Windows 管理员授权。";
        SelectAllButton.IsEnabled = !_busy && !_reportNeedsRefresh && available;
        SelectAllButton.ToolTip = !available ? "当前没有可选择处理的项目。" + (counts.AttentionCount > 0 ? "请查看每项未处理原因。" : "普通说明不需要处理。")
            : _busy ? "正在执行其他操作，请等待结束。"
            : _reportNeedsRefresh ? "请重新扫描后再选择处理。" : $"仅选择 {counts.Actionable} 项有处理资格的发现；待确认及暂不能处理的项目不会被勾选。";
    }

    private void UpdateFindingActions()
    {
        if (ReviewFindingButton is null || OccupancyButton is null || FindingsGrid is null) return;
        FindingItemViewModel? item = FindingsGrid.SelectedItem as FindingItemViewModel;
        bool diagnostic = item?.IsTrustProxyFinding == true;
        bool related = item is not null && RelatedComponentReportPresentation.IsRelatedFinding(item.Finding);
        bool relatedFileAvailable = !related || GetRelatedFindingReviewTargets(item!.Finding).Count > 0;
        bool visiblePage = ResultTabs.SelectedIndex == 0;
        ReviewFindingButton.Content = diagnostic ? "检查代理与证书" : "进一步检查";
        ReviewFindingButton.ToolTip = diagnostic
            ? "只读检查本机代理配置与证书，不连接外部地址、不修改配置，已有扫描发现会保留。"
            : related && !relatedFileAvailable ? "当前关联记录尚未定位可补查的本地文件，请查看“组件关联”页的原因。"
            : "检查当前选中项的实际文件和关联启动入口，不执行文件，也不会自动隔离。";
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
        ShowActivity(ActivityPhase.Inspecting, "正在只读采集本机代理与证书；不连接外部地址，不修改配置，可取消。已有扫描发现会保留。");
        ResultTabs.SelectedItem = TrustProxyTab;
        TrustProxyStatusText.Text = "正在采集本机代理与证书";
        _scanCancellation = new CancellationTokenSource();
        CancellationToken cancellation = _scanCancellation.Token;
        CancelScanButton.IsEnabled = true;
        using var progress = CreateUiProgress(p =>
        {
            TrustProxyStatusText.Text = p.Stage + " · " + p.CurrentItem;
            ActivityDetailText.Text = p.Message;
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
                Name = "本地诊断采集",
                Status = ex is OperationCanceledException ? DiagnosticReadStatus.Cancelled : DiagnosticReadStatus.Failed,
                Detail = "本次诊断未完成：" + ex.Message
            };
            TrustProxyDiagnosticReport diagnostic = new() { StartedAtUtc = started, CompletedAtUtc = DateTimeOffset.UtcNow, Checks = [failed] };
            ApplyTrustProxyDiagnosticReport(new ScanReport
            {
                StartedAtUtc = started,
                CompletedAtUtc = diagnostic.CompletedAtUtc,
                Mode = ScanMode.Custom,
                Coverage = ScanCoverage.Partial,
                RuleSetVersion = _coordinator.Rules.Version,
                TrustProxyDiagnostics = diagnostic,
                ScopeNotes = [DiagnosticScopePrefix + "本次采集未完成，不能据此判断配置状态。"],
                Findings = [new Finding
                {
                    RuleId = "TRUST-PROXY-DIAGNOSTIC-FAILED", Category = FindingCategory.Coverage,
                    SourceKind = "trust-proxy-diagnostics", DiagnosticObservationIds = [failed.Id],
                    Title = "代理与证书诊断未完成", Target = "本地代理与证书", Description = failed.Detail,
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
        FooterText.Text = "代理与证书只读诊断已更新，原有扫描发现已保留。可导出当前报告；执行结果仍在“处置结果”。";
    }

    internal static ScanReport MergeTrustProxyDiagnosticReport(ScanReport? basis, ScanReport diagnostic)
    {
        if (diagnostic.TrustProxyDiagnostics is null)
            throw new InvalidDataException("采集器没有返回代理与证书诊断快照，不能用空结果替换已有线索。");
        if (basis is null) return diagnostic;
        return new ScanReport
        {
            ProductVersion = basis.ProductVersion,
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
            ScopeNotes = [.. basis.ScopeNotes.Where(note => !note.StartsWith(DiagnosticScopePrefix, StringComparison.Ordinal)), .. diagnostic.ScopeNotes,
                DiagnosticScopePrefix + $"本次仅刷新本地代理与证书。原扫描 ID 为 {basis.ScanId:N}，原扫描时间、范围、文件指标及未完成状态保留；局部诊断不替代全范围复扫。"]
        };
    }

    internal static int IncompleteDiagnosticChecks(TrustProxyDiagnosticReport diagnostic) => diagnostic.Checks.Count(check =>
        check.Required && check.Status is not (DiagnosticReadStatus.Complete or DiagnosticReadStatus.NotPresent));

    private void DisplayTrustProxyDiagnostics(TrustProxyDiagnosticReport? diagnostic)
    {
        if (TrustProxyDetailsText is null) return;
        if (diagnostic is null)
        {
            TrustProxyStatusText.Text = "尚未检查代理与证书";
            TrustProxyDetailsText.Text = "点击“检查代理与证书”后，这里会列出每项采集状态、代理配置来源、证书存储区及证书摘要。已有扫描发现会保留。";
            return;
        }
        int incomplete = IncompleteDiagnosticChecks(diagnostic);
        string state = diagnostic.CompletedAtUtc is null ? "采集尚未结束" : incomplete > 0
            ? $"本地采集未完成（{incomplete} 项）" : diagnostic.Checks.Any(check => check.Required) ? "本地采集已完成" : "采集状态待核对";
        string time = (diagnostic.CompletedAtUtc ?? diagnostic.StartedAtUtc).ToLocalTime().ToString("MM-dd HH:mm:ss");
        TrustProxyStatusText.Text = $"{state} · 代理 {diagnostic.Proxies.Count} 项 · 证书 {diagnostic.Certificates.Count} 张 · {time}";
        string details = TrustProxyReportPresentation.Describe(diagnostic);
        TrustProxyDetailsText.Text = details.Length <= MaximumDiagnosticDisplayCharacters ? details
            : details[..MaximumDiagnosticDisplayCharacters] + "\n\n界面显示已达到长度上限。其余诊断记录仍保存在报告中，请导出查看完整内容。";
        TrustProxyDetailsText.ScrollToHome();
    }
}
