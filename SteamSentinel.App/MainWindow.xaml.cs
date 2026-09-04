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

namespace SteamSentinel.App;

public partial class MainWindow : Window
{
    private readonly ScanCoordinator _coordinator = new();
    private readonly ArchiveWorkerClient _workerClient = new();
    private readonly RemediationClient _remediationClient = new();
    private InstallationSecurityStatus _installationSecurity = new(false, "正在检查安装环境");
    private ElevationContext _elevationContext = ElevationContext.Read();
    private CancellationTokenSource? _scanCancellation;
    private ScanReport? _lastReport;
    private ScanReport? _caseScan;
    private RemediationPlan? _casePlan;
    private RemediationRunResult? _caseResult;
    private ScanReport? _caseFollowUp;
    private bool _reportNeedsRefresh;
    private bool _busy;

    public MainWindow()
    {
        InitializeComponent();
        WorkshopScopeComboBox.ItemsSource = new[] { new WorkshopScopeItem("", "全部本地工坊") };
        WorkshopScopeComboBox.SelectedIndex = 0;
        Findings = [];
        QuarantineItems = [];
        DataContext = this;
        SetBusy(true);
        HeaderDetailText.Text = $"规则 {_coordinator.Rules.Version}";
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
            ShowActivity(ActivityPhase.Working, "正在发现 Steam 目录并读取已有隔离记录，请稍候。");
            SteamLayout layout = await Task.Run(SteamLocator.Discover);
            List<WorkshopScopeItem> scopes = [new("", "全部本地工坊")];
            foreach (string appId in layout.WorkshopRoots.Select(ContentDiscovery.WorkshopAppId).Where(id => id.Length > 0).Distinct())
                scopes.Add(new(appId, (layout.Games.FirstOrDefault(game => game.AppId == appId)?.Name ?? (appId == "431960" ? "Wallpaper Engine" : "Steam 工坊")) + " · " + appId));
            WorkshopScopeComboBox.ItemsSource = scopes;
            WorkshopScopeComboBox.SelectedIndex = 0;
            if (Application.Current is App { AdministratorWindowRequested: true })
                FooterText.Text = _elevationContext.IsElevated
                    ? "这是新的管理员窗口，请重新扫描，再核对目标并处置。若使用了另一账户，请确认扫描范围包含原用户的 Steam 与工坊目录。"
                    : "新窗口未取得管理员权限，请重新授权，扫描与报告导出仍可使用。";
            await RefreshQuarantineItemsAsync();
        }
        catch (Exception ex)
        {
            AppErrorLog.Write("InitializeWindow", ex);
            HeaderDetailText.Text = "初始化未完成，请查看安装提示或重试。";
            FooterText.Text = ex.Message;
        }
        finally { SetBusy(false); }
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
        ScanScopeText.Text = "快速扫描：Steam 客户端与相关运行状态，以及所选本地工坊、MOD 和插件。视频先查格式、结构与尾随数据，不是全盘扫描。" +
            (DownloadLocationsCheckBox.IsChecked == true ? " 已额外包含下载、桌面与临时目录，可能包含资料和样本库。" : " 不额外检查下载、桌面和临时目录，已识别的关联落点除外。");
    }

    private void CoverageGrid_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (CoverageGrid.SelectedItem is not CoverageGroup group) { CoverSelectedButton.IsEnabled = false; return; }
        DetailDescriptionText.Text = group.NextStep;
        DetailEvidenceText.Text = string.Join(Environment.NewLine + Environment.NewLine, group.Entries.Take(50).Select(i => i.Target + "\n" + i.Detail)) +
            (group.Count > 50 ? $"\n本组共 {group.Count:N0} 次覆盖记录，界面只展示部分记录。重复原因按目录合并，示例路径并非完整文件清单，可按目录补查。" : "");
        DetailHashText.Text = "覆盖记录不是威胁，不参与隔离选择。";
        DetailWorkshopText.Text = "按路径补查，压缩包使用外层文件。";
        CoverSelectedButton.IsEnabled = !_busy && group.CanFullScan && CoverageTargets(group).Count > 0;
    }

    private void ResultTabs_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (!ReferenceEquals(e.Source, ResultTabs) || DetailDescriptionText is null) return;
        FindingDetailCard.Visibility = ResultTabs.SelectedIndex == 2 ? Visibility.Collapsed : Visibility.Visible;
        if (ResultTabs.SelectedIndex == 0) FindingsGrid_SelectionChanged(FindingsGrid, e);
        else if (ResultTabs.SelectedIndex == 1)
        {
            if (CoverageGrid.SelectedIndex < 0 && CoverageGrid.Items.Count > 0) CoverageGrid.SelectedIndex = 0;
            CoverageGrid_SelectionChanged(CoverageGrid, e);
        }
    }

    internal static List<string> CoverageTargets(CoverageGroup group) => group.Entries.Select(i => i.Target)
        .Where(p => ContentDiscovery.IsLocalSafePath(p) && (File.Exists(p) || Directory.Exists(p)))
        .Distinct(StringComparer.OrdinalIgnoreCase).ToList();

    private async void CoverSelected_Click(object sender, RoutedEventArgs e)
    {
        if (_busy || CoverageGrid.SelectedItem is not CoverageGroup { CanFullScan: true } group) return;
        List<string> targets = CoverageTargets(group);
        if (targets.Count == 0) return;
        if (MessageBox.Show(this, $"将对这组记录中的 {targets.Count:N0} 个文件或目录进行完整内容扫描，并开启压缩内容检查。\n\n扫描会生成新报告，如需保留当前结果，请先取消并导出报告。加密内容需输入正确密码，权限、损坏及安全上限可能仍无法解决。本次仅补查所选位置，不代替系统复扫。",
            "补查所选内容", MessageBoxButton.OKCancel, MessageBoxImage.Information) != MessageBoxResult.OK) return;
        ArchiveCheckBox.IsChecked = true;
        await StartScanAsync(ScanMode.Custom, targets);
    }

    private async void FileScan_Click(object sender, RoutedEventArgs e)
    {
        OpenFileDialog dialog = new() { Title = "选择要静态扫描的文件", CheckFileExists = true };
        if (dialog.ShowDialog(this) == true) await StartScanAsync(ScanMode.Custom, [dialog.FileName]);
    }

    private async void FolderScan_Click(object sender, RoutedEventArgs e)
    {
        OpenFolderDialog dialog = new() { Title = "选择要静态扫描的目录", Multiselect = false };
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
        if (MessageBox.Show(this, $"将重新扫描 {targets.Count} 个相关外层文件，之前的密码已清空，需要重新输入。请准备好外层和内层密码。新结果只覆盖这些文件，不是全机复扫。",
            "重试未解密内容", MessageBoxButton.OKCancel, MessageBoxImage.Information) != MessageBoxResult.OK) return;
        ArchiveCheckBox.IsChecked = true;
        await StartScanAsync(ScanMode.Custom, targets);
    }

    internal static List<string> GetPasswordRetryTargets(ScanReport report) => report.Findings
        .Where(f => f.Category == FindingCategory.Coverage && f.RuleId is
            "ARCHIVE-PASSWORD-FAILED" or "ARCHIVE-ENCRYPTED-NOT-SCANNED" or "ARCHIVE-ENCRYPTED-DEFERRED")
        .Select(f => f.Target).Where(File.Exists).Distinct(StringComparer.OrdinalIgnoreCase).ToList();

    private async Task StartScanAsync(ScanMode mode, List<string> customRoots, bool reviewRelated = false)
    {
        if (_busy) return;
        SetBusy(true);
        ShowActivity(ActivityPhase.Scanning);
        Findings.Clear();
        CoverageGrid.ItemsSource = null;
        CoverageTab.Header = "未检查内容";
        CoverageStatusText.Text = "扫描结束后显示未深查与读取受限的内容。";
        CoverSelectedButton.IsEnabled = false;
        ResultTabs.SelectedIndex = 0;
        _lastReport = null;
        _reportNeedsRefresh = false;
        HeaderStatusText.Text = "正在扫描";
        HeaderDetailText.Text = mode switch
        {
            ScanMode.Quick => "快速系统与工坊扫描",
            ScanMode.Full => "完整哈希与递归内容扫描",
            _ => "自定义内容扫描"
        };
        FindingCountText.Text = "0 项风险或提示";
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
                    () => _coordinator.RunAsync(systemOptions, null, progress, token), token);
                if (systemReport.Findings.Any(f => f.IsKnownMalware && f.Category == FindingCategory.Process && f.CanRemediate) &&
                    MessageBox.Show(this, "已发现运行中的威胁关联，后续内容扫描可能较久。是否先查看结果并处置？选择“是”会暂停后续检查，不会自动停止进程。",
                        "发现活动威胁", MessageBoxButton.YesNo, MessageBoxImage.Warning, MessageBoxResult.Yes) == MessageBoxResult.Yes)
                {
                    systemReport.Coverage = ScanCoverage.Partial;
                    systemReport.CoverageNotes.Add("发现活动威胁后，用户选择先处理，工坊与关联落点的后续内容检查尚未开始。");
                    _lastReport = systemReport; PopulateFindings(systemReport); UpdateSummary(systemReport); return;
                }
            }

            ScanOptions contentOptions = new()
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
                UseAmsi = AmsiCheckBox.IsChecked == true,
                HashEveryFile = mode != ScanMode.Quick,
                MaximumContentBytes = mode == ScanMode.Quick ? 1024L * 1024 * 1024 : long.MaxValue,
                CustomRoots = customRoots,
                ExcludedRoots = [AppPaths.MachineStateRoot, AppPaths.TemporaryRoot, AppPaths.WorkerTemporaryRoot, AppContext.BaseDirectory]
            };

            contentAttempted = true;
            ScanReport contentReport = await _workerClient.RunAsync(
                contentOptions, RequestPasswordAsync, progress, token);
            _lastReport = systemReport is null ? contentReport : ScanReportMerger.Merge(systemReport, contentReport);
            if (mode != ScanMode.Custom) await Task.Run(() => ProtectionConfiguration.CollectAsync(SteamLocator.Discover(), _lastReport, token), token);
            PopulateFindings(_lastReport);
            UpdateSummary(_lastReport);
        }
        catch (OperationCanceledException ex)
        {
            if (contentAttempted) PreserveScanFailure(systemReport, mode, customRoots, ex, cancelled: true);
            HeaderStatusText.Text = "扫描已取消";
            HeaderDetailText.Text = systemReport is null ? "内容检查未完成" : "已保留系统检查结果，内容检查未完成";
            FooterText.Text = "扫描已取消，加密包密码不会保留，当前结果不能作为完整复扫。";
        }
        catch (Exception ex)
        {
            if (contentAttempted) PreserveScanFailure(systemReport, mode, customRoots, ex, cancelled: false);
            else
            {
                HeaderStatusText.Text = "扫描失败";
                HeaderDetailText.Text = ex.Message;
            }
            AppErrorLog.Write("Scan", ex);
            if (!_closeWhenIdle) MessageBox.Show(this, ex.Message, "SteamSentinel 扫描失败", MessageBoxButton.OK, MessageBoxImage.Error);
        }
        finally
        {
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
            HeaderStatusText.Text = cancelled ? "扫描已取消" : "扫描不完整";
        HeaderDetailText.Text = "已保留可用结果，内容检查未完成，可导出报告查看最后路径与错误";
        ProgressStageText.Text = cancelled ? "扫描已取消" : "内容检查未完成";
        ScanProgressBar.Value = 0;
        ProgressItemText.Text = _lastReport.WorkerDiagnostics is { LastPath.Length: > 0 } diagnostic
            ? $"最后处理：{diagnostic.LastPath}（{diagnostic.Stage}），已保留此前结果，可导出报告反馈。"
            : "已保留可用结果，请查看覆盖说明，或导出报告反馈。";
    }

    private Task<ArchivePasswordResponse> RequestPasswordAsync(ArchivePasswordRequest request, CancellationToken cancellationToken)
    {
        return Dispatcher.InvokeAsync(() =>
        {
            cancellationToken.ThrowIfCancellationRequested();
            PasswordDialog dialog = new(request) { Owner = this };
            bool accepted = dialog.ShowDialog() == true;
            return new ArchivePasswordResponse(
                request.RequestId,
                !accepted,
                accepted ? dialog.EnteredPassword : null,
                false, dialog.ReuseScope);
        }).Task;
    }

    private void UpdateProgress(ScanProgress progress)
    {
        if (_lastReport is not null) return;
        ProgressStageText.Text = progress.Stage + " · " + progress.Message;
        ProgressItemText.Text = progress.CurrentItem;
        FooterText.Text = $"已处理 {progress.Completed:N0} 项 · {progress.CurrentItem}";
    }

    private void PopulateFindings(ScanReport report)
    {
        Findings.Clear();
        foreach (Finding finding in report.Findings.Where(f => f.Category != FindingCategory.Coverage)) Findings.Add(new FindingItemViewModel(finding));
        FindingCountText.Text = $"{Findings.Count:N0} 项风险或提示";
        IReadOnlyList<CoverageGroup> groups = CoveragePresentation.Groups(report);
        CoverageGrid.ItemsSource = groups;
        CoverageTab.Header = groups.Count > 0 ? $"未检查内容（{groups.Count} 类）" : "检查范围";
        CoverageStatusText.Text = groups.Count > 0 ? $"{groups.Count} 类覆盖说明，不计入风险数量。选中一类可查看原因与补查方式，记录数不一定等于文件数。" : "本次支持范围内没有额外跳过项，仍不代表电脑绝对安全。";
        ExportButton.IsEnabled = true;
        RemediateButton.IsEnabled = !_busy && !_reportNeedsRefresh && _installationSecurity.IsProtected && Findings.Any(item => item.CanSelect);
        if (Findings.Count > 0) FindingsGrid.SelectedIndex = 0;
    }

    private void UpdateSummary(ScanReport report)
    {
        bool confirmed = report.Findings.Any(finding => finding.IsKnownMalware);
        bool suspicious = report.Findings.Any(finding => finding.Category != FindingCategory.Coverage && finding.Severity >= FindingSeverity.Medium);
        if (confirmed)
        {
            bool hostEvidence = report.Findings.Any(f => f.Category is FindingCategory.Process or FindingCategory.Persistence or FindingCategory.Steam && f.Severity >= FindingSeverity.High);
            HeaderStatusText.Text = hostEvidence ? "发现威胁与本机异常" : "扫描内容包含已知威胁";
            HeaderDetailText.Text = "请核对内容位置与外层隔离目标，文件检出不等于本机已感染";
        }
        else if (suspicious)
        {
            HeaderStatusText.Text = "发现可疑项";
            HeaderDetailText.Text = "需要人工复核，未自动判定为病毒";
        }
        else
        {
            HeaderStatusText.Text = "已检查部分未发现需处理的风险";
            HeaderDetailText.Text = "结论仅适用于已完成的检查，不代表电脑绝对安全";
        }

        HeaderDetailText.Text += report.Coverage == ScanCoverage.Complete
            ? "，已完成支持范围内的检查。" : "，部分内容未检查，请查看“未检查内容”。";
        ProgressStageText.Text = report.Mode == ScanMode.Quick ? "快速扫描已完成" : "本次扫描已完成";
        ProgressItemText.Text = "风险与提示、未检查内容已分开列出，请核对后再处置。";
        ScanProgressBar.Value = 100;
        FooterText.Text = $"文件 {report.Metrics.FilesVisited:N0} · 工坊 {report.Metrics.WorkshopItemsVisited:N0} · 压缩条目 {report.Metrics.ArchiveEntriesVisited:N0} · 覆盖 {ReportExporter.CoverageLabel(report.Coverage)}";
    }

    private void FindingsGrid_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        FindingItemViewModel? item = FindingsGrid.SelectedItem as FindingItemViewModel;
        DetailDescriptionText.Text = item?.Description ?? string.Empty;
        if (item is not null && !item.CanSelect)
            DetailDescriptionText.Text += "\n此项目前仅作提示，尚无足够依据执行处置。可点击“进一步检查”核对实际文件，若仍无法判断，请导出记录。";
        DetailEvidenceText.Text = item?.Evidence ?? string.Empty;
        DetailHashText.Text = item is null ? string.Empty : $"命中内容：{item.Sha256}\n隔离目标：{item.Finding.TargetSha256 ?? "不适用"}\n内容位置：{item.Finding.ContentPath ?? item.Target}";
        DetailWorkshopText.Text = item?.WorkshopId ?? string.Empty;
        ReviewFindingButton.IsEnabled = !_busy && item is not null;
        OccupancyButton.IsEnabled = !_busy && item is not null;
    }

    private async void Occupancy_Click(object sender, RoutedEventArgs e)
    {
        if (_busy || FindingsGrid.SelectedItem is not FindingItemViewModel item) return;
        SetBusy(true);
        ShowActivity(ActivityPhase.Inspecting, "只读查询文件占用，单个位置最多等待 15 秒，不会关闭进程或句柄。");
        try
        {
            List<string> paths = FindingReviewTargets.Get(item.Finding);
            if (paths.Count == 0) paths.AddRange(await Task.Run(() => new RelatedArtifactScanner(_coordinator.Rules).GetCandidatePathsAsync(item.Finding)));
            if (paths.Count == 0)
            {
                MessageBox.Show(this, "尚未定位到可读的实际文件或目录，请先进一步检查或重新扫描。", "占用状态未知", MessageBoxButton.OK, MessageBoxImage.Information);
                return;
            }
            List<string> details = [];
            foreach (string path in paths.Take(4))
            {
                FileOccupancyResult occupancy = await Task.Run(() => FileOccupancy.Inspect(path, Directory.Exists(path)))
                    .WaitAsync(TimeSpan.FromSeconds(15));
                details.Add(path + "\n" + FileOccupancy.Describe(occupancy));
            }
            details.Add("只读快照，最多检查四个关联位置。没有关闭任何程序或句柄。未列出占用不表示一定可以删除，目录句柄和受保护进程可能无法识别。请先保存工作并正常退出相关程序，不要仅凭 PID 强行结束系统进程。");
            DetailEvidenceText.Text = string.Join("\n\n", details);
            MessageBox.Show(this, DetailEvidenceText.Text, "文件占用情况", MessageBoxButton.OK, MessageBoxImage.Information);
        }
        catch (Exception ex) { MessageBox.Show(this, "未能完成占用查询，没有关闭任何程序。\n" + ex.Message, "占用状态未知", MessageBoxButton.OK, MessageBoxImage.Information); }
        finally { SetBusy(false); }
    }

    private async void ReviewFinding_Click(object sender, RoutedEventArgs e)
    {
        if (_busy || FindingsGrid.SelectedItem is not FindingItemViewModel item) return;
        List<string> targets;
        SetBusy(true);
        ShowActivity(ActivityPhase.Inspecting);
        try
        {
            targets = (await Task.Run(() => new RelatedArtifactScanner(_coordinator.Rules).GetCandidatePathsAsync(item.Finding)))
                .Concat(FindingReviewTargets.Get(item.Finding).Where(Directory.Exists))
                .Distinct(StringComparer.OrdinalIgnoreCase).ToList();
        }
        catch (Exception ex) { MessageBox.Show(this, ex.Message, "未能定位关联文件", MessageBoxButton.OK, MessageBoxImage.Information); return; }
        finally { SetBusy(false); }
        if (MessageBox.Show(this, "将重新检查系统启动入口，并完整检查所选项可定位的实际文件或目录。不会执行文件，也不会自动处置。\n\n这会替换当前扫描结果，如需保留，请先取消并导出报告。" +
            (targets.Count == 0 ? "\n该项尚未定位到可读文件，本次将先刷新系统关联证据。" : $"\n本次内容位置：{targets.Count} 个。"),
            "进一步检查", MessageBoxButton.OKCancel, MessageBoxImage.Information) != MessageBoxResult.OK) return;
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
            Title = _caseResult is null ? "导出扫描或完整处置记录" : "导出当前扫描报告，或本窗口最近一次处置的完整记录包",
            Filter = "Markdown 报告 (*.md)|*.md|JSON 证据 (*.json)|*.json|完整记录包 (*.zip)|*.zip",
            FileName = $"SteamSentinel-{_lastReport.ScanId:N}.md"
        };
        if (dialog.ShowDialog(this) != true) return;
        SetBusy(true);
        ShowActivity(ActivityPhase.Exporting);
        try
        {
            string extension = Path.GetExtension(dialog.FileName);
            if (extension.Equals(".zip", StringComparison.OrdinalIgnoreCase))
                await Task.Run(() => CaseBundleExporter.ExportAsync(dialog.FileName, _caseScan ?? _lastReport, _casePlan, _caseResult, _caseFollowUp,
                    batches: _caseBatch, contentFollowUp: _caseContentFollowUp));
            else if (extension.Equals(".json", StringComparison.OrdinalIgnoreCase))
                await Task.Run(() => ReportExporter.ExportJsonAsync(_lastReport, dialog.FileName));
            else await Task.Run(() => ReportExporter.ExportMarkdownAsync(_lastReport, dialog.FileName));
            FooterText.Text = $"记录已导出：{dialog.FileName}";
        }
        catch (Exception ex) { MessageBox.Show(this, ex.Message, "导出未完成", MessageBoxButton.OK, MessageBoxImage.Warning); }
        finally { SetBusy(false); }
    }

    private async void RefreshQuarantine_Click(object sender, RoutedEventArgs e)
    {
        if (_busy) return;
        SetBusy(true);
        ShowActivity(ActivityPhase.Working, "正在读取已有隔离记录，不会还原或删除文件。");
        try { await RefreshQuarantineItemsAsync(); }
        finally { SetBusy(false); }
    }

    private async Task RefreshQuarantineItemsAsync()
    {
        QuarantineItems.Clear();
        if (!Directory.Exists(AppPaths.QuarantineRoot)) return;

        string[] manifestPaths;
        try
        {
            manifestPaths = await Task.Run(() => Directory.GetFiles(AppPaths.QuarantineRoot, "manifest.json", SearchOption.AllDirectories));
        }
        catch (Exception ex)
        {
            FooterText.Text = $"无法读取隔离清单：{ex.Message}";
            return;
        }

        foreach (string manifestPath in manifestPaths)
        {
            try
            {
                QuarantineManifest manifest = await JsonFile.ReadAsync<QuarantineManifest>(manifestPath);
                if (manifest.Records.Count == 0) continue;
                QuarantineItems.Add(new QuarantineItemViewModel { Manifest = manifest, ManifestPath = manifestPath });
            }
            catch
            {
                // A malformed manifest is not automatically deleted or trusted.
            }
        }
    }

    private void OpenQuarantine_Click(object sender, RoutedEventArgs e)
    {
        if (!Directory.Exists(AppPaths.QuarantineRoot))
        {
            MessageBox.Show(this, "当前还没有隔离事件。", "SteamSentinel", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }
        Process.Start(new ProcessStartInfo("explorer.exe", AppPaths.QuarantineRoot) { UseShellExecute = true });
    }

    private async void Rollback_Click(object sender, RoutedEventArgs e)
    {
        if (QuarantineGrid.SelectedItem is not QuarantineItemViewModel selected) return;
        if (MessageBox.Show(this,
                "回滚会尝试把文件和配置恢复到原位置。若原位置已被占用，管理员处置组件将拒绝覆盖。继续吗？",
                "确认回滚", MessageBoxButton.YesNo, MessageBoxImage.Warning) != MessageBoxResult.Yes) return;
        await RunIncidentActionAsync(RemediationActionType.RollbackIncident, selected.IncidentId);
    }

    private async void DeleteIncident_Click(object sender, RoutedEventArgs e)
    {
        if (QuarantineGrid.SelectedItem is not QuarantineItemViewModel selected) return;
        if (!selected.RebootObserved)
        {
            MessageBox.Show(this, "该隔离事件创建后尚未检测到一次系统重启，永久删除已被阻止。", "SteamSentinel", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }
        bool cleanRescan = _lastReport is not null && _lastReport.Coverage == ScanCoverage.Complete &&
                           !_lastReport.Findings.Any(finding => finding.IsKnownMalware && finding.Severity == FindingSeverity.Critical);
        if (!cleanRescan)
        {
            MessageBox.Show(this, "请先完成一次覆盖状态为“完整”的复扫，并确认没有已知恶意项。", "SteamSentinel", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }
        if (MessageBox.Show(this,
                "这会永久删除所选隔离事件及其中样本，无法通过本工具恢复。是否继续？",
                "永久删除确认", MessageBoxButton.YesNo, MessageBoxImage.Stop) != MessageBoxResult.Yes) return;
        await RunIncidentActionAsync(RemediationActionType.DeleteIncident, selected.IncidentId);
    }

    private async Task RunIncidentActionAsync(RemediationActionType type, string incidentId)
    {
        if (_busy) return;
        if (!await EnsureRemediationAvailableAsync()) return;
        SetBusy(true);
        _operationCommitted = true;
        ShowActivity(ActivityPhase.Applying, type == RemediationActionType.RollbackIncident
            ? "正在请求回滚并等待结果，请核对 Windows 授权，不要关闭窗口或重启。"
            : "正在请求永久删除所选隔离事件，请核对 Windows 授权，不要关闭窗口或重启。");
        try
        {
            RemediationPlan plan = new()
            {
                Actions =
                {
                    new RemediationAction
                    {
                        Type = type,
                        DisplayName = type == RemediationActionType.RollbackIncident ? "回滚隔离事件" : "永久删除隔离事件",
                        Target = incidentId,
                        IncidentId = incidentId
                    }
                }
            };
            RemediationRunResult result = await Task.Run(() => _remediationClient.ExecuteAsync(plan));
            HideActivity();
            MessageBox.Show(this,
                string.Join(Environment.NewLine,
                    result.Actions.Select(action => action.Message).Concat(result.Errors.Select(error => "错误 · " + error))),
                result.Success ? "操作完成" : "操作失败",
                MessageBoxButton.OK,
                result.Success ? MessageBoxImage.Information : MessageBoxImage.Error);
            await RefreshQuarantineItemsAsync();
        }
        catch (OperationCanceledException) { }
        catch (Exception ex)
        {
            MessageBox.Show(this, ex.Message, "隔离操作失败", MessageBoxButton.OK, MessageBoxImage.Error);
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
        WorkshopScopeComboBox.IsEnabled = !busy;
        DownloadLocationsCheckBox.IsEnabled = !busy;
        ExecutionHistoryCheckBox.IsEnabled = !busy;
        FullScanButton.IsEnabled = !busy;
        FileScanButton.IsEnabled = !busy;
        FolderScanButton.IsEnabled = !busy;
        ArchiveCheckBox.IsEnabled = !busy;
        DomainBlockCheckBox.IsEnabled = !busy;
        AmsiCheckBox.IsEnabled = !busy;
        CoverSelectedButton.IsEnabled = !busy && CoverageGrid.SelectedItem is CoverageGroup { CanFullScan: true } group && CoverageTargets(group).Count > 0;
        RetryPasswordsButton.IsEnabled = !busy && _lastReport is not null && GetPasswordRetryTargets(_lastReport).Count > 0;
        CancelScanButton.IsEnabled = busy && _scanCancellation is not null;
        RemediateButton.IsEnabled = !busy && !_reportNeedsRefresh && _installationSecurity.IsProtected && Findings.Any(item => item.CanSelect);
        ExportButton.IsEnabled = !busy && _lastReport is not null;
        ReviewFindingButton.IsEnabled = !busy && ResultTabs.SelectedIndex == 0 && FindingsGrid.SelectedItem is FindingItemViewModel;
        OccupancyButton.IsEnabled = !busy && ResultTabs.SelectedIndex == 0 && FindingsGrid.SelectedItem is FindingItemViewModel;
        RollbackButton.IsEnabled = !busy && _installationSecurity.IsProtected;
        DeleteIncidentButton.IsEnabled = !busy && _installationSecurity.IsProtected;
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
        await RefreshInstallationSecurityAsync();
        if (_installationSecurity.IsProtected)
        {
            if (_elevationContext.CanElevateSameUser) return true;
            // Broker plans remain bound to one SID. A different administrator must rescan.
            await OpenAdministratorWindowAsync();
            return false;
        }
        MessageBox.Show(this,
            _installationSecurity.Message + "。这不是缺少管理员授权，提权也不会解除此限制。请使用安装包修复安装，再点击“重新检查”。扫描与报告导出仍可使用。",
            "安装环境未通过检查",
            MessageBoxButton.OK,
            MessageBoxImage.Warning);
        return false;
    }

    private void ApplyInstallationSecurityStatus()
    {
        InstallationSecurityText.Text = _installationSecurity.IsProtected
            ? (_elevationContext.IsElevated ? "安装检查通过，当前为管理员窗口。" : "安装检查通过，当前为普通权限窗口。")
            : $"安装检查未通过：{_installationSecurity.Message}。";
        ElevationHintText.Text = !_installationSecurity.IsProtected
            ? "提权不能修复安装环境，请用安装包修复后重新检查。扫描与导出仍可用。"
            : _elevationContext.IsElevated
                ? "可扫描并处置，执行前仍会请你核对并确认，不会自动清除。"
                : _elevationContext.CanElevateSameUser
                    ? "扫描无需提权，处置时会自动请求 Windows 授权。也可先打开管理员窗口。"
                    : "扫描无需提权，处置需先打开管理员窗口，输入管理员凭据并重新扫描。";
        ElevateButton.Content = _elevationContext.IsElevated ? "已是管理员窗口" : "打开管理员窗口";
        ElevateButton.ToolTip = "通过 Windows UAC 打开独立窗口，原窗口与报告会保留，新窗口需重新扫描。";
        RefreshInstallationButton.ToolTip = "重新检查安装目录、组件完整性与当前权限，不会更改扫描结果。";
        InstallationSecurityText.Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString(
            _installationSecurity.IsProtected ? "#027A48" : "#B54708"));
        string tooltip = _installationSecurity.IsProtected ? "管理员处置可用" : _installationSecurity.Message;
        RemediateButton.ToolTip = tooltip;
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
        if (!_busy) await RefreshInstallationSecurityAsync();
    }

    private async void Elevate_Click(object sender, RoutedEventArgs e)
    {
        if (!_busy) await OpenAdministratorWindowAsync();
    }

    private async Task OpenAdministratorWindowAsync()
    {
        if (_elevationContext.IsElevated) return;
        if (MessageBox.Show(this,
                "即将请求 Windows 管理员授权，并打开一个独立窗口。原窗口和扫描结果会保留，取消授权不会丢失结果。\n\n请在新窗口重新扫描，再确认处置。若 Windows 要求输入另一管理员账户的凭据，请确认新扫描包含原用户的 Steam 与工坊目录。没有管理员凭据时仍可扫描和导出报告。继续吗？",
                "打开管理员窗口", MessageBoxButton.OKCancel, MessageBoxImage.Information) != MessageBoxResult.OK) return;
        SetBusy(true);
        try
        {
            ElevationOutcome outcome = await Task.Run(() => new ElevationService().OpenAdministratorWindow());
            FooterText.Text = outcome == ElevationOutcome.Cancelled
                ? "已取消管理员授权，原窗口和扫描结果均已保留。"
                : "已请求打开管理员窗口，请确认新窗口显示管理员状态后重新扫描。此窗口仍保留原报告。";
        }
        catch (Exception ex)
        {
            MessageBox.Show(this, $"未能打开管理员窗口：{ex.Message}\n\n原窗口和扫描结果均已保留。",
                "管理员窗口未打开", MessageBoxButton.OK, MessageBoxImage.Warning);
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
