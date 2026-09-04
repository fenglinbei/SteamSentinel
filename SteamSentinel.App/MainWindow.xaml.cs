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
    private bool _busy;

    public MainWindow()
    {
        InitializeComponent();
        Findings = [];
        QuarantineItems = [];
        DataContext = this;
        SetBusy(true);
        HeaderDetailText.Text = $"规则 {_coordinator.Rules.Version}";
        Loaded += MainWindow_Loaded;
        Closing += (_, _) => _scanCancellation?.Cancel();
    }

    public ObservableCollection<FindingItemViewModel> Findings { get; }
    public ObservableCollection<QuarantineItemViewModel> QuarantineItems { get; }

    private async void MainWindow_Loaded(object sender, RoutedEventArgs e)
    {
        await RefreshInstallationSecurityAsync();
        if (Application.Current is App { AdministratorWindowRequested: true })
            FooterText.Text = _elevationContext.IsElevated
                ? "这是新的管理员窗口，请重新扫描，再核对目标并处置。若使用了另一账户，请确认扫描范围包含原用户的 Steam 与工坊目录。"
                : "新窗口未取得管理员权限，请重新授权，扫描与报告导出仍可使用。";
        await RefreshQuarantineItemsAsync();
    }

    private async void QuickScan_Click(object sender, RoutedEventArgs e) =>
        await StartScanAsync(ScanMode.Quick, []);

    private async void FullScan_Click(object sender, RoutedEventArgs e) =>
        await StartScanAsync(ScanMode.Full, []);

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

    private void CancelScan_Click(object sender, RoutedEventArgs e) => _scanCancellation?.Cancel();

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

    private async Task StartScanAsync(ScanMode mode, List<string> customRoots)
    {
        if (_busy) return;
        SetBusy(true);
        Findings.Clear();
        _lastReport = null;
        HeaderStatusText.Text = "正在扫描";
        HeaderDetailText.Text = mode switch
        {
            ScanMode.Quick => "快速系统与工坊扫描",
            ScanMode.Full => "完整哈希与递归内容扫描",
            _ => "自定义内容扫描"
        };
        FindingCountText.Text = "0 项发现";
        ScanProgressBar.IsIndeterminate = true;
        _scanCancellation = new CancellationTokenSource();
        CancellationToken token = _scanCancellation.Token;
        Progress<ScanProgress> progress = new(UpdateProgress);
        ScanReport? systemReport = null;
        bool contentAttempted = false;

        try
        {
            if (mode != ScanMode.Custom)
            {
                ScanOptions systemOptions = new()
                {
                    Mode = mode,
                    IncludeSystem = true,
                    IncludeSteam = true,
                    IncludeWorkshop = false,
                    InspectArchives = false,
                    UseAmsi = false,
                    ExcludedRoots = [AppPaths.MachineStateRoot, AppPaths.TemporaryRoot, AppPaths.WorkerTemporaryRoot]
                };
                systemReport = await Task.Run(
                    () => _coordinator.RunAsync(systemOptions, null, progress, token), token);
            }

            ScanOptions contentOptions = new()
            {
                Mode = mode,
                IncludeSystem = false,
                IncludeSteam = false,
                IncludeWorkshop = mode != ScanMode.Custom,
                InspectArchives = ArchiveCheckBox.IsChecked == true,
                UseAmsi = AmsiCheckBox.IsChecked == true,
                HashEveryFile = mode != ScanMode.Quick,
                CustomRoots = customRoots,
                ExcludedRoots = [AppPaths.MachineStateRoot, AppPaths.TemporaryRoot, AppPaths.WorkerTemporaryRoot, AppContext.BaseDirectory]
            };

            contentAttempted = true;
            ScanReport contentReport = await _workerClient.RunAsync(
                contentOptions, RequestPasswordAsync, progress, token);
            _lastReport = systemReport is null ? contentReport : ScanReportMerger.Merge(systemReport, contentReport);
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
            MessageBox.Show(this, ex.Message, "SteamSentinel 扫描失败", MessageBoxButton.OK, MessageBoxImage.Error);
        }
        finally
        {
            ScanProgressBar.IsIndeterminate = false;
            ScanProgressBar.Value = 0;
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
        HeaderDetailText.Text = systemReport is null
            ? "内容检查未完成，可导出报告查看启动阶段与错误"
            : "系统检查结果已保留，内容检查未完成，可导出报告查看错误";
        ProgressStageText.Text = cancelled ? "扫描已取消" : "内容检查未完成";
        ProgressItemText.Text = "已保留可用结果，请查看覆盖说明，或导出报告反馈。";
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
        ProgressStageText.Text = progress.Stage + " · " + progress.Message;
        ProgressItemText.Text = progress.CurrentItem;
        FooterText.Text = $"已处理 {progress.Completed:N0} 项 · {progress.CurrentItem}";
    }

    private void PopulateFindings(ScanReport report)
    {
        Findings.Clear();
        foreach (Finding finding in report.Findings) Findings.Add(new FindingItemViewModel(finding));
        FindingCountText.Text = $"{Findings.Count:N0} 项发现";
        ExportButton.IsEnabled = true;
        RemediateButton.IsEnabled = _installationSecurity.IsProtected && Findings.Any(item => item.CanSelect);
        if (Findings.Count > 0) FindingsGrid.SelectedIndex = 0;
    }

    private void UpdateSummary(ScanReport report)
    {
        bool confirmed = report.Findings.Any(finding => finding.IsKnownMalware);
        bool suspicious = report.Findings.Any(finding => finding.Severity >= FindingSeverity.High);
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
        else if (report.Coverage == ScanCoverage.Partial)
        {
            HeaderStatusText.Text = "扫描不完整";
            HeaderDetailText.Text = "存在加密、权限或格式覆盖限制";
        }
        else
        {
            HeaderStatusText.Text = "未发现已知威胁";
            HeaderDetailText.Text = "不代表对未知漏洞的绝对保证";
        }

        HeaderDetailText.Text += report.Coverage == ScanCoverage.Complete
            ? "，已完成支持范围内的检查。" : "，仍有内容未完整扫描，请查看覆盖说明。";
        FooterText.Text = $"文件 {report.Metrics.FilesVisited:N0} · 工坊 {report.Metrics.WorkshopItemsVisited:N0} · 压缩条目 {report.Metrics.ArchiveEntriesVisited:N0} · 覆盖 {ReportExporter.CoverageLabel(report.Coverage)}";
    }

    private void FindingsGrid_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        FindingItemViewModel? item = FindingsGrid.SelectedItem as FindingItemViewModel;
        DetailDescriptionText.Text = item?.Description ?? string.Empty;
        DetailEvidenceText.Text = item?.Evidence ?? string.Empty;
        DetailHashText.Text = item is null ? string.Empty : $"命中内容：{item.Sha256}\n隔离目标：{item.Finding.TargetSha256 ?? "不适用"}\n内容位置：{item.Finding.ContentPath ?? item.Target}";
        DetailWorkshopText.Text = item?.WorkshopId ?? string.Empty;
    }

    private void SelectAll_Click(object sender, RoutedEventArgs e)
    {
        foreach (FindingItemViewModel item in Findings.Where(item => item.CanSelect)) item.IsSelected = true;
    }

    private void ClearSelection_Click(object sender, RoutedEventArgs e)
    {
        foreach (FindingItemViewModel item in Findings) item.IsSelected = false;
    }

    private async void Remediate_Click(object sender, RoutedEventArgs e)
    {
        if (_busy) return;
        if (!await EnsureRemediationAvailableAsync()) return;
        List<Finding> selected = Findings.Where(item => item.IsSelected && item.CanSelect).Select(item => item.Finding).ToList();
        if (selected.Count == 0)
        {
            MessageBox.Show(this, "请先勾选至少一项可处置发现。", "SteamSentinel", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }
        if (selected.Any(finding => finding.Category == FindingCategory.Steam) && IsSteamRunning())
        {
            MessageBox.Show(this,
                "所选动作包含 Steam 客户端恢复。请先从 Steam 菜单完整退出，并确认 steam.exe 与 steamwebhelper.exe 已结束，再重新点击处置。这样可以避免占用文件导致只完成部分隔离。",
                "请先退出 Steam",
                MessageBoxButton.OK,
                MessageBoxImage.Information);
            return;
        }

        try
        {
            SetBusy(true);
            RemediationPlanBuilder builder = new(_coordinator.Rules);
            RemediationPlan plan = await builder.BuildAsync(selected, DomainBlockCheckBox.IsChecked == true);
            if (plan.Actions.Count == 0)
            {
                MessageBox.Show(this, "所选发现没有可执行的安全动作。", "SteamSentinel", MessageBoxButton.OK, MessageBoxImage.Information);
                return;
            }
            RemediationPreviewWindow preview = new(plan) { Owner = this };
            if (preview.ShowDialog() != true) return;
            HeaderStatusText.Text = "等待管理员处置";
            RemediationRunResult result = await _remediationClient.ExecuteAsync(plan);
            IEnumerable<string> actionDetails = result.Actions.Select(action =>
                $"{(action.Success ? "成功" : "失败")} · {ReportExporter.ActionLabel(action.Type)} · {action.Message}");
            string details = string.Join(Environment.NewLine, actionDetails.Concat(result.Errors.Select(error => "错误 · " + error)));
            bool steamRepairPrepared = result.Success &&
                                       selected.Any(finding => finding.Category == FindingCategory.Steam) &&
                                       result.Actions.Any(action => action.Success &&
                                           action.Type is RemediationActionType.QuarantineFile or RemediationActionType.QuarantineDirectory);
            if (steamRepairPrepared)
            {
                details += Environment.NewLine + Environment.NewLine +
                           "Steam 恢复准备已完成：异常前端文件或禁更配置已移入隔离区。现在请从原快捷方式重新启动 Steam，让官方客户端补全缺失组件。若未自动补全，请使用 Steam 官方安装包覆盖安装。";
            }
            MessageBox.Show(this, details, result.Success ? "处置完成" : "处置部分失败",
                MessageBoxButton.OK, result.Success ? MessageBoxImage.Information : MessageBoxImage.Warning);
            HeaderStatusText.Text = result.Success ? "处置完成，建议复扫" : "处置部分失败";
            HeaderDetailText.Text = steamRepairPrepared
                ? "请重新启动 Steam 完成官方组件补全，随后再次扫描"
                : result.Success ? "重启后再次扫描，再决定永久删除" : "请查看动作结果，不要直接删除隔离证据";
            await RefreshQuarantineItemsAsync();
        }
        catch (OperationCanceledException)
        {
            HeaderStatusText.Text = "处置已取消";
        }
        catch (Exception ex)
        {
            MessageBox.Show(this, ex.Message, "处置失败", MessageBoxButton.OK, MessageBoxImage.Error);
        }
        finally
        {
            SetBusy(false);
        }
    }

    private async void Export_Click(object sender, RoutedEventArgs e)
    {
        if (_lastReport is null) return;
        SaveFileDialog dialog = new()
        {
            Title = "导出脱敏扫描报告",
            Filter = "Markdown 报告 (*.md)|*.md|JSON 证据 (*.json)|*.json",
            FileName = $"SteamSentinel-{_lastReport.ScanId:N}.md"
        };
        if (dialog.ShowDialog(this) != true) return;
        if (Path.GetExtension(dialog.FileName).Equals(".json", StringComparison.OrdinalIgnoreCase))
            await ReportExporter.ExportJsonAsync(_lastReport, dialog.FileName);
        else
            await ReportExporter.ExportMarkdownAsync(_lastReport, dialog.FileName);
        FooterText.Text = $"报告已导出：{dialog.FileName}";
    }

    private async void RefreshQuarantine_Click(object sender, RoutedEventArgs e) =>
        await RefreshQuarantineItemsAsync();

    private async Task RefreshQuarantineItemsAsync()
    {
        QuarantineItems.Clear();
        if (!Directory.Exists(AppPaths.QuarantineRoot)) return;

        string[] manifestPaths;
        try
        {
            manifestPaths = Directory.GetFiles(AppPaths.QuarantineRoot, "manifest.json", SearchOption.AllDirectories);
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
            RemediationRunResult result = await _remediationClient.ExecuteAsync(plan);
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
            SetBusy(false);
        }
    }

    private void SetBusy(bool busy)
    {
        _busy = busy;
        QuickScanButton.IsEnabled = !busy;
        FullScanButton.IsEnabled = !busy;
        FileScanButton.IsEnabled = !busy;
        FolderScanButton.IsEnabled = !busy;
        RetryPasswordsButton.IsEnabled = !busy && _lastReport is not null && GetPasswordRetryTargets(_lastReport).Count > 0;
        CancelScanButton.IsEnabled = busy && _scanCancellation is not null;
        RemediateButton.IsEnabled = !busy && _installationSecurity.IsProtected && Findings.Any(item => item.CanSelect);
        ExportButton.IsEnabled = !busy && _lastReport is not null;
        RollbackButton.IsEnabled = !busy && _installationSecurity.IsProtected;
        DeleteIncidentButton.IsEnabled = !busy && _installationSecurity.IsProtected;
        ElevateButton.IsEnabled = !busy && _installationSecurity.IsProtected && !_elevationContext.IsElevated;
        RefreshInstallationButton.IsEnabled = !busy;
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
