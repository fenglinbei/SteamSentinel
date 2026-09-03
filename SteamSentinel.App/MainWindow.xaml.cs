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
    private readonly InstallationSecurityStatus _installationSecurity;
    private CancellationTokenSource? _scanCancellation;
    private ScanReport? _lastReport;
    private bool _busy;

    public MainWindow()
    {
        InitializeComponent();
        Findings = [];
        QuarantineItems = [];
        DataContext = this;
        _installationSecurity = InstallationSecurity.Evaluate();
        HeaderDetailText.Text = $"规则 {_coordinator.Rules.Version}";
        Loaded += MainWindow_Loaded;
        Closing += (_, _) => _scanCancellation?.Cancel();
    }

    public ObservableCollection<FindingItemViewModel> Findings { get; }
    public ObservableCollection<QuarantineItemViewModel> QuarantineItems { get; }

    private async void MainWindow_Loaded(object sender, RoutedEventArgs e)
    {
        ApplyInstallationSecurityStatus();
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

        try
        {
            ScanReport? systemReport = null;
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

            ScanReport contentReport = await _workerClient.RunAsync(
                contentOptions, RequestPasswordAsync, progress, token);
            _lastReport = systemReport is null ? contentReport : ScanReportMerger.Merge(systemReport, contentReport);
            PopulateFindings(_lastReport);
            UpdateSummary(_lastReport);
        }
        catch (OperationCanceledException)
        {
            HeaderStatusText.Text = "扫描已取消";
            HeaderDetailText.Text = "尚未形成可用于处置的完整结果";
            FooterText.Text = "扫描已取消，加密包密码不会保留。";
        }
        catch (Exception ex)
        {
            HeaderStatusText.Text = "扫描失败";
            HeaderDetailText.Text = ex.Message;
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
                accepted && dialog.ReuseForSession);
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
        bool confirmed = report.Findings.Any(finding => finding.IsKnownMalware && finding.Severity == FindingSeverity.Critical);
        bool suspicious = report.Findings.Any(finding => finding.Severity >= FindingSeverity.High);
        if (confirmed)
        {
            HeaderStatusText.Text = "已确认威胁";
            HeaderDetailText.Text = "请核对预选动作并进行隔离";
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

        FooterText.Text = $"文件 {report.Metrics.FilesVisited:N0} · 工坊 {report.Metrics.WorkshopItemsVisited:N0} · 压缩条目 {report.Metrics.ArchiveEntriesVisited:N0} · 覆盖 {ReportExporter.CoverageLabel(report.Coverage)}";
    }

    private void FindingsGrid_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        FindingItemViewModel? item = FindingsGrid.SelectedItem as FindingItemViewModel;
        DetailDescriptionText.Text = item?.Description ?? string.Empty;
        DetailEvidenceText.Text = item?.Evidence ?? string.Empty;
        DetailHashText.Text = item?.Sha256 ?? string.Empty;
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
        if (!EnsureRemediationAvailable()) return;
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
        if (!EnsureRemediationAvailable()) return;
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
        CancelScanButton.IsEnabled = busy && _scanCancellation is not null;
        RemediateButton.IsEnabled = !busy && _installationSecurity.IsProtected && Findings.Any(item => item.CanSelect);
        ExportButton.IsEnabled = !busy && _lastReport is not null;
        RollbackButton.IsEnabled = !busy && _installationSecurity.IsProtected;
        DeleteIncidentButton.IsEnabled = !busy && _installationSecurity.IsProtected;
    }

    private bool EnsureRemediationAvailable()
    {
        InstallationSecurityStatus current = InstallationSecurity.Evaluate();
        if (current.IsProtected) return true;
        MessageBox.Show(this,
            current.Message + "。请使用 v0.1.4 安装包安装后再执行隔离、恢复或永久删除，扫描与报告导出仍可使用。",
            "管理员处置未启用",
            MessageBoxButton.OK,
            MessageBoxImage.Warning);
        return false;
    }

    private void ApplyInstallationSecurityStatus()
    {
        InstallationSecurityText.Text = _installationSecurity.IsProtected
            ? "处置环境：受保护安装与组件完整性校验已通过，可使用隔离、恢复和永久删除。"
            : $"处置环境：{_installationSecurity.Message}。请使用安装包启用隔离与恢复。";
        InstallationSecurityText.Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString(
            _installationSecurity.IsProtected ? "#027A48" : "#B54708"));
        string tooltip = _installationSecurity.IsProtected ? "管理员处置可用" : _installationSecurity.Message;
        RemediateButton.ToolTip = tooltip;
        RollbackButton.ToolTip = tooltip;
        DeleteIncidentButton.ToolTip = tooltip;
        SetBusy(_busy);
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
