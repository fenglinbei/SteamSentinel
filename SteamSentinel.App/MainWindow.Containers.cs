using System.Windows;
using System.Windows.Controls;
using Microsoft.Win32;
using SteamSentinel.Core.Models;
using SteamSentinel.Core.Reporting;
using SteamSentinel.Core.Steam;
using SteamSentinel.Core.Utilities;

namespace SteamSentinel.App;

public partial class MainWindow
{
    private ContainerScanReport? _containerReport;

    private void DisplayContainers(ContainerScanReport? report)
    {
        if (ContainerNodesComboBox is null) return;
        Guid? selected = (ContainerNodesComboBox.SelectedItem as ContainerNodeItem)?.Node.NodeId;
        _containerReport = report;
        ContainerStatusText.Text = ContainerReportPresentation.Summary(report);
        ContainerTab.Header = report?.Nodes.Count > 0 ? DisplayText.Format("Ui.Containers.DisplayContainers.01", (report.Nodes.Count)) : DisplayText.Get("Ui.Containers.DisplayContainers.02");
        ContainerNodesComboBox.ItemsSource = report?.Nodes.Select(node => new ContainerNodeItem(node)).ToArray() ?? [];
        if (report?.Nodes.Count > 0)
            ContainerNodesComboBox.SelectedItem = ContainerNodesComboBox.Items.Cast<ContainerNodeItem>().FirstOrDefault(item => item.Node.NodeId == selected) ?? ContainerNodesComboBox.Items[0];
        else
        {
            ContainerDetailsText.Text = report is null
                ? DisplayText.Get("Ui.Containers.DisplayContainers.03")
                : ContainerReportPresentation.Describe(report);
        }
        UpdateContainerActions();
    }

    private void ContainerNodes_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (ContainerDetailsText is null) return;
        if (_containerReport is { } report && ContainerNodesComboBox.SelectedItem is ContainerNodeItem item)
        {
            ContainerDetailsText.Text = ContainerReportPresentation.Describe(report, item.Node.NodeId);
            ContainerDetailsText.ScrollToHome();
        }
        UpdateContainerActions();
    }

    private void UpdateContainerActions()
    {
        if (ContainerRecheckButton is null) return;
        bool available = !_busy && _lastReport is not null && _containerReport is not null &&
            ContainerNodesComboBox.SelectedItem is ContainerNodeItem item && GetContainerReviewTargets(_containerReport, item.Node).Count > 0;
        ContainerRecheckButton.IsEnabled = available;
        ContainerSupplementButton.IsEnabled = available;
        ContainerRecoveryButton.IsEnabled = available;
        ContainerNodesComboBox.IsEnabled = !_busy && _containerReport?.Nodes.Count > 0;
        ContainerFullDetailsButton.IsEnabled = !_busy && _containerReport is not null;
        ContainerExportButton.IsEnabled = !_busy && _lastReport is not null;
    }

    private void ContainerFullDetails_Click(object sender, RoutedEventArgs e)
    {
        if (_containerReport is null) return;
        new Dialogs.TextDetailsWindow(DisplayText.Get("Ui.Containers.ContainerFullDetails_Click.01"), ContainerReportPresentation.Describe(_containerReport)) { Owner = this }.ShowDialog();
    }

    private async void ContainerRecheck_Click(object sender, RoutedEventArgs e)
    {
        if (_busy || _containerReport is null || ContainerNodesComboBox.SelectedItem is not ContainerNodeItem selected) return;
        await RunContainerReviewAsync(GetContainerReviewTargets(_containerReport, selected.Node), [], null);
    }

    private async void ContainerSupplement_Click(object sender, RoutedEventArgs e)
    {
        if (_busy || _containerReport is null || ContainerNodesComboBox.SelectedItem is not ContainerNodeItem selected) return;
        List<string> targets = GetContainerReviewTargets(_containerReport, selected.Node);
        if (targets.Count == 0) return;
        OpenFolderDialog dialog = new() { Title = DisplayText.Get("Ui.Containers.ContainerSupplement_Click.01"), Multiselect = false };
        if (dialog.ShowDialog(this) != true) return;
        if (!TryContainerDirectory(dialog.FolderName, recovery: false, targets, out string directory, out string reason))
        { MessageBox.Show(this, reason, DisplayText.Get("Ui.Containers.ContainerSupplement_Click.02"), MessageBoxButton.OK, MessageBoxImage.Information); return; }
        await RunContainerReviewAsync(targets, [directory], null);
    }

    private async void ContainerRecovery_Click(object sender, RoutedEventArgs e)
    {
        if (_busy || _containerReport is null || ContainerNodesComboBox.SelectedItem is not ContainerNodeItem selected) return;
        List<string> targets = GetContainerReviewTargets(_containerReport, selected.Node);
        if (targets.Count == 0) return;
        OpenFolderDialog dialog = new()
        {
            Title = DisplayText.Get("Ui.Containers.ContainerRecovery_Click.01"),
            Multiselect = false
        };
        if (dialog.ShowDialog(this) != true) return;
        if (!TryContainerDirectory(dialog.FolderName, recovery: true, targets, out string directory, out string reason))
        { MessageBox.Show(this, reason, DisplayText.Get("Ui.Containers.ContainerRecovery_Click.02"), MessageBoxButton.OK, MessageBoxImage.Information); return; }
        await RunContainerReviewAsync(targets, [], directory);
    }

    // The optional runner is used by harmless dispatcher tests. Production always goes
    // through ArchiveWorkerClient; no parsing or recovery writes occur in the WPF process.
    internal async Task RunContainerReviewAsync(IReadOnlyList<string> targets, IReadOnlyList<string> supplementalDirectories,
        string? recoveryDirectory, Func<ScanOptions, IProgress<ScanProgress>, CancellationToken, Task<ScanReport>>? runner = null)
    {
        Dispatcher.VerifyAccess();
        if (_busy || targets.Count == 0) return;
        ScanOptions options = BuildContainerReviewOptions(_lastReport?.ContentScanSettings, targets, supplementalDirectories,
            recoveryDirectory, AmsiCheckBox.IsChecked == true, DeepSignatureCheckBox.IsChecked == true);
        ArchiveCheckBox.IsChecked = true;
        await StartScanAsync(ScanMode.Custom, options.CustomRoots, suppliedContentOptions: options, contentRunner: runner);
        ResultTabs.SelectedItem = ContainerTab;
        if (_lastReport is not null)
            FooterText.Text = recoveryDirectory is null
                ? DisplayText.Get("Ui.Containers.RunContainerReviewAsync.01")
                : DisplayText.Get("Ui.Containers.RunContainerReviewAsync.02");
    }

    internal static ScanOptions BuildContainerReviewOptions(ScanOptions? previous, IReadOnlyList<string> targets,
        IReadOnlyList<string> supplementalDirectories, string? recoveryDirectory, bool useAmsi, bool signatures)
    {
        // Preserve explicit deep limits, but upgrade a quick scan to the full default
        // budget. Recovery output is a per-invocation argument, never copied from history.
        bool deep = previous is { Mode: not ScanMode.Quick };
        return new()
        {
            Mode = ScanMode.Custom,
            IncludeSystem = false,
            IncludeSteam = false,
            IncludeWorkshop = false,
            IncludeRelatedContent = false,
            IncludeDownloadLocations = false,
            IncludeExecutionHistory = false,
            CustomRoots = targets.Distinct(StringComparer.OrdinalIgnoreCase).ToList(),
            InspectArchives = true,
            UseAmsi = ScanEnhancements.AmsiAvailable && useAmsi,
            HashEveryFile = true,
            MaximumContentBytes = long.MaxValue,
            MaximumArchiveDepth = deep ? previous!.MaximumArchiveDepth : 12,
            MaximumEntryBytes = deep ? previous!.MaximumEntryBytes : 8L * 1024 * 1024 * 1024,
            MaximumExpandedBytes = deep ? previous!.MaximumExpandedBytes : 32L * 1024 * 1024 * 1024,
            MaximumArchiveEntries = previous?.MaximumArchiveEntries ?? 20_000,
            MaximumCompressionRatio = previous?.MaximumCompressionRatio ?? 500,
            MaximumFiles = previous?.MaximumFiles ?? 200_000,
            ContainerLimits = deep ? previous!.ContainerLimits : null,
            InspectDeepSignatures = signatures,
            SupplementalVolumeDirectories = supplementalDirectories.Distinct(StringComparer.OrdinalIgnoreCase).ToList(),
            RecoveryOutputDirectory = recoveryDirectory,
            ExcludedRoots = [AppPaths.MachineStateRoot, AppPaths.TemporaryRoot, AppPaths.WorkerTemporaryRoot, AppContext.BaseDirectory]
        };
    }

    internal static List<string> GetContainerReviewTargets(ContainerScanReport report, ContainerScanNode selected)
    {
        IReadOnlyList<ContainerScanNode> chain = ContainerReportPresentation.Ancestors(report, selected);
        IEnumerable<string> paths = chain.Take(1).Select(node => node.OriginalTarget)
            .Concat(chain.SelectMany(node => node.Volumes.Where(volume => !volume.IsTemporary).Select(volume => volume.OriginalPath)));
        string[] excluded = [AppContext.BaseDirectory, AppPaths.MachineStateRoot, AppPaths.UserStateRoot, AppPaths.TemporaryRoot, AppPaths.WorkerTemporaryRoot];
        return paths.Where(path => Path.IsPathFullyQualified(path) && ContentDiscovery.IsLocalSafePath(path) && File.Exists(path) &&
                !excluded.Any(root => ContentDiscovery.IsWithin(path, root)))
            .Select(Path.GetFullPath).Distinct(StringComparer.OrdinalIgnoreCase).Take(128).ToList();
    }

    internal static bool TryContainerDirectory(string input, bool recovery, IReadOnlyList<string> sources, out string directory, out string reason)
    {
        directory = string.Empty; reason = DisplayText.Get("Ui.Containers.TryContainerDirectory.01");
        if (!Path.IsPathFullyQualified(input) || !ContentDiscovery.IsLocalSafePath(input) || !Directory.Exists(input)) return false;
        string full = Path.GetFullPath(input);
        string[] protectedRoots = [AppContext.BaseDirectory, AppPaths.MachineStateRoot, AppPaths.UserStateRoot, AppPaths.TemporaryRoot,
            AppPaths.WorkerTemporaryRoot, Environment.GetFolderPath(Environment.SpecialFolder.Windows)];
        if (protectedRoots.Any(root => root.Length > 0 && ContentDiscovery.IsWithin(full, root)))
        { reason = DisplayText.Get("Ui.Containers.TryContainerDirectory.02"); return false; }
        if (recovery && sources.Any(source => ContentDiscovery.IsWithin(source, full)))
        { reason = DisplayText.Get("Ui.Containers.TryContainerDirectory.03"); return false; }
        directory = full; reason = string.Empty; return true;
    }

    private sealed record ContainerNodeItem(ContainerScanNode Node)
    {
        public string Label => SteamSentinel.Core.Inspection.ScriptSignals.RedactSecrets(new string(' ', Math.Clamp(Node.Depth, 0, 32) * 2) +
            $"{Node.Format} · {ContainerReportPresentation.StatusLabel(Node.Overall)} · {Node.DisplayPath}");
    }
}
