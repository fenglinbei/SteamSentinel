using SteamSentinel.Core.Models;
using SteamSentinel.Core.Remediation;
using SteamSentinel.Core.Reporting;
using SteamSentinel.Core.Steam;
using SteamSentinel.Core.Utilities;

namespace SteamSentinel.App;

public partial class MainWindow
{
    private void DisplayRelatedComponentDiagnostics(RelatedComponentDiagnosticReport? diagnostic)
    {
        if (RelatedComponentsDetailsText is null) return;
        if (diagnostic is null)
        {
            RelatedComponentsStatusText.Text = "尚无组件关联记录";
            RelatedComponentsDetailsText.Text = "正常扫描完成关联检查后，这里显示来源、宿主身份、候选原因、受限内容检查与各轮预算。关联记录不会自行生成处理权限。";
            return;
        }
        RelatedComponentsStatusText.Text = RelatedComponentReportPresentation.Summary(diagnostic);
        RelatedComponentsDetailsText.Text = RelatedComponentReportPresentation.Describe(diagnostic);
        RelatedComponentsDetailsText.ScrollToHome();
    }

    // Review only existing, local, exact files. A relation, task name, command or URL
    // cannot itself become a file target or cause the UI to parse untrusted content.
    private List<string> GetRelatedFindingReviewTargets(Finding finding)
    {
        IEnumerable<string> targets = FindingReviewTargets.Get(finding);
        if (_lastReport?.RelatedComponentDiagnostics is { } diagnostic)
        {
            HashSet<string> ids = finding.AssociationObservationIds.ToHashSet(StringComparer.Ordinal);
            targets = targets.Concat(diagnostic.Candidates.Where(candidate => ids.Contains(candidate.Id)).Select(candidate => candidate.Path));
        }
        string[] excluded = [Environment.GetFolderPath(Environment.SpecialFolder.Windows), AppContext.BaseDirectory,
            AppPaths.MachineStateRoot, AppPaths.UserStateRoot, AppPaths.TemporaryRoot, AppPaths.WorkerTemporaryRoot];
        return targets.Where(path => ContentDiscovery.IsLocalSafePath(path) &&
                !excluded.Any(root => !string.IsNullOrWhiteSpace(root) && ContentDiscovery.IsWithin(path, root)) && File.Exists(path))
            .Select(Path.GetFullPath).Distinct(StringComparer.OrdinalIgnoreCase).Take(32).ToList();
    }
}
