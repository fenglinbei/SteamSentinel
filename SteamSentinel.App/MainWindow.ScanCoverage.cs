using System.IO;
using SteamSentinel.Core.Models;

namespace SteamSentinel.App;

public partial class MainWindow
{
    internal static bool ExplicitContentRootsUnchecked(ScanReport report)
    {
        // Zero files alone can mean a successfully inspected empty directory. Require
        // an incomplete root summary for every explicit target; never infer from prose.
        // The merged report may contain files read by system or other content checks;
        // only the per-root counters describe whether these selected paths were read.
        if (report.Coverage == ScanCoverage.Complete || report.ContentScanSettings is not { CustomRoots.Count: > 0 } settings)
            return false;
        try
        {
            static string Normalize(string path) => Path.TrimEndingDirectorySeparator(Path.GetFullPath(path));
            var summaries = report.RootSummaries.ToLookup(summary => Normalize(summary.Path), StringComparer.OrdinalIgnoreCase);
            return settings.CustomRoots.All(path =>
            {
                ScanRootSummary[] roots = summaries[Normalize(path)].ToArray();
                return roots.Length > 0 && roots.All(root => root.Coverage is ScanCoverage.Partial or ScanCoverage.Skipped && root.FilesVisited == 0);
            });
        }
        catch (Exception ex) when (ex is ArgumentException or NotSupportedException or PathTooLongException)
        {
            return false;
        }
    }
}
