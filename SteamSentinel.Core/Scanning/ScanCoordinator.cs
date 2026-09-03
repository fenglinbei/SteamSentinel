using SteamSentinel.Core.Models;
using SteamSentinel.Core.Rules;
using SteamSentinel.Core.Steam;
using SteamSentinel.Core.Utilities;

namespace SteamSentinel.Core.Scanning;

public sealed class ScanCoordinator
{
    private readonly RuleSet _rules;

    public ScanCoordinator(RuleSet? rules = null)
    {
        _rules = rules ?? RuleLoader.LoadEmbedded();
    }

    public RuleSet Rules => _rules;

    public async Task<ScanReport> RunAsync(
        ScanOptions options,
        IArchivePasswordProvider? passwordProvider = null,
        IProgress<ScanProgress>? progress = null,
        CancellationToken cancellationToken = default)
    {
        passwordProvider ??= new NullPasswordProvider();
        ScanReport report = new()
        {
            Mode = options.Mode,
            RuleSetVersion = _rules.Version
        };
        report.Roots.AddRange(options.CustomRoots);

        try
        {
            if (options.IncludeSystem)
            {
                SystemScanner systemScanner = new(_rules);
                await systemScanner.ScanAsync(report, options, progress, cancellationToken);
            }

            SteamLayout? layout = null;
            if (options.IncludeSteam || options.IncludeWorkshop)
            {
                progress?.Report(new ScanProgress("Steam 发现", "Steam Library", 0, null, "解析 Steam 多库布局"));
                layout = SteamLocator.Discover();
                foreach (string root in layout.SteamRoots.Concat(layout.LibraryRoots).Concat(layout.WorkshopRoots))
                {
                    if (!report.Roots.Contains(root, StringComparer.OrdinalIgnoreCase)) report.Roots.Add(root);
                }
            }

            if (options.IncludeSteam && layout is not null)
            {
                SteamSecurityScanner steamScanner = new(_rules);
                await steamScanner.ScanAsync(layout, report, cancellationToken);
            }

            using ContentScanner contentScanner = new(_rules);
            HashSet<string> scanned = new(StringComparer.OrdinalIgnoreCase);

            if (options.IncludeWorkshop && layout is not null)
            {
                foreach (string root in layout.WorkshopRoots)
                {
                    IEnumerable<string> projects;
                    try { projects = Directory.EnumerateDirectories(root).ToArray(); }
                    catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
                    {
                        MarkPartial(report, $"无法枚举工坊目录 {root}：{ex.Message}");
                        continue;
                    }

                    foreach (string projectDirectory in projects)
                    {
                        cancellationToken.ThrowIfCancellationRequested();
                        WallpaperProject project = SteamLocator.ReadWallpaperProject(projectDirectory);
                        report.Metrics.WorkshopItemsVisited++;
                        progress?.Report(new ScanProgress("Wallpaper Engine", projectDirectory,
                            report.Metrics.WorkshopItemsVisited, null, project.Title ?? project.WorkshopId));

                        if (project.ParseError is not null)
                        {
                            report.Findings.Add(new Finding
                            {
                                RuleId = "WORKSHOP-PROJECT-METADATA",
                                Category = FindingCategory.WallpaperEngine,
                                Severity = FindingSeverity.Medium,
                                Score = 35,
                                Title = "Wallpaper Engine 项目元数据缺失或损坏",
                                Description = project.ParseError,
                                Target = projectDirectory,
                                Evidence = $"Workshop ID: {project.WorkshopId}",
                                WorkshopId = project.WorkshopId,
                                CanRemediate = false,
                                SuggestedActions = [SuggestedActionKind.ReviewOnly]
                            });
                        }

                        scanned.Add(Path.GetFullPath(projectDirectory));
                        await contentScanner.ScanRootAsync(projectDirectory, report, options, passwordProvider,
                            progress, cancellationToken, project.WorkshopId, project.Type);
                    }
                }

                foreach (string root in layout.WallpaperProjectRoots)
                {
                    if (!Directory.Exists(root)) continue;
                    foreach (string projectDirectory in Directory.EnumerateDirectories(root))
                    {
                        cancellationToken.ThrowIfCancellationRequested();
                        if (!scanned.Add(Path.GetFullPath(projectDirectory))) continue;
                        WallpaperProject project = SteamLocator.ReadWallpaperProject(projectDirectory);
                        string? projectType = Path.GetFileName(projectDirectory).Equals("defaultprojects", StringComparison.OrdinalIgnoreCase)
                            ? "trusted-default"
                            : project.Type;
                        report.Metrics.WorkshopItemsVisited++;
                        await contentScanner.ScanRootAsync(projectDirectory, report, options, passwordProvider,
                            progress, cancellationToken, "local:" + project.WorkshopId, projectType);
                    }
                }
            }

            foreach (string root in options.CustomRoots)
            {
                cancellationToken.ThrowIfCancellationRequested();
                string full;
                try { full = Path.GetFullPath(root); }
                catch
                {
                    MarkPartial(report, $"自定义路径无效：{root}");
                    continue;
                }

                if (!scanned.Add(full)) continue;
                await contentScanner.ScanRootAsync(full, report, options, passwordProvider, progress, cancellationToken);
            }
        }
        catch (OperationCanceledException)
        {
            report.Coverage = ScanCoverage.Partial;
            report.CoverageNotes.Add("扫描被用户取消。");
            throw;
        }
        finally
        {
            report.CompletedAtUtc = DateTimeOffset.UtcNow;
        }

        report.Findings.Sort((left, right) =>
        {
            int severity = right.Severity.CompareTo(left.Severity);
            return severity != 0 ? severity : right.Score.CompareTo(left.Score);
        });
        return report;
    }

    private static void MarkPartial(ScanReport report, string message)
    {
        report.Coverage = ScanCoverage.Partial;
        report.CoverageNotes.Add(message);
    }
}
