using SteamSentinel.Core.Models;
using SteamSentinel.Core.Rules;
using SteamSentinel.Core.Steam;
using SteamSentinel.Core.Utilities;

namespace SteamSentinel.Core.Scanning;

public sealed class ScanCoordinator
{
    private readonly RuleSet _rules;
    private readonly SteamLayout? _layoutOverride;

    public ScanCoordinator(RuleSet? rules = null, SteamLayout? layout = null)
    {
        _rules = rules ?? RuleLoader.LoadEmbedded();
        _layoutOverride = layout;
    }

    public RuleSet Rules => _rules;

    public async Task<ScanReport> RunAsync(
        ScanOptions options,
        IArchivePasswordProvider? passwordProvider = null,
        IProgress<ScanProgress>? progress = null,
        CancellationToken cancellationToken = default,
        Action<ScanReport>? checkpoint = null)
    {
        passwordProvider ??= new NullPasswordProvider();
        ScanReport report = new()
        {
            Mode = options.Mode,
            RuleSetVersion = _rules.Version,
            ContentScanSettings = options
        };
        report.Roots.AddRange(options.CustomRoots);
        if (options.IncludeSystem || options.IncludeSteam)
            report.ScopeNotes.Add("系统阶段：" + (options.IncludeSystem ? "检查相关进程、启动项和系统配置。" : "") +
                (options.IncludeSteam ? "检查 Steam 客户端。" : ""));
        if (options.IncludeWorkshop || options.IncludeRelatedContent || options.IncludeDownloadLocations || options.CustomRoots.Count > 0 || options.RelatedRoots.Count > 0)
        {
            report.ScopeNotes.Add(options.Mode == ScanMode.Quick ? Reporting.CoveragePresentation.QuickScope : Reporting.CoveragePresentation.FullScope);
            report.ScopeNotes.Add(options.Mode == ScanMode.Custom ? "内容阶段只检查所选文件或目录，系统运行状态是否检查以系统阶段说明为准。" :
                "内容阶段工坊范围：" + (options.IncludeWorkshop ? options.WorkshopAppIds.Count == 0 ? "全部已发现的本地工坊" : string.Join("，", options.WorkshopAppIds) : "未额外检查工坊"));
            report.ScopeNotes.Add(options.IncludeDownloadLocations ? "已额外包含下载、桌面与临时目录，资料和样本库也可能进入扫描。" : "未额外扫描下载、桌面与临时目录，已识别的关联落点除外。");
            report.ScopeNotes.Add((options.MaximumContentBytes == long.MaxValue ? "内容阶段不设整轮哈希字节上限，仍保留文件数、内存与解压安全限制" : $"内容阶段文件哈希读取预算：{options.MaximumContentBytes / 1024 / 1024:N0} MiB") +
                (options.Mode == ScanMode.Quick ? "，另为小型启动文件保留最多 128 MiB。" : "。") +
                (options.InspectArchives ? "已开启压缩内容检查。" : "未开启压缩内容检查。"));
        }
        if (options.WorkshopAppIds.Count > 0) MarkPartial(report, "本次只检查所选工坊 AppID：" + string.Join("，", options.WorkshopAppIds) + "，不能作为全部工坊复扫。");

        checkpoint?.Invoke(report);
        string? currentApp = null, currentKind = null;
        int decorated = 0;
        void Checkpoint(ScanReport state)
        {
            foreach (Finding finding in state.Findings.Skip(decorated))
            {
                finding.AppId ??= currentApp;
                finding.SourceKind ??= currentKind;
            }
            decorated = state.Findings.Count;
            checkpoint?.Invoke(state);
        }
        try
        {
            if (options.IncludeSystem)
            {
                SystemScanner systemScanner = new(_rules);
                await systemScanner.ScanAsync(report, options, progress, cancellationToken);
            }

            SteamLayout? layout = null;
            if (options.IncludeSteam || options.IncludeWorkshop || options.IncludeRelatedContent)
            {
                progress?.Report(new ScanProgress("Steam 发现", "Steam Library", 0, null, "解析 Steam 多库布局"));
                layout = _layoutOverride ?? SteamLocator.Discover();
                foreach (string note in layout.DiscoveryNotes) MarkPartial(report, note);
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

            if (options.IncludeSystem && layout is not null)
            {
                progress?.Report(new ScanProgress("关联检查", "启动目标与已加载模块", 0, null, "定位实际落点与恶意组件链"));
                await new RelatedArtifactScanner(_rules).CollectAsync(layout, report, options, cancellationToken);
            }

            using ContentScanner contentScanner = new(_rules);
            decorated = report.Findings.Count;
            contentScanner.Checkpoint = Checkpoint;
            HashSet<string> scanned = new(StringComparer.OrdinalIgnoreCase);

            // Examine evidence-linked locations before media libraries can consume the quick budget.
            IEnumerable<string> priorityRoots = options.RelatedRoots.Concat(
                options.IncludeRelatedContent ? report.CandidateRoots : []);
            foreach (string root in priorityRoots.Distinct(StringComparer.OrdinalIgnoreCase))
            {
                cancellationToken.ThrowIfCancellationRequested();
                if (!ContentDiscovery.IsLocalSafePath(root)) { MarkPartial(report, $"关联路径无法安全读取：{root}"); continue; }
                if (!scanned.Add(Path.GetFullPath(root))) continue;
                report.ContentSources.Add($"优先检查关联落点：{root}");
                await contentScanner.ScanRootAsync(root, report, options, passwordProvider, progress, cancellationToken);
            }

            if (options.IncludeRelatedContent && layout is not null)
            {
                foreach (ContentRoot source in layout.ContentRoots.Where(item => item.Kind is "mod" or "plugin"))
                {
                    if (!scanned.Add(Path.GetFullPath(source.Path))) continue;
                    int first = report.Findings.Count;
                    currentApp = source.AppId; currentKind = source.Kind;
                    report.ContentSources.Add($"{source.Name}，{source.Kind}：{source.Path}");
                    await contentScanner.ScanRootAsync(source.Path, report, options, passwordProvider, progress, cancellationToken,
                        projectType: source.Kind);
                    foreach (Finding finding in report.Findings.Skip(first)) { finding.AppId = source.AppId; finding.SourceKind = source.Kind; }
                }
            }

            if (options.IncludeWorkshop && layout is not null)
            {
                currentApp = null; currentKind = null;
                foreach (string root in layout.WorkshopRoots)
                {
                    string appId = ContentDiscovery.WorkshopAppId(root);
                    if (options.WorkshopAppIds.Count > 0 && !options.WorkshopAppIds.Contains(appId)) continue;
                    List<string> notes = [];
                    IReadOnlyList<string> projects = ContentDiscovery.Children(root, true, notes, 40_000);
                    foreach (string note in notes) MarkPartial(report, note);

                    foreach (string projectDirectory in projects)
                    {
                        cancellationToken.ThrowIfCancellationRequested();
                        string id = Path.GetFileName(projectDirectory);
                        if (!ContentDiscovery.IsNumericId(id)) continue;
                        WallpaperProject project = appId == "431960" ? SteamLocator.ReadWallpaperProject(projectDirectory)
                            : new(projectDirectory, id, null, "workshop", null, null, null);
                        report.Metrics.WorkshopItemsVisited++;
                        progress?.Report(new ScanProgress($"Steam 工坊 {appId}", projectDirectory,
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

                        if (!scanned.Add(Path.GetFullPath(projectDirectory))) continue;
                        currentApp = appId; currentKind = "workshop";
                        int first = report.Findings.Count;
                        report.ContentSources.Add($"工坊 {appId}/{project.WorkshopId}：{projectDirectory}");
                        await contentScanner.ScanRootAsync(projectDirectory, report, options, passwordProvider,
                            progress, cancellationToken, project.WorkshopId, project.Type);
                        foreach (Finding finding in report.Findings.Skip(first)) { finding.AppId = appId; finding.SourceKind = "workshop"; }
                    }
                }

                foreach (string root in layout.WallpaperProjectRoots)
                {
                    currentApp = "431960"; currentKind = "wallpaper-local";
                    if (!Directory.Exists(root)) continue;
                    List<string> notes = [];
                    foreach (string projectDirectory in ContentDiscovery.Children(root, true, notes))
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
                    foreach (string note in notes) MarkPartial(report, note);
                }
            }

            List<string> related = [.. options.RelatedRoots];
            currentApp = null; currentKind = null;
            if (options.IncludeRelatedContent) related.AddRange(report.CandidateRoots);
            if (options.IncludeDownloadLocations)
                related.AddRange(new[] { Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads"),
                    Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory), Path.GetTempPath() });
            foreach (string root in related.Distinct(StringComparer.OrdinalIgnoreCase))
            {
                cancellationToken.ThrowIfCancellationRequested();
                if (!ContentDiscovery.IsLocalSafePath(root)) { MarkPartial(report, $"关联路径无法安全读取：{root}"); continue; }
                if (!scanned.Add(Path.GetFullPath(root))) continue;
                report.ContentSources.Add($"关联落点：{root}");
                await contentScanner.ScanRootAsync(root, report, options, passwordProvider, progress, cancellationToken);
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

        Checkpoint(report);
        // Checkpoints use append-only offsets. The UI sorts the merged report independently.
        if (checkpoint is null) report.Findings.Sort((left, right) =>
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
