using SteamSentinel.Core.Reporting;
using SteamSentinel.Core.Models;
using SteamSentinel.Core.Rules;
using SteamSentinel.Core.Steam;
using SteamSentinel.Core.Utilities;

namespace SteamSentinel.Core.Scanning;

public sealed class ScanCoordinator
{
    private readonly RuleSet _rules;
    private readonly SteamLayout? _layoutOverride;
    private readonly bool _allowRelatedSignatureProbe;

    public ScanCoordinator(RuleSet? rules = null, SteamLayout? layout = null, bool allowRelatedSignatureProbe = false)
    {
        _rules = rules ?? RuleLoader.LoadActive().Rules;
        _layoutOverride = layout;
        _allowRelatedSignatureProbe = allowRelatedSignatureProbe;
    }

    public RuleSet Rules => _rules;

    public Task<ScanReport> RunTrustProxyDiagnosticsAsync(IProgress<ScanProgress>? progress = null,
        CancellationToken cancellationToken = default) => Task.Run(() =>
    {
        ScanReport report = new() { Mode = ScanMode.Custom, RuleSetVersion = _rules.Version, StatusSchemaVersion = ScanExecution.SchemaVersion, ExecutionState = ScanExecutionState.Running };
        new TrustProxyDiagnosticScanner().Collect(report, progress, cancellationToken);
        report.CompletedAtUtc = DateTimeOffset.UtcNow;
        ScanExecution.Set(report, cancellationToken.IsCancellationRequested ? ScanExecutionState.Cancelled : ScanExecutionState.Completed,
            cancellationToken.IsCancellationRequested ? ReasonCodes.UserCancelled : null);
        return report;
    });

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
            StatusSchemaVersion = ScanExecution.SchemaVersion,
            ExecutionState = ScanExecutionState.Running,
            Mode = options.Mode,
            RuleSetVersion = _rules.Version,
            ContentScanSettings = ScanEnhancements.ForExecution(options)
        };
        report.Roots.AddRange(options.CustomRoots);
        ScanResourceSession.Current?.Bind(report);
        if (options.MaximumParallelFiles > 1 || options.AllowResourceDecisions)
        {
            report.ResourceAudit ??= new();
            report.ResourceAudit.Preflight ??= ScanResourcePlanner.Capture(Path.GetTempPath());
        }
        if (options.IncludeSystem || options.IncludeSteam)
            report.AddScopeNote(MessageText.Create("Backend.Core.ScanCoordinator.RunAsync.01") + (options.IncludeSystem ? MessageText.Create("Backend.Core.ScanCoordinator.RunAsync.02") : (MessageText)"") +
                (options.IncludeSteam ? MessageText.Create("Backend.Core.ScanCoordinator.RunAsync.03") : (MessageText)""));
        if (options.IncludeWorkshop || options.IncludeRelatedContent || options.IncludeDownloadLocations || options.CustomRoots.Count > 0 || options.RelatedRoots.Count > 0)
        {
            report.AddScopeNote(options.Mode == ScanMode.Quick ? MessageText.Create("Coverage.QuickScope.01") : MessageText.Create("Coverage.FullScope.01"));
            report.AddScopeNote(options.Mode == ScanMode.Custom ? MessageText.Create("Backend.Core.ScanCoordinator.RunAsync.04") :
                MessageText.Create("Backend.Core.ScanCoordinator.RunAsync.05") + (options.IncludeWorkshop ? options.WorkshopAppIds.Count == 0 ? MessageText.Create("Backend.Core.ScanCoordinator.RunAsync.06") : string.Join("，", options.WorkshopAppIds) : MessageText.Create("Backend.Core.ScanCoordinator.RunAsync.07")));
            report.AddScopeNote(options.IncludeDownloadLocations ? MessageText.Create("Backend.Core.ScanCoordinator.RunAsync.08") : MessageText.Create("Backend.Core.ScanCoordinator.RunAsync.09"));
            report.AddScopeNote((options.MaximumContentBytes == long.MaxValue ? MessageText.Create("Backend.Core.ScanCoordinator.RunAsync.10") : MessageText.Create("Backend.Core.ScanCoordinator.RunAsync.11", (System.FormattableString.Invariant($"{options.MaximumContentBytes / 1024 / 1024:N0}")))) +
                (options.Mode == ScanMode.Quick ? MessageText.Create("Backend.Core.ScanCoordinator.RunAsync.12", (System.FormattableString.Invariant($"{options.MaximumQuickPriorityBytes / 1048576m:0.########}"))) : (MessageText)"。") +
                (options.InspectArchives ? MessageText.Create("Backend.Core.ScanCoordinator.RunAsync.13") : MessageText.Create("Backend.Core.ScanCoordinator.RunAsync.14")));
        }
        if (options.WorkshopAppIds.Count > 0) MarkPartial(report, MessageText.Create("Backend.Core.ScanCoordinator.RunAsync.15") + string.Join("，", options.WorkshopAppIds) + MessageText.Create("Backend.Core.ScanCoordinator.RunAsync.16"), ReasonCodes.WorkshopSelection);

        checkpoint?.Invoke(report);
        string? currentApp = null, currentKind = null;
        int decorated = 0;
        void Checkpoint(ScanReport state)
        {
            // Read the live resource-session options; do not scan a detached budget copy.
            state.ContentScanSettings = ScanEnhancements.ForExecution(options);
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
            bool willIncludeContent = options.IncludeWorkshop || options.IncludeRelatedContent ||
                options.IncludeDownloadLocations || options.RelatedRoots.Count > 0 || options.CustomRoots.Count > 0;
            bool systemOnlyMode = options.IncludeSystem && !willIncludeContent;
            long systemBandStart = 0;
            long systemBandEnd = systemOnlyMode ? 1000 : 200;

            if (options.IncludeSystem)
            {
                StageProgressRelay systemStageProgress = new(progress, value =>
                {
                    // 将系统 4 步（及代理子步 0/2..1/2）平滑映射至系统区间前 65%
                    double baseFraction = value.Total is > 0
                        ? Math.Clamp((double)value.Completed / value.Total.Value, 0.0, 1.0)
                        : 0.0;
                    if (value.StageMessage?.MessageId is "Backend.Core.TrustProxyDiagnosticScanner.Collect.05" or "Backend.Core.TrustProxyDiagnosticScanner.Collect.09")
                        baseFraction = 0.75 + baseFraction * 0.25;
                    else
                        baseFraction *= 0.65;
                    long mapped = systemBandStart + (long)Math.Round((systemBandEnd - systemBandStart) * baseFraction);
                    return (mapped, 1000);
                });
                SystemScanner systemScanner = new(_rules);
                await systemScanner.ScanAsync(report, options, systemStageProgress, cancellationToken);
            }

            SteamLayout? layout = null;
            if (options.IncludeSteam || options.IncludeWorkshop || options.IncludeRelatedContent)
            {
                long steamStart = options.IncludeSystem ? (systemOnlyMode ? 650 : 130) : 0;
                ReportMappedProgress(progress, MessageText.Create("Backend.Core.ScanCoordinator.RunAsync.17"), "Steam Library", steamStart, 1000, MessageText.Create("Backend.Core.ScanCoordinator.RunAsync.18"));
                layout = _layoutOverride ?? SteamLocator.Discover();
                foreach (MessageText note in layout.DiscoveryTexts) MarkPartial(report, note);
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
                long relStart = systemOnlyMode ? 820 : 165;
                ReportMappedProgress(progress, MessageText.Create("Backend.Core.ScanCoordinator.RunAsync.19"), MessageText.Create("Backend.Core.ScanCoordinator.RunAsync.20"), relStart, 1000, MessageText.Create("Backend.Core.ScanCoordinator.RunAsync.21"));
                await new RelatedArtifactScanner(_rules).CollectAsync(layout, report, options, cancellationToken);
            }

            if (options.IncludeSystem)
            {
                long initialStart = systemOnlyMode ? 930 : 185;
                StageProgressRelay initialRelay = new(progress, _ => (initialStart, 1000));
                new RelatedComponentPipeline(_rules).CollectInitial(report, options, initialRelay, cancellationToken);
            }
            if (options.RelatedSignaturePaths.Count > 0)
            {
                if (!_allowRelatedSignatureProbe) MarkPartial(report, MessageText.Create("Backend.Core.ScanCoordinator.RunAsync.22"));
                else await new RelatedSignatureProbe().CollectAsync(report, options.RelatedSignaturePaths,
                    options.MaximumRelatedSignatureBytes, cancellationToken, Checkpoint);
            }

            if (systemOnlyMode)
            {
                ReportMappedProgress(progress, MessageText.Create("Backend.Core.ScanCoordinator.RunAsync.19"), "SteamSentinel", 1000, 1000, MessageText.Create("Backend.Core.ScanCoordinator.RunAsync.21"));
            }

            using ContentScanner contentScanner = new(_rules);
            decorated = report.Findings.Count;
            contentScanner.Checkpoint = Checkpoint;
            HashSet<string> plannedUnique = new(StringComparer.OrdinalIgnoreCase);

            List<string> priorityList = [];
            foreach (string root in options.RelatedRoots.Concat(options.IncludeRelatedContent ? report.CandidateRoots : []).Distinct(StringComparer.OrdinalIgnoreCase))
            {
                cancellationToken.ThrowIfCancellationRequested();
                if (!ContentDiscovery.IsLocalSafePath(root)) { MarkPartial(report, MessageText.Create("Backend.Core.ScanCoordinator.RunAsync.23", (root))); continue; }
                string full = Path.GetFullPath(root);
                if (plannedUnique.Add(full)) priorityList.Add(full);
            }

            List<ContentRoot> modPluginList = [];
            if (options.IncludeRelatedContent && layout is not null)
            {
                foreach (ContentRoot source in layout.ContentRoots.Where(item => item.Kind is "mod" or "plugin"))
                {
                    string full = Path.GetFullPath(source.Path);
                    if (plannedUnique.Add(full)) modPluginList.Add(source);
                }
            }

            List<(string AppId, string ProjectDirectory)> plannedWorkshopProjects = [];
            List<(string Root, MessageTextCollection Notes, List<string> Projects)> plannedLocalRoots = [];
            if (options.IncludeWorkshop && layout is not null)
            {
                foreach (string root in layout.WorkshopRoots)
                {
                    string appId = ContentDiscovery.WorkshopAppId(root);
                    if (options.WorkshopAppIds.Count > 0 && !options.WorkshopAppIds.Contains(appId)) continue;
                    MessageTextCollection notes = [];
                    IReadOnlyList<string> projects = ContentDiscovery.Children(root, true, notes, 40_000);
                    foreach (MessageText note in notes.Texts) MarkPartial(report, note);
                    foreach (string projectDirectory in projects)
                    {
                        string id = Path.GetFileName(projectDirectory);
                        if (!ContentDiscovery.IsNumericId(id)) continue;
                        string full = Path.GetFullPath(projectDirectory);
                        if (plannedUnique.Add(full)) plannedWorkshopProjects.Add((appId, projectDirectory));
                    }
                }
                foreach (string root in layout.WallpaperProjectRoots)
                {
                    if (!Directory.Exists(root)) continue;
                    MessageTextCollection notes = [];
                    List<string> items = [];
                    foreach (string projectDirectory in ContentDiscovery.Children(root, true, notes))
                    {
                        string full = Path.GetFullPath(projectDirectory);
                        if (plannedUnique.Add(full)) items.Add(projectDirectory);
                    }
                    plannedLocalRoots.Add((root, notes, items));
                }
            }

            List<string> extraRelatedList = [];
            List<string> relatedCandidates = [.. options.RelatedRoots];
            if (options.IncludeRelatedContent) relatedCandidates.AddRange(report.CandidateRoots);
            if (options.IncludeDownloadLocations)
                relatedCandidates.AddRange(new[] { Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads"),
                    Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory), Path.GetTempPath() });
            foreach (string root in relatedCandidates.Distinct(StringComparer.OrdinalIgnoreCase))
            {
                cancellationToken.ThrowIfCancellationRequested();
                if (!ContentDiscovery.IsLocalSafePath(root)) { MarkPartial(report, MessageText.Create("Backend.Core.ScanCoordinator.RunAsync.28", (root))); continue; }
                string full = Path.GetFullPath(root);
                if (plannedUnique.Add(full)) extraRelatedList.Add(full);
            }

            List<(string OriginalRoot, string? FullPath)> plannedCustomRoots = [];
            foreach (string root in options.CustomRoots)
            {
                cancellationToken.ThrowIfCancellationRequested();
                string full;
                try { full = Path.GetFullPath(root); }
                catch
                {
                    MarkPartial(report, MessageText.Create("Backend.Core.ScanCoordinator.RunAsync.30", (root)));
                    continue;
                }
                if (plannedUnique.Add(full)) plannedCustomRoots.Add((root, full));
            }

            int totalUnits = priorityList.Count + modPluginList.Count + plannedWorkshopProjects.Count +
                plannedLocalRoots.Sum(entry => entry.Projects.Count) + extraRelatedList.Count + plannedCustomRoots.Count;
            long contentBandStart = options.IncludeSystem ? 200 : 0;
            long contentBandSpan = 1000 - contentBandStart;
            int unitIndex = 0;

            IProgress<ScanProgress>? CreateUnitProgress(int currentUnit)
            {
                if (progress is null || totalUnits <= 0) return progress;
                if (totalUnits == 1 && !options.IncludeSystem) return new MonotonicProgressRelay(progress);
                long unitStart = contentBandStart + (long)Math.Round(contentBandSpan * (double)currentUnit / totalUnits);
                long unitEnd = contentBandStart + (long)Math.Round(contentBandSpan * (double)(currentUnit + 1) / totalUnits);
                long unitSpan = Math.Max(1, unitEnd - unitStart);
                long subTicks = 0;
                return new StageProgressRelay(progress, value =>
                {
                    long offset;
                    if (value.Total is > 0 and long total)
                    {
                        double frac = Math.Clamp((double)value.Completed / total, 0.0, 1.0);
                        offset = (long)Math.Round(unitSpan * frac);
                    }
                    else
                    {
                        subTicks++;
                        double frac = Math.Min(0.85, subTicks * 0.04);
                        offset = (long)Math.Round(unitSpan * frac);
                    }
                    return (Math.Min(unitEnd, unitStart + offset), 1000);
                });
            }

            foreach (string fullRoot in priorityList)
            {
                cancellationToken.ThrowIfCancellationRequested();
                report.AddContentSource(MessageText.Create("Backend.Core.ScanCoordinator.RunAsync.24", (fullRoot)));
                IProgress<ScanProgress>? unitProgress = CreateUnitProgress(unitIndex++);
                await contentScanner.ScanRootAsync(fullRoot, report, options, passwordProvider, unitProgress, cancellationToken);
            }

            if (modPluginList.Count > 0)
            {
                foreach (ContentRoot source in modPluginList)
                {
                    int first = report.Findings.Count;
                    currentApp = source.AppId; currentKind = source.Kind;
                    report.AddContentSource($"{source.Name}，{source.Kind}：{source.Path}");
                    if (source.AppId == VPetDiscovery.AppId &&
                        Path.GetFileName(source.Path).Equals(VPetDiscovery.ModDirectoryName, StringComparison.OrdinalIgnoreCase))
                    {
                        List<string> metadataNotes = [];
                        foreach (string directory in ContentDiscovery.Children(source.Path, true, metadataNotes, 256))
                            RecordVPetMetadata(report, directory, cancellationToken);
                        foreach (string note in metadataNotes) MarkPartial(report, note);
                    }
                    IProgress<ScanProgress>? unitProgress = CreateUnitProgress(unitIndex++);
                    await contentScanner.ScanRootAsync(source.Path, report, options, passwordProvider, unitProgress, cancellationToken,
                        projectType: source.Kind);
                    foreach (Finding finding in report.Findings.Skip(first)) { finding.AppId = source.AppId; finding.SourceKind = source.Kind; }
                }
            }

            if (options.IncludeWorkshop && layout is not null)
            {
                currentApp = null; currentKind = null;
                foreach ((string appId, string projectDirectory) in plannedWorkshopProjects)
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    string id = Path.GetFileName(projectDirectory);
                    VPetModMetadata? vpet = appId == VPetDiscovery.AppId
                        ? RecordVPetMetadata(report, projectDirectory, cancellationToken) : null;
                    WallpaperProject project = appId == "431960" ? SteamLocator.ReadWallpaperProject(projectDirectory)
                        : new(projectDirectory, id, vpet?.Name, vpet is null ? "workshop" : "vpet-mod", null, null, null);
                    report.Metrics.WorkshopItemsVisited++;
                    int currentUnit = unitIndex++;
                    long workshopMapped = totalUnits > 0
                        ? contentBandStart + (long)Math.Round(contentBandSpan * (double)currentUnit / totalUnits)
                        : report.Metrics.WorkshopItemsVisited;
                    progress?.Report(new ScanProgress(MessageText.Create("Backend.Core.ScanCoordinator.RunAsync.25", (appId)), projectDirectory,
                        workshopMapped, totalUnits > 0 ? 1000 : null, (MessageText)(project.Title ?? project.WorkshopId)));

                    if (project.ParseError is not null)
                    {
                        report.Findings.Add(new Finding
                        {
                            RuleId = "WORKSHOP-PROJECT-METADATA",
                            Category = FindingCategory.WallpaperEngine,
                            Severity = FindingSeverity.Medium,
                            Score = 35,
                            TitleText = MessageText.Create("Backend.Core.ScanCoordinator.RunAsync.26"),
                            DescriptionText = project.ParseErrorText,
                            Target = projectDirectory,
                            EvidenceText = $"Workshop ID: {project.WorkshopId}",
                            WorkshopId = project.WorkshopId,
                            CanRemediate = false,
                            SuggestedActions = [SuggestedActionKind.ReviewOnly]
                        });
                    }

                    currentApp = appId; currentKind = "workshop";
                    int first = report.Findings.Count;
                    report.AddContentSource(MessageText.Create("Backend.Core.ScanCoordinator.RunAsync.27", (appId), (project.WorkshopId), (projectDirectory)));
                    IProgress<ScanProgress>? unitProgress = CreateUnitProgress(currentUnit);
                    await contentScanner.ScanRootAsync(projectDirectory, report, options, passwordProvider,
                        unitProgress, cancellationToken, project.WorkshopId, project.Type);
                    foreach (Finding finding in report.Findings.Skip(first)) { finding.AppId = appId; finding.SourceKind = "workshop"; }
                }

                foreach ((_, MessageTextCollection notes, List<string> items) in plannedLocalRoots)
                {
                    currentApp = "431960"; currentKind = "wallpaper-local";
                    foreach (string projectDirectory in items)
                    {
                        cancellationToken.ThrowIfCancellationRequested();
                        WallpaperProject project = SteamLocator.ReadWallpaperProject(projectDirectory);
                        string? projectType = Path.GetFileName(projectDirectory).Equals("defaultprojects", StringComparison.OrdinalIgnoreCase)
                            ? "trusted-default"
                            : project.Type;
                        report.Metrics.WorkshopItemsVisited++;
                        IProgress<ScanProgress>? unitProgress = CreateUnitProgress(unitIndex++);
                        await contentScanner.ScanRootAsync(projectDirectory, report, options, passwordProvider,
                            unitProgress, cancellationToken, "local:" + project.WorkshopId, projectType);
                    }
                    foreach (MessageText note in notes.Texts) MarkPartial(report, note);
                }
            }

            currentApp = null; currentKind = null;
            foreach (string full in extraRelatedList)
            {
                cancellationToken.ThrowIfCancellationRequested();
                report.AddContentSource(MessageText.Create("Backend.Core.ScanCoordinator.RunAsync.29", (full)));
                IProgress<ScanProgress>? unitProgress = CreateUnitProgress(unitIndex++);
                await contentScanner.ScanRootAsync(full, report, options, passwordProvider, unitProgress, cancellationToken);
            }

            foreach ((_, string? full) in plannedCustomRoots)
            {
                if (full is null) continue;
                cancellationToken.ThrowIfCancellationRequested();
                IProgress<ScanProgress>? unitProgress = CreateUnitProgress(unitIndex++);
                await contentScanner.ScanRootAsync(full, report, options, passwordProvider, unitProgress, cancellationToken);
            }
        }
        catch (OperationCanceledException)
        {
            report.Coverage = ScanCoverage.Partial;
            ScanExecution.Set(report, ScanExecutionState.Cancelled, ReasonCodes.UserCancelled);
            ScanExecution.AddNotice(report, ReasonCodes.UserCancelled, MessageText.Create("Backend.Core.ScanCoordinator.RunAsync.31"));
            throw;
        }
        catch (Exception ex)
        {
            ScanExecution.Set(report, ScanExecutionState.Failed, ReasonCodes.ForFailureType(ex.GetType().Name));
            report.Coverage = ScanCoverage.Partial;
            throw;
        }
        finally
        {
            report.ContentScanSettings = ScanEnhancements.ForExecution(options);
            if (report.ExecutionState == ScanExecutionState.Running) ScanExecution.Set(report, ScanExecutionState.Completed);
            report.CompletedAtUtc = DateTimeOffset.UtcNow;
            if (report.ResourceAudit is { } audit) audit.Phase = ScanResourcePhase.Finished;
        }

        SteamSecurityScanner.CorrelateLoopbackScripts(report, _rules);
        Checkpoint(report);
        // Checkpoints use append-only offsets. The UI sorts the merged report independently.
        if (checkpoint is null) report.Findings.Sort((left, right) =>
        {
            int severity = right.Severity.CompareTo(left.Severity);
            return severity != 0 ? severity : right.Score.CompareTo(left.Score);
        });
        return report;
    }

    private static VPetModMetadata RecordVPetMetadata(ScanReport report, string directory, CancellationToken token)
    {
        VPetModMetadata metadata = VPetDiscovery.ReadMetadata(directory, token);
        report.AddContentSource(MessageText.Create("Backend.Core.ScanCoordinator.RecordVPetMetadata.01", (metadata.ReasonCode), (directory)) +
            (metadata.Name is null ? (MessageText)"" : MessageText.Create("Backend.Core.ScanCoordinator.RecordVPetMetadata.02", (metadata.Name))) +
            (metadata.DeclaredWorkshopId is null ? (MessageText)"" : MessageText.Create("Backend.Core.ScanCoordinator.RecordVPetMetadata.03", (metadata.DeclaredWorkshopId))));
        if (metadata.Status != VPetMetadataStatus.Available)
            MarkPartial(report, MessageText.Create("Backend.Core.ScanCoordinator.RecordVPetMetadata.04", (metadata.ReasonCode), (directory)));
        return metadata;
    }

    private static void MarkPartial(ScanReport report, MessageText message, string reason = ReasonCodes.ReadIncomplete)
    {
        report.Coverage = ScanCoverage.Partial;
        ScanExecution.AddNotice(report, reason, message);
    }

    private static void ReportMappedProgress(IProgress<ScanProgress>? progress, MessageText stage, string currentItem, long completed, long total, MessageText message) =>
        progress?.Report(new ScanProgress(stage, currentItem, completed, total, message));

    private static void ReportMappedProgress(IProgress<ScanProgress>? progress, MessageText stage, MessageText currentItem, long completed, long total, MessageText message) =>
        progress?.Report(new ScanProgress(stage, currentItem, completed, total, message));

    /// <summary>保留原阶段文案与当前对象不变，仅将数值刻度映射为单调递增的区间进度。</summary>
    private sealed class StageProgressRelay(
        IProgress<ScanProgress>? inner,
        Func<ScanProgress, (long Completed, long Total)> map) : IProgress<ScanProgress>
    {
        private long _maxCompleted;

        public void Report(ScanProgress value)
        {
            if (inner is null) return;
            (long completed, long total) = map(value);
            if (total > 0)
            {
                if (completed < _maxCompleted) completed = _maxCompleted;
                else _maxCompleted = completed;
            }
            inner.Report(value with { Completed = completed, Total = total > 0 ? total : value.Total });
        }
    }

    /// <summary>单根目录透传进度并保证在已报告 Total 后单调递增不倒退。</summary>
    private sealed class MonotonicProgressRelay(IProgress<ScanProgress> inner) : IProgress<ScanProgress>
    {
        private long _maxCompleted;
        private long? _lastTotal;

        public void Report(ScanProgress value)
        {
            if (value.Total is > 0 and long total)
            {
                _lastTotal = total;
                long completed = Math.Max(_maxCompleted, Math.Clamp(value.Completed, 0, total));
                _maxCompleted = completed;
                inner.Report(value with { Completed = completed, Total = total });
            }
            else if (_lastTotal is > 0 and long preservedTotal)
            {
                inner.Report(value with { Completed = _maxCompleted, Total = preservedTotal });
            }
            else
            {
                inner.Report(value);
            }
        }
    }
}
