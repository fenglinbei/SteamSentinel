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
        _rules = rules ?? RuleLoader.LoadEmbedded();
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
            if (options.IncludeSystem)
            {
                SystemScanner systemScanner = new(_rules);
                await systemScanner.ScanAsync(report, options, progress, cancellationToken);
            }

            SteamLayout? layout = null;
            if (options.IncludeSteam || options.IncludeWorkshop || options.IncludeRelatedContent)
            {
                progress?.Report(new ScanProgress(MessageText.Create("Backend.Core.ScanCoordinator.RunAsync.17"), "Steam Library", 0, null, MessageText.Create("Backend.Core.ScanCoordinator.RunAsync.18")));
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
                progress?.Report(new ScanProgress(MessageText.Create("Backend.Core.ScanCoordinator.RunAsync.19"), MessageText.Create("Backend.Core.ScanCoordinator.RunAsync.20"), 0, null, MessageText.Create("Backend.Core.ScanCoordinator.RunAsync.21")));
                await new RelatedArtifactScanner(_rules).CollectAsync(layout, report, options, cancellationToken);
            }

            if (options.IncludeSystem)
                new RelatedComponentPipeline(_rules).CollectInitial(report, options, progress, cancellationToken);
            if (options.RelatedSignaturePaths.Count > 0)
            {
                if (!_allowRelatedSignatureProbe) MarkPartial(report, MessageText.Create("Backend.Core.ScanCoordinator.RunAsync.22"));
                else await new RelatedSignatureProbe().CollectAsync(report, options.RelatedSignaturePaths,
                    options.MaximumRelatedSignatureBytes, cancellationToken, Checkpoint);
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
                if (!ContentDiscovery.IsLocalSafePath(root)) { MarkPartial(report, MessageText.Create("Backend.Core.ScanCoordinator.RunAsync.23", (root))); continue; }
                if (!scanned.Add(Path.GetFullPath(root))) continue;
                report.AddContentSource(MessageText.Create("Backend.Core.ScanCoordinator.RunAsync.24", (root)));
                await contentScanner.ScanRootAsync(root, report, options, passwordProvider, progress, cancellationToken);
            }

            if (options.IncludeRelatedContent && layout is not null)
            {
                foreach (ContentRoot source in layout.ContentRoots.Where(item => item.Kind is "mod" or "plugin"))
                {
                    if (!scanned.Add(Path.GetFullPath(source.Path))) continue;
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
                    MessageTextCollection notes = [];
                    IReadOnlyList<string> projects = ContentDiscovery.Children(root, true, notes, 40_000);
                    foreach (MessageText note in notes.Texts) MarkPartial(report, note);

                    foreach (string projectDirectory in projects)
                    {
                        cancellationToken.ThrowIfCancellationRequested();
                        string id = Path.GetFileName(projectDirectory);
                        if (!ContentDiscovery.IsNumericId(id)) continue;
                        VPetModMetadata? vpet = appId == VPetDiscovery.AppId
                            ? RecordVPetMetadata(report, projectDirectory, cancellationToken) : null;
                        WallpaperProject project = appId == "431960" ? SteamLocator.ReadWallpaperProject(projectDirectory)
                            : new(projectDirectory, id, vpet?.Name, vpet is null ? "workshop" : "vpet-mod", null, null, null);
                        report.Metrics.WorkshopItemsVisited++;
                        progress?.Report(new ScanProgress(MessageText.Create("Backend.Core.ScanCoordinator.RunAsync.25", (appId)), projectDirectory,
                            report.Metrics.WorkshopItemsVisited, null, (MessageText)(project.Title ?? project.WorkshopId)));

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

                        if (!scanned.Add(Path.GetFullPath(projectDirectory))) continue;
                        currentApp = appId; currentKind = "workshop";
                        int first = report.Findings.Count;
                        report.AddContentSource(MessageText.Create("Backend.Core.ScanCoordinator.RunAsync.27", (appId), (project.WorkshopId), (projectDirectory)));
                        await contentScanner.ScanRootAsync(projectDirectory, report, options, passwordProvider,
                            progress, cancellationToken, project.WorkshopId, project.Type);
                        foreach (Finding finding in report.Findings.Skip(first)) { finding.AppId = appId; finding.SourceKind = "workshop"; }
                    }
                }

                foreach (string root in layout.WallpaperProjectRoots)
                {
                    currentApp = "431960"; currentKind = "wallpaper-local";
                    if (!Directory.Exists(root)) continue;
                    MessageTextCollection notes = [];
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
                    foreach (MessageText note in notes.Texts) MarkPartial(report, note);
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
                if (!ContentDiscovery.IsLocalSafePath(root)) { MarkPartial(report, MessageText.Create("Backend.Core.ScanCoordinator.RunAsync.28", (root))); continue; }
                if (!scanned.Add(Path.GetFullPath(root))) continue;
                report.AddContentSource(MessageText.Create("Backend.Core.ScanCoordinator.RunAsync.29", (root)));
                await contentScanner.ScanRootAsync(root, report, options, passwordProvider, progress, cancellationToken);
            }

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

                if (!scanned.Add(full)) continue;
                await contentScanner.ScanRootAsync(full, report, options, passwordProvider, progress, cancellationToken);
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
}
