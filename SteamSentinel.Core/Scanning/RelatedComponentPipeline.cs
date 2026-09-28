using SteamSentinel.Core.Reporting;
using System.ComponentModel;
using System.Diagnostics;
using System.Security.Principal;
using SteamSentinel.Core.Models;
using SteamSentinel.Core.Remediation;
using SteamSentinel.Core.Rules;
using SteamSentinel.Core.Steam;
using SteamSentinel.Core.Utilities;

namespace SteamSentinel.Core.Scanning;

/// <summary>Bounded discovery and evidence closure. Untrusted content is delegated to the caller's restricted worker.</summary>
public sealed partial class RelatedComponentPipeline
{
    public const string SourceKind = "related-components";
    private readonly RuleSet _rules;
    private readonly Action<RelatedComponentDiscoveryRequest, RelatedComponentDiagnosticReport, RelatedComponentLimits, CancellationToken> _collect;
    private readonly Func<string> _sid;
    private readonly Func<IEnumerable<Finding>, ScanReport, CancellationToken, long, Task<RelatedArtifactExpansion>> _expand;

    public RelatedComponentPipeline(RuleSet? rules = null) : this(rules ?? RuleLoader.LoadEmbedded(),
        new RelatedComponentDiscovery().Collect, CurrentUserSid, null)
    { }

    internal RelatedComponentPipeline(RuleSet rules,
        Action<RelatedComponentDiscoveryRequest, RelatedComponentDiagnosticReport, RelatedComponentLimits, CancellationToken> collect,
        Func<string> sid, Func<IEnumerable<Finding>, ScanReport, CancellationToken, long, Task<RelatedArtifactExpansion>>? expand)
    {
        _rules = rules; _collect = collect; _sid = sid;
        _expand = expand ?? ((findings, report, token, budget) => new RelatedArtifactScanner(rules).ExpandAsync(findings, report, token, budget));
    }

    private static string CurrentUserSid()
    { using WindowsIdentity identity = WindowsIdentity.GetCurrent(); return identity.User?.Value ?? string.Empty; }

    public void CollectInitial(ScanReport report, ScanOptions options, IProgress<ScanProgress>? progress = null,
        CancellationToken token = default, RelatedComponentLimits? limits = null)
    {
        limits ??= new();
        string sid;
        try { sid = _sid(); } catch (Exception ex) when (ex is not OutOfMemoryException) { sid = string.Empty; }
        RelatedComponentDiagnosticReport diagnostic = new() { TargetUserSid = sid, AppliedLimits = limits };
        report.RelatedComponentDiagnostics = diagnostic;
        progress?.Report(new(MessageText.Create("Backend.Core.RelatedComponentPipeline.CollectInitial.01"), MessageText.Create("Backend.Core.RelatedComponentPipeline.CollectInitial.02"), 0, null, MessageText.Create("Backend.Core.RelatedComponentPipeline.CollectInitial.03")));
        Collect(report, options, diagnostic, limits, token);
        foreach (RelatedComponentCandidate candidate in diagnostic.Candidates.Where(c => IsSafeCandidate(c.Path, options)))
            if (!report.CandidateRoots.Contains(candidate.Path, StringComparer.OrdinalIgnoreCase)) report.CandidateRoots.Add(candidate.Path);
        report.AddScopeNote(MessageText.Create("Backend.Core.RelatedComponentPipeline.CollectInitial.04"));
        MarkIncomplete(report, diagnostic);
    }

    public async Task<ScanReport> CompleteAsync(ScanReport report, ScanOptions originalContentOptions,
        Func<ScanOptions, IProgress<ScanProgress>?, CancellationToken, Task<ScanReport>> scanContent,
        IProgress<ScanProgress>? progress = null, CancellationToken token = default, RelatedComponentLimits? limits = null)
    {
        limits ??= report.RelatedComponentDiagnostics?.AppliedLimits ?? new();
        if (limits.MaximumRounds is < 0 or > 2 || limits.MaximumCandidates is < 0 or > 128 ||
            limits.MaximumTotalBytes < 0 || limits.MaximumFileBytes < 0 || limits.MaximumDuration < TimeSpan.Zero)
            throw SteamSentinel.Core.Reporting.MessageExceptions.Create(MessageText.Create("Backend.Core.RelatedComponentPipeline.CompleteAsync.01"), sourceText => new ArgumentOutOfRangeException(nameof(limits), sourceText));
        if (report.RelatedComponentDiagnostics is null) CollectInitial(report, originalContentOptions, progress, token, limits);
        RelatedComponentDiagnosticReport diagnostic = report.RelatedComponentDiagnostics!;
        ScanOptions? originalSettings = report.ContentScanSettings;
        HashSet<string> visited = new(StringComparer.OrdinalIgnoreCase);
        HashSet<string> signatureVisited = new(StringComparer.OrdinalIgnoreCase);
        HashSet<string> closedEvidence = new(StringComparer.OrdinalIgnoreCase);
        foreach (RelatedComponentCandidate candidate in diagnostic.Candidates)
        {
            ScanRootSummary? summary = report.RootSummaries.LastOrDefault(r => SamePath(r.Path, candidate.Path));
            if (summary is null) continue;
            visited.Add(candidate.Path);
            candidate.ContentStatus = summary.Coverage == ScanCoverage.Complete ? DiagnosticReadStatus.Complete : DiagnosticReadStatus.NotChecked;
            candidate.ContentDetailText = summary.Coverage == ScanCoverage.Complete
                ? MessageText.Create("Backend.Core.RelatedComponentPipeline.CompleteAsync.02")
                : MessageText.Create("Backend.Core.RelatedComponentPipeline.CompleteAsync.03");
        }
        long consumed = 0;
        Stopwatch elapsed = Stopwatch.StartNew();
        using CancellationTokenSource deadline = CancellationTokenSource.CreateLinkedTokenSource(token);
        deadline.CancelAfter(limits.MaximumDuration);
        CancellationToken bounded = deadline.Token;
        try
        {
            for (int number = 1; number <= limits.MaximumRounds; number++)
            {
                bounded.ThrowIfCancellationRequested();
                RelatedScanRound round = new() { Number = number, MaximumBytes = Math.Max(0, limits.MaximumTotalBytes - consumed), Status = DiagnosticReadStatus.NotChecked };
                diagnostic.Rounds.Add(round);
                long before = consumed;
                progress?.Report(new(MessageText.Create("Backend.Core.RelatedComponentPipeline.CompleteAsync.04"), MessageText.Create("Backend.Core.RelatedComponentPipeline.CompleteAsync.05", (number)), number - 1, limits.MaximumRounds, MessageText.Create("Backend.Core.RelatedComponentPipeline.CompleteAsync.06")));
                try
                {
                    consumed += await CloseEvidenceAsync(report, Math.Max(0, limits.MaximumTotalBytes - consumed), bounded, closedEvidence);
                    RelatedComponentDiagnosticReport fresh = new() { TargetUserSid = diagnostic.TargetUserSid, AppliedLimits = limits };
                    Collect(report, originalContentOptions, fresh, limits, bounded);
                    MergeDiscovery(diagnostic, fresh, limits);
                    await RefreshEvidenceIdentitiesAsync(report, originalContentOptions, limits, visited,
                        () => Math.Max(0, limits.MaximumTotalBytes - consumed), bytes => consumed += bytes, bounded);
                    AssociateEvidence(report);
                    RelatedComponentCandidate[] pending = diagnostic.Candidates.Where(c => !visited.Contains(c.Path) &&
                        IsSafeCandidate(c.Path, originalContentOptions)).Take(limits.MaximumCandidates).ToArray();
                    List<string> signatures = diagnostic.Hosts.Where(h => originalContentOptions.InspectDeepSignatures && h.SignatureStatus == "NotChecked" &&
                            !signatureVisited.Contains(h.ImagePath) && ContentDiscovery.IsLocalSafePath(h.ImagePath) &&
                            !originalContentOptions.ExcludedRoots.Any(root => ContentDiscovery.IsWithin(h.ImagePath, root)))
                        .Select(h => h.ImagePath).Distinct(StringComparer.OrdinalIgnoreCase).Take(32).ToList();
                    long signatureBudget = signatures.Count == 0 ? 0 : Math.Min(128L * 1024 * 1024, Math.Max(0, limits.MaximumTotalBytes - consumed) / 4);
                    if (pending.Length == 0 && signatures.Count == 0)
                    { round.Status = DiagnosticReadStatus.Complete; round.DetailText = MessageText.Create("Backend.Core.RelatedComponentPipeline.CompleteAsync.07"); break; }

                    List<(RelatedComponentCandidate Candidate, FileStream Lease)> leases = [];
                    long reservedContentBytes = 0;
                    try
                    {
                        foreach (RelatedComponentCandidate candidate in pending)
                        {
                            bounded.ThrowIfCancellationRequested();
                            visited.Add(candidate.Path); round.CandidateIds.Add(candidate.Id);
                            FileStream? lease = null;
                            try
                            {
                                lease = RelatedArtifactReader.Open(candidate.Path);
                                long remaining = limits.MaximumTotalBytes - consumed - reservedContentBytes - signatureBudget;
                                // Leave capacity for the worker to read these same bytes and expand supported content.
                                if (lease.Length > limits.MaximumFileBytes || lease.Length > remaining / 3)
                                    throw MessageExceptions.Create(MessageText.Create("Backend.Core.RelatedComponentPipeline.CompleteAsync.08"), sourceText => new RelatedBudgetException(sourceText));
                                candidate.Length = lease.Length;
                                candidate.Sha256 = await Hashing.Sha256StreamAsync(lease, bounded, bytes => consumed += bytes);
                                candidate.VerifiedAtUtc = DateTimeOffset.UtcNow;
                                reservedContentBytes += lease.Length * 2;
                                candidate.Status = DiagnosticReadStatus.Complete;
                                candidate.DetailText = MessageText.Create("Backend.Core.RelatedComponentPipeline.CompleteAsync.09");
                                leases.Add((candidate, lease)); lease = null;
                            }
                            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or Win32Exception)
                            {
                                candidate.Status = candidate.ContentStatus = ex is RelatedBudgetException ? DiagnosticReadStatus.LimitReached :
                                    ex is UnauthorizedAccessException || ex is Win32Exception { NativeErrorCode: 5 } ? DiagnosticReadStatus.AccessDenied : DiagnosticReadStatus.Failed;
                                candidate.DetailText = candidate.ContentDetailText = MessageExceptions.Describe(ex);
                                Check(diagnostic, "related.file_identity", MessageText.Create("Backend.Core.RelatedComponentPipeline.CompleteAsync.10"), candidate.Status, MessageExceptions.Describe(ex), candidate.Id);
                                if (ex is RelatedBudgetException) AddOuterRecheck(report, candidate.Path, MessageExceptions.Describe(ex));
                            }
                            finally { if (lease is not null) await lease.DisposeAsync(); }
                        }
                        if (leases.Count > 0 || signatures.Count > 0)
                        {
                            long remaining = Math.Max(0, limits.MaximumTotalBytes - consumed);
                            if (remaining - signatureBudget < 2)
                            {
                                Check(diagnostic, "related.container_budget", MessageText.Create("Backend.Core.RelatedComponentPipeline.CompleteAsync.11"), DiagnosticReadStatus.LimitReached, MessageText.Create("Backend.Core.RelatedComponentPipeline.CompleteAsync.12"));
                                foreach (var held in leases) AddOuterRecheck(report, held.Candidate.Path, MessageText.Create("Backend.Core.RelatedComponentPipeline.CompleteAsync.13"));
                                continue;
                            }
                            ScanOptions followUp = FollowUpOptions(originalContentOptions, leases.Select(l => l.Candidate.Path).ToList(), remaining, signatures, signatureBudget);
                            foreach (string path in signatures) signatureVisited.Add(path);
                            ScanReport content = await scanContent(followUp, progress, bounded);
                            consumed += FollowUpChargedBytes(content, signatureBudget);
                            ApplySignatureResults(report, content);
                            foreach ((RelatedComponentCandidate candidate, FileStream lease) in leases)
                            {
                                bool pathValid = true;
                                try { RelatedArtifactReader.ValidatePath(lease.SafeFileHandle, Path.GetFullPath(candidate.Path)); }
                                catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or Win32Exception)
                                { pathValid = false; Check(diagnostic, "related.followup_identity", MessageText.Create("Backend.Core.RelatedComponentPipeline.CompleteAsync.14"), DiagnosticReadStatus.Failed, MessageExceptions.Describe(ex), candidate.Id); }
                                bool mismatch = !pathValid || content.Findings.Where(f => SamePath(f.Target, candidate.Path))
                                    .Select(f => f.TargetSha256 ?? (f.ContentPath is null || SamePath(f.ContentPath, f.Target) ? f.Sha256 : null))
                                    .Any(hash => hash is not null && !hash.Equals(candidate.Sha256, StringComparison.OrdinalIgnoreCase));
                                ScanRootSummary? summary = content.RootSummaries.LastOrDefault(r => SamePath(r.Path, candidate.Path));
                                bool complete = !mismatch && summary?.Coverage == ScanCoverage.Complete;
                                candidate.ContentStatus = complete ? DiagnosticReadStatus.Complete : DiagnosticReadStatus.NotChecked;
                                candidate.ContentDetailText = complete ? MessageText.Create("Backend.Core.RelatedComponentPipeline.CompleteAsync.15") :
                                    mismatch ? MessageText.Create("Backend.Core.RelatedComponentPipeline.CompleteAsync.16") : MessageText.Create("Backend.Core.RelatedComponentPipeline.CompleteAsync.17");
                                if (mismatch) content.Findings.RemoveAll(f => SamePath(f.Target, candidate.Path));
                                if (!complete) Check(diagnostic, "related.new_content", MessageText.Create("Backend.Core.RelatedComponentPipeline.CompleteAsync.18"), DiagnosticReadStatus.NotChecked, candidate.ContentDetailText, candidate.Id);
                            }
                            AppendContent(report, content);
                        }
                        round.Status = diagnostic.Candidates.Where(c => round.CandidateIds.Contains(c.Id)).All(c => c.ContentStatus == DiagnosticReadStatus.Complete)
                            ? DiagnosticReadStatus.Complete : DiagnosticReadStatus.NotChecked;
                        round.DetailText = MessageText.Create("Backend.Core.RelatedComponentPipeline.CompleteAsync.19");
                    }
                    finally { foreach (var item in leases) await item.Lease.DisposeAsync(); }
                }
                finally { round.BytesRead = consumed - before; round.CompletedAtUtc = DateTimeOffset.UtcNow; }
                if (consumed >= limits.MaximumTotalBytes) break;
            }
            // The last content batch may supply a previously unknown module's proof. Close it now,
            // with the same remaining budget, without silently starting a third content scan.
            consumed += await CloseEvidenceAsync(report, Math.Max(0, limits.MaximumTotalBytes - consumed), bounded, closedEvidence);
            AssociateEvidence(report);
            foreach (Finding pendingProof in report.Findings.Where(RelatedArtifactRelations.IsFileEvidence)
                .DistinctBy(ClosureKey).Where(f => !closedEvidence.Contains(ClosureKey(f))))
                Check(diagnostic, "related.remaining_evidence", MessageText.Create("Backend.Core.RelatedComponentPipeline.CompleteAsync.20"), DiagnosticReadStatus.LimitReached,
                    MessageText.Create("Backend.Core.RelatedComponentPipeline.CompleteAsync.21") + pendingProof.Target);
            foreach (RelatedComponentCandidate candidate in diagnostic.Candidates.Where(c => !visited.Contains(c.Path)))
            {
                candidate.ContentStatus = DiagnosticReadStatus.LimitReached;
                candidate.ContentDetailText = MessageText.Create("Backend.Core.RelatedComponentPipeline.CompleteAsync.22") + candidate.Path;
                AddOuterRecheck(report, candidate.Path, candidate.ContentDetailText);
                Check(diagnostic, "related.remaining_candidates", MessageText.Create("Backend.Core.RelatedComponentPipeline.CompleteAsync.23"), DiagnosticReadStatus.LimitReached, candidate.ContentDetailText, candidate.Id);
            }
        }
        catch (OperationCanceledException)
        {
            DiagnosticReadStatus state = token.IsCancellationRequested ? DiagnosticReadStatus.Cancelled : DiagnosticReadStatus.LimitReached;
            if (diagnostic.Rounds.LastOrDefault() is { Status: DiagnosticReadStatus.NotChecked } round)
            { round.Status = state; round.CompletedAtUtc = DateTimeOffset.UtcNow; }
            Check(diagnostic, "related.followup", MessageText.Create("Backend.Core.RelatedComponentPipeline.CompleteAsync.24"), state, token.IsCancellationRequested ? MessageText.Create("Backend.Core.RelatedComponentPipeline.CompleteAsync.25") : MessageText.Create("Backend.Core.RelatedComponentPipeline.CompleteAsync.26"));
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        { Check(diagnostic, "related.followup", MessageText.Create("Backend.Core.RelatedComponentPipeline.CompleteAsync.27"), DiagnosticReadStatus.Failed, MessageText.Create("Backend.Core.RelatedComponentPipeline.CompleteAsync.28") + MessageExceptions.Describe(ex)); }
        finally
        {
            diagnostic.CompletedAtUtc = DateTimeOffset.UtcNow;
            report.CompletedAtUtc = diagnostic.CompletedAtUtc;
            report.ContentScanSettings = originalSettings;
            report.AddScopeNote(MessageText.Create("Backend.Core.RelatedComponentPipeline.CompleteAsync.29", (limits.MaximumRounds), (consumed), (System.FormattableString.Invariant($"{elapsed.Elapsed.TotalSeconds:F1}"))));
            MarkIncomplete(report, diagnostic);
        }
        return report;
    }

    private void Collect(ScanReport report, ScanOptions options, RelatedComponentDiagnosticReport output, RelatedComponentLimits limits, CancellationToken token)
    {
        try
        {
            if (string.IsNullOrWhiteSpace(output.TargetUserSid)) { Check(output, "related.collection_identity", MessageText.Create("Backend.Core.RelatedComponentPipeline.Collect.01"), DiagnosticReadStatus.Failed, MessageText.Create("Backend.Core.RelatedComponentPipeline.Collect.02")); return; }
            _collect(new()
            {
                TargetUserSid = output.TargetUserSid,
                ExcludedRoots = options.ExcludedRoots,
                SeedPaths = report.CandidateRoots.Concat(report.Findings.Where(f => f.Severity >= FindingSeverity.Medium || f.IsKnownMalware)
                    .SelectMany(f => new[] { f.RelatedFilePath, f.Target }).Where(p => p is not null).Select(p => p!))
                    .Where(p => ContentDiscovery.IsLocalSafePath(p)).Distinct(StringComparer.OrdinalIgnoreCase).Take(limits.MaximumCandidates).ToArray(),
                SeedProcessIds = report.Findings.Where(f => f.ProcessId is not null).Select(f => f.ProcessId!.Value).Distinct().Take(limits.MaximumHosts).ToArray()
            }, output, limits, token);
        }
        catch (OperationCanceledException) { Check(output, "related.source_collection", MessageText.Create("Backend.Core.RelatedComponentPipeline.Collect.03"), DiagnosticReadStatus.Cancelled, MessageText.Create("Backend.Core.RelatedComponentPipeline.Collect.04")); throw; }
        catch (Exception ex) when (ex is not OutOfMemoryException) { Check(output, "related.source_collection", MessageText.Create("Backend.Core.RelatedComponentPipeline.Collect.05"), DiagnosticReadStatus.Failed, MessageExceptions.Describe(ex)); }
    }

    private async Task<long> CloseEvidenceAsync(ScanReport report, long budget, CancellationToken token, HashSet<string> closed)
    {
        Finding[] evidence = report.Findings.Where(RelatedArtifactRelations.IsFileEvidence).Reverse().DistinctBy(ClosureKey)
            .OrderBy(f => closed.Contains(ClosureKey(f))).Take(64).ToArray();
        if (evidence.Length == 0) return 0;
        if (budget <= 0) { Check(report.RelatedComponentDiagnostics!, "related.identity_recheck", MessageText.Create("Backend.Core.RelatedComponentPipeline.CloseEvidenceAsync.01"), DiagnosticReadStatus.LimitReached, MessageText.Create("Backend.Core.RelatedComponentPipeline.CloseEvidenceAsync.02")); return 0; }
        RelatedArtifactExpansion closure = await _expand(evidence, report, token, budget);
        foreach (Finding finding in evidence) closed.Add(ClosureKey(finding));
        foreach (Finding finding in closure.Findings.Where(f => f.Category is FindingCategory.Process or FindingCategory.Persistence))
            if (!report.Findings.Any(old => FindingKey(old) == FindingKey(finding))) report.Findings.Add(finding);
        foreach (MessageText scope in closure.ScopeTexts) if (!report.ScopeNotes.Contains(scope.OriginalText)) report.AddScopeNote(scope);
        foreach (MessageText note in closure.NoteTexts) Check(report.RelatedComponentDiagnostics!, "related.evidence_recheck", MessageText.Create("Backend.Core.RelatedComponentPipeline.CloseEvidenceAsync.03"), DiagnosticReadStatus.NotChecked, note);
        return closure.VerificationBytesRead;
    }

    private static string ClosureKey(Finding finding) => finding.Target.ToUpperInvariant() + "|" + RelatedArtifactRelations.FileHash(finding)?.ToUpperInvariant();

    internal static ScanOptions FollowUpOptions(ScanOptions original, List<string> paths, long remaining,
        List<string>? signatures = null, long signatureBudget = 0)
    {
        if (signatureBudget < 0 || remaining < signatureBudget || remaining - signatureBudget < 2)
            throw SteamSentinel.Core.Reporting.MessageExceptions.Create(MessageText.Create("Backend.Core.RelatedComponentPipeline.FollowUpOptions.01"), sourceText => new ArgumentOutOfRangeException(nameof(remaining), sourceText));
        long available = remaining - signatureBudget, hashAllowance = available / 2;
        ContainerResourceLimits source = original.ContainerLimits ?? new();
        ContainerResourceLimits narrowed = new()
        {
            MaximumEntryBytes = Math.Min(Math.Min(original.MaximumEntryBytes, source.MaximumEntryBytes), hashAllowance),
            MaximumExpandedBytes = Math.Min(Math.Min(original.MaximumExpandedBytes, source.MaximumExpandedBytes), available - hashAllowance),
            MaximumWorkBytes = Math.Min(source.MaximumWorkBytes, available),
            MaximumTemporaryBytes = Math.Min(source.MaximumTemporaryBytes, available),
            ReservedDiskBytes = source.ReservedDiskBytes,
            MaximumDepth = Math.Min(original.MaximumArchiveDepth, source.MaximumDepth),
            MaximumEntries = Math.Min(Math.Min(original.MaximumArchiveEntries, source.MaximumEntries), 2048),
            MaximumMetadataAttempts = Math.Min(source.MaximumMetadataAttempts, 8192),
            MaximumPasswordAttempts = Math.Min(source.MaximumPasswordAttempts, 64),
            MaximumVolumes = source.MaximumVolumes,
            MaximumDirectoryCandidates = Math.Min(source.MaximumDirectoryCandidates, 512),
            MaximumDurationSeconds = Math.Min(source.MaximumDurationSeconds, 90),
            MaximumCompressionRatio = Math.Min(original.MaximumCompressionRatio, source.MaximumCompressionRatio)
        };
        return new()
        {
            Mode = ScanMode.Custom,
            IncludeSystem = false,
            IncludeSteam = false,
            IncludeWorkshop = false,
            IncludeRelatedContent = false,
            IncludeDownloadLocations = false,
            CustomRoots = paths,
            ExcludedRoots = [.. original.ExcludedRoots],
            InspectArchives = original.InspectArchives,
            UseAmsi = ScanEnhancements.UseAmsi(original),
            MaximumStringScanBytes = original.MaximumStringScanBytes,
            MaximumAmsiBytes = original.MaximumAmsiBytes,
            MaximumWorkerMemoryBytes = original.MaximumWorkerMemoryBytes,
            MaximumReportRecords = original.MaximumReportRecords,
            MaximumReportTextCharacters = original.MaximumReportTextCharacters,
            MaximumStructureDurationSeconds = original.MaximumStructureDurationSeconds,
            RangeLimits = original.RangeLimits,
            HashEveryFile = true,
            RelatedSignaturePaths = original.InspectDeepSignatures ? signatures ?? [] : [],
            MaximumRelatedSignatureBytes = original.InspectDeepSignatures ? signatureBudget : 0,
            MaximumContentBytes = signatureBudget + hashAllowance,
            MaximumExpandedBytes = narrowed.MaximumExpandedBytes,
            MaximumEntryBytes = narrowed.MaximumEntryBytes,
            MaximumArchiveDepth = narrowed.MaximumDepth,
            MaximumArchiveEntries = narrowed.MaximumEntries,
            MaximumFiles = Math.Min(original.MaximumFiles, 4096),
            MaximumCompressionRatio = narrowed.MaximumCompressionRatio,
            ContainerLimits = narrowed,
            InspectDeepSignatures = original.InspectDeepSignatures,
            SupplementalVolumeDirectories = [.. original.SupplementalVolumeDirectories],
            RecoveryOutputDirectory = null
        };
    }

    private static long FollowUpChargedBytes(ScanReport content, long signatureBudget)
    {
        long legacy = checked(content.Metrics.BytesHashed + content.Metrics.ArchiveBytesExpanded);
        if (content.Containers is not { } containers) return legacy;
        IEnumerable<ContainerResourceSnapshot> snapshots = containers.Runs.Count > 0 ? containers.Runs.Select(run => run.Resources) : [containers.Resources];
        long work = 0;
        foreach (ContainerResourceSnapshot usage in snapshots)
            work = checked(work + usage.ReadBytes + usage.DecodedBytes + usage.NativeReservedReadBytes + usage.NativeReservedDecodedBytes);
        // The older separate host-signature probe reports logical bytes in legacy
        // metrics. Its reserved share is bounded, and is conservatively counted without
        // treating the container's own hash bytes as another full content read.
        return checked(work + Math.Min(signatureBudget, legacy));
    }

    private static void AddOuterRecheck(ScanReport report, string path, MessageText detail)
    {
        if (report.Findings.Any(f => f.RuleId == "CONTENT-BYTE-BUDGET" && SamePath(f.Target, path))) return;
        report.Findings.Add(new()
        {
            RuleId = "CONTENT-BYTE-BUDGET",
            ReasonCode = ReasonCodes.ReadBudget,
            Category = FindingCategory.Coverage,
            SourceKind = SourceKind,
            Target = path,
            TitleText = MessageText.Create("Backend.Core.RelatedComponentPipeline.AddOuterRecheck.01"),
            DescriptionText = detail + MessageText.Create("Backend.Core.RelatedComponentPipeline.AddOuterRecheck.02"),
            HandlingReason = FindingHandlingReason.IncompleteInspection,
            CanRemediate = false
        });
        report.Coverage = ScanCoverage.Partial;
    }

    private static void AppendContent(ScanReport report, ScanReport content)
    {
        report.Containers = Reporting.ContainerReportMerger.Merge(report, content);
        foreach (Finding finding in content.Findings) if (!report.Findings.Any(old => FindingKey(old) == FindingKey(finding))) report.Findings.Add(finding);
        report.RootSummaries.AddRange(content.RootSummaries);
        foreach (MessageText note in content.CoverageTexts.Where(n => !report.CoverageNotes.Contains(n.OriginalText))) report.AddCoverageNote(note);
        report.CoverageNotices.AddRange(content.CoverageNotices);
        ScanExecutionState combinedState = ScanExecution.Combine(report.ExecutionState, content.ExecutionState);
        if (combinedState != report.ExecutionState) report.ExecutionReasonCode = content.ExecutionReasonCode;
        report.ExecutionState = combinedState;
        report.StatusSchemaVersion = Math.Max(report.StatusSchemaVersion, content.StatusSchemaVersion);
        report.CoverageAggregates.AddRange(content.CoverageAggregates);
        foreach (MessageText source in content.CustomSourceNames()) report.AddContentSource(source);
        report.Metrics.FilesVisited += content.Metrics.FilesVisited; report.Metrics.BytesHashed += content.Metrics.BytesHashed;
        report.Metrics.ArchiveEntriesVisited += content.Metrics.ArchiveEntriesVisited; report.Metrics.ArchiveBytesExpanded += content.Metrics.ArchiveBytesExpanded;
        report.Metrics.MediaStructuresChecked += content.Metrics.MediaStructuresChecked;
        report.WorkerDiagnostics = content.WorkerDiagnostics ?? report.WorkerDiagnostics;
        if (content.Coverage != ScanCoverage.Complete || report.Containers is { Complete: false }) report.Coverage = ScanCoverage.Partial;
    }

    private static bool IsSafeCandidate(string path, ScanOptions options) => ContentDiscovery.IsLocalSafePath(path) &&
        !RelatedArtifactReader.IsProtected(path) && !options.ExcludedRoots.Any(root => ContentDiscovery.IsWithin(path, root)) && File.Exists(path);
    private static bool SamePath(string? left, string? right) => left is not null && right is not null && RelatedArtifactRelations.SamePath(left, right);
    private static string FindingKey(Finding f) => string.Join("|", f.RuleId, f.Target.ToUpperInvariant(), f.ContentPath, f.TargetSha256 ?? f.Sha256,
        f.ProcessId, f.ProcessStartedAtUtc, f.RelatedFilePath?.ToUpperInvariant(), f.RelatedFileSha256, f.RegistryHive, f.RegistryView, f.RegistryKey, f.RegistryValueName, f.ConfigurationSnapshot);

    internal static void Check(RelatedComponentDiagnosticReport diagnostic, string code, MessageText name, DiagnosticReadStatus status, MessageText detail, string? observationId = null)
    {
        if (diagnostic.Checks.Count < 2047) diagnostic.Checks.Add(new() { CheckCode = code, NameText = name, Status = status, DetailText = detail, ObservationId = observationId });
        else if (!diagnostic.Checks.Any(c => c.CheckCode == "related.total_check_limit"))
            diagnostic.Checks.Add(new()
            {
                CheckCode = "related.total_check_limit",
                NameText = MessageText.Create("Backend.Core.RelatedComponentPipeline.Check.01"),
                Status = DiagnosticReadStatus.LimitReached,
                DetailText = MessageText.Create("Backend.Core.RelatedComponentPipeline.Check.02")
            });
    }

    internal static void MarkIncomplete(ScanReport report, RelatedComponentDiagnosticReport diagnostic)
    {
        foreach (DiagnosticCheck check in diagnostic.Checks.Where(TrustProxyCorrelator.IsIncomplete))
        {
            report.Coverage = ScanCoverage.Partial;
            if (report.Findings.Any(f => f.RuleId == "ASSOCIATION-COVERAGE" && f.AssociationObservationIds.Contains(check.Id))) continue;
            report.Findings.Add(new()
            {
                RuleId = "ASSOCIATION-COVERAGE",
                ReasonCode = ReasonCodes.ForReadStatus(check.Status),
                Category = FindingCategory.Coverage,
                SourceKind = SourceKind,
                TitleText = MessageText.Create("Backend.Core.RelatedComponentPipeline.MarkIncomplete.01"),
                TargetText = check.NameText,
                DescriptionText = check.DetailText,
                EvidenceText = check.Status.ToString(),
                HandlingReason = FindingHandlingReason.IncompleteInspection,
                AssociationObservationIds = [check.Id],
                AssociationEvidenceTier = RelatedEvidenceTier.Observation
            });
        }
    }

    private sealed class RelatedBudgetException : IOException
    {
        public RelatedBudgetException(MessageText message) : base(message.OriginalText) { MessageExceptions.Attach(this, message); }
    }
}

internal static class RelatedContentSourceExtensions
{
    internal static IEnumerable<MessageText> CustomSourceNames(this ScanReport content) => content.Roots.Select(path => MessageText.Create("Backend.Core.RelatedComponentPipeline.CustomSourceNames.01") + path);
}
