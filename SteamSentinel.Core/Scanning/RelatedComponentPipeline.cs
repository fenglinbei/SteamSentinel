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
        progress?.Report(new("组件关联", "启动入口与已加载模块", 0, null, "只读收集精确候选，未知组件交由受限扫描组件检查"));
        Collect(report, options, diagnostic, limits, token);
        foreach (RelatedComponentCandidate candidate in diagnostic.Candidates.Where(c => IsSafeCandidate(c.Path, options)))
            if (!report.CandidateRoots.Contains(candidate.Path, StringComparer.OrdinalIgnoreCase)) report.CandidateRoots.Add(candidate.Path);
        report.ScopeNotes.Add("组件关联：启动命令、宿主及已加载模块为只读观察；同目录、文件名、有效签名或同机代理不授权隔离，也不能定位写入者。");
        MarkIncomplete(report, diagnostic);
    }

    public async Task<ScanReport> CompleteAsync(ScanReport report, ScanOptions originalContentOptions,
        Func<ScanOptions, IProgress<ScanProgress>?, CancellationToken, Task<ScanReport>> scanContent,
        IProgress<ScanProgress>? progress = null, CancellationToken token = default, RelatedComponentLimits? limits = null)
    {
        limits ??= report.RelatedComponentDiagnostics?.AppliedLimits ?? new();
        if (limits.MaximumRounds is < 0 or > 2 || limits.MaximumCandidates is < 0 or > 128 ||
            limits.MaximumTotalBytes < 0 || limits.MaximumFileBytes < 0 || limits.MaximumDuration < TimeSpan.Zero)
            throw new ArgumentOutOfRangeException(nameof(limits), "组件补查最多两轮、128个候选，字节和时间限额不得为负数。");
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
            candidate.ContentDetail = summary.Coverage == ScanCoverage.Complete
                ? "此精确文件已在原内容阶段完成支持范围内的检查；没有命中不等于未知威胁已排除。"
                : "原内容阶段未完成此精确目标，不把未命中视为排除。";
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
                progress?.Report(new("组件关联", $"第 {number} 轮", number - 1, limits.MaximumRounds, "核对内容证据与启动入口、宿主和模块，再补查新增的精确目标"));
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
                    { round.Status = DiagnosticReadStatus.Complete; round.Detail = "本轮没有新增的精确内容候选，已回填可验证关系。"; break; }

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
                                    throw new RelatedBudgetException("剩余关联字节预算不足或超过单文件上限，未核验或补查该文件。");
                                candidate.Length = lease.Length;
                                candidate.Sha256 = await Hashing.Sha256StreamAsync(lease, bounded, bytes => consumed += bytes);
                                candidate.VerifiedAtUtc = DateTimeOffset.UtcNow;
                                reservedContentBytes += lease.Length * 2;
                                candidate.Status = DiagnosticReadStatus.Complete;
                                candidate.Detail = "使用拒绝写入和删除的只读句柄核验身份，补查结束后释放；未强行解锁。";
                                leases.Add((candidate, lease)); lease = null;
                            }
                            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or Win32Exception)
                            {
                                candidate.Status = candidate.ContentStatus = ex is RelatedBudgetException ? DiagnosticReadStatus.LimitReached :
                                    ex is UnauthorizedAccessException || ex is Win32Exception { NativeErrorCode: 5 } ? DiagnosticReadStatus.AccessDenied : DiagnosticReadStatus.Failed;
                                candidate.Detail = candidate.ContentDetail = ex.Message;
                                Check(diagnostic, "精确文件核验", candidate.Status, ex.Message, candidate.Id);
                                if (ex is RelatedBudgetException) AddOuterRecheck(report, candidate.Path, ex.Message);
                            }
                            finally { if (lease is not null) await lease.DisposeAsync(); }
                        }
                        if (leases.Count > 0 || signatures.Count > 0)
                        {
                            long remaining = Math.Max(0, limits.MaximumTotalBytes - consumed);
                            if (remaining - signatureBudget < 2)
                            {
                                Check(diagnostic, "关联容器补查预算", DiagnosticReadStatus.LimitReached, "剩余关联预算不足以建立容器读取与展开限额，未启动后续内容检查。");
                                foreach (var held in leases) AddOuterRecheck(report, held.Candidate.Path, "关联补查预算已用尽。");
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
                                { pathValid = false; Check(diagnostic, "补查后路径身份", DiagnosticReadStatus.Failed, ex.Message, candidate.Id); }
                                bool mismatch = !pathValid || content.Findings.Where(f => SamePath(f.Target, candidate.Path))
                                    .Select(f => f.TargetSha256 ?? (f.ContentPath is null || SamePath(f.ContentPath, f.Target) ? f.Sha256 : null))
                                    .Any(hash => hash is not null && !hash.Equals(candidate.Sha256, StringComparison.OrdinalIgnoreCase));
                                ScanRootSummary? summary = content.RootSummaries.LastOrDefault(r => SamePath(r.Path, candidate.Path));
                                bool complete = !mismatch && summary?.Coverage == ScanCoverage.Complete;
                                candidate.ContentStatus = complete ? DiagnosticReadStatus.Complete : DiagnosticReadStatus.NotChecked;
                                candidate.ContentDetail = complete ? "受限组件已读取固定身份的目标，未发现不等于未知威胁已排除。" :
                                    mismatch ? "内容结果与已固定的文件身份不一致，已拒绝该目标的处置资格。" : "受限组件没有完成此目标的全部支持范围检查，具体缺口已保留。";
                                if (mismatch) content.Findings.RemoveAll(f => SamePath(f.Target, candidate.Path));
                                if (!complete) Check(diagnostic, "新增组件内容检查", DiagnosticReadStatus.NotChecked, candidate.ContentDetail, candidate.Id);
                            }
                            AppendContent(report, content);
                        }
                        round.Status = diagnostic.Candidates.Where(c => round.CandidateIds.Contains(c.Id)).All(c => c.ContentStatus == DiagnosticReadStatus.Complete)
                            ? DiagnosticReadStatus.Complete : DiagnosticReadStatus.NotChecked;
                        round.Detail = "新增候选已交给受限组件；文件身份、内容缺口和原始扫描范围分别保留。";
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
                Check(diagnostic, "剩余文件证据关联", DiagnosticReadStatus.LimitReached,
                    "轮次或身份核验预算结束，未完成此文件证据的宿主及启动关联复核：" + pendingProof.Target);
            foreach (RelatedComponentCandidate candidate in diagnostic.Candidates.Where(c => !visited.Contains(c.Path)))
            {
                candidate.ContentStatus = DiagnosticReadStatus.LimitReached;
                candidate.ContentDetail = "达到关联轮数、范围或字节上限，未补查此候选。可使用原始文件路径单独完整内容补查：" + candidate.Path;
                AddOuterRecheck(report, candidate.Path, candidate.ContentDetail);
                Check(diagnostic, "剩余组件候选", DiagnosticReadStatus.LimitReached, candidate.ContentDetail, candidate.Id);
            }
        }
        catch (OperationCanceledException)
        {
            DiagnosticReadStatus state = token.IsCancellationRequested ? DiagnosticReadStatus.Cancelled : DiagnosticReadStatus.LimitReached;
            if (diagnostic.Rounds.LastOrDefault() is { Status: DiagnosticReadStatus.NotChecked } round)
            { round.Status = state; round.CompletedAtUtc = DateTimeOffset.UtcNow; }
            Check(diagnostic, "组件关联补查", state, token.IsCancellationRequested ? "已取消；保留此前观察、内容结果和未完成对象。" : "达到关联时间预算；保留已取得的结果。");
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        { Check(diagnostic, "组件关联补查", DiagnosticReadStatus.Failed, "补查未完成：" + ex.Message); }
        finally
        {
            diagnostic.CompletedAtUtc = DateTimeOffset.UtcNow;
            report.CompletedAtUtc = diagnostic.CompletedAtUtc;
            report.ContentScanSettings = originalSettings;
            report.ScopeNotes.Add($"组件关联：最多 {limits.MaximumRounds} 轮新增目标内容补查；本次关联核验与补查累计计入 {consumed} 字节，用时 {elapsed.Elapsed.TotalSeconds:F1} 秒。容器按实际流读取、解码和原生预留计量，另对宿主签名预算保守计入；不是物理I/O。关联补查使用较窄预算，大归档未必完成，可按原始外层文件单独补查。原内容范围与设置未被补查覆盖。");
            MarkIncomplete(report, diagnostic);
        }
        return report;
    }

    private void Collect(ScanReport report, ScanOptions options, RelatedComponentDiagnosticReport output, RelatedComponentLimits limits, CancellationToken token)
    {
        try
        {
            if (string.IsNullOrWhiteSpace(output.TargetUserSid)) { Check(output, "组件采集用户身份", DiagnosticReadStatus.Failed, "无法取得目标用户 SID，未进行当前用户采集。"); return; }
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
        catch (OperationCanceledException) { Check(output, "组件来源采集", DiagnosticReadStatus.Cancelled, "来源采集已取消，保留已读取记录。"); throw; }
        catch (Exception ex) when (ex is not OutOfMemoryException) { Check(output, "组件来源采集", DiagnosticReadStatus.Failed, ex.Message); }
    }

    private async Task<long> CloseEvidenceAsync(ScanReport report, long budget, CancellationToken token, HashSet<string> closed)
    {
        Finding[] evidence = report.Findings.Where(RelatedArtifactRelations.IsFileEvidence).Reverse().DistinctBy(ClosureKey)
            .OrderBy(f => closed.Contains(ClosureKey(f))).Take(64).ToArray();
        if (evidence.Length == 0) return 0;
        if (budget <= 0) { Check(report.RelatedComponentDiagnostics!, "关联身份复核", DiagnosticReadStatus.LimitReached, "没有剩余字节预算，未重核启动与加载关系。"); return 0; }
        RelatedArtifactExpansion closure = await _expand(evidence, report, token, budget);
        foreach (Finding finding in evidence) closed.Add(ClosureKey(finding));
        foreach (Finding finding in closure.Findings.Where(f => f.Category is FindingCategory.Process or FindingCategory.Persistence))
            if (!report.Findings.Any(old => FindingKey(old) == FindingKey(finding))) report.Findings.Add(finding);
        foreach (string scope in closure.ScopeNotes) if (!report.ScopeNotes.Contains(scope)) report.ScopeNotes.Add(scope);
        foreach (string note in closure.Notes) Check(report.RelatedComponentDiagnostics!, "内容证据关联复核", DiagnosticReadStatus.NotChecked, note);
        return closure.VerificationBytesRead;
    }

    private static string ClosureKey(Finding finding) => finding.Target.ToUpperInvariant() + "|" + RelatedArtifactRelations.FileHash(finding)?.ToUpperInvariant();

    internal static ScanOptions FollowUpOptions(ScanOptions original, List<string> paths, long remaining,
        List<string>? signatures = null, long signatureBudget = 0)
    {
        if (signatureBudget < 0 || remaining < signatureBudget || remaining - signatureBudget < 2)
            throw new ArgumentOutOfRangeException(nameof(remaining), "关联补查没有可分配的容器读取与展开预算。");
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
            UseAmsi = original.UseAmsi,
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

    private static void AddOuterRecheck(ScanReport report, string path, string detail)
    {
        if (report.Findings.Any(f => f.RuleId == "CONTENT-BYTE-BUDGET" && SamePath(f.Target, path))) return;
        report.Findings.Add(new()
        {
            RuleId = "CONTENT-BYTE-BUDGET",
            Category = FindingCategory.Coverage,
            SourceKind = SourceKind,
            Target = path,
            Title = "关联补查未覆盖完整原始文件",
            Description = detail + " 关联补查保留较窄预算，不能代表大归档已完成。请按此原始外层文件路径单独补查。",
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
        report.CoverageNotes.AddRange(content.CoverageNotes.Where(n => !report.CoverageNotes.Contains(n)));
        report.CoverageAggregates.AddRange(content.CoverageAggregates);
        report.ContentSources.AddRange(content.CustomSourceNames());
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

    internal static void Check(RelatedComponentDiagnosticReport diagnostic, string name, DiagnosticReadStatus status, string detail, string? observationId = null)
    {
        if (diagnostic.Checks.Any(c => c.Name == name && c.Status == status && c.Detail == detail && c.ObservationId == observationId)) return;
        if (diagnostic.Checks.Count < 2047) diagnostic.Checks.Add(new() { Name = name, Status = status, Detail = detail, ObservationId = observationId });
        else if (!diagnostic.Checks.Any(c => c.Name == "累计关联检查说明限额"))
            diagnostic.Checks.Add(new()
            {
                Name = "累计关联检查说明限额",
                Status = DiagnosticReadStatus.LimitReached,
                Detail = "累计检查说明达到2048项上限，其余逐项缺口未保存，检查不能视为完整。"
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
                Category = FindingCategory.Coverage,
                SourceKind = SourceKind,
                Title = "组件关联检查未完成",
                Target = check.Name,
                Description = check.Detail,
                Evidence = check.Status.ToString(),
                HandlingReason = FindingHandlingReason.IncompleteInspection,
                AssociationObservationIds = [check.Id],
                AssociationEvidenceTier = RelatedEvidenceTier.Observation
            });
        }
    }

    private sealed class RelatedBudgetException(string message) : IOException(message);
}

internal static class RelatedContentSourceExtensions
{
    internal static IEnumerable<string> CustomSourceNames(this ScanReport content) => content.Roots.Select(path => "关联补查精确目标：" + path);
}
