using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using SteamSentinel.Core.Models;
using SteamSentinel.Core.Reporting;
using SteamSentinel.Core.Scanning;
using SteamSentinel.Core.Utilities;

namespace SteamSentinel.SelfTest;

internal static partial class Program
{
    /// <summary>
    /// Explicit native discovery probe. Only CollectInitial runs: no content worker,
    /// signature probe, sample execution, network request, or configuration mutation.
    /// The only writes are two uniquely named JSON files in outputDirectory.
    /// </summary>
    private static async Task<int> RunPhase2NativeSmokeAsync(string outputDirectory)
    {
        string directory = Path.GetFullPath(outputDirectory);
        Directory.CreateDirectory(directory);
        string prefix = $"native-related-components-{DateTimeOffset.UtcNow:yyyyMMdd-HHmmssfff}-{Guid.NewGuid():N}";
        string reportName = prefix + ".report.json", summaryName = prefix + ".summary.json";
        RelatedComponentLimits limits = new();
        ScanOptions options = new()
        {
            Mode = ScanMode.Custom,
            IncludeSystem = true,
            IncludeSteam = false,
            IncludeWorkshop = false,
            IncludeRelatedContent = false,
            IncludeDownloadLocations = false,
            IncludeExecutionHistory = false,
            InspectArchives = false,
            UseAmsi = false,
            HashEveryFile = false
        };
        ScanReport report = new() { Mode = ScanMode.Custom };
        List<Phase2NativeCheck> checks = [];
        List<string> unexpected = [];
        void Verify(string name, bool passed, string detail) => checks.Add(new(name, passed, detail));
        string? expectedSid = null;
        Stopwatch timer = Stopwatch.StartNew();
        using CancellationTokenSource deadline = new(TimeSpan.FromSeconds(60));
        try
        {
            using WindowsIdentity identity = WindowsIdentity.GetCurrent();
            expectedSid = identity.User?.Value;
            new RelatedComponentPipeline().CollectInitial(report, options, token: deadline.Token, limits: limits);
        }
        catch (Exception ex) when (ex is not OutOfMemoryException) { unexpected.Add(ex.ToString()); }
        timer.Stop();
        report.CompletedAtUtc = DateTimeOffset.UtcNow;
        RelatedComponentDiagnosticReport? diagnostic = report.RelatedComponentDiagnostics;
        // CollectInitial is normally followed by content closure. This explicit discovery-only
        // harness finalizes its snapshot, without claiming that content closure was performed.
        if (diagnostic is not null) diagnostic.CompletedAtUtc = report.CompletedAtUtc;
        Verify("WindowsNativeCollector", OperatingSystem.IsWindows(), RuntimeInformation.OSDescription);
        Verify("DiagnosticPresent", diagnostic is not null, "真实采集应保留结构化来源或明确的读取缺口。");
        string[] knownKinds = ["Run", "StartupFile", "StartupDirectory", "Task", "TaskEnumeration", "Service", "ServiceDll", "ServiceEnumeration"];
        if (diagnostic is not null)
        {
            Verify("TargetUserSidMatches", !string.IsNullOrWhiteSpace(expectedSid) && diagnostic.TargetUserSid == expectedSid,
                "与调用前 WindowsIdentity 的实际用户 SID 一致；未改用其他账户视图。");
            Verify("NativeSourceKinds", diagnostic.Sources.All(s => knownKinds.Contains(s.Kind, StringComparer.Ordinal)),
                string.Join(", ", diagnostic.Sources.Select(s => s.Kind).Distinct().Order()));
            Verify("NativeSourceScopes", diagnostic.Sources.All(s => s.Scope is "CurrentUser" or "LocalMachine") &&
                diagnostic.Sources.Where(s => s.Scope == "CurrentUser").All(s => s.UserSid == diagnostic.TargetUserSid),
                "用户来源绑定目标 SID；系统任务可保留其原始运行账户，不混作当前用户。");
            string[] sourceIds = diagnostic.Sources.Select(s => s.Id).ToArray();
            string[] hostIds = diagnostic.Hosts.Select(h => h.Id).ToArray();
            string[] candidateIds = diagnostic.Candidates.Select(c => c.Id).ToArray();
            string[] allIds = sourceIds.Concat(hostIds).Concat(candidateIds).Concat(diagnostic.Checks.Select(c => c.Id)).ToArray();
            HashSet<string> sources = sourceIds.ToHashSet(StringComparer.Ordinal), hosts = hostIds.ToHashSet(StringComparer.Ordinal),
                candidates = candidateIds.ToHashSet(StringComparer.Ordinal), ids = allIds.ToHashSet(StringComparer.Ordinal);
            static bool References(List<string> references, HashSet<string> expected) =>
                references.Count == references.Distinct(StringComparer.Ordinal).Count() && references.All(expected.Contains);
            Verify("UniqueInternalIds", allIds.All(id => !string.IsNullOrWhiteSpace(id)) && ids.Count == allIds.Length,
                $"{allIds.Length} 个来源、宿主、候选和检查 ID 唯一且非空。");
            Verify("TypedHostAndCandidateReferences", diagnostic.Hosts.All(h => References(h.SourceObservationIds, sources)) &&
                diagnostic.Candidates.All(c => References(c.SourceObservationIds, sources) && References(c.HostObservationIds, hosts) &&
                    References(c.EvidenceObservationIds, ids)), "来源和宿主引用均指向对应类型的现存对象；证据引用存在且无重复。");
            Verify("CheckAndFindingReferences", diagnostic.Checks.All(c => c.ObservationId is null || ids.Contains(c.ObservationId)) &&
                report.Findings.All(f => References(f.AssociationObservationIds, ids)) &&
                diagnostic.Rounds.All(r => References(r.CandidateIds, candidates)), "检查、覆盖发现和轮次不含悬空 ID。");
            Verify("TypedNativeRelations", diagnostic.Relations.All(r => ids.Contains(r.FromId) && ids.Contains(r.ToId) && (r.Kind switch
            {
                "SourceReferencesFile" => sources.Contains(r.FromId) && candidates.Contains(r.ToId),
                "SourceAndHostImagePathMatch" => sources.Contains(r.FromId) && hosts.Contains(r.ToId),
                "ObservedLoadedModulePath" => hosts.Contains(r.FromId) && candidates.Contains(r.ToId),
                _ => false
            })), $"{diagnostic.Relations.Count} 条只读关系的类型和两端引用有效。");
            Verify("NativeRecordLimits", diagnostic.Sources.Count <= limits.MaximumSources && diagnostic.Hosts.Count <= limits.MaximumHosts &&
                diagnostic.Candidates.Count <= limits.MaximumCandidates && diagnostic.Checks.Count <= 2048 && diagnostic.Relations.Count <= 4096 &&
                diagnostic.Hosts.All(h => diagnostic.Candidates.Count(c => c.HostObservationIds.Contains(h.Id)) <= limits.MaximumModulesPerHost),
                $"来源 {diagnostic.Sources.Count}/{limits.MaximumSources}；宿主 {diagnostic.Hosts.Count}/{limits.MaximumHosts}；候选 {diagnostic.Candidates.Count}/{limits.MaximumCandidates}；检查 {diagnostic.Checks.Count}；关系 {diagnostic.Relations.Count}。");
            Verify("ValidReadStatusValues", diagnostic.Sources.All(s => Enum.IsDefined(s.Status)) && diagnostic.Hosts.All(h => Enum.IsDefined(h.Status)) &&
                diagnostic.Candidates.All(c => Enum.IsDefined(c.Status) && Enum.IsDefined(c.ContentStatus)) && diagnostic.Checks.All(c => Enum.IsDefined(c.Status)),
                "验证状态枚举有效；AccessDenied、NotChecked、Failed、LimitReached 等实际缺口不作为结构测试失败。");
            Verify("EverySourceHasReadCheck", diagnostic.Sources.All(s => diagnostic.Checks.Any(c => c.ObservationId == s.Id)) ||
                diagnostic.Checks.Any(c => c.Status is DiagnosticReadStatus.LimitReached or DiagnosticReadStatus.Cancelled),
                "每个来源保留读取检查；整体数量或取消上限触发时允许明确记录的未完成尾部。");
            Verify("DiscoveryDidNotClaimContentOrSignatures", diagnostic.Rounds.Count == 0 &&
                diagnostic.Candidates.All(c => c.Sha256 is null && c.VerifiedAtUtc is null && c.ContentStatus != DiagnosticReadStatus.Complete) &&
                diagnostic.Hosts.All(h => h.ImageSha256 is null && h.SignatureStatus == "NotChecked"),
                "只做路径和运行状态观察；没有文件哈希、签名结论或内容补查轮次。");
            Verify("NoActionOrMalwareVerdict", report.Findings.All(f => !f.CanRemediate && !f.IsKnownMalware &&
                f.AssociationEvidenceTier is null or RelatedEvidenceTier.Observation &&
                f.SuggestedActions.All(a => a is SuggestedActionKind.None or SuggestedActionKind.ReviewOnly)),
                "只读采集的覆盖提示不授予处理资格，也不将文件名、同目录或加载关系判为恶意。");
            Verify("NoOtherScanStage", report.TrustProxyDiagnostics is null && report.Metrics.BytesHashed == 0 && report.Metrics.FilesVisited == 0 &&
                report.Metrics.ArchiveEntriesVisited == 0 && report.Metrics.ArchiveBytesExpanded == 0 && report.RootSummaries.Count == 0,
                "未调用系统全扫、内容 worker、证书/代理采集或归档展开；字面脚本和任务元数据仅按发现预算只读解析。");
        }
        Verify("NoEscapedCollectorException", unexpected.Count == 0, string.Join("\n", unexpected));

        JsonSerializerOptions compact = new(JsonFile.Options) { WriteIndented = false };
        int frames = 0, maximumFrameCharacters = 0, maximumFrameUtf8Bytes = 0;
        try
        {
            ReportBatchReader reader = new();
            ReportBatchWriter writer = new(batch =>
            {
                string wire = JsonSerializer.Serialize(new WorkerMessage { Type = WorkerMessageTypes.Checkpoint, Batch = batch }, compact);
                maximumFrameCharacters = Math.Max(maximumFrameCharacters, wire.Length);
                maximumFrameUtf8Bytes = Math.Max(maximumFrameUtf8Bytes, Encoding.UTF8.GetByteCount(wire));
                if (wire.Length >= 1024 * 1024) throw new InvalidDataException("真实采集帧超出通信字符上限。");
                WorkerMessage restored = JsonSerializer.Deserialize<WorkerMessage>(wire, JsonFile.Options)
                    ?? throw new InvalidDataException("真实采集帧反序列化为空。");
                reader.Apply(restored.Batch ?? throw new InvalidDataException("真实采集帧缺少 Batch。"));
                frames++;
            });
            writer.Send(report, final: true);
            Verify("NativeBatchRoundTrip", diagnostic is not null && reader.Report?.RelatedComponentDiagnostics is { } transported &&
                !reader.HasIncompleteRelatedComponentDiagnostics && !reader.HasIncompleteTrustProxyDiagnostics &&
                JsonSerializer.Serialize(transported, compact) == JsonSerializer.Serialize(diagnostic, compact) && reader.Count == writer.Count &&
                reader.Report.CompletedAtUtc == report.CompletedAtUtc && reader.Report.Coverage == report.Coverage &&
                JsonSerializer.Serialize(reader.Report.Findings, compact) == JsonSerializer.Serialize(report.Findings, compact) &&
                reader.Report.CandidateRoots.SequenceEqual(report.CandidateRoots),
                $"实际原生结果经过 {frames} 帧序列化、反序列化和 Reader 校验；诊断全部字段、缺口、发现和候选保持一致。");
        }
        catch (Exception ex) when (ex is not OutOfMemoryException) { Verify("NativeBatchRoundTrip", false, ex.ToString()); }

        // Use the application's export privacy rules for the local artifact. The transport test
        // above compares the full in-memory record, before any deliberate secret redaction.
        await using (FileStream stream = new(Path.Combine(directory, reportName), FileMode.CreateNew, FileAccess.Write, FileShare.Read))
            await JsonSerializer.SerializeAsync(stream, report, ReportPrivacy.ExportOptions);
        try
        {
            ScanReport saved = await JsonFile.ReadAsync<ScanReport>(Path.Combine(directory, reportName));
            ScanReport expected = JsonSerializer.Deserialize<ScanReport>(JsonSerializer.Serialize(report, ReportPrivacy.ExportOptions), JsonFile.Options)!;
            Verify("PersistedExportRoundTrip", JsonSerializer.Serialize(saved.RelatedComponentDiagnostics, compact) ==
                JsonSerializer.Serialize(expected.RelatedComponentDiagnostics, compact) && saved.ScanId == report.ScanId &&
                saved.Findings.Select(f => f.Id).SequenceEqual(report.Findings.Select(f => f.Id)),
                "磁盘 JSON 按应用的隐私导出规则重读，完整诊断及发现 ID 保持一致；命令中秘密值可被标准规则脱敏。");
        }
        catch (Exception ex) when (ex is not OutOfMemoryException) { Verify("PersistedExportRoundTrip", false, ex.ToString()); }
        int failed = checks.Count(c => !c.Passed);
        var summary = new
        {
            SchemaVersion = 1,
            Probe = "RelatedComponentNativeReadOnly",
            report.ProductVersion,
            report.BuildIdentity,
            report.StartedAtUtc,
            report.CompletedAtUtc,
            ElapsedMilliseconds = timer.ElapsedMilliseconds,
            OsDescription = RuntimeInformation.OSDescription,
            ProcessArchitecture = RuntimeInformation.ProcessArchitecture.ToString(),
            FrameworkDescription = RuntimeInformation.FrameworkDescription,
            TargetUserSid = diagnostic?.TargetUserSid,
            Limits = limits,
            ExitCode = failed == 0 ? 0 : 1,
            Passed = checks.Count(c => c.Passed),
            Failed = failed,
            Scope = "只调用 CollectInitial 读取本机当前用户和系统启动来源、有限宿主及模块路径；不执行样本、联网、检查内容/签名或更改配置。仅写这两个 JSON 文件。",
            Interpretation = "通过表示原生采集输出结构、引用、限额及真实通信往返一致；不表示来源齐全、所有命令均已解析或恶意软件已排除。同步本机调用只能在前后协作检查时间预算。",
            SnapshotCompletedBy = "Discovery-only harness; content closure was not run",
            KnownSourceKinds = knownKinds,
            ObservedSourceKinds = diagnostic?.Sources.Select(s => s.Kind).Distinct().Order().ToArray(),
            SourceCounts = diagnostic?.Sources.GroupBy(s => (s.Kind, s.Scope, s.Status)).Select(g => new { g.Key.Kind, g.Key.Scope, g.Key.Status, Count = g.Count() }).ToArray(),
            HostStatusCounts = diagnostic?.Hosts.GroupBy(h => h.Status).ToDictionary(g => g.Key.ToString(), g => g.Count()),
            CandidateStatusCounts = diagnostic?.Candidates.GroupBy(c => c.Status).ToDictionary(g => g.Key.ToString(), g => g.Count()),
            ReadCheckCounts = diagnostic?.Checks.GroupBy(c => c.Status).ToDictionary(g => g.Key.ToString(), g => g.Count()),
            RequiredReadGaps = diagnostic?.Checks.Count(c => c.Required && c.Status is not (DiagnosticReadStatus.Complete or DiagnosticReadStatus.NotPresent)),
            NativeReadChecks = diagnostic?.Checks.Select(c => new { c.Id, c.Name, c.Status, c.Required, c.ObservationId, c.Detail }).ToArray(),
            CandidateCount = diagnostic?.Candidates.Count ?? 0,
            HostCount = diagnostic?.Hosts.Count ?? 0,
            RelationCount = diagnostic?.Relations.Count ?? 0,
            Frames = frames,
            MaximumFrameCharacters = maximumFrameCharacters,
            MaximumFrameUtf8Bytes = maximumFrameUtf8Bytes,
            Checks = checks,
            UnexpectedExceptions = unexpected,
            ReportFile = reportName
        };
        await using (FileStream stream = new(Path.Combine(directory, summaryName), FileMode.CreateNew, FileAccess.Write, FileShare.Read))
            await JsonSerializer.SerializeAsync(stream, summary, ReportPrivacy.ExportOptions);
        Console.WriteLine($"NATIVE_RELATED_COMPONENTS_PASS={checks.Count(c => c.Passed)};FAIL={failed};SOURCES={diagnostic?.Sources.Count ?? 0};HOSTS={diagnostic?.Hosts.Count ?? 0};CANDIDATES={diagnostic?.Candidates.Count ?? 0};FRAMES={frames};ELAPSED_MS={timer.ElapsedMilliseconds}");
        Console.WriteLine("SUMMARY=" + Path.Combine(directory, summaryName));
        Console.WriteLine("REPORT=" + Path.Combine(directory, reportName));
        return failed == 0 ? 0 : 1;
    }

    private sealed record Phase2NativeCheck(string Name, bool Passed, string Detail);
}
