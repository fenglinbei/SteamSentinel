using System.Collections.Concurrent;
using System.Diagnostics;
using System.IO;
using System.IO.Compression;
using SteamSentinel.App;
using SteamSentinel.Core.Models;
using SteamSentinel.Core.Remediation;
using SteamSentinel.Core.Rules;
using SteamSentinel.Core.Scanning;
using SteamSentinel.Core.Utilities;

namespace SteamSentinel.SelfTest;

internal static partial class Program
{
    private sealed class SuiteAccumulator(string name, SuiteAccumulator? parent = null)
    {
        public string Name { get; } = name;
        public int Passed { get; private set; }
        public int Failed => Failures.Count;
        public int Skipped { get; private set; }
        public List<string> Failures { get; } = [];
        public long ElapsedMs { get; set; }

        public void Record(string checkName, bool condition)
        {
            if (condition) Passed++;
            else Failures.Add(checkName);
            parent?.Record(checkName, condition);
        }

        public void RecordSkip()
        {
            Skipped++;
            parent?.RecordSkip();
        }
    }

    private sealed class SubSuiteScope : IDisposable
    {
        private readonly SuiteAccumulator? _previous;
        private bool _disposed;

        public SubSuiteScope(SuiteAccumulator? previous) => _previous = previous;

        public void Dispose()
        {
            if (_disposed) return;
            CurrentSuiteAccumulator.Value = _previous;
            _disposed = true;
        }
    }

    internal sealed class SuiteRunOptions
    {
        public string? ResultsPath { get; set; }
        public string? WatchdogResultsPath { get; set; }
        public string? FindingPriorityResultsPath { get; set; }
        public bool ShowTimings { get; set; }
        public bool FastOnly { get; set; }
        public bool NoParallel { get; set; }
        public List<string> FilterTerms { get; } = [];
    }

    private sealed record TestSuiteDefinition(
        string Name,
        bool ExclusiveSerial,
        bool Slow,
        int EstimatedWeight,
        Func<string, RuleSet, Task> Execute,
        string? ExportGroup = null,
        bool ShareSuiteRoot = false,
        string[]? Prerequisites = null);

    private static readonly object CheckLock = new();
    private static readonly AsyncLocal<SuiteAccumulator?> CurrentSuiteAccumulator = new();
    private static ConcurrentDictionary<string, SuiteAccumulator>? _subSuiteAccumulators;

    /// <summary>进入命名子套件归集作用域，使全量中的嵌套测试能同步导出独立的分项门禁统计。</summary>
    private static IDisposable EnterSubSuite(string name)
    {
        SuiteAccumulator? previous = CurrentSuiteAccumulator.Value;
        ConcurrentDictionary<string, SuiteAccumulator>? subSuites = _subSuiteAccumulators;
        if (subSuites is null) return new SubSuiteScope(previous);
        SuiteAccumulator child = subSuites.GetOrAdd(name, key => new SuiteAccumulator(key, previous));
        CurrentSuiteAccumulator.Value = child;
        return new SubSuiteScope(previous);
    }

    internal static bool TryParseSuiteOptions(string[] args, out SuiteRunOptions? options, out string? error)
    {
        options = null;
        error = null;
        if (args.Length == 0)
        {
            options = new SuiteRunOptions();
            return true;
        }

        if (!IsSuiteArgument(args[0])) return false;

        SuiteRunOptions parsed = new();
        for (int index = 0; index < args.Length; index++)
        {
            string argument = args[index];
            switch (argument)
            {
                case "--results":
                    if (index + 1 >= args.Length || string.IsNullOrWhiteSpace(args[index + 1]))
                    {
                        error = "--results 缺少输出路径参数。";
                        return false;
                    }
                    parsed.ResultsPath = Path.GetFullPath(args[++index]);
                    break;
                case "--watchdog-results":
                    if (index + 1 >= args.Length || string.IsNullOrWhiteSpace(args[index + 1]))
                    {
                        error = "--watchdog-results 缺少输出路径参数。";
                        return false;
                    }
                    parsed.WatchdogResultsPath = Path.GetFullPath(args[++index]);
                    break;
                case "--finding-priority-results":
                    if (index + 1 >= args.Length || string.IsNullOrWhiteSpace(args[index + 1]))
                    {
                        error = "--finding-priority-results 缺少输出路径参数。";
                        return false;
                    }
                    parsed.FindingPriorityResultsPath = Path.GetFullPath(args[++index]);
                    break;
                case "--filter":
                    if (index + 1 >= args.Length || string.IsNullOrWhiteSpace(args[index + 1]))
                    {
                        error = "--filter 缺少筛选关键词。";
                        return false;
                    }
                    foreach (string term in args[++index].Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
                        parsed.FilterTerms.Add(term);
                    if (parsed.FilterTerms.Count == 0)
                    {
                        error = "--filter 至少需要一个有效的套件关键词。";
                        return false;
                    }
                    break;
                case "--timings":
                    parsed.ShowTimings = true;
                    break;
                case "--fast":
                    parsed.FastOnly = true;
                    break;
                case "--no-parallel":
                    parsed.NoParallel = true;
                    break;
                default:
                    error = "未知的自检参数：" + argument;
                    return false;
            }
        }

        if ((parsed.WatchdogResultsPath is not null || parsed.FindingPriorityResultsPath is not null) &&
            (parsed.FastOnly || parsed.FilterTerms.Count > 0))
        {
            error = "--watchdog-results 与 --finding-priority-results 仅允许在完整全量自检中导出，不可与 --fast 或 --filter 联用。";
            return false;
        }

        options = parsed;
        return true;
    }

    private static bool IsSuiteArgument(string argument) => argument is
        "--results" or "--watchdog-results" or "--finding-priority-results" or
        "--filter" or "--timings" or "--fast" or "--no-parallel";

    private static IReadOnlyList<TestSuiteDefinition> BuildAllSuites() =>
    [
        // 优先启动的前置与重型并发套件（LPT 调度）
        new("ContentScanner", false, false, 15, (r, rules) => TestContentScannerAsync(r, rules), ShareSuiteRoot: true),
        new("EncryptedArchive", false, false, 15, (r, rules) => TestEncryptedArchiveAsync(r, rules), ShareSuiteRoot: true),
        new("V0114Coverage", false, true, 120, (r, _) => TestV0114CoverageAsync(r)),
        new("SystemScannerReadOnly", false, true, 110, (_, rules) => TestSystemScannerReadOnlyAsync(rules)),
        new("FirewallVerificationBudget", false, true, 100, (r, _) => TestFirewallVerificationBudgetAsync(r)),
        new("V031CasePersistence", false, true, 95, (r, _) => TestV031CasePersistenceAsync(r)),
        new("V0113", false, true, 92, (r, _) => TestV0113Async(r)),
        new("V020ContainerResources", false, true, 90, (r, _) => TestV020ContainerResourcesAsync(r)),
        new("V031WorkerTextBudgets", false, true, 85, (r, _) => TestV031WorkerTextBudgetsAsync(r)),
        new("V030LanguageSettings", false, true, 80, (r, _) => TestV030LanguageSettingsAsync(r)),
        new("V020ArchiveVolumes", false, true, 75, (r, _) => TestV020ArchiveVolumesAsync(r)),
        new("V020OtherArchives", false, true, 70, (r, _) => TestV020OtherArchivesAsync(r)),
        new("V031ReportBudgets", false, true, 68, (_, _) => { TestV031ReportBudgets(); return Task.CompletedTask; }),
        new("V0114Broker", false, true, 66, (r, _) => TestV0114BrokerAsync(r)),
        new("V030", false, true, 64, (r, _) => TestV030Async(r)),
        new("V030AdaptiveScan", false, true, 62, (r, _) => TestV030AdaptiveScanAsync(r)),
        new("V0117Scanner", false, false, 61, (r, _) => TestV0117ScannerAsync(r)),
        new("Phase3Cases", false, false, 61, (r, _) => TestPhase3CasesAsync(r)),
        new("SteamAlertWatchdogHost", false, false, 60, (r, _) => TestSteamAlertWatchdogHostAsync(r), ExportGroup: "Watchdog"),
        new("V015", false, false, 55, (r, rules) => TestV015Async(r, rules)),
        new("ScanLimitSettings", false, false, 35, (r, _) => TestScanLimitSettingsAsync(r)),
        new("V0112", false, false, 24, (r, _) => TestV0112Async(r)),
        new("V0111", false, false, 22, (r, rules) => TestV0111Async(r, rules)),
        new("V017", false, false, 20, (r, _) => TestV017Async(r)),
        new("Phase2Msi", false, false, 18, (r, rules) => TestPhase2MsiAsync(r, rules)),
        new("Phase2Pipeline", false, false, 16, (r, _) => TestPhase2PipelineAsync(r)),
        new("Phase2RelatedSignature", false, false, 14, (r, _) => TestPhase2RelatedSignatureAsync(r)),

        // 其余并发套件
        new("RuleSetAndServiceApp", false, false, 10, (_, rules) =>
        {
            Check("规则集载入", rules.KnownHashes.Count >= 14 && rules.KnownDomains.Contains("luminovastella.top"));
            TestServiceAppCoverage(rules);
            return Task.CompletedTask;
        }),
        new("FindingPriorityPresentation", false, false, 10, (_, _) =>
        {
            TestFindingPriorityPresentation();
            return Task.CompletedTask;
        }, ExportGroup: "FindingPriority"),
        new("FindingPriorityScanner", false, false, 10, (r, _) => TestFindingPriorityScannerAsync(r), ExportGroup: "FindingPriority"),
        new("FileTypes", false, false, 5, (r, _) => TestFileTypesAsync(r)),
        new("JsonFileSynchronizationContext", false, false, 5, (r, _) => TestJsonFileSynchronizationContextAsync(r)),
        new("WriteNewAndDirectoryFingerprint", false, false, 5, (r, _) => TestWriteNewAndDirectoryFingerprintAsync(r)),
        new("SecurityValidation", false, false, 5, (_, _) => { TestSecurityValidation(); return Task.CompletedTask; }),
        new("StartupCompatibility", false, false, 10, (r, _) => TestStartupCompatibilityAsync(r)),
        new("ManagedErrorReports", false, false, 5, (r, _) => TestManagedErrorReportsAsync(r)),
        new("DefaultWallpaperSuppression", false, false, 5, (r, rules) => TestDefaultWallpaperSuppressionAsync(r, rules)),
        new("SteamTamperScanner", false, false, 5, (r, rules) => TestSteamTamperScannerAsync(r, rules)),
        new("V0114Relation", false, false, 10, (r, _) => TestV0114RelationAsync(r)),
        new("V0114Ui", false, false, 5, (r, _) => TestV0114UiAsync(r)),
        new("V0119Copy", false, false, 5, (_, _) => { TestV0119Copy(); return Task.CompletedTask; }),
        new("V0119PasswordBoundaries", false, false, 5, (_, _) => { TestV0119PasswordBoundaries(); return Task.CompletedTask; }),
        new("V020ContainerRanges", false, false, 5, (_, _) => { TestV020ContainerRanges(); return Task.CompletedTask; }),
        new("V020ContainerExport", false, false, 10, (r, _) => TestV020ContainerExportAsync(r)),
        new("V020ContainerMerges", false, false, 10, (r, _) => TestV020ContainerMergesAsync(r)),
        new("V020ContainerReview", false, false, 10, (r, _) => TestV020ContainerReviewAsync(r)),
        new("V020StructuredBudget", false, false, 10, (r, _) => TestV020StructuredBudgetAsync(r)),
        new("V030Status", false, false, 5, (r, _) => TestV030StatusAsync(r)),
        new("V030Resources", false, false, 10, (r, _) => TestV030ResourcesAsync(r)),
        new("V030FalsePositiveStrings", false, false, 10, (r, _) => TestV030FalsePositiveStringsAsync(r)),
        new("V030FalsePositiveFormatPath", false, false, 10, (r, _) => TestV030FalsePositiveFormatPathAsync(r)),
        new("V030FalsePositiveAssociation", false, false, 10, (r, _) => TestV030FalsePositiveAssociationAsync(r)),
        new("V030FalsePositiveScriptConsumers", false, false, 10, (r, _) => TestV030FalsePositiveScriptConsumersAsync(r)),
        new("V030RemediationEvidencePolicy", false, false, 10, (r, _) => TestV030RemediationEvidencePolicyAsync(r)),
        new("V030BrokerPreflight", false, false, 5, (r, _) => TestV030BrokerPreflightAsync(r)),
        new("V030EndedResults", false, false, 5, (r, _) => TestV030EndedResultsAsync(r)),
        new("V030RemediationRecovery", false, false, 5, (r, _) => TestV030RemediationRecoveryAsync(r)),
        new("TrustProxyProxy", false, false, 5, (_, _) => { TestTrustProxyProxy(); return Task.CompletedTask; }),
        new("TrustProxyCertificates", false, false, 5, (_, _) => { TestTrustProxyCertificates(); return Task.CompletedTask; }),
        new("TrustProxyDiagnostics", false, false, 5, (r, _) => TestTrustProxyDiagnosticsAsync(r)),
        new("TrustProxyBatch", false, false, 5, (_, _) => { TestTrustProxyBatch(); return Task.CompletedTask; }),
        new("Phase2Discovery", false, false, 5, (_, _) => { TestPhase2Discovery(); return Task.CompletedTask; }),
        new("Phase2SourceBounds", false, false, 5, (_, _) => { TestPhase2SourceBounds(); return Task.CompletedTask; }),
        new("Phase2RelatedBatch", false, false, 5, (_, _) => { TestPhase2RelatedBatch(); return Task.CompletedTask; }),
        new("Phase2RelatedPresentation", false, false, 5, (r, _) => TestPhase2RelatedPresentationAsync(r)),
        new("Phase3Dependencies", false, false, 5, (r, _) => TestPhase3DependenciesAsync(r)),
        new("Phase3CertificateRepair", false, false, 5, (_, _) => { TestPhase3CertificateRepair(); return Task.CompletedTask; }),
        new("Phase3CertificateAbi", false, false, 5, (_, _) => { TestPhase3CertificateAbi(); return Task.CompletedTask; }),
        new("Phase3ProxyRepair", false, false, 5, (_, _) => { TestPhase3ProxyRepair(); return Task.CompletedTask; }),
        new("Phase3ConfigurationBroker", false, false, 5, (_, _) => TestPhase3ConfigurationBrokerAsync()),
        new("Phase3CaseExport", false, false, 10, (r, _) => TestPhase3CaseExportAsync(r)),
        new("V0117Security", false, false, 10, (r, _) => TestV0117SecurityAsync(r)),
        new("V0117ReleaseEngineering", false, false, 10, (_, _) => { TestV0117ReleaseEngineering(); return Task.CompletedTask; }),
        new("PlanBuilder", false, false, 5, (r, rules) => TestPlanBuilderAsync(r, rules)),
        new("V030RemediationScope", false, false, 5, (_, _) => { TestV030RemediationScope(); return Task.CompletedTask; }),
        new("V032CoreScope", false, false, 5, (r, _) => TestV032CoreScopeAsync(r)),
        new("SteamAlert", false, false, 10, (r, _) => TestSteamAlertAsync(r)),
        new("SteamAlertWatchdogDiscovery", false, false, 10, (r, _) => TestSteamAlertWatchdogDiscoveryAsync(r), ExportGroup: "Watchdog"),
        new("SteamAlertWatchdogBroker", false, false, 10, (r, _) => TestSteamAlertWatchdogBrokerAsync(r), ExportGroup: "Watchdog"),
        new("SteamAlertWatchdogPlan", false, false, 10, (r, _) => TestSteamAlertWatchdogPlanAsync(r), ExportGroup: "Watchdog"),
        new("SteamAlertUpdateHandoff", false, false, 10, (r, _) => TestSteamAlertUpdateHandoffAsync(r), ExportGroup: "Watchdog"),
        new("SteamAlertHandoffBroker", false, false, 10, (r, _) => TestSteamAlertHandoffBrokerAsync(r), ExportGroup: "Watchdog"),
        new("SteamAlertHandoffDiscovery", false, false, 10, (r, _) => TestSteamAlertHandoffDiscoveryAsync(r), ExportGroup: "Watchdog"),
        new("SteamAlertClosure", false, false, 10, (r, _) => TestSteamAlertClosureAsync(r), ExportGroup: "Watchdog"),
        new("SteamAlertEmbeddedEvidence", false, false, 10, (r, _) => TestSteamAlertEmbeddedEvidenceAsync(r)),
        new("BoundBrokerPlan", false, false, 5, (_, _) => TestBoundBrokerPlanAsync()),
        new("SecureFileLease", false, false, 5, (r, _) => TestSecureFileLeaseAsync(r)),
        new("ReportExport", false, false, 5, (r, rules) => TestReportExportAsync(r, rules)),
        new("DisplayLabelsAndProcessGate", false, false, 5, (_, _) =>
        {
            Check("Steam 进程门禁不误判 SteamSentinel", MainWindow.IsSteamClientProcessName("steam") &&
                                                     MainWindow.IsSteamClientProcessName("steamwebhelper") &&
                                                     !MainWindow.IsSteamClientProcessName("SteamSentinel"));
            TestDisplayLabels();
            return Task.CompletedTask;
        }),
        new("SteamDiscovery", false, false, 5, (_, _) => { TestSteamDiscovery(); return Task.CompletedTask; }),
        new("P2ADetectionPerformance", false, false, 10, (r, _) => TestP2ADetectionPerformanceAsync(r)),
        new("SelfTestHarness", false, false, 5, (_, _) =>
        {
            TestSelfTestHarnessContracts();
            return Task.CompletedTask;
        }),
        new("WorkerProtocol", false, false, 12, async (r, _) =>
        {
            EnsureMinimalContentFixture(r);
            await TestWorkerProtocolAsync(r);
        }, ShareSuiteRoot: true, Prerequisites: ["ContentScanner", "EncryptedArchive"]),
        new("RestrictedWorkerClient", false, false, 12, async (r, _) =>
        {
            EnsureMinimalContentFixture(r);
            await TestRestrictedWorkerClientAsync(r);
        }, ShareSuiteRoot: true, Prerequisites: ["ContentScanner"]),

        // 独占串行套件（修改全局环境变量、进程语言、进程级 Token 特权、静态超时、目录/进程快照、真实 HKCU 或唯一 WPF Application）
        new("V018", true, true, 50, (r, _) => TestV018Async(r)),
        new("V0117Ui", true, true, 40, (r, _) => TestV0117UiAsync(r)),
        new("V0119Passwords", true, true, 60, (r, rules) => TestV0119PasswordsAsync(r, rules)),
        new("V016", true, true, 60, (r, rules) => TestV016Async(r, rules)),
        new("V030BackendMessages", true, false, 10, (r, _) => TestV030BackendMessagesAsync(r)),
        new("V0116", true, false, 15, (r, _) => TestV0116Async(r)),
        new("RemediationModes", true, false, 10, (r, _) => TestRemediationModesAsync(r)),
        new("SteamConfigurationRepair", true, false, 10, (r, _) => TestSteamConfigurationRepairAsync(r)),
        new("P2BSteamRecovery", true, false, 10, (r, _) => TestP2BSteamRecoveryAsync(r)),
        new("V032BrokerScope", true, false, 10, (r, _) => TestV032BrokerScopeAsync(r)),
        new("BrokerScopeDiagnostics", true, false, 10, (r, _) => TestBrokerScopeDiagnosticsAsync(r))
    ];

    private static void EnsureMinimalContentFixture(string root)
    {
        string contentDir = Path.Combine(root, "content");
        string renamed = Path.Combine(contentDir, "renamed.mp4");
        if (File.Exists(renamed)) return;
        Directory.CreateDirectory(contentDir);
        CreateZip(renamed, archive =>
        {
            using StreamWriter writer = new(archive.CreateEntry("wallpaper.jpg").Open());
            writer.Write("inert minimal worker fixture");
        });
    }

    private static void TestSelfTestHarnessContracts()
    {
        RuleSet rules = new();
        LiveAssociationProbeMode defaultScannerMode = (LiveAssociationProbeMode)typeof(RelatedArtifactScanner)
            .GetField("_liveProbeMode", System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic)!
            .GetValue(new RelatedArtifactScanner(rules))!;
        LiveAssociationProbeMode defaultPlannerMode = (LiveAssociationProbeMode)typeof(RemediationBatchPlanner)
            .GetField("_liveProbeMode", System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic)!
            .GetValue(new RemediationBatchPlanner(rules))!;
        Check("自检夹具 默认关联扫描与批量规划器保持真实宿主机实时探测",
            defaultScannerMode == LiveAssociationProbeMode.HostLive &&
            defaultPlannerMode == LiveAssociationProbeMode.HostLive);

        Check("自检夹具 拒绝非全量模式下导出分项门禁报告",
            !TryParseSuiteOptions(["--fast", "--watchdog-results", "wd.json"], out _, out string? fastError) &&
            !string.IsNullOrWhiteSpace(fastError) &&
            !TryParseSuiteOptions(["--filter", "P2A", "--finding-priority-results", "fp.json"], out _, out string? filterError) &&
            !string.IsNullOrWhiteSpace(filterError));

        Check("自检夹具 完整导出参数与计时筛选参数解析准确",
            TryParseSuiteOptions(["--results", "r.json", "--watchdog-results", "w.json", "--finding-priority-results", "f.json", "--timings"],
                out SuiteRunOptions? fullParsed, out string? noError) &&
            noError is null && fullParsed is { ShowTimings: true, FastOnly: false } &&
            fullParsed.WatchdogResultsPath is not null && fullParsed.FindingPriorityResultsPath is not null);
    }

    private static async Task<int> RunSelectedSuitesAsync(string root, RuleSet rules, SuiteRunOptions options)
    {
        IReadOnlyList<TestSuiteDefinition> allSuites = BuildAllSuites();
        bool hasFilter = options.FilterTerms.Count > 0;
        List<TestSuiteDefinition> selected = [];
        int fastSkipped = 0;

        foreach (TestSuiteDefinition suite in allSuites)
        {
            if (hasFilter && !options.FilterTerms.Any(term => suite.Name.Contains(term, StringComparison.OrdinalIgnoreCase)))
                continue;
            if (options.FastOnly && suite.Slow)
            {
                fastSkipped++;
                continue;
            }
            selected.Add(suite);
        }

        if (selected.Count == 0)
        {
            Console.Error.WriteLine("没有匹配当前 --filter / --fast 条件的测试套件。");
            return 2;
        }

        if (options.FastOnly)
        {
            Console.WriteLine($"[FAST MODE] 已启用快速开发模式：跳过 {fastSkipped} 个耗时外部进程/真环境套件（仅限本地迭代，不替代发版/提交前全量门禁）。");
        }

        Stopwatch totalClock = Stopwatch.StartNew();
        ConcurrentDictionary<string, SuiteAccumulator> accumulators = new(StringComparer.OrdinalIgnoreCase);
        _subSuiteAccumulators = new ConcurrentDictionary<string, SuiteAccumulator>(StringComparer.OrdinalIgnoreCase);
        try
        {
            List<TestSuiteDefinition> parallelSuites = selected.Where(s => !s.ExclusiveSerial).ToList();
            List<TestSuiteDefinition> serialSuites = selected.Where(s => s.ExclusiveSerial).ToList();

            Dictionary<string, TaskCompletionSource> completionSignals = parallelSuites.ToDictionary(
                s => s.Name,
                _ => new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously),
                StringComparer.OrdinalIgnoreCase);

            async Task ExecuteSuiteAsync(TestSuiteDefinition suite)
            {
                SuiteAccumulator accumulator = new(suite.Name);
                accumulators[suite.Name] = accumulator;
                string suiteRoot = suite.ShareSuiteRoot ? root : Path.Combine(root, "_suites", suite.Name);
                Directory.CreateDirectory(suiteRoot);

                CurrentSuiteAccumulator.Value = accumulator;
                Stopwatch suiteClock = Stopwatch.StartNew();
                try
                {
                    await suite.Execute(suiteRoot, rules);
                }
                catch (Exception ex)
                {
                    Check($"{suite.Name}: 未处理异常 ({ex.GetType().Name})", false);
                    Console.Error.WriteLine(ex);
                }
                finally
                {
                    suiteClock.Stop();
                    accumulator.ElapsedMs = suiteClock.ElapsedMilliseconds;
                    CurrentSuiteAccumulator.Value = null;
                    if (completionSignals.TryGetValue(suite.Name, out TaskCompletionSource? signal))
                        signal.TrySetResult();
                }
            }

            if (options.NoParallel)
            {
                foreach (TestSuiteDefinition suite in parallelSuites)
                    await ExecuteSuiteAsync(suite);
            }
            else if (parallelSuites.Count > 0)
            {
                int concurrency = Math.Clamp(Environment.ProcessorCount, 2, 6);
                using SemaphoreSlim gate = new(concurrency, concurrency);
                Task[] tasks = parallelSuites.Select(async suite =>
                {
                    if (suite.Prerequisites is { Length: > 0 })
                    {
                        foreach (string dependency in suite.Prerequisites)
                            if (completionSignals.TryGetValue(dependency, out TaskCompletionSource? signal))
                                await signal.Task;
                    }

                    await gate.WaitAsync();
                    try
                    {
                        await ExecuteSuiteAsync(suite);
                    }
                    finally
                    {
                        gate.Release();
                    }
                }).ToArray();
                await Task.WhenAll(tasks);
            }

            foreach (TestSuiteDefinition suite in serialSuites)
                await ExecuteSuiteAsync(suite);

            totalClock.Stop();

            List<SuiteAccumulator> orderedTimings = accumulators.Values
                .OrderByDescending(item => item.ElapsedMs)
                .ThenBy(item => item.Name, StringComparer.OrdinalIgnoreCase)
                .ToList();

            if (options.ShowTimings)
            {
                Console.WriteLine();
                Console.WriteLine("=== 测试套件耗时统计 (Top 15) ===");
                foreach (SuiteAccumulator item in orderedTimings.Take(15))
                    Console.WriteLine($"  {item.ElapsedMs,7} ms | {item.Passed,4} pass / {item.Failed,2} fail / {item.Skipped,2} skip | {item.Name}");
            }

            Console.WriteLine();
            Console.WriteLine($"通过：{_passed}；失败：{Failures.Count}；跳过：{_skipped}；耗时：{totalClock.ElapsedMilliseconds} ms");
            foreach (string failure in Failures) Console.WriteLine("FAIL: " + failure);

            string modeName = options.FastOnly ? "fast" : hasFilter ? "filtered" : "full";
            if (options.ResultsPath is not null)
            {
                await JsonFile.WriteAtomicAsync(options.ResultsPath, new
                {
                    passed = _passed,
                    failed = Failures.Count,
                    skipped = _skipped,
                    elapsedMs = totalClock.ElapsedMilliseconds,
                    mode = modeName,
                    filter = hasFilter ? options.FilterTerms : null,
                    parallel = !options.NoParallel,
                    version = ProductInfo.Version,
                    buildIdentity = ProductInfo.BuildIdentity,
                    failures = Failures,
                    timings = orderedTimings.Select(item => new
                    {
                        name = item.Name,
                        elapsedMs = item.ElapsedMs,
                        passed = item.Passed,
                        failed = item.Failed,
                        skipped = item.Skipped
                    }),
                    completedAtUtc = DateTimeOffset.UtcNow
                });
            }

            if (options.WatchdogResultsPath is not null)
            {
                List<SuiteAccumulator> watchdogSuites = selected
                    .Where(s => s.ExportGroup == "Watchdog")
                    .Select(s => accumulators[s.Name])
                    .ToList();
                List<string> watchdogFailures = watchdogSuites.SelectMany(s => s.Failures).ToList();
                await JsonFile.WriteAtomicAsync(options.WatchdogResultsPath, new
                {
                    passed = watchdogSuites.Sum(s => s.Passed),
                    failed = watchdogFailures.Count,
                    failures = watchdogFailures,
                    skipped = watchdogSuites.Sum(s => s.Skipped),
                    version = ProductInfo.Version,
                    buildIdentity = ProductInfo.BuildIdentity
                });
            }

            if (options.FindingPriorityResultsPath is not null)
            {
                List<SuiteAccumulator> fpSuites = selected
                    .Where(s => s.ExportGroup == "FindingPriority")
                    .Select(s => accumulators[s.Name])
                    .ToList();
                if (_subSuiteAccumulators.TryGetValue("FindingPriorityUi", out SuiteAccumulator? uiAccumulator))
                    fpSuites.Add(uiAccumulator);
                List<string> fpFailures = fpSuites.SelectMany(s => s.Failures).ToList();
                await JsonFile.WriteAtomicAsync(options.FindingPriorityResultsPath, new
                {
                    passed = fpSuites.Sum(s => s.Passed),
                    failed = fpFailures.Count,
                    failures = fpFailures,
                    skipped = fpSuites.Sum(s => s.Skipped),
                    version = ProductInfo.Version,
                    buildIdentity = ProductInfo.BuildIdentity,
                    safety = "Hidden UI reports plus static reads of locally generated harmless fixtures; no sample, file, Broker execution or remediation."
                });
            }

            return Failures.Count == 0 ? 0 : 1;
        }
        finally
        {
            _subSuiteAccumulators = null;
            CurrentSuiteAccumulator.Value = null;
        }
    }
}
