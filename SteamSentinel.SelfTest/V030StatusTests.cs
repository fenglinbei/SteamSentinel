using System.Globalization;
using System.IO;
using System.Text.Json;
using SteamSentinel.App.Services;
using SteamSentinel.Core.Models;
using SteamSentinel.Core.Remediation;
using SteamSentinel.Core.Reporting;
using SteamSentinel.Core.Rules;
using SteamSentinel.Core.Scanning;
using SteamSentinel.Core.Steam;
using SteamSentinel.Core.Utilities;

namespace SteamSentinel.SelfTest;

internal static partial class Program
{
    private static async Task TestV030StatusAsync(string root)
    {
        CultureInfo zh = CultureInfo.GetCultureInfo("zh-Hans"), en = CultureInfo.GetCultureInfo("en-US");
        ScanReport report = new() { CompletedAtUtc = DateTimeOffset.UtcNow };
        ScanExecution.Set(report, ScanExecutionState.Completed);
        report.CoverageNotes.Add(@"C:\取消\OutOfMemoryException\AMSI\上限.txt");
        Check("状态码 路径与说明文字不改变已完成状态", report.ExecutionState == ScanExecutionState.Completed &&
            report.ExecutionStatus == "本次扫描已完成");
        Check("状态码 中文与英文从同一完成状态渲染", StatusPresentation.Scan(report, zh) == "本次扫描已完成" &&
            StatusPresentation.Scan(report, en) == "Scan completed");
        report.Coverage = ScanCoverage.Partial;
        Check("状态码 执行完成与覆盖缺口独立", report.ExecutionState == ScanExecutionState.Completed &&
            StatusPresentation.Scan(report, en) == "Scan finished; some content was not checked");

        ScanReport legacy = JsonSerializer.Deserialize<ScanReport>("""
            {"ExecutionStatus":"本次扫描已完成","CompletedAtUtc":"2026-09-21T00:00:00Z","Coverage":"Complete","CoverageNotes":["用户取消了扫描"]}
            """, JsonFile.Options)!;
        Check("状态码 旧中文报告保留原文但不推断完成或取消", legacy.ExecutionState == ScanExecutionState.Unknown &&
            legacy.StatusSchemaVersion == 0 && legacy.LegacyExecutionStatus == "本次扫描已完成" &&
            StatusPresentation.Scan(legacy, en).StartsWith("Execution state was not recorded", StringComparison.Ordinal));
        string oldRoundtrip = JsonSerializer.Serialize(legacy, JsonFile.Options);
        Check("状态码 旧状态文字往返保留", JsonSerializer.Deserialize<ScanReport>(oldRoundtrip, JsonFile.Options)!.LegacyExecutionStatus == legacy.LegacyExecutionStatus);
        string modernJson = JsonSerializer.Serialize(report, JsonFile.Options);
        using (JsonDocument json = JsonDocument.Parse(modernJson))
            Check("状态码 新报告保存机器字段而不写本地化执行状态", json.RootElement.GetProperty("ExecutionState").GetString() == "Completed" &&
                !json.RootElement.TryGetProperty("ExecutionStatus", out _));

        foreach (string reason in new[] { ReasonCodes.ResourceLimit, ReasonCodes.AllocationFailed, ReasonCodes.AmsiUnavailable, ReasonCodes.ReadBudget })
        {
            CoverageEntry chinese = CoveragePresentation.Describe("CONTENT-SCAN-FAILED", "example", "取消 / 上限 / AMSI", reason, zh);
            CoverageEntry english = CoveragePresentation.Describe("CONTENT-SCAN-FAILED", "example", "completely different text", reason, en);
            Check("状态码 覆盖分类跨语言不变 " + reason, chinese.ReasonCode == english.ReasonCode && chinese.CanFullScan == english.CanFullScan && chinese.Kind != english.Kind);
        }
        CoverageEntry unknown = CoveragePresentation.Describe("UNKNOWN", "example", "AMSI 取消 字节预算 上限");
        Check("状态码 未知原文不能触发补查资格", !unknown.CanFullScan && unknown.ReasonCode == ReasonCodes.ReadIncomplete);
        Check("状态码 未知未来原因保留代码且保守显示", CoveragePresentation.Describe("QUICK-MEDIA-STRUCTURE", "example", "", "future.reason", en) is
        { ReasonCode: "future.reason", CanFullScan: false });
        Check("状态码 未知资源键回退可读文本", StatusPresentation.Text("future.reason", en) == "Unrecognized display code: future.reason");
        Check("状态码 消息参数作为文本而非模板执行", StatusPresentation.Text("Message.Unknown", en, "{0}{1}") == "Unrecognized display code: {0}{1}");
        Check("状态码 过长代码和消息参数拒绝", V020Throws<InvalidDataException>(() => StatusMessage.Create(new string('x', 97)).Validate()) &&
            V020Throws<InvalidDataException>(() => StatusMessage.Create("example", new string('x', 4097)).Validate()));

        WorkerFailureException textOnly = new(WorkerStage.Scanning, null, "OutOfMemoryException 用户取消 上限");
        WorkerFailureException typed = new(WorkerStage.Scanning, null, "unrelated display text", new OutOfMemoryException("inert"));
        Check("状态码 后台错误只从类型或原因码分类", textOnly.ReasonCode == ReasonCodes.ComponentFailed && typed.ReasonCode == ReasonCodes.AllocationFailed);
        WorkerFailureException budget = new(WorkerStage.Scanning, null, "arbitrary detail", reasonCode: ReasonCodes.ResourceLimit);
        ScanReport failed = ScanFailureReports.PreserveSystemResults(report, ScanMode.Custom, [], "test", budget, false);
        Check("状态码 失败报告明确记录执行状态及覆盖原因", failed.ExecutionState == ScanExecutionState.Failed &&
            failed.ExecutionReasonCode == ReasonCodes.ResourceLimit && failed.Findings.Last().ReasonCode == ReasonCodes.ResourceLimit);
        ScanReport completed = new() { CompletedAtUtc = DateTimeOffset.UtcNow };
        ScanExecution.Set(completed, ScanExecutionState.Completed);
        ScanReport cancelled = new() { CompletedAtUtc = DateTimeOffset.UtcNow };
        ScanExecution.Set(cancelled, ScanExecutionState.Cancelled, ReasonCodes.UserCancelled);
        Check("状态码 报告合并不会将失败或取消提升为完成", ScanReportMerger.Merge(completed, failed).ExecutionState == ScanExecutionState.Failed &&
            ScanReportMerger.Merge(completed, cancelled).ExecutionState == ScanExecutionState.Cancelled &&
            ScanReportMerger.Merge(completed, legacy).ExecutionState == ScanExecutionState.Unknown);

        RemediationTargetOutcome oldTarget = JsonSerializer.Deserialize<RemediationTargetOutcome>("""
            {"Status":"已完成","Reason":"everything succeeded"}
            """, JsonFile.Options)!;
        RemediationTargetOutcome target = new() { ActionIds = [Guid.NewGuid()] };
        target.SetState(RemediationTargetState.Failed, ReasonCodes.ActionFailed);
        target.LegacyStatus = "已完成";
        RemediationBatchSession session = new() { ExecutionStarted = true, Targets = [oldTarget, target] };
        Check("状态码 旧文字不能增加完成计数", oldTarget.State == RemediationTargetState.Unknown &&
            oldTarget.LegacyStatus == "已完成" && session.CompletedCount == 0 && session.FailedCount == 1 && session.UnfinishedCount == 1);
        Check("状态码 中英批次汇总读取相同计数", StatusPresentation.Batch(session, zh).Contains("失败 1 个") &&
            StatusPresentation.Batch(session, en).Contains("1 failed") && session.CompletedCount == 0);
        RemediationActionResult result = new()
        {
            ActionId = target.ActionIds[0],
            Success = true,
            ExecutionStatus = RemediationExecutionStatus.Succeeded,
            VerificationStatus = RemediationVerificationStatus.PendingReboot,
            Message = "failed / 失败",
            VerificationSummary = "completed / 已完成"
        };
        session.Results.Add(new() { Actions = [result] });
        RemediationBatchPlanner.RefreshOutcomes(session);
        Check("状态码 动作成功但待重启只能需复核", target.State == RemediationTargetState.ReviewRequired &&
            target.ReasonCode == ReasonCodes.VerificationIncomplete && session.CompletedCount == 0);
        result.VerificationStatus = RemediationVerificationStatus.Verified;
        RemediationBatchPlanner.RefreshOutcomes(session);
        Check("状态码 执行成功且验证通过才完成", target.State == RemediationTargetState.Completed && target.ReasonCode == ReasonCodes.ActionsVerified && session.CompletedCount == 1);
        result.Success = false;
        RemediationBatchPlanner.RefreshOutcomes(session);
        Check("状态码 执行失败不能被验证文案提升", target.State == RemediationTargetState.Failed && session.CompletedCount == 0);
        RemediationBatchSession expired = new() { Plans = [new() { ExpiresAtUtc = DateTimeOffset.UtcNow.AddMinutes(-1) }] };
        bool ran = false;
        await RemediationBatchPlanner.ExecuteAsync(expired, _ => { ran = true; return Task.FromResult(new RemediationRunResult()); });
        Check("状态码 过期计划保留独立中断原因且未执行", !ran && expired.InterruptionReasonCode == ReasonCodes.PlanExpired);

        ScanReport streamed = new() { CompletedAtUtc = DateTimeOffset.UtcNow, LegacyExecutionStatus = "legacy text" };
        ScanExecution.Set(streamed, ScanExecutionState.Completed);
        streamed.CoverageNotices.Add(new(ReasonCodes.AmsiUnavailable, "first unavailable result"));
        ReportBatchReader reader = new();
        List<ReportBatch> frames = [];
        ReportBatchWriter writer = new(batch =>
        {
            string wire = JsonSerializer.Serialize(batch, JsonFile.Options);
            Check("状态码 分片保持既有帧上限", wire.Length < 1024 * 1024);
            ReportBatch received = JsonSerializer.Deserialize<ReportBatch>(wire, JsonFile.Options)!;
            frames.Add(received); reader.Apply(received);
        });
        writer.Send(streamed);
        Check("状态码 未结束传输不提前声明扫描完成", reader.Report!.ExecutionState == ScanExecutionState.Running);
        streamed.CoverageNotices[0] = new(ReasonCodes.AmsiUnavailable, "updated unavailable result");
        writer.Send(streamed, true);
        Check("状态码 最终帧保留状态与更新后的原因", reader.Report!.ExecutionState == ScanExecutionState.Completed &&
            reader.Report.LegacyExecutionStatus == "legacy text" && reader.Report.CoverageNotices.Single().Detail == "updated unavailable result");
        int before = reader.Count;
        Check("状态码 非法原因分片原子拒绝", V020Throws<InvalidDataException>(() => reader.Apply(new(before, new(0, 0, 0, 0, 0, 0, 0),
            new() { ScanId = streamed.ScanId, Findings = [new() { Title = "must not be added" }], CoverageNotices = [new("invalid reason", "text")] }))) &&
            reader.Count == before && reader.Report.Findings.Count == 0);
        Check("状态码 未知枚举分片原子拒绝", V020Throws<InvalidDataException>(() => reader.Apply(new(before, new(0, 0, 0, 0, 0, 0, 0),
            new() { ScanId = streamed.ScanId, ExecutionState = (ScanExecutionState)99 }))) && reader.Count == before);
        ScanReport crowded = new();
        for (int i = 0; i < 70; i++) crowded.CoverageNotices.Add(new("future.reason", new string('\u0001', 4096)));
        long largest = 0; int count = 0;
        new ReportBatchWriter(batch => { largest = Math.Max(largest, JsonSerializer.Serialize(batch, JsonFile.Options).Length); count++; }).Send(crowded, true);
        Check("状态码 多条高转义说明按文本预算分片", count > 1 && largest < 1024 * 1024);
        ScanReport limited = new() { ContentScanSettings = new() { MaximumReportTextCharacters = 100 }, CoverageNotices = [new(ReasonCodes.ReadIncomplete, new string('x', 101))] };
        Check("状态码 结构化说明计入总文本预算", V020Throws<ScanResourceLimitException>(() => new ScanResourceGuard().Check(limited)));

        const string sid = "S-1-5-21-1-2-3-1001";
        ScanReport diagnostic = new() { RelatedComponentDiagnostics = new() { TargetUserSid = sid, CompletedAtUtc = DateTimeOffset.UtcNow } };
        RelatedComponentPipeline.Check(diagnostic.RelatedComponentDiagnostics, "related.example", "上限已完成", DiagnosticReadStatus.AccessDenied, "任意描述");
        ReportBatchReader diagnosticReader = new();
        new ReportBatchWriter(diagnosticReader.Apply).Send(diagnostic, true);
        DiagnosticCheck restored = diagnosticReader.Report!.RelatedComponentDiagnostics!.Checks.Single();
        Check("状态码 诊断身份与读取状态跨分片保留", restored.CheckCode == "related.example" && restored.Status == DiagnosticReadStatus.AccessDenied);
        RelatedComponentPipeline.MarkIncomplete(diagnostic, diagnostic.RelatedComponentDiagnostics);
        Check("状态码 诊断名称不决定覆盖分类", diagnostic.Findings.Single().ReasonCode == ReasonCodes.AccessDenied);

        string path = Path.Combine(root, "status-inert"); Directory.CreateDirectory(path);
        await File.WriteAllTextAsync(Path.Combine(path, "取消-上限.txt"), "inert");
        List<string> notes = []; List<DiscoveryReadNote> reads = [];
        _ = ContentDiscovery.Files(Path.Combine(path, "上限-AccessDenied-missing"), notes, 8, 8, structuredNotes: reads).ToArray();
        Check("状态码 不存在的目录名称不伪装限额或拒绝访问", reads.Single().Status == DiagnosticReadStatus.Failed);
        notes.Clear(); reads.Clear();
        _ = ContentDiscovery.Files(path, notes, 0, 8, structuredNotes: reads).ToArray();
        Check("状态码 目录限额从发生点记录", reads.Single().Status == DiagnosticReadStatus.LimitReached && reads[0].ReasonCode == ReasonCodes.ResourceLimit);
    }

    private static async Task<int> RunV030StatusAsync(string root)
    {
        if (Directory.Exists(root) || File.Exists(root)) throw new IOException("A new inert status-test directory is required.");
        Directory.CreateDirectory(root);
        try
        {
            await TestV030StatusAsync(root);
            TestV0119Copy();
            await TestV015Async(root, RuleLoader.LoadEmbedded());
            await TestV0114UiAsync(root);
            await TestV0116Async(root);
            TestTrustProxyBatch();
            TestPhase2Discovery();
            TestPhase2SourceBounds();
            TestPhase2RelatedBatch();
            await TestPhase2PipelineAsync(root);
        }
        catch (Exception ex) { Failures.Add(ex.ToString()); Console.Error.WriteLine(ex); }
        await JsonFile.WriteNewAsync(Path.Combine(root, "results.json"), new
        { passed = _passed, failed = Failures.Count, skipped = _skipped, failures = Failures, completedAtUtc = DateTimeOffset.UtcNow });
        Console.WriteLine($"STATUS_PASS={_passed};FAIL={Failures.Count};SKIP={_skipped}");
        return Failures.Count == 0 ? 0 : 1;
    }
}
