using System.IO;
using System.Text.Json;
using SteamSentinel.Core.Models;
using SteamSentinel.Core.Reporting;
using SteamSentinel.Core.Scanning;
using SteamSentinel.Core.Utilities;

namespace SteamSentinel.SelfTest;

internal static partial class Program
{
    private static void TestV031ReportBudgets()
    {
        TestV031RepeatedDiagnosticFragments();
        TestV031DiagnosticReplacementBudget();
        TestV031ApprovedReportTextBudget();
        TestV031ProducerDiagnosticBudget();
    }

    private static void TestV031RepeatedDiagnosticFragments()
    {
        const int updates = 100_001;
        const int revisionsPerNode = 32;
        int nodeCount = (updates + revisionsPerNode - 1) / revisionsPerNode;
        Guid scanId = Guid.NewGuid();
        Guid[] nodeIds = Enumerable.Range(0, nodeCount).Select(_ => Guid.NewGuid()).ToArray();
        WorkerDiagnostics diagnostics = new(
            MessageText.Create("Backend.Core.ContentScanner.Containers.ScanContainerFileAsync.02"),
            new MessageText("inert.txt"),
            MessageText.Create("Backend.Core.ContentScanner.Containers.ScanContainerFileAsync.03", 0, "1,048,576", "0", "0"),
            0, 0, 0, DateTimeOffset.UtcNow);
        ReportBatchReader reader = new();
        ContainerScanMetadata metadata = new(nodeCount, false, new(), new(), [], null);
        for (int i = 0; i < updates; i++)
        {
            // A fresh node models the separately deserialized worker fragment;
            // replacing it must not mutate an earlier accepted snapshot.
            int index = i / revisionsPerNode;
            ContainerScanNode node = V020Node($"inert-{index}.txt", id: nodeIds[index]);
            node.Revision = i % revisionsPerNode + 1;
            reader.Apply(new(i, new(0, 0, 0, 0, 0, 0, 0), new()
            { ScanId = scanId, WorkerDiagnostics = diagnostics })
            { ContainerFragment = new(metadata, index, node, false) });
        }
        Check("0.3.1 十万次容器分片诊断仅占当前快照预算", reader.Count == updates &&
            reader.Report?.Containers?.Nodes.Count == nodeCount && reader.Report.Containers.Nodes[0].Revision == revisionsPerNode &&
            reader.Report.Containers.Nodes[^1].Revision == (updates - 1) % revisionsPerNode + 1 &&
            reader.Report.WorkerDiagnostics == diagnostics &&
            diagnostics.ValidateDisplayMessages() * updates > ScanResourceGuard.MaximumTextCharacters);
        reader.Apply(new(reader.Count, new(0, 0, 0, 0, 0, 0, 0), new() { ScanId = scanId })
        { ContainerFragment = new(metadata, nodeCount, null, true) });
        Check("0.3.1 空诊断容器footer保留最后诊断且正常结束", !reader.HasIncompleteContainers &&
            reader.Report!.WorkerDiagnostics == diagnostics && reader.Report.Containers!.Nodes.Count == nodeCount);
    }

    private static void TestV031DiagnosticReplacementBudget()
    {
        Guid scanId = Guid.NewGuid();
        ReportBatchReader reader = new(maximumTextCharacters: 100);
        ReportBatch Frame(WorkerDiagnostics? diagnostic = null, List<Finding>? findings = null, int? offset = null) =>
            new(reader.Count, new(offset ?? reader.Report?.Findings.Count ?? 0, 0, 0, 0, 0, 0, 0), new()
            { ScanId = scanId, WorkerDiagnostics = diagnostic, Findings = findings ?? [] });

        WorkerDiagnostics large = V031Diagnostic(80), small = V031Diagnostic(20);
        reader.Apply(Frame(large));
        reader.Apply(Frame(small));
        reader.Apply(Frame(findings: [V031Finding(80)]));
        Check("0.3.1 较小诊断替换释放预算且空值不清除诊断", reader.Report!.WorkerDiagnostics == small &&
            reader.Report.Findings.Single().ValidateDisplayMessages() + small.ValidateDisplayMessages() == 100);

        string before = JsonSerializer.Serialize(reader.Report, JsonFile.Options);
        int count = reader.Count;
        ReportBatch invalidContainer = Frame(V031Diagnostic(16)) with
        { ContainerFragment = new(new(1, false, new(), new(), [], null), 1, V020Node("invalid.txt"), false) };
        Check("0.3.1 后续容器校验拒绝时不提交诊断或计数", V020Throws<InvalidDataException>(() => reader.Apply(invalidContainer)) &&
            reader.Count == count && before == JsonSerializer.Serialize(reader.Report, JsonFile.Options));
        // A failed smaller replacement must not release budget internally.
        Check("0.3.1 被拒绝的小诊断不能为新发现释放额度", V020Throws<InvalidDataException>(() => reader.Apply(Frame(findings:
            [new() { Title = "inert", TitleMessage = new("tiny", []) }]))) && reader.Count == count);
        Check("0.3.1 被拒绝分片不释放诊断额度", V020Throws<InvalidDataException>(() => reader.Apply(Frame(V031Diagnostic(21)))) &&
            reader.Count == count && reader.Report.WorkerDiagnostics == small);
        reader.Apply(Frame());
        Check("0.3.1 空诊断分片不重复累计也不释放已有额度", reader.Report.WorkerDiagnostics == small &&
            V020Throws<InvalidDataException>(() => reader.Apply(Frame(findings: [V031Finding(16)]))));

        reader.Apply(Frame(V031Diagnostic(16), [V031Finding(84)], 0));
        Check("0.3.1 诊断与发现同时替换按最终保留量计费", reader.Report.Findings is [var finding] &&
            finding.ValidateDisplayMessages() == 84 && reader.Report.WorkerDiagnostics!.ValidateDisplayMessages() == 16);
        WorkerDiagnostics noMetadata = new("plain", "inert", "plain", 0, 0, 0, DateTimeOffset.UtcNow);
        reader.Apply(Frame(noMetadata, [V031Finding(100)], 0));
        Check("0.3.1 无显示描述的新诊断释放旧描述额度", reader.Report.WorkerDiagnostics == noMetadata &&
            reader.Report.Findings.Single().ValidateDisplayMessages() == 100);
    }

    private static void TestV031ApprovedReportTextBudget()
    {
        const long increased = 16L * 1024 * 1024;
        DisplayMessage message = new("Fixture.LargeText",
            Enumerable.Repeat(new DisplayArgument(new string('x', 4090)), 3).ToArray());
        ScanReport source = new()
        {
            ContentScanSettings = new() { MaximumReportTextCharacters = increased },
            CompletedAtUtc = DateTimeOffset.UtcNow,
            Findings = Enumerable.Range(0, 768).Select(_ => new Finding
            { Description = "inert fixture", DescriptionMessage = message }).ToList()
        };
        List<ReportBatch> frames = [];
        JsonSerializerOptions wire = new(JsonFile.Options) { WriteIndented = false };
        ReportBatchWriter writer = new(frame => frames.Add(JsonSerializer.Deserialize<ReportBatch>(
            JsonSerializer.Serialize(frame, wire), wire)!));
        writer.Send(source);
        writer.Send(source, final: true);
        long characters = source.Findings.Sum(f => f.ValidateDisplayMessages());
        Check("0.3.1 真实序列化回归数据超过8Mi字符且仍在批准预算内",
            characters > ScanResourceGuard.MaximumTextCharacters && characters < increased && frames.Count > 1);

        ReportBatchReader restricted = new();
        int next = 0;
        for (; next < frames.Count; next++)
        {
            try { restricted.Apply(frames[next]); }
            catch (InvalidDataException ex) when (ex.Message == "Display message aggregate limit exceeded.") { break; }
        }
        Check("0.3.1 Worker自报较大文本设置不能扩大接收端授权", next is > 0 && next < frames.Count &&
            restricted.Count == next && restricted.Report?.CompletedAtUtc is null &&
            restricted.Report!.Findings.Sum(f => f.ValidateDisplayMessages()) <= ScanResourceGuard.MaximumTextCharacters);
        int beforeCount = restricted.Count, beforeFindings = restricted.Report!.Findings.Count;
        Check("0.3.1 未批准时重试超限分片仍被原子拒绝", next < frames.Count &&
            V020Throws<InvalidDataException>(() => restricted.Apply(frames[next])) && restricted.Count == beforeCount &&
            restricted.Report.Findings.Count == beforeFindings);

        restricted.IncreaseTextBudget(increased);
        for (; next < frames.Count; next++) restricted.Apply(frames[next]);
        Check("0.3.1 批准提高文本预算后重试同一分片并完整收齐", restricted.Count == frames.Count &&
            restricted.Report.Findings.Count == source.Findings.Count && restricted.Report.CompletedAtUtc == source.CompletedAtUtc);

        ReportBatchReader configured = new(maximumTextCharacters: increased);
        foreach (ReportBatch frame in frames) configured.Apply(frame);
        Check("0.3.1 初始文本预算大于8Mi字符时直接生效", configured.Report!.Findings.Count == source.Findings.Count &&
            configured.Report.CompletedAtUtc == source.CompletedAtUtc);
        Check("0.3.1 文本预算拒绝倒退和不合法值", V020Throws<InvalidDataException>(() => configured.IncreaseTextBudget(increased - 1)) &&
            V020Throws<InvalidDataException>(() => configured.IncreaseTextBudget(long.MaxValue)) &&
            V020Throws<InvalidDataException>(() => _ = new ReportBatchReader(maximumTextCharacters: 0)));

        ReportBatch invalidMessage = new(configured.Count, new(configured.Report.Findings.Count, 0, 0, 0, 0, 0, 0), new()
        {
            ScanId = source.ScanId,
            Findings = [new() { TitleMessage = new("invalid id", []) }]
        });
        Check("0.3.1 提高总预算仍保留单条描述协议校验", V020Throws<InvalidDataException>(() => configured.Apply(invalidMessage)) &&
            configured.Count == frames.Count && configured.Report.Findings.Count == source.Findings.Count);
    }

    private static DisplayMessage V031CounterMessage(int characters) =>
        new("Fixture.Counter", [new(new string('x', characters - "Fixture.Counter".Length))]);
    private static WorkerDiagnostics V031Diagnostic(int characters) => new("inert", "inert", "inert", 0, 0, 0, DateTimeOffset.UtcNow)
    { StageMessage = V031CounterMessage(characters) };
    private static Finding V031Finding(int characters) => new()
    { Title = "inert", TitleMessage = V031CounterMessage(characters) };

    private static void TestV031ProducerDiagnosticBudget()
    {
        ScanOptions refusedOptions = new() { MaximumReportTextCharacters = 50, AllowResourceDecisions = true };
        ScanReport refusedReport = new() { ContentScanSettings = refusedOptions, WorkerDiagnostics = V031Diagnostic(80) };
        using (ScanResourceSession refused = new(refusedOptions,
            request => new(request.RequestId, ResourceDecisionKind.Skip, [], "resource.user_kept_limits"), default))
        {
            refused.Bind(refusedReport);
            Check("0.3.1 生产端在发送前为当前诊断请求预算并尊重拒绝", V020Throws<ScanResourceLimitException>(() =>
                new ScanResourceGuard().Check(refusedReport)) && refused.Audit.Decisions is [var decision] &&
                decision.Request.LimitKey == nameof(ScanOptions.MaximumReportTextCharacters) && decision.Request.RequiredMinimum == 80);
        }

        ScanOptions options = new() { MaximumReportTextCharacters = 50, AllowResourceDecisions = true };
        ScanReport report = new() { ContentScanSettings = options, WorkerDiagnostics = V031Diagnostic(80) };
        ReportBatchReader reader = new(maximumTextCharacters: options.MaximumReportTextCharacters);
        int approvals = 0;
        using ScanResourceSession session = new(options, request =>
        {
            approvals++;
            long grant = Math.Max(request.RequiredMinimum, request.CurrentLimit * 2);
            reader.IncreaseTextBudget(grant);
            return new(request.RequestId, ResourceDecisionKind.Approve,
                [new(request.LimitKey, request.CurrentLimit, grant)], "resource.user_approved");
        }, default);
        session.Bind(report);
        ScanResourceGuard guard = new();
        ReportBatchWriter writer = new(reader.Apply);
        guard.Check(report);
        writer.Send(report);
        Check("0.3.1 小预算诊断获得批准后生产端与接收端一致", approvals == 1 && options.MaximumReportTextCharacters == 100 &&
            reader.Report!.WorkerDiagnostics == report.WorkerDiagnostics);
        for (int i = 0; i < 1000; i++) guard.Check(report);
        Check("0.3.1 重复生产端检查不累计旧诊断或重复申请额度", approvals == 1);
        report.WorkerDiagnostics = V031Diagnostic(110);
        guard.Check(report);
        writer.Send(report);
        Check("0.3.1 最后诊断快照增大仍先申请预算再传输", approvals == 2 && options.MaximumReportTextCharacters == 200 &&
            reader.Report!.WorkerDiagnostics!.ValidateDisplayMessages() == 110);
    }

    private static async Task<int> RunV031ReportBudgetTestsAsync(string root)
    {
        if (Directory.Exists(root) || File.Exists(root)) throw new IOException("Use a new report-budget test directory.");
        Directory.CreateDirectory(root);
        try { TestV031ReportBudgets(); await TestV031WorkerTextBudgetsAsync(root); }
        catch (Exception ex) { Failures.Add(ex.ToString()); }
        await JsonFile.WriteNewAsync(Path.Combine(root, "results.json"), new
        { passed = _passed, failed = Failures.Count, failures = Failures, completedAtUtc = DateTimeOffset.UtcNow });
        Console.WriteLine($"REPORT_BUDGET_PASS={_passed};FAIL={Failures.Count}");
        foreach (string failure in Failures) Console.Error.WriteLine(failure);
        return Failures.Count == 0 ? 0 : 1;
    }
}
