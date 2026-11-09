using System.Diagnostics;
using System.IO;
using System.Text.Json;
using SteamSentinel.App.Native;
using SteamSentinel.App.Services;
using SteamSentinel.Core.Models;
using SteamSentinel.Core.Reporting;
using SteamSentinel.Core.Scanning;
using SteamSentinel.Core.Utilities;

namespace SteamSentinel.SelfTest;

internal static partial class Program
{
    private const int V031WorkerLargeFindings = 768;

    private static async Task TestV031WorkerTextBudgetsAsync(string root)
    {
        string directory = Path.Combine(root, "v031-worker-budget-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        foreach (string file in Directory.EnumerateFiles(AppContext.BaseDirectory))
            File.Copy(file, Path.Combine(directory, Path.GetFileName(file)));
        string fixture = Path.Combine(directory, "SteamSentinelFixture-textbudget.exe");
        File.Copy(Path.Combine(AppContext.BaseDirectory, "SteamSentinel.SelfTest.exe"), fixture);
        File.Copy(Path.Combine(AppContext.BaseDirectory, "SteamSentinel.SelfTest.dll"), Path.ChangeExtension(fixture, ".dll"));

        static ScanOptions Options(long text = ScanResourceGuard.MaximumTextCharacters, bool allow = true)
        {
            ScanLimitSettings settings = new() { AskBeforeIncreasing = allow };
            settings.Full[nameof(ScanOptions.MaximumReportTextCharacters)] = text;
            return settings.Apply(new()
            {
                Mode = ScanMode.Custom,
                IncludeSystem = false,
                IncludeSteam = false,
                IncludeWorkshop = false,
                UseAmsi = false
            });
        }
        static Task<ArchivePasswordResponse> NoPassword(ArchivePasswordRequest request, CancellationToken _) =>
            Task.FromResult(new ArchivePasswordResponse(request.RequestId, true, null, false));
        async Task<ScanReport> RunAsync(ScanOptions options, Func<ScanResourceProposal, CancellationToken, Task<ScanLimitResponse>> callback)
        {
            using CancellationTokenSource timeout = new(TimeSpan.FromSeconds(45));
            return await new ArchiveWorkerClient(fixture).RunAsync(options, NoPassword, null, timeout.Token, callback);
        }

        int approvals = 0;
        ScanReport approved = await RunAsync(Options(), (proposal, _) =>
        {
            approvals++;
            if (proposal.Assessment != ResourceAssessmentKind.EstimatedAvailable)
                throw new InvalidOperationException("Inert IPC text-budget test needs capacity for its small resource grant.");
            return Task.FromResult(new ScanLimitResponse(proposal.Request.RequestId, ResourceDecisionKind.Approve,
                [.. proposal.Changes], "resource.user_approved"));
        });
        long displayCharacters = approved.Findings.Sum(f => f.ValidateDisplayMessages());
        Check("0.3.1 真实受限Worker批准文本预算后接收超过8Mi字符", approvals == 1 &&
            approved.Findings.Count == V031WorkerLargeFindings + 1 && displayCharacters > ScanResourceGuard.MaximumTextCharacters &&
            approved.ExecutionState == ScanExecutionState.Completed && approved.CompletedAtUtc is not null && approved.Coverage == ScanCoverage.Complete);
        Check("0.3.1 真实客户端保留已生效额度及批准审计", approved.ContentScanSettings!.MaximumReportTextCharacters >= displayCharacters &&
            approved.ResourceAudit?.Decisions is [var decision] && decision.Decision == ResourceDecisionKind.Approve &&
            decision.Request.LimitKey == nameof(ScanOptions.MaximumReportTextCharacters) &&
            decision.Changes.Any(change => change.LimitKey == nameof(ScanOptions.MaximumReportTextCharacters) && change.After >= displayCharacters));

        int configuredRequests = 0;
        ScanReport configured = await RunAsync(Options(16L * 1024 * 1024, allow: false), (proposal, _) =>
        {
            configuredRequests++;
            return Task.FromResult(new ScanLimitResponse(proposal.Request.RequestId, ResourceDecisionKind.Skip, []));
        });
        Check("0.3.1 真实客户端初始16Mi文本预算不需要再次批准", configuredRequests == 0 &&
            configured.Findings.Count == V031WorkerLargeFindings + 1 && configured.ExecutionState == ScanExecutionState.Completed &&
            configured.ContentScanSettings!.MaximumReportTextCharacters == 16L * 1024 * 1024 &&
            configured.Findings.Sum(f => f.ValidateDisplayMessages()) == displayCharacters);

        int refusals = 0;
        WorkerFailureException? refused = null;
        try
        {
            await RunAsync(Options(), (proposal, _) =>
            {
                refusals++;
                return Task.FromResult(new ScanLimitResponse(proposal.Request.RequestId, ResourceDecisionKind.Skip, [], "resource.user_kept_limits"));
            });
        }
        catch (WorkerFailureException ex) { refused = ex; }
        Check("0.3.1 真实协议保留预算时返回资源受限而非完成", refusals == 1 && refused is
        {
            Stage: WorkerStage.Scanning, ReasonCode: ReasonCodes.ResourceLimit, PartialReport.ExecutionState: ScanExecutionState.Failed,
            PartialReport.Coverage: ScanCoverage.Partial, PartialReport.CompletedAtUtc: null
        } &&
            refused.PartialReport.Findings is [var retained] && retained.RuleId == "BENIGN-TEXT-BUDGET-CHECKPOINT");
        Check("0.3.1 拒绝扩额保留原始额度和拒绝审计", refused?.PartialReport?.ContentScanSettings?.MaximumReportTextCharacters ==
            ScanResourceGuard.MaximumTextCharacters && refused.PartialReport.ResourceAudit?.Decisions is [var refusal] &&
            refusal.Decision == ResourceDecisionKind.Skip && refusal.Changes.Count == 0);

        WorkerFailureException? malformed = null;
        try
        {
            await RunAsync(Options(), (proposal, _) => Task.FromResult(new ScanLimitResponse(proposal.Request.RequestId,
                ResourceDecisionKind.Approve, proposal.Changes.Select(change => change with { After = change.After + 1 }).ToList(), "resource.user_approved")));
        }
        catch (WorkerFailureException ex) { malformed = ex; }
        Check("0.3.1 真实协议拒绝与提案不一致的扩额且保留部分结果", malformed is
        {
            Stage: WorkerStage.Scanning, InnerException: InvalidDataException, PartialReport.ExecutionState: ScanExecutionState.Failed,
            PartialReport.CompletedAtUtc: null
        } && malformed.InnerException.Message == "Unapproved resource grant." &&
            malformed.PartialReport.Findings.Count == 1 &&
            malformed.PartialReport.ContentScanSettings!.MaximumReportTextCharacters == ScanResourceGuard.MaximumTextCharacters);
    }

    private static async Task<int> RunV031WorkerTextBudgetFixtureAsync()
    {
        JsonSerializerOptions wire = new(JsonFile.Options) { WriteIndented = false };
        async Task SendAsync(WorkerMessage message)
        {
            string frame = JsonSerializer.Serialize(message, wire);
            if (frame.Length >= 1024 * 1024) throw new InvalidDataException("Inert fixture exceeded the worker frame limit.");
            await Console.Out.WriteLineAsync(frame);
            await Console.Out.FlushAsync();
        }
        await SendAsync(new() { Type = WorkerMessageTypes.Ready, Containment = ProcessIntegrity.GetCurrent().ToString() });
        string? startLine = await Console.In.ReadLineAsync();
        if (startLine is null) return 2;
        WorkerMessage? start = JsonSerializer.Deserialize<WorkerMessage>(startLine, wire);
        if (start?.Type != WorkerMessageTypes.Start || start.Options is not { } options) return 2;
        ScanReport report = new()
        {
            ContentScanSettings = options,
            Mode = ScanMode.Custom,
            ExecutionState = ScanExecutionState.Running,
            Coverage = ScanCoverage.Complete,
            Findings = [new() { RuleId = "BENIGN-TEXT-BUDGET-CHECKPOINT", Title = "inert fixture checkpoint" }]
        };
        ReportBatchWriter writer = new(batch => SendAsync(new()
        { Type = WorkerMessageTypes.Checkpoint, Batch = batch }).GetAwaiter().GetResult());
        writer.Send(report);

        DisplayMessage descriptor = new("Fixture.WorkerLargeText",
            Enumerable.Repeat(new DisplayArgument(new string('x', 4090)), 3).ToArray());
        for (int i = 0; i < V031WorkerLargeFindings; i++)
            report.Findings.Add(new() { RuleId = "BENIGN-TEXT-BUDGET", Description = "inert text", DescriptionMessage = descriptor });
        long required = report.Findings.Sum(f => f.ValidateDisplayMessages()) + 1024 * 1024;
        if (required > options.MaximumReportTextCharacters)
        {
            using Process process = Process.GetCurrentProcess();
            ScanLimitRequest request = new(Guid.NewGuid().ToString("N"), nameof(ScanOptions.MaximumReportTextCharacters),
                options.MaximumReportTextCharacters, required, options.MaximumReportTextCharacters, true,
                "inert-worker-report", process.PrivateMemorySize64, 0, 0);
            await SendAsync(new() { Type = WorkerMessageTypes.ResourceRequest, ResourceRequest = request });
            string? responseLine = await Console.In.ReadLineAsync();
            if (responseLine is null) return 2;
            WorkerMessage? responseMessage = JsonSerializer.Deserialize<WorkerMessage>(responseLine, wire);
            if (responseMessage?.Type != WorkerMessageTypes.ResourceResponse || responseMessage.ResourceResponse is not { } response ||
                response.RequestId != request.RequestId) return 2;
            if (response.Decision != ResourceDecisionKind.Approve)
            {
                await SendAsync(new()
                {
                    Type = WorkerMessageTypes.Failed,
                    Error = "Inert fixture kept the original text budget.",
                    ReasonCode = ReasonCodes.ResourceLimit
                });
                return 1;
            }
            ScanLimitAccess.Apply(options, response.Changes);
        }
        writer.Send(report);
        report.CompletedAtUtc = DateTimeOffset.UtcNow;
        ScanExecution.Set(report, ScanExecutionState.Completed);
        writer.Send(report, final: true);
        await SendAsync(new() { Type = WorkerMessageTypes.Completed, BatchCount = writer.Count });
        return 0;
    }
}
