using SteamSentinel.Core.Reporting;
using System.Text.Json;
using System.Threading.Channels;
using SteamSentinel.Core.Models;
using SteamSentinel.Core.Scanning;
using SteamSentinel.Core.Utilities;

namespace SteamSentinel.ArchiveWorker;

internal static class Program
{
    private static readonly SemaphoreSlim OutputLock = new(1, 1);
    private static readonly JsonSerializerOptions CompactJson = new(JsonFile.Options) { WriteIndented = false };
    private static readonly BoundedLineReader Input = new(Console.In);

    [STAThread]
    private static async Task<int> Main()
    {
        Console.InputEncoding = System.Text.Encoding.UTF8;
        Console.OutputEncoding = System.Text.Encoding.UTF8;
        ScanProgress? lastProgress = null;
        WorkerDiagnostics? diagnostics = null;
        ScanReport? live = null;
        ReportBatchWriter? partialWriter = null;
        ScanResourceGuard resources = new(checkProcessMemory: true);
        byte[]? emergencyReserve = new byte[2 * 1024 * 1024];
        try
        {
            ProcessIntegrityLevel integrity = ProcessIntegrity.GetCurrent();
            await WriteAsync(new WorkerMessage
            {
                Type = WorkerMessageTypes.Ready,
                Containment = integrity.ToString()
            });
            string? line = await Input.ReadLineAsync();
            if (string.IsNullOrWhiteSpace(line)) return 2;
            line = line.TrimStart('\uFEFF');
            WorkerMessage? start = JsonSerializer.Deserialize<WorkerMessage>(line, JsonFile.Options);
            if (start?.Type != WorkerMessageTypes.Start || start.Options is null)
            {
                await WriteAsync(new WorkerMessage { Type = WorkerMessageTypes.Failed, ReasonCode = ReasonCodes.WorkerStartFailed, ErrorText = MessageText.Create("Backend.Worker.Program.Main.01") });
                return 2;
            }
            ScanOptions scanOptions = ScanEnhancements.ForExecution(start.Options);
            ContainerRequestValidation.Validate(scanOptions, Path.Combine(Environment.CurrentDirectory, "recovery"));

            using CancellationTokenSource scanCancellation = new();
            Channel<ArchivePasswordResponse> responses = Channel.CreateBounded<ArchivePasswordResponse>(8);
            Channel<ScanLimitResponse> resourceResponses = Channel.CreateBounded<ScanLimitResponse>(1);
            _ = Task.Run(async () =>
            {
                try
                {
                    while (true)
                    {
                        string? input = await Input.ReadLineAsync(scanCancellation.Token);
                        if (input is null) { scanCancellation.Cancel(); break; }
                        WorkerMessage? message = JsonSerializer.Deserialize<WorkerMessage>(input.TrimStart('\uFEFF'), JsonFile.Options);
                        if (message?.Type == WorkerMessageTypes.Cancel) { scanCancellation.Cancel(); break; }
                        if (message?.Type == WorkerMessageTypes.ResourceResponse && message.ResourceResponse is { } decision)
                        {
                            if (!scanOptions.AllowResourceDecisions || !resourceResponses.Writer.TryWrite(decision))
                                throw new InvalidDataException("Unexpected resource response.");
                            continue;
                        }
                        if (message?.Type != WorkerMessageTypes.PasswordResponse || message.PasswordResponse is null)
                            throw MessageExceptions.Create(MessageText.Create("Backend.Worker.Program.Main.02"), sourceText => new InvalidDataException(sourceText));
                        _ = ArchivePasswordInput.ValidateAndGetPasswords(message.PasswordResponse);
                        if (!responses.Writer.TryWrite(message.PasswordResponse))
                            throw MessageExceptions.Create(MessageText.Create("Backend.Worker.Program.Main.03"), sourceText => new InvalidDataException(sourceText));
                    }
                }
                catch (Exception ex)
                {
                    responses.Writer.TryComplete(ex);
                    resourceResponses.Writer.TryComplete(ex);
                    try { scanCancellation.Cancel(); } catch (ObjectDisposedException) { }
                }
                finally { responses.Writer.TryComplete(); resourceResponses.Writer.TryComplete(); }
            });
            StdioPasswordProvider passwordProvider = new(responses.Reader);
            using ScanResourceSession? resourceSession = scanOptions.AllowResourceDecisions
                ? new(scanOptions, request =>
                {
                    WriteAsync(new WorkerMessage { Type = WorkerMessageTypes.ResourceRequest, ResourceRequest = request }).GetAwaiter().GetResult();
                    return resourceResponses.Reader.ReadAsync(scanCancellation.Token).AsTask().GetAwaiter().GetResult();
                }, scanCancellation.Token) : null;
            long lastDiagnostics = 0, lastCheckpoint = 0, lastProgressSent = 0;
            string? lastStageSent = null;
            int lastFindings = -1;
            long lastCoverageOccurrences = -1;
            ReportBatchWriter batches = partialWriter = new(batch => WriteAsync(new WorkerMessage
            { Type = WorkerMessageTypes.Checkpoint, Batch = batch }).GetAwaiter().GetResult());
            SynchronousProgress progress = new(message =>
            {
                lastProgress = message;
                long now = Environment.TickCount64;
                if (now - lastDiagnostics >= 1000)
                { diagnostics = WorkerDiagnostics.Capture(message); lastDiagnostics = now; }
                if (now - lastProgressSent >= 100 || message.Stage != lastStageSent)
                {
                    WriteAsync(new WorkerMessage
                    {
                        Type = WorkerMessageTypes.Progress,
                        Progress = message,
                        Diagnostics = diagnostics
                    }).GetAwaiter().GetResult();
                    lastProgressSent = now;
                    lastStageSent = message.Stage;
                }
                if (live is not null) resources.Check(live);
            });
            void Checkpoint(ScanReport state)
            {
                live = state;
                resources.Check(state);
                long coverageOccurrences = state.CoverageAggregates.Sum(item => item.Count);
                if (state.Findings.Count == lastFindings && coverageOccurrences == lastCoverageOccurrences &&
                    Environment.TickCount64 - lastCheckpoint < 1000) return;
                state.WorkerDiagnostics = diagnostics ??= WorkerDiagnostics.Capture(lastProgress);
                if (lastProgress is not null) state.WorkerDiagnostics = state.WorkerDiagnostics with
                { Stage = lastProgress.Stage, LastPath = lastProgress.CurrentItem, Operation = lastProgress.Message };
                batches.Send(state);
                lastFindings = state.Findings.Count;
                lastCoverageOccurrences = coverageOccurrences;
                lastCheckpoint = Environment.TickCount64;
            }
            ScanCoordinator coordinator = new(allowRelatedSignatureProbe: true);
            ScanReport report = await coordinator.RunAsync(scanOptions, passwordProvider, progress,
                cancellationToken: scanCancellation.Token, checkpoint: Checkpoint);
            if (resourceSession is not null) resourceSession.Audit.Phase = ScanResourcePhase.Finished;
            scanCancellation.Token.ThrowIfCancellationRequested();
            report.WorkerDiagnostics = WorkerDiagnostics.Capture(lastProgress);
            batches.Send(report, final: true);
            await WriteAsync(new WorkerMessage { Type = WorkerMessageTypes.Completed, BatchCount = batches.Count });
            GC.KeepAlive(emergencyReserve);
            return 0;
        }
        catch (OperationCanceledException)
        {
            TryPublishPartial();
            await WriteAsync(new WorkerMessage { Type = WorkerMessageTypes.Failed, ReasonCode = ReasonCodes.UserCancelled, ErrorText = MessageText.Create("Backend.Worker.Program.Main.04") });
            return 3;
        }
        catch (Exception ex)
        {
            emergencyReserve = null;
            if (ex is OutOfMemoryException) GC.Collect(2, GCCollectionMode.Aggressive, blocking: true, compacting: true);
            try { diagnostics = WorkerDiagnostics.Capture(lastProgress, ex); } catch { }
            TryPublishPartial();
            await WriteAsync(new WorkerMessage
            {
                Type = WorkerMessageTypes.Failed,
                ErrorText = MessageText.Create("Backend.Exception", ex.GetType().Name, MessageExceptions.Describe(ex)),
                ReasonCode = ReasonCodes.ForFailureType(ex.GetType().Name),
                Diagnostics = diagnostics
            });
            return 1;
        }
        void TryPublishPartial()
        {
            if (live is null || partialWriter is null) return;
            try
            {
                if (live.ResourceAudit is { } audit) audit.Phase = ScanResourcePhase.Finished;
                new ScanResourceGuard().Check(live);
                partialWriter.Send(live, final: true);
            }
            catch (Exception) { /* Keep the previously validated checkpoint if final serialization cannot fit. */ }
        }
    }

    private static async Task WriteAsync(WorkerMessage message)
    {
        await OutputLock.WaitAsync();
        try
        {
            string json = JsonSerializer.Serialize(message, CompactJson);
            if (json.Length > 1024 * 1024) throw MessageExceptions.Create(MessageText.Create("Backend.Worker.Program.WriteAsync.01"), sourceText => new InvalidDataException(sourceText));
            await Console.Out.WriteLineAsync(json);
            await Console.Out.FlushAsync();
        }
        finally
        {
            OutputLock.Release();
        }
    }

    private sealed class StdioPasswordProvider(ChannelReader<ArchivePasswordResponse> responses) : IArchivePasswordProvider
    {
        public async Task<ArchivePasswordResponse> RequestPasswordAsync(
            ArchivePasswordRequest request,
            CancellationToken cancellationToken)
        {
            await WriteAsync(new WorkerMessage
            {
                Type = WorkerMessageTypes.PasswordRequest,
                PasswordRequest = request
            });

            while (await responses.WaitToReadAsync(cancellationToken))
            {
                while (responses.TryRead(out ArchivePasswordResponse? response))
                    if (response.RequestId == request.RequestId) return response;
            }
            cancellationToken.ThrowIfCancellationRequested();
            throw MessageExceptions.Create(MessageText.Create("Backend.Worker.Program.RequestPasswordAsync.01"), sourceText => new OperationCanceledException(sourceText, cancellationToken));
        }
    }

    private sealed class SynchronousProgress(Action<ScanProgress> action) : IProgress<ScanProgress>
    {
        public void Report(ScanProgress value) => action(value);
    }
}
