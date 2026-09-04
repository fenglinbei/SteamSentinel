using System.Text.Json;
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
                await WriteAsync(new WorkerMessage { Type = WorkerMessageTypes.Failed, Error = "工作进程没有收到有效启动请求。" });
                return 2;
            }

            StdioPasswordProvider passwordProvider = new();
            long lastDiagnostics = 0, lastCheckpoint = 0, lastProgressSent = 0;
            int lastFindings = -1;
            long lastCoverageOccurrences = -1;
            ReportBatchWriter batches = new(batch => WriteAsync(new WorkerMessage
                { Type = WorkerMessageTypes.Checkpoint, Batch = batch }).GetAwaiter().GetResult());
            SynchronousProgress progress = new(message =>
            {
                lastProgress = message;
                long now = Environment.TickCount64;
                if (now - lastDiagnostics >= 1000)
                { diagnostics = WorkerDiagnostics.Capture(message); lastDiagnostics = now; }
                if (now - lastProgressSent >= 100 || message.Stage is "压缩包目录" or "压缩包扫描" or "内容特征" or "本机安全引擎")
                {
                    WriteAsync(new WorkerMessage { Type = WorkerMessageTypes.Progress, Progress = message,
                        Diagnostics = diagnostics }).GetAwaiter().GetResult();
                    lastProgressSent = now;
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
            ScanCoordinator coordinator = new();
            ScanReport report = await coordinator.RunAsync(start.Options, passwordProvider, progress, checkpoint: Checkpoint);
            report.WorkerDiagnostics = WorkerDiagnostics.Capture(lastProgress);
            batches.Send(report, final: true);
            await WriteAsync(new WorkerMessage { Type = WorkerMessageTypes.Completed, BatchCount = batches.Count });
            GC.KeepAlive(emergencyReserve);
            return 0;
        }
        catch (OperationCanceledException)
        {
            await WriteAsync(new WorkerMessage { Type = WorkerMessageTypes.Failed, Error = "扫描已取消。" });
            return 3;
        }
        catch (Exception ex)
        {
            emergencyReserve = null;
            if (ex is OutOfMemoryException) GC.Collect(2, GCCollectionMode.Aggressive, blocking: true, compacting: true);
            try { diagnostics = WorkerDiagnostics.Capture(lastProgress, ex); } catch { }
            await WriteAsync(new WorkerMessage
            {
                Type = WorkerMessageTypes.Failed,
                Error = $"{ex.GetType().Name}: {ex.Message}",
                Diagnostics = diagnostics
            });
            return 1;
        }
    }

    private static async Task WriteAsync(WorkerMessage message)
    {
        await OutputLock.WaitAsync();
        try
        {
            string json = JsonSerializer.Serialize(message, CompactJson);
            if (json.Length > 1024 * 1024) throw new InvalidDataException("扫描结果单批过大，已保留此前交回的结果。");
            await Console.Out.WriteLineAsync(json);
            await Console.Out.FlushAsync();
        }
        finally
        {
            OutputLock.Release();
        }
    }

    private sealed class StdioPasswordProvider : IArchivePasswordProvider
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

            while (true)
            {
                cancellationToken.ThrowIfCancellationRequested();
                string? line = await Input.ReadLineAsync(cancellationToken);
                if (line is null) return new ArchivePasswordResponse(request.RequestId, true, null, false);
                line = line.TrimStart('\uFEFF');
                WorkerMessage? response = JsonSerializer.Deserialize<WorkerMessage>(line, JsonFile.Options);
                if (response?.Type == WorkerMessageTypes.Cancel)
                {
                    return new ArchivePasswordResponse(request.RequestId, true, null, false);
                }

                if (response?.Type == WorkerMessageTypes.PasswordResponse &&
                    response.PasswordResponse?.RequestId == request.RequestId)
                {
                    return response.PasswordResponse;
                }
            }
        }
    }

    private sealed class SynchronousProgress(Action<ScanProgress> action) : IProgress<ScanProgress>
    {
        public void Report(ScanProgress value) => action(value);
    }
}
