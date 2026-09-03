using System.Text.Json;
using SteamSentinel.Core.Models;
using SteamSentinel.Core.Scanning;
using SteamSentinel.Core.Utilities;

namespace SteamSentinel.ArchiveWorker;

internal static class Program
{
    private static readonly SemaphoreSlim OutputLock = new(1, 1);

    [STAThread]
    private static async Task<int> Main()
    {
        Console.InputEncoding = System.Text.Encoding.UTF8;
        Console.OutputEncoding = System.Text.Encoding.UTF8;
        try
        {
            ProcessIntegrityLevel integrity = ProcessIntegrity.GetCurrent();
            await WriteAsync(new WorkerMessage
            {
                Type = WorkerMessageTypes.Ready,
                Containment = integrity.ToString()
            });
            string? line = await Console.In.ReadLineAsync();
            if (string.IsNullOrWhiteSpace(line)) return 2;
            line = line.TrimStart('\uFEFF');
            WorkerMessage? start = JsonSerializer.Deserialize<WorkerMessage>(line, JsonFile.Options);
            if (start?.Type != WorkerMessageTypes.Start || start.Options is null)
            {
                await WriteAsync(new WorkerMessage { Type = WorkerMessageTypes.Failed, Error = "工作进程没有收到有效启动请求。" });
                return 2;
            }

            StdioPasswordProvider passwordProvider = new();
            SynchronousProgress progress = new(message =>
                WriteAsync(new WorkerMessage { Type = WorkerMessageTypes.Progress, Progress = message }).GetAwaiter().GetResult());
            ScanCoordinator coordinator = new();
            ScanReport report = await coordinator.RunAsync(start.Options, passwordProvider, progress);
            await WriteAsync(new WorkerMessage { Type = WorkerMessageTypes.Completed, Report = report });
            return 0;
        }
        catch (OperationCanceledException)
        {
            await WriteAsync(new WorkerMessage { Type = WorkerMessageTypes.Failed, Error = "扫描已取消。" });
            return 3;
        }
        catch (Exception ex)
        {
            await WriteAsync(new WorkerMessage
            {
                Type = WorkerMessageTypes.Failed,
                Error = $"{ex.GetType().Name}: {ex.Message}"
            });
            return 1;
        }
    }

    private static async Task WriteAsync(WorkerMessage message)
    {
        await OutputLock.WaitAsync();
        try
        {
            string json = JsonSerializer.Serialize(message, JsonFile.Options);
            json = json.Replace("\r", string.Empty).Replace("\n", string.Empty);
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
                string? line = await Console.In.ReadLineAsync(cancellationToken);
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
