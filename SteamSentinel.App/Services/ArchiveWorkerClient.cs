using System.Diagnostics;
using System.Text;
using System.Text.Json;
using SteamSentinel.App.Native;
using SteamSentinel.Core.Models;
using SteamSentinel.Core.Utilities;

namespace SteamSentinel.App.Services;

internal sealed class ArchiveWorkerClient
{
    private static readonly JsonSerializerOptions CompactJson = new(JsonFile.Options) { WriteIndented = false };

    public async Task<ScanReport> RunAsync(
        ScanOptions options,
        Func<ArchivePasswordRequest, CancellationToken, Task<ArchivePasswordResponse>> passwordCallback,
        IProgress<ScanProgress>? progress,
        CancellationToken cancellationToken)
    {
        string workerPath = Path.Combine(AppContext.BaseDirectory, "SteamSentinel.ArchiveWorker.exe");
        if (!File.Exists(workerPath)) throw new FileNotFoundException("缺少隔离内容扫描组件。", workerPath);

        ProcessStartInfo startInfo = new()
        {
            FileName = workerPath,
            UseShellExecute = false,
            RedirectStandardInput = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true,
            StandardInputEncoding = Encoding.UTF8,
            StandardOutputEncoding = Encoding.UTF8,
            StandardErrorEncoding = Encoding.UTF8
        };
        using Process worker = new() { StartInfo = startInfo };
        worker.Start();
        using JobObject job = new();
        job.Assign(worker);

        using CancellationTokenRegistration registration = cancellationToken.Register(() =>
        {
            try { if (!worker.HasExited) worker.Kill(entireProcessTree: true); } catch { }
        });
        Task<string> errorTask = worker.StandardError.ReadToEndAsync(cancellationToken);

        await WriteAsync(worker, new WorkerMessage { Type = WorkerMessageTypes.Start, Options = options }, cancellationToken);
        ScanReport? report = null;
        string? failure = null;

        while (!worker.HasExited)
        {
            cancellationToken.ThrowIfCancellationRequested();
            string? line = await worker.StandardOutput.ReadLineAsync(cancellationToken);
            if (line is null) break;
            WorkerMessage? message = JsonSerializer.Deserialize<WorkerMessage>(line, JsonFile.Options);
            if (message is null) continue;

            switch (message.Type)
            {
                case WorkerMessageTypes.Progress when message.Progress is not null:
                    progress?.Report(message.Progress);
                    break;
                case WorkerMessageTypes.PasswordRequest when message.PasswordRequest is not null:
                    ArchivePasswordResponse response = await passwordCallback(message.PasswordRequest, cancellationToken);
                    await WriteAsync(worker, new WorkerMessage
                    {
                        Type = WorkerMessageTypes.PasswordResponse,
                        PasswordResponse = response
                    }, cancellationToken);
                    break;
                case WorkerMessageTypes.Completed:
                    report = message.Report;
                    break;
                case WorkerMessageTypes.Failed:
                    failure = message.Error ?? "内容扫描工作进程失败。";
                    break;
            }

            if (report is not null || failure is not null) break;
        }

        await worker.WaitForExitAsync(cancellationToken);
        string error = await errorTask;
        if (report is null)
        {
            throw new InvalidOperationException(failure ?? (string.IsNullOrWhiteSpace(error)
                ? $"内容扫描工作进程异常退出：{worker.ExitCode}"
                : error.Trim()));
        }
        return report;
    }

    private static async Task WriteAsync(Process process, WorkerMessage message, CancellationToken cancellationToken)
    {
        string json = JsonSerializer.Serialize(message, CompactJson);
        await process.StandardInput.WriteLineAsync(json.AsMemory(), cancellationToken);
        await process.StandardInput.FlushAsync(cancellationToken);
    }
}
