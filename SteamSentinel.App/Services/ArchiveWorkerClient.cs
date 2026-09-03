using System.Text;
using System.Text.Json;
using SteamSentinel.App.Native;
using SteamSentinel.Core.Models;
using SteamSentinel.Core.Utilities;

namespace SteamSentinel.App.Services;

internal sealed class ArchiveWorkerClient
{
    private static readonly JsonSerializerOptions CompactJson = new(JsonFile.Options) { WriteIndented = false };
    private readonly string? _workerPathOverride;

    public ArchiveWorkerClient(string? workerPathOverride = null) =>
        _workerPathOverride = workerPathOverride;

    public async Task<ScanReport> RunAsync(
        ScanOptions options,
        Func<ArchivePasswordRequest, CancellationToken, Task<ArchivePasswordResponse>> passwordCallback,
        IProgress<ScanProgress>? progress,
        CancellationToken cancellationToken)
    {
        string workerPath = _workerPathOverride ?? Path.Combine(AppContext.BaseDirectory, "SteamSentinel.ArchiveWorker.exe");
        if (!File.Exists(workerPath)) throw new FileNotFoundException("缺少隔离内容扫描组件。", workerPath);
        string workerRoot = Path.GetFullPath(AppPaths.WorkerTemporaryRoot);
        Directory.CreateDirectory(workerRoot);
        if (Validation.ContainsReparsePoint(workerRoot))
            throw new UnauthorizedAccessException("工作进程临时目录包含重解析点。");
        string workingDirectory = Path.Combine(workerRoot, Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(workingDirectory);

        using JobObject job = new();
        using RestrictedProcess worker = RestrictedProcess.Start(workerPath, workingDirectory, job);

        using CancellationTokenRegistration registration = cancellationToken.Register(() =>
        {
            try { worker.Kill(); } catch { }
        });
        Task<string> errorTask = worker.StandardError.ReadToEndAsync(cancellationToken);

        try
        {
            using CancellationTokenSource readyTimeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            readyTimeout.CancelAfter(TimeSpan.FromSeconds(10));
            string? readyLine;
            try
            {
                readyLine = await worker.StandardOutput.ReadLineAsync(readyTimeout.Token);
            }
            catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
            {
                throw new TimeoutException("受限内容扫描工作进程没有按时完成安全握手。");
            }
            WorkerMessage? ready = string.IsNullOrWhiteSpace(readyLine)
                ? null
                : JsonSerializer.Deserialize<WorkerMessage>(readyLine, JsonFile.Options);
            if (ready?.Type != WorkerMessageTypes.Ready ||
                ready.Containment is not (nameof(ProcessIntegrityLevel.Low) or nameof(ProcessIntegrityLevel.Untrusted)))
            {
                throw new UnauthorizedAccessException("内容扫描工作进程未运行在 Low Integrity 隔离级别，已拒绝发送扫描路径。");
            }

            await WriteAsync(worker, new WorkerMessage { Type = WorkerMessageTypes.Start, Options = options }, cancellationToken);
            ScanReport? report = null;
            string? failure = null;

            while (true)
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
        finally
        {
            try
            {
                if (!worker.HasExited)
                {
                    worker.Kill();
                    using CancellationTokenSource cleanupTimeout = new(TimeSpan.FromSeconds(3));
                    await worker.WaitForExitAsync(cleanupTimeout.Token);
                }
            }
            catch { }
            try
            {
                if (Directory.Exists(workingDirectory) && !Validation.ContainsReparsePoint(workingDirectory))
                    Directory.Delete(workingDirectory, recursive: true);
            }
            catch { }
        }
    }

    private static async Task WriteAsync(RestrictedProcess process, WorkerMessage message, CancellationToken cancellationToken)
    {
        string json = JsonSerializer.Serialize(message, CompactJson);
        await process.StandardInput.WriteLineAsync(json.AsMemory(), cancellationToken);
        await process.StandardInput.FlushAsync(cancellationToken);
    }
}
