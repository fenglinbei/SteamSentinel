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
        if (!File.Exists(workerPath)) throw new WorkerFailureException(WorkerStage.Preflight, null, "缺少隔离内容扫描组件。", new FileNotFoundException(null, workerPath));
        string workerAssembly = Path.ChangeExtension(workerPath, ".dll");
        if (!File.Exists(workerAssembly))
            throw new WorkerFailureException(WorkerStage.Preflight, null, "缺少扫描组件 DLL，不能开始内容检查。", new FileNotFoundException(null, workerAssembly));
        string workerRoot = Path.GetFullPath(AppPaths.WorkerTemporaryRoot);
        Directory.CreateDirectory(workerRoot);
        if (Validation.ContainsReparsePoint(workerRoot))
            throw new UnauthorizedAccessException("工作进程临时目录包含重解析点。");
        string workingDirectory = Path.Combine(workerRoot, Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(workingDirectory);

        try
        {
            using JobObject job = new();
            using RestrictedProcess worker = RestrictedProcess.Start(workerPath, workingDirectory, job);
            return await RunProtocolAsync(worker, options, passwordCallback, progress, cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
        catch (WorkerFailureException) { throw; }
        catch (Exception ex)
        {
            throw new WorkerFailureException(WorkerStage.RestrictedStart, null, ex.Message, ex);
        }
        finally
        {
            // Process/Job handles must be closed before removing the child's working directory.
            for (int attempt = 0; attempt < 3; attempt++)
            {
                try
                {
                    if (Directory.Exists(workingDirectory) && !Validation.ContainsReparsePoint(workingDirectory))
                        Directory.Delete(workingDirectory, recursive: true);
                    break;
                }
                catch (IOException) { await Task.Delay(50 * (attempt + 1)).ConfigureAwait(false); }
                catch (UnauthorizedAccessException) { break; }
            }
        }
    }

    private static async Task<ScanReport> RunProtocolAsync(
        RestrictedProcess worker, ScanOptions options,
        Func<ArchivePasswordRequest, CancellationToken, Task<ArchivePasswordResponse>> passwordCallback,
        IProgress<ScanProgress>? progress, CancellationToken cancellationToken)
    {
        using CancellationTokenRegistration registration = cancellationToken.Register(() =>
        {
            try { worker.Kill(); } catch { }
        });
        using CancellationTokenSource errorCancellation = new();
        BoundedWorkerError errors = new();
        Task errorTask = errors.DrainAsync(worker.StandardError, errorCancellation.Token);
        WorkerStage stage = WorkerStage.Handshake;
        BoundedLineReader output = new(worker.StandardOutput);
        ReportBatchReader batches = new();
        ScanProgress? lastProgress = null;
        WorkerDiagnostics? diagnostics = null;
        string launcherIntegrity = ProcessIntegrity.GetCurrent().ToString();
        long lastUiProgress = 0;

        ScanReport Partial()
        {
            ScanReport partial = batches.Report ?? new ScanReport { Mode = options.Mode, ContentScanSettings = options };
            partial.Coverage = ScanCoverage.Partial;
            if (diagnostics is not null) partial.WorkerDiagnostics = diagnostics with { LauncherIntegrity = launcherIntegrity };
            else if (lastProgress is not null) partial.WorkerDiagnostics = new(lastProgress.Stage, lastProgress.CurrentItem,
                lastProgress.Message, 0, 0, 0, DateTimeOffset.UtcNow, LauncherIntegrity: launcherIntegrity);
            return partial;
        }

        try
        {
            using CancellationTokenSource readyTimeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            readyTimeout.CancelAfter(TimeSpan.FromSeconds(10));
            string? readyLine;
            try
            {
                readyLine = await output.ReadLineAsync(readyTimeout.Token);
            }
            catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
            {
                throw new TimeoutException("受限内容扫描工作进程没有按时完成安全握手。");
            }
            WorkerMessage? ready = string.IsNullOrWhiteSpace(readyLine)
                ? null
                : JsonSerializer.Deserialize<WorkerMessage>(readyLine, JsonFile.Options);
            if (ready is null)
                throw new InvalidOperationException("扫描组件在安全握手前关闭了输出通道，未发送扫描路径。");
            if (ready?.Type != WorkerMessageTypes.Ready ||
                ready.Containment is not (nameof(ProcessIntegrityLevel.Low) or nameof(ProcessIntegrityLevel.Untrusted)))
            {
                throw new UnauthorizedAccessException("内容扫描工作进程未运行在 Low Integrity 隔离级别，已拒绝发送扫描路径。");
            }

            stage = WorkerStage.Scanning;
            await WriteAsync(worker, new WorkerMessage { Type = WorkerMessageTypes.Start, Options = options }, cancellationToken);
            ScanReport? report = null;
            string? failure = null;

            while (true)
            {
                cancellationToken.ThrowIfCancellationRequested();
                string? line = await output.ReadLineAsync(cancellationToken);
                if (line is null) break;
                WorkerMessage? message = JsonSerializer.Deserialize<WorkerMessage>(line, JsonFile.Options);
                if (message is null) continue;
                if (message.Diagnostics is not null) diagnostics = message.Diagnostics;

                switch (message.Type)
                {
                    case WorkerMessageTypes.Progress when message.Progress is not null:
                        lastProgress = message.Progress;
                        if (diagnostics is not null) diagnostics = diagnostics with { Stage = lastProgress.Stage,
                            LastPath = lastProgress.CurrentItem, Operation = lastProgress.Message };
                        if (Environment.TickCount64 - lastUiProgress >= 100)
                        { progress?.Report(message.Progress); lastUiProgress = Environment.TickCount64; }
                        break;
                    case WorkerMessageTypes.Checkpoint when message.Batch is not null:
                        batches.Apply(message.Batch);
                        diagnostics = message.Batch.Data.WorkerDiagnostics ?? diagnostics;
                        break;
                    case WorkerMessageTypes.PasswordRequest when message.PasswordRequest is not null:
                        lastProgress = new("等待压缩包密码", message.PasswordRequest.ArchivePath, 0, null, "尚未读取这一层加密内容");
                        if (diagnostics is not null) diagnostics = diagnostics with { Stage = lastProgress.Stage,
                            LastPath = lastProgress.CurrentItem, Operation = lastProgress.Message };
                        ArchivePasswordResponse response = await passwordCallback(message.PasswordRequest, cancellationToken);
                        await WriteAsync(worker, new WorkerMessage
                        {
                            Type = WorkerMessageTypes.PasswordResponse,
                            PasswordResponse = response
                        }, cancellationToken);
                        break;
                    case WorkerMessageTypes.Completed:
                        if (message.BatchCount is int expected)
                        {
                            if (expected != batches.Count || batches.Report is null)
                                throw new InvalidDataException("扫描结果批次缺失，不能作为完整结果。");
                            report = batches.Report;
                        }
                        else report = message.Report;
                        break;
                    case WorkerMessageTypes.Failed:
                        failure = message.Error ?? "内容扫描工作进程失败。";
                        break;
                }

                if (report is not null || failure is not null) break;
            }

            if (report is not null && failure is null) stage = WorkerStage.Exit;
            using CancellationTokenSource exitTimeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            exitTimeout.CancelAfter(TimeSpan.FromSeconds(5));
            await worker.WaitForExitAsync(exitTimeout.Token);
            await errorTask.WaitAsync(TimeSpan.FromSeconds(1), cancellationToken);
            if (report is null || worker.ExitCode != 0)
            {
                throw new InvalidOperationException(failure ?? "扫描组件没有正常返回完整结果。");
            }
            if (report.WorkerDiagnostics is not null)
                report.WorkerDiagnostics = report.WorkerDiagnostics with { LauncherIntegrity = launcherIntegrity };
            report.Findings.Sort((left, right) =>
            {
                int severity = right.Severity.CompareTo(left.Severity);
                return severity != 0 ? severity : right.Score.CompareTo(left.Score);
            });
            return report;
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        { throw new WorkerCancelledException(Partial(), cancellationToken); }
        catch (Exception ex)
        {
            int? exitCode = null;
            try
            {
                // EOF can precede the process signal briefly. Do not mistake our later Kill for its exit code.
                using CancellationTokenSource settle = new(TimeSpan.FromMilliseconds(350));
                await worker.WaitForExitAsync(settle.Token).ConfigureAwait(false);
                exitCode = worker.ExitCode;
                try { await errorTask.WaitAsync(TimeSpan.FromMilliseconds(200)).ConfigureAwait(false); } catch { }
            }
            catch { }
            string detail = ex is OperationCanceledException ? "扫描组件没有在限定时间内正常退出。" : ex.Message;
            if (!string.IsNullOrWhiteSpace(errors.Text)) detail += "\n组件错误输出：" + errors.Text;
            throw new WorkerFailureException(stage, exitCode, detail, ex) { PartialReport = Partial() };
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
            errorCancellation.Cancel();
            try { await errorTask.WaitAsync(TimeSpan.FromSeconds(1)).ConfigureAwait(false); } catch { }
        }
    }

    internal sealed class BoundedWorkerError
    {
        private readonly StringBuilder _text = new();
        private readonly object _sync = new();
        public string Text { get { lock (_sync) return _text.ToString(); } }

        internal async Task DrainAsync(TextReader reader, CancellationToken cancellationToken)
        {
            char[] buffer = new char[1024];
            while (true)
            {
                int count = await reader.ReadAsync(buffer.AsMemory(), cancellationToken).ConfigureAwait(false);
                if (count == 0) return;
                lock (_sync)
                {
                    int keep = Math.Min(count, 4096 - _text.Length);
                    if (keep > 0) _text.Append(buffer, 0, keep);
                }
                // Continue draining after the cap so a noisy worker cannot block on a full pipe.
            }
        }
    }

    private static async Task WriteAsync(RestrictedProcess process, WorkerMessage message, CancellationToken cancellationToken)
    {
        string json = JsonSerializer.Serialize(message, CompactJson);
        await process.StandardInput.WriteLineAsync(json.AsMemory(), cancellationToken);
        await process.StandardInput.FlushAsync(cancellationToken);
    }
}
