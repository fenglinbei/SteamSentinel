using System.Text;
using System.Text.Json;
using SteamSentinel.App.Native;
using SteamSentinel.Core.Models;
using SteamSentinel.Core.Scanning;
using SteamSentinel.Core.Utilities;

namespace SteamSentinel.App.Services;

internal sealed class ArchiveWorkerClient
{
    private static readonly JsonSerializerOptions CompactJson = new(JsonFile.Options) { WriteIndented = false };
    private readonly string? _workerPathOverride;

    public ArchiveWorkerClient(string? workerPathOverride = null) =>
        _workerPathOverride = workerPathOverride;

    internal static TimeSpan ScanHardTimeout(ScanOptions options)
    {
        if (options.ContainerLimits is { } limits) ContainerResourceBudget.Validate(limits);
        int seconds = options.ContainerLimits?.MaximumDurationSeconds ?? (options.Mode == ScanMode.Quick ? 300 : 1800);
        // The scanner owns its cooperative deadline. A separate launcher deadline also bounds
        // native decoders and signature providers that never return to the scanner's checks.
        return TimeSpan.FromSeconds(seconds + 5);
    }

    internal static ScanOptions CopyOptions(ScanOptions o, string? recoveryDirectory = null) => new()
    {
        Mode = o.Mode,
        IncludeSystem = o.IncludeSystem,
        IncludeSteam = o.IncludeSteam,
        IncludeWorkshop = o.IncludeWorkshop,
        IncludeRelatedContent = o.IncludeRelatedContent,
        IncludeDownloadLocations = o.IncludeDownloadLocations,
        IncludeExecutionHistory = o.IncludeExecutionHistory,
        RelatedRoots = [.. o.RelatedRoots],
        RelatedSignaturePaths = [.. o.RelatedSignaturePaths],
        MaximumRelatedSignatureBytes = o.MaximumRelatedSignatureBytes,
        WorkshopAppIds = [.. o.WorkshopAppIds],
        MaximumContentBytes = o.MaximumContentBytes,
        MaximumQuickFileBytes = o.MaximumQuickFileBytes,
        MaximumQuickPriorityBytes = o.MaximumQuickPriorityBytes,
        MaximumQuickPriorityFileBytes = o.MaximumQuickPriorityFileBytes,
        MaximumStringScanBytes = o.MaximumStringScanBytes,
        MaximumAmsiBytes = o.MaximumAmsiBytes,
        MaximumWorkerMemoryBytes = o.MaximumWorkerMemoryBytes,
        MaximumReportRecords = o.MaximumReportRecords,
        MaximumReportTextCharacters = o.MaximumReportTextCharacters,
        MaximumStructureDurationSeconds = o.MaximumStructureDurationSeconds,
        RangeLimits = o.RangeLimits,
        InspectArchives = o.InspectArchives,
        UseAmsi = o.UseAmsi,
        HashEveryFile = o.HashEveryFile,
        MaximumArchiveDepth = o.MaximumArchiveDepth,
        MaximumEntryBytes = o.MaximumEntryBytes,
        MaximumExpandedBytes = o.MaximumExpandedBytes,
        ContainerLimits = o.ContainerLimits,
        InspectDeepSignatures = o.InspectDeepSignatures,
        SupplementalVolumeDirectories = [.. o.SupplementalVolumeDirectories],
        RecoveryOutputDirectory = recoveryDirectory,
        MaximumArchiveEntries = o.MaximumArchiveEntries,
        MaximumCompressionRatio = o.MaximumCompressionRatio,
        MaximumFiles = o.MaximumFiles,
        CustomRoots = [.. o.CustomRoots],
        ExcludedRoots = [.. o.ExcludedRoots]
    };

    public async Task<ScanReport> RunAsync(
        ScanOptions options,
        Func<ArchivePasswordRequest, CancellationToken, Task<ArchivePasswordResponse>> passwordCallback,
        IProgress<ScanProgress>? progress,
        CancellationToken cancellationToken)
    {
        ContainerRequestValidation.Validate(options);
        _ = ScanHardTimeout(options);
        string workerPath = _workerPathOverride ?? Path.Combine(AppContext.BaseDirectory, "SteamSentinel.ArchiveWorker.exe");
        if (!File.Exists(workerPath)) throw new WorkerFailureException(WorkerStage.Preflight, null, "缺少隔离内容扫描组件。", new FileNotFoundException(null, workerPath));
        string workerAssembly = Path.ChangeExtension(workerPath, ".dll");
        if (!File.Exists(workerAssembly))
            throw new WorkerFailureException(WorkerStage.Preflight, null, "缺少扫描组件 DLL，不能开始内容检查。", new FileNotFoundException(null, workerAssembly));
        await using WorkerWorkspace workspace = new();
        string workingDirectory = workspace.Path;
        string? recoveryDirectory = options.RecoveryOutputDirectory is null ? null : Path.Combine(workingDirectory, "recovery");
        if (recoveryDirectory is not null) Directory.CreateDirectory(recoveryDirectory);
        ScanOptions workerOptions = CopyOptions(options, recoveryDirectory);

        void PreserveSettings(ScanReport? report)
        {
            if (report is not null) report.ContentScanSettings = CopyOptions(options);
        }
        void DiscardUndeliveredRecovery(ScanReport? report)
        {
            PreserveSettings(report);
            if (report?.Containers is not { } containers) return;
            bool staged = containers.Nodes.Any(node => node.RecoveredContentAvailable);
            containers.RecoveryOutputDirectory = null;
            foreach (ContainerScanNode node in containers.Nodes)
            { node.RecoveredContentAvailable = false; node.RecoveredContentName = null; }
            if (staged && containers.Checks.Count < 512)
                containers.Checks.Add("暂存恢复内容尚未交付到用户输出目录；本轮已停止，不能将临时文件视为已保存结果。");
        }
        ScanReport? producedReport = null;
        bool recoveryExportStarted = false;
        void PreserveExportFailure()
        {
            if (producedReport is null) return;
            // The exporter clears undelivered node flags in its finally block. Retain files it
            // already delivered, including their evidence directory, if a later copy failed.
            if (!recoveryExportStarted || producedReport.Containers?.RecoveryOutputDirectory is null)
                DiscardUndeliveredRecovery(producedReport);
            else
            {
                PreserveSettings(producedReport);
                if (producedReport.Containers.Checks.Count < 512)
                    producedReport.Containers.Checks.Add("恢复内容交付未全部完成；已交付文件及对应证据保留在显示的输出目录中。");
            }
            producedReport.Coverage = ScanCoverage.Partial; producedReport.CompletedAtUtc = null;
        }

        try
        {
            using JobObject job = new(options.MaximumWorkerMemoryBytes);
            using RestrictedProcess worker = RestrictedProcess.Start(workerPath, workingDirectory, job);
            ScanReport report = producedReport = await RunProtocolAsync(worker, workerOptions, passwordCallback, progress, cancellationToken).ConfigureAwait(false);
            PreserveSettings(report);
            if (recoveryDirectory is not null && options.RecoveryOutputDirectory is { } destination)
            {
                if (report.Containers is { } containers) containers.RecoveryOutputDirectory = null;
                recoveryExportStarted = true;
                await ContainerRecoveryExporter.CopyAsync(report, recoveryDirectory, destination, cancellationToken).ConfigureAwait(false);
            }
            else DiscardUndeliveredRecovery(report);
            return report;
        }
        catch (WorkerCancelledException ex) { DiscardUndeliveredRecovery(ex.PartialReport); throw; }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            if (producedReport is null) throw;
            PreserveExportFailure();
            throw new WorkerCancelledException(producedReport, cancellationToken);
        }
        catch (WorkerFailureException ex) { DiscardUndeliveredRecovery(ex.PartialReport); throw; }
        catch (Exception ex)
        {
            if (producedReport is not null)
            {
                PreserveExportFailure();
                throw new WorkerFailureException(WorkerStage.Scanning, null, "恢复内容交付未完成：" + ex.Message, ex) { PartialReport = producedReport };
            }
            throw new WorkerFailureException(WorkerStage.RestrictedStart, null, ex.Message, ex);
        }
    }

    private static async Task<ScanReport> RunProtocolAsync(
        RestrictedProcess worker, ScanOptions options,
        Func<ArchivePasswordRequest, CancellationToken, Task<ArchivePasswordResponse>> passwordCallback,
        IProgress<ScanProgress>? progress, CancellationToken callerCancellationToken)
    {
        using CancellationTokenSource hardTimeout = new(ScanHardTimeout(options));
        using CancellationTokenSource operationCancellation = CancellationTokenSource.CreateLinkedTokenSource(callerCancellationToken, hardTimeout.Token);
        CancellationToken cancellationToken = operationCancellation.Token;
        SemaphoreSlim inputLock = new(1, 1);
        async Task SendAsync(WorkerMessage message, CancellationToken token)
        {
            await inputLock.WaitAsync(token).ConfigureAwait(false);
            try { await WriteAsync(worker, message, token).ConfigureAwait(false); }
            finally { inputLock.Release(); }
        }
        Task? cancellationCleanup = null;
        using CancellationTokenRegistration registration = cancellationToken.Register(() =>
            cancellationCleanup = Task.Run(async () =>
            {
                try
                {
                    using CancellationTokenSource grace = new(TimeSpan.FromSeconds(2));
                    await SendAsync(new WorkerMessage { Type = WorkerMessageTypes.Cancel }, grace.Token)
                        .WaitAsync(grace.Token).ConfigureAwait(false);
                    await worker.WaitForExitAsync(grace.Token).ConfigureAwait(false);
                }
                catch { try { worker.Kill(); } catch { } }
            }));
        using CancellationTokenSource errorCancellation = new();
        BoundedWorkerError errors = new();
        Task errorTask = errors.DrainAsync(worker.StandardError, errorCancellation.Token);
        WorkerStage stage = WorkerStage.Handshake;
        BoundedLineReader output = new(worker.StandardOutput);
        ReportBatchReader batches = new(options.MaximumReportRecords);
        ScanProgress? lastProgress = null;
        WorkerDiagnostics? diagnostics = null;
        string launcherIntegrity = ProcessIntegrity.GetCurrent().ToString();
        long lastUiProgress = 0;
        string? lastUiStage = null;

        ScanReport Partial()
        {
            ScanReport partial = batches.Report ?? new ScanReport { Mode = options.Mode, ContentScanSettings = options };
            partial.Coverage = ScanCoverage.Partial;
            partial.CompletedAtUtc = null;
            if (partial.Containers is { } containers) containers.Complete = false;
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
            await SendAsync(new WorkerMessage { Type = WorkerMessageTypes.Start, Options = options }, cancellationToken);
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
                        if (diagnostics is not null) diagnostics = diagnostics with
                        {
                            Stage = lastProgress.Stage,
                            LastPath = lastProgress.CurrentItem,
                            Operation = lastProgress.Message
                        };
                        if (Environment.TickCount64 - lastUiProgress >= 100 || message.Progress.Stage != lastUiStage)
                        {
                            progress?.Report(message.Progress);
                            lastUiProgress = Environment.TickCount64;
                            lastUiStage = message.Progress.Stage;
                        }
                        break;
                    case WorkerMessageTypes.Checkpoint when message.Batch is not null:
                        batches.Apply(message.Batch);
                        diagnostics = message.Batch.Data.WorkerDiagnostics ?? diagnostics;
                        break;
                    case WorkerMessageTypes.PasswordRequest when message.PasswordRequest is not null:
                        lastProgress = new("等待压缩包密码", message.PasswordRequest.ArchivePath, 0, null, "尚未读取这一层加密内容");
                        if (diagnostics is not null) diagnostics = diagnostics with
                        {
                            Stage = lastProgress.Stage,
                            LastPath = lastProgress.CurrentItem,
                            Operation = lastProgress.Message
                        };
                        ArchivePasswordResponse response = await passwordCallback(message.PasswordRequest, cancellationToken).WaitAsync(cancellationToken);
                        if (!string.Equals(response.RequestId, message.PasswordRequest.RequestId, StringComparison.Ordinal))
                            throw new InvalidDataException("密码响应与当前请求不匹配，已停止内容检查。");
                        _ = ArchivePasswordInput.ValidateAndGetPasswords(response);
                        await SendAsync(new WorkerMessage
                        {
                            Type = WorkerMessageTypes.PasswordResponse,
                            PasswordResponse = response
                        }, cancellationToken);
                        break;
                    case WorkerMessageTypes.Completed:
                        if (message.BatchCount is int expected)
                        {
                            if (expected != batches.Count || batches.Report is null || batches.HasIncompleteTrustProxyDiagnostics || batches.HasIncompleteRelatedComponentDiagnostics || batches.HasIncompleteContainers)
                                throw new InvalidDataException("扫描结果批次缺失，不能作为完整结果。");
                            report = batches.Report;
                        }
                        else
                        {
                            if (message.Report?.Containers is not null)
                                throw new InvalidDataException("容器检查结果必须通过有界分片和结束帧传输。");
                            report = message.Report;
                        }
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
            cancellationToken.ThrowIfCancellationRequested();
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
        catch (OperationCanceledException) when (callerCancellationToken.IsCancellationRequested)
        { throw new WorkerCancelledException(Partial(), callerCancellationToken); }
        catch (Exception ex) when (hardTimeout.IsCancellationRequested && !callerCancellationToken.IsCancellationRequested)
        {
            throw new WorkerFailureException(stage, null,
                "ScanResourceLimitException: 内容检查达到本轮时间上限及结束宽限，已停止受限组件；此前交回的结果已保留，剩余内容尚未完成。",
                new TimeoutException("受限内容扫描超过整轮硬超时。", ex))
            { PartialReport = Partial() };
        }
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
            if (cancellationCleanup is not null)
                try { await cancellationCleanup.WaitAsync(TimeSpan.FromSeconds(3)).ConfigureAwait(false); } catch { }
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
