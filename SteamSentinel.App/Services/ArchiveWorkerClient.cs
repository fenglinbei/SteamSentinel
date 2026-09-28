using SteamSentinel.Core.Reporting;
using System.Text;
using System.Diagnostics;
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

    internal static ScanOptions CopyOptions(ScanOptions o, string? recoveryDirectory = null, int? parallelFiles = null) => new()
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
        AllowResourceDecisions = o.AllowResourceDecisions,
        MaximumParallelFiles = parallelFiles ?? o.MaximumParallelFiles,
        PerformanceMode = o.PerformanceMode,
        RangeLimits = o.RangeLimits is null ? null : JsonSerializer.Deserialize<ContainerRangeLimits>(JsonSerializer.Serialize(o.RangeLimits)),
        InspectArchives = o.InspectArchives,
        UseAmsi = ScanEnhancements.UseAmsi(o),
        HashEveryFile = o.HashEveryFile,
        MaximumArchiveDepth = o.MaximumArchiveDepth,
        MaximumEntryBytes = o.MaximumEntryBytes,
        MaximumExpandedBytes = o.MaximumExpandedBytes,
        ContainerLimits = o.ContainerLimits is null ? null : JsonSerializer.Deserialize<ContainerResourceLimits>(JsonSerializer.Serialize(o.ContainerLimits)),
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
        CancellationToken cancellationToken,
        Func<ScanResourceProposal, CancellationToken, Task<ScanLimitResponse>>? resourceCallback = null)
    {
        ContainerRequestValidation.Validate(options);
        _ = ScanHardTimeout(options);
        string workerPath = _workerPathOverride ?? Path.Combine(AppContext.BaseDirectory, "SteamSentinel.ArchiveWorker.exe");
        if (!File.Exists(workerPath)) throw new WorkerFailureException(WorkerStage.Preflight, null, MessageText.Create("Backend.App.ArchiveWorkerClient.RunAsync.01"), new FileNotFoundException(null, workerPath));
        string workerAssembly = Path.ChangeExtension(workerPath, ".dll");
        if (!File.Exists(workerAssembly))
            throw new WorkerFailureException(WorkerStage.Preflight, null, MessageText.Create("Backend.App.ArchiveWorkerClient.RunAsync.02"), new FileNotFoundException(null, workerAssembly));
        await using WorkerWorkspace workspace = new();
        string workingDirectory = workspace.Path;
        string? recoveryDirectory = options.RecoveryOutputDirectory is null ? null : Path.Combine(workingDirectory, "recovery");
        if (recoveryDirectory is not null) Directory.CreateDirectory(recoveryDirectory);
        ScanMachineResources preflight = ScanResourcePlanner.Capture(workingDirectory);
        ScanOptions workerOptions = CopyOptions(options, recoveryDirectory,
            Math.Min(options.MaximumParallelFiles, ScanResourcePlanner.ParallelFiles(preflight, options.PerformanceMode)));

        void PreserveSettings(ScanReport? report)
        {
            if (report is not null) report.ContentScanSettings = CopyOptions(workerOptions);
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
                containers.AddCheck(MessageText.Create("Backend.App.ArchiveWorkerClient.RunAsync.03"));
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
                    producedReport.Containers.AddCheck(MessageText.Create("Backend.App.ArchiveWorkerClient.RunAsync.04"));
            }
            producedReport.Coverage = ScanCoverage.Partial; producedReport.CompletedAtUtc = null;
            ScanExecution.Set(producedReport, ScanExecutionState.Failed, ReasonCodes.ComponentFailed);
        }

        try
        {
            using JobObject job = new(options.MaximumWorkerMemoryBytes);
            using RestrictedProcess worker = RestrictedProcess.Start(workerPath, workingDirectory, job);
            ScanReport report = producedReport = await RunProtocolAsync(worker, workerOptions, passwordCallback, progress, cancellationToken,
                job, workingDirectory, preflight, resourceCallback).ConfigureAwait(false);
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
            ScanExecution.Set(producedReport, ScanExecutionState.Cancelled, ReasonCodes.UserCancelled);
            throw new WorkerCancelledException(producedReport, cancellationToken);
        }
        catch (WorkerFailureException ex) { DiscardUndeliveredRecovery(ex.PartialReport); throw; }
        catch (Exception ex)
        {
            if (producedReport is not null)
            {
                PreserveExportFailure();
                throw new WorkerFailureException(WorkerStage.Scanning, null, MessageText.Create("Backend.App.ArchiveWorkerClient.RunAsync.05") + ex.Message, ex) { PartialReport = producedReport };
            }
            throw new WorkerFailureException(WorkerStage.RestrictedStart, null, ex.Message, ex);
        }
    }

    private static async Task<ScanReport> RunProtocolAsync(
        RestrictedProcess worker, ScanOptions options,
        Func<ArchivePasswordRequest, CancellationToken, Task<ArchivePasswordResponse>> passwordCallback,
        IProgress<ScanProgress>? progress, CancellationToken callerCancellationToken,
        JobObject job, string workingDirectory, ScanMachineResources preflight,
        Func<ScanResourceProposal, CancellationToken, Task<ScanLimitResponse>>? resourceCallback)
    {
        using CancellationTokenSource hardTimeout = new(ScanHardTimeout(options));
        Stopwatch activeTime = Stopwatch.StartNew();
        ScanResourceAudit resourceAudit = new() { Preflight = preflight };
        HashSet<string> resourceRequestIds = [];
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
        string? failureReasonCode = null;

        ScanReport Partial(ScanExecutionState state, string reason)
        {
            ScanReport partial = batches.Report ?? new ScanReport { Mode = options.Mode, ContentScanSettings = options };
            if (options.AllowResourceDecisions)
            {
                resourceAudit.Phase = ScanResourcePhase.Finished;
                resourceAudit.PeakParallelFiles = partial.ResourceAudit?.PeakParallelFiles ?? 1;
                partial.ResourceAudit = resourceAudit;
            }
            partial.Coverage = ScanCoverage.Partial;
            ScanExecution.Set(partial, state, reason);
            partial.CompletedAtUtc = null;
            if (partial.Containers is { } containers) containers.Complete = false;
            if (diagnostics is not null) partial.WorkerDiagnostics = diagnostics with { LauncherIntegrity = launcherIntegrity };
            else if (lastProgress is not null) partial.WorkerDiagnostics = new(new MessageText(lastProgress.Stage, lastProgress.StageMessage), new MessageText(lastProgress.CurrentItem, lastProgress.CurrentItemMessage),
                new MessageText(lastProgress.Message, lastProgress.DetailMessage), 0, 0, 0, DateTimeOffset.UtcNow, LauncherIntegrity: launcherIntegrity);
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
                throw MessageExceptions.Create(MessageText.Create("Backend.App.ArchiveWorkerClient.RunProtocolAsync.01"), sourceText => new TimeoutException(sourceText));
            }
            WorkerMessage? ready = string.IsNullOrWhiteSpace(readyLine)
                ? null
                : JsonSerializer.Deserialize<WorkerMessage>(readyLine, JsonFile.Options);
            if (ready is null)
                throw MessageExceptions.Create(MessageText.Create("Backend.App.ArchiveWorkerClient.RunProtocolAsync.02"), sourceText => new InvalidOperationException(sourceText));
            if (ready?.Type != WorkerMessageTypes.Ready ||
                ready.Containment is not (nameof(ProcessIntegrityLevel.Low) or nameof(ProcessIntegrityLevel.Untrusted)))
            {
                throw MessageExceptions.Create(MessageText.Create("Backend.App.ArchiveWorkerClient.RunProtocolAsync.03"), sourceText => new UnauthorizedAccessException(sourceText));
            }

            stage = WorkerStage.Scanning;
            await SendAsync(new WorkerMessage { Type = WorkerMessageTypes.Start, Options = options }, cancellationToken);
            ScanReport? report = null;
            MessageText? failure = null;

            while (true)
            {
                cancellationToken.ThrowIfCancellationRequested();
                string? line = await output.ReadLineAsync(cancellationToken);
                if (line is null) break;
                WorkerMessage? message = JsonSerializer.Deserialize<WorkerMessage>(line, JsonFile.Options);
                if (message is null) continue;
                if (message.Diagnostics is not null) { message.Diagnostics.ValidateDisplayMessages(); diagnostics = message.Diagnostics; }

                switch (message.Type)
                {
                    case WorkerMessageTypes.ResourceRequest when message.ResourceRequest is { } resourceRequest:
                        resourceRequest.Validate();
                        if (!options.AllowResourceDecisions || !resourceRequestIds.Add(resourceRequest.RequestId) ||
                            resourceRequestIds.Count > ScanResourceAudit.MaximumDecisions)
                            throw new InvalidDataException("Unexpected or repeated resource request.");
                        cancellationToken.ThrowIfCancellationRequested();
                        hardTimeout.CancelAfter(Timeout.InfiniteTimeSpan);
                        activeTime.Stop();
                        Stopwatch waiting = Stopwatch.StartNew();
                        resourceAudit.Phase = ScanResourcePhase.AwaitingDecision;
                        try
                        {
                            ScanResourceProposal proposal = ScanResourcePlanner.Propose(options, resourceRequest, ScanResourcePlanner.Capture(workingDirectory));
                            progress?.Report(new ScanProgress(MessageText.Create("Resource.Waiting"), resourceRequest.Target, 0, null,
                                MessageText.Create("Resource.WaitingDetail")));
                            ScanLimitResponse resourceResponse = resourceCallback is null
                                ? new(resourceRequest.RequestId, ResourceDecisionKind.Skip, [], "resource.no_callback")
                                : await resourceCallback(proposal, callerCancellationToken).WaitAsync(callerCancellationToken);
                            if (resourceResponse.RequestId != resourceRequest.RequestId || !Enum.IsDefined(resourceResponse.Decision) || !ResourceDecisionReasons.IsValid(resourceResponse.ReasonCode) || resourceResponse.Changes is null ||
                                resourceResponse.Decision != ResourceDecisionKind.Approve && resourceResponse.Changes.Count != 0)
                                throw new InvalidDataException("Invalid resource decision.");
                            if (resourceResponse.Decision == ResourceDecisionKind.Approve)
                            {
                                if (proposal.Changes.Count == 0 || !resourceResponse.Changes.SequenceEqual(proposal.Changes))
                                    throw new InvalidDataException("Unapproved resource grant.");
                                ScanResourceProposal fresh = ScanResourcePlanner.Propose(options, resourceRequest, ScanResourcePlanner.Capture(workingDirectory));
                                if (fresh.Assessment != ResourceAssessmentKind.EstimatedAvailable)
                                {
                                    progress?.Report(new ScanProgress(MessageText.Create("Resource.CapacityChanged"), resourceRequest.Target, 0, null,
                                        MessageText.Create("Resource.CapacityChangedDetail")));
                                    resourceResponse = new(resourceRequest.RequestId, ResourceDecisionKind.Skip, [], "resource.capacity_changed");
                                }
                                else
                                {
                                    ScanLimitChange? memory = resourceResponse.Changes.FirstOrDefault(c => c.LimitKey == nameof(ScanOptions.MaximumWorkerMemoryBytes));
                                    if (memory is not null) job.SetMemoryLimit(memory.After);
                                    ScanLimitAccess.Apply(options, resourceResponse.Changes);
                                    batches.IncreaseRecordBudget(options.MaximumReportRecords);
                                }
                            }
                            resourceResponse = resourceResponse with { ReasonCode = resourceResponse.ReasonCode ?? ResourceDecisionReasons.For(resourceResponse.Decision) };
                            resourceAudit.Decisions.Add(new(resourceRequest, resourceResponse.Decision, [.. resourceResponse.Changes], DateTimeOffset.UtcNow, resourceResponse.ReasonCode));
                            await SendAsync(new WorkerMessage { Type = WorkerMessageTypes.ResourceResponse, ResourceResponse = resourceResponse }, callerCancellationToken);
                        }
                        finally
                        {
                            resourceAudit.WaitingMilliseconds += waiting.ElapsedMilliseconds;
                            resourceAudit.Phase = ScanResourcePhase.Running;
                            activeTime.Start();
                            hardTimeout.CancelAfter(TimeSpan.FromMilliseconds(Math.Max(1, ScanHardTimeout(options).TotalMilliseconds - activeTime.Elapsed.TotalMilliseconds)));
                        }
                        break;
                    case WorkerMessageTypes.Progress when message.Progress is not null:
                        message.Progress.ValidateDisplayMessages();
                        lastProgress = message.Progress;
                        if (diagnostics is not null) diagnostics = diagnostics with
                        {
                            StageText = new MessageText(lastProgress.Stage, lastProgress.StageMessage),
                            LastPathText = new MessageText(lastProgress.CurrentItem, lastProgress.CurrentItemMessage),
                            OperationText = new MessageText(lastProgress.Message, lastProgress.DetailMessage)
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
                        message.PasswordRequest.ReasonMessage?.Validate();
                        lastProgress = new(MessageText.Create("Backend.App.ArchiveWorkerClient.RunProtocolAsync.04"), message.PasswordRequest.ArchivePath, 0, null, MessageText.Create("Backend.App.ArchiveWorkerClient.RunProtocolAsync.05"));
                        if (diagnostics is not null) diagnostics = diagnostics with
                        {
                            StageText = new MessageText(lastProgress.Stage, lastProgress.StageMessage),
                            LastPathText = new MessageText(lastProgress.CurrentItem, lastProgress.CurrentItemMessage),
                            OperationText = new MessageText(lastProgress.Message, lastProgress.DetailMessage)
                        };
                        ArchivePasswordResponse response = await passwordCallback(message.PasswordRequest, cancellationToken).WaitAsync(cancellationToken);
                        if (!string.Equals(response.RequestId, message.PasswordRequest.RequestId, StringComparison.Ordinal))
                            throw MessageExceptions.Create(MessageText.Create("Backend.App.ArchiveWorkerClient.RunProtocolAsync.06"), sourceText => new InvalidDataException(sourceText));
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
                                throw MessageExceptions.Create(MessageText.Create("Backend.App.ArchiveWorkerClient.RunProtocolAsync.07"), sourceText => new InvalidDataException(sourceText));
                            report = batches.Report;
                        }
                        else
                        {
                            if (message.Report?.Containers is not null)
                                throw MessageExceptions.Create(MessageText.Create("Backend.App.ArchiveWorkerClient.RunProtocolAsync.08"), sourceText => new InvalidDataException(sourceText));
                            report = message.Report;
                        }
                        break;
                    case WorkerMessageTypes.Failed:
                        message.ErrorMessage?.Validate();
                        if (message.ReasonCode is not null && !ReasonCodes.IsValid(message.ReasonCode))
                            throw new InvalidDataException("Invalid worker failure reason code.");
                        failureReasonCode = message.ReasonCode;
                        failure = message.Error is null ? MessageText.Create("Backend.App.ArchiveWorkerClient.RunProtocolAsync.09") : message.ErrorText;
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
                throw MessageExceptions.Create(failure ?? MessageText.Create("Backend.App.ArchiveWorkerClient.RunProtocolAsync.10"), sourceText => new InvalidOperationException(sourceText));
            }
            if (report.WorkerDiagnostics is not null)
                report.WorkerDiagnostics = report.WorkerDiagnostics with { LauncherIntegrity = launcherIntegrity };
            report.Findings.Sort((left, right) =>
            {
                int severity = right.Severity.CompareTo(left.Severity);
                return severity != 0 ? severity : right.Score.CompareTo(left.Score);
            });
            if (options.AllowResourceDecisions)
            {
                resourceAudit.Phase = ScanResourcePhase.Finished;
                resourceAudit.PeakParallelFiles = report.ResourceAudit?.PeakParallelFiles ?? 1;
                report.ResourceAudit = resourceAudit;
            }
            return report;
        }
        catch (OperationCanceledException) when (callerCancellationToken.IsCancellationRequested)
        { throw new WorkerCancelledException(Partial(ScanExecutionState.Cancelled, ReasonCodes.UserCancelled), callerCancellationToken); }
        catch (Exception ex) when (hardTimeout.IsCancellationRequested && !callerCancellationToken.IsCancellationRequested)
        {
            throw new WorkerFailureException(stage, null,
                MessageText.Create("Backend.App.ArchiveWorkerClient.RunProtocolAsync.11"),
                MessageExceptions.Create(MessageText.Create("Backend.App.ArchiveWorkerClient.RunProtocolAsync.12"), sourceText => new TimeoutException(sourceText, ex)), ReasonCodes.ResourceLimit)
            { PartialReport = Partial(ScanExecutionState.Failed, ReasonCodes.ResourceLimit) };
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
            MessageText detail = ex is OperationCanceledException ? MessageText.Create("Backend.App.ArchiveWorkerClient.RunProtocolAsync.13") : MessageExceptions.Describe(ex);
            if (!string.IsNullOrWhiteSpace(errors.Text)) detail += MessageText.Create("Backend.App.ArchiveWorkerClient.RunProtocolAsync.14") + errors.Text;
            string reason = failureReasonCode ?? (diagnostics?.FailureType is { } type ? ReasonCodes.ForFailureType(type)
                : stage is WorkerStage.Preflight or WorkerStage.RestrictedStart or WorkerStage.Handshake
                    ? ReasonCodes.WorkerStartFailed : ReasonCodes.ForFailureType(ex.GetType().Name));
            if (reason == ReasonCodes.UserCancelled)
                throw new WorkerCancelledException(Partial(ScanExecutionState.Cancelled, reason), callerCancellationToken);
            throw new WorkerFailureException(stage, exitCode, detail, ex, reason)
            { PartialReport = Partial(reason == ReasonCodes.UserCancelled ? ScanExecutionState.Cancelled : ScanExecutionState.Failed, reason) };
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
