using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text.Json;
using Microsoft.Win32.SafeHandles;
using SteamSentinel.App.Services;
using SteamSentinel.Core.Models;
using SteamSentinel.Core.Reporting;
using SteamSentinel.Core.Scanning;
using SteamSentinel.Core.Steam;
using SteamSentinel.Core.Utilities;

namespace SteamSentinel.SelfTest;

internal static partial class Program
{
    // Optional standalone utility: only the generated Large topology is accepted. It runs
    // the production client/Low worker; no fixture executable is launched or disk filled.
    private static async Task<int> RunV020WorkerBoundaryAsync(string manifestPath, string outputDirectory, string? workerOverride = null)
    {
        Stopwatch total = Stopwatch.StartNew();
        int initialPassed = _passed, initialFailures = Failures.Count;
        string manifestFull = Path.GetFullPath(manifestPath), output = Path.GetFullPath(outputDirectory);
        Directory.CreateDirectory(output);
        using JsonDocument manifest = JsonDocument.Parse(await File.ReadAllTextAsync(manifestFull));
        JsonElement spec = manifest.RootElement;
        if (spec.GetProperty("SchemaVersion").GetInt32() != 1 || spec.GetProperty("Profile").GetString() != "Large" ||
            !spec.GetProperty("PasswordIsPublicFixtureData").GetBoolean() || spec.GetProperty("LeafCount").GetInt32() != 167)
            throw new InvalidDataException("边界验收只接受生成的167叶子Large惰性夹具清单。");
        string rootFile = Path.GetFullPath(spec.GetProperty("RootFile").GetString()!);
        if (!ContentDiscovery.IsWithin(rootFile, Path.GetDirectoryName(manifestFull)!)) throw new InvalidDataException("夹具根路径超出清单目录。");
        JsonElement rootLayer = spec.GetProperty("Layers").EnumerateArray().Single(layer =>
            Path.GetFullPath(layer.GetProperty("Path").GetString()!).Equals(rootFile, StringComparison.OrdinalIgnoreCase));
        using FileStream fixture = RelatedArtifactReader.Open(rootFile);
        bool physicalLarge = fixture.Length > 1024L * 1024 * 1024 && fixture.Length == rootLayer.GetProperty("Length").GetInt64() &&
            !rootLayer.GetProperty("Sparse").GetBoolean() && (File.GetAttributes(rootFile) & FileAttributes.SparseFile) == 0;
        Check("0.2边界验收使用清单内大于1GiB的非稀疏实体根文件", physicalLarge);
        if (!physicalLarge) throw new InvalidDataException("边界验收夹具长度或非稀疏条件不符。");

        string workerPath = Path.GetFullPath(workerOverride ?? DevelopmentWorkerPath());
        string workerAssembly = Path.ChangeExtension(workerPath, ".dll"), coreAssembly = Path.Combine(Path.GetDirectoryName(workerPath)!, "SteamSentinel.Core.dll");
        // Keep the exact executable and managed components read-locked throughout all cases.
        using FileStream workerLock = RelatedArtifactReader.Open(workerPath);
        using FileStream assemblyLock = RelatedArtifactReader.Open(workerAssembly);
        using FileStream coreLock = RelatedArtifactReader.Open(coreAssembly);
        string workerHash = await Hashing.Sha256FileAsync(workerPath), assemblyHash = await Hashing.Sha256FileAsync(workerAssembly),
            coreHash = await Hashing.Sha256FileAsync(coreAssembly), manifestHash = await Hashing.Sha256FileAsync(manifestFull);
        Directory.CreateDirectory(AppPaths.WorkerTemporaryRoot);
        string temporaryRoot = OwnedDirectoryPhysicalPath.ResolveForCreation(AppPaths.WorkerTemporaryRoot);
        string diskRoot = Path.GetPathRoot(temporaryRoot)!;
        string publicPassword = spec.GetProperty("Password").GetString()!;
        List<V020WorkerBoundaryResult> results = [];
        using CancellationTokenSource suiteDeadline = new(TimeSpan.FromSeconds(24));

        await RunCase("cancel-large", rootLayer, 30, 1000, 0);
        await RunCase("duration-one-second", rootLayer, 1, null, 0);
        const long maximumReserve = 16L * 1024 * 1024 * 1024;
        long available = new DriveInfo(diskRoot).AvailableFreeSpace;
        if (available < maximumReserve && total.Elapsed < TimeSpan.FromSeconds(20))
        {
            // The same manifest's unencrypted >1GiB RAR reaches its first temporary write
            // without spending the short boundary-test window on outer AES authentication.
            JsonElement diskLayer = spec.GetProperty("Layers").EnumerateArray().Single(layer => layer.GetProperty("Name").GetString() == "disguised-rar");
            await RunCase("disk-reserve-rejection", diskLayer, 30, null, Math.Min(maximumReserve, checked(available + 2L * 1024 * 1024 * 1024)));
        }
        else results.Add(new()
        {
            Name = "disk-reserve-rejection",
            Outcome = "Skipped",
            DiskAvailableBefore = available,
            Detail = available >= maximumReserve ? "可用空间不低于合法16GiB保留量上限，无法仅用合法配置注入磁盘不足；未填充磁盘。" : "为保持整套约30秒的运行边界，未再启动第三个场景。"
        });

        Check("0.2实体Worker边界验收整套在约30秒内返回", total.Elapsed < TimeSpan.FromSeconds(30));
        await JsonFile.WriteAtomicAsync(Path.Combine(output, "worker-boundary-results.json"), new
        {
            Passed = _passed - initialPassed,
            Failed = Failures.Count - initialFailures,
            Failures = Failures.Skip(initialFailures).ToArray(),
            BuildIdentity = ProductInfo.BuildIdentity,
            WorkerPath = workerPath,
            WorkerSha256 = workerHash,
            WorkerAssemblySha256 = assemblyHash,
            CoreAssemblySha256 = coreHash,
            WorkerAssemblyProductVersion = FileVersionInfo.GetVersionInfo(workerAssembly).ProductVersion,
            ManifestPath = manifestFull,
            ManifestSha256 = manifestHash,
            RootFile = rootFile,
            RootLength = fixture.Length,
            ManifestRootSha256 = rootLayer.GetProperty("Sha256").GetString(),
            RootHashRecomputedByHarness = false,
            RootIsSparse = false,
            TemporaryRoot = temporaryRoot,
            Results = results,
            ElapsedMilliseconds = total.ElapsedMilliseconds,
            CompletedAtUtc = DateTimeOffset.UtcNow,
            Safety = "实际Low Worker读取既有非稀疏大文件；前两项使用外层MP4，磁盘项使用同一Large清单的未加密改名RAR。注入主动取消、1秒预算及合法磁盘保留量不足。未执行SFX或叶子、未填磁盘、未模拟真实慢磁盘。保留量场景若不能合法构造则明确跳过。"
        }, options: ReportPrivacy.ExportOptions);
        Console.WriteLine($"V020_WORKER_BOUNDARY_PASS={_passed - initialPassed};FAIL={Failures.Count - initialFailures};ELAPSED_MS={total.ElapsedMilliseconds}");
        return Failures.Count == initialFailures ? 0 : 1;

        async Task RunCase(string name, JsonElement layer, int durationSeconds, int? cancelAfterMilliseconds, long reservedBytes)
        {
            if (suiteDeadline.IsCancellationRequested || total.Elapsed >= TimeSpan.FromSeconds(23))
            {
                results.Add(new() { Name = name, Outcome = "Skipped", Detail = "整套边界验收截止已到，未启动额外进程。" });
                Check("0.2实体Worker边界场景已运行：" + name, false); return;
            }
            string caseTarget = Path.GetFullPath(layer.GetProperty("Path").GetString()!);
            if (!ContentDiscovery.IsWithin(caseTarget, Path.GetDirectoryName(manifestFull)!)) throw new InvalidDataException("场景输入超出本夹具清单目录。");
            using FileStream targetLock = RelatedArtifactReader.Open(caseTarget);
            if (targetLock.Length <= 1024L * 1024 * 1024 || targetLock.Length != layer.GetProperty("Length").GetInt64() ||
                layer.GetProperty("Sparse").GetBoolean() || (File.GetAttributes(caseTarget) & FileAttributes.SparseFile) != 0)
                throw new InvalidDataException("场景输入不是清单匹配的非稀疏大实体文件。");
            ScanOptions options = new()
            {
                Mode = ScanMode.Custom,
                IncludeSystem = false,
                IncludeSteam = false,
                IncludeWorkshop = false,
                IncludeRelatedContent = false,
                UseAmsi = false,
                InspectArchives = true,
                InspectDeepSignatures = false,
                HashEveryFile = true,
                CustomRoots = [caseTarget],
                MaximumContentBytes = long.MaxValue,
                ContainerLimits = new() { MaximumDurationSeconds = durationSeconds, ReservedDiskBytes = reservedBytes }
            };
            HashSet<string> beforeSessions = BoundarySessions(temporaryRoot);
            using V020BoundaryProcessObservation processes = new(workerPath);
            using CancellationTokenSource guard = CancellationTokenSource.CreateLinkedTokenSource(suiteDeadline.Token);
            guard.CancelAfter(TimeSpan.FromSeconds(name == "disk-reserve-rejection" ? 18 : 8));
            using CancellationTokenSource cancellation = CancellationTokenSource.CreateLinkedTokenSource(guard.Token);
            Stopwatch elapsed = Stopwatch.StartNew();
            V020WorkerBoundaryResult result = new()
            {
                Name = name,
                MaximumDurationSeconds = durationSeconds,
                CancelAfterMilliseconds = cancelAfterMilliseconds,
                ReservedDiskBytes = reservedBytes,
                DiskAvailableBefore = new DriveInfo(diskRoot).AvailableFreeSpace,
                TargetPath = caseTarget,
                TargetLength = targetLock.Length,
                ManifestTargetSha256 = layer.GetProperty("Sha256").GetString()
            };
            IProgress<ScanProgress> progress = new V020BoundaryProgress(value =>
            {
                result.ProgressFrames++;
                if (result.Progress.Count < 32) result.Progress.Add(value);
            });
            Task<ScanReport> running = new ArchiveWorkerClient(workerPath).RunAsync(options, (request, token) =>
            {
                token.ThrowIfCancellationRequested(); result.PasswordRequests++;
                return Task.FromResult(new ArchivePasswordResponse(request.RequestId, result.PasswordRequests > 6,
                    result.PasswordRequests > 6 ? null : publicPassword, false, ArchivePasswordReuseScope.ArchiveTree));
            }, progress, cancellation.Token);
            // RunAsync creates its marked workspace synchronously before awaiting Ready. This
            // narrow before/after observation avoids attributing earlier parallel sessions to it.
            string[] sessions = BoundarySessions(temporaryRoot).Except(beforeSessions, StringComparer.OrdinalIgnoreCase).ToArray();
            result.SessionDirectories = sessions;
            processes.Observe();
            if (cancelAfterMilliseconds is int delay) cancellation.CancelAfter(delay);
            using CancellationTokenSource observeStop = new();
            Task observing = ObserveAsync();
            ScanReport? report = null;
            try
            {
                double waitSeconds = Math.Max(1, Math.Min(name == "disk-reserve-rejection" ? 20 : 10, 24 - total.Elapsed.TotalSeconds));
                report = await running.WaitAsync(TimeSpan.FromSeconds(waitSeconds));
                result.Outcome = "ReturnedReport";
            }
            catch (WorkerCancelledException ex) { report = ex.PartialReport; result.Outcome = "Cancelled"; result.Detail = ex.Message; }
            catch (WorkerFailureException ex) { report = ex.PartialReport; result.Outcome = "WorkerFailure"; result.Detail = ex.Message; }
            catch (TimeoutException ex)
            {
                result.Outcome = "HarnessTimeout"; result.Detail = ex.Message; result.HarnessForcedKill = true;
                cancellation.Cancel(); processes.KillObservedChildren();
                try { report = await running.WaitAsync(TimeSpan.FromSeconds(2)); }
                catch (WorkerCancelledException stopped) { report = stopped.PartialReport; }
                catch (WorkerFailureException stopped) { report = stopped.PartialReport; }
                catch (Exception) { }
            }
            catch (Exception ex) { result.Outcome = "UnexpectedFailure"; result.Detail = ex.GetType().Name + ": " + ex.Message; }
            finally
            {
                observeStop.Cancel(); await observing;
                result.ElapsedMilliseconds = elapsed.ElapsedMilliseconds;
                result.GuardDeadlineReached = guard.IsCancellationRequested;
                result.Processes = processes.Snapshot();
                result.AllProcessesExited = result.Processes.Count > 0 && result.Processes.All(process => process.Exited);
                result.SessionBindingUnambiguous = sessions.Length == 1;
                result.AllObservedSessionsCleaned = sessions.Length > 0 && sessions.All(path => !Directory.Exists(path));
                result.DiskAvailableAfter = new DriveInfo(diskRoot).AvailableFreeSpace;
            }
            result.WorkerBuildIdentity = report?.BuildIdentity;
            result.ReturnedPartialReport = report is not null;
            if (report is not null)
            {
                result.PartialReportPath = Path.Combine(output, name + "-report.json");
                await JsonFile.WriteAtomicAsync(result.PartialReportPath, report, options: ReportPrivacy.ExportOptions);
                result.Resources = report.Containers?.Resources;
                result.WorkerTargetSha256 = report.Containers?.Nodes.FirstOrDefault(node => node.ParentId is null && node.OriginalTarget == caseTarget)?.Sha256;
            }
            bool incomplete = report?.Coverage == ScanCoverage.Partial && report.Containers?.Complete != true;
            bool expectedBoundary = name switch
            {
                "cancel-large" => result.Outcome == "Cancelled" && !result.GuardDeadlineReached && report?.CompletedAtUtc is null,
                "duration-one-second" => !result.GuardDeadlineReached && (report?.Containers?.Nodes.Any(node => node.Overall == ContainerStageStatus.LimitReached) == true ||
                    result.Detail?.Contains("ScanResourceLimitException", StringComparison.Ordinal) == true),
                _ => result.Outcome is "ReturnedReport" or "WorkerFailure" && !result.GuardDeadlineReached && reservedBytes > result.DiskAvailableBefore &&
                    reservedBytes > result.DiskAvailableAfter && result.Resources is { DecodedBytes: > 0, PeakTemporaryBytes: 0 } &&
                    result.WorkerTargetSha256 == result.ManifestTargetSha256 &&
                    report?.Containers?.Nodes.Any(node => node.Overall == ContainerStageStatus.LimitReached) == true &&
                    report.Containers.Nodes.All(node => node.Overall != ContainerStageStatus.Corrupt)
            };
            result.ExpectedBoundaryObserved = expectedBoundary;
            if (name == "disk-reserve-rejection")
                result.InjectionExplanation = "合法保留量大于场景前后实测可用空间；要求解码已返回字节、暂存峰值仍为0且覆盖不完整。此项是保留量不足注入，不是真实磁盘写满或慢盘测试。";
            Check("0.2实体Worker触发指定边界：" + name, expectedBoundary && incomplete);
            Check("0.2实体Worker保留交回报告且不误报全量完成：" + name, report is not null && incomplete &&
                (report.Metrics.FilesVisited > 0 || result.Progress.Any(value => value.CurrentItem == caseTarget && value.Completed > 0)));
            Check("0.2实体Worker确为本测试启动的Low进程：" + name,
                result.Processes.Count == 1 && result.Processes[0].Integrity is "Low" or "Untrusted");
            Check("0.2实体Worker有界结束且无需测试工具强杀：" + name,
                result.ElapsedMilliseconds < (name == "disk-reserve-rejection" ? 22_000 : 12_000) && result.AllProcessesExited && !result.HarnessForcedKill);
            Check("0.2实体Worker会话和所有内部临时内容已清理：" + name,
                result.SessionBindingUnambiguous && result.AllObservedSessionsCleaned);
            Check("0.2实体Worker边界只解析夹具不执行内容：" + name, report?.Metrics.ProcessesVisited == 0);
            results.Add(result);
            Console.WriteLine($"WORKER_BOUNDARY {name} {result.Outcome} {result.ElapsedMilliseconds}ms; partial={incomplete}; exited={result.AllProcessesExited}; cleaned={result.AllObservedSessionsCleaned}");

            async Task ObserveAsync()
            {
                try
                {
                    while (!running.IsCompleted)
                    {
                        processes.Observe(); await Task.Delay(40, observeStop.Token);
                    }
                }
                catch (OperationCanceledException) when (observeStop.IsCancellationRequested) { }
            }
        }
    }

    private static HashSet<string> BoundarySessions(string root) => Directory.EnumerateDirectories(root).Take(4096)
        .Where(path => Guid.TryParseExact(Path.GetFileName(path), "N", out _) && File.Exists(Path.Combine(path, ".steamsentinel-session")))
        .ToHashSet(StringComparer.OrdinalIgnoreCase);

    private sealed class V020BoundaryProgress(Action<ScanProgress> callback) : IProgress<ScanProgress>
    { public void Report(ScanProgress value) => callback(value); }

    private sealed class V020WorkerBoundaryResult
    {
        public string Name { get; init; } = "";
        public string? TargetPath { get; init; }
        public long TargetLength { get; init; }
        public string? ManifestTargetSha256 { get; init; }
        public string? WorkerTargetSha256 { get; set; }
        public string Outcome { get; set; } = "";
        public string? Detail { get; set; }
        public string? InjectionExplanation { get; set; }
        public int MaximumDurationSeconds { get; init; }
        public int? CancelAfterMilliseconds { get; init; }
        public long ReservedDiskBytes { get; init; }
        public long DiskAvailableBefore { get; init; }
        public long DiskAvailableAfter { get; set; }
        public long ElapsedMilliseconds { get; set; }
        public int ProgressFrames { get; set; }
        public int PasswordRequests { get; set; }
        public List<ScanProgress> Progress { get; } = [];
        public bool GuardDeadlineReached { get; set; }
        public bool HarnessForcedKill { get; set; }
        public bool ExpectedBoundaryObserved { get; set; }
        public bool ReturnedPartialReport { get; set; }
        public string? WorkerBuildIdentity { get; set; }
        public string? PartialReportPath { get; set; }
        public ContainerResourceSnapshot? Resources { get; set; }
        public string[] SessionDirectories { get; set; } = [];
        public bool SessionBindingUnambiguous { get; set; }
        public bool AllObservedSessionsCleaned { get; set; }
        public List<V020BoundaryProcessResult> Processes { get; set; } = [];
        public bool AllProcessesExited { get; set; }
    }
    private sealed record V020BoundaryProcessResult(int ProcessId, string Integrity, bool Exited);

    private sealed class V020BoundaryProcessObservation(string workerPath) : IDisposable
    {
        private readonly object _sync = new();
        private readonly Dictionary<int, (Process Process, string Integrity)> _observed = [];
        internal void Observe()
        {
            lock (_sync) ObserveLocked();
        }
        private void ObserveLocked()
        {
            using SafeFileHandle snapshot = BoundaryCreateSnapshot(2, 0);
            if (snapshot.IsInvalid) return;
            BoundaryProcessEntry entry = new() { Size = (uint)Marshal.SizeOf<BoundaryProcessEntry>(), ExeFile = "" };
            if (!BoundaryProcessFirst(snapshot, ref entry)) return;
            do
            {
                if (entry.ParentProcessId != Environment.ProcessId || _observed.ContainsKey((int)entry.ProcessId) ||
                    !entry.ExeFile.Equals(Path.GetFileName(workerPath), StringComparison.OrdinalIgnoreCase)) continue;
                Process? process = null;
                try
                {
                    process = Process.GetProcessById((int)entry.ProcessId);
                    if (!string.Equals(process.MainModule?.FileName, workerPath, StringComparison.OrdinalIgnoreCase)) { process.Dispose(); continue; }
                    string integrity = BoundaryIntegrity(process);
                    _observed.Add(process.Id, (process, integrity)); process = null;
                }
                catch (Exception ex) when (ex is Win32Exception or InvalidOperationException or ArgumentException) { process?.Dispose(); }
            } while (BoundaryProcessNext(snapshot, ref entry));
        }
        internal List<V020BoundaryProcessResult> Snapshot()
        {
            lock (_sync) return _observed.Select(pair => new V020BoundaryProcessResult(
                pair.Key, pair.Value.Integrity, pair.Value.Process.HasExited)).ToList();
        }
        internal void KillObservedChildren()
        {
            // Only a failed harness timeout reaches this path. These handles were bound to
            // direct children with the exact requested worker image, never unrelated workers.
            lock (_sync)
                foreach ((Process process, _) in _observed.Values)
                    try { if (!process.HasExited) process.Kill(); } catch (Exception ex) when (ex is Win32Exception or InvalidOperationException) { }
        }
        public void Dispose() { foreach ((Process process, _) in _observed.Values) process.Dispose(); }
    }

    private static string BoundaryIntegrity(Process process)
    {
        if (!BoundaryOpenToken(process.Handle, 8, out SafeAccessTokenHandle token)) return "Unknown";
        using (token)
        {
            BoundaryGetTokenInformation(token, 25, IntPtr.Zero, 0, out uint size);
            if (size is 0 or > 65536) return "Unknown";
            IntPtr memory = Marshal.AllocHGlobal((int)size);
            try
            {
                if (!BoundaryGetTokenInformation(token, 25, memory, size, out _)) return "Unknown";
                string sid = new SecurityIdentifier(Marshal.ReadIntPtr(memory)).Value;
                int rid = int.Parse(sid.Split('-')[^1], System.Globalization.CultureInfo.InvariantCulture);
                return rid < 0x1000 ? "Untrusted" : rid < 0x2000 ? "Low" : rid < 0x3000 ? "Medium" : "HighOrSystem";
            }
            finally { Marshal.FreeHGlobal(memory); }
        }
    }
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct BoundaryProcessEntry
    {
        public uint Size; public uint Usage; public uint ProcessId; public nuint DefaultHeapId;
        public uint ModuleId; public uint Threads; public uint ParentProcessId; public int BasePriority; public uint Flags;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)] public string ExeFile;
    }
    [DllImport("kernel32.dll", SetLastError = true, EntryPoint = "CreateToolhelp32Snapshot")]
    private static extern SafeFileHandle BoundaryCreateSnapshot(uint flags, uint processId);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true, EntryPoint = "Process32FirstW")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool BoundaryProcessFirst(SafeFileHandle snapshot, ref BoundaryProcessEntry entry);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true, EntryPoint = "Process32NextW")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool BoundaryProcessNext(SafeFileHandle snapshot, ref BoundaryProcessEntry entry);
    [DllImport("advapi32.dll", SetLastError = true, EntryPoint = "OpenProcessToken")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool BoundaryOpenToken(IntPtr process, uint access, out SafeAccessTokenHandle token);
    [DllImport("advapi32.dll", SetLastError = true, EntryPoint = "GetTokenInformation")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool BoundaryGetTokenInformation(SafeAccessTokenHandle token, int kind, IntPtr information, uint length, out uint returned);
}
