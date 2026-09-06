using System.Collections;
using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using System.Xml;
using System.Xml.Linq;
using Microsoft.Win32;
using Microsoft.Win32.SafeHandles;
using SteamSentinel.Core.Inspection;
using SteamSentinel.Core.Models;
using SteamSentinel.Core.Steam;

namespace SteamSentinel.Core.Scanning;

public sealed record RelatedSourceRead
{
    public string Kind { get; init; } = string.Empty;
    public string Scope { get; init; } = string.Empty;
    public string Location { get; init; } = string.Empty;
    public string RawCommand { get; init; } = string.Empty;
    public string? ExecutablePath { get; init; }
    public string? Arguments { get; init; }
    public string? WorkingDirectory { get; init; }
    public string? UserSid { get; init; }
    public string? ShortcutPath { get; init; }
    public DiagnosticReadStatus Status { get; init; } = DiagnosticReadStatus.Complete;
    public string Detail { get; init; } = string.Empty;
    public int SnapshotBytesRead { get; init; }
}

public sealed record RelatedProcessRead(int ProcessId, DateTimeOffset? StartedAtUtc, string ImagePath,
    DiagnosticReadStatus Status, string Detail, string? CommandLine = null, string? WorkingDirectory = null,
    string SignatureStatus = "NotChecked", string? SignatureDetail = null);
public sealed record RelatedModuleRead(DiagnosticReadStatus Status, string Detail, bool IdentityMatched, IReadOnlyList<string> Paths);
public sealed record RelatedFileRead(DiagnosticReadStatus Status, string Detail, byte[] Bytes, int BytesRead = 0);
public sealed record RelatedPathRead(DiagnosticReadStatus Status, string Detail, bool IsFile, bool IsDirectory, bool IsUserArea, bool IsProtected);

/// <summary>Inputs are bounded local snapshots. Implementations must never execute a target or resolve a shell link.</summary>
public interface IRelatedComponentDataSource
{
    string? ReadCurrentUserSid();
    IReadOnlyDictionary<string, string> ReadEnvironmentVariables(string targetUserSid);
    IEnumerable<RelatedSourceRead> ReadSources(RelatedComponentDiscoveryRequest request, RelatedComponentLimits limits,
        Func<long> remainingSnapshotBytes, CancellationToken token);
    IEnumerable<RelatedProcessRead> ReadProcesses(int maximumProcesses, CancellationToken token);
    RelatedModuleRead ReadModules(RelatedProcessRead process, int maximumModules, CancellationToken token);
    RelatedPathRead ProbePath(string path);
    RelatedFileRead ReadFile(string path, int maximumBytes, CancellationToken token);
}

/// <summary>Discovers exact file candidates and provenance only. Never hashes, verifies trust, scans a directory, or grants an action.</summary>
public sealed class RelatedComponentDiscovery(IRelatedComponentDataSource? dataSource = null, TimeProvider? timeProvider = null)
{
    private readonly IRelatedComponentDataSource _source = dataSource ?? new WindowsRelatedComponentDataSource();
    private readonly TimeProvider _time = timeProvider ?? TimeProvider.System;
    private static readonly HashSet<string> ScriptExtensions = new([".bat", ".cmd", ".ps1", ".vbs", ".js", ".py"], StringComparer.OrdinalIgnoreCase);
    private static readonly HashSet<string> WrapperNames = new(["cmd", "powershell", "pwsh", "wscript", "cscript", "rundll32", "regsvr32", "python", "pythonw", "py", "mshta", "dotnet"], StringComparer.OrdinalIgnoreCase);

    public void Collect(RelatedComponentDiscoveryRequest request, RelatedComponentDiagnosticReport output,
        RelatedComponentLimits limits, CancellationToken token = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(output);
        ArgumentNullException.ThrowIfNull(limits);
        long started = _time.GetTimestamp();
        long scriptBytes = 0;
        bool stopped = false;
        Dictionary<string, RelatedComponentCandidate> candidates = output.Candidates.ToDictionary(c => c.Path, StringComparer.OrdinalIgnoreCase);
        Dictionary<string, int> candidatePriorities = output.Candidates.ToDictionary(c => c.Path, _ => 1000, StringComparer.OrdinalIgnoreCase);
        HashSet<string> seeds = new(StringComparer.OrdinalIgnoreCase);
        HashSet<string> sourceTargets = new(StringComparer.OrdinalIgnoreCase);
        Dictionary<string, HashSet<string>> pathSources = new(StringComparer.OrdinalIgnoreCase);
        HashSet<string> wrapperContexts = new(StringComparer.OrdinalIgnoreCase);
        HashSet<string> scriptSnapshots = new(StringComparer.OrdinalIgnoreCase);
        Dictionary<string, RelatedPathRead> pathSnapshots = new(StringComparer.OrdinalIgnoreCase);
        IReadOnlyDictionary<string, string> environment = new Dictionary<string, string>();

        void Check(string name, DiagnosticReadStatus status, string detail, string? observation = null, bool required = true)
        {
            if (output.Checks.Any(c => c.Name == name && c.Status == status && c.Detail == detail && c.ObservationId == observation)) return;
            if (output.Checks.Count < 1023) output.Checks.Add(new() { Name = name, Status = status, Detail = detail, ObservationId = observation, Required = required });
            else if (!output.Checks.Any(c => c.Name == "关联检查说明数量")) output.Checks.Add(new()
            { Name = "关联检查说明数量", Status = DiagnosticReadStatus.LimitReached, Detail = "检查说明达到 1024 项上限，其余逐项说明未保存；保留已取得原始观察。" });
        }
        bool Continue()
        {
            if (stopped) return false;
            if (token.IsCancellationRequested)
            { stopped = true; Check("关联候选采集", DiagnosticReadStatus.Cancelled, "已取消；保留此前取得的观察，未继续读取其他来源。"); return false; }
            if (_time.GetElapsedTime(started) >= limits.MaximumDiscoveryDuration)
            { stopped = true; Check("关联发现时间预算", DiagnosticReadStatus.LimitReached, "发现阶段时间预算已用尽，保留此前取得的观察；同步原生调用只在前后检查预算。"); return false; }
            try
            {
                string? current = _source.ReadCurrentUserSid();
                if (!string.IsNullOrWhiteSpace(current) && current.Equals(request.TargetUserSid, StringComparison.OrdinalIgnoreCase)) return true;
                stopped = true;
                Check("关联发现用户身份", DiagnosticReadStatus.AccessDenied, "扫描用户 SID 不匹配或发生变化；未改用另一账户视图，已停止新增关联。");
                return false;
            }
            catch (Exception ex) when (IsReadException(ex))
            { stopped = true; Check("关联发现用户身份", StatusFor(ex), "无法核验当前用户：" + ex.Message); return false; }
        }
        bool Excluded(string path) => request.ExcludedRoots.Any(root => !string.IsNullOrWhiteSpace(root) && ContentDiscovery.IsWithin(path, root));
        RelatedPathRead Probe(string path)
        {
            if (pathSnapshots.TryGetValue(path, out RelatedPathRead? saved)) return saved;
            try { saved = _source.ProbePath(path); }
            catch (Exception ex) when (IsReadException(ex)) { saved = new(StatusFor(ex), ex.Message, false, false, false, false); }
            pathSnapshots.Add(path, saved);
            return saved;
        }
        void RecordPathSource(string path, string sourceId)
        {
            if (!pathSources.TryGetValue(path, out HashSet<string>? ids)) pathSources.Add(path, ids = new(StringComparer.Ordinal));
            ids.Add(sourceId);
        }
        RelatedComponentCandidate? AddCandidate(string raw, string reason, string? sourceId = null, string? hostId = null, bool requireUserArea = false, int priority = 50)
        {
            if (!Continue()) return null;
            if (!RelatedCommandResolver.TryNormalizeLocalLiteral(raw, null, out string? path, out _))
            { Check("候选路径范围", DiagnosticReadStatus.NotChecked, "未采纳非明确本地文件路径：" + Short(raw), sourceId); return null; }
            RelatedPathRead probe = Probe(path!);
            if (Excluded(path!) || probe.IsProtected)
            { Check("候选路径范围", DiagnosticReadStatus.NotChecked, "此路径属于排除或受保护范围，未纳入内容候选：" + path, sourceId, required: false); return null; }
            if (probe.IsDirectory)
            { Check("精确文件候选", DiagnosticReadStatus.NotChecked, "来源指向目录，未扩大为目录全扫：" + path, sourceId); return null; }
            if (requireUserArea && !probe.IsUserArea && !seeds.Contains(path!)) return null;
            if (!candidates.TryGetValue(path!, out RelatedComponentCandidate? candidate))
            {
                if (output.Candidates.Count >= limits.MaximumCandidates)
                {
                    RelatedComponentCandidate? displaced = output.Candidates.Where(c => candidatePriorities.GetValueOrDefault(c.Path, 1000) < priority)
                        .OrderBy(c => candidatePriorities[c.Path]).FirstOrDefault();
                    if (displaced is null)
                    { Check("关联候选数量", DiagnosticReadStatus.LimitReached, $"达到 {limits.MaximumCandidates} 个精确文件上限，未纳入：{path}", sourceId); return null; }
                    output.Candidates.Remove(displaced);
                    candidates.Remove(displaced.Path);
                    candidatePriorities.Remove(displaced.Path);
                    output.Relations.RemoveAll(r => r.FromId == displaced.Id || r.ToId == displaced.Id);
                    Check("关联候选优先级", DiagnosticReadStatus.LimitReached,
                        "候选达到上限，优先保留精确种子或实际模块路径；较低优先级引用仍保存在来源快照中但本轮未纳入内容检查：" + displaced.Path);
                }
                candidate = new()
                {
                    Path = path!,
                    Reason = reason,
                    Status = probe.Status == DiagnosticReadStatus.Complete ? DiagnosticReadStatus.NotChecked : probe.Status,
                    Detail = probe.Status == DiagnosticReadStatus.Complete
                        ? "仅取得本地精确路径与文件属性；尚未核验文件哈希、内容或归属。" : probe.Detail
                };
                candidates.Add(path!, candidate);
                candidatePriorities.Add(path!, priority);
                output.Candidates.Add(candidate);
            }
            else candidatePriorities[path!] = Math.Max(candidatePriorities.GetValueOrDefault(path!, 1000), priority);
            if (sourceId is not null)
            {
                AddUnique(candidate.SourceObservationIds, sourceId);
                RecordPathSource(path!, sourceId);
                AddRelation(output, sourceId, candidate.Id, "SourceReferencesFile", "来源快照含有此精确路径；不证明实际执行或写入配置。");
            }
            if (hostId is not null)
            {
                AddUnique(candidate.HostObservationIds, hostId);
                AddRelation(output, hostId, candidate.Id, "ObservedLoadedModulePath", "在相同 PID、启动时间和映像身份下枚举到此模块路径；文件内容身份尚未核验，也不证明写入行为。");
            }
            return candidate;
        }
        void ReadScript(string path, RelatedSourceObservation parent, IReadOnlyDictionary<string, string>? sourceEnvironment)
        {
            if (!Continue() || !ScriptExtensions.Contains(Path.GetExtension(path)) || !scriptSnapshots.Add(path)) return;
            if (scriptBytes >= limits.MaximumTotalScriptBytes)
            { Check("脚本正文读取", DiagnosticReadStatus.LimitReached, "脚本与快捷方式总字节预算不足，未继续读取正文。", parent.Id); return; }
            int remaining = (int)Math.Min(limits.MaximumScriptBytes, limits.MaximumTotalScriptBytes - scriptBytes);
            RelatedFileRead read;
            try { read = _source.ReadFile(path, remaining, token); }
            catch (Exception ex) when (IsReadException(ex)) { read = new(StatusFor(ex), ex.Message, []); }
            scriptBytes += Math.Max(read.BytesRead, read.Bytes.Length);
            if (!Continue()) return;
            if (scriptBytes > limits.MaximumTotalScriptBytes || read.Bytes.Length > remaining)
            { Check("脚本正文读取", DiagnosticReadStatus.LimitReached, "数据源返回的正文超过约定字节限额，未解析此正文。", parent.Id); return; }
            if (read.Status != DiagnosticReadStatus.Complete)
            { Check("脚本正文读取", read.Status, path + "：" + read.Detail, parent.Id); return; }
            string text = DecodeText(read.Bytes);
            RelatedCommandResolution nested = RelatedCommandResolver.ResolveScriptLiterals(text, path, sourceEnvironment);
            Check("脚本字面引用", nested.Status, string.Join("；", nested.Notes), parent.Id);
            foreach (RelatedResolvedCommandTarget target in nested.Targets)
            {
                if (!AddSourceTarget(parent, target.Path)) continue;
                AddCandidate(target.Path, "启动脚本中出现的本地字面引用，未证明分支运行。", parent.Id, requireUserArea: false, priority: 60);
            }
        }
        bool AddSourceTarget(RelatedSourceObservation source, string path)
        {
            if (RelatedComponentRecordBounds.TryAddTarget(source, path)) return true;
            if (!output.Checks.Any(c => c.Name == "来源目标列表限额" && c.ObservationId == source.Id))
                Check("来源目标列表限额", DiagnosticReadStatus.LimitReached, RelatedComponentRecordBounds.SourceTargetLimitDetail, source.Id);
            return false;
        }
        try
        {
            if (limits.MaximumSources < 0 || limits.MaximumProcesses < 0 || limits.MaximumHosts < 0 || limits.MaximumModulesPerHost < 0 ||
                limits.MaximumCandidates < 0 || limits.MaximumScriptBytes < 0 || limits.MaximumTotalScriptBytes < 0 || limits.MaximumDiscoveryDuration < TimeSpan.Zero)
            { Check("关联发现限额", DiagnosticReadStatus.Failed, "发现限额不能为负数，未开始读取。"); return; }
            if (string.IsNullOrWhiteSpace(request.TargetUserSid) || output.TargetUserSid != request.TargetUserSid)
            { Check("关联发现用户身份", DiagnosticReadStatus.AccessDenied, "缺少目标 SID 或请求和输出的目标 SID 不一致，未开始读取。"); return; }
            try { _ = new SecurityIdentifier(request.TargetUserSid); }
            catch (ArgumentException) { Check("关联发现用户身份", DiagnosticReadStatus.AccessDenied, "目标 SID 格式无效，未开始读取。"); return; }
            if (!Continue()) return;
            try { environment = _source.ReadEnvironmentVariables(request.TargetUserSid); }
            catch (Exception ex) when (IsReadException(ex)) { Check("关联命令环境", StatusFor(ex), "来源身份下的环境未取得；不猜测变量值。" + ex.Message); }
            foreach (string seed in request.SeedPaths.Take(Math.Max(limits.MaximumCandidates, 1) + 1))
            {
                if (!Continue()) return;
                if (RelatedCommandResolver.TryNormalizeLocalLiteral(seed, null, out string? path, out _))
                {
                    seeds.Add(path!);
                    AddCandidate(path!, "已有内容风险或明确选择提供的精确文件路径；内容身份需要独立核验。", priority: 100);
                }
                else Check("精确种子范围", DiagnosticReadStatus.NotChecked, "种子不是明确本地文件路径，未扩大为目录扫描：" + Short(seed));
            }
            if (request.SeedPaths.Count > Math.Max(limits.MaximumCandidates, 1))
                Check("精确种子数量", DiagnosticReadStatus.LimitReached, "精确种子超过候选数量限额，其余未纳入。");

            int sourcesRead = 0;
            using (IEnumerator<RelatedSourceRead> enumerator = _source.ReadSources(request, limits,
                () => Math.Max(0, limits.MaximumTotalScriptBytes - scriptBytes), token).GetEnumerator())
            {
                while (Continue())
                {
                    if (sourcesRead >= limits.MaximumSources)
                    { Check("启动来源数量", DiagnosticReadStatus.LimitReached, $"达到 {limits.MaximumSources} 个来源上限，后续来源未读取。"); break; }
                    if (!enumerator.MoveNext()) break;
                    RelatedSourceRead read = enumerator.Current;
                    if (!Continue()) break;
                    sourcesRead++;
                    scriptBytes += read.SnapshotBytesRead;
                    if (scriptBytes > limits.MaximumTotalScriptBytes)
                    { Check("启动元数据字节预算", DiagnosticReadStatus.LimitReached, "启动来源数据源返回了超出剩余预算的快照，未解析此记录。"); break; }
                    string rawCommand = read.RawCommand;
                    string? executable = read.ExecutablePath, arguments = read.Arguments, working = read.WorkingDirectory;
                    DiagnosticReadStatus readStatus = read.Status;
                    string readDetail = read.Detail;
                    if (read.ShortcutPath is not null && readStatus == DiagnosticReadStatus.Complete)
                    {
                        int remaining = (int)Math.Max(0, Math.Min(limits.MaximumScriptBytes, limits.MaximumTotalScriptBytes - scriptBytes));
                        RelatedFileRead link = remaining == 0 ? new(DiagnosticReadStatus.LimitReached, "快捷方式读取字节预算不足。", []) :
                            _source.ReadFile(read.ShortcutPath, remaining, token);
                        scriptBytes += Math.Max(link.BytesRead, link.Bytes.Length);
                        if (!Continue()) break;
                        if (scriptBytes > limits.MaximumTotalScriptBytes || link.Bytes.Length > remaining)
                            link = new(DiagnosticReadStatus.LimitReached, "数据源返回的快捷方式超过约定字节限额，未解析此对象。", []);
                        readStatus = link.Status;
                        readDetail += " " + link.Detail;
                        if (link.Status == DiagnosticReadStatus.Complete)
                        {
                            ShortcutInspection shortcut = ShortcutInspector.Inspect(link.Bytes);
                            executable = shortcut.Target;
                            arguments = shortcut.Arguments;
                            working = shortcut.WorkingDirectory;
                            rawCommand = (executable is null ? "" : "\"" + executable + "\"") + (string.IsNullOrEmpty(arguments) ? "" : " " + arguments);
                            if (!shortcut.Complete) readStatus = DiagnosticReadStatus.NotChecked;
                            readDetail += " " + shortcut.Detail;
                        }
                    }
                    RelatedSourceObservation source = new()
                    {
                        Kind = read.Kind,
                        Scope = read.Scope,
                        Location = read.Location,
                        RawCommand = rawCommand,
                        WorkingDirectory = working,
                        UserSid = read.UserSid,
                        Status = readStatus,
                        Detail = readDetail
                    };
                    source = RelatedComponentRecordBounds.PrepareOriginal(source, out bool sourceOmitted, request.TargetUserSid);
                    output.Sources.Add(source);
                    if (sourceOmitted)
                    {
                        Check("原始来源记录限额", DiagnosticReadStatus.LimitReached, RelatedComponentRecordBounds.OriginalSourceLimitDetail, source.Id);
                        continue;
                    }
                    if (string.IsNullOrWhiteSpace(rawCommand) && string.IsNullOrWhiteSpace(executable))
                    { Check(source.Kind, source.Status, source.Detail, source.Id); continue; }
                    IReadOnlyDictionary<string, string>? sourceEnvironment = read.Kind is "Run" or "StartupFile" || read.UserSid == request.TargetUserSid
                        ? environment : environment.Where(p => p.Key.Equals("SystemRoot", StringComparison.OrdinalIgnoreCase) || p.Key.Equals("windir", StringComparison.OrdinalIgnoreCase))
                            .ToDictionary(p => p.Key, p => p.Value, StringComparer.OrdinalIgnoreCase);
                    RelatedCommandResolution resolution = RelatedCommandResolver.Resolve(new(rawCommand, working, executable, arguments, sourceEnvironment));
                    if (source.Status == DiagnosticReadStatus.Complete && resolution.Status != DiagnosticReadStatus.Complete) source.Status = resolution.Status;
                    if (resolution.Notes.Count > 0 && !RelatedComponentRecordBounds.TryAppendDetail(source, string.Join("；", resolution.Notes)))
                        Check("来源解析说明限额", DiagnosticReadStatus.LimitReached, RelatedComponentRecordBounds.SourceDetailLimitDetail, source.Id);
                    foreach (RelatedResolvedCommandTarget target in resolution.Targets)
                    {
                        if (!AddSourceTarget(source, target.Path)) continue;
                        sourceTargets.Add(target.Path);
                        RecordPathSource(target.Path, source.Id);
                        bool userOnly = source.Kind is "Service" or "ServiceDll" || source.Scope == "LocalMachine";
                        int priority = target.Kind is "ScriptArgument" or "ModuleArgument" ? 90 : target.Kind is "Executable" or "WrapperExecutable" ? 80 : 50;
                        RelatedComponentCandidate? candidate = AddCandidate(target.Path, "启动来源中的本地命令目标或字面引用，尚未核验内容。", source.Id, requireUserArea: userOnly, priority: priority);
                        if (candidate is not null) ReadScript(candidate.Path, source, sourceEnvironment);
                    }
                    // This is only a bounded host search hint, not a running-instance identity match.
                    foreach (string name in WrapperNames)
                        if (rawCommand.TrimStart(' ', '"').StartsWith(name + ".exe", StringComparison.OrdinalIgnoreCase) ||
                            rawCommand.TrimStart(' ', '"').StartsWith(name + " ", StringComparison.OrdinalIgnoreCase)) wrapperContexts.Add(name);
                    Check(source.Kind, source.Status, source.Detail, source.Id);
                }
            }
            if (!Continue()) return;
            List<(RelatedProcessRead Process, int Priority, string Reason)> hostCandidates = [];
            int processesRead = 0;
            Dictionary<DiagnosticReadStatus, int> inaccessible = [];
            using (IEnumerator<RelatedProcessRead> enumerator = _source.ReadProcesses(limits.MaximumProcesses, token).GetEnumerator())
            {
                while (Continue())
                {
                    if (processesRead >= limits.MaximumProcesses)
                    { Check("进程元数据数量", DiagnosticReadStatus.LimitReached, $"达到 {limits.MaximumProcesses} 个进程元数据上限，其他进程未读取。"); break; }
                    if (!enumerator.MoveNext()) break;
                    RelatedProcessRead process = enumerator.Current;
                    if (!Continue()) break;
                    processesRead++;
                    bool explicitPid = request.SeedProcessIds.Contains(process.ProcessId);
                    if (process.Status != DiagnosticReadStatus.Complete && !explicitPid)
                    { inaccessible[process.Status] = inaccessible.GetValueOrDefault(process.Status) + 1; continue; }
                    int score = 0;
                    string reason = string.Empty;
                    if (explicitPid) { score = 100; reason = "已有观察提供的 PID；当前身份需独立读取。"; }
                    else if (seeds.Contains(process.ImagePath)) { score = 90; reason = "进程映像路径与精确种子相同。"; }
                    else if (SameComponentDirectory(process.ImagePath, seeds))
                    { score = 85; reason = "映像与精确文件种子位于同一组件目录，优先检查模块但不据此确认加载关系。"; }
                    else if (sourceTargets.Contains(process.ImagePath)) { score = 80; reason = "进程映像路径出现在启动来源快照中；未证明此实例由该入口启动。"; }
                    else if (SameComponentDirectory(process.ImagePath, sourceTargets))
                    { score = 50; reason = "映像与精确候选位于同一组件目录，仅用于限制宿主检查范围。"; }
                    else if (wrapperContexts.Contains(Path.GetFileNameWithoutExtension(process.ImagePath)))
                    { score = 30; reason = "启动来源使用同类包装器，仅作为有界宿主搜索范围，不证明此实例执行该命令。"; }
                    if (score > 0 && !Excluded(process.ImagePath)) hostCandidates.Add((process, score, reason));
                }
            }
            foreach (var incomplete in inaccessible) Check("进程元数据读取", incomplete.Key,
                $"{incomplete.Value} 个进程的映像或启动身份未完整取得（{incomplete.Key}），未枚举它们的模块；无法据此排除相关宿主。");
            if (hostCandidates.Count > limits.MaximumHosts) Check("候选宿主数量", DiagnosticReadStatus.LimitReached,
                $"有 {hostCandidates.Count} 个范围候选，按已有 PID、精确路径和启动上下文优先读取 {limits.MaximumHosts} 个；其他宿主未枚举模块。");
            foreach (var selection in hostCandidates.OrderByDescending(p => p.Priority).ThenBy(p => p.Process.ProcessId).Take(limits.MaximumHosts))
            {
                if (!Continue()) return;
                RelatedProcessRead process = selection.Process;
                RelatedHostObservation host = new()
                {
                    ProcessId = process.ProcessId,
                    StartedAtUtc = process.StartedAtUtc,
                    ImagePath = process.ImagePath,
                    CommandLine = process.CommandLine,
                    WorkingDirectory = process.WorkingDirectory,
                    Status = process.Status,
                    Detail = selection.Reason + " " + process.Detail,
                    SignatureStatus = process.SignatureStatus,
                    SignatureDetail = process.SignatureDetail ?? "签名未检查；宿主签名不豁免模块内容检查，也不授权隔离宿主。"
                };
                if (pathSources.TryGetValue(process.ImagePath, out HashSet<string>? ids)) host.SourceObservationIds.AddRange(ids);
                output.Hosts.Add(host);
                foreach (string sourceId in host.SourceObservationIds)
                    AddRelation(output, sourceId, host.Id, "SourceAndHostImagePathMatch", "来源目标与运行映像路径相同；尚未证明启动实例或文件内容身份。");
                if (host.Status != DiagnosticReadStatus.Complete || process.StartedAtUtc is null || string.IsNullOrWhiteSpace(process.ImagePath))
                { Check("候选宿主身份", host.Status == DiagnosticReadStatus.Complete ? DiagnosticReadStatus.NotChecked : host.Status, host.Detail, host.Id); continue; }
                if (process.CommandLine is null || process.WorkingDirectory is null)
                    Check("宿主命令与工作目录", DiagnosticReadStatus.NotChecked, "当前进程命令行或工作目录未取得；未借用启动项内容当作实际进程参数。", host.Id);
                RelatedModuleRead modules;
                try { modules = _source.ReadModules(process, limits.MaximumModulesPerHost, token); }
                catch (Exception ex) when (IsReadException(ex)) { modules = new(StatusFor(ex), ex.Message, false, []); }
                if (!Continue())
                {
                    host.Status = token.IsCancellationRequested ? DiagnosticReadStatus.Cancelled :
                        _time.GetElapsedTime(started) >= limits.MaximumDiscoveryDuration ? DiagnosticReadStatus.LimitReached : DiagnosticReadStatus.AccessDenied;
                    host.Detail += " 本次模块读取返回后采集已停止，未将此批路径确认为当前加载关系。";
                    Check("宿主模块读取", host.Status, host.Detail, host.Id);
                    return;
                }
                host.Status = modules.Status;
                host.Detail += " " + modules.Detail;
                int metadataLimit = limits.MaximumModulesPerHost == 0 ? 0 : (int)Math.Clamp((long)limits.MaximumModulesPerHost * 16, 256, 8192);
                string[] eligibleModules = modules.Paths.Take(metadataLimit).Where(p =>
                        RelatedCommandResolver.TryNormalizeLocalLiteral(p, null, out _, out _) &&
                        !p.Equals(process.ImagePath, StringComparison.OrdinalIgnoreCase) && !Excluded(p) && !Probe(p).IsProtected)
                    .Distinct(StringComparer.OrdinalIgnoreCase).OrderByDescending(p => seeds.Contains(p) ? 100 :
                        Path.GetDirectoryName(p)?.Equals(Path.GetDirectoryName(process.ImagePath), StringComparison.OrdinalIgnoreCase) == true ? 90 : sourceTargets.Contains(p) ? 80 : 50)
                    .ThenBy(p => p, StringComparer.OrdinalIgnoreCase).ToArray();
                if (!modules.IdentityMatched)
                {
                    if (host.Status == DiagnosticReadStatus.Complete) host.Status = DiagnosticReadStatus.NotChecked;
                    host.Detail += " 未取得稳定 PID、启动时间和映像身份，未将模块路径绑定为当前加载关系。";
                    foreach (string module in eligibleModules.Take(limits.MaximumModulesPerHost))
                    {
                        if (module.Equals(process.ImagePath, StringComparison.OrdinalIgnoreCase)) continue;
                        RelatedComponentCandidate? unbound = AddCandidate(module, "模块枚举期间出现的路径，但宿主身份无法复核，未建立当前加载关系。", priority: 40);
                        if (unbound is not null) unbound.Detail += " 宿主身份变化或无法核验；此记录没有新增宿主绑定，需重新读取运行关系。";
                    }
                }
                else foreach (string module in eligibleModules.Take(limits.MaximumModulesPerHost))
                {
                    if (!module.Equals(process.ImagePath, StringComparison.OrdinalIgnoreCase))
                        AddCandidate(module, "在限定宿主快照中枚举到的未知加载组件；宿主签名不会豁免其内容检查。", hostId: host.Id,
                            priority: Path.GetDirectoryName(module)?.Equals(Path.GetDirectoryName(process.ImagePath), StringComparison.OrdinalIgnoreCase) == true ? 95 : 85);
                }
                if (eligibleModules.Length > limits.MaximumModulesPerHost || modules.Paths.Count > metadataLimit)
                { host.Status = DiagnosticReadStatus.LimitReached; host.Detail += " 模块路径超过单宿主上限，超出部分未纳入。"; }
                Check("宿主模块读取", host.Status, host.Detail, host.Id);
            }
            Check("关联候选范围", DiagnosticReadStatus.Complete,
                "仅以启动链、已有精确路径/PID和组件目录确定有界宿主范围；未检查所有进程模块。未以代理/PAC与组件同机出现定位写入者；未验证签名、执行文件、读取任意目录或创建处理动作。", required: false);
        }
        catch (OperationCanceledException)
        { Check("关联候选采集", DiagnosticReadStatus.Cancelled, "已取消，此前取得的观察保留。"); }
        catch (Exception ex) when (IsReadException(ex))
        { Check("关联候选采集", StatusFor(ex), "某个来源读取未完成，已保留此前观察：" + ex.Message); }
    }

    private static bool SameComponentDirectory(string image, IEnumerable<string> paths)
    {
        if (!RelatedCommandResolver.TryNormalizeLocalLiteral(image, null, out string? normalized, out _)) return false;
        string? directory = Path.GetDirectoryName(normalized);
        if (directory is null || directory.Length <= 3 || directory.Equals(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), StringComparison.OrdinalIgnoreCase) ||
            ContentDiscovery.IsWithin(directory, Environment.GetFolderPath(Environment.SpecialFolder.Windows))) return false;
        return paths.Any(path => Path.GetDirectoryName(path)?.Equals(directory, StringComparison.OrdinalIgnoreCase) == true);
    }
    private static void AddRelation(RelatedComponentDiagnosticReport output, string from, string to, string kind, string evidence)
    {
        if (output.Relations.Count < 4096 && !output.Relations.Any(r => r.FromId == from && r.ToId == to && r.Kind == kind))
            output.Relations.Add(new(from, to, kind, evidence));
        else if (output.Relations.Count >= 4096 && !output.Checks.Any(c => c.Name == "关联关系数量")) output.Checks.Add(new()
        { Name = "关联关系数量", Status = DiagnosticReadStatus.LimitReached, Detail = "关系记录达到 4096 条上限；原始观察和候选来源 ID 保留，关联图未完成。" });
    }
    private static void AddUnique(List<string> values, string value) { if (!values.Contains(value, StringComparer.OrdinalIgnoreCase)) values.Add(value); }
    private static string Short(string value) => value.Length <= 256 ? value : value[..256] + "…";
    private static string DecodeText(byte[] bytes)
    {
        using MemoryStream stream = new(bytes, writable: false);
        using StreamReader reader = new(stream, Encoding.UTF8, detectEncodingFromByteOrderMarks: true);
        return reader.ReadToEnd();
    }
    internal static bool IsReadException(Exception ex) => ex is IOException or UnauthorizedAccessException or System.Security.SecurityException or
        Win32Exception or ArgumentException or InvalidOperationException or NotSupportedException or XmlException;
    internal static DiagnosticReadStatus StatusFor(Exception ex) => ex switch
    {
        UnauthorizedAccessException or System.Security.SecurityException => DiagnosticReadStatus.AccessDenied,
        FileNotFoundException or DirectoryNotFoundException => DiagnosticReadStatus.NotPresent,
        Win32Exception native when native.NativeErrorCode is 5 => DiagnosticReadStatus.AccessDenied,
        Win32Exception native when native.NativeErrorCode is 2 or 3 or 87 or 1168 => DiagnosticReadStatus.NotPresent,
        Win32Exception native when native.NativeErrorCode is 32 or 33 or 299 => DiagnosticReadStatus.NotChecked,
        _ => DiagnosticReadStatus.Failed
    };
}

/// <summary>Local registry/file/limited process queries. No WMI shell, shell-link resolution, private key, or write API.</summary>
internal sealed class WindowsRelatedComponentDataSource : IRelatedComponentDataSource
{
    private string? _processUserSid;
    public string? ReadCurrentUserSid()
    {
        using WindowsIdentity identity = WindowsIdentity.GetCurrent();
        if (_processUserSid is null)
        {
            if (!OpenProcessToken(GetCurrentProcess(), 0x0008, out SafeAccessTokenHandle token)) throw new Win32Exception(Marshal.GetLastWin32Error());
            using (token)
            using (WindowsIdentity processIdentity = new(token.DangerousGetHandle())) _processUserSid = processIdentity.User?.Value;
        }
        // Startup folders and process environment belong to the process identity, not an impersonated account.
        return identity.User?.Value == _processUserSid ? _processUserSid : null;
    }
    public IReadOnlyDictionary<string, string> ReadEnvironmentVariables(string targetUserSid)
    {
        if (ReadCurrentUserSid() != targetUserSid) throw new UnauthorizedAccessException("当前有效用户 SID 已变化。");
        Dictionary<string, string> variables = new(StringComparer.OrdinalIgnoreCase);
        foreach (DictionaryEntry pair in Environment.GetEnvironmentVariables())
            if (pair.Key is string key && pair.Value is string value && key.Length <= 128 && value.Length <= RelatedCommandResolver.MaximumCommandCharacters)
                variables[key] = value;
        return variables;
    }

    public IEnumerable<RelatedSourceRead> ReadSources(RelatedComponentDiscoveryRequest request, RelatedComponentLimits limits,
        Func<long> remainingSnapshotBytes, CancellationToken token)
    {
        foreach (RelatedSourceRead item in ReadRun(request.TargetUserSid, false, limits.MaximumSources, token)) yield return item;
        foreach (RelatedSourceRead item in ReadStartup(Environment.GetFolderPath(Environment.SpecialFolder.Startup), request.TargetUserSid, limits.MaximumSources, token)) yield return item;
        foreach (RelatedSourceRead item in ReadRun(request.TargetUserSid, true, limits.MaximumSources, token)) yield return item;
        foreach (RelatedSourceRead item in ReadStartup(Environment.GetFolderPath(Environment.SpecialFolder.CommonStartup), null, limits.MaximumSources, token)) yield return item;
        foreach (RelatedSourceRead item in ReadTasks(limits, remainingSnapshotBytes, token)) yield return item;
        foreach (RelatedSourceRead item in ReadServices(limits.MaximumSources, token)) yield return item;
    }

    private static IEnumerable<RelatedSourceRead> ReadRun(string sid, bool machine, int maximum, CancellationToken token)
    {
        RegistryView[] views = machine && Environment.Is64BitOperatingSystem ? [RegistryView.Registry64, RegistryView.Registry32] :
            [Environment.Is64BitOperatingSystem ? RegistryView.Registry64 : RegistryView.Registry32];
        foreach (RegistryView view in views)
            foreach (string suffix in new[] { @"Software\Microsoft\Windows\CurrentVersion\Run", @"Software\Microsoft\Windows\CurrentVersion\RunOnce" })
            {
                string keyPath = machine ? suffix : sid + "\\" + suffix;
                string location = (machine ? "HKEY_LOCAL_MACHINE\\" : "HKEY_USERS\\") + keyPath + " [" + view + "]";
                List<RelatedSourceRead> rows = [];
                try
                {
                    token.ThrowIfCancellationRequested();
                    using RegistryKey baseKey = RegistryKey.OpenBaseKey(machine ? RegistryHive.LocalMachine : RegistryHive.Users, view);
                    using RegistryKey? key = baseKey.OpenSubKey(keyPath, writable: false);
                    if (key is null) rows.Add(SourceState("Run", machine ? "LocalMachine" : "CurrentUser", location, DiagnosticReadStatus.NotPresent, "来源键不存在。", machine ? null : sid));
                    else
                    {
                        string[] names = key.GetValueNames();
                        foreach (string name in names.Take(maximum))
                        {
                            token.ThrowIfCancellationRequested();
                            try
                            {
                                object? value = key.GetValue(name, null, RegistryValueOptions.DoNotExpandEnvironmentNames);
                                rows.Add(value is string command && command.Length <= RelatedCommandResolver.MaximumCommandCharacters
                                    ? new()
                                    {
                                        Kind = "Run",
                                        Scope = machine ? "LocalMachine" : "CurrentUser",
                                        Location = location + "\\" + name,
                                        RawCommand = command,
                                        UserSid = machine ? null : sid,
                                        Detail = "只读保存原始注册表命令；工作目录未记录，不以当前扫描目录替代。"
                                    }
                                    : SourceState("Run", machine ? "LocalMachine" : "CurrentUser", location + "\\" + name, DiagnosticReadStatus.NotChecked, "注册表值不是有界命令字符串。", machine ? null : sid));
                            }
                            catch (Exception ex) when (RelatedComponentDiscovery.IsReadException(ex))
                            { rows.Add(SourceState("Run", machine ? "LocalMachine" : "CurrentUser", location + "\\" + name, RelatedComponentDiscovery.StatusFor(ex), ex.Message, machine ? null : sid)); }
                        }
                        if (names.Length > maximum) rows.Add(SourceState("Run", machine ? "LocalMachine" : "CurrentUser", location, DiagnosticReadStatus.LimitReached, "此键值数量超过来源限额。", machine ? null : sid));
                    }
                }
                catch (Exception ex) when (RelatedComponentDiscovery.IsReadException(ex))
                { rows.Add(SourceState("Run", machine ? "LocalMachine" : "CurrentUser", location, RelatedComponentDiscovery.StatusFor(ex), ex.Message, machine ? null : sid)); }
                foreach (RelatedSourceRead row in rows) yield return row;
            }
    }

    private IEnumerable<RelatedSourceRead> ReadStartup(string root, string? sid, int maximum, CancellationToken token)
    {
        List<string> notes = [];
        List<string> files = [];
        RelatedSourceRead? unavailable = null;
        try
        {
            token.ThrowIfCancellationRequested();
            FileAttributes attributes = File.GetAttributes(root);
            if ((attributes & FileAttributes.ReparsePoint) != 0 || !ContentDiscovery.IsLocalSafePath(root))
                unavailable = SourceState("StartupDirectory", sid is null ? "LocalMachine" : "CurrentUser", root,
                    DiagnosticReadStatus.NotChecked, "启动目录是重解析点或无法验证为安全本地路径。", sid);
            else
            {
                string[] entries = Directory.EnumerateFileSystemEntries(root).Take(maximum < int.MaxValue ? maximum + 1 : maximum).ToArray();
                foreach (string entry in entries.Take(maximum))
                {
                    token.ThrowIfCancellationRequested();
                    try
                    {
                        FileAttributes item = File.GetAttributes(entry);
                        if ((item & FileAttributes.ReparsePoint) != 0) { notes.Add("启动目录条目为重解析点，未读取：" + entry); continue; }
                        if ((item & FileAttributes.Directory) == 0) files.Add(entry);
                    }
                    catch (Exception ex) when (RelatedComponentDiscovery.IsReadException(ex))
                    { notes.Add("启动目录条目未完整读取（" + RelatedComponentDiscovery.StatusFor(ex) + "）：" + entry + "；" + ex.Message); }
                }
                if (entries.Length > maximum) notes.Add("启动目录条目达到数量上限，其余未读取。");
            }
        }
        catch (Exception ex) when (RelatedComponentDiscovery.IsReadException(ex))
        { unavailable = SourceState("StartupDirectory", sid is null ? "LocalMachine" : "CurrentUser", root, RelatedComponentDiscovery.StatusFor(ex), ex.Message, sid); }
        if (unavailable is not null) yield return unavailable;
        foreach (string file in files)
        {
            token.ThrowIfCancellationRequested();
            if (file.EndsWith("desktop.ini", StringComparison.OrdinalIgnoreCase)) continue;
            yield return new()
            {
                Kind = "StartupFile",
                Scope = sid is null ? "LocalMachine" : "CurrentUser",
                Location = file,
                UserSid = sid,
                RawCommand = file.EndsWith(".lnk", StringComparison.OrdinalIgnoreCase) ? "" : "\"" + file + "\"",
                ExecutablePath = file.EndsWith(".lnk", StringComparison.OrdinalIgnoreCase) ? null : file,
                ShortcutPath = file.EndsWith(".lnk", StringComparison.OrdinalIgnoreCase) ? file : null,
                Detail = "启动目录中的精确文件；快捷方式只解析本地字节，不启动目标或进行 Shell 解析。"
            };
        }
        foreach (string note in notes) yield return SourceState("StartupDirectory", sid is null ? "LocalMachine" : "CurrentUser", root,
            note.Contains("上限", StringComparison.Ordinal) ? DiagnosticReadStatus.LimitReached :
                note.Contains("AccessDenied", StringComparison.Ordinal) ? DiagnosticReadStatus.AccessDenied : DiagnosticReadStatus.NotChecked, note, sid);
    }

    private IEnumerable<RelatedSourceRead> ReadTasks(RelatedComponentLimits limits, Func<long> remainingSnapshotBytes, CancellationToken token)
    {
        string root = RelatedTaskSnapshotReader.TaskRoot;
        List<string> notes = [];
        foreach (string path in ContentDiscovery.Files(root, notes, limits.MaximumSources, 8, token))
        {
            token.ThrowIfCancellationRequested();
            int budget = (int)Math.Max(0, Math.Min(limits.MaximumScriptBytes, remainingSnapshotBytes()));
            RelatedFileRead read = ReadFile(path, budget, token);
            if (read.Status != DiagnosticReadStatus.Complete)
            { yield return SourceState("Task", "LocalMachine", path, read.Status, read.Detail) with { SnapshotBytesRead = read.BytesRead }; continue; }
            List<RelatedSourceRead> rows = [];
            try
            {
                using MemoryStream input = new(read.Bytes, writable: false);
                using XmlReader reader = XmlReader.Create(input, new()
                {
                    DtdProcessing = DtdProcessing.Prohibit,
                    XmlResolver = null,
                    MaxCharactersInDocument = Math.Min(limits.MaximumScriptBytes, RelatedTaskSnapshotReader.MaximumBytes),
                    MaxCharactersFromEntities = 1024
                });
                XDocument document = XDocument.Load(reader);
                if (document.Root?.Name.LocalName != "Task") throw new InvalidDataException("来源不是 Task XML。");
                string? principal = document.Descendants().FirstOrDefault(e => e.Name.LocalName == "UserId")?.Value;
                XElement[] actions = document.Root.Elements().Where(e => e.Name.LocalName == "Actions").SelectMany(e => e.Elements()).ToArray();
                int index = 0;
                foreach (XElement action in actions.Take(32))
                {
                    if (action.Name.LocalName != "Exec")
                    { rows.Add(SourceState("Task", "LocalMachine", path, DiagnosticReadStatus.NotChecked, "任务含非 Exec 动作，未调用 COM 或执行动作。", principal)); continue; }
                    string[] commands = action.Elements().Where(e => e.Name.LocalName == "Command").Select(e => e.Value).ToArray();
                    string[] arguments = action.Elements().Where(e => e.Name.LocalName == "Arguments").Select(e => e.Value).ToArray();
                    string[] working = action.Elements().Where(e => e.Name.LocalName == "WorkingDirectory").Select(e => e.Value).ToArray();
                    if (commands.Length != 1 || arguments.Length > 1 || working.Length > 1 || commands.Concat(arguments).Concat(working).Any(s => s.Length > RelatedCommandResolver.MaximumCommandCharacters))
                    { rows.Add(SourceState("Task", "LocalMachine", path, DiagnosticReadStatus.NotChecked, "任务 Exec 字段重复、缺失或超过长度上限。", principal)); continue; }
                    rows.Add(new()
                    {
                        Kind = "Task",
                        Scope = principal == ReadCurrentUserSid() ? "CurrentUser" : "LocalMachine",
                        Location = path + "#Exec" + (++index),
                        UserSid = principal,
                        ExecutablePath = commands[0],
                        Arguments = arguments.FirstOrDefault(),
                        WorkingDirectory = working.FirstOrDefault(),
                        RawCommand = "\"" + commands[0] + "\"" + (arguments.Length == 0 ? "" : " " + arguments[0]),
                        Detail = "只读解析任务 XML 中 Command、Arguments 与 WorkingDirectory；没有替换为扫描进程工作目录。"
                    });
                }
                if (actions.Length > 32) rows.Add(SourceState("Task", "LocalMachine", path, DiagnosticReadStatus.LimitReached, "单任务动作超过 32 个上限。", principal));
            }
            catch (Exception ex) when (RelatedComponentDiscovery.IsReadException(ex))
            { rows.Add(SourceState("Task", "LocalMachine", path, RelatedComponentDiscovery.StatusFor(ex), ex.Message)); }
            if (rows.Count == 0) rows.Add(SourceState("Task", "LocalMachine", path, DiagnosticReadStatus.Complete, "任务没有 Exec 动作。"));
            rows[0] = rows[0] with { SnapshotBytesRead = Math.Max(read.BytesRead, read.Bytes.Length) };
            foreach (RelatedSourceRead row in rows) yield return row;
        }
        foreach (string note in notes) yield return SourceState("TaskEnumeration", "LocalMachine", root,
            note.Contains("上限", StringComparison.Ordinal) ? DiagnosticReadStatus.LimitReached : DiagnosticReadStatus.NotChecked, note);
    }

    private static IEnumerable<RelatedSourceRead> ReadServices(int maximum, CancellationToken token)
    {
        List<RelatedSourceRead> rows = [];
        const string rootPath = @"SYSTEM\CurrentControlSet\Services";
        try
        {
            using RegistryKey? root = Registry.LocalMachine.OpenSubKey(rootPath, writable: false);
            if (root is null) rows.Add(SourceState("Service", "LocalMachine", rootPath, DiagnosticReadStatus.NotPresent, "服务来源键不存在。"));
            else
            {
                string[] names = root.GetSubKeyNames();
                foreach (string name in names.Take(maximum))
                {
                    token.ThrowIfCancellationRequested();
                    string location = "HKEY_LOCAL_MACHINE\\" + rootPath + "\\" + name;
                    try
                    {
                        using RegistryKey? key = root.OpenSubKey(name, writable: false);
                        if (key is null) { rows.Add(SourceState("Service", "LocalMachine", location, DiagnosticReadStatus.NotPresent, "服务键在读取时不存在。")); continue; }
                        object? image = key.GetValue("ImagePath", null, RegistryValueOptions.DoNotExpandEnvironmentNames);
                        if (image is string command && command.Length <= RelatedCommandResolver.MaximumCommandCharacters)
                            rows.Add(new()
                            {
                                Kind = "Service",
                                Scope = "LocalMachine",
                                Location = location + "\\ImagePath",
                                RawCommand = command,
                                Detail = "只读保存服务 ImagePath；未猜测服务工作目录或将服务视为已启动。"
                            });
                        else if (image is not null) rows.Add(SourceState("Service", "LocalMachine", location + "\\ImagePath", DiagnosticReadStatus.NotChecked, "ImagePath 不是有界字符串。"));
                        using RegistryKey? parameters = key.OpenSubKey("Parameters", writable: false);
                        object? dll = parameters?.GetValue("ServiceDll", null, RegistryValueOptions.DoNotExpandEnvironmentNames);
                        if (dll is string module && module.Length <= RelatedCommandResolver.MaximumCommandCharacters)
                            rows.Add(new()
                            {
                                Kind = "ServiceDll",
                                Scope = "LocalMachine",
                                Location = location + "\\Parameters\\ServiceDll",
                                RawCommand = "\"" + module + "\"",
                                ExecutablePath = module,
                                Detail = "只读保存服务 DLL 精确配置；不证明当前实例已加载或写入任何配置。"
                            });
                    }
                    catch (Exception ex) when (RelatedComponentDiscovery.IsReadException(ex))
                    { rows.Add(SourceState("Service", "LocalMachine", location, RelatedComponentDiscovery.StatusFor(ex), ex.Message)); }
                }
                if (names.Length > maximum) rows.Add(SourceState("ServiceEnumeration", "LocalMachine", rootPath, DiagnosticReadStatus.LimitReached, "服务数量超过来源限额。"));
            }
        }
        catch (Exception ex) when (RelatedComponentDiscovery.IsReadException(ex))
        { rows.Add(SourceState("ServiceEnumeration", "LocalMachine", rootPath, RelatedComponentDiscovery.StatusFor(ex), ex.Message)); }
        foreach (RelatedSourceRead row in rows) yield return row;
    }

    public IEnumerable<RelatedProcessRead> ReadProcesses(int maximumProcesses, CancellationToken token)
    {
        Process[] processes = Process.GetProcesses();
        try
        {
            foreach (Process process in processes.OrderBy(p => p.Id).Take(maximumProcesses < int.MaxValue ? maximumProcesses + 1 : maximumProcesses))
            { token.ThrowIfCancellationRequested(); yield return ReadProcess(process.Id); }
        }
        finally { foreach (Process process in processes) process.Dispose(); }
    }

    public RelatedModuleRead ReadModules(RelatedProcessRead expected, int maximumModules, CancellationToken token)
    {
        token.ThrowIfCancellationRequested();
        if (maximumModules <= 0) return new(DiagnosticReadStatus.LimitReached, "单宿主模块限额为零，未开始枚举。", false, []);
        RelatedProcessRead before = ReadProcess(expected.ProcessId);
        if (!SameProcess(expected, before)) return new(DiagnosticReadStatus.NotChecked, "模块读取前 PID、启动时间或映像身份已变化或无法核验。", false, []);
        List<string> paths = [];
        DiagnosticReadStatus status = DiagnosticReadStatus.Complete;
        string detail = "只读枚举限定宿主的模块路径；没有停止进程、读取模块内存或核验模块内容。";
        try
        {
            using Process process = Process.GetProcessById(expected.ProcessId);
            int visited = 0, maximumMetadata = (int)Math.Clamp((long)maximumModules * 16, 256, 8192);
            foreach (ProcessModule module in process.Modules)
            {
                token.ThrowIfCancellationRequested();
                if (++visited > maximumMetadata)
                { status = DiagnosticReadStatus.LimitReached; detail += $" 模块路径元数据达到 {maximumMetadata} 项上限。"; break; }
                string path = module.FileName;
                if (path.Equals(expected.ImagePath, StringComparison.OrdinalIgnoreCase) || RelatedArtifactReader.IsProtected(path)) continue;
                if (paths.Count >= maximumModules)
                { status = DiagnosticReadStatus.LimitReached; detail += " 模块枚举达到单宿主上限。"; break; }
                paths.Add(path);
            }
            detail += $" 排除 Windows/本工具模块后最多保留 {maximumModules} 条组件路径；最多查看 {maximumMetadata} 条模块路径元数据，未对系统 DLL 进行内容扫描。";
        }
        catch (Exception ex) when (RelatedComponentDiscovery.IsReadException(ex))
        { status = RelatedComponentDiscovery.StatusFor(ex); detail += " " + ex.Message; }
        RelatedProcessRead after = ReadProcess(expected.ProcessId);
        bool matches = SameProcess(expected, after);
        if (!matches) { status = DiagnosticReadStatus.NotChecked; detail += " 模块读取后宿主身份变化，未建立当前加载关系。"; }
        return new(status, detail, matches, paths);
    }

    public RelatedPathRead ProbePath(string path)
    {
        if (!ContentDiscovery.IsLocalSafePath(path)) return new(DiagnosticReadStatus.NotChecked, "网络路径、重解析点或路径安全属性未验证。", false, false, false, false);
        bool protectedPath = RelatedArtifactReader.IsProtected(path);
        bool user = new[] { Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), Path.GetTempPath() }
            .Any(root => !string.IsNullOrWhiteSpace(root) && ContentDiscovery.IsWithin(path, root));
        try
        {
            FileAttributes attributes = File.GetAttributes(path);
            bool directory = (attributes & FileAttributes.Directory) != 0;
            return new(DiagnosticReadStatus.Complete, "只读取得本地文件属性；用户目录位置不等于已验证 ACL 可写性。", !directory, directory, user, protectedPath);
        }
        catch (Exception ex) when (RelatedComponentDiscovery.IsReadException(ex))
        { return new(RelatedComponentDiscovery.StatusFor(ex), ex.Message, false, false, user, protectedPath); }
    }

    public RelatedFileRead ReadFile(string path, int maximumBytes, CancellationToken token)
    {
        if (maximumBytes <= 0) return new(DiagnosticReadStatus.LimitReached, "没有剩余元数据读取预算。", []);
        int bytesRead = 0;
        try
        {
            token.ThrowIfCancellationRequested();
            using FileStream stream = RelatedArtifactReader.Open(path);
            if (stream.Length > maximumBytes) return new(DiagnosticReadStatus.LimitReached, "文件超过单项或剩余字节预算，未读取正文。", []);
            byte[] bytes = new byte[checked((int)stream.Length)];
            while (bytesRead < bytes.Length)
            {
                token.ThrowIfCancellationRequested();
                int read = stream.Read(bytes, bytesRead, Math.Min(64 * 1024, bytes.Length - bytesRead));
                if (read == 0) throw new EndOfStreamException("文件在读取过程中长度变化。");
                bytesRead += read;
            }
            RelatedArtifactReader.ValidatePath(stream.SafeFileHandle, Path.GetFullPath(path));
            return new(DiagnosticReadStatus.Complete, "通过只读、拒绝写入/删除的句柄取得字节快照并核对最终路径。", bytes, bytesRead);
        }
        catch (Exception ex) when (RelatedComponentDiscovery.IsReadException(ex))
        { return new(RelatedComponentDiscovery.StatusFor(ex), ex is Win32Exception { NativeErrorCode: 32 or 33 } ? "文件被占用，未强行解锁或停止进程。" : ex.Message, [], bytesRead); }
    }

    private static RelatedSourceRead SourceState(string kind, string scope, string location, DiagnosticReadStatus status, string detail, string? sid = null) =>
        new() { Kind = kind, Scope = scope, Location = location, Status = status, Detail = detail, UserSid = sid };
    private static bool SameProcess(RelatedProcessRead expected, RelatedProcessRead actual) => actual.Status == DiagnosticReadStatus.Complete &&
        expected.ProcessId == actual.ProcessId && expected.StartedAtUtc is not null && expected.StartedAtUtc == actual.StartedAtUtc &&
        expected.ImagePath.Equals(actual.ImagePath, StringComparison.OrdinalIgnoreCase);
    private static RelatedProcessRead ReadProcess(int pid)
    {
        // Public limited-query APIs: https://learn.microsoft.com/windows/win32/api/winbase/nf-winbase-queryfullprocessimagenamew
        using SafeProcessHandle handle = OpenProcess(0x1000, false, pid);
        if (handle.IsInvalid)
        {
            Win32Exception ex = new(Marshal.GetLastWin32Error());
            return new(pid, null, "", RelatedComponentDiscovery.StatusFor(ex), "无法只读取得进程身份：" + ex.Message);
        }
        StringBuilder image = new(RelatedCommandResolver.MaximumCommandCharacters);
        uint length = (uint)image.Capacity;
        if (!QueryFullProcessImageName(handle, 0, image, ref length) || !GetProcessTimes(handle, out long created, out _, out _, out _))
        {
            Win32Exception ex = new(Marshal.GetLastWin32Error());
            return new(pid, null, image.ToString(), RelatedComponentDiscovery.StatusFor(ex), "进程映像或启动时间未取得：" + ex.Message);
        }
        try
        {
            return new(pid, DateTimeOffset.FromFileTime(created).ToUniversalTime(), image.ToString(), DiagnosticReadStatus.Complete,
            "已取得 PID、启动时间和映像路径；命令行/工作目录没有公开直接读取结果，保留未知，未读取 PEB 或猜测偏移。");
        }
        catch (ArgumentOutOfRangeException ex) { return new(pid, null, image.ToString(), DiagnosticReadStatus.Failed, ex.Message); }
    }
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern SafeProcessHandle OpenProcess(uint access, [MarshalAs(UnmanagedType.Bool)] bool inheritHandle, int processId);
    [DllImport("kernel32.dll")]
    private static extern IntPtr GetCurrentProcess();
    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool OpenProcessToken(IntPtr process, uint access, out SafeAccessTokenHandle token);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, EntryPoint = "QueryFullProcessImageNameW", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool QueryFullProcessImageName(SafeProcessHandle process, uint flags, StringBuilder name, ref uint size);
    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetProcessTimes(SafeProcessHandle process, out long creation, out long exit, out long kernel, out long user);
}
