using System.Buffers.Binary;
using System.IO;
using System.Text;
using SteamSentinel.Core.Models;
using SteamSentinel.Core.Scanning;

namespace SteamSentinel.SelfTest;

internal static partial class Program
{
    private static void TestPhase2Discovery()
    {
        const string sid = "S-1-5-21-100-200-300-1001";
        const string app = @"C:\Users\Fixture\App";
        const string hostPath = app + @"\SignedHost.exe";
        const string module = app + @"\unknown.dll";
        const string script = app + @"\loader.ps1";
        DateTimeOffset start = new(2026, 9, 6, 4, 0, 0, TimeSpan.Zero);
        Dictionary<string, string> environment = new(StringComparer.OrdinalIgnoreCase) { ["APPDATA"] = @"C:\Users\Fixture\AppData\Roaming" };

        RelatedCommandResolution ps = RelatedCommandResolver.Resolve(new("powershell.exe -NoProfile -File .\\loader.ps1", app));
        Check("第二批 命令解析显式工作目录中的相对PowerShell脚本",
            ps.Targets.Any(t => t.Path == script && t.Kind == "ScriptArgument" && t.ResolutionBasis == "ExplicitWorkingDirectory"));
        RelatedCommandResolution dll = RelatedCommandResolver.Resolve(new("rundll32.exe \".\\unknown.dll\",Entry", app));
        Check("第二批 rundll32参数保留DLL路径且不当作宿主内容身份",
            dll.Targets.Any(t => t.Path == module && t.Kind == "ModuleArgument") && dll.Status == DiagnosticReadStatus.NotChecked);
        RelatedCommandResolution nested = RelatedCommandResolver.Resolve(new("cmd.exe /c \"\"C:\\Users\\Fixture\\App\\wrapper.cmd\" --probe\""));
        Check("第二批 只读拆分cmd双引号包装器",
            nested.Targets.Any(t => t.Path == app + @"\wrapper.cmd" && t.Kind == "Executable"));
        RelatedCommandResolution quoted = RelatedCommandResolver.Resolve(new("\"C:\\Program Files\\Fixture\\host.exe\" -quiet"));
        RelatedCommandResolution unquoted = RelatedCommandResolver.Resolve(new(@"C:\Program Files\Fixture\host.exe -quiet"));
        Check("第二批 未加引号空格程序路径保留歧义而不确认实际映像",
            quoted.Targets.Any(t => t.Kind == "Executable") && unquoted.Status == DiagnosticReadStatus.NotChecked &&
            unquoted.Targets.All(t => t.Kind != "Executable") && unquoted.Targets.Any(t => t.Path == @"C:\Program Files\Fixture\host.exe"));
        RelatedCommandResolution expanded = RelatedCommandResolver.Resolve(new("\"%APPDATA%\\loader.exe\"", EnvironmentVariables: environment));
        RelatedCommandResolution missing = RelatedCommandResolver.Resolve(new("\"%UNSEEN%\\loader.exe\""));
        Check("第二批 环境变量只来自显式身份快照且缺失变量不借用本机环境",
            expanded.Targets.Any(t => t.Path == @"C:\Users\Fixture\AppData\Roaming\loader.exe") &&
            missing.Status == DiagnosticReadStatus.NotChecked && missing.Targets.Count == 0);
        RelatedCommandResolution noDirectory = RelatedCommandResolver.Resolve(new("wscript.exe .\\loader.vbs"));
        Check("第二批 缺少工作目录不按扫描器当前目录定位相对文件", noDirectory.Targets.Count == 0 && noDirectory.Status == DiagnosticReadStatus.NotChecked);
        RelatedCommandResolution structured = RelatedCommandResolver.Resolve(new("source original", app, @"C:\Program Files\Fixture\host.exe", "-quiet"));
        Check("第二批 结构化任务目标有空格时不丢失程序边界",
            structured.Targets.Any(t => t.Path == @"C:\Program Files\Fixture\host.exe" && t.Kind == "Executable"));
        RelatedCommandResolution shell = RelatedCommandResolver.Resolve(new(@"cmd.exe /c C:\Users\Fixture\App\one.exe & C:\Users\Fixture\App\two.exe"));
        Check("第二批 复合shell命令仅保留字面引用不证明执行顺序",
            shell.Status == DiagnosticReadStatus.NotChecked && shell.Targets.Count > 0 && shell.Targets.All(t => t.Kind == "LiteralReference"));
        RelatedCommandResolution encoded = RelatedCommandResolver.Resolve(new("powershell.exe -EncodedCommand " + Convert.ToBase64String(Encoding.Unicode.GetBytes("Start-Process C:\\unknown.exe"))));
        Check("第二批 编码或内联PowerShell命令不执行或假装完整解析", encoded.Status == DiagnosticReadStatus.NotChecked && encoded.Targets.Count == 0);
        Check("第二批 UNC设备路径ADS和驱动器相对路径不进入精确候选",
            new[] { @"\\server\share\bad.dll", @"\\?\C:\bad.dll", @"C:\bad.dll:stream", @"C:bad.dll" }
                .All(path => RelatedCommandResolver.Resolve(new("\"" + path + "\"")).Targets.Count == 0));
        RelatedCommandResolution scriptReferences = RelatedCommandResolver.ResolveScriptLiterals(
            "rundll32 \"$PSScriptRoot\\unknown.dll\",Entry\r\ncall %~dp0next.cmd", script);
        Check("第二批 脚本目录字面引用可解析但不执行分支",
            scriptReferences.Targets.Any(t => t.Path == module) && scriptReferences.Targets.Any(t => t.Path == app + @"\next.cmd") &&
            scriptReferences.Status == DiagnosticReadStatus.NotChecked);
        Check("第二批 命令和字面目标数量严格有界",
            RelatedCommandResolver.Resolve(new(new string('x', RelatedCommandResolver.MaximumCommandCharacters + 1))).Status == DiagnosticReadStatus.LimitReached &&
            RelatedCommandResolver.Resolve(new(string.Join(" ", Enumerable.Range(0, 50).Select(i => @"C:\Users\Fixture\App\" + i + ".dll")))).Targets.Count <= RelatedCommandResolver.MaximumTargets);

        Phase2SourceFixture fixture = new(sid);
        fixture.Sources.Add(new() { Kind = "Run", Scope = "CurrentUser", UserSid = sid, Location = "HKU/fixture/Run/Host", RawCommand = "\"" + hostPath + "\"" });
        fixture.Processes.Add(new(101, start, hostPath, DiagnosticReadStatus.Complete, "fixture", "\"" + hostPath + "\"", app, "Valid", "已在离线固定夹具中提供签名观察。"));
        fixture.Processes.Add(new(102, start, @"C:\Unrelated\other.exe", DiagnosticReadStatus.Complete, "fixture"));
        fixture.Modules[101] = new(DiagnosticReadStatus.Complete, "fixture", true, [hostPath, module, @"C:\Windows\System32\kernel32.dll"]);
        RelatedComponentDiagnosticReport discovery = Discover(fixture);
        RelatedComponentCandidate foundModule = discovery.Candidates.Single(c => c.Path == module);
        Check("第二批 签名有效宿主仍产生未知DLL内容候选且不扫描无关进程模块",
            foundModule.HostObservationIds.Count == 1 && discovery.Hosts.Single().SignatureStatus == "Valid" &&
            fixture.ModuleRequests.SequenceEqual(new[] { 101 }) && discovery.Candidates.All(c => !c.Path.StartsWith(@"C:\Windows\", StringComparison.OrdinalIgnoreCase)));
        Check("第二批 候选无哈希和内容结论且关系只保留观察资格",
            discovery.Candidates.All(c => c.Sha256 is null && c.ContentStatus == DiagnosticReadStatus.NotChecked && c.VerifiedAtUtc is null) &&
            discovery.Hosts.All(h => h.ImageSha256 is null) &&
            discovery.Relations.Any(r => r.Kind == "ObservedLoadedModulePath" && r.ToId == foundModule.Id));
        Check("第二批 启动来源保留原命令位置与用户SID",
            discovery.Sources.Single().RawCommand == "\"" + hostPath + "\"" && discovery.Sources.Single().UserSid == sid &&
            discovery.Sources.Single().Location == "HKU/fixture/Run/Host");

        Phase2SourceFixture moduleSeed = new(sid);
        moduleSeed.Processes.Add(new(201, start, hostPath, DiagnosticReadStatus.Complete, "fixture", "cmd", app));
        moduleSeed.Modules[201] = new(DiagnosticReadStatus.Complete, "fixture", true, [module]);
        RelatedComponentDiagnosticReport sameDirectory = Discover(moduleSeed, new() { TargetUserSid = sid, SeedPaths = [module] });
        Check("第二批 DLL种子可通过有界组件目录宿主检查找到加载者",
            moduleSeed.ModuleRequests.SequenceEqual(new[] { 201 }) && sameDirectory.Candidates.Single(c => c.Path == module).HostObservationIds.Count == 1 &&
            sameDirectory.Candidates.All(c => c.Path != hostPath));

        Phase2SourceFixture changed = new(sid);
        changed.Processes.Add(new(301, start, hostPath, DiagnosticReadStatus.Complete, "fixture", "cmd", app));
        changed.Modules[301] = new(DiagnosticReadStatus.NotChecked, "读取期间 PID 的启动时间已变化。", false, [module]);
        RelatedComponentDiagnosticReport reused = Discover(changed, new() { TargetUserSid = sid, SeedProcessIds = [301] });
        Check("第二批 PID复用保留未绑定候选但不写宿主加载关系",
            reused.Hosts.Single().Status == DiagnosticReadStatus.NotChecked && reused.Candidates.Single().HostObservationIds.Count == 0 &&
            reused.Relations.All(r => r.Kind != "ObservedLoadedModulePath"));

        Phase2SourceFixture identity = new(sid);
        identity.Processes.Add(new(401, start, hostPath, DiagnosticReadStatus.Complete, "fixture", "cmd", app));
        identity.Modules[401] = new(DiagnosticReadStatus.Complete, "fixture", true, [module]);
        identity.AfterModules = () => identity.Sid = "S-1-5-21-100-200-300-1002";
        RelatedComponentDiagnosticReport identityChange = Discover(identity, new() { TargetUserSid = sid, SeedProcessIds = [401] });
        Check("第二批 读取后用户SID变化立即停止关联并保留访问受限状态",
            identityChange.Candidates.Count == 0 && identityChange.Hosts.Single().Status == DiagnosticReadStatus.AccessDenied &&
            identityChange.Checks.Any(c => c.Status == DiagnosticReadStatus.AccessDenied));
        Phase2SourceFixture wrongIdentity = new("S-1-5-21-100-200-300-1002");
        RelatedComponentDiagnosticReport deniedIdentity = Discover(wrongIdentity, new() { TargetUserSid = sid });
        Check("第二批 请求用户不匹配时不读取任何启动或进程来源",
            wrongIdentity.SourceYields == 0 && wrongIdentity.ProcessYields == 0 && deniedIdentity.Checks.Any(c => c.Status == DiagnosticReadStatus.AccessDenied));

        Phase2SourceFixture denied = new(sid);
        denied.Sources.Add(new() { Kind = "Run", Scope = "CurrentUser", Location = "denied-source", Status = DiagnosticReadStatus.AccessDenied, Detail = "访问拒绝。" });
        denied.Processes.Add(new(501, null, "", DiagnosticReadStatus.AccessDenied, "进程拒绝访问。"));
        RelatedComponentDiagnosticReport permission = Discover(denied, new() { TargetUserSid = sid, SeedProcessIds = [501] });
        Check("第二批 启动来源与显式PID访问拒绝分别保留",
            permission.Sources.Single().Status == DiagnosticReadStatus.AccessDenied && permission.Hosts.Single().Status == DiagnosticReadStatus.AccessDenied &&
            denied.ModuleRequests.Count == 0);

        Phase2SourceFixture task = new(sid);
        task.Sources.Add(new()
        {
            Kind = "Task",
            Scope = "CurrentUser",
            UserSid = sid,
            Location = "Tasks/fixture#Exec1",
            RawCommand = "powershell.exe -File loader.ps1",
            ExecutablePath = "powershell.exe",
            Arguments = "-File loader.ps1",
            WorkingDirectory = app
        });
        task.Files[script] = new(DiagnosticReadStatus.NotChecked, "文件被占用，未强行解锁。", []);
        RelatedComponentDiagnosticReport occupied = Discover(task);
        Check("第二批 任务工作目录及脚本占用状态保留且不强行解锁",
            occupied.Sources.Single().WorkingDirectory == app && occupied.Candidates.Any(c => c.Path == script) &&
            occupied.Checks.Any(c => c.Detail.Contains("文件被占用", StringComparison.Ordinal)) && task.FileRequests.Count == 1);

        Phase2SourceFixture shortcut = new(sid);
        string linkPath = app + @"\startup.lnk";
        shortcut.Sources.Add(new() { Kind = "StartupFile", Scope = "CurrentUser", UserSid = sid, Location = linkPath, ShortcutPath = linkPath });
        shortcut.Files[linkPath] = new(DiagnosticReadStatus.Complete, "fixture", Phase2ShortcutBytes(@".\SignedHost.exe", app, "-quiet"));
        RelatedComponentDiagnosticReport link = Discover(shortcut);
        Check("第二批 LNK仅用字节解析相对目标和工作目录并保留来源",
            link.Sources.Single().Location == linkPath && link.Sources.Single().WorkingDirectory == app && link.Candidates.Any(c => c.Path == hostPath));

        Phase2SourceFixture scripts = new(sid);
        scripts.Sources.Add(new() { Kind = "Run", Scope = "CurrentUser", UserSid = sid, Location = "Run/script", RawCommand = "powershell.exe -File \"" + script + "\"" });
        scripts.Files[script] = new(DiagnosticReadStatus.Complete, "fixture", Encoding.UTF8.GetBytes("& \"$PSScriptRoot\\unknown.dll\""));
        RelatedComponentDiagnosticReport body = Discover(scripts);
        Check("第二批 启动脚本中的字面DLL进入后续内容候选而非恶意结论",
            body.Candidates.Any(c => c.Path == module && c.HostObservationIds.Count == 0) &&
            body.Checks.Any(c => c.Name == "脚本字面引用" && c.Status == DiagnosticReadStatus.NotChecked));
        RelatedComponentDiagnosticReport byteLimit = Discover(scripts, limits: new() { MaximumScriptBytes = 4, MaximumTotalScriptBytes = 4 });
        Check("第二批 脚本字节不足时只保留脚本路径且不继续正文解析",
            byteLimit.Candidates.All(c => c.Path != module) && byteLimit.Checks.Any(c => c.Status == DiagnosticReadStatus.LimitReached));

        Phase2SourceFixture caps = new(sid);
        caps.Sources.AddRange(Enumerable.Range(0, 3).Select(i => new RelatedSourceRead { Kind = "Run", Scope = "CurrentUser", Location = "Run/" + i, RawCommand = "\"" + app + "\\" + i + ".exe\"" }));
        RelatedComponentDiagnosticReport cappedSources = Discover(caps, limits: new() { MaximumSources = 1 });
        Check("第二批 来源枚举在限额处停止并保留未完成说明", caps.SourceYields == 1 && cappedSources.Sources.Count == 1 && cappedSources.Checks.Any(c => c.Status == DiagnosticReadStatus.LimitReached));
        RelatedComponentDiagnosticReport cappedCandidates = Discover(new(sid), new() { TargetUserSid = sid, SeedPaths = [module, script, hostPath] }, new() { MaximumCandidates = 2 });
        Check("第二批 精确候选达到上限后不扩成目录扫描", cappedCandidates.Candidates.Count == 2 && cappedCandidates.Checks.Any(c => c.Name == "关联候选数量"));

        Phase2SourceFixture hostCap = new(sid);
        hostCap.Processes.AddRange([new(601, start, hostPath, DiagnosticReadStatus.Complete, "fixture", "cmd", app),
            new(602, start, app + @"\otherhost.exe", DiagnosticReadStatus.Complete, "fixture", "cmd", app)]);
        hostCap.Modules[601] = new(DiagnosticReadStatus.Complete, "fixture", true, [module]);
        hostCap.Modules[602] = new(DiagnosticReadStatus.Complete, "fixture", true, [module, app + @"\second.dll"]);
        RelatedComponentDiagnosticReport cappedHosts = Discover(hostCap, new() { TargetUserSid = sid, SeedPaths = [module], SeedProcessIds = [602] },
            new() { MaximumHosts = 1, MaximumModulesPerHost = 1 });
        Check("第二批 明确PID优先于同目录线索且模块按单宿主限额读取",
            hostCap.ModuleRequests.SequenceEqual(new[] { 602 }) && cappedHosts.Hosts.Single().Status == DiagnosticReadStatus.LimitReached &&
            cappedHosts.Candidates.All(c => c.Path != app + @"\second.dll"));

        Phase2SourceFixture priorities = new(sid);
        for (int i = 0; i < 40; i++)
        {
            string unrelatedRun = @"C:\Users\Fixture\Other" + i + @"\agent.exe";
            priorities.Sources.Add(new() { Kind = "Run", Scope = "CurrentUser", UserSid = sid, Location = "Run/noise/" + i, RawCommand = "\"" + unrelatedRun + "\"" });
            priorities.Processes.Add(new(700 + i, start, unrelatedRun, DiagnosticReadStatus.Complete, "fixture", "cmd", Path.GetDirectoryName(unrelatedRun)));
        }
        priorities.Processes.Add(new(799, start, hostPath, DiagnosticReadStatus.Complete, "fixture", "cmd", app, "Valid"));
        priorities.Modules[799] = new(DiagnosticReadStatus.Complete, "fixture", true,
            [.. Enumerable.Range(0, 20).Select(i => @"C:\Windows\System32\system" + i + ".dll"), module, app + @"\new-unknown.dll"]);
        RelatedComponentDiagnosticReport priorityResult = Discover(priorities, new() { TargetUserSid = sid, SeedPaths = [module] },
            new() { MaximumHosts = 1, MaximumCandidates = 2, MaximumModulesPerHost = 2 });
        Check("第二批 真实DLL种子宿主不被大量Run宿主或系统DLL挤占",
            priorities.ModuleRequests.SequenceEqual(new[] { 799 }) && priorityResult.Candidates.Any(c => c.Path == module && c.HostObservationIds.Count == 1) &&
            priorityResult.Candidates.Any(c => c.Path == app + @"\new-unknown.dll" && c.HostObservationIds.Count == 1) && priorityResult.Candidates.Count == 2);
        HashSet<string> priorityIds = priorityResult.Sources.Select(s => s.Id).Concat(priorityResult.Hosts.Select(h => h.Id)).Concat(priorityResult.Candidates.Select(c => c.Id)).ToHashSet(StringComparer.Ordinal);
        Check("第二批 候选优先替换保留来源快照且不留下悬空关系",
            priorityResult.Sources.Count == 40 && priorityResult.Relations.All(r => priorityIds.Contains(r.FromId) && priorityIds.Contains(r.ToId)) &&
            priorityResult.Checks.Any(c => c.Name == "关联候选优先级" && c.Status == DiagnosticReadStatus.LimitReached));

        using CancellationTokenSource cancellation = new(); cancellation.Cancel();
        Phase2SourceFixture cancelledFixture = new(sid);
        RelatedComponentDiagnosticReport cancelled = Discover(cancelledFixture, token: cancellation.Token);
        Check("第二批 预取消不读取来源并返回可报告的取消状态", cancelledFixture.SourceYields == 0 && cancelled.Checks.Any(c => c.Status == DiagnosticReadStatus.Cancelled));
        Phase2DiscoveryClock clock = new();
        Phase2SourceFixture timed = new(sid);
        timed.Sources.Add(new() { Kind = "Run", Scope = "CurrentUser", Location = "clock", RawCommand = "\"" + hostPath + "\"" });
        timed.AfterSource = () => clock.Advance(TimeSpan.FromSeconds(2));
        RelatedComponentDiagnosticReport expired = new() { TargetUserSid = sid };
        new RelatedComponentDiscovery(timed, clock).Collect(new() { TargetUserSid = sid }, expired, new() { MaximumDiscoveryDuration = TimeSpan.FromSeconds(1) });
        Check("第二批 来源调用返回后检查时间预算不追加超时结果", expired.Sources.Count == 0 && expired.Checks.Any(c => c.Status == DiagnosticReadStatus.LimitReached));

        RelatedComponentDiagnosticReport Discover(Phase2SourceFixture data, RelatedComponentDiscoveryRequest? request = null,
            RelatedComponentLimits? limits = null, CancellationToken token = default)
        {
            request ??= new() { TargetUserSid = sid };
            RelatedComponentDiagnosticReport output = new() { TargetUserSid = request.TargetUserSid };
            new RelatedComponentDiscovery(data).Collect(request, output, limits ?? new(), token);
            return output;
        }
    }

    private static byte[] Phase2ShortcutBytes(string relative, string working, string arguments)
    {
        using MemoryStream stream = new();
        byte[] header = new byte[76];
        BinaryPrimitives.WriteUInt32LittleEndian(header, 76);
        new Guid("00021401-0000-0000-c000-000000000046").ToByteArray().CopyTo(header, 4);
        BinaryPrimitives.WriteUInt32LittleEndian(header.AsSpan(20), 128 | 8 | 16 | 32);
        stream.Write(header);
        foreach (string value in new[] { relative, working, arguments })
        {
            byte[] prefix = new byte[2];
            BinaryPrimitives.WriteUInt16LittleEndian(prefix, (ushort)value.Length);
            stream.Write(prefix);
            stream.Write(Encoding.Unicode.GetBytes(value));
        }
        stream.Write(new byte[4]);
        return stream.ToArray();
    }

    private sealed class Phase2SourceFixture(string sid) : IRelatedComponentDataSource
    {
        public string Sid { get; set; } = sid;
        public List<RelatedSourceRead> Sources { get; } = [];
        public List<RelatedProcessRead> Processes { get; } = [];
        public Dictionary<int, RelatedModuleRead> Modules { get; } = [];
        public Dictionary<string, RelatedFileRead> Files { get; } = new(StringComparer.OrdinalIgnoreCase);
        public List<int> ModuleRequests { get; } = [];
        public List<(string Path, int Maximum)> FileRequests { get; } = [];
        public int SourceYields { get; private set; }
        public int ProcessYields { get; private set; }
        public Action? AfterSource { get; set; }
        public Action? AfterModules { get; set; }
        public string? ReadCurrentUserSid() => Sid;
        public IReadOnlyDictionary<string, string> ReadEnvironmentVariables(string targetUserSid) => new Dictionary<string, string>();
        public IEnumerable<RelatedSourceRead> ReadSources(RelatedComponentDiscoveryRequest request, RelatedComponentLimits limits,
            Func<long> remainingSnapshotBytes, CancellationToken token)
        {
            foreach (RelatedSourceRead item in Sources) { token.ThrowIfCancellationRequested(); SourceYields++; AfterSource?.Invoke(); yield return item; }
        }
        public IEnumerable<RelatedProcessRead> ReadProcesses(int maximumProcesses, CancellationToken token)
        {
            foreach (RelatedProcessRead item in Processes) { token.ThrowIfCancellationRequested(); ProcessYields++; yield return item; }
        }
        public RelatedModuleRead ReadModules(RelatedProcessRead process, int maximumModules, CancellationToken token)
        { token.ThrowIfCancellationRequested(); ModuleRequests.Add(process.ProcessId); AfterModules?.Invoke(); return Modules.GetValueOrDefault(process.ProcessId, new(DiagnosticReadStatus.Complete, "fixture", true, [])); }
        public RelatedPathRead ProbePath(string path) => new(DiagnosticReadStatus.Complete, "fixture", true, false,
            path.StartsWith(@"C:\Users\Fixture\", StringComparison.OrdinalIgnoreCase), path.StartsWith(@"C:\Windows\", StringComparison.OrdinalIgnoreCase));
        public RelatedFileRead ReadFile(string path, int maximumBytes, CancellationToken token)
        {
            token.ThrowIfCancellationRequested(); FileRequests.Add((path, maximumBytes));
            RelatedFileRead file = Files.GetValueOrDefault(path, new(DiagnosticReadStatus.NotPresent, "fixture missing", []));
            return file.Bytes.Length <= maximumBytes ? file : new(DiagnosticReadStatus.LimitReached, "fixture byte limit", []);
        }
    }
    private sealed class Phase2DiscoveryClock : TimeProvider
    {
        private long _ticks;
        public override long TimestampFrequency => TimeSpan.TicksPerSecond;
        public override long GetTimestamp() => _ticks;
        public void Advance(TimeSpan duration) => _ticks += duration.Ticks;
    }
}
