using System.Diagnostics;
using System.IO;
using System.Security.Principal;
using SteamSentinel.App.Services;
using SteamSentinel.Core.Utilities;

namespace SteamSentinel.SelfTest;

internal static partial class Program
{
    private static async Task TestStartupCompatibilityAsync(string root, bool includeElevatedBrokerProbe = false)
    {
        const string nonce = "0123456789abcdefABCDEF0123456789";
        string directory = Path.Combine(root, "startup-compatibility");
        Directory.CreateDirectory(directory);
        foreach (StartupRole role in Enum.GetValues<StartupRole>())
        {
            foreach (StartupMode mode in Enum.GetValues<StartupMode>())
            {
                string host = Path.Combine(directory, StartupCompatibility.HostFileName(role, mode));
                Check($"启动模式 {role}/{mode} 从实际文件名识别", StartupCompatibility.TryIdentifyHost(host, role, out StartupMode actual, out bool unified) &&
                    actual == mode && unified && StartupCompatibility.IsUnifiedHost(host));
                using StringWriter output = new();
                Check($"启动预检 {role}/{mode} 精确就绪协议", StartupCompatibility.TryRunProbe(
                    ["--startup-probe", nonce], role, host, output, out int exit) && exit == 0 &&
                    output.ToString() == $"STEAMSENTINEL_STARTUP_READY/1|{StartupCompatibility.RoleName(role)}|{StartupCompatibility.ModeName(mode)}|{nonce}{Environment.NewLine}");
                Check($"启动预检 {role}/{mode} 角色不可混用", !StartupCompatibility.TryIdentifyHost(host,
                    role == StartupRole.App ? StartupRole.Broker : StartupRole.App, out _, out _));
            }
            string legacy = Path.Combine(directory, StartupCompatibility.AssemblyBaseName(role) + ".exe");
            Check($"启动模式 {role} 开发入口保持标准", StartupCompatibility.TryIdentifyHost(legacy, role, out StartupMode legacyMode, out bool legacyUnified) &&
                legacyMode == StartupMode.Standard && !legacyUnified && !StartupCompatibility.IsUnifiedHost(legacy));
        }
        foreach (string unknown in new[] { "SteamSentinel.Compat.exe.backup", "SteamSentinel.FakeCompat.exe", "dotnet.exe", "SteamSentinel.Broker.Compat.exe", "" })
            Check("启动模式 不按子串或其他角色选择兼容 " + unknown, !StartupCompatibility.TryIdentifyHost(unknown, StartupRole.App, out _, out _));

        string standard = Path.Combine(directory, "SteamSentinel.Standard.exe");
        foreach (string[] invalid in new[]
        {
            new[] { "--startup-probe" }, new[] { "--startup-probe", "" }, new[] { "--startup-probe", new string('a', 31) },
            new[] { "--startup-probe", new string('a', 33) }, new[] { "--startup-probe", new string('z', 32) },
            new[] { "--startup-probe", nonce, "plan.json" }, new[] { "plan.json", "--startup-probe", nonce },
            new[] { "--STARTUP-PROBE", nonce }, new[] { "--startup-probe=" + nonce },
            new[] { "--startup-probe", nonce[..31] + "|" }
        })
        {
            using StringWriter output = new();
            Check("启动预检 非法协议禁止进入业务 " + string.Join(' ', invalid), StartupCompatibility.TryRunProbe(invalid,
                StartupRole.App, standard, output, out int exit) && exit != 0 && output.ToString().Length == 0);
        }
        using (StringWriter output = new())
        {
            Check("启动预检 未知宿主不伪造就绪", StartupCompatibility.TryRunProbe(["--startup-probe", nonce], StartupRole.App,
                "other.exe", output, out int exit) && exit != 0 && output.ToString().Length == 0);
            Check("启动预检 普通启动参数不拦截", !StartupCompatibility.TryRunProbe(["--ui-language", "en"], StartupRole.App, standard, output, out _));
        }
        foreach (StartupMode mode in Enum.GetValues<StartupMode>())
        {
            string app = Path.Combine(directory, StartupCompatibility.HostFileName(StartupRole.App, mode));
            string worker = StartupCompatibility.WorkerPath(directory, app);
            Check("启动模式 Worker 跟随当前实际 UI 宿主 " + mode, worker == Path.Combine(directory, StartupCompatibility.HostFileName(StartupRole.Worker, mode)));
            Check("启动模式 Worker 两种宿主使用固定原始 DLL " + mode,
                StartupCompatibility.WorkerAssemblyPath(worker) == Path.Combine(directory, "SteamSentinel.ArchiveWorker.dll"));
            ProcessStartInfo broker = new();
            RemediationClient.AddStartupPreference(broker, app);
            broker.ArgumentList.Add("plan.json");
            Check("启动模式 Broker 首选模式位于计划前 " + mode,
                broker.ArgumentList.SequenceEqual(new[] { "--startup-mode", StartupCompatibility.ModeName(mode), "plan.json" }));
        }
        ProcessStartInfo legacyBroker = new();
        RemediationClient.AddStartupPreference(legacyBroker, Path.Combine(directory, "SteamSentinel.exe"));
        Check("启动模式 开发 Broker 参数不变", legacyBroker.ArgumentList.Count == 0);
        Check("启动模式 开发 Worker 原路径不变", StartupCompatibility.WorkerPath(directory, "dotnet.exe") == Path.Combine(directory, "SteamSentinel.ArchiveWorker.exe"));
        Check("启动模式 无害 Worker 测试宿主仍支持独立 DLL", StartupCompatibility.WorkerAssemblyPath(Path.Combine(directory, "fixture.exe")) == Path.Combine(directory, "fixture.dll"));

        string[] required = InstallationSecurity.RequiredComponents(unified: true).ToArray();
        Check("启动完整性 统一包要求两个原生入口及六个宿主", required.Count(name => name.EndsWith(".exe", StringComparison.OrdinalIgnoreCase)) == 8 &&
            required.Contains("SteamSentinel.exe") && required.Contains("SteamSentinel.Broker.exe") &&
            Enum.GetValues<StartupRole>().All(role => Enum.GetValues<StartupMode>().All(mode => required.Contains(StartupCompatibility.HostFileName(role, mode)))));
        Check("启动完整性 共享运行时与 DLL 仍为必需", required.Contains("SteamSentinel.Core.dll") && required.Contains("SteamSentinel.Broker.dll") &&
            required.Contains("SteamSentinel.ArchiveWorker.dll") && required.Contains("SteamSentinel.runtimeconfig.json"));
        Dictionary<string, string> empty = new(StringComparer.OrdinalIgnoreCase);
        Check("启动完整性 当前统一宿主不可通过删清单降级", InstallationSecurity.HasUnifiedPayload(directory, empty, standard));
        Check("启动完整性 旧布局仍兼容", !InstallationSecurity.HasUnifiedPayload(directory, empty, "SteamSentinel.exe") &&
            InstallationSecurity.RequiredComponents(unified: false).Contains("SteamSentinel.ArchiveWorker.exe"));
        foreach (StartupRole role in Enum.GetValues<StartupRole>())
        {
            string name = StartupCompatibility.HostFileName(role, StartupMode.Compat);
            Check("启动完整性 任一角色清单标记要求完整统一包 " + role,
                InstallationSecurity.HasUnifiedPayload(directory, new Dictionary<string, string> { [name] = "irrelevant" }, "SteamSentinel.exe"));
        }

        // Exercise actual entrypoints with inherited pipes, not only protocol helper calls. No plans,
        // scanning, settings or writes are requested; Broker is never elevated by the test.
        foreach (StartupRole role in Enum.GetValues<StartupRole>())
        {
            string host = Path.Combine(AppContext.BaseDirectory, StartupCompatibility.AssemblyBaseName(role) + ".exe");
            if (role == StartupRole.Worker && !File.Exists(StartupCompatibility.WorkerAssemblyPath(host)))
                host = DevelopmentWorkerPath();
            if (role == StartupRole.Broker)
            {
                // The normal suite has no elevation prerequisite. Published Broker probes belong
                // to the elevated startup gate; the focused diagnostic suite can report a skip.
                if (!includeElevatedBrokerProbe) continue;
                using WindowsIdentity identity = WindowsIdentity.GetCurrent();
                if (!new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator)) { _skipped++; continue; }
            }
            Check("启动预检 实际开发入口存在 " + role, File.Exists(host));
            if (!File.Exists(host)) continue;
            (int exit, string stdout, string stderr) = await RunStartupProbeChildAsync(host, ["--startup-probe", nonce], directory);
            Check("启动预检 实际入口无业务初始化 " + role, exit == 0 && string.IsNullOrWhiteSpace(stderr) &&
                stdout.TrimEnd('\r', '\n') == $"STEAMSENTINEL_STARTUP_READY/1|{StartupCompatibility.RoleName(role)}|standard|{nonce}");
            (int invalidExit, string invalidOut, _) = await RunStartupProbeChildAsync(host, ["--startup-probe", "invalid"], directory);
            Check("启动预检 实际入口非法请求立即失败 " + role, invalidExit == 2 && string.IsNullOrWhiteSpace(invalidOut));
        }
        Check("启动预检 不创建工作目录内容", Directory.GetFileSystemEntries(directory).Length == 0);
    }

    private static async Task<(int Exit, string Stdout, string Stderr)> RunStartupProbeChildAsync(string path, string[] args, string directory)
    {
        ProcessStartInfo start = new(path)
        {
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            WorkingDirectory = directory
        };
        foreach (string arg in args) start.ArgumentList.Add(arg);
        using Process child = Process.Start(start) ?? throw new InvalidOperationException("Startup probe did not start.");
        Task<string> stdout = child.StandardOutput.ReadToEndAsync();
        Task<string> stderr = child.StandardError.ReadToEndAsync();
        try { await child.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(15)); }
        catch { if (!child.HasExited) child.Kill(entireProcessTree: true); throw; }
        return (child.ExitCode, await stdout, await stderr);
    }

    private static async Task<int> RunStartupCompatibilityTestsAsync(string root)
    {
        Directory.CreateDirectory(root);
        try { await TestStartupCompatibilityAsync(root, includeElevatedBrokerProbe: true); }
        catch (Exception ex) { Failures.Add(ex.ToString()); Console.Error.WriteLine(ex); }
        await JsonFile.WriteAtomicAsync(Path.Combine(root, "startup-compatibility-results.json"),
            new { passed = _passed, failed = Failures.Count, skipped = _skipped, failures = Failures });
        return Failures.Count == 0 ? 0 : 1;
    }
}
