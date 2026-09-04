using System.ComponentModel;
using System.IO;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text.Json;
using System.Windows.Controls;
using Microsoft.Win32.SafeHandles;
using SteamSentinel.App;
using SteamSentinel.App.Native;
using SteamSentinel.App.Services;
using SteamSentinel.Core.Models;
using SteamSentinel.Core.Reporting;
using SteamSentinel.Core.Utilities;
using Validation = SteamSentinel.Core.Utilities.Validation;

namespace SteamSentinel.SelfTest;

internal static partial class Program
{
    private static async Task TestV018Async(string root)
    {
        using WindowsIdentity identity = WindowsIdentity.GetCurrent();
        SecurityIdentifier user = identity.User!;
        RawAcl acl = new(RestrictedTokenSecurity.BuildDefaultDacl(user), 0);
        Check("受限对象 ACL 仅授权当前用户和 SYSTEM", acl.Count == 2 && acl.Cast<CommonAce>().All(a =>
            a.AceQualifier == AceQualifier.AccessAllowed && a.AccessMask == 0x10000000 &&
            (a.SecurityIdentifier.Equals(user) || a.SecurityIdentifier.IsWellKnown(WellKnownSidType.LocalSystemSid))));
        RawAcl systemAcl = new(RestrictedTokenSecurity.BuildDefaultDacl(new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null)), 0);
        Check("SYSTEM 身份的默认权限不重复添加同一 SID", systemAcl.Count == 1);
        using (SafeAccessTokenHandle token = RestrictedProcess.CreateLowIntegrityToken())
        {
            Check("新扫描令牌保留 Low 且对象所有者为当前用户", TokenProbe.Sid(token, 25) == "S-1-16-4096" && TokenProbe.Sid(token, 4) == user.Value);
            using WindowsIdentity restricted = new(token.DangerousGetHandle());
            Check("扫描令牌不具有有效管理员组权限", !new WindowsPrincipal(restricted).IsInRole(WindowsBuiltInRole.Administrator));
        }

        string directory = Path.Combine(root, "v018"); Directory.CreateDirectory(directory);
        string workerPath = DevelopmentWorkerPath();
        // Recreate the observed administrator-only default on a token COPY, not the caller.
        using SafeAccessTokenHandle caller = TokenProbe.OpenCurrent();
        byte[] originalDacl = TokenProbe.Dacl(caller);
        using (SafeAccessTokenHandle adminLike = TokenProbe.Copy(caller))
        {
            RawAcl adminOnly = new RawSecurityDescriptor("D:(A;;GA;;;BA)(A;;GA;;;SY)").DiscretionaryAcl!;
            byte[] synthetic = new byte[adminOnly.BinaryLength]; adminOnly.GetBinaryForm(synthetic, 0);
            TokenProbe.SetDacl(adminLike, synthetic);
            using SafeAccessTokenHandle repaired = RestrictedProcess.CreateLowIntegrityToken(adminLike);
            Check("管理员默认 DACL 经生产令牌工厂修正且不修改来源", TokenProbe.Dacl(repaired).SequenceEqual(RestrictedTokenSecurity.BuildDefaultDacl(user)) &&
                TokenProbe.Dacl(adminLike).SequenceEqual(synthetic) && TokenProbe.Sid(repaired, 25) == "S-1-16-4096");
        }
        string working = Path.Combine(AppPaths.WorkerTemporaryRoot, "selftest-v018-" + Guid.NewGuid().ToString("N"));
        using (JobObject job = new())
        using (RestrictedProcess worker = RestrictedProcess.Start(workerPath, working, job))
        {
            using CancellationTokenSource timeout = new(TimeSpan.FromSeconds(10));
            string? ready = await worker.StandardOutput.ReadLineAsync(timeout.Token);
            worker.StandardInput.Close();
            await worker.WaitForExitAsync(timeout.Token);
            Check("生产启动器完成 Low 握手并按 EOF 退出", ready?.Contains("\"Low\"", StringComparison.Ordinal) == true && worker.ExitCode == 2);
            Check("退出后可重复读取原生退出码", worker.HasExited && worker.ExitCode == 2 && worker.ExitCode == 2);
        }
        if (Directory.Exists(working) && !Validation.ContainsReparsePoint(working)) Directory.Delete(working, true);
        Check("修复不修改调用方默认 DACL", TokenProbe.Dacl(caller).SequenceEqual(originalDacl));

        string fixtureDir = Path.Combine(directory, "fixtures"); Directory.CreateDirectory(fixtureDir);
        foreach (string file in Directory.EnumerateFiles(AppContext.BaseDirectory))
            File.Copy(file, Path.Combine(fixtureDir, Path.GetFileName(file)), true);
        string Fixture(string mode)
        {
            string path = Path.Combine(fixtureDir, "SteamSentinelFixture-" + mode + ".exe");
            File.Copy(Path.Combine(AppContext.BaseDirectory, "SteamSentinel.SelfTest.exe"), path, true);
            File.Copy(Path.Combine(AppContext.BaseDirectory, "SteamSentinel.SelfTest.dll"), Path.ChangeExtension(path, ".dll"), true);
            return path;
        }
        ScanOptions options = new() { Mode = ScanMode.Custom, IncludeSystem = false, IncludeSteam = false, IncludeWorkshop = false, UseAmsi = false };
        static Task<ArchivePasswordResponse> NoPassword(ArchivePasswordRequest request, CancellationToken _) => Task.FromResult(new ArchivePasswordResponse(request.RequestId, true, null, false));
        HashSet<string> beforeFolders = Directory.Exists(AppPaths.WorkerTemporaryRoot)
            ? Directory.GetDirectories(AppPaths.WorkerTemporaryRoot).ToHashSet(StringComparer.OrdinalIgnoreCase) : [];
        foreach (string mode in new[] { "exit0142", "exit259", "flood", "invalidhello", "reportfail", "checkpointoom", "checkpointexit" })
        {
            WorkerFailureException? failure = null;
            using CancellationTokenSource timeout = new(TimeSpan.FromSeconds(15));
            try { await new ArchiveWorkerClient(Fixture(mode)).RunAsync(options, NoPassword, null, timeout.Token); }
            catch (WorkerFailureException ex) { failure = ex; }
            Check($"工作进程故障诊断：{mode}", failure is not null && mode switch
            {
                "exit0142" or "flood" => failure.Stage == WorkerStage.Handshake && failure.NativeExitCode == unchecked((int)0xC0000142) && failure.Message.Contains("0xC0000142", StringComparison.Ordinal),
                "exit259" => failure.NativeExitCode == 259,
                "invalidhello" => failure.BeforeScan && failure.Message.Contains("Low Integrity", StringComparison.Ordinal),
                "checkpointoom" or "checkpointexit" => failure.Stage == WorkerStage.Scanning && failure.PartialReport?.Metrics.FilesVisited == 4 &&
                    failure.PartialReport.Findings.Count == 1 && failure.PartialReport.WorkerDiagnostics?.LastPath == "inert.zip!/next.rar",
                _ => failure.Stage == WorkerStage.Exit && failure.NativeExitCode == 23
            });
        }
        using (CancellationTokenSource cancel = new(TimeSpan.FromSeconds(2)))
        {
            WorkerCancelledException? failure = null;
            try { await new ArchiveWorkerClient(Fixture("checkpointcancel")).RunAsync(options, NoPassword, null, cancel.Token); }
            catch (WorkerCancelledException ex) { failure = ex; }
            Check("取消后保留已交回内容批次", failure?.PartialReport?.Metrics.FilesVisited == 4 && failure.PartialReport.Findings.Count == 1);
        }
        using (CancellationTokenSource cancel = new(TimeSpan.FromMilliseconds(250)))
        {
            bool cancelled = false;
            try { await new ArchiveWorkerClient(Fixture("hang")).RunAsync(options, NoPassword, null, cancel.Token); }
            catch (OperationCanceledException) { cancelled = true; }
            Check("握手前取消仍返回取消且不等待完整超时", cancelled);
        }
        WorkerFailureException? timedOut = null;
        using (CancellationTokenSource timeout = new(TimeSpan.FromSeconds(15)))
        {
            try { await new ArchiveWorkerClient(Fixture("hang")).RunAsync(options, NoPassword, null, timeout.Token); }
            catch (WorkerFailureException ex) { timedOut = ex; }
        }
        Check("握手超时报告对应阶段且不将清理退出码当成故障码", timedOut?.Stage == WorkerStage.Handshake &&
            timedOut.NativeExitCode is null && timedOut.Message.Contains("按时完成安全握手", StringComparison.Ordinal));
        WorkerFailureException? missing = null;
        try { await new ArchiveWorkerClient(Path.Combine(directory, "missing.exe")).RunAsync(options, NoPassword, null, CancellationToken.None); }
        catch (WorkerFailureException ex) { missing = ex; }
        Check("缺失组件明确报告预检失败", missing?.Stage == WorkerStage.Preflight);
        Check("失败和取消后释放工作目录", Directory.GetDirectories(AppPaths.WorkerTemporaryRoot).All(beforeFolders.Contains));
        ArchiveWorkerClient.BoundedWorkerError capture = new();
        using StringReader noisy = new(new string('x', 100000));
        await capture.DrainAsync(noisy, CancellationToken.None);
        Check("标准错误有界保留但完整排空", capture.Text.Length == 4096 && noisy.Read() == -1);

        ScanReport system = new() { Mode = ScanMode.Quick, RuleSetVersion = "fixture", Metrics = new ScanMetrics { ProcessesVisited = 7 } };
        Finding threat = new() { Category = FindingCategory.Steam, CanRemediate = true, IsKnownMalware = true, Severity = FindingSeverity.Critical };
        system.Findings.Add(threat);
        WorkerFailureException launchError = new(WorkerStage.Handshake, unchecked((int)0xC0000142), "inert fixture");
        ScanReport preserved = ScanFailureReports.PreserveSystemResults(system, ScanMode.Quick, [], "fixture", launchError, false);
        Check("Worker 失败保留既有系统发现与计数", preserved.Findings.Contains(threat) && preserved.Metrics.ProcessesVisited == 7);
        Check("Worker 失败结果明确 Partial 且缺口不可处置", preserved.Coverage == ScanCoverage.Partial && preserved.Findings.Any(f => f.RuleId == "CONTENT-SCAN-FAILED" && !f.CanRemediate));
        string exported = Path.Combine(directory, "failure.md"); await ReportExporter.ExportMarkdownAsync(preserved, exported);
        Check("导出报告保留启动阶段与原生退出码", (await File.ReadAllTextAsync(exported)).Contains("0xC0000142", StringComparison.Ordinal));
        ScanReport custom = ScanFailureReports.PreserveSystemResults(null, ScanMode.Custom, ["inert.zip", "inert.zip"], "fixture", launchError, false);
        Check("自定义启动失败不冒充已扫描所选文件", custom.Coverage == ScanCoverage.Partial && custom.RootSummaries.Count == 1 && custom.Metrics.FilesVisited == 0);
        ScanReport cancelledReport = ScanFailureReports.PreserveSystemResults(null, ScanMode.Custom, [], "fixture", new OperationCanceledException(), true);
        Check("取消与失败使用不同覆盖说明", cancelledReport.Findings.Single().RuleId == "CONTENT-SCAN-CANCELLED");
    }

    private static async Task<int> RunWorkerFixtureAsync(string mode)
    {
        if (mode == "exit0142") return unchecked((int)0xC0000142);
        if (mode == "exit259") return 259;
        if (mode == "flood") { await Console.Error.WriteAsync(new string('x', 100000)); return unchecked((int)0xC0000142); }
        if (mode == "hang") { await Task.Delay(TimeSpan.FromSeconds(30)); return 0; }
        await Console.Out.WriteLineAsync(JsonSerializer.Serialize(new WorkerMessage
        {
            Type = WorkerMessageTypes.Ready,
            Containment = mode == "invalidhello" ? "High" : "Low"
        }));
        await Console.Out.FlushAsync();
        if (await Console.In.ReadLineAsync() is null) return 2;
        if (mode.StartsWith("checkpoint", StringComparison.Ordinal))
        {
            ScanReport partial = new() { Metrics = new() { FilesVisited = 4 },
                WorkerDiagnostics = new("压缩包目录", "inert.zip!/next.rar", "读取目录", 123, 456, 100, DateTimeOffset.UtcNow) };
            partial.Findings.Add(new() { RuleId = "BENIGN-CHECKPOINT", Target = "inert.txt", TargetSha256 = new string('A', 64) });
            new ReportBatchWriter(batch => Console.Out.WriteLine(JsonSerializer.Serialize(new WorkerMessage
                { Type = WorkerMessageTypes.Checkpoint, Batch = batch }))).Send(partial);
            await Console.Out.FlushAsync();
            if (mode == "checkpointcancel") await Task.Delay(TimeSpan.FromSeconds(30));
            if (mode == "checkpointoom") await Console.Out.WriteLineAsync(JsonSerializer.Serialize(new WorkerMessage
                { Type = WorkerMessageTypes.Failed, Error = "OutOfMemoryException: inert simulated failure",
                    Diagnostics = partial.WorkerDiagnostics with { FailureType = "OutOfMemoryException" } }));
            return 23;
        }
        if (mode == "reportfail")
            await Console.Out.WriteLineAsync(JsonSerializer.Serialize(new WorkerMessage { Type = WorkerMessageTypes.Completed, Report = new ScanReport() }));
        return 23;
    }

    private static void TestV018Window()
    {
        MainWindow window = new();
        var preserve = typeof(MainWindow).GetMethod("PreserveScanFailure", BindingFlags.Instance | BindingFlags.NonPublic)!;
        preserve.Invoke(window, [new ScanReport { Mode = ScanMode.Quick }, ScanMode.Quick, Array.Empty<string>(),
            new WorkerFailureException(WorkerStage.Handshake, unchecked((int)0xC0000142), "inert fixture"), false]);
        UiPreview.ApplyAccessState(window, InstallationSecurityStatus.Protected, new(true, true));
        Check("失败界面保留报告导出且不显示安全结论", ((Button)window.FindName("ExportButton")).IsEnabled &&
            ((TextBlock)window.FindName("HeaderStatusText")).Text == "扫描不完整" && !((Button)window.FindName("RemediateButton")).IsEnabled);
        window.Close();
    }

    private static class TokenProbe
    {
        public static SafeAccessTokenHandle OpenCurrent()
        {
            if (!OpenProcessToken(GetCurrentProcess(), 0x8a, out SafeAccessTokenHandle token)) throw new Win32Exception(Marshal.GetLastWin32Error());
            return token;
        }
        public static SafeAccessTokenHandle Copy(SafeAccessTokenHandle source)
        {
            if (!DuplicateTokenEx(source, 0x8b, IntPtr.Zero, 2, 1, out SafeAccessTokenHandle copy)) throw new Win32Exception(Marshal.GetLastWin32Error());
            return copy;
        }
        public static string Sid(SafeAccessTokenHandle token, int type)
        {
            IntPtr data = Query(token, type);
            try { return new SecurityIdentifier(Marshal.ReadIntPtr(data)).Value; } finally { Marshal.FreeHGlobal(data); }
        }
        public static byte[] Dacl(SafeAccessTokenHandle token)
        {
            IntPtr data = Query(token, 6);
            try
            {
                IntPtr pointer = Marshal.ReadIntPtr(data);
                if (pointer == IntPtr.Zero) throw new InvalidDataException("Fixture requires a non-null original DACL");
                byte[] acl = new byte[(ushort)Marshal.ReadInt16(pointer, 2)]; Marshal.Copy(pointer, acl, 0, acl.Length); return acl;
            }
            finally { Marshal.FreeHGlobal(data); }
        }
        public static void SetDacl(SafeAccessTokenHandle token, byte[] acl)
        {
            IntPtr data = Marshal.AllocHGlobal(IntPtr.Size + acl.Length);
            try
            {
                Marshal.WriteIntPtr(data, data + IntPtr.Size); Marshal.Copy(acl, 0, data + IntPtr.Size, acl.Length);
                if (!SetTokenInformation(token, 6, data, IntPtr.Size)) throw new Win32Exception(Marshal.GetLastWin32Error());
            }
            finally { Marshal.FreeHGlobal(data); }
        }
        private static IntPtr Query(SafeAccessTokenHandle token, int type)
        {
            GetTokenInformation(token, type, IntPtr.Zero, 0, out int size);
            IntPtr data = Marshal.AllocHGlobal(size);
            if (GetTokenInformation(token, type, data, size, out _)) return data;
            int error = Marshal.GetLastWin32Error(); Marshal.FreeHGlobal(data); throw new Win32Exception(error);
        }
        [DllImport("kernel32.dll")] private static extern IntPtr GetCurrentProcess();
        [DllImport("advapi32.dll", SetLastError = true)] private static extern bool OpenProcessToken(IntPtr process, uint access, out SafeAccessTokenHandle token);
        [DllImport("advapi32.dll", SetLastError = true)] private static extern bool DuplicateTokenEx(SafeAccessTokenHandle token, uint access, IntPtr attributes, int level, int type, out SafeAccessTokenHandle copy);
        [DllImport("advapi32.dll", SetLastError = true)] private static extern bool GetTokenInformation(SafeAccessTokenHandle token, int type, IntPtr buffer, int length, out int returned);
        [DllImport("advapi32.dll", SetLastError = true)] private static extern bool SetTokenInformation(SafeAccessTokenHandle token, int type, IntPtr buffer, int length);
    }
}
