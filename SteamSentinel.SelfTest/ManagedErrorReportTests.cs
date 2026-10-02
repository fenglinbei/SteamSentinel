using System.IO;
using System.Text;
using SteamSentinel.App.Services;
using SteamSentinel.Core.Models;
using SteamSentinel.Core.Reporting;
using SteamSentinel.Core.Utilities;

namespace SteamSentinel.SelfTest;

internal static partial class Program
{
    private static async Task TestManagedErrorReportsAsync(string root)
    {
        string directory = Path.Combine(root, "managed-error-reports");
        Directory.CreateDirectory(directory);
        for (int i = 1; i <= 3; i++)
        {
            string path = Path.Combine(directory, $"startup-fixture-{i}.txt");
            await File.WriteAllTextAsync(path, "NATIVE_CONTENT_MUST_NOT_BE_COLLECTED");
            File.SetLastWriteTimeUtc(path, DateTime.UtcNow.AddMinutes(-10 + i));
        }
        Exception inner;
        try { throw new IOException("fixture-inner-reason token=private-token"); }
        catch (Exception error) { inner = error; }
        Exception outer = new InvalidOperationException("fixture-outer-reason\nAuthorization: Bearer private-header-token", inner);
        outer.Data["secret"] = "EXCEPTION_DATA_MUST_NOT_BE_COLLECTED";
        string? reportPath = AppErrorLog.Write("fixture-stage", outer, directory);
        Check("错误报告 成功返回已保存文件路径", reportPath is not null && File.Exists(reportPath));
        string report = reportPath is null ? string.Empty : await File.ReadAllTextAsync(reportPath);
        Check("错误报告 包含构建运行时系统与实际宿主信息", report.Contains("BuildIdentity: " + ProductInfo.BuildIdentity) &&
            report.Contains("Version: " + ProductInfo.Version) && report.Contains("Runtime:") && report.Contains("OS:") &&
            report.Contains("Architecture:") && report.Contains("Process:") && report.Contains("Startup:") && report.Contains("UTC:"));
        Check("错误报告 保留外层内层原因及堆栈", report.Contains("fixture-outer-reason") && report.Contains("fixture-inner-reason") &&
            report.Contains("System.InvalidOperationException") && report.Contains("System.IO.IOException") && report.Contains(nameof(TestManagedErrorReportsAsync)));
        Check("错误报告 过滤已知凭据且不读取异常Data", !report.Contains("private-token") && !report.Contains("private-header-token") &&
            !report.Contains("EXCEPTION_DATA_MUST_NOT_BE_COLLECTED") && report.Contains("[REDACTED]"));
        Check("错误报告 只索引最近两份原生报告不复制内容", report.Contains("startup-fixture-3.txt") && report.Contains("startup-fixture-2.txt") &&
            !report.Contains("startup-fixture-1.txt") && !report.Contains("NATIVE_CONTENT_MUST_NOT_BE_COLLECTED"));
        Check("错误报告 明确本地收集不自动上传", report.Contains("local only") && report.Contains("no automatic upload"));
        for (int i = 0; i < 130; i++)
        {
            string path = Path.Combine(directory, $"startup-late-{i:D3}.txt");
            await File.WriteAllTextAsync(path, "LATE_NATIVE_CONTENT_MUST_NOT_BE_COLLECTED");
            File.SetLastWriteTimeUtc(path, DateTime.UtcNow.AddMinutes(i + 1));
        }
        string manyStartupReports = AppErrorLog.FormatReport("many-startup-reports", outer, directory);
        Check("错误报告 超过128份仍索引真正最新两份", manyStartupReports.Contains("startup-late-129.txt") &&
            manyStartupReports.Contains("startup-late-128.txt") && !manyStartupReports.Contains("startup-late-127.txt") &&
            !manyStartupReports.Contains("startup-fixture-3.txt") && !manyStartupReports.Contains("LATE_NATIVE_CONTENT_MUST_NOT_BE_COLLECTED"));

        AggregateException large = new(Enumerable.Range(0, 100).Select(index => new InvalidDataException($"reason-{index}:" + new string('测', 8000))));
        string largeReport = AppErrorLog.FormatReport("large", large, directory);
        Check("错误报告 UTF8中文总量严格有界且注明截断", Encoding.UTF8.GetByteCount(largeReport) <= AppErrorLog.MaximumReportBytes &&
            largeReport.Contains("report truncated") && largeReport.Contains("reason-0"));
        string? largePath = AppErrorLog.Write("large", large, directory);
        Check("错误报告 实际文件遵守128KiB限额", largePath is not null && new FileInfo(largePath).Length <= AppErrorLog.MaximumReportBytes);
        string markerPath = Path.Combine(directory, "file-is-not-a-directory");
        await File.WriteAllTextAsync(markerPath, "keep this fixture unchanged");
        Check("错误报告 无法写入时返回失败不覆盖原文件", AppErrorLog.Write("unwritable", outer, markerPath) is null &&
            await File.ReadAllTextAsync(markerPath) == "keep this fixture unchanged");
        Check("错误报告 写失败后可继续报告下一错误", AppErrorLog.Write("after-write-failure", outer, directory) is not null);

        string recursiveDirectory = Path.Combine(directory, "recursive");
        CallbackMessageException recursive = new(() => AppErrorLog.Write("recursive-inner", outer, recursiveDirectory));
        string? recursivePath = AppErrorLog.Write("recursive-outer", recursive, recursiveDirectory);
        Check("错误报告 异常属性递归写入被阻止", recursivePath is not null && recursive.Calls == 1 &&
            Directory.EnumerateFiles(recursiveDirectory, "error-*.log").Count() == 1);
        ThrowingMessageException throwing = new();
        string? throwingPath = AppErrorLog.Write("throwing-field", throwing, directory);
        Check("错误报告 异常属性自身报错不会递归或丢报告", throwingPath is not null && (await File.ReadAllTextAsync(throwingPath)).Contains("exception field unavailable"));

        foreach (var culture in new[] { DisplayText.Chinese, DisplayText.English })
        {
            using IDisposable scope = DisplayText.UseCulture(culture);
            string saved = DisplayText.Format("Ui.App.ErrorReport.Saved", "fixture-report-path");
            Check("错误报告 路径提示已本地化 " + culture.Name, saved.Contains("fixture-report-path") && !saved.Contains("Ui.App.ErrorReport"));
            Check("错误报告 写入失败提示已本地化 " + culture.Name,
                !DisplayText.Get("Ui.App.ErrorReport.Unavailable").Contains("Ui.App.ErrorReport"));
        }
        await TestNativeBrokerPreflightExitAsync(root);
    }

    private static async Task TestNativeBrokerPreflightExitAsync(string root)
    {
        string directory = Path.Combine(root, "native-broker-preflight");
        Directory.CreateDirectory(directory);
        int reads = 0;
        RemediationClient client = new((_, _) => { reads++; return Task.FromResult<RemediationRunResult?>(null); });
        RemediationPlan plan = new() { PlanId = Guid.NewGuid() };
        string planPath = Path.Combine(directory, "plan.json");
        await File.WriteAllTextAsync(planPath, "inert fixture plan");
        client.RestoreUnresolvedPlan(plan);
        foreach (int exit in new[] { 0, 1, 3, 10, 125, 126, unchecked((int)0x80131506) })
            Check("Broker预检 非专用退出码保留待决状态 " + exit,
                !client.TryCompleteNativePreflightExit(plan.PlanId, exit, usesNativeWrapper: true, planPath) &&
                client.IsUnresolved(plan.PlanId) && File.Exists(planPath));
        Check("Broker预检 开发托管入口无权声明专用NotStarted",
            !client.TryCompleteNativePreflightExit(plan.PlanId, StartupCompatibility.BrokerPreflightNotStartedExitCode, usesNativeWrapper: false, planPath) &&
            client.IsUnresolved(plan.PlanId) && File.Exists(planPath));
        Check("Broker预检 原生专用码释放待决并只清理本次计划",
            client.TryCompleteNativePreflightExit(plan.PlanId, StartupCompatibility.BrokerPreflightNotStartedExitCode, usesNativeWrapper: true, planPath) &&
            !client.HasUnresolvedExecution && !File.Exists(planPath));
        Check("Broker预检 不伪造结果也不读取执行回执", reads == 0 && Directory.GetFileSystemEntries(directory).Length == 0);
        Check("Broker预检 重复完成不得再次认定新操作未开始",
            !client.TryCompleteNativePreflightExit(plan.PlanId, StartupCompatibility.BrokerPreflightNotStartedExitCode, usesNativeWrapper: true, planPath));
        client.RestoreUnresolvedPlan(plan);
        Check("Broker预检 清理失败不递归且已知未开始状态可释放",
            client.TryCompleteNativePreflightExit(plan.PlanId, StartupCompatibility.BrokerPreflightNotStartedExitCode, usesNativeWrapper: true, directory) &&
            !client.HasUnresolvedExecution && Directory.Exists(directory));
        foreach (var culture in new[] { DisplayText.Chinese, DisplayText.English })
        {
            using IDisposable scope = DisplayText.UseCulture(culture);
            string message = DisplayText.Format("Backend.App.RemediationClient.PreflightNotStarted.01", "fixture-log-path");
            Check("Broker预检 操作未开始提示已本地化 " + culture.Name,
                message.Contains("fixture-log-path") && !message.Contains("Backend.App.RemediationClient"));
        }
    }

    private sealed class CallbackMessageException(Func<string?> callback) : Exception
    {
        internal int Calls { get; private set; }
        public override string Message { get { Calls++; _ = callback(); return "recursive fixture"; } }
    }

    private sealed class ThrowingMessageException : Exception
    {
        public override string Message => throw new InvalidOperationException("fixture getter failure");
    }

    private static async Task<int> RunManagedErrorReportTestsAsync(string root)
    {
        Directory.CreateDirectory(root);
        try { await TestManagedErrorReportsAsync(root); }
        catch (Exception ex) { Failures.Add(ex.ToString()); Console.Error.WriteLine(ex); }
        await JsonFile.WriteAtomicAsync(Path.Combine(root, "managed-error-report-results.json"),
            new { passed = _passed, failed = Failures.Count, skipped = _skipped, failures = Failures });
        return Failures.Count == 0 ? 0 : 1;
    }
}
