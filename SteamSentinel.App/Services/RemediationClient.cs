using System.ComponentModel;
using System.Diagnostics;
using SteamSentinel.Core.Models;
using SteamSentinel.Core.Utilities;

namespace SteamSentinel.App.Services;

internal sealed class RemediationClient
{
    public async Task<RemediationRunResult> ExecuteAsync(RemediationPlan plan, CancellationToken cancellationToken = default)
    {
        if (!ElevationContext.Read().CanElevateSameUser)
            throw new UnauthorizedAccessException("当前账户需要先打开管理员窗口并重新扫描，不能把原账户的处置计划交给另一账户执行。");
        InstallationSecurityStatus installation = await Task.Run(() => InstallationSecurity.Evaluate(), cancellationToken);
        if (!installation.IsProtected) throw new UnauthorizedAccessException(installation.Message);

        string brokerPath = Path.Combine(AppContext.BaseDirectory, "SteamSentinel.Broker.exe");
        if (!File.Exists(brokerPath)) throw new FileNotFoundException("缺少管理员处置组件。", brokerPath);

        Directory.CreateDirectory(AppPaths.PlansRoot);
        string planPath = Path.Combine(AppPaths.PlansRoot, $"plan-{plan.PlanId:N}.json");
        string resultPath = Path.Combine(AppPaths.ResultsRoot, $"result-{plan.PlanId:N}.json");
        await JsonFile.WriteAtomicAsync(planPath, plan, cancellationToken);
        string planSha256 = await Hashing.Sha256FileExclusiveAsync(planPath, cancellationToken);

        ProcessStartInfo startInfo = new()
        {
            FileName = brokerPath,
            UseShellExecute = true,
            Verb = "runas",
            WorkingDirectory = AppContext.BaseDirectory,
            WindowStyle = ProcessWindowStyle.Hidden
        };
        startInfo.ArgumentList.Add(planPath);
        startInfo.ArgumentList.Add(planSha256);

        int brokerExitCode;
        try
        {
            using Process process = Process.Start(startInfo)
                ?? throw new InvalidOperationException("无法启动管理员处置组件。");
            await process.WaitForExitAsync(cancellationToken);
            brokerExitCode = process.ExitCode;
        }
        catch (Win32Exception ex) when (ex.NativeErrorCode == 1223)
        {
            throw new OperationCanceledException("用户取消了 UAC 授权。", ex, cancellationToken);
        }
        finally
        {
            try { File.Delete(planPath); } catch { }
        }

        if (brokerExitCode == 10)
            throw new InvalidOperationException("管理员处置结果通道已被占用或无法安全新建，本次结果不可采信，请导出报告后重新扫描。已执行的动作可能需要人工核对。");
        if (brokerExitCode is not (0 or 1 or 3))
            throw new InvalidOperationException($"管理员处置组件异常退出：{brokerExitCode}");
        if (!File.Exists(resultPath)) throw new InvalidOperationException("处置组件没有返回受保护结果文件。");
        RemediationRunResult result = await JsonFile.ReadAsync<RemediationRunResult>(resultPath, cancellationToken);
        if (result.PlanId != plan.PlanId) throw new InvalidDataException("处置结果与请求计划不匹配。");
        return result;
    }
}
