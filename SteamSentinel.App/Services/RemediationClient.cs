using System.ComponentModel;
using System.Diagnostics;
using SteamSentinel.Core.Models;
using SteamSentinel.Core.Utilities;

namespace SteamSentinel.App.Services;

internal sealed class RemediationClient
{
    public async Task<RemediationRunResult> ExecuteAsync(RemediationPlan plan, CancellationToken cancellationToken = default)
    {
        string brokerPath = Path.Combine(AppContext.BaseDirectory, "SteamSentinel.Broker.exe");
        if (!File.Exists(brokerPath)) throw new FileNotFoundException("缺少管理员处置组件。", brokerPath);

        Directory.CreateDirectory(AppPaths.PlansRoot);
        string planPath = Path.Combine(AppPaths.PlansRoot, $"plan-{plan.PlanId:N}.json");
        string resultPath = Path.Combine(AppPaths.PlansRoot, $"result-{plan.PlanId:N}.json");
        await JsonFile.WriteAtomicAsync(planPath, plan, cancellationToken);

        ProcessStartInfo startInfo = new()
        {
            FileName = brokerPath,
            UseShellExecute = true,
            Verb = "runas",
            WorkingDirectory = AppContext.BaseDirectory,
            WindowStyle = ProcessWindowStyle.Hidden
        };
        startInfo.ArgumentList.Add(planPath);
        startInfo.ArgumentList.Add(resultPath);

        try
        {
            using Process process = Process.Start(startInfo)
                ?? throw new InvalidOperationException("无法启动管理员处置组件。");
            await process.WaitForExitAsync(cancellationToken);
        }
        catch (Win32Exception ex) when (ex.NativeErrorCode == 1223)
        {
            throw new OperationCanceledException("用户取消了 UAC 授权。", ex, cancellationToken);
        }

        if (!File.Exists(resultPath)) throw new InvalidOperationException("处置组件没有返回结果文件。");
        return await JsonFile.ReadAsync<RemediationRunResult>(resultPath, cancellationToken);
    }
}
