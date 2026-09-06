using System.ComponentModel;
using System.Diagnostics;
using SteamSentinel.Core.Models;
using SteamSentinel.Core.Remediation;
using SteamSentinel.Core.Utilities;

namespace SteamSentinel.App.Services;

internal sealed class RemediationClient
{
    internal const int MaximumWaitSeconds = 300;
    private readonly Dictionary<Guid, RemediationPlan> _unresolvedPlans = [];
    internal bool HasUnresolvedExecution => _unresolvedPlans.Count > 0;
    internal bool IsUnresolved(Guid id) => _unresolvedPlans.ContainsKey(id);
    internal void RestoreUnresolvedPlan(RemediationPlan plan)
    {
        if (plan.PlanId == Guid.Empty || plan.Actions.Count > 64) throw new InvalidDataException("未决计划记录无效。");
        _unresolvedPlans.TryAdd(plan.PlanId, plan);
    }

    internal async Task<RemediationRunResult?> TryRecoverResultAsync()
    {
        foreach ((Guid id, RemediationPlan plan) in _unresolvedPlans.ToArray())
        {
            RemediationRunResult? result;
            try { result = await ProtectedRemediationResultReader.TryReadAsync(plan).ConfigureAwait(false); }
            catch (IOException) { continue; }
            catch (Win32Exception) { continue; }
            if (result is null) continue;
            _unresolvedPlans.Remove(id);
            try { File.Delete(Path.Combine(AppPaths.PlansRoot, $"plan-{id:N}.json")); } catch (IOException) { }
            return result;
        }
        return null;
    }

    public async Task<RemediationRunResult> ExecuteAsync(RemediationPlan plan, CancellationToken cancellationToken = default,
        Func<RemediationPlan, CancellationToken, Task>? beforeLaunch = null)
    {
        if (HasUnresolvedExecution) throw new InvalidOperationException("上一次管理员操作尚无确定结果，禁止提交新操作。请重新检查并导出记录。");
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
        bool started = false;
        try
        {
            if (beforeLaunch is not null) await beforeLaunch(plan, cancellationToken).ConfigureAwait(false);
            _unresolvedPlans.Add(plan.PlanId, plan);
            using Process process = Process.Start(startInfo)
                ?? throw new InvalidOperationException("无法启动管理员处置组件。");
            started = true;
            try
            {
                await WaitForBrokerAsync(process.WaitForExitAsync(CancellationToken.None),
                    TimeSpan.FromSeconds(MaximumWaitSeconds), cancellationToken).ConfigureAwait(false);
            }
            catch (Exception ex) when (ex is TimeoutException or OperationCanceledException)
            {
                throw new InvalidOperationException($"管理员操作在等待期限内未返回确定结果，后台可能仍在执行，已暂停新的处置。可导出记录并关闭此窗口；请勿重复操作或重启。结果位置：{resultPath}", ex);
            }
            brokerExitCode = process.ExitCode;
        }
        catch (Win32Exception ex) when (ex.NativeErrorCode == 1223)
        {
            _unresolvedPlans.Remove(plan.PlanId);
            throw new OperationCanceledException("用户取消了 UAC 授权。", ex, cancellationToken);
        }
        catch when (!started)
        {
            _unresolvedPlans.Remove(plan.PlanId);
            throw;
        }
        finally
        {
            if (!HasUnresolvedExecution) try { File.Delete(planPath); } catch { }
        }

        if (brokerExitCode == 10)
            throw new InvalidOperationException("管理员处置结果通道已被占用或无法安全新建，本次结果不可采信，请导出报告后重新扫描。已执行的动作可能需要人工核对。");
        if (brokerExitCode is not (0 or 1 or 3))
            throw new InvalidOperationException($"管理员处置组件异常退出：{brokerExitCode}");
        if (!File.Exists(resultPath)) throw new InvalidOperationException("处置组件没有返回受保护结果文件。");
        RemediationRunResult result = await ProtectedRemediationResultReader.TryReadAsync(plan, cancellationToken)
            ?? throw new InvalidDataException("管理员结果尚未完整返回，保持执行状态未知。");
        _unresolvedPlans.Remove(plan.PlanId);
        try { File.Delete(planPath); } catch (IOException) { }
        return result;
    }

    internal static Task WaitForBrokerAsync(Task processExit, TimeSpan timeout, CancellationToken token) =>
        processExit.WaitAsync(timeout, token);
}
