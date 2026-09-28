using SteamSentinel.Core.Reporting;
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
        if (plan.PlanId == Guid.Empty || plan.Actions.Count > 64) throw MessageExceptions.Create(MessageText.Create("Backend.App.RemediationClient.RestoreUnresolvedPlan.01"), sourceText => new InvalidDataException(sourceText));
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
        if (HasUnresolvedExecution) throw MessageExceptions.Create(MessageText.Create("Backend.App.RemediationClient.ExecuteAsync.01"), sourceText => new InvalidOperationException(sourceText));
        if (!ElevationContext.Read().CanElevateSameUser)
            throw MessageExceptions.Create(MessageText.Create("Backend.App.RemediationClient.ExecuteAsync.02"), sourceText => new UnauthorizedAccessException(sourceText));
        InstallationSecurityStatus installation = await Task.Run(() => InstallationSecurity.Evaluate(), cancellationToken);
        if (!installation.IsProtected) throw SteamSentinel.Core.Reporting.MessageExceptions.Create(installation.MessageText, text => new UnauthorizedAccessException(text));

        string brokerPath = Path.Combine(AppContext.BaseDirectory, "SteamSentinel.Broker.exe");
        if (!File.Exists(brokerPath)) throw MessageExceptions.Create(MessageText.Create("Backend.App.RemediationClient.ExecuteAsync.03"), sourceText => new FileNotFoundException(sourceText, brokerPath));

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
        startInfo.ArgumentList.Add("--ui-language");
        startInfo.ArgumentList.Add(DisplayText.ApplicationCulture.TwoLetterISOLanguageName == "zh" ? "zh-Hans" : "en");

        int brokerExitCode;
        bool started = false;
        try
        {
            if (beforeLaunch is not null) await beforeLaunch(plan, cancellationToken).ConfigureAwait(false);
            _unresolvedPlans.Add(plan.PlanId, plan);
            using Process process = Process.Start(startInfo)
                ?? throw MessageExceptions.Create(MessageText.Create("Backend.App.RemediationClient.ExecuteAsync.04"), sourceText => new InvalidOperationException(sourceText));
            started = true;
            try
            {
                await WaitForBrokerAsync(process.WaitForExitAsync(CancellationToken.None),
                    TimeSpan.FromSeconds(MaximumWaitSeconds), cancellationToken).ConfigureAwait(false);
            }
            catch (Exception ex) when (ex is TimeoutException or OperationCanceledException)
            {
                throw MessageExceptions.Create(MessageText.Create("Backend.App.RemediationClient.ExecuteAsync.05", (resultPath)), sourceText => new InvalidOperationException(sourceText, ex));
            }
            brokerExitCode = process.ExitCode;
        }
        catch (Win32Exception ex) when (ex.NativeErrorCode == 1223)
        {
            _unresolvedPlans.Remove(plan.PlanId);
            throw MessageExceptions.Create(MessageText.Create("Backend.App.RemediationClient.ExecuteAsync.06"), sourceText => new OperationCanceledException(sourceText, ex, cancellationToken));
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
            throw MessageExceptions.Create(MessageText.Create("Backend.App.RemediationClient.ExecuteAsync.07"), sourceText => new InvalidOperationException(sourceText));
        if (brokerExitCode is not (0 or 1 or 3))
            throw MessageExceptions.Create(MessageText.Create("Backend.App.RemediationClient.ExecuteAsync.08", (brokerExitCode)), sourceText => new InvalidOperationException(sourceText));
        if (!File.Exists(resultPath)) throw MessageExceptions.Create(MessageText.Create("Backend.App.RemediationClient.ExecuteAsync.09"), sourceText => new InvalidOperationException(sourceText));
        RemediationRunResult result = await ProtectedRemediationResultReader.TryReadAsync(plan, cancellationToken)
            ?? throw MessageExceptions.Create(MessageText.Create("Backend.App.RemediationClient.ExecuteAsync.10"), sourceText => new InvalidDataException(sourceText));
        _unresolvedPlans.Remove(plan.PlanId);
        try { File.Delete(planPath); } catch (IOException) { }
        return result;
    }

    internal static Task WaitForBrokerAsync(Task processExit, TimeSpan timeout, CancellationToken token) =>
        processExit.WaitAsync(timeout, token);
}
