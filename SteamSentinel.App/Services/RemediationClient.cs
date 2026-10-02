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
    private readonly Func<RemediationPlan, CancellationToken, Task<RemediationRunResult?>> _readFinished;

    internal RemediationClient() : this(ProtectedRemediationResultReader.TryReadFinishedAsync) { }

    // Test readers return inert receipts only; production always reads the protected, closed channel.
    internal RemediationClient(Func<RemediationPlan, CancellationToken, Task<RemediationRunResult?>> readFinished)
        => _readFinished = readFinished;
    internal bool HasUnresolvedExecution => _unresolvedPlans.Count > 0;
    internal bool IsUnresolved(Guid id) => _unresolvedPlans.ContainsKey(id);
    internal void RestoreUnresolvedPlan(RemediationPlan plan)
    {
        if (plan.PlanId == Guid.Empty || plan.Actions.Count > 64) throw MessageExceptions.Create(MessageText.Create("Backend.App.RemediationClient.RestoreUnresolvedPlan.01"), sourceText => new InvalidDataException(sourceText));
        _unresolvedPlans.TryAdd(plan.PlanId, plan);
    }

    internal async Task<RemediationRunResult?> TryRecoverResultAsync()
    {
        foreach (RemediationPlan plan in _unresolvedPlans.Values.ToArray())
        {
            RemediationRunResult? result;
            try
            {
                result = await _readFinished(plan, CancellationToken.None).ConfigureAwait(false);
                if (result is not null) ProtectedRemediationResultReader.ValidateFinished(plan, result);
            }
            catch (IOException) { continue; }
            catch (InvalidDataException) { continue; }
            catch (Win32Exception) { continue; }
            catch (UnauthorizedAccessException) { continue; }
            if (result is null) continue;
            // Reading a finished receipt does not unlock anything until its history is durable.
            return result;
        }
        return null;
    }

    internal async Task PersistResultAsync(RemediationRunResult result, Func<Task> persist)
    {
        if (!_unresolvedPlans.TryGetValue(result.PlanId, out RemediationPlan? plan))
            throw MessageExceptions.Create(MessageText.Create("Backend.App.RemediationClient.ExecuteAsync.10"), sourceText => new InvalidDataException(sourceText));
        ProtectedRemediationResultReader.ValidateFinished(plan, result);
        await persist().ConfigureAwait(false);
        _unresolvedPlans.Remove(result.PlanId);
        try { File.Delete(Path.Combine(AppPaths.PlansRoot, $"plan-{result.PlanId:N}.json")); }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { }
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
        bool usesNativeWrapper = AddStartupPreference(startInfo, Environment.ProcessPath);
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

        if (TryCompleteNativePreflightExit(plan.PlanId, brokerExitCode, usesNativeWrapper, planPath))
            throw MessageExceptions.Create(MessageText.Create("Backend.App.RemediationClient.PreflightNotStarted.01",
                Path.Combine(AppPaths.UserStateRoot, "Logs")), text => new BrokerPreflightNotStartedException(text));
        if (brokerExitCode == 10)
            throw MessageExceptions.Create(MessageText.Create("Backend.App.RemediationClient.ExecuteAsync.07"), sourceText => new InvalidOperationException(sourceText));
        if (brokerExitCode is not (0 or 1 or 3))
            throw MessageExceptions.Create(MessageText.Create("Backend.App.RemediationClient.ExecuteAsync.08", (brokerExitCode)), sourceText => new InvalidOperationException(sourceText));
        if (!File.Exists(resultPath)) throw MessageExceptions.Create(MessageText.Create("Backend.App.RemediationClient.ExecuteAsync.09"), sourceText => new InvalidOperationException(sourceText));
        RemediationRunResult result = await _readFinished(plan, cancellationToken)
            ?? throw MessageExceptions.Create(MessageText.Create("Backend.App.RemediationClient.ExecuteAsync.10"), sourceText => new InvalidDataException(sourceText));
        ProtectedRemediationResultReader.ValidateFinished(plan, result);
        // ExecuteRecordedPlanAsync persists the receipt before releasing the pending gate.
        return result;
    }

    internal static Task WaitForBrokerAsync(Task processExit, TimeSpan timeout, CancellationToken token) =>
        processExit.WaitAsync(timeout, token);

    internal bool TryCompleteNativePreflightExit(Guid planId, int exitCode, bool usesNativeWrapper, string planPath)
    {
        // Only the fixed, integrity-checked native wrapper may certify this before business launch.
        // Unknown errors, timeouts and all business exits continue to require a protected receipt.
        if (!usesNativeWrapper || exitCode != StartupCompatibility.BrokerPreflightNotStartedExitCode ||
            !_unresolvedPlans.Remove(planId)) return false;
        try { File.Delete(planPath); }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { }
        return true;
    }

    internal static bool AddStartupPreference(ProcessStartInfo startInfo, string? appProcessPath)
    {
        if (!StartupCompatibility.TryIdentifyHost(appProcessPath, StartupRole.App, out StartupMode mode, out bool unified) || !unified)
            return false;
        // The native wrapper removes these arguments, probes under the elevated token and starts
        // the managed broker once. This preference never replaces any broker authorization checks.
        startInfo.ArgumentList.Add("--startup-mode");
        startInfo.ArgumentList.Add(StartupCompatibility.ModeName(mode));
        return true;
    }
}

internal sealed class BrokerPreflightNotStartedException(string message) : InvalidOperationException(message);
