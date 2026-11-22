using SteamSentinel.Core.Reporting;
using SteamSentinel.Core.Models;

namespace SteamSentinel.Core.Remediation;

public interface IRemediationStateProbe
{
    Task<RemediationVerificationObservation> ObserveAsync(RemediationAction action, CancellationToken cancellationToken);
}

/// <summary>Two bounded read-only observations, not a claim that the whole computer is clean.</summary>
public sealed class RemediationVerification
{
    private readonly IRemediationStateProbe _probe;
    private readonly TimeProvider _timeProvider;

    public RemediationVerification(IRemediationStateProbe probe) : this(probe, null)
    {
    }

    // 仅向内部测试暴露 TimeProvider 注入，生产调用仍默认使用系统时钟。
    internal RemediationVerification(IRemediationStateProbe probe, TimeProvider? timeProvider = null)
    {
        _probe = probe;
        _timeProvider = timeProvider ?? TimeProvider.System;
    }

    public const int MaximumMessageCharacters = 512;
    public static readonly TimeSpan ProbeTimeout = TimeSpan.FromSeconds(10);
    public static readonly TimeSpan FirewallProbeTimeout = TimeSpan.FromSeconds(15);
    public static readonly TimeSpan SecondPassBudget = TimeSpan.FromSeconds(45);

    public static TimeSpan GetProbeTimeout(RemediationActionType type) =>
        type == RemediationActionType.AddProgramFirewallBlock ? FirewallProbeTimeout : ProbeTimeout;

    public async Task ObserveAsync(RemediationAction action, RemediationActionResult result, int pass,
        CancellationToken cancellationToken = default)
    {
        if (pass is < 1 or > 2 || result.Verifications.Count >= 2) throw SteamSentinel.Core.Reporting.MessageExceptions.Create(MessageText.Create("RemediationVerification.ObserveAsync.01"), sourceText => new InvalidOperationException(sourceText));
        if (result.ExecutionStatus is RemediationExecutionStatus.SkippedDependency or RemediationExecutionStatus.ExecutionUnknown)
        {
            result.VerificationStatus = RemediationVerificationStatus.Unknown;
            result.VerificationSummaryText = MessageText.Create("RemediationVerification.ObserveAsync.02");
            return;
        }
        // 使用基于 TimeProvider 的超时令牌与外部取消令牌链接，确保虚拟时钟与真实取消均可触发。
        using CancellationTokenSource timeoutDelay = new(GetProbeTimeout(action.Type), _timeProvider);
        using CancellationTokenSource timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, timeoutDelay.Token);
        RemediationVerificationObservation observation;
        try
        {
            timeout.Token.ThrowIfCancellationRequested();
            observation = await _probe.ObserveAsync(action, timeout.Token).WaitAsync(timeout.Token).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            observation = new()
            {
                Status = RemediationVerificationStatus.Unknown,
                MessageText = ex is OperationCanceledException ? MessageText.Create("RemediationVerification.ObserveAsync.03") : MessageText.Create("Verification.FailedRead", MessageExceptions.Describe(ex))
            };
        }
        RemediationVerificationStatus status = observation.Status;
        if (!Enum.IsDefined(status) || status == RemediationVerificationStatus.NotChecked) status = RemediationVerificationStatus.Unknown;
        if (pass == 2 && status is RemediationVerificationStatus.ResidualDetected or RemediationVerificationStatus.PendingReboot &&
            result.Verifications.Any(item => IsClear(item.Status)))
            status = RemediationVerificationStatus.Reappeared;
        MessageText message = Limit(observation.MessageText, MaximumMessageCharacters);
        if (SteamAlertWatchdogStateProbe.IsFamilyTargetAction(action) &&
            result.VerificationStatus == RemediationVerificationStatus.Reappeared && IsClear(status))
        {
            // A bounded later observation cannot erase a replacement instance observed at
            // an action boundary during this run. Require a fresh review/scan of the chain.
            status = RemediationVerificationStatus.Reappeared;
            message = MessageText.Create("Watchdog.ReappearedDuringRun", result.VerificationSummaryText);
        }
        if (result.ExecutionStatus == RemediationExecutionStatus.Failed && IsClear(status))
        {
            status = RemediationVerificationStatus.Unknown;
            message = MessageText.Create("Verification.ExecutionFailed", message);
        }
        if (status == RemediationVerificationStatus.Reappeared) message = MessageText.Create("Verification.Reappeared", message);
        result.Verifications.Add(new() { Pass = pass, Status = status, MessageText = Limit(message, MaximumMessageCharacters) });
        result.VerificationStatus = status;
        result.VerificationSummaryText = Limit(message, MaximumMessageCharacters);
    }

    public async Task CompleteAsync(RemediationPlan plan, RemediationRunResult result,
        CancellationToken cancellationToken = default, TimeSpan? secondPassDelay = null)
    {
        TimeSpan delay = secondPassDelay ?? TimeSpan.FromSeconds(1);
        if (delay < TimeSpan.Zero || delay > TimeSpan.FromSeconds(2)) throw new ArgumentOutOfRangeException(nameof(secondPassDelay));
        using CancellationTokenSource budgetDelay = new(SecondPassBudget, _timeProvider);
        using CancellationTokenSource budget = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, budgetDelay.Token);
        try { await Task.Delay(delay, _timeProvider, budget.Token).ConfigureAwait(false); }
        catch (OperationCanceledException) { }
        await Parallel.ForEachAsync(result.Actions, new ParallelOptions { MaxDegreeOfParallelism = 2 }, async (actionResult, _) =>
        {
            RemediationAction? action = plan.Actions.FirstOrDefault(item => item.ActionId == actionResult.ActionId);
            if (action is not null) await ObserveAsync(action, actionResult, 2, budget.Token).ConfigureAwait(false);
        }).ConfigureAwait(false);
        Summarize(result);
    }

    public static void Summarize(RemediationRunResult result)
    {
        RemediationVerificationStatus[] states = result.Actions.Select(action => action.VerificationStatus).ToArray();
        RemediationVerificationStatus[] priorities = [RemediationVerificationStatus.Reappeared,
            RemediationVerificationStatus.ResidualDetected, RemediationVerificationStatus.Unknown,
            RemediationVerificationStatus.NotChecked, RemediationVerificationStatus.PendingReboot];
        result.VerificationStatus = states.Length == 0 ? RemediationVerificationStatus.NotChecked :
            priorities.Where(states.Contains).Cast<RemediationVerificationStatus?>().FirstOrDefault() ??
            (states.All(state => state == RemediationVerificationStatus.NoResidual) ? RemediationVerificationStatus.NoResidual : RemediationVerificationStatus.Verified);
        result.VerificationSummaryText = MessageText.Create("Verification.Summary", MessageText.Join(MessageText.Create("Common.ListSeparator"), states.GroupBy(state => state)
            .Select(group => MessageText.Create("RemediationVerification.Summarize.02", LabelText(group.Key), group.Count()))));
        result.VerificationCompletedAtUtc = DateTimeOffset.UtcNow;
    }

    private static bool IsClear(RemediationVerificationStatus status) =>
        status is RemediationVerificationStatus.Verified or RemediationVerificationStatus.NoResidual;

    public static string Label(RemediationVerificationStatus status, System.Globalization.CultureInfo culture)
    {
        using IDisposable scope = DisplayText.UseCulture(culture);
        return Label(status);
    }

    public static string Label(RemediationVerificationStatus status) => LabelText(status).Display;

    public static MessageText LabelText(RemediationVerificationStatus status) => status switch
    {
        RemediationVerificationStatus.NotChecked => MessageText.Create("RemediationVerification.Label.NotChecked.01"),
        RemediationVerificationStatus.Verified => MessageText.Create("RemediationVerification.Label.Verified.01"),
        RemediationVerificationStatus.NoResidual => MessageText.Create("RemediationVerification.Label.NoResidual.01"),
        RemediationVerificationStatus.PendingReboot => MessageText.Create("RemediationVerification.Label.PendingReboot.01"),
        RemediationVerificationStatus.ResidualDetected => MessageText.Create("RemediationVerification.Label.ResidualDetected.01"),
        RemediationVerificationStatus.Reappeared => MessageText.Create("RemediationVerification.Label.Reappeared.01"),
        _ => MessageText.Create("RemediationVerification.Label.01")
    };

    public static string Limit(string? value, int length = MaximumMessageCharacters)
    {
        if (string.IsNullOrEmpty(value)) return string.Empty;
        string limited = value.Length <= length ? value : value[..Math.Max(0, length - 1)] + "…";
        return new string(limited.Select(character => char.IsControl(character) ? ' ' : character).ToArray());
    }

    public static MessageText Limit(MessageText value, int length = MaximumMessageCharacters)
    {
        string limited = Limit(value.OriginalText, length);
        return limited == value.OriginalText ? value : new(limited);
    }
}
