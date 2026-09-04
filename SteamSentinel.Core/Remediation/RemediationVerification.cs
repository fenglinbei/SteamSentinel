using SteamSentinel.Core.Models;

namespace SteamSentinel.Core.Remediation;

public interface IRemediationStateProbe
{
    Task<RemediationVerificationObservation> ObserveAsync(RemediationAction action, CancellationToken cancellationToken);
}

/// <summary>Two bounded read-only observations, not a claim that the whole computer is clean.</summary>
public sealed class RemediationVerification(IRemediationStateProbe probe)
{
    public const int MaximumMessageCharacters = 512;
    public static readonly TimeSpan ProbeTimeout = TimeSpan.FromSeconds(4);
    public static readonly TimeSpan SecondPassBudget = TimeSpan.FromSeconds(20);

    public async Task ObserveAsync(RemediationAction action, RemediationActionResult result, int pass,
        CancellationToken cancellationToken = default)
    {
        if (pass is < 1 or > 2 || result.Verifications.Count >= 2) throw new InvalidOperationException("验证最多两轮。");
        using CancellationTokenSource timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(ProbeTimeout);
        RemediationVerificationObservation observation;
        try
        {
            timeout.Token.ThrowIfCancellationRequested();
            observation = await probe.ObserveAsync(action, timeout.Token).WaitAsync(timeout.Token).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            observation = new() { Status = RemediationVerificationStatus.Unknown,
                Message = ex is OperationCanceledException ? "只读验证超时或取消，无法确认状态。" : "只读验证失败：" + ex.Message };
        }
        RemediationVerificationStatus status = observation.Status;
        if (!Enum.IsDefined(status) || status == RemediationVerificationStatus.NotChecked) status = RemediationVerificationStatus.Unknown;
        if (pass == 2 && status is RemediationVerificationStatus.ResidualDetected or RemediationVerificationStatus.PendingReboot &&
            result.Verifications.Any(item => IsClear(item.Status)))
            status = RemediationVerificationStatus.Reappeared;
        string message = Limit(observation.Message, MaximumMessageCharacters);
        if (status == RemediationVerificationStatus.Reappeared) message = "首次验证通过后目标再次出现/状态回退，" + message;
        result.Verifications.Add(new() { Pass = pass, Status = status, Message = Limit(message, MaximumMessageCharacters) });
        result.VerificationStatus = status;
        result.VerificationSummary = Limit(message, MaximumMessageCharacters);
    }

    public async Task CompleteAsync(RemediationPlan plan, RemediationRunResult result,
        CancellationToken cancellationToken = default, TimeSpan? secondPassDelay = null)
    {
        TimeSpan delay = secondPassDelay ?? TimeSpan.FromSeconds(1);
        if (delay < TimeSpan.Zero || delay > TimeSpan.FromSeconds(2)) throw new ArgumentOutOfRangeException(nameof(secondPassDelay));
        using CancellationTokenSource budget = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        budget.CancelAfter(SecondPassBudget);
        try { await Task.Delay(delay, budget.Token).ConfigureAwait(false); }
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
        result.VerificationSummary = "仅验证本计划目标，非全机安全结论。" + string.Join("，", states.GroupBy(state => state)
            .Select(group => $"{Label(group.Key)} {group.Count()} 项"));
        result.VerificationCompletedAtUtc = DateTimeOffset.UtcNow;
    }

    private static bool IsClear(RemediationVerificationStatus status) =>
        status is RemediationVerificationStatus.Verified or RemediationVerificationStatus.NoResidual;

    public static string Label(RemediationVerificationStatus status) => status switch
    {
        RemediationVerificationStatus.NotChecked => "尚未验证",
        RemediationVerificationStatus.Verified => "已验证",
        RemediationVerificationStatus.NoResidual => "未发现目标残留",
        RemediationVerificationStatus.PendingReboot => "待重启复验",
        RemediationVerificationStatus.ResidualDetected => "仍有残留",
        RemediationVerificationStatus.Reappeared => "再次出现",
        _ => "状态未知"
    };

    public static string Limit(string? value, int length = MaximumMessageCharacters)
    {
        if (string.IsNullOrEmpty(value)) return string.Empty;
        string limited = value.Length <= length ? value : value[..Math.Max(0, length - 1)] + "…";
        return new string(limited.Select(character => char.IsControl(character) ? ' ' : character).ToArray());
    }
}
