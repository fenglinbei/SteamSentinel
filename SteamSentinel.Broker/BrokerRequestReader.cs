using SteamSentinel.Core.Reporting;
using System.Security.Principal;
using SteamSentinel.Core.Models;
using SteamSentinel.Core.Utilities;

namespace SteamSentinel.Broker;

internal static class BrokerRequestReader
{
    private const long MaximumPlanBytes = 1024 * 1024;

    public static async Task<RemediationPlan> ReadAsync(
        string planPath,
        string expectedSha256,
        CancellationToken cancellationToken = default)
    {
        if (!Validation.IsHexSha256(expectedSha256))
            throw MessageExceptions.Create(MessageText.Create("Backend.Broker.BrokerRequestReader.ReadAsync.01"), sourceText => new InvalidDataException(sourceText));

        string fullPath = ValidatePlanPath(planPath);
        await using SecureFileLease planLease = SecureFileLease.Open(
            fullPath,
            allowPackagedLocalAppDataRedirection: true);
        if (planLease.Length is <= 0 or > MaximumPlanBytes)
            throw MessageExceptions.Create(MessageText.Create("Backend.Broker.BrokerRequestReader.ReadAsync.02"), sourceText => new InvalidDataException(sourceText));
        string actualSha256 = await planLease.ComputeSha256Async(cancellationToken).ConfigureAwait(false);
        if (!actualSha256.Equals(expectedSha256, StringComparison.OrdinalIgnoreCase))
            throw MessageExceptions.Create(MessageText.Create("Backend.Broker.BrokerRequestReader.ReadAsync.03"), sourceText => new InvalidDataException(sourceText));

        RemediationPlan plan = await planLease.ReadJsonAsync<RemediationPlan>(cancellationToken).ConfigureAwait(false);
        string expectedName = $"plan-{plan.PlanId:N}.json";
        if (!Path.GetFileName(fullPath).Equals(expectedName, StringComparison.OrdinalIgnoreCase))
            throw MessageExceptions.Create(MessageText.Create("Backend.Broker.BrokerRequestReader.ReadAsync.04"), sourceText => new InvalidDataException(sourceText));

        string currentSid = WindowsIdentity.GetCurrent().User?.Value ?? string.Empty;
        if (string.IsNullOrWhiteSpace(plan.RequestedBySid) ||
            !plan.RequestedBySid.Equals(currentSid, StringComparison.OrdinalIgnoreCase))
        {
            throw MessageExceptions.Create(MessageText.Create("Backend.Broker.BrokerRequestReader.ReadAsync.05"), sourceText => new UnauthorizedAccessException(sourceText));
        }

        return plan;
    }

    private static string ValidatePlanPath(string path)
    {
        string root = Path.TrimEndingDirectorySeparator(Path.GetFullPath(AppPaths.PlansRoot));
        string full = Path.GetFullPath(path);
        if (!full.StartsWith(root + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase) ||
            !Path.GetFileName(full).StartsWith("plan-", StringComparison.OrdinalIgnoreCase) ||
            !full.EndsWith(".json", StringComparison.OrdinalIgnoreCase))
        {
            throw MessageExceptions.Create(MessageText.Create("Backend.Broker.BrokerRequestReader.ValidatePlanPath.01"), sourceText => new UnauthorizedAccessException(sourceText));
        }

        if (Validation.ContainsReparsePoint(Path.GetDirectoryName(full)!))
            throw MessageExceptions.Create(MessageText.Create("Backend.Broker.BrokerRequestReader.ValidatePlanPath.02"), sourceText => new UnauthorizedAccessException(sourceText));
        return full;
    }
}
