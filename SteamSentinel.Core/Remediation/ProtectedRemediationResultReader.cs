using SteamSentinel.Core.Reporting;
using System.Security.Principal;
using System.Text.Json;
using SteamSentinel.Core.Models;
using SteamSentinel.Core.Scanning;
using SteamSentinel.Core.Utilities;

namespace SteamSentinel.Core.Remediation;

public static class ProtectedRemediationResultReader
{
    public const int MaximumBytes = 1024 * 1024;
    public static async Task<RemediationRunResult?> TryReadAsync(RemediationPlan plan, CancellationToken token = default)
    {
        if (plan.PlanId == Guid.Empty || plan.RequestedBySid != WindowsIdentity.GetCurrent().User?.Value)
            throw MessageExceptions.Create(MessageText.Create("Backend.Core.ProtectedRemediationResultReader.TryReadAsync.01"), sourceText => new UnauthorizedAccessException(sourceText));
        string path = Path.Combine(AppPaths.ResultsRoot, $"result-{plan.PlanId:N}.json");
        if (!File.Exists(path)) return null;
        MachineStateSecurity.EnsureProtectedPath(AppPaths.MachineStateRoot);
        MachineStateSecurity.EnsureProtectedPath(AppPaths.ResultsRoot);
        MachineStateSecurity.EnsureProtectedPath(path);
        await using FileStream stream = RelatedArtifactReader.Open(path);
        if (stream.Length is <= 0 or > MaximumBytes) return null;
        RemediationRunResult? result;
        try { result = await JsonSerializer.DeserializeAsync<RemediationRunResult>(stream, JsonFile.Options, token).ConfigureAwait(false); }
        catch (JsonException) { return null; }
        RelatedArtifactReader.ValidatePath(stream.SafeFileHandle, Path.GetFullPath(path));
        MachineStateSecurity.EnsureProtectedPath(path);
        if (result is null) return null;
        Validate(plan, result);
        return result;
    }

    public static void Validate(RemediationPlan plan, RemediationRunResult result)
    {
        if (result.Actions is null || result.Errors is null || result.Actions.Count > 64 || result.Errors.Count > 128 ||
            result.Actions.Any(action => action is null || action.Verifications is null || action.Verifications.Count > 256 || action.Verifications.Any(observation => observation is null)))
            throw MessageExceptions.Create(MessageText.Create("Backend.Core.ProtectedRemediationResultReader.Validate.01"), sourceText => new InvalidDataException(sourceText));
        if (result.ErrorMessages is not null && (result.ErrorMessages.Count != result.Errors.Count || result.ErrorMessages.Count > 128))
            throw new InvalidDataException("Invalid result error message descriptors.");
        long displayCharacters = 0;
        foreach (DisplayMessage? message in result.ErrorMessages ?? []) displayCharacters += message?.Validate() ?? 0;
        displayCharacters += result.VerificationSummaryMessage?.Validate() ?? 0;
        foreach (RemediationActionResult action in result.Actions)
        {
            displayCharacters += (action.ResultMessage?.Validate() ?? 0) + (action.VerificationSummaryMessage?.Validate() ?? 0);
            displayCharacters += action.Occupancy?.DiagnosticMessage?.Validate() ?? 0;
            foreach (RemediationVerificationObservation observation in action.Verifications)
                displayCharacters += observation.ResultMessage?.Validate() ?? 0;
        }
        if (displayCharacters > 256 * 1024) throw new InvalidDataException("Result display message limit exceeded.");
        if (!Validation.IsHexSha256(result.PlanIdentitySha256) ||
            !result.PlanIdentitySha256.Equals(RemediationPlanIdentity.Fingerprint(plan), StringComparison.OrdinalIgnoreCase) ||
            result.PlanId != plan.PlanId || result.CompletedAtUtc is null || result.StartedAtUtc == default ||
            result.Disposition == RemediationRunDisposition.ExecutionUnknown || !Enum.IsDefined(result.Disposition) ||
            result.Disposition == RemediationRunDisposition.NotStarted && (result.Success || result.Actions.Count != 0 || result.Errors.Count == 0) ||
            result.Disposition != RemediationRunDisposition.NotStarted && result.Actions.Count != plan.Actions.Count ||
            result.CompletedAtUtc < result.StartedAtUtc || result.Actions is null || result.Errors is null ||
            result.Actions.Count > 64 || result.Errors.Count > 128 ||
            result.Actions.Select(a => a.ActionId).Distinct().Count() != result.Actions.Count ||
            result.Actions.Any(a => a.ExecutionStatus == RemediationExecutionStatus.ExecutionUnknown || !Enum.IsDefined(a.ExecutionStatus)) ||
            result.Actions.Any(r => !plan.Actions.Any(a => a.ActionId == r.ActionId && a.Type == r.Type && a.Target == r.Target)) ||
            result.Success && (result.Actions.Count != plan.Actions.Count || result.Errors.Count > 0 || result.Actions.Any(a => !a.Success)))
            throw MessageExceptions.Create(MessageText.Create("Backend.Core.ProtectedRemediationResultReader.Validate.02"), sourceText => new InvalidDataException(sourceText));
    }
}
