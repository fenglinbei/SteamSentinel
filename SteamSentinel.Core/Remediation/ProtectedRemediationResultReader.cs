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

    /// <summary>
    /// Reads a result from the authenticated, closed Broker channel. A returned ExecutionUnknown
    /// remains unknown: this proves only that the original channel is no longer executing, never
    /// that its actions succeeded, did not start, or may be replayed. Broker releases its mutation
    /// lease before closing this channel; the read handle denies concurrent write/delete access.
    /// </summary>
    public static Task<RemediationRunResult?> TryReadFinishedAsync(RemediationPlan plan, CancellationToken token = default)
    {
        string path = Path.Combine(AppPaths.ResultsRoot, $"result-{plan.PlanId:N}.json");
        return TryReadFinishedCoreAsync(plan, path, WindowsIdentity.GetCurrent().User?.Value, () =>
        {
            MachineStateSecurity.EnsureProtectedPath(AppPaths.MachineStateRoot);
            MachineStateSecurity.EnsureProtectedPath(AppPaths.ResultsRoot);
            MachineStateSecurity.EnsureProtectedPath(path);
        }, token);
    }

    // Only SelfTest may substitute a fixture path and ACL check. The real deny-write/delete open
    // and final-handle path validation are deliberately shared with the production reader.
    internal static Task<RemediationRunResult?> TryReadFinishedForTestingAsync(RemediationPlan plan,
        string path, string? currentUserSid, Action ensureProtectedPaths, CancellationToken token = default) =>
        TryReadFinishedCoreAsync(plan, path, currentUserSid, ensureProtectedPaths, token);

    private static async Task<RemediationRunResult?> TryReadFinishedCoreAsync(RemediationPlan plan,
        string path, string? currentUserSid, Action ensureProtectedPaths, CancellationToken token)
    {
        if (plan.PlanId == Guid.Empty || string.IsNullOrWhiteSpace(currentUserSid) || plan.RequestedBySid != currentUserSid)
            throw MessageExceptions.Create(MessageText.Create("Backend.Core.ProtectedRemediationResultReader.TryReadAsync.01"), sourceText => new UnauthorizedAccessException(sourceText));
        token.ThrowIfCancellationRequested();
        if (!File.Exists(path)) return null;
        ensureProtectedPaths();
        await using FileStream stream = RelatedArtifactReader.Open(path);
        if (stream.Length is <= 0 or > MaximumBytes) return null;
        RemediationRunResult? result;
        try
        {
            using JsonDocument document = await JsonDocument.ParseAsync(stream, cancellationToken: token).ConfigureAwait(false);
            result = document.RootElement.Deserialize<RemediationRunResult>(JsonFile.Options);
            if (result?.Disposition == RemediationRunDisposition.ExecutionUnknown)
            {
                // Model defaults must not turn an incomplete record into evidence of completion.
                HashSet<string> fields = new(StringComparer.OrdinalIgnoreCase);
                foreach (JsonProperty property in document.RootElement.EnumerateObject())
                    if (!fields.Add(property.Name)) throw new InvalidDataException("Duplicate finished result property.");
                string[] required = [nameof(result.PlanId), nameof(result.PlanIdentitySha256), nameof(result.StartedAtUtc),
                    nameof(result.CompletedAtUtc), nameof(result.Disposition), nameof(result.Success),
                    nameof(result.Actions), nameof(result.Errors), nameof(result.VerificationStatus)];
                if (required.Any(field => !fields.Contains(field)))
                    throw new InvalidDataException("Incomplete finished result record.");
            }
        }
        catch (JsonException) { return null; }
        RelatedArtifactReader.ValidatePath(stream.SafeFileHandle, Path.GetFullPath(path));
        ensureProtectedPaths();
        if (result is null) return null;
        ValidateFinished(plan, result);
        return result;
    }

    /// <summary>
    /// Validates structure and plan binding only. This method alone is NOT evidence that a Broker
    /// has stopped; only TryReadFinishedAsync's protected closed-channel read supplies that proof.
    /// ExecutionUnknown retains its original disposition and cannot authorize success or replay.
    /// </summary>
    public static void ValidateFinished(RemediationPlan plan, RemediationRunResult result)
    {
        if (result.Disposition != RemediationRunDisposition.ExecutionUnknown)
        {
            Validate(plan, result);
            return;
        }

        // This is the narrow run-level exception shape emitted by Broker's outer catch. Partial
        // action results and claimed verification outcomes must still fail closed.
        if (plan.PlanId == Guid.Empty || string.IsNullOrWhiteSpace(plan.RequestedBySid) ||
            !Validation.IsHexSha256(result.PlanIdentitySha256) ||
            !result.PlanIdentitySha256.Equals(RemediationPlanIdentity.Fingerprint(plan), StringComparison.OrdinalIgnoreCase) ||
            result.PlanId != plan.PlanId || result.StartedAtUtc == default || result.CompletedAtUtc is null ||
            result.CompletedAtUtc < result.StartedAtUtc || result.Success || result.Actions is null || result.Actions.Count != 0 ||
            result.Errors is null || result.Errors.Count is < 1 or > 128 ||
            result.Errors.Any(error => string.IsNullOrWhiteSpace(error) || error.Length > 8192) ||
            result.VerificationStatus is not (RemediationVerificationStatus.NotChecked or RemediationVerificationStatus.Unknown) ||
            result.ManifestPath is not null || result.VerificationCompletedAtUtc is not null ||
            !string.IsNullOrEmpty(result.VerificationSummary) || result.VerificationSummaryMessage is not null)
            throw MessageExceptions.Create(MessageText.Create("Backend.Core.ProtectedRemediationResultReader.Validate.02"), sourceText => new InvalidDataException(sourceText));

        List<DisplayMessage?>? errorMessages = result.ErrorMessages;
        if (errorMessages is not null && errorMessages.Count != result.Errors.Count)
            throw new InvalidDataException("Invalid result error message descriptors.");
        long displayCharacters = 0;
        foreach (DisplayMessage? message in errorMessages ?? []) displayCharacters += message?.Validate() ?? 0;
        if (displayCharacters > 256 * 1024 || result.Errors.Sum(error => (long)error.Length) > 256 * 1024)
            throw new InvalidDataException("Result display message limit exceeded.");
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
