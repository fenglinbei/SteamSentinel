using SteamSentinel.Core.Reporting;
using SteamSentinel.Core.Models;
using SteamSentinel.Core.Steam;

namespace SteamSentinel.Core.Scanning;

public static class ContainerRequestValidation
{
    public const int MaximumSupplementalDirectories = 32;

    public static void Validate(ScanOptions options, string? requiredRecoveryDirectory = null)
    {
        ArgumentNullException.ThrowIfNull(options);
        if (options.MaximumParallelFiles is < 1 or > 4 || !Enum.IsDefined(options.PerformanceMode))
            throw new InvalidDataException("Invalid scan performance settings.");
        if (options.AllowResourceDecisions && (options.ContainerLimits is null || options.RangeLimits is null))
            throw new InvalidDataException("Interactive scans require explicit effective limits.");
        if (options.MaximumQuickFileBytes < 1 || options.MaximumQuickPriorityBytes < 0 || options.MaximumQuickPriorityFileBytes < 1 ||
            options.MaximumStringScanBytes < 1 || options.MaximumAmsiBytes < 1 || options.MaximumAmsiBytes > Array.MaxLength ||
            options.MaximumWorkerMemoryBytes < 1 || options.MaximumReportRecords is < 1 or > int.MaxValue - 257 ||
            options.MaximumReportTextCharacters < 1 || options.MaximumStructureDurationSeconds is < 1 or > 4294960)
            throw MessageExceptions.Create(MessageText.Create("Backend.Core.ContainerRequestValidation.Validate.01"), sourceText => new InvalidDataException(sourceText));
        if (options.RangeLimits is { } range && (range.MaximumReadBytes < 1 || range.MaximumSignatureSearchBytes < 1 ||
            range.MaximumCandidates < 1 || range.MaximumRecords < 1 || range.MaximumZipEntries < 1 ||
            range.MaximumHeaderBytes < 1 || range.MaximumSfxConfigurationBytes < 1 || range.MaximumDuration <= TimeSpan.Zero))
            throw MessageExceptions.Create(MessageText.Create("Backend.Core.ContainerRequestValidation.Validate.02"), sourceText => new InvalidDataException(sourceText));
        if (options.ContainerLimits is { } limits) ContainerResourceBudget.Validate(limits);
        if (options.SupplementalVolumeDirectories is null || options.SupplementalVolumeDirectories.Count > MaximumSupplementalDirectories ||
            options.SupplementalVolumeDirectories.Any(path => !IsExistingLocalDirectory(path)))
            throw MessageExceptions.Create(MessageText.Create("Backend.Core.ContainerRequestValidation.Validate.03"), sourceText => new InvalidDataException(sourceText));
        if (options.RecoveryOutputDirectory is not { } recovery) return;
        if (!IsExistingLocalDirectory(recovery))
            throw MessageExceptions.Create(MessageText.Create("Backend.Core.ContainerRequestValidation.Validate.04"), sourceText => new InvalidDataException(sourceText));
        if (requiredRecoveryDirectory is not null && !Path.TrimEndingDirectorySeparator(Path.GetFullPath(recovery)).Equals(
            Path.TrimEndingDirectorySeparator(Path.GetFullPath(requiredRecoveryDirectory)), StringComparison.OrdinalIgnoreCase))
            throw MessageExceptions.Create(MessageText.Create("Backend.Core.ContainerRequestValidation.Validate.05"), sourceText => new InvalidDataException(sourceText));
    }

    private static bool IsExistingLocalDirectory(string? path) => path is { Length: > 0 and <= 32768 } &&
        !path.Any(char.IsControl) && Path.IsPathFullyQualified(path) && ContentDiscovery.IsLocalSafePath(path) && Directory.Exists(path);
}
