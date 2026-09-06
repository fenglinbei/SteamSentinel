using SteamSentinel.Core.Models;
using SteamSentinel.Core.Steam;

namespace SteamSentinel.Core.Scanning;

public static class ContainerRequestValidation
{
    public const int MaximumSupplementalDirectories = 32;

    public static void Validate(ScanOptions options, string? requiredRecoveryDirectory = null)
    {
        ArgumentNullException.ThrowIfNull(options);
        if (options.MaximumQuickFileBytes < 1 || options.MaximumQuickPriorityBytes < 0 || options.MaximumQuickPriorityFileBytes < 1 ||
            options.MaximumStringScanBytes < 1 || options.MaximumAmsiBytes < 1 || options.MaximumAmsiBytes > Array.MaxLength ||
            options.MaximumWorkerMemoryBytes < 1 || options.MaximumReportRecords is < 1 or > int.MaxValue - 257 ||
            options.MaximumReportTextCharacters < 1 || options.MaximumStructureDurationSeconds is < 1 or > 4294960)
            throw new InvalidDataException("扫描预算必须在数值类型、数组长度和计时器支持范围内。");
        if (options.RangeLimits is { } range && (range.MaximumReadBytes < 1 || range.MaximumSignatureSearchBytes < 1 ||
            range.MaximumCandidates < 1 || range.MaximumRecords < 1 || range.MaximumZipEntries < 1 ||
            range.MaximumHeaderBytes < 1 || range.MaximumSfxConfigurationBytes < 1 || range.MaximumDuration <= TimeSpan.Zero))
            throw new InvalidDataException("容器结构检查预算必须大于零。");
        if (options.ContainerLimits is { } limits) ContainerResourceBudget.Validate(limits);
        if (options.SupplementalVolumeDirectories is null || options.SupplementalVolumeDirectories.Count > MaximumSupplementalDirectories ||
            options.SupplementalVolumeDirectories.Any(path => !IsExistingLocalDirectory(path)))
            throw new InvalidDataException("补充分卷位置必须是数量有限的现有本地完整目录，不能包含网络路径或重解析点。");
        if (options.RecoveryOutputDirectory is not { } recovery) return;
        if (!IsExistingLocalDirectory(recovery))
            throw new InvalidDataException("恢复输出位置必须是现有本地完整目录，不能包含网络路径或重解析点。");
        if (requiredRecoveryDirectory is not null && !Path.TrimEndingDirectorySeparator(Path.GetFullPath(recovery)).Equals(
            Path.TrimEndingDirectorySeparator(Path.GetFullPath(requiredRecoveryDirectory)), StringComparison.OrdinalIgnoreCase))
            throw new InvalidDataException("工作进程只可将恢复内容写入本轮专用临时目录。");
    }

    private static bool IsExistingLocalDirectory(string? path) => path is { Length: > 0 and <= 32768 } &&
        !path.Any(char.IsControl) && Path.IsPathFullyQualified(path) && ContentDiscovery.IsLocalSafePath(path) && Directory.Exists(path);
}
