namespace SteamSentinel.Core.Inspection;

public enum ArchiveVolumeFormat { Zip, Rar, SevenZip }
public enum ArchiveVolumeLayout { Single, RarNumbered, RarLegacy, NumericSplit, ZipSpanned }
public enum ArchiveVolumeStatus
{
    Ready, NotArchive, MissingVolume, DuplicateVolume, MixedVolumes, InvalidMetadata,
    UnsupportedLayout, UnsupportedIntegrity, LimitExceeded, Unavailable
}

/// <summary>DisplayName retains the logical archive member directory; PhysicalPath is never inferred from it.</summary>
public sealed record ArchiveVolumeCandidate(string PhysicalPath, string DisplayName, long Offset = 0, long? Length = null);
public sealed record ArchiveVolumeIdentity(string PhysicalPath, string DisplayName, long Length, string Sha256,
    long Offset, long SourceLength, string RangeSha256);
public sealed record ArchiveVolumeLimits
{
    public int MaximumCandidates { get; init; } = 4096;
    public int MaximumVolumes { get; init; } = 128;
    public long MaximumTotalBytes { get; init; } = 8L * 1024 * 1024 * 1024;
    public int MaximumMetadataBytes { get; init; } = 16 * 1024 * 1024;
    public int MaximumEntries { get; init; } = 100000;

    internal void Validate()
    {
        if (MaximumCandidates is < 1 or >= int.MaxValue || MaximumVolumes is < 1 or >= int.MaxValue ||
            MaximumTotalBytes is < 1 or > long.MaxValue - 1048576 ||
            MaximumMetadataBytes is < 1024 or > 64 * 1024 * 1024 || MaximumEntries is < 1 or >= int.MaxValue)
            throw new ArgumentOutOfRangeException(nameof(ArchiveVolumeLimits));
    }
}

/// <summary>Ready establishes a bounded naming group only. OpenAsync must still validate bytes and volume metadata.</summary>
public sealed class ArchiveVolumePlan
{
    public ArchiveVolumeStatus Status { get; }
    public ArchiveVolumeFormat Format { get; }
    public ArchiveVolumeLayout Layout { get; }
    public string GroupKey { get; }
    public IReadOnlyList<ArchiveVolumeCandidate> Members { get; }
    public string Detail { get; }
    public ArchiveVolumeLimits Limits { get; }

    internal ArchiveVolumePlan(ArchiveVolumeStatus status, ArchiveVolumeFormat format, ArchiveVolumeLayout layout,
        string groupKey, IEnumerable<ArchiveVolumeCandidate> members, string detail, ArchiveVolumeLimits limits)
    {
        Status = status; Format = format; Layout = layout; GroupKey = groupKey;
        Members = Array.AsReadOnly(members.ToArray()); Detail = detail; Limits = limits;
    }
}

public sealed class ArchiveVolumeException(ArchiveVolumeStatus reason, string message, Exception? inner = null)
    : IOException(message, inner)
{
    public ArchiveVolumeStatus Reason { get; } = reason;
}

public sealed record ArchiveIntegrityRequirement(bool Supported, bool CheckCrc32, uint ExpectedCrc32,
    long ExpectedLength, bool CanValidatePassword, string Detail);

public static partial class ArchiveIntegrity
{
    public static uint Crc32(ReadOnlySpan<byte> bytes)
    {
        uint crc = uint.MaxValue;
        foreach (byte value in bytes)
        {
            crc ^= value;
            for (int bit = 0; bit < 8; bit++) crc = (crc >> 1) ^ (0xedb88320u & (uint)-(int)(crc & 1));
        }
        return ~crc;
    }

    public static void Complete(ArchiveIntegrityRequirement requirement, long copied, uint actualCrc32)
    {
        if (!requirement.Supported)
            throw new ArchiveVolumeException(ArchiveVolumeStatus.UnsupportedIntegrity, requirement.Detail);
        if (copied != requirement.ExpectedLength)
            throw new ArchiveVolumeException(ArchiveVolumeStatus.InvalidMetadata, "归档成员实际长度与声明不一致。");
        if (requirement.CheckCrc32 && actualCrc32 != requirement.ExpectedCrc32)
            throw new ArchiveVolumeException(ArchiveVolumeStatus.InvalidMetadata, "归档成员 CRC32 校验不匹配。");
    }
}
