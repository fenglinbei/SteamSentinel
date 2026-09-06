namespace SteamSentinel.Core.Models;

public enum ContainerRangeType { Unknown, Mp4, PeImage, PeCertificateTable, Zip, Rar4, Rar5, SfxConfiguration }
public enum ContainerRangeStatus
{
    Unknown, Validated, ValidatedContainerHeader, Malformed, Unsupported, LimitReached, Cancelled
}

/// <summary>All offsets refer to the supplied seekable stream, never a guessed original-file offset.</summary>
public sealed class ContainerRange
{
    public long Offset { get; init; }
    public long Length { get; init; }
    public ContainerRangeType Type { get; init; }
    public ContainerRangeStatus Status { get; init; }
    public bool LengthIsExact { get; init; }
    public bool NeedsPassword { get; init; }
    public string Detail { get; init; } = string.Empty;
}

public sealed class ContainerRangeInspection
{
    public long FileLength { get; init; }
    public ContainerRangeType ContainerType { get; set; }
    public ContainerRangeStatus Status { get; set; } = ContainerRangeStatus.Unknown;
    public long LastContainerBoundary { get; set; }
    public long BytesRead { get; set; }
    public List<ContainerRange> Ranges { get; init; } = [];
    public List<ContainerRange> UnknownRanges { get; init; } = [];
    public List<ContainerRangeCheck> Checks { get; init; } = [];
    public List<ContainerRangeSfxDirective> SfxConfiguration { get; init; } = [];
    public string Detail { get; set; } = string.Empty;
}

public sealed class ContainerRangeCheck
{
    public long Offset { get; init; }
    public ContainerRangeStatus Status { get; init; }
    public string Detail { get; init; } = string.Empty;
}

public sealed class ContainerRangeRarInspection
{
    public int Version { get; set; }
    public long Offset { get; init; }
    public long AvailableLength { get; init; }
    public long? Length { get; set; }
    public long? EndOffset { get; set; }
    public ContainerRangeStatus Status { get; set; } = ContainerRangeStatus.Unknown;
    public bool HeaderIntegrityVerified { get; set; }
    public bool HasEndMarker { get; set; }
    public bool HeaderEncrypted { get; set; }
    /// <summary>Observed in readable file-header encryption extra fields; false does not inspect encrypted archive headers.</summary>
    public bool HasEncryptedFileHeaders { get; set; }
    public bool HasHashMacFileHeaders { get; set; }
    public bool NeedsPassword => HeaderEncrypted || HasEncryptedFileHeaders;
    public bool IsMultiVolume { get; set; }
    public bool? IsFirstVolume { get; set; }
    /// <summary>Native zero-based volume number, when explicitly recorded.</summary>
    public long? VolumeNumber { get; set; }
    public bool? ExpectsNextVolume { get; set; }
    public bool? FirstFileSplitBefore { get; set; }
    public bool? LastFileSplitAfter { get; set; }
    public int FileHeaderCount { get; set; }
    public long BytesRead { get; set; }
    public string Detail { get; set; } = string.Empty;
    public List<ContainerRangeSfxDirective> SfxConfiguration { get; init; } = [];
}

/// <summary>Static archive-comment text only; never an instruction to start a command.</summary>
public sealed class ContainerRangeSfxDirective
{
    public string Name { get; init; } = string.Empty;
    public string Value { get; init; } = string.Empty;
    public long? Offset { get; init; }
    public string Source { get; init; } = string.Empty;
}

public sealed class ContainerRangeLimits
{
    public long MaximumReadBytes { get; init; } = 32L * 1024 * 1024;
    public int MaximumSignatureSearchBytes { get; init; } = 4 * 1024 * 1024;
    public int MaximumCandidates { get; init; } = 128;
    public int MaximumRecords { get; init; } = 100_000;
    public int MaximumZipEntries { get; init; } = 100_000;
    public int MaximumHeaderBytes { get; init; } = 2 * 1024 * 1024;
    public int MaximumSfxConfigurationBytes { get; init; } = 256 * 1024;
    public TimeSpan MaximumDuration { get; init; } = TimeSpan.FromSeconds(15);
}
