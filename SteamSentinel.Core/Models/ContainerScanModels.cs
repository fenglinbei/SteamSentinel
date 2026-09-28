namespace SteamSentinel.Core.Models;

public enum ContainerNodeKind { File, EmbeddedRange, ArchiveMember, VolumeGroup, UnknownRange }
public enum ContainerStageStatus
{
    NotRequested, Pending, Complete, Partial, PasswordRequired, PasswordFailed, Skipped,
    MissingVolume, MixedVolumes, DuplicateVolume, Corrupt, Unsupported, UnsupportedIntegrity,
    LimitReached, AccessDenied, SourceChanged, Cancelled, Failed
}
public enum ContentSignatureStatus { NotChecked, Valid, NotSigned, HashMismatch, Untrusted, Unavailable, Failed }

public sealed partial class ContainerEngineObservation
{
    public string Engine { get; init; } = string.Empty;
    public ContainerStageStatus Status { get; set; }
    public long? Offset { get; init; }
    public long? Length { get; init; }
    public string Detail { get; set; } = string.Empty;
    public AmsiDiagnosticInfo? AmsiDiagnostics { get; init; }
}

public sealed class ContainerVolumeIdentity
{
    public string OriginalPath { get; init; } = string.Empty;
    public string DisplayName { get; init; } = string.Empty;
    public long Length { get; init; }
    public string Sha256 { get; init; } = string.Empty;
    public bool IsTemporary { get; init; }
}

public sealed partial class ContainerScanNode
{
    public int Revision { get; set; }
    public Guid NodeId { get; init; } = Guid.NewGuid();
    public Guid? ParentId { get; init; }
    public ContainerNodeKind Kind { get; set; }
    public string DisplayPath { get; init; } = string.Empty;
    public string OriginalTarget { get; init; } = string.Empty;
    public string? OriginalTargetSha256 { get; set; }
    public string Format { get; set; } = string.Empty;
    public int Depth { get; init; }
    public long Length { get; set; }
    public long? ParentOffset { get; init; }
    public long? ParentLength { get; init; }
    public string? Sha256 { get; set; }
    public string? VolumeGroupSha256 { get; set; }
    public Guid? ReusedNodeId { get; set; }
    public ContainerStageStatus Recognition { get; set; } = ContainerStageStatus.Pending;
    public ContainerStageStatus DirectoryRead { get; set; } = ContainerStageStatus.NotRequested;
    public ContainerStageStatus Decryption { get; set; } = ContainerStageStatus.NotRequested;
    public ContainerStageStatus Integrity { get; set; } = ContainerStageStatus.Pending;
    public ContainerStageStatus ContentCheck { get; set; } = ContainerStageStatus.Pending;
    public ContainerStageStatus Overall { get; set; } = ContainerStageStatus.Pending;
    public List<ContainerVolumeIdentity> Volumes { get; init; } = [];
    public List<ContainerEngineObservation> Engines { get; init; } = [];
    public VPetFamilyEvidence? VPetFamily { get; set; }
    public List<string> Details { get; init; } = [];
    public ContentSignatureStatus Signature { get; set; } = ContentSignatureStatus.NotChecked;
    public DateTimeOffset? SignatureCheckedAtUtc { get; set; }
    public DateTimeOffset StartedAtUtc { get; init; } = DateTimeOffset.UtcNow;
    public DateTimeOffset? CompletedAtUtc { get; set; }
    public bool RecoveredContentAvailable { get; set; }
    public string? RecoveredContentName { get; set; }
}

public sealed class ContainerResourceSnapshot
{
    public long ReadBytes { get; init; }
    public long DecodedBytes { get; init; }
    public long AcceptedExpandedBytes { get; init; }
    public long RangeCopyBytes { get; init; }
    public long NativeReservedReadBytes { get; init; }
    public long NativeReservedDecodedBytes { get; init; }
    public long CurrentTemporaryBytes { get; init; }
    public long PeakTemporaryBytes { get; init; }
    public long PeakPrivateMemoryBytes { get; init; }
    public long MetadataAttempts { get; init; }
    public int PasswordAttempts { get; init; }
    public long ElapsedMilliseconds { get; init; }
    public string Accounting => "Stream bytes delivered to scanner/decoder, including repeat reads; not operating-system physical I/O.";
}

public sealed partial class ContainerScanReport
{
    public const int MaximumNodes = int.MaxValue - 1;
    public int SchemaVersion { get; init; } = 1;
    public List<ContainerScanNode> Nodes { get; init; } = [];
    public List<ContainerScanRunSummary> Runs { get; init; } = [];
    public ContainerResourceSnapshot Resources { get; set; } = new();
    public ContainerResourceLimits Limits { get; set; } = new();
    public bool Complete { get; set; }
    public string? RecoveryOutputDirectory { get; set; }
    public List<string> Checks { get; init; } = [];
}

public sealed class ContainerResourceLimits
{
    public long MaximumEntryBytes { get; init; } = 8L * 1024 * 1024 * 1024;
    public long MaximumExpandedBytes { get; init; } = 32L * 1024 * 1024 * 1024;
    public long MaximumWorkBytes { get; init; } = 64L * 1024 * 1024 * 1024;
    public long MaximumTemporaryBytes { get; init; } = 16L * 1024 * 1024 * 1024;
    public long ReservedDiskBytes { get; init; } = 1024L * 1024 * 1024;
    public int MaximumDepth { get; init; } = 12;
    public int MaximumEntries { get; init; } = 20_000;
    public int MaximumNodes { get; init; } = 20_000;
    public int MaximumMetadataAttempts { get; init; } = 80_000;
    public int MaximumPasswordAttempts { get; init; } = 512;
    public int MaximumVolumes { get; init; } = 128;
    public int MaximumDirectoryCandidates { get; init; } = 4096;
    public int MaximumDurationSeconds { get; init; } = 1800;
    public double MaximumCompressionRatio { get; init; } = 500;
}
