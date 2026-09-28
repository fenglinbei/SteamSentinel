namespace SteamSentinel.Core.Models;

public enum VPetFamilyStatus { CodeMatched, Decoded, Malformed, Unsupported, LimitReached }
public enum VPetComponentRole { Unknown, Loader, UiPayload, CredentialPayload, ManagedWrapper }
public sealed record VPetDecodedRegion(long Rva, long Offset, long Length);

/// <summary>Static evidence only. Neither a path to an extracted executable nor action authorization.</summary>
public sealed class VPetFamilyEvidence
{
    public string DecoderId { get; init; } = "VPET-20260919-1";
    public string ReasonCode { get; set; } = string.Empty;
    public VPetFamilyStatus Status { get; set; }
    public VPetComponentRole Role { get; set; }
    public string SourceSha256 { get; init; } = string.Empty;
    public string? CodeSha256 { get; set; }
    public string? DerivedSha256 { get; set; }
    public long DerivedLength { get; set; }
    public long FooterOffset { get; set; }
    public long FooterLength { get; set; }
    public bool EnvelopeValidated { get; set; }
    public string? ExportModule { get; set; }
    public List<VPetDecodedRegion> Regions { get; init; } = [];
    public List<string> Signals { get; init; } = [];
    public List<string> RelatedNames { get; init; } = [];
    public List<Guid> RelatedNodeIds { get; init; } = [];
}
