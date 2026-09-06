namespace SteamSentinel.Core.Models;

public sealed class BoundCertificateTarget
{
    public string TargetUserSid { get; init; } = string.Empty;
    public string StoreLocation { get; init; } = string.Empty;
    public string StoreName { get; init; } = string.Empty;
    public string DerSha256 { get; init; } = string.Empty;
    public string PropertiesSha256 { get; init; } = string.Empty;
}

public sealed class BoundCertificateProperty
{
    public uint Id { get; init; }
    public string ValueBase64 { get; init; } = string.Empty;
}

public sealed class BoundCertificateBackup
{
    public BoundCertificateTarget Target { get; init; } = new();
    public string DerBase64 { get; init; } = string.Empty;
    public List<BoundCertificateProperty> Properties { get; init; } = [];
}

public enum BoundCertificateProbeStatus { Present, Absent, Changed, Unsupported, Unknown }

public sealed record BoundCertificateProbe(BoundCertificateProbeStatus Status, string Detail);
