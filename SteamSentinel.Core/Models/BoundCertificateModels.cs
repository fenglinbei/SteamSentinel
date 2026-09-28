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
[method: System.Text.Json.Serialization.JsonConstructor]
public sealed record BoundCertificateProbe(BoundCertificateProbeStatus Status, string Detail)
{
    [System.Text.Json.Serialization.JsonIgnore(Condition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull)]
    public SteamSentinel.Core.Models.DisplayMessage? DetailMessage { get => SteamSentinel.Core.Reporting.MessageText.BoundDescriptor(field, Detail); init => field = value; }

    [System.Text.Json.Serialization.JsonIgnore]
    public SteamSentinel.Core.Reporting.MessageText DetailText
    {
        get => new(Detail ?? string.Empty, DetailMessage);
        init
        {
            Detail = value.OriginalText;
            DetailMessage = value.Message;
        }
    }

    public BoundCertificateProbe(BoundCertificateProbeStatus Status, SteamSentinel.Core.Reporting.MessageText Detail) : this(Status, Detail.OriginalText)
    {
        DetailMessage = Detail.Message;
    }
}
