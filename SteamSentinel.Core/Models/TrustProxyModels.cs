namespace SteamSentinel.Core.Models;

public enum DiagnosticReadStatus { Complete, NotPresent, NotChecked, AccessDenied, Failed, LimitReached, Cancelled }

/// <summary>Local, read-only observations. These are not remediation authorization or proof of a writer.</summary>
public sealed class TrustProxyDiagnosticReport
{
    public int SchemaVersion { get; init; } = 1;
    public DateTimeOffset StartedAtUtc { get; init; } = DateTimeOffset.UtcNow;
    public DateTimeOffset? CompletedAtUtc { get; set; }
    public string TargetUserSid { get; init; } = string.Empty;
    public List<ProxyConfigurationObservation> Proxies { get; init; } = [];
    public List<CertificateStoreObservation> CertificateStores { get; init; } = [];
    public List<CertificateObservation> Certificates { get; init; } = [];
    public List<DiagnosticRelation> Relations { get; init; } = [];
    public List<DiagnosticCheck> Checks { get; init; } = [];
}

public sealed partial class DiagnosticCheck
{
    public string? CheckCode { get; init; }
    public string Id { get; init; } = Guid.NewGuid().ToString("N");
    public string? ObservationId { get; init; }
    public string Name { get; init; } = string.Empty;
    public DiagnosticReadStatus Status { get; init; }
    public bool Required { get; init; } = true;
    public string Detail { get; init; } = string.Empty;
}

public sealed partial class ProxyConfigurationObservation
{
    public string Id { get; init; } = Guid.NewGuid().ToString("N");
    public string Source { get; init; } = string.Empty;
    public string Scope { get; init; } = string.Empty;
    public string? UserSid { get; init; }
    public string Location { get; init; } = string.Empty;
    public DiagnosticReadStatus Status { get; init; }
    public string Detail { get; init; } = string.Empty;
    public bool? ProxyEnabled { get; init; }
    public bool? AutoDetect { get; init; }
    public string? ProxyServer { get; init; }
    public string? ProxyBypass { get; init; }
    public string? AutoConfigUrl { get; init; }
    [System.Text.Json.Serialization.JsonIgnore(Condition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull)]
    public DisplayMessage? ProxyServerMessage { get => SteamSentinel.Core.Reporting.MessageText.BoundDescriptor(field, ProxyServer); init => field = value; }
    [System.Text.Json.Serialization.JsonIgnore]
    public SteamSentinel.Core.Reporting.MessageText ProxyServerText => new(ProxyServer ?? string.Empty, ProxyServerMessage);
    [System.Text.Json.Serialization.JsonIgnore(Condition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull)]
    public DisplayMessage? ProxyBypassMessage { get => SteamSentinel.Core.Reporting.MessageText.BoundDescriptor(field, ProxyBypass); init => field = value; }
    [System.Text.Json.Serialization.JsonIgnore]
    public SteamSentinel.Core.Reporting.MessageText ProxyBypassText => new(ProxyBypass ?? string.Empty, ProxyBypassMessage);
    [System.Text.Json.Serialization.JsonIgnore(Condition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull)]
    public DisplayMessage? AutoConfigUrlMessage { get => SteamSentinel.Core.Reporting.MessageText.BoundDescriptor(field, AutoConfigUrl); init => field = value; }
    [System.Text.Json.Serialization.JsonIgnore]
    public SteamSentinel.Core.Reporting.MessageText AutoConfigUrlText => new(AutoConfigUrl ?? string.Empty, AutoConfigUrlMessage);
    public List<DiagnosticConfigurationValue> Values { get; init; } = [];
}
[method: System.Text.Json.Serialization.JsonConstructor]
public sealed record DiagnosticConfigurationValue(string Name, string Kind, string? Value, bool Present, string? Sha256 = null, bool Redacted = false, DiagnosticReadStatus ReadStatus = DiagnosticReadStatus.Complete)
{
    [System.Text.Json.Serialization.JsonIgnore(Condition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull)]
    public SteamSentinel.Core.Models.DisplayMessage? ValueMessage { get => SteamSentinel.Core.Reporting.MessageText.BoundDescriptor(field, Value); init => field = value; }

    [System.Text.Json.Serialization.JsonIgnore]
    public SteamSentinel.Core.Reporting.MessageText ValueText
    {
        get => new(Value ?? string.Empty, ValueMessage);
        init
        {
            Value = value.OriginalText;
            ValueMessage = value.Message;
        }
    }

}

public sealed partial class CertificateStoreObservation
{
    public string Id { get; init; } = Guid.NewGuid().ToString("N");
    public string Scope { get; init; } = string.Empty;
    public string StoreName { get; init; } = string.Empty;
    public string Provider { get; init; } = string.Empty;
    public string? UserSid { get; init; }
    public DiagnosticReadStatus Status { get; set; }
    public string Detail { get; set; } = string.Empty;
    public int CertificatesRead { get; set; }
}

public sealed partial class CertificateObservation
{
    public string Id { get; init; } = Guid.NewGuid().ToString("N");
    public string StoreObservationId { get; init; } = string.Empty;
    public string DerSha256 { get; init; } = string.Empty;
    public string Sha1Thumbprint { get; init; } = string.Empty;
    public string DerBase64 { get; init; } = string.Empty;
    public string Subject { get; init; } = string.Empty;
    public string Issuer { get; init; } = string.Empty;
    public DateTimeOffset NotBeforeUtc { get; init; }
    public DateTimeOffset NotAfterUtc { get; init; }
    public bool SubjectEqualsIssuer { get; init; }
    public bool? SelfSignatureVerified { get; init; }
    public bool? IsCertificateAuthority { get; init; }
    public bool? HasPathLengthConstraint { get; init; }
    public int? PathLengthConstraint { get; init; }
    public bool? BasicConstraintsCritical { get; init; }
    public string? KeyUsage { get; init; }
    public List<string> EnhancedKeyUsages { get; init; } = [];
    public DiagnosticReadStatus ChainStatus { get; set; } = DiagnosticReadStatus.NotChecked;
    public string ChainScope { get; set; } = "OfflineSnapshot";
    public List<string> ChainFlags { get; init; } = [];
    public List<string> ChainCertificateSha256 { get; init; } = [];
    public string ChainDetail { get; set; } = string.Empty;
}
[method: System.Text.Json.Serialization.JsonConstructor]
public sealed record DiagnosticRelation(string FromId, string ToId, string Kind, string Evidence)
{
    [System.Text.Json.Serialization.JsonIgnore(Condition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull)]
    public SteamSentinel.Core.Models.DisplayMessage? EvidenceMessage { get => SteamSentinel.Core.Reporting.MessageText.BoundDescriptor(field, Evidence); init => field = value; }

    [System.Text.Json.Serialization.JsonIgnore]
    public SteamSentinel.Core.Reporting.MessageText EvidenceText
    {
        get => new(Evidence ?? string.Empty, EvidenceMessage);
        init
        {
            Evidence = value.OriginalText;
            EvidenceMessage = value.Message;
        }
    }

    public DiagnosticRelation(string FromId, string ToId, string Kind, SteamSentinel.Core.Reporting.MessageText Evidence) : this(FromId, ToId, Kind, Evidence.OriginalText)
    {
        EvidenceMessage = Evidence.Message;
    }
}

public sealed class DiagnosticScanLimits
{
    public int MaximumCertificatesPerStore { get; init; } = 2048;
    public int MaximumCertificateBytes { get; init; } = 128 * 1024;
    public long MaximumTotalCertificateBytes { get; init; } = 16L * 1024 * 1024;
    public int MaximumProxyValueCharacters { get; init; } = 8192;
    public TimeSpan MaximumDuration { get; init; } = TimeSpan.FromSeconds(20);
}

public enum FindingHandlingReason { None, InsufficientEvidence, UnsupportedAction, IncompleteInspection, PrerequisiteNotMet }
public enum FindingDisposition { Actionable, NeedsReview, Unsupported, Blocked, Informational }
