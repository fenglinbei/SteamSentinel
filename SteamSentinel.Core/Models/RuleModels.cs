namespace SteamSentinel.Core.Models;

public sealed class RuleSet
{
    public string SchemaVersion { get; init; } = "1";
    public string Version { get; init; } = string.Empty;
    public DateTimeOffset PublishedAtUtc { get; init; }
    public List<HashRule> KnownHashes { get; init; } = [];
    public List<string> KnownDomains { get; init; } = [];
    public List<string> KnownProcessNames { get; init; } = [];
    public List<string> KnownRunValueNames { get; init; } = [];
    public List<string> KnownTaskNames { get; init; } = [];
    public List<string> KnownPathTemplates { get; init; } = [];
    public List<StringRule> SuspiciousStrings { get; init; } = [];
    public List<string> SteamInjectionNames { get; init; } = [];
    public List<string> DangerousExtensions { get; init; } = [];
    public List<string> ArchiveExtensions { get; init; } = [];
}

public sealed partial class HashRule
{
    public string Id { get; init; } = string.Empty;
    public string Sha256 { get; init; } = string.Empty;
    public string Label { get; init; } = string.Empty;
    public FindingSeverity Severity { get; init; } = FindingSeverity.Critical;
    public bool Malware { get; init; } = true;
    public bool Remediable { get; init; }
    public string? Evidence { get; init; }
}

public sealed partial class StringRule
{
    public string Id { get; init; } = string.Empty;
    public string Value { get; init; } = string.Empty;
    public int Score { get; init; }
    public string Label { get; init; } = string.Empty;
}

/// <summary>当前生效规则集的来源与摘要元数据。</summary>
public sealed record RuleSetMetadata(
    string Version,
    DateTimeOffset PublishedAtUtc,
    string Source,
    int HashRuleCount,
    int DomainCount,
    string? Notice = null);

/// <summary>包含完整规则集及其来源元数据的只读快照。</summary>
public sealed record ActiveRuleSnapshot(RuleSet Rules, RuleSetMetadata Metadata);

/// <summary>离线签名规则包的明文载荷，仅允许追加兼容规则与 IOC。</summary>
public sealed record RulePackagePayload(
    int SchemaVersion,
    string Product,
    string Version,
    DateTimeOffset PublishedAtUtc,
    DateTimeOffset ExpiresAtUtc,
    string MinimumEngineVersion,
    List<HashRule>? KnownHashes = null,
    List<string>? KnownDomains = null,
    List<string>? KnownProcessNames = null,
    List<string>? KnownRunValueNames = null,
    List<string>? KnownTaskNames = null,
    List<string>? KnownPathTemplates = null,
    List<StringRule>? SuspiciousStrings = null,
    List<string>? SteamInjectionNames = null);

/// <summary>离线签名规则包外层信封（绑定固定 KeyId 与 RSA-PSS/SHA-256 签名）。</summary>
public sealed record RulePackageEnvelope(
    int SchemaVersion,
    string KeyId,
    string PayloadBase64,
    string SignatureBase64);
