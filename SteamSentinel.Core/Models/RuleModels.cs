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

public sealed class HashRule
{
    public string Id { get; init; } = string.Empty;
    public string Sha256 { get; init; } = string.Empty;
    public string Label { get; init; } = string.Empty;
    public FindingSeverity Severity { get; init; } = FindingSeverity.Critical;
    public bool Malware { get; init; } = true;
}

public sealed class StringRule
{
    public string Id { get; init; } = string.Empty;
    public string Value { get; init; } = string.Empty;
    public int Score { get; init; }
    public string Label { get; init; } = string.Empty;
}
