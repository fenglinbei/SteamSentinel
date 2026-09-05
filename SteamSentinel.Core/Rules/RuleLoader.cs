using System.Reflection;
using System.Text.Json;
using System.Text.Json.Serialization;
using SteamSentinel.Core.Models;

namespace SteamSentinel.Core.Rules;

public static class RuleLoader
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNameCaseInsensitive = true,
        Converters = { new JsonStringEnumConverter() }
    };

    public static RuleSet LoadEmbedded()
    {
        Assembly assembly = typeof(RuleLoader).Assembly;
        string resourceName = assembly.GetManifestResourceNames()
            .Single(name => name.EndsWith("default-rules.json", StringComparison.Ordinal));

        using Stream stream = assembly.GetManifestResourceStream(resourceName)
            ?? throw new InvalidOperationException("无法读取内置规则。");

        RuleSet rules = JsonSerializer.Deserialize<RuleSet>(stream, JsonOptions)
            ?? throw new InvalidOperationException("内置规则格式无效。");
        Validate(rules);
        return rules;
    }

    public static void Validate(RuleSet rules)
    {
        ArgumentNullException.ThrowIfNull(rules);
        if (rules.SchemaVersion != "1")
        {
            throw new InvalidDataException($"不支持的规则架构版本：{rules.SchemaVersion}");
        }

        if (string.IsNullOrWhiteSpace(rules.Version) || rules.Version.Length > 128)
            throw new InvalidDataException("规则版本为空或过长。");
        RequireCollection(rules.KnownHashes, nameof(rules.KnownHashes));
        RequireCollection(rules.KnownDomains, nameof(rules.KnownDomains));
        RequireCollection(rules.KnownProcessNames, nameof(rules.KnownProcessNames));
        RequireCollection(rules.KnownRunValueNames, nameof(rules.KnownRunValueNames));
        RequireCollection(rules.KnownTaskNames, nameof(rules.KnownTaskNames));
        RequireCollection(rules.KnownPathTemplates, nameof(rules.KnownPathTemplates));
        RequireCollection(rules.SuspiciousStrings, nameof(rules.SuspiciousStrings));
        RequireCollection(rules.SteamInjectionNames, nameof(rules.SteamInjectionNames));
        RequireCollection(rules.DangerousExtensions, nameof(rules.DangerousExtensions));
        RequireCollection(rules.ArchiveExtensions, nameof(rules.ArchiveExtensions));

        HashSet<string> ids = new(StringComparer.OrdinalIgnoreCase);
        HashSet<string> hashes = new(StringComparer.OrdinalIgnoreCase);
        foreach (HashRule rule in rules.KnownHashes)
        {
            if (rule is null || !ValidText(rule.Id, 128) || !ids.Add(rule.Id) ||
                !hashes.Add(rule.Sha256) || !Utilities.Validation.IsHexSha256(rule.Sha256) ||
                !ValidText(rule.Label, 512) || !Enum.IsDefined(rule.Severity) ||
                rule.Evidence is { Length: > 4096 })
            {
                throw new InvalidDataException($"无效或重复的哈希规则：{rule?.Id ?? "<null>"}");
            }
        }

        HashSet<string> domains = new(StringComparer.OrdinalIgnoreCase);
        foreach (string domain in rules.KnownDomains)
        {
            if (!ValidText(domain, 253) || !domains.Add(domain) || !Utilities.Validation.IsSafeDomain(domain))
            {
                throw new InvalidDataException($"无效域名规则：{domain}");
            }
        }

        foreach (StringRule rule in rules.SuspiciousStrings)
        {
            if (rule is null || !ValidText(rule.Id, 128) || !ids.Add(rule.Id) ||
                !ValidText(rule.Value, 4096) || !ValidText(rule.Label, 512) || rule.Score is < 1 or > 100)
                throw new InvalidDataException($"无效或重复的字符串规则：{rule?.Id ?? "<null>"}");
        }

        ValidateTextList(rules.KnownProcessNames, nameof(rules.KnownProcessNames), 260);
        ValidateTextList(rules.KnownRunValueNames, nameof(rules.KnownRunValueNames), 512);
        ValidateTextList(rules.KnownTaskNames, nameof(rules.KnownTaskNames), 512);
        ValidateTextList(rules.KnownPathTemplates, nameof(rules.KnownPathTemplates), 1024);
        ValidateTextList(rules.SteamInjectionNames, nameof(rules.SteamInjectionNames), 260);
        ValidateExtensions(rules.DangerousExtensions, nameof(rules.DangerousExtensions));
        ValidateExtensions(rules.ArchiveExtensions, nameof(rules.ArchiveExtensions));
    }

    private static void RequireCollection<T>(ICollection<T>? collection, string name)
    {
        if (collection is null || collection.Count > 100_000)
            throw new InvalidDataException($"规则集合为空或超过数量上限：{name}");
    }

    private static void ValidateTextList(IEnumerable<string> values, string name, int maximumLength)
    {
        HashSet<string> seen = new(StringComparer.OrdinalIgnoreCase);
        foreach (string value in values)
            if (!ValidText(value, maximumLength) || value.Any(char.IsControl) || !seen.Add(value))
                throw new InvalidDataException($"规则集合包含空值、重复项或非法文本：{name}");
    }

    private static void ValidateExtensions(IEnumerable<string> values, string name)
    {
        HashSet<string> seen = new(StringComparer.OrdinalIgnoreCase);
        foreach (string value in values)
            if (!ValidText(value, 32) || value[0] != '.' ||
                value.Skip(1).Any(character => !char.IsAsciiLetterOrDigit(character)) || !seen.Add(value))
                throw new InvalidDataException($"扩展名规则无效或重复：{name}");
    }

    private static bool ValidText(string? value, int maximumLength) =>
        !string.IsNullOrWhiteSpace(value) && value.Length <= maximumLength;
}
