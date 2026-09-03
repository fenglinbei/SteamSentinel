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
        if (rules.SchemaVersion != "1")
        {
            throw new InvalidDataException($"不支持的规则架构版本：{rules.SchemaVersion}");
        }

        HashSet<string> ids = new(StringComparer.OrdinalIgnoreCase);
        foreach (HashRule rule in rules.KnownHashes)
        {
            if (!ids.Add(rule.Id) || rule.Sha256.Length != 64 ||
                !rule.Sha256.All(Uri.IsHexDigit))
            {
                throw new InvalidDataException($"无效的哈希规则：{rule.Id}");
            }
        }

        foreach (string domain in rules.KnownDomains)
        {
            if (!Utilities.Validation.IsSafeDomain(domain))
            {
                throw new InvalidDataException($"无效域名规则：{domain}");
            }
        }
    }
}
