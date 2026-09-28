using SteamSentinel.Core.Reporting;
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
            ?? throw MessageExceptions.Create(MessageText.Create("Backend.Core.RuleLoader.LoadEmbedded.01"), sourceText => new InvalidOperationException(sourceText));

        RuleSet rules = JsonSerializer.Deserialize<RuleSet>(stream, JsonOptions)
            ?? throw MessageExceptions.Create(MessageText.Create("Backend.Core.RuleLoader.LoadEmbedded.02"), sourceText => new InvalidOperationException(sourceText));
        Validate(rules);
        return rules;
    }

    public static void Validate(RuleSet rules)
    {
        ArgumentNullException.ThrowIfNull(rules);
        if (rules.SchemaVersion != "1")
        {
            throw MessageExceptions.Create(MessageText.Create("Backend.Core.RuleLoader.Validate.01", (rules.SchemaVersion)), sourceText => new InvalidDataException(sourceText));
        }

        if (string.IsNullOrWhiteSpace(rules.Version) || rules.Version.Length > 128)
            throw MessageExceptions.Create(MessageText.Create("Backend.Core.RuleLoader.Validate.02"), sourceText => new InvalidDataException(sourceText));
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
        long displayCharacters = 0;
        foreach (HashRule rule in rules.KnownHashes)
        {
            if (rule is null || !ValidText(rule.Id, 128) || !ids.Add(rule.Id) ||
                !hashes.Add(rule.Sha256) || !Utilities.Validation.IsHexSha256(rule.Sha256) ||
                !ValidText(rule.Label, 512) || !Enum.IsDefined(rule.Severity) ||
                rule.Evidence is { Length: > 4096 })
            {
                throw MessageExceptions.Create(MessageText.Create("Backend.Core.RuleLoader.Validate.03", (rule?.Id ?? "<null>")), sourceText => new InvalidDataException(sourceText));
            }
            displayCharacters += (rule.LabelMessage?.Validate() ?? 0) + (rule.EvidenceMessage?.Validate() ?? 0);
        }

        HashSet<string> domains = new(StringComparer.OrdinalIgnoreCase);
        foreach (string domain in rules.KnownDomains)
        {
            if (!ValidText(domain, 253) || !domains.Add(domain) || !Utilities.Validation.IsSafeDomain(domain))
            {
                throw MessageExceptions.Create(MessageText.Create("Backend.Core.RuleLoader.Validate.04", (domain)), sourceText => new InvalidDataException(sourceText));
            }
        }

        foreach (StringRule rule in rules.SuspiciousStrings)
        {
            if (rule is null || !ValidText(rule.Id, 128) || !ids.Add(rule.Id) ||
                !ValidText(rule.Value, 4096) || !ValidText(rule.Label, 512) || rule.Score is < 1 or > 100)
                throw MessageExceptions.Create(MessageText.Create("Backend.Core.RuleLoader.Validate.05", (rule?.Id ?? "<null>")), sourceText => new InvalidDataException(sourceText));
            displayCharacters += rule.LabelMessage?.Validate() ?? 0;
        }

        if (displayCharacters > 8 * 1024 * 1024) throw new InvalidDataException("Rule display message limit exceeded.");

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
            throw MessageExceptions.Create(MessageText.Create("Backend.Core.RuleLoader.RequireCollection.01", (name)), sourceText => new InvalidDataException(sourceText));
    }

    private static void ValidateTextList(IEnumerable<string> values, string name, int maximumLength)
    {
        HashSet<string> seen = new(StringComparer.OrdinalIgnoreCase);
        foreach (string value in values)
            if (!ValidText(value, maximumLength) || value.Any(char.IsControl) || !seen.Add(value))
                throw MessageExceptions.Create(MessageText.Create("Backend.Core.RuleLoader.ValidateTextList.01", (name)), sourceText => new InvalidDataException(sourceText));
    }

    private static void ValidateExtensions(IEnumerable<string> values, string name)
    {
        HashSet<string> seen = new(StringComparer.OrdinalIgnoreCase);
        foreach (string value in values)
            if (!ValidText(value, 32) || value[0] != '.' ||
                value.Skip(1).Any(character => !char.IsAsciiLetterOrDigit(character)) || !seen.Add(value))
                throw MessageExceptions.Create(MessageText.Create("Backend.Core.RuleLoader.ValidateExtensions.01", (name)), sourceText => new InvalidDataException(sourceText));
    }

    private static bool ValidText(string? value, int maximumLength) =>
        !string.IsNullOrWhiteSpace(value) && value.Length <= maximumLength;
}
