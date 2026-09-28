using SteamSentinel.Core.Reporting;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using SteamSentinel.Core.Models;
using SteamSentinel.Core.Utilities;

namespace SteamSentinel.Core.Remediation;

public sealed class BoundConfigurationEvidenceRule
{
    public string Id { get; init; } = string.Empty;
    public RemediationActionType ActionType { get; init; }
    public string TargetIdentitySha256 { get; init; } = string.Empty;
    public string SourceArtifactSha256 { get; init; } = string.Empty;
    public string EvidenceReference { get; init; } = string.Empty;
    public string? ConfirmedWriterSha256 { get; init; }
}

/// <summary>Reviewed build-time rules only. Client findings, scores and user-owned case files are not authority.</summary>
public sealed class BoundConfigurationEvidenceCatalog
{
    private readonly BoundConfigurationEvidenceRule[] _rules;
    public static BoundConfigurationEvidenceCatalog Embedded { get; } = new([]);
    // Intentionally empty: the archived screenshots and MSI tables do not prove a removable DER
    // or a safe proxy delta. Add reviewed rules only after a reproducible evidence record exists.
    internal BoundConfigurationEvidenceCatalog(IEnumerable<BoundConfigurationEvidenceRule> rules)
    {
        _rules = rules.ToArray();
        if (_rules.Length > 256 || _rules.Select(r => r.Id).Distinct(StringComparer.Ordinal).Count() != _rules.Length ||
            _rules.Any(r => string.IsNullOrWhiteSpace(r.Id) || r.Id.Length > 128 ||
                !Validation.IsHexSha256(r.TargetIdentitySha256) || !Validation.IsHexSha256(r.SourceArtifactSha256) ||
                string.IsNullOrWhiteSpace(r.EvidenceReference) || r.EvidenceReference.Length > 2048 ||
                r.ActionType is not (RemediationActionType.RemoveBoundCertificate or RemediationActionType.RestoreBoundProxyConfiguration) ||
                r.ConfirmedWriterSha256 is not null && !Validation.IsHexSha256(r.ConfirmedWriterSha256)))
            throw MessageExceptions.Create(MessageText.Create("Backend.Core.BoundConfigurationEvidence.Constructor.01"), sourceText => new InvalidDataException(sourceText));
    }

    public int Count => _rules.Length;
    public static readonly MessageText MissingEvidenceMessage = MessageText.Create("Backend.Core.BoundConfigurationEvidence.MissingEvidenceMessage.01");

    public BoundConfigurationEvidenceRule Authorize(RemediationAction action)
    {
        if (action.Type == RemediationActionType.RemoveBoundCertificate && action.BoundCertificate is { } certificate)
            _ = BoundCertificateRepair.ValidateTarget(certificate, requireProperties: true);
        else if (action.Type == RemediationActionType.RestoreBoundProxyConfiguration && action.BoundProxy is { } proxy)
            BoundProxyRepair.ValidateTarget(proxy);
        string identity = IdentityFingerprint(action);
        BoundConfigurationEvidenceRule? rule = _rules.FirstOrDefault(r => r.Id == action.ConfigurationEvidenceRuleId &&
            r.ActionType == action.Type && r.TargetIdentitySha256.Equals(identity, StringComparison.OrdinalIgnoreCase));
        if (rule is null) throw SteamSentinel.Core.Reporting.MessageExceptions.Create(MissingEvidenceMessage, sourceText => new UnauthorizedAccessException(sourceText));
        if (rule.ConfirmedWriterSha256 is { } writer &&
            (!writer.Equals(action.RelatedFileSha256, StringComparison.OrdinalIgnoreCase) ||
             string.IsNullOrWhiteSpace(action.RelatedFilePath) || !Path.IsPathFullyQualified(action.RelatedFilePath)))
            throw MessageExceptions.Create(MessageText.Create("Backend.Core.BoundConfigurationEvidence.Authorize.01"), sourceText => new UnauthorizedAccessException(sourceText));
        if (rule.ConfirmedWriterSha256 is null && (action.RelatedFilePath is not null || action.RelatedFileSha256 is not null))
            throw MessageExceptions.Create(MessageText.Create("Backend.Core.BoundConfigurationEvidence.Authorize.02"), sourceText => new UnauthorizedAccessException(sourceText));
        return rule;
    }

    public static string IdentityFingerprint(RemediationAction action)
    {
        JsonNode node;
        if (action.Type == RemediationActionType.RemoveBoundCertificate && action.BoundCertificate is { } certificate && action.BoundProxy is null)
            node = JsonSerializer.SerializeToNode(new
            {
                certificate.StoreLocation,
                certificate.StoreName,
                DerSha256 = certificate.DerSha256.ToUpperInvariant()
            }, JsonFile.Options)!;
        else if (action.Type == RemediationActionType.RestoreBoundProxyConfiguration && action.BoundProxy is { } proxy && action.BoundCertificate is null)
        {
            node = JsonSerializer.SerializeToNode(proxy, JsonFile.Options)!;
            RemoveProxyDisplayMetadata(node);
            // User identity is checked against the process token separately; it is not a malware indicator.
            if (node is JsonObject obj)
                foreach (string key in obj.Select(p => p.Key).Where(k => k.Equals("TargetUserSid", StringComparison.OrdinalIgnoreCase)).ToArray()) obj.Remove(key);
        }
        else throw MessageExceptions.Create(MessageText.Create("Backend.Core.BoundConfigurationEvidence.IdentityFingerprint.01"), sourceText => new InvalidDataException(sourceText));
        string canonical = Canonical(node);
        if (Encoding.UTF8.GetByteCount(canonical) > 96 * 1024) throw MessageExceptions.Create(MessageText.Create("Backend.Core.BoundConfigurationEvidence.IdentityFingerprint.02"), sourceText => new InvalidDataException(sourceText));
        return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(action.Type + "\n" + canonical)));
    }

    internal static void RemoveProxyDisplayMetadata(JsonNode? node)
    {
        string Name(string name) => JsonFile.Options.PropertyNamingPolicy?.ConvertName(name) ?? name;
        if (node is not JsonObject proxy) return;
        foreach (string snapshot in new[] { nameof(BoundProxyTarget.Before), nameof(BoundProxyTarget.Desired) })
            if (proxy[Name(snapshot)] is JsonObject value && value[Name(nameof(BoundProxySnapshot.PolicyGuard))] is JsonObject guard)
                guard.Remove(Name(nameof(BoundProxyPolicyGuard.DetailMessage)));
    }

    private static string Canonical(JsonNode? node) => node switch
    {
        JsonObject obj => "{" + string.Join(',', obj.OrderBy(p => p.Key, StringComparer.Ordinal).Select(p => JsonSerializer.Serialize(p.Key) + ":" + Canonical(p.Value))) + "}",
        JsonArray array => "[" + string.Join(',', array.Select(Canonical)) + "]",
        null => "null",
        _ => node.ToJsonString()
    };
}

public static class BoundConfigurationPlanBuilder
{
    public static RemediationPlan Build(IEnumerable<RemediationAction> configurationActions,
        IEnumerable<RemediationAction>? prerequisites = null) => Build(configurationActions, prerequisites, BoundConfigurationEvidenceCatalog.Embedded);

    internal static RemediationPlan Build(IEnumerable<RemediationAction> configurationActions,
        IEnumerable<RemediationAction>? prerequisites, BoundConfigurationEvidenceCatalog catalog)
    {
        RemediationAction[] configurations = configurationActions.Take(17).ToArray();
        if (configurations.Length is < 1 or > 16) throw MessageExceptions.Create(MessageText.Create("Backend.Core.BoundConfigurationEvidence.Build.01"), sourceText => new InvalidDataException(sourceText));
        List<RemediationAction> actions = (prerequisites ?? []).Take(65).ToList();
        if (actions.Any(a => a.Type is RemediationActionType.RollbackIncident or RemediationActionType.DeleteIncident || a.BoundCertificate is not null || a.BoundProxy is not null))
            throw MessageExceptions.Create(MessageText.Create("Backend.Core.BoundConfigurationEvidence.Build.02"), sourceText => new InvalidDataException(sourceText));
        foreach (RemediationAction action in configurations) catalog.Authorize(action);
        actions.AddRange(configurations);
        RemediationDependencies.AssignAndOrder(actions);
        RemediationPlan plan = new() { Actions = actions };
        if (JsonSerializer.SerializeToUtf8Bytes(plan, JsonFile.Options).Length > 1024 * 1024)
            throw MessageExceptions.Create(MessageText.Create("Backend.Core.BoundConfigurationEvidence.Build.03"), sourceText => new InvalidDataException(sourceText));
        return plan;
    }
}
