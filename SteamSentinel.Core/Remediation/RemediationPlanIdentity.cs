using SteamSentinel.Core.Reporting;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using SteamSentinel.Core.Models;
using SteamSentinel.Core.Utilities;

namespace SteamSentinel.Core.Remediation;

/// <summary>Versioned typed-plan identity, independent of formatting and optional display descriptors.</summary>
public static class RemediationPlanIdentity
{
    public static string Fingerprint(RemediationPlan plan)
    {
        ArgumentNullException.ThrowIfNull(plan);
        byte[] serialized = JsonSerializer.SerializeToUtf8Bytes(plan, JsonFile.Options);
        if (serialized.Length > 1024 * 1024) throw MessageExceptions.Create(MessageText.Create("Backend.Core.RemediationPlanIdentity.Fingerprint.01"), sourceText => new InvalidDataException(sourceText));
        JsonNode node = JsonNode.Parse(serialized) ?? throw MessageExceptions.Create(MessageText.Create("Backend.Core.RemediationPlanIdentity.Fingerprint.02"), sourceText => new InvalidDataException(sourceText));
        string actionsName = JsonFile.Options.PropertyNamingPolicy?.ConvertName(nameof(RemediationPlan.Actions)) ?? nameof(RemediationPlan.Actions);
        string displayName = JsonFile.Options.PropertyNamingPolicy?.ConvertName(nameof(RemediationAction.DisplayNameMessage)) ?? nameof(RemediationAction.DisplayNameMessage);
        if (node is JsonObject root && root[actionsName] is JsonArray actions)
            foreach (JsonObject action in actions.OfType<JsonObject>())
            {
                action.Remove(displayName);
                string proxyName = JsonFile.Options.PropertyNamingPolicy?.ConvertName(nameof(RemediationAction.BoundProxy)) ?? nameof(RemediationAction.BoundProxy);
                BoundConfigurationEvidenceCatalog.RemoveProxyDisplayMetadata(action[proxyName]);
            }
        // The pre-UAC file SHA-256 still binds the complete request bytes. Display descriptors
        // neither identify action targets nor grant execution authority.
        return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes("SteamSentinel.TypedPlan.v1\n" + Canonical(node))));
    }

    private static string Canonical(JsonNode? node) => node switch
    {
        JsonObject obj => "{" + string.Join(',', obj.OrderBy(p => p.Key, StringComparer.Ordinal)
            .Select(p => JsonSerializer.Serialize(p.Key) + ":" + Canonical(p.Value))) + "}",
        JsonArray array => "[" + string.Join(',', array.Select(Canonical)) + "]",
        null => "null",
        _ => node.ToJsonString()
    };
}
