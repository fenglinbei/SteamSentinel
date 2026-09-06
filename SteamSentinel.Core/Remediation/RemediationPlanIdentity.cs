using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using SteamSentinel.Core.Models;
using SteamSentinel.Core.Utilities;

namespace SteamSentinel.Core.Remediation;

/// <summary>Versioned complete typed-plan identity, independent of JSON property order and whitespace.</summary>
public static class RemediationPlanIdentity
{
    public static string Fingerprint(RemediationPlan plan)
    {
        ArgumentNullException.ThrowIfNull(plan);
        byte[] serialized = JsonSerializer.SerializeToUtf8Bytes(plan, JsonFile.Options);
        if (serialized.Length > 1024 * 1024) throw new InvalidDataException("完整处置计划身份超过 1 MiB 上限。");
        JsonNode node = JsonNode.Parse(serialized) ?? throw new InvalidDataException("计划身份为空。");
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
