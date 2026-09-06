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
            throw new InvalidDataException("配置处置规则缺少已核验的精确身份或证据来源。");
    }

    public int Count => _rules.Length;
    public const string MissingEvidenceMessage = "尚无经样本或受控实验确认的精确配置处置规则；PAC、证书名称、自签状态与同机文件不能单独授权修复。";

    public BoundConfigurationEvidenceRule Authorize(RemediationAction action)
    {
        if (action.Type == RemediationActionType.RemoveBoundCertificate && action.BoundCertificate is { } certificate)
            _ = BoundCertificateRepair.ValidateTarget(certificate, requireProperties: true);
        else if (action.Type == RemediationActionType.RestoreBoundProxyConfiguration && action.BoundProxy is { } proxy)
            BoundProxyRepair.ValidateTarget(proxy);
        string identity = IdentityFingerprint(action);
        BoundConfigurationEvidenceRule? rule = _rules.FirstOrDefault(r => r.Id == action.ConfigurationEvidenceRuleId &&
            r.ActionType == action.Type && r.TargetIdentitySha256.Equals(identity, StringComparison.OrdinalIgnoreCase));
        if (rule is null) throw new UnauthorizedAccessException(MissingEvidenceMessage);
        if (rule.ConfirmedWriterSha256 is { } writer &&
            (!writer.Equals(action.RelatedFileSha256, StringComparison.OrdinalIgnoreCase) ||
             string.IsNullOrWhiteSpace(action.RelatedFilePath) || !Path.IsPathFullyQualified(action.RelatedFilePath)))
            throw new UnauthorizedAccessException("配置处置缺少规则绑定的已确认写入组件。");
        if (rule.ConfirmedWriterSha256 is null && (action.RelatedFilePath is not null || action.RelatedFileSha256 is not null))
            throw new UnauthorizedAccessException("此规则没有确认写入来源，不能用客户端关联字段声明写入者。");
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
            // User identity is checked against the process token separately; it is not a malware indicator.
            if (node is JsonObject obj)
                foreach (string key in obj.Select(p => p.Key).Where(k => k.Equals("TargetUserSid", StringComparison.OrdinalIgnoreCase)).ToArray()) obj.Remove(key);
        }
        else throw new InvalidDataException("专用配置动作缺少唯一的类型化目标。");
        string canonical = Canonical(node);
        if (Encoding.UTF8.GetByteCount(canonical) > 96 * 1024) throw new InvalidDataException("配置目标超过上限。");
        return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(action.Type + "\n" + canonical)));
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
        if (configurations.Length is < 1 or > 16) throw new InvalidDataException("每批精确配置处置限定 1 至 16 项。");
        List<RemediationAction> actions = (prerequisites ?? []).Take(65).ToList();
        if (actions.Any(a => a.Type is RemediationActionType.RollbackIncident or RemediationActionType.DeleteIncident || a.BoundCertificate is not null || a.BoundProxy is not null))
            throw new InvalidDataException("配置前置动作不能嵌套生命周期或配置处置。");
        foreach (RemediationAction action in configurations) catalog.Authorize(action);
        actions.AddRange(configurations);
        RemediationDependencies.AssignAndOrder(actions);
        RemediationPlan plan = new() { Actions = actions };
        if (JsonSerializer.SerializeToUtf8Bytes(plan, JsonFile.Options).Length > 1024 * 1024)
            throw new InvalidDataException("精确配置计划超过 1 MiB，未截断目标或拆分关联链。");
        return plan;
    }
}
