using System.Security.Cryptography;
using SteamSentinel.Core.Inspection;
using SteamSentinel.Core.Models;
using SteamSentinel.Core.Reporting;
using SteamSentinel.Core.Steam;
using SteamSentinel.Core.Scanning;
using SteamSentinel.Core.Utilities;

namespace SteamSentinel.Core.Remediation;

public sealed record SteamScriptRepairSnapshot(string OriginalSha256, string RepairedSha256,
    string FileIdentity, string ParentIdentity);

/// <summary>Read-only preparation of a repair to a currently installed Steam script.</summary>
public static class SteamScriptRepairTarget
{
    public static HashSet<string> SourceHashes(RuleSet rules) => rules.KnownHashes
        .Where(rule => rule.Malware && (SteamAlertInstallation.FamilyRole(rule.Id) is not null || SteamAlertWatchdog.IsFamilyHash(rule.Sha256)))
        .Select(rule => rule.Sha256).ToHashSet(StringComparer.OrdinalIgnoreCase);

    public static void AddSourceDependencies(IReadOnlyList<RemediationAction> actions, RuleSet rules)
    {
        HashSet<string> hashes = SourceHashes(rules);
        foreach (RemediationAction repair in actions.Where(action => action.Type == RemediationActionType.RepairSteamScript))
            foreach (RemediationAction source in actions.Where(action => action.Type != RemediationActionType.RepairSteamScript &&
                (hashes.Contains(action.ExpectedSha256 ?? string.Empty) || hashes.Contains(action.RelatedFileSha256 ?? string.Empty))))
                if (!repair.DependsOnActionIds.Contains(source.ActionId)) repair.DependsOnActionIds.Add(source.ActionId);
    }

    public static bool IsScriptPath(string path, SteamLayout layout) =>
        ContentDiscovery.IsLocalSafePath(path) && Path.GetExtension(path).Equals(".js", StringComparison.OrdinalIgnoreCase) &&
        layout.SteamRoots.Any(root => ContentDiscovery.IsWithin(path, Path.Combine(root, "steamui")) ||
            ContentDiscovery.IsWithin(path, Path.Combine(root, "clientui")));

    public static async Task<SteamScriptRepairSnapshot> CaptureAsync(string path, string? expectedSha256,
        SteamLayout layout, CancellationToken token = default)
    {
        if (!IsScriptPath(path, layout) || !Validation.IsHexSha256(expectedSha256) ||
            !FileScopeSafety.EvaluatePath(path).Allowed)
            throw MessageExceptions.Create(MessageText.Create("SteamScript.InvalidTarget"), text => new InvalidDataException(text));
        string fullPath = Path.GetFullPath(path);
        await using FileStream input = RelatedArtifactReader.Open(fullPath);
        if (input.Length <= 0 || input.Length > SteamScriptRepair.MaximumBytes)
            throw MessageExceptions.Create(MessageText.Create("SteamScript.Unconfirmed"), text => new InvalidDataException(text));
        byte[] original = new byte[checked((int)input.Length)];
        await input.ReadExactlyAsync(original, token);
        string originalHash = Convert.ToHexString(SHA256.HashData(original));
        if (input.ReadByte() != -1 || !originalHash.Equals(expectedSha256, StringComparison.OrdinalIgnoreCase))
            throw MessageExceptions.Create(MessageText.Create("SteamScript.Changed"), text => new InvalidDataException(text));
        if (!SteamScriptRepair.TryRepair(original, out byte[] repaired))
            throw MessageExceptions.Create(MessageText.Create("SteamScript.Unconfirmed"), text => new InvalidDataException(text));
        RelatedArtifactReader.ValidatePath(input.SafeFileHandle, fullPath);
        return new(originalHash, Convert.ToHexString(SHA256.HashData(repaired)),
            FileScopeSafety.CaptureIdentity(fullPath), FileScopeSafety.CaptureIdentity(Path.GetDirectoryName(fullPath)!, true));
    }

    internal static Finding CreateFinding(string path, string originalHash, string repairedHash) => new()
    {
        RuleId = SteamScriptRepair.RuleId,
        Category = FindingCategory.Steam,
        Severity = FindingSeverity.High,
        Score = 95,
        TitleText = MessageText.Create("SteamScript.Title"),
        DescriptionText = MessageText.Create("SteamScript.Description"),
        EvidenceText = MessageText.Create("SteamScript.Evidence", originalHash, repairedHash),
        HandlingDetailsText = MessageText.Create("SteamScript.Handling"),
        Target = path,
        Sha256 = originalHash,
        TargetSha256 = originalHash,
        IsKnownMalware = true,
        CanRemediate = true,
        SuggestedActions = [SuggestedActionKind.RepairSteamScript]
    };
}
