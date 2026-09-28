using SteamSentinel.Core.Models;

namespace SteamSentinel.Core.Inspection;

/// <summary>Informational links only between hashed nodes already observed in this scan root and archive scope.</summary>
internal static class VPetComponentLinks
{
    internal static void Link(IReadOnlyList<ContainerScanNode> nodes, CancellationToken token = default)
    {
        // A display-name collision is not sufficient to identify a member. Ambiguous keys are excluded.
        var index = nodes.Where(n => n.Kind is ContainerNodeKind.File or ContainerNodeKind.ArchiveMember && n.Sha256 is not null)
            .GroupBy(Key, StringComparer.OrdinalIgnoreCase).Where(g => g.Count() == 1)
            .ToDictionary(g => g.Key, g => g.Single(), StringComparer.OrdinalIgnoreCase);
        foreach (ContainerScanNode source in nodes)
        {
            token.ThrowIfCancellationRequested();
            if (source.VPetFamily is not { Status: VPetFamilyStatus.CodeMatched or VPetFamilyStatus.Decoded } family ||
                family.RelatedNames.Count != 2 || !index.TryGetValue(Key(source), out var unique) || unique != source) continue;
            string path = source.DisplayPath.Replace('\\', '/');
            int split = path.LastIndexOf('/');
            if (split < 0) continue;
            string directory = path[..split]; int before = family.RelatedNodeIds.Count;
            if (family.Role == VPetComponentRole.Loader && family.EnvelopeValidated)
            {
                foreach (string name in family.RelatedNames)
                    Add(directory + "/" + name, "VPET-LINK-NATIVE-PAYLOAD", n => n.VPetFamily is
                    { Status: VPetFamilyStatus.Decoded, Role: VPetComponentRole.UiPayload or VPetComponentRole.CredentialPayload });
            }
            else if (family.Role == VPetComponentRole.ManagedWrapper && directory.EndsWith("/plugin", StringComparison.OrdinalIgnoreCase))
            {
                string mod = directory[..^7];
                Add(mod + "/native/" + family.RelatedNames[0], "VPET-LINK-NATIVE-LOADER", n => n.VPetFamily is
                { Status: VPetFamilyStatus.CodeMatched, Role: VPetComponentRole.Loader, EnvelopeValidated: true });
                // The name shows delegation, not that this dependency is clean or usable for restoration.
                Add(directory + "/lib/" + family.RelatedNames[1], "VPET-LINK-UNTRUSTED-ORIGINAL", _ => true);
                Add(directory + "/" + family.RelatedNames[1], "VPET-LINK-UNTRUSTED-ORIGINAL", _ => true);
                Add(mod + "/info.lps", "VPET-LINK-MOD-METADATA", _ => true);
                Add(mod + "/.px_sidecar", "VPET-LINK-SIDECAR-METADATA", _ => true);
            }
            if (family.RelatedNodeIds.Count > before) source.Revision++;

            void Add(string target, string signal, Func<ContainerScanNode, bool> predicate)
            {
                if (!index.TryGetValue(source.ParentId + "|" + target, out ContainerScanNode? match) ||
                    match.NodeId == source.NodeId || !predicate(match) || family.RelatedNodeIds.Contains(match.NodeId)) return;
                family.RelatedNodeIds.Add(match.NodeId);
                if (!family.Signals.Contains(signal)) family.Signals.Add(signal);
            }
        }
        static string Key(ContainerScanNode node) => node.ParentId + "|" + node.DisplayPath.Replace('\\', '/');
    }
}
