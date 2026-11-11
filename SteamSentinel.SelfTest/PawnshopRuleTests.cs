using SteamSentinel.Core.Models;
using SteamSentinel.Core.Rules;

namespace SteamSentinel.SelfTest;

internal static partial class Program
{
    private static void TestPawnshopExactRules()
    {
        RuleSet rules = RuleLoader.LoadEmbedded();
        (string Id, string Sha256)[] components =
        [
            ("STEAMALERT-MOD-LOADER", "20510416665705F7D3B55DE60F22B6072295B8A5BFB51139FE972E916B53F272"),
            ("STEAMALERT-RESIDENT", "86E0D69C3F7A0B376D88BFDF9DBEFDDA314541A8389FB66E399E4DD2A06C290B"),
            ("STEAMALERT-CORE", "3CDD5D6ED2F62AD76EAF1CBCDFBD840CDFC12ED990F66FFD841B323D89ACB211")
        ];
        foreach ((string id, string sha256) in components)
        {
            Check("深空当铺精确组件规则 " + id, rules.KnownHashes.Any(rule =>
                rule.Id == id && rule.Sha256 == sha256 && rule.Malware && rule.Severity == FindingSeverity.Critical &&
                rule.LabelMessage?.MessageId == $"Rule.{id}.label" && rule.EvidenceMessage?.MessageId == $"Rule.{id}.evidence"));
        }

        string[] controls =
        [
            "325DF02F40B0B48E73D0E238E5FC30B86FC2116EC42CD197AD42EAD57FB4FBDB", // DailyCheckin.dll
            "5D37C9347235A3772CC83CA6A6D1E26D9017287055391011561757ADCDDEA162", // SpeedUp.Mono.dll
            "411FFC1C8E0FDEDC6F1ECC1C81A989F29DEBB6583CD5CA25E784DBB4F9569CC7"  // Incident evidence archive
        ];
        Check("深空当铺同包其他插件与证据包整体不作为已知恶意哈希",
            !rules.KnownHashes.Any(rule => rule.Malware && controls.Contains(rule.Sha256, StringComparer.OrdinalIgnoreCase)));
    }
}
