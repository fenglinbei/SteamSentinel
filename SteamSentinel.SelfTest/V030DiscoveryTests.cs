using System.IO;
using System.Text;
using SteamSentinel.Core.Models;
using SteamSentinel.Core.Rules;
using SteamSentinel.Core.Scanning;
using SteamSentinel.Core.Steam;
using SteamSentinel.Core.Utilities;

namespace SteamSentinel.SelfTest;

internal static partial class Program
{
    private static async Task TestV030DiscoveryAsync(string root)
    {
        RuleSet embedded = RuleLoader.LoadEmbedded();
        HashRule[] variant = embedded.KnownHashes.Where(r => r.Id.StartsWith("STEAMRED-VPET-", StringComparison.Ordinal)).ToArray();
        Check("0.3 精确规则包含三包十二核心组件且均为确认身份", variant.Length == 15 && variant.All(r => r.Malware && r.Evidence is { Length: > 0 }) &&
            variant.Count(r => r.Id.Contains("ARCHIVE", StringComparison.Ordinal)) == 3 && embedded.Version == "2026.09.20.1");
        string[] normalHashes =
        [
            "F24670CC98DB50C3440F22F1B21B2F2A0744F7EE448A8BF757D4894446210DCC",
            "CCA49B741B584875B9445BD2127E4E7484A9B7FE82A1C3292D0626EC72843444",
            "A6ECE3219045AE74995309007E35CA145EBF6F5B6D47ABF0986E79EB942AA271",
            "F6FD9B861CCE9AD7C18DC6690CDB0E55F7AFC58AF1FD34C03063F4DC59A1C37A",
            "DAC1764CD736BB7D9BBEDD0A36517FA4C7134139F9EB367E5C36A3D01822FE2E"
        ];
        Check("0.3 官方对照 DLL 和未独立确认为恶意的 orig 不加入确认规则", normalHashes.All(h => !embedded.KnownHashes.Any(r => r.Malware && r.Sha256 == h)));
        string[] newDomains = ["bvdpp.top", "skylinemediaworld.top", "ultracloudmarket.top", "advancedwebfactory.top", "fastdigitalcenter.top",
            "veloriquantica.top", "quantumservernode.top", "zentravolix.top", "toralumivent.top", "vexorandria.top", "yywuxfll.top", "ufyyekkl.top",
            "uuyyywuul.top", "llxzpfsj.top", "fwqoop.org", "fufjxzl.org", "fuuewq.org", "vorqube.com", "zentryxful.icu"];
        Check("0.3 十九个新域名保留旧规则并去重", newDomains.All(embedded.KnownDomains.Contains) && embedded.KnownDomains.Contains("luminovastella.top") &&
            embedded.KnownDomains.Count == embedded.KnownDomains.Distinct(StringComparer.OrdinalIgnoreCase).Count());

        string directory = Path.Combine(root, "v030-discovery"), library = Path.Combine(directory, "library");
        string steamapps = Path.Combine(library, "steamapps"), game = Path.Combine(steamapps, "common", "Renamed Pet Installation");
        string mod = Path.Combine(game, "mod", "1000_fixture"), workshop = Path.Combine(steamapps, "workshop", "content", VPetDiscovery.AppId, "123456789");
        Directory.CreateDirectory(Path.Combine(mod, "native")); Directory.CreateDirectory(workshop);
        const string metadata = "vupmod#Fixture Clock:|author#Inert Test:|\nitemid#987654321:|\nplugin#C:/must-not-be-followed:|\n";
        await File.WriteAllTextAsync(Path.Combine(mod, "info.lps"), metadata);
        await File.WriteAllTextAsync(Path.Combine(workshop, "info.lps"), metadata);
        await File.WriteAllTextAsync(Path.Combine(steamapps, "appmanifest_1920960.acf"),
            "\"AppState\" { \"appid\" \"1920960\" \"name\" \"VPet Fixture\" \"installdir\" \"Renamed Pet Installation\" }");
        string unrelated = Path.Combine(steamapps, "common", "VPet", "mod"); Directory.CreateDirectory(unrelated);
        await File.WriteAllTextAsync(Path.Combine(steamapps, "appmanifest_111.acf"),
            "\"AppState\" { \"appid\" \"111\" \"name\" \"VPet\" \"installdir\" \"VPet\" }");
        SteamLayout layout = new(); layout.LibraryRoots.Add(library); ContentDiscovery.Populate(layout);
        Check("0.3 VPet 按 AppID 发现单数 mod 并保留任意安装目录名", layout.ContentRoots.Any(r => r.AppId == VPetDiscovery.AppId && r.Kind == "mod" && r.Path == Path.GetDirectoryName(mod)));
        Check("0.3 VPet 工坊分类与数字条目发现保留", layout.ContentRoots.Any(r => r.AppId == VPetDiscovery.AppId && r.Kind == "workshop" && r.Name == "VPet Simulator"));
        Check("0.3 同名无关游戏不触发 VPet 私有目录适配", !layout.ContentRoots.Any(r => r.Path == unrelated));
        VPetModMetadata normal = VPetDiscovery.ReadMetadata(mod);
        Check("0.3 有界读取 LPS 只取得显示名称与声明 ID", normal.Status == VPetMetadataStatus.Available && normal.Name == "Fixture Clock" && normal.DeclaredWorkshopId == "987654321");
        Check("0.3 VPet 元数据不访问 UNC 或相对目录", VPetDiscovery.ReadMetadata(@"\\example.invalid\share\mod").Status == VPetMetadataStatus.UnsafePath &&
            VPetDiscovery.ReadMetadata("relative-mod").Status == VPetMetadataStatus.UnsafePath);

        string invalid = Path.Combine(directory, "invalid"); Directory.CreateDirectory(invalid);
        string info = Path.Combine(invalid, "info.lps");
        Check("0.3 VPet 缺少元数据与读取失败分开", VPetDiscovery.ReadMetadata(invalid).Status == VPetMetadataStatus.Missing);
        await File.WriteAllTextAsync(info, metadata);
        using (FileStream locked = new(info, FileMode.Open, FileAccess.Read, FileShare.None))
            Check("0.3 VPet 无法读取实际存在的元数据不伪装为缺失", VPetDiscovery.ReadMetadata(invalid).Status == VPetMetadataStatus.Unavailable);
        foreach (string value in new[] { "vupmod#One:|\nvupmod#Two:|", "vupmod#One:|\nitemid#../outside:|", "vupmod#One:|\nitemid#1:|\nitemid#2:|", "vupmod#missing terminator" })
        {
            await File.WriteAllTextAsync(info, value);
            Check("0.3 VPet 拒绝重复或不完整的身份字段", VPetDiscovery.ReadMetadata(invalid).Status == VPetMetadataStatus.Invalid);
        }
        await File.WriteAllBytesAsync(info, [0xff, 0xfe, 0xff]);
        Check("0.3 VPet 拒绝非法 UTF-8 元数据", VPetDiscovery.ReadMetadata(invalid).Status == VPetMetadataStatus.Invalid);
        await File.WriteAllBytesAsync(info, new byte[VPetDiscovery.MaximumMetadataBytes + 1]);
        Check("0.3 VPet 读取前执行字节上限", VPetDiscovery.ReadMetadata(invalid).Status == VPetMetadataStatus.TooLarge);
        string junction = Path.Combine(directory, "junction"); Directory.CreateDirectory(junction);
        try
        {
            V020RecoverySetJunction(junction, mod);
            Check("0.3 VPet 不沿重解析点读取名称", VPetDiscovery.ReadMetadata(junction).Status == VPetMetadataStatus.UnsafePath);
        }
        finally { Directory.Delete(junction); }

        byte[] inert = "SteamSentinel VPet discovery inert content fixture."u8.ToArray();
        string file = Path.Combine(mod, "native", "renamed.dat"), workshopFile = Path.Combine(workshop, "member.dat");
        await File.WriteAllBytesAsync(file, inert); await File.WriteAllBytesAsync(workshopFile, inert);
        RuleSet fixtureRules = new() { KnownHashes = [new() { Id = "VPET-INERT-FIXTURE", Sha256 = Hashing.Sha256Bytes(inert), Label = "inert test", Malware = true }] };
        ScanReport scanned = await new ScanCoordinator(fixtureRules, layout).RunAsync(new ScanOptions
        {
            Mode = ScanMode.Full,
            IncludeSystem = false,
            IncludeSteam = false,
            IncludeRelatedContent = true,
            IncludeWorkshop = true,
            UseAmsi = false,
            InspectArchives = true
        });
        Finding[] hits = scanned.Findings.Where(f => f.RuleId == "VPET-INERT-FIXTURE").ToArray();
        Check("0.3 VPet 实际扫描覆盖本地 native 与工坊副本", hits.Length == 2 && hits.All(f => f.AppId == VPetDiscovery.AppId) &&
            hits.Any(f => f.SourceKind == "mod" && f.Target == file) && hits.Any(f => f.SourceKind == "workshop" && f.Target == workshopFile));
        Check("0.3 声明工坊编号不替代实际目录归属", hits.Single(f => f.SourceKind == "mod").WorkshopId is null &&
            hits.Single(f => f.SourceKind == "workshop").WorkshopId == "123456789" && scanned.ContentSources.Any(s => s.Contains("未验证订阅归属", StringComparison.Ordinal)));
    }
}
