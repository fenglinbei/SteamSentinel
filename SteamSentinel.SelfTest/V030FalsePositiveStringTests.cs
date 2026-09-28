using System.IO;
using System.IO.Compression;
using System.Text;
using SteamSentinel.Core.Inspection;
using SteamSentinel.Core.Models;
using SteamSentinel.Core.Reporting;
using SteamSentinel.Core.Scanning;

namespace SteamSentinel.SelfTest;

internal static partial class Program
{
    private static async Task TestV030FalsePositiveStringsAsync(string root)
    {
        string directory = Path.Combine(root, "v030-token-observations");
        Directory.CreateDirectory(directory);
        const string resources = "{\"url_format\":\"https://\",\"utility_name\":\"rundll32\",\"ui_key\":\"captcha\",\"password\":\"private-fixture-value\"}";
        string library = Path.Combine(directory, "ordinary-resources.dll");
        await File.WriteAllBytesAsync(library, [.. CreateV0117PeHeader(), .. Encoding.UTF8.GetBytes(resources)]);
        ScanReport simple = await ScanV030FormatFixtureAsync(library, new RuleSet());
        Finding weak = simple.Findings.First(f => f.RuleId == "HEUR-SCRIPT-TOKEN-COOCCURRENCE" && f.ContentPath == library);
        Check("0.3.0 普通资源词共现只产生中等复核项", weak.Severity == FindingSeverity.Medium && weak.Score == 40 &&
            weak.ReasonCode == "ScriptTokenCooccurrenceOnly" && weak.HandlingReason == FindingHandlingReason.InsufficientEvidence &&
            !weak.CanRemediate && !weak.IsKnownMalware && weak.SuggestedActions.SequenceEqual([SuggestedActionKind.ReviewOnly]));
        Check("0.3.0 共现不生成高风险或已加载恶意模块结论", simple.Findings.All(f => f.Severity < FindingSeverity.High && !f.CanRemediate));
        Check("0.3.0 共现证据只保留固定词及窗口信息不含原文秘密", weak.Evidence.Contains("UTF-8") && weak.Evidence.Contains("rundll32") &&
            !weak.Evidence.Contains("private-fixture-value") && weak.Evidence.Length < 8192 && weak.TargetSha256?.Length == 64);
        using (DisplayText.UseCulture(DisplayText.English))
            Check("0.3.0 共现原因保持机器码且英文准确区分字符串与行为", weak.ReasonCode == "ScriptTokenCooccurrenceOnly" &&
                weak.DescriptionText.Display.Contains("does not establish an execution chain") && weak.EvidenceDisplay.Contains("decoding window"));
        using (DisplayText.UseCulture(DisplayText.Chinese))
            Check("0.3.0 共现中文说明不再声称恶意行为", weak.DescriptionText.Display.Contains("不能据此确认执行链") && weak.EvidenceDisplay.Contains("窗口起始字节"));

        string separated = Path.Combine(directory, "separated.dat");
        await using (FileStream file = new(separated, FileMode.CreateNew))
        {
            file.SetLength(4 * 1024 * 1024);
            await file.WriteAsync("https://"u8.ToArray());
            file.Position = 2 * 1024 * 1024;
            await file.WriteAsync(Encoding.Unicode.GetBytes("rundll32"));
            file.Position = 3 * 1024 * 1024;
            await file.WriteAsync(Encoding.BigEndianUnicode.GetBytes("captcha"));
        }
        ScanReport distributed = await ScanV030FormatFixtureAsync(separated, new RuleSet());
        Check("0.3.0 跨大文件混合编码的词仍被保留但不能隔离", distributed.Findings.Any(f => f.RuleId == weak.RuleId &&
            f.ReasonCode == weak.ReasonCode && !f.CanRemediate && f.Evidence.Contains("UTF-16LE") && f.Evidence.Contains("UTF-16BE")));
        await using (FileStream input = File.OpenRead(separated))
        {
            var signals = await StreamingStringInspection.ReadAsync(input, [], [], input.Length, default);
            Check("0.3.0 词位置证据有界并保存不同的源窗口", signals.Observations.Count <= ScriptSignals.Tokens.Length &&
                signals.Observations.Single(o => o.Token == "https://").WindowByteOffset == 0 &&
                signals.Observations.Single(o => o.Token == "captcha").WindowByteOffset > 2 * 1024 * 1024);
        }
        string encoded = "powershell -enc " + Convert.ToBase64String(Encoding.Unicode.GetBytes("https:// rundll32 captcha"));
        using (MemoryStream input = new(Encoding.UTF8.GetBytes(encoded)))
        {
            var signals = await StreamingStringInspection.ReadAsync(input, [], [], input.Length, default);
            Check("0.3.0 编码文本观察注明规范化且不声称精确字节位置", signals.Observations.Count == 3 && signals.Observations.All(o => o.Normalized));
        }
        string markdown = Path.Combine(directory, "notes.md");
        await File.WriteAllTextAsync(markdown, resources);
        ScanReport notes = await ScanV030FormatFixtureAsync(markdown, new RuleSet());
        Check("0.3.0 文档中的通用示例继续不报警", notes.Findings.All(f => f.RuleId != weak.RuleId));

        string archive = Path.Combine(directory, "resource-package.zip");
        using (ZipArchive zip = ZipFile.Open(archive, ZipArchiveMode.Create))
        {
            using StreamWriter writer = new(zip.CreateEntry("component.dll").Open());
            writer.Write(resources);
        }
        ScanReport container = await new ScanCoordinator(new RuleSet()).RunAsync(new ScanOptions
        {
            Mode = ScanMode.Custom, IncludeSystem = false, IncludeSteam = false, IncludeWorkshop = false,
            UseAmsi = false, InspectArchives = true, InspectDeepSignatures = false, CustomRoots = [archive]
        });
        Check("0.3.0 容器成员仅词共现不能授权外层隔离", container.Findings.Any(f => f.RuleId == weak.RuleId) &&
            container.Findings.All(f => !f.CanRemediate));

        string[] strong = ["steam://open/supportalert SupportMessages HelpFrontPage steamhelper bSupportPopupMessage",
            "SteamKey20260310 CryptUnprotectData steam.exe /downloadlog/",
            "steam_save_mafile steam_outbox_list password proconnector.cfd"];
        string[] ids = ["HEUR-STEAM-UI-PATCHER", "HEUR-STEAM-TOKEN-STEALER", "HEUR-STEAM-CREDENTIAL-PLUGIN"];
        for (int i = 0; i < strong.Length; i++)
        {
            string path = Path.Combine(directory, $"specific-{i}.dat");
            await File.WriteAllTextAsync(path, strong[i]);
            ScanReport report = await ScanV030FormatFixtureAsync(path, new RuleSet());
            Check($"0.3.0 专用组合特征 {ids[i]} 保留处置", report.Findings.Any(f => f.RuleId == ids[i] && f.CanRemediate && f.Severity == FindingSeverity.High));
        }
    }
}
