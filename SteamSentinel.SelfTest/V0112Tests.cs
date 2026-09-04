using System.Buffers.Binary;
using System.IO;
using System.Text;
using SteamSentinel.App;
using SteamSentinel.App.ViewModels;
using SteamSentinel.Core.Inspection;
using SteamSentinel.Core.Models;
using SteamSentinel.Core.Reporting;
using SteamSentinel.Core.Scanning;
using SteamSentinel.Core.Utilities;

namespace SteamSentinel.SelfTest;

internal static partial class Program
{
    private static async Task TestV0112Async(string root)
    {
        string folder = Path.Combine(root, "v0112"); Directory.CreateDirectory(folder);
        string media = Path.Combine(folder, "large.mp4");
        MakeMediaFixture(media, 300L * 1024 * 1024);
        string program = Path.Combine(folder, "payload.mp4");
        await File.WriteAllBytesAsync(program, "MZ harmless signature-only fixture"u8.ToArray());
        string hash = await Hashing.Sha256FileAsync(program);
        RuleSet rules = new() { KnownHashes = { new() { Id = "HARMLESS-FIXTURE", Sha256 = hash, Malware = true, Label = "无害回归规则" } } };
        ScanOptions quick = new() { Mode = ScanMode.Quick, IncludeSystem = false, IncludeSteam = false, IncludeWorkshop = false, UseAmsi = false,
            MaximumContentBytes = 1, InspectArchives = false };
        using ContentScanner scanner = new(rules);
        ScanReport mediaReport = new() { Mode = ScanMode.Quick };
        await scanner.ScanRootAsync(media, mediaReport, quick, new NullPasswordProvider());
        Check("大于 256 MiB 的正常 MP4 仍做结构检查", mediaReport.Metrics.MediaStructuresChecked == 1);
        Check("正常视频不消耗快速整文件哈希预算", mediaReport.Metrics.BytesHashed == 0);
        Check("媒体范围说明不计入威胁严重度与数量", mediaReport.RiskFindingCount == 0 && mediaReport.HighestSeverity == FindingSeverity.Information);
        Check("媒体未做完整比对仍披露 Partial", mediaReport.Coverage == ScanCoverage.Partial &&
            mediaReport.CoverageAggregates.Single() is { RuleId: "QUICK-MEDIA-STRUCTURE", Count: 1 });
        Check("媒体覆盖说明提供完整内容扫描下一步", CoveragePresentation.Groups(mediaReport).Single().NextStep.Contains(CoveragePresentation.FullScanAction));
        ScanReport programReport = new() { Mode = ScanMode.Quick };
        await scanner.ScanRootAsync(program, programReport, quick, new NullPasswordProvider());
        Check("主预算不足时为小型启动文件保留检查预算", programReport.Findings.Any(f => f.IsKnownMalware) && programReport.Metrics.QuickPriorityBytesHashed > 0);
        Check("伪装 MP4 的程序不会走正常媒体快路径", programReport.Metrics.MediaStructuresChecked == 0 && programReport.Findings.Any(f => f.RuleId == "CONTENT-EXTENSION-MISMATCH"));

        string overlay = Path.Combine(folder, "overlay.mp4"); MakeMediaFixture(overlay, 300L * 1024 * 1024);
        await using (FileStream append = new(overlay, FileMode.Append)) await append.WriteAsync("MZ harmless tail fixture"u8.ToArray());
        ScanReport overlayReport = new() { Mode = ScanMode.Quick };
        await scanner.ScanRootAsync(overlay, overlayReport, quick, new NullPasswordProvider());
        Check("大视频即使预算不足仍发现尾随可执行内容", overlayReport.Findings.Any(f => f.RuleId == "MP4-TRAILING-DATA" && f.Severity == FindingSeverity.High));
        Check("未展开尾随内容不伪装完整检查", overlayReport.Coverage == ScanCoverage.Partial);

        string small = Path.Combine(folder, "small.mp4"); MakeMediaFixture(small, 128);
        ScanReport full = new() { Mode = ScanMode.Custom };
        await scanner.ScanRootAsync(small, full, new ScanOptions { Mode = ScanMode.Custom, IncludeSystem = false, IncludeSteam = false,
            UseAmsi = false, HashEveryFile = true, MaximumContentBytes = 1024 }, new NullPasswordProvider());
        Check("完整内容补查会计算整个视频哈希", full.Metrics.BytesHashed == 128 && full.Coverage == ScanCoverage.Complete);
        ScanReport scopeReport = await new ScanCoordinator(rules).RunAsync(new ScanOptions { Mode = ScanMode.Custom,
            IncludeSystem = false, IncludeSteam = false, IncludeWorkshop = false, UseAmsi = false, CustomRoots = [small], MaximumContentBytes = 1024 });
        Check("报告预算说明仅记录实际内容阶段", scopeReport.ScopeNotes.Count(n => n.Contains("文件哈希读取预算")) == 1 &&
            scopeReport.ScopeNotes.All(n => !n.StartsWith("系统阶段")));

        ScanReport noise = new() { Mode = ScanMode.Quick, CompletedAtUtc = DateTimeOffset.UtcNow };
        for (int i = 0; i < 6500; i++) noise.Findings.Add(new() { Category = FindingCategory.Coverage, RuleId = "CONTENT-BYTE-BUDGET",
            Target = small, Description = "budget " + i, Severity = FindingSeverity.Medium, Score = 30 });
        Check("六千五百条旧覆盖记录仅汇总为一类", CoveragePresentation.Groups(noise).Single().Count == 6500);
        Check("旧版覆盖记录也不推高风险数量和严重度", noise.RiskFindingCount == 0 && noise.HighestSeverity == FindingSeverity.Information);
        Check("补查目标使用外层路径并去重", MainWindow.CoverageTargets(CoveragePresentation.Groups(noise).Single()).SequenceEqual([small]));
        var encrypted = CoveragePresentation.Describe("ARCHIVE-PASSWORD-FAILED", small, "未解密");
        Check("加密补查说明要求正确密码", encrypted.CanFullScan && encrypted.NextStep.Contains("正确") && encrypted.NextStep.Contains("密码"));
        Check("读取失败不承诺完整扫描自动解决", !CoveragePresentation.Describe("SCAN-PARTIAL", small, "拒绝访问").CanFullScan);
        Check("安全上限不能用完整扫描绕过", !CoveragePresentation.Describe("ARCHIVE-RATIO-LIMIT", small, "压缩比超过上限").CanFullScan);
        Check("缺外层哈希的尾随威胁不可选择隔离", !new FindingItemViewModel(new() { CanRemediate = true, IsKnownMalware = true,
            Target = media, ContentPath = media + "!/<尾随内容>" }).CanSelect);
        noise.Findings.Add(new() { Category = FindingCategory.File, Severity = FindingSeverity.Critical, IsKnownMalware = true, Title = "无害规则" });
        Check("覆盖记录不压制真实威胁", noise.RiskFindingCount == 1 && noise.HighestSeverity == FindingSeverity.Critical);
        string output = Path.Combine(folder, "report.md"); await ReportExporter.ExportMarkdownAsync(noise, output);
        string markdown = await File.ReadAllTextAsync(output);
        Check("报告独立列出覆盖分类和补查方式", markdown.Contains("## 未检查内容与补查方式") && markdown.Contains(CoveragePresentation.FullScanAction));
        ScanReport merged = ScanReportMerger.Merge(mediaReport, programReport);
        Check("跨 Worker 合并保留媒体与优先预算指标", merged.Metrics.MediaStructuresChecked == 1 && merged.Metrics.QuickPriorityBytesHashed > 0);
        byte[] overflow = new byte[16]; BinaryPrimitives.WriteUInt32BigEndian(overflow, 1); "ftyp"u8.CopyTo(overflow.AsSpan(4));
        BinaryPrimitives.WriteUInt64BigEndian(overflow.AsSpan(8), ulong.MaxValue);
        Check("畸形 MP4 扩展长度不导致扫描崩溃", !(await Mp4Inspector.InspectAsync(new MemoryStream(overflow))).IsStructurallyValid);
    }

    private static void MakeMediaFixture(string path, long length)
    {
        using FileStream stream = File.Create(path);
        byte[] header = new byte[24];
        BinaryPrimitives.WriteUInt32BigEndian(header, 16); "ftyp"u8.CopyTo(header.AsSpan(4)); "isom"u8.CopyTo(header.AsSpan(8));
        BinaryPrimitives.WriteUInt32BigEndian(header.AsSpan(16), checked((uint)(length - 16))); "mdat"u8.CopyTo(header.AsSpan(20));
        stream.Write(header); stream.SetLength(length);
    }
}
