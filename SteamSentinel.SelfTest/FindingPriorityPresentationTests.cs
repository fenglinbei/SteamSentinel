using System.IO;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using SteamSentinel.Core.Models;
using SteamSentinel.Core.Reporting;
using SteamSentinel.Core.Scanning;
using SteamSentinel.Core.Utilities;

namespace SteamSentinel.SelfTest;

internal static partial class Program
{
    private static async Task TestFindingPriorityScannerAsync(string root)
    {
        string directory = Path.Combine(root, "finding-priority-scanner");
        Directory.CreateDirectory(directory);
        string path = Path.Combine(directory, "ordinary-archive.dat");
        byte[] entryBytes = Encoding.UTF8.GetBytes("Inert presentation integration fixture. This is plain text.");
        byte[] archiveBytes;
        using (MemoryStream stream = new())
        {
            using (ZipArchive archive = new(stream, ZipArchiveMode.Create, leaveOpen: true))
            using (Stream entry = archive.CreateEntry("ordinary-note.txt").Open())
                entry.Write(entryBytes);
            archiveBytes = stream.ToArray();
        }
        await File.WriteAllBytesAsync(path, archiveBytes);
        ScanOptions options = new()
        {
            Mode = ScanMode.Custom,
            IncludeSystem = false,
            IncludeSteam = false,
            IncludeWorkshop = false,
            UseAmsi = false,
            InspectArchives = true,
            InspectDeepSignatures = false,
            HashEveryFile = true
        };
        ScanReport report = new();
        using (ContentScanner scanner = new(new RuleSet()))
            await scanner.ScanRootAsync(path, report, options, new NullPasswordProvider());
        Finding? mismatch = report.Findings.SingleOrDefault(finding => finding.RuleId == "CONTENT-EXTENSION-MISMATCH");
        await WriteFindingPriorityScanDiagnosticsAsync(directory, "ordinary", report);
        Check("结果优先级集成：真实ZIP改后缀生成40分格式提示", mismatch is
        { Severity: FindingSeverity.Medium, Score: 40, HandlingReason: FindingHandlingReason.None, CanRemediate: false });
        Check("结果优先级集成：扫描器原始格式提示进入参考分组", mismatch is not null &&
            FindingPriorityPresentation.ReferenceFindingIds(report).Contains(mismatch.Id));
        Check("结果优先级集成：ZIP内容确实完成展开检查", report.Containers is { } containers && containers.Nodes.Any(node =>
            node.Kind == ContainerNodeKind.ArchiveMember && node.DisplayPath.EndsWith("ordinary-note.txt", StringComparison.Ordinal)) &&
            report.Findings.All(finding => finding.Category != FindingCategory.Coverage));

        string json = JsonSerializer.Serialize(report, JsonFile.Options);
        ScanReport restored = JsonSerializer.Deserialize<ScanReport>(json, JsonFile.Options)!;
        Check("结果优先级集成：JSON报告往返保持参考分组", mismatch is not null &&
            FindingPriorityPresentation.ReferenceFindingIds(restored).Contains(mismatch.Id));
        restored.Containers = null;
        Check("结果优先级集成：缺少容器图时使用扫描器格式消息参数", mismatch is not null &&
            FindingPriorityPresentation.ReferenceFindingIds(restored).Contains(mismatch.Id));

        // The exact-hash rule below marks only these locally generated plain-text bytes.
        // It tests evidence precedence without using or executing any malicious fixture.
        RuleSet exactRules = new()
        {
            KnownHashes = [new HashRule { Id = "TEST-PRIORITY-INERT-ENTRY-HASH", Label = "Inert entry evidence fixture",
                Sha256 = Convert.ToHexString(SHA256.HashData(entryBytes)), Malware = true, Severity = FindingSeverity.Critical }]
        };
        ScanReport stronger = new();
        using (ContentScanner scanner = new(exactRules))
            await scanner.ScanRootAsync(path, stronger, options, new NullPasswordProvider());
        await WriteFindingPriorityScanDiagnosticsAsync(directory, "stronger", stronger);
        Check("结果优先级集成：压缩包内精确证据关联外层格式提示", stronger.Findings.Any(finding =>
            finding.RuleId == "TEST-PRIORITY-INERT-ENTRY-HASH" && finding.IsKnownMalware &&
            finding.ContentPath?.Contains("!/", StringComparison.Ordinal) == true) &&
            stronger.Findings.Any(finding => finding.RuleId == "CONTENT-EXTENSION-MISMATCH") &&
            FindingPriorityPresentation.ReferenceFindingIds(stronger).Count == 0);
        Check("结果优先级集成：分类没有改变原始报告及测试文件", JsonSerializer.Serialize(report, JsonFile.Options) == json &&
            (await File.ReadAllBytesAsync(path)).AsSpan().SequenceEqual(archiveBytes));
        await TestExplicitRootCoverageScannerAsync(root);
    }

    private static async Task WriteFindingPriorityScanDiagnosticsAsync(string directory, string name, ScanReport report)
    {
        // Keep the actual scanner output for a focused run, including archive preparation
        // errors that can otherwise look like a classification regression in the sandbox.
        string destination = Path.Combine(directory, name + "-report.json");
        await File.WriteAllTextAsync(destination, JsonSerializer.Serialize(report, JsonFile.Options));
        foreach (Finding finding in report.Findings.Where(finding => finding.Category == FindingCategory.Coverage))
            Console.WriteLine($"DIAGNOSTIC finding-priority/{name}: {finding.RuleId}: {finding.DescriptionText.Display} {finding.EvidenceDisplay}");
        if (report.Containers is { } containers)
            foreach (ContainerScanNode node in containers.Nodes.Where(node => node.Overall != ContainerStageStatus.Complete))
                Console.WriteLine($"DIAGNOSTIC finding-priority/{name}: {node.DisplayPath}: {node.Overall}: {string.Join("; ", node.DetailTexts.Select(text => text.Display))}");
    }

    private static void TestFindingPriorityPresentation()
    {
        const string root = @"C:\SteamSentinel-Inert-Presentation-Fixtures\";
        static MessageText Format(string type) => type is "Png" or "Jpeg" or "Gif" or "Pdf" or "JavaScript" or "Unknown"
            ? new(type) : MessageText.Create("Backend.Core.FileTypeDetector.Label." + type + ".01");
        static Finding Mismatch(string path, string type = "Zip", int score = 40, string? id = null,
            string? target = null, FindingSeverity severity = FindingSeverity.Medium) => new()
            {
                Id = id ?? Guid.NewGuid().ToString("N"),
                RuleId = "CONTENT-EXTENSION-MISMATCH",
                Category = FindingCategory.File,
                Severity = severity,
                Score = score,
                Target = target ?? path,
                ContentPath = path,
                SuggestedActions = [SuggestedActionKind.ReviewOnly],
                DescriptionText = MessageText.Create("Backend.Core.ContentScanner.Containers.AddContainerFileFindings.04", ".dat", Format(type))
            };
        static ContainerScanNode Node(string path, string type, string? target = null) => new()
        {
            DisplayPath = path,
            OriginalTarget = target ?? path,
            Format = type,
            Recognition = ContainerStageStatus.Complete,
            Overall = ContainerStageStatus.Complete,
            ContentCheck = ContainerStageStatus.Complete,
            Integrity = ContainerStageStatus.Complete
        };
        static bool IsReference(Finding finding) => FindingPriorityPresentation.ReferenceFindingIds(new() { Findings = [finding] }).Contains(finding.Id);

        Finding zip = Mismatch(root + "archive.dat");
        Check("结果优先级：描述参数中的单纯ZIP格式不符可作为参考", IsReference(zip));
        Check("结果优先级：普通图片与PDF格式不符可作为参考", new[] { "Png", "Jpeg", "Gif", "Pdf" }
            .All(type => IsReference(Mismatch(root + type + ".dat", type))));
        Check("结果优先级：参考分组不以40分阈值决定", IsReference(Mismatch(root + "scoring.dat", score: 60)));
        Check("结果优先级：PE伪装保持重点", !IsReference(Mismatch(root + "program.dat", "PortableExecutable", 65,
            severity: FindingSeverity.High)));
        Check("结果优先级：40分快捷方式和脚本保持重点", new[] { "Shortcut", "PowerShell", "Batch", "JavaScript" }
            .All(type => !IsReference(Mismatch(root + type + ".dat", type))));
        Check("结果优先级：未知格式和升级严重级别保持重点", !IsReference(Mismatch(root + "unknown.dat", "Unknown")) &&
            !IsReference(Mismatch(root + "upgraded.dat", severity: FindingSeverity.High)));

        Finding legacy = new()
        {
            RuleId = "CONTENT-EXTENSION-MISMATCH",
            Category = FindingCategory.File,
            Severity = FindingSeverity.Medium,
            Score = 40,
            Target = root + "legacy.dat",
            Description = "ZIP",
            SuggestedActions = [SuggestedActionKind.ReviewOnly]
        };
        Check("结果优先级：旧报告只有文案时保持重点", !IsReference(legacy));
        ScanReport graphOnly = new() { Findings = [legacy], Containers = new() { Nodes = [Node(legacy.Target, "Zip")] } };
        Check("结果优先级：容器格式字段可独立识别参考项", FindingPriorityPresentation.ReferenceFindingIds(graphOnly).Contains(legacy.Id));
        graphOnly.Containers!.Nodes[0].Recognition = ContainerStageStatus.Pending;
        Check("结果优先级：格式识别未完成不折叠", FindingPriorityPresentation.ReferenceFindingIds(graphOnly).Count == 0);

        ContainerScanNode combinedNode = Node(zip.Target, "Zip");
        combinedNode.FormatText = "Zip" + (MessageText)"";
        ScanReport combined = new() { Findings = [zip], Containers = new() { Nodes = [combinedNode] } };
        Check("结果优先级：扫描器单卷格式组合消息可识别", FindingPriorityPresentation.ReferenceFindingIds(combined).Contains(zip.Id));
        ScanReport combinedRestored = JsonSerializer.Deserialize<ScanReport>(JsonSerializer.Serialize(combined, JsonFile.Options), JsonFile.Options)!;
        Check("结果优先级：单卷格式组合消息JSON往返保持分类", FindingPriorityPresentation.ReferenceFindingIds(combinedRestored).Contains(zip.Id));
        combinedNode.FormatText = "Zip" + MessageText.Create("Backend.Core.ContentScanner.ArchiveGraph.ScanContainerArchiveAsync.01", 2);
        Check("结果优先级：正规分卷计数组合保留档案格式", FindingPriorityPresentation.ReferenceFindingIds(combined).Contains(zip.Id));
        combinedNode.FormatText = "PortableExecutable" + (MessageText)"";
        Check("结果优先级：组合消息内可执行格式冲突保持重点", FindingPriorityPresentation.ReferenceFindingIds(combined).Count == 0);
        combinedNode.FormatText = "Zip" + (MessageText)"Png";
        Check("结果优先级：非正规格式拼接保持重点", FindingPriorityPresentation.ReferenceFindingIds(combined).Count == 0);
        combinedNode.FormatText = new("Zip", new DisplayMessage("Future.UnknownFormat", []));
        Check("结果优先级：未知格式消息不因原文像ZIP而折叠", FindingPriorityPresentation.ReferenceFindingIds(combined).Count == 0);
        combinedNode.FormatText = "Zip" + MessageText.Create("Backend.Core.ContentScanner.ArchiveGraph.ScanContainerArchiveAsync.01", "invalid");
        Check("结果优先级：无效分卷计数保持重点", FindingPriorityPresentation.ReferenceFindingIds(combined).Count == 0);

        ScanReport conflict = new() { Findings = [zip], Containers = new() { Nodes = [Node(zip.Target, "Png")] } };
        Check("结果优先级：容器格式和描述矛盾保持重点", FindingPriorityPresentation.ReferenceFindingIds(conflict).Count == 0);
        conflict.Containers!.Nodes.Clear();
        conflict.Containers.Nodes.AddRange([Node(zip.Target, "Zip"), Node(zip.Target.ToUpperInvariant(), "PortableExecutable")]);
        Check("结果优先级：同路径容器记录类型冲突保持重点", FindingPriorityPresentation.ReferenceFindingIds(conflict).Count == 0);

        Finding signature = new()
        {
            RuleId = "CONTENT-SIGNATURE-HASH-MISMATCH",
            Target = zip.Target.ToUpperInvariant().Replace('\\', '/'),
            Category = FindingCategory.File,
            Severity = FindingSeverity.Medium,
            Score = 40,
            SuggestedActions = [SuggestedActionKind.ReviewOnly]
        };
        ScanReport stronger = new() { Findings = [zip, signature] };
        Check("结果优先级：同文件签名异常保持重点且兼容路径大小写分隔符", FindingPriorityPresentation.ReferenceFindingIds(stronger).Count == 0);
        Finding independent = Mismatch(root + "independent.dat");
        stronger.Findings.Add(independent);
        Check("结果优先级：另一文件的参考项不受无关威胁影响", FindingPriorityPresentation.ReferenceFindingIds(stronger).SetEquals([independent.Id]));

        Finding member = Mismatch(root + "bundle.dat!/folder/image.dat", "Png", target: root + "bundle.dat");
        Finding known = new()
        {
            RuleId = "EXACT-MALWARE-HASH",
            Target = root + "bundle.dat!/other/payload.exe",
            Category = FindingCategory.File,
            Severity = FindingSeverity.Critical,
            Score = 100,
            IsKnownMalware = true
        };
        Check("结果优先级：同容器另一条目有威胁时不折叠格式提示", FindingPriorityPresentation.ReferenceFindingIds(new() { Findings = [member, known] }).Count == 0);
        Finding related = new()
        {
            RuleId = "RELATED-PERSISTENCE",
            Target = @"HKCU\Software\Run\InertFixture",
            RelatedFilePath = zip.Target,
            Category = FindingCategory.Persistence,
            Severity = FindingSeverity.High
        };
        Check("结果优先级：关联文件证据保持重点", FindingPriorityPresentation.ReferenceFindingIds(new() { Findings = [zip, related] }).Count == 0);
        Finding aliased = Mismatch(root + "alias.dat");
        ScanReport aliasGraph = new()
        {
            Findings = [aliased, known],
            Containers = new()
            { Nodes = [Node(aliased.Target, "Zip", root + "bundle.dat")] }
        };
        Check("结果优先级：容器原始目标关联强证据", FindingPriorityPresentation.ReferenceFindingIds(aliasGraph).Count == 0);

        Finding coverage = new() { RuleId = "CONTENT-BYTE-BUDGET", Target = zip.Target, Category = FindingCategory.Coverage };
        Check("结果优先级：同文件未检查完整不折叠", FindingPriorityPresentation.ReferenceFindingIds(new() { Findings = [zip, coverage] }).Count == 0);
        Finding duplicateA = Mismatch(root + "duplicate-a.dat", id: "duplicate-id");
        Finding duplicateB = Mismatch(root + "duplicate-b.dat", id: "DUPLICATE-ID");
        Check("结果优先级：重复ID不误折叠任何一条", FindingPriorityPresentation.ReferenceFindingIds(new() { Findings = [duplicateA, duplicateB] }).Count == 0);
        Finding emptyId = Mismatch(root + "empty-id.dat", id: "");
        Check("结果优先级：缺失ID保持重点", !IsReference(emptyId));

        Finding eligible = new()
        {
            RuleId = "CONTENT-EXTENSION-MISMATCH",
            Category = FindingCategory.File,
            Target = zip.Target,
            DescriptionText = zip.DescriptionText,
            Severity = FindingSeverity.Medium,
            CanRemediate = true,
            SuggestedActions = [SuggestedActionKind.QuarantineFile]
        };
        Check("结果优先级：已有处置资格的发现保持重点", !IsReference(eligible));
        Finding invalidMetadata = new()
        {
            RuleId = "CONTENT-EXTENSION-MISMATCH",
            Target = root + "invalid.dat",
            Category = FindingCategory.File,
            Description = "invalid",
            DescriptionMessage = new("Invalid", Enumerable.Repeat(new DisplayArgument("x"), 9).ToArray())
        };
        Check("结果优先级：损坏描述元数据保留重点且不抛异常", !IsReference(invalidMetadata));

        string original = JsonSerializer.Serialize(stronger);
        using (DisplayText.UseCulture(DisplayText.English))
            Check("结果优先级：英文显示不改变分类", FindingPriorityPresentation.ReferenceFindingIds(stronger).SetEquals([independent.Id]));
        Check("结果优先级：不改动扫描证据分数或处置权限", JsonSerializer.Serialize(stronger) == original && zip.Score == 40 && !zip.CanRemediate);

        ScanReport large = new();
        for (int i = 0; i < 12_000; i++) large.Findings.Add(Mismatch(root + $"large-{i:D5}.dat"));
        Finding largeStrong = new()
        {
            RuleId = "EXACT-MALWARE-HASH",
            Category = FindingCategory.File,
            Target = large.Findings[6_000].Target,
            IsKnownMalware = true,
            Severity = FindingSeverity.Critical
        };
        large.Findings.Add(largeStrong);
        IReadOnlySet<string> largeReferences = FindingPriorityPresentation.ReferenceFindingIds(large);
        Check("结果优先级：大批结果完整分组且强证据不被淹没", largeReferences.Count == 11_999 &&
            !largeReferences.Contains(large.Findings[6_000].Id) && !largeReferences.Contains(largeStrong.Id));
    }
}
