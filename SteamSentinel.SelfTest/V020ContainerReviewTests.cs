using System.IO;
using System.IO.Compression;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using SteamSentinel.Core.Models;
using SteamSentinel.Core.Scanning;
using SteamSentinel.Core.Utilities;

namespace SteamSentinel.SelfTest;

internal static partial class Program
{
    private static async Task TestV020ContainerReviewAsync(string root)
    {
        TestV020CompleteStageConsistency();
        string directory = Path.Combine(root, "v020-origin-review-" + Guid.NewGuid().ToString("N"));
        string copies = Path.Combine(directory, "copies"), volumes = Path.Combine(directory, "volumes");
        Directory.CreateDirectory(copies); Directory.CreateDirectory(volumes);
        byte[] payload = Encoding.UTF8.GetBytes("Inert origin identity fixture. No executable content.");
        byte[] archive = V020StoredZip(payload);
        const string marker = "INERT-V020-ORIGIN-HASH";
        RuleSet rules = new()
        {
            KnownHashes = [new() { Id = marker, Sha256 = Convert.ToHexString(SHA256.HashData(payload)),
                Label = "Inert regression fixture", Malware = false, Remediable = true }],
            ArchiveExtensions = [".zip"]
        };
        ScanOptions options = new()
        {
            Mode = ScanMode.Custom,
            IncludeSystem = false,
            IncludeSteam = false,
            IncludeWorkshop = false,
            IncludeRelatedContent = false,
            UseAmsi = false,
            InspectArchives = true,
            InspectDeepSignatures = false,
            HashEveryFile = true,
            ContainerLimits = new() { ReservedDiskBytes = 0 }
        };
        await TestV020FindingCheckpointIdentityAsync(directory, archive, payload, options);
        await TestV020UnknownRangesAsync(directory, options);
        await TestV020VerifiedPrefixAsync(directory);
        await TestV020PublishedMemberIdentityAsync(directory);
        await TestV020PendingSiblingEntryBudgetAsync(directory);
        string first = Path.Combine(copies, "copy-a.zip"), second = Path.Combine(copies, "copy-b.zip");
        await File.WriteAllBytesAsync(first, archive); await File.WriteAllBytesAsync(second, archive);
        ScanReport sameDirectory = new();
        using (ContentScanner scanner = new(rules))
            await scanner.ScanRootAsync(copies, sameDirectory, options, new NullPasswordProvider());
        Check("0.2容器审阅 同目录字节相同的两个原件分别保留成员命中与修复目标",
            sameDirectory.Findings.Where(finding => finding.RuleId == marker).Select(finding => finding.Target)
                .ToHashSet(StringComparer.OrdinalIgnoreCase).SetEquals([first, second]) &&
            sameDirectory.Containers!.Nodes.Count(node => node.ParentId is null && node.ReusedNodeId.HasValue) == 0);
        Check("0.2容器审阅 复制件成员各自绑定正确原件SHA与内容路径",
            sameDirectory.Findings.Where(finding => finding.RuleId == marker).All(finding =>
                finding.TargetSha256 == Convert.ToHexString(SHA256.HashData(archive)) &&
                finding.ContentPath == finding.Target + "!/inert.txt"));

        ScanReport repeated = new();
        using (ContentScanner scanner = new(rules))
        {
            await scanner.ScanRootAsync(first, repeated, options, new NullPasswordProvider());
            await scanner.ScanRootAsync(first, repeated, options, new NullPasswordProvider());
        }
        Check("0.2容器审阅 同一明确根的相同物理组重复入口仍只解码一次",
            repeated.Findings.Count(finding => finding.RuleId == marker) == 1 &&
            repeated.Containers!.Nodes.Count(node => node.ReusedNodeId.HasValue) == 1);

        string partOne = Path.Combine(volumes, "inert.zip.001"), partTwo = Path.Combine(volumes, "inert.zip.002");
        await File.WriteAllBytesAsync(partOne, archive[..(archive.Length / 2)]);
        await File.WriteAllBytesAsync(partTwo, archive[(archive.Length / 2)..]);
        ScanReport oneDirectory = new();
        using (ContentScanner scanner = new(rules))
            await scanner.ScanRootAsync(volumes, oneDirectory, options, new NullPasswordProvider());
        ContainerScanNode[] grouped = oneDirectory.Containers!.Nodes.Where(node => node.Kind == ContainerNodeKind.VolumeGroup).ToArray();
        Check("0.2容器审阅 同目录根中的同物理分卷组保持去重及卷身份",
            grouped.Length == 2 && grouped.Count(node => node.ReusedNodeId.HasValue) == 1 && grouped.All(node => node.Volumes.Count == 2) &&
            oneDirectory.Findings.Count(finding => finding.RuleId == marker) == 1);

        ScanReport distinctRoots = new();
        using (ContentScanner scanner = new(rules))
        {
            await scanner.ScanRootAsync(partOne, distinctRoots, options, new NullPasswordProvider());
            await scanner.ScanRootAsync(partTwo, distinctRoots, options, new NullPasswordProvider());
        }
        Check("0.2容器审阅 同物理卷组被明确选择为两个根时分别保留命中",
            distinctRoots.Findings.Where(finding => finding.RuleId == marker).Select(finding => finding.Target)
                .ToHashSet(StringComparer.OrdinalIgnoreCase).SetEquals([partOne, partTwo]) &&
            distinctRoots.Containers!.Nodes.All(node => !node.ReusedNodeId.HasValue));
    }

    private static async Task TestV020UnknownRangesAsync(string directory, ScanOptions options)
    {
        byte[] media = [.. V020RangeBox("ftyp", "isom\0\0\0\0isom"u8.ToArray()), .. V020RangeBox("mdat", "inert media"u8.ToArray())];
        byte[] tail = "Inert unknown-tail evidence marker, no executable content."u8.ToArray();
        string path = Path.Combine(directory, "unknown-tail.mp4");
        byte[] fileBytes = [.. media, .. tail]; await File.WriteAllBytesAsync(path, fileBytes);
        const string ruleId = "INERT-V020-UNKNOWN-HASH";
        RuleSet rules = new()
        {
            KnownHashes = [new() { Id = ruleId, Sha256 = Convert.ToHexString(SHA256.HashData(tail)),
            Label = "Inert unknown range fixture", Malware = false, Remediable = true }]
        };
        ScanReport report = new();
        List<Finding> transmitted = [];
        ReportBatchWriter unknownWriter = new(batch => transmitted.AddRange(JsonSerializer.Deserialize<ReportBatch>(
            JsonSerializer.Serialize(batch, JsonFile.Options), JsonFile.Options)!.Data.Findings));
        using (ContentScanner scanner = new(rules))
        {
            scanner.Checkpoint = state => unknownWriter.Send(state);
            await scanner.ScanRootAsync(path, report, options, new NullPasswordProvider());
        }
        ContainerScanNode unknown = report.Containers!.Nodes.Single(node => node.Kind == ContainerNodeKind.UnknownRange);
        Check("0.2容器审阅 未知尾部独立哈希只覆盖准确父层范围",
            unknown.Sha256 == Convert.ToHexString(SHA256.HashData(tail)) && unknown.ParentOffset == media.Length &&
            unknown.ParentLength == tail.Length && unknown.Length == tail.Length && unknown.OriginalTargetSha256 == Convert.ToHexString(SHA256.HashData(fileBytes)));
        Check("0.2容器审阅 未知范围引擎完成仍不冒充格式或完整性通过",
            unknown.Recognition == ContainerStageStatus.Unsupported && unknown.Integrity == ContainerStageStatus.UnsupportedIntegrity &&
            unknown.Overall == ContainerStageStatus.Unsupported && unknown.ContentCheck == ContainerStageStatus.Complete &&
            unknown.Engines.Any(engine => engine.Engine == "字符串与行为特征" && engine.Status == ContainerStageStatus.Complete && engine.Length == tail.Length) &&
            !report.Containers.Complete && report.Coverage == ScanCoverage.Partial);
        Check("0.2容器审阅 未知范围哈希命中仍绑定真实原件身份",
            report.Findings.SingleOrDefault(finding => finding.RuleId == ruleId) is { } finding && finding.Target == path &&
            finding.ContentPath == unknown.DisplayPath && finding.TargetSha256 == unknown.OriginalTargetSha256);
        Check("0.2容器审阅 未知范围初始覆盖缺口首次发帧即绑定原件身份",
            transmitted.SingleOrDefault(finding => finding.RuleId == "CONTAINER-UNKNOWN-RANGE") is { } gap &&
            gap.TargetSha256 == unknown.OriginalTargetSha256 && gap.ContentPath == unknown.DisplayPath);
        Check("0.2容器审阅 未知内容检查保持源文件字节不变", (await File.ReadAllBytesAsync(path)).SequenceEqual(fileBytes));

        string fakeArchivePath = Path.Combine(directory, "unknown-fake-zip.mp4");
        byte[] fakeArchive = [0x50, 0x4b, 0x03, 0x04, .. new byte[40]];
        await File.WriteAllBytesAsync(fakeArchivePath, [.. media, .. fakeArchive]);
        ScanReport fake = new();
        using (ContentScanner scanner = new(new())) await scanner.ScanRootAsync(fakeArchivePath, fake, options, new NullPasswordProvider());
        Check("0.2容器审阅 未知范围有ZIP魔数也不递归猜测解码成功",
            fake.Containers!.Nodes.Count == 2 && fake.Containers.Nodes.Single(node => node.Kind == ContainerNodeKind.UnknownRange) is
            { Recognition: ContainerStageStatus.Unsupported, Integrity: ContainerStageStatus.UnsupportedIntegrity, Sha256: not null } &&
            fake.Containers.Nodes.All(node => node.Kind != ContainerNodeKind.ArchiveMember));

        string executableTailPath = Path.Combine(directory, "unknown-short-pe.mp4");
        await File.WriteAllBytesAsync(executableTailPath, [.. media, .. MakePortableExecutableFixture()]);
        ScanOptions tinyQuick = new()
        {
            Mode = ScanMode.Quick,
            IncludeSystem = false,
            IncludeSteam = false,
            IncludeWorkshop = false,
            UseAmsi = false,
            InspectArchives = false,
            InspectDeepSignatures = false,
            MaximumContentBytes = 1
        };
        ScanReport quick = new();
        using (ContentScanner scanner = new(new())) await scanner.ScanRootAsync(executableTailPath, quick, tinyQuick, new NullPasswordProvider());
        Check("0.2容器审阅 快速哈希预算不足仍以有界头识别PE尾随且只报一次",
            quick.Findings.Count(finding => finding.RuleId == "MP4-TRAILING-DATA") == 1 &&
            quick.Findings.Single(finding => finding.RuleId == "MP4-TRAILING-DATA").Severity == FindingSeverity.High &&
            quick.Containers!.Nodes.Single(node => node.Kind == ContainerNodeKind.UnknownRange) is { Sha256: null, ContentCheck: ContainerStageStatus.LimitReached } &&
            quick.Metrics.BytesHashed == 0 && quick.Containers.Resources.ReadBytes < 256 * 1024);

        byte[] nested = fileBytes;
        for (int depth = 0; depth < 32; depth++) nested = V020StoredZip(nested);
        string deepPath = Path.Combine(directory, "depth-32-ranges.zip"); await File.WriteAllBytesAsync(deepPath, nested);
        ScanOptions deepest = new()
        {
            Mode = ScanMode.Custom,
            IncludeSystem = false,
            IncludeSteam = false,
            IncludeWorkshop = false,
            UseAmsi = false,
            InspectArchives = true,
            InspectDeepSignatures = false,
            HashEveryFile = true,
            ContainerLimits = new() { MaximumDepth = 32, ReservedDiskBytes = 0 }
        };
        ScanReport depthReport = new(); ReportBatchReader depthReader = new();
        ReportBatchWriter depthWriter = new(batch => depthReader.Apply(JsonSerializer.Deserialize<ReportBatch>(
            JsonSerializer.Serialize(batch, JsonFile.Options), JsonFile.Options)!));
        using (ContentScanner scanner = new(new()))
        {
            scanner.Checkpoint = state => depthWriter.Send(state);
            await scanner.ScanRootAsync(deepPath, depthReport, deepest, new NullPasswordProvider());
        }
        depthWriter.Send(depthReport, final: true);
        Check("0.2容器审阅 最大32层的范围缺口留在父项并可完整交回协议",
            depthReport.Containers!.Nodes.Max(node => node.Depth) == 32 &&
            depthReport.Containers.Nodes.Single(node => node.Depth == 32).Overall == ContainerStageStatus.LimitReached &&
            depthReader.Report?.Containers?.Nodes.Count == 33 && !depthReport.Containers.Complete);
    }

    private static async Task TestV020VerifiedPrefixAsync(string directory)
    {
        byte[] prefix = "verified prefix"u8.ToArray(), later = Enumerable.Repeat((byte)0x35, 64).ToArray();
        byte[] archive = V020ReviewZip(("prefix.txt", prefix, CompressionLevel.NoCompression), ("later.txt", later, CompressionLevel.NoCompression));
        string path = Path.Combine(directory, "verified-prefix.zip"); await File.WriteAllBytesAsync(path, archive);
        ScanOptions Options(ContainerResourceLimits limits) => new()
        {
            Mode = ScanMode.Custom,
            IncludeSystem = false,
            IncludeSteam = false,
            IncludeWorkshop = false,
            UseAmsi = false,
            InspectArchives = true,
            InspectDeepSignatures = false,
            HashEveryFile = true,
            ContainerLimits = limits
        };
        string expected = Convert.ToHexString(SHA256.HashData(prefix));
        ScanReport cancelled = new(); ReportBatchReader reader = new();
        ReportBatchWriter writer = new(batch => reader.Apply(JsonSerializer.Deserialize<ReportBatch>(JsonSerializer.Serialize(batch, JsonFile.Options), JsonFile.Options)!));
        using CancellationTokenSource cancellation = new();
        bool cancellationObserved;
        using (ContentScanner scanner = new(new()))
        {
            scanner.Checkpoint = state => writer.Send(state);
            cancellationObserved = await V020ThrowsAsync<OperationCanceledException>(() => scanner.ScanRootAsync(path, cancelled,
                Options(new() { ReservedDiskBytes = 0 }), new NullPasswordProvider(), new V020ReviewProgress(progress =>
                {
                    if (progress.Stage == "归档成员已校验" && progress.CurrentItem.EndsWith("!/prefix.txt", StringComparison.Ordinal)) cancellation.Cancel();
                }), cancellation.Token));
        }
        ContainerScanNode? kept = cancelled.Containers?.Nodes.SingleOrDefault(node => node.ParentId.HasValue);
        Check("0.2容器审阅 解码中取消先保留已校验前缀SHA长度及未做内容状态",
            cancellationObserved && kept is
            {
                Integrity: ContainerStageStatus.Complete, ContentCheck: ContainerStageStatus.Cancelled,
                Overall: ContainerStageStatus.Cancelled, Recognition: ContainerStageStatus.Pending
            } && kept.Sha256 == expected && kept.Length == prefix.Length &&
            kept.OriginalTargetSha256 == Convert.ToHexString(SHA256.HashData(archive)));
        Check("0.2容器审阅 取消前缀通过真实检查点交回且不冒充恢复文件",
            reader.Report?.Containers?.Nodes.Any(node => node.Sha256 == expected && node.ContentCheck == ContainerStageStatus.Cancelled) == true &&
            cancelled.Containers is { Complete: false, Resources.CurrentTemporaryBytes: 0 } &&
            cancelled.Containers.Nodes.All(node => !node.RecoveredContentAvailable) && cancelled.Metrics.ArchiveEntriesVisited == 1);

        ScanReport temporaryLimit = new(); bool tempStopped;
        using (ContentScanner scanner = new(new()))
            tempStopped = await V020ThrowsAsync<ScanResourceLimitException>(() => scanner.ScanRootAsync(path, temporaryLimit,
                Options(new() { MaximumTemporaryBytes = prefix.Length, ReservedDiskBytes = 0 }), new NullPasswordProvider()));
        Check("0.2容器审阅 全局临时预算耗尽保留已校验前缀不接受当前未校验成员",
            tempStopped && temporaryLimit.Containers!.Nodes.Count(node => node.ParentId.HasValue) == 1 &&
            temporaryLimit.Containers.Nodes.Single(node => node.ParentId.HasValue) is
            {
                Integrity: ContainerStageStatus.Complete,
                ContentCheck: ContainerStageStatus.LimitReached, Sha256: not null
            } saved && saved.Sha256 == expected &&
            temporaryLimit.Containers.Resources.PeakTemporaryBytes == prefix.Length && temporaryLimit.Containers.Resources.CurrentTemporaryBytes == 0 &&
            temporaryLimit.Containers.Resources.DecodedBytes > prefix.Length);

        ScanReport metadataLimit = new(); bool metadataStopped;
        using (ContentScanner scanner = new(new()))
            metadataStopped = await V020ThrowsAsync<ScanResourceLimitException>(() => scanner.ScanRootAsync(path, metadataLimit,
                Options(new() { MaximumMetadataAttempts = 2, ReservedDiskBytes = 0 }), new NullPasswordProvider()));
        Check("0.2容器审阅 最终目录检查达到整轮限额仍保留两个已校验成员",
            metadataStopped && metadataLimit.Containers!.Nodes.Count(node => node.ParentId.HasValue) == 2 &&
            metadataLimit.Containers.Nodes.Where(node => node.ParentId.HasValue).All(node => node.Sha256 is not null &&
                node.Integrity == ContainerStageStatus.Complete && node.ContentCheck == ContainerStageStatus.LimitReached) &&
            metadataLimit.Containers.Resources.MetadataAttempts == 3);

        const string marker = "INERT-V020-PREFIX-HASH";
        RuleSet rules = new() { KnownHashes = [new() { Id = marker, Sha256 = expected, Label = "Inert prefix fixture", Malware = false }] };
        string next = Path.Combine(directory, "after-limited-archive.txt"); await File.WriteAllBytesAsync(next, prefix);
        string sizePath = Path.Combine(directory, "size-limited.zip");
        await File.WriteAllBytesAsync(sizePath, V020ReviewZip(("prefix.txt", prefix, CompressionLevel.NoCompression),
            ("oversized.txt", new byte[64], CompressionLevel.NoCompression), ("after.txt", prefix, CompressionLevel.NoCompression)));
        ScanReport size = new();
        using (ContentScanner scanner = new(rules))
        {
            ScanOptions options = Options(new() { MaximumEntryBytes = 32, ReservedDiskBytes = 0 });
            await scanner.ScanRootAsync(sizePath, size, options, new NullPasswordProvider());
            await scanner.ScanRootAsync(next, size, options, new NullPasswordProvider());
        }
        Check("0.2容器审阅 ZIP单成员尺寸超限不解码并继续后项和后根",
            size.Findings.Any(finding => finding.RuleId == "ARCHIVE-SIZE-LIMIT" && finding.Target == sizePath) &&
            size.Findings.Where(finding => finding.RuleId == marker).Select(finding => finding.Target).ToHashSet().SetEquals([sizePath, next]) &&
            size.Containers!.Nodes.Single(node => node.DisplayPath == sizePath + "!/prefix.txt").ContentCheck == ContainerStageStatus.Complete &&
            size.Containers.Nodes.Single(node => node.DisplayPath == sizePath + "!/after.txt").ContentCheck == ContainerStageStatus.Complete);
        Check("0.2容器审阅 ZIP跳过成员只有声明元数据且整个归档保持不完整",
            size.Containers!.Nodes.Single(node => node.DisplayPath == sizePath + "!/oversized.txt") is
            {
                Sha256: null, Length: 64, Integrity: ContainerStageStatus.LimitReached, ContentCheck: ContainerStageStatus.LimitReached,
                RecoveredContentAvailable: false
            } &&
            size.Containers.Nodes.Single(node => node.DisplayPath == sizePath) is
            { DirectoryRead: ContainerStageStatus.Complete, Integrity: ContainerStageStatus.Partial, Overall: ContainerStageStatus.Partial } &&
            size.Containers.Resources.DecodedBytes == prefix.Length * 2 && !size.Containers.Complete && size.Metrics.ArchiveEntriesVisited == 3);

        string ratioPath = Path.Combine(directory, "ratio-limited.zip");
        await File.WriteAllBytesAsync(ratioPath, V020ReviewZip(("prefix.txt", prefix, CompressionLevel.NoCompression),
            ("ratio.txt", new byte[8192], CompressionLevel.SmallestSize), ("after.txt", prefix, CompressionLevel.NoCompression)));
        ScanReport ratio = new();
        using (ContentScanner scanner = new(rules))
        {
            ScanOptions options = Options(new() { MaximumCompressionRatio = 2, ReservedDiskBytes = 0 });
            await scanner.ScanRootAsync(ratioPath, ratio, options, new NullPasswordProvider());
            await scanner.ScanRootAsync(next, ratio, options, new NullPasswordProvider());
        }
        Check("0.2容器审阅 ZIP压缩比上限保留专用规则并继续后项和后根",
            ratio.Findings.Any(finding => finding.RuleId == "ARCHIVE-RATIO-LIMIT" && finding.Target == ratioPath) &&
            ratio.Findings.Any(finding => finding.RuleId == marker && finding.Target == next) &&
            ratio.Containers!.Nodes.Single(node => node.DisplayPath == ratioPath + "!/after.txt").ContentCheck == ContainerStageStatus.Complete &&
            ratio.Containers.Resources.DecodedBytes == prefix.Length * 2);

        string encrypted = Path.Combine(directory, "unverified-password.zip");
        await File.WriteAllBytesAsync(encrypted, V020AesZip(prefix, "inert-correct-secret", 2));
        RecordingPasswords passwords = new((_, number) => number == 1 ? "inert-wrong-secret" : null);
        ScanReport wrong = new();
        using (ContentScanner scanner = new(new())) await scanner.ScanRootAsync(encrypted, wrong,
            Options(new() { ReservedDiskBytes = 0 }), passwords);
        Check("0.2容器审阅 错误密码尝试不发布未验证成员或伪造前缀",
            wrong.Containers!.Nodes.All(node => node.ParentId is null) && !wrong.Containers.Complete &&
            wrong.Containers.Resources.PasswordAttempts == 1 && passwords.Requests.Count == 2 &&
            wrong.Containers.Nodes.All(node => !node.RecoveredContentAvailable));
    }

    private static async Task TestV020PublishedMemberIdentityAsync(string directory)
    {
        byte[] payload = "Inert identical member content for interrupted publication identity."u8.ToArray();
        string hash = Convert.ToHexString(SHA256.HashData(payload));
        ScanOptions Options(long? workBytes = null) => new()
        {
            Mode = ScanMode.Custom,
            IncludeSystem = false,
            IncludeSteam = false,
            IncludeWorkshop = false,
            UseAmsi = false,
            InspectArchives = true,
            InspectDeepSignatures = false,
            HashEveryFile = true,
            ContainerLimits = new() { MaximumWorkBytes = workBytes ?? 64L * 1024 * 1024 * 1024, ReservedDiskBytes = 0 }
        };

        // Exact duplicate ZIP metadata cannot be uniquely bound to the integrity index.
        // Keep that rejection intact; do not weaken it just to reach the retention helper.
        string duplicatesPath = Path.Combine(directory, "exact-duplicate-members.zip");
        await File.WriteAllBytesAsync(duplicatesPath, V020ReviewZip(("same.txt", payload, CompressionLevel.NoCompression),
            ("same.txt", payload, CompressionLevel.NoCompression)));
        ScanReport duplicates = new();
        using (ContentScanner scanner = new(new()))
            await scanner.ScanRootAsync(duplicatesPath, duplicates, Options(), new NullPasswordProvider());
        Check("0.2容器审阅 完全重名同内容ZIP不绕过唯一完整性映射",
            duplicates.Containers!.Nodes.All(node => !node.ParentId.HasValue) && !duplicates.Containers.Complete &&
            duplicates.Containers.Nodes.Single().Integrity == ContainerStageStatus.UnsupportedIntegrity);

        // These are distinct, valid ZIP names, but CR/LF sanitization gives them the same
        // displayed path. Their verified hashes are also equal: the old display/hash lookup
        // would merge the unpublished sibling into the already published current node.
        string path = Path.Combine(directory, "same-display-members.zip");
        await File.WriteAllBytesAsync(path, V020ReviewZip(("same\rname.txt", payload, CompressionLevel.NoCompression),
            ("same\nname.txt", payload, CompressionLevel.NoCompression)));
        string display = path + "!/same_name.txt";
        FieldInfo progressClock = typeof(ContentScanner).GetField("_lastContainerProgress", BindingFlags.Instance | BindingFlags.NonPublic)!;
        ScanReport cancelled = new(); ReportBatchReader cancelledReader = new();
        ReportBatchWriter cancelledWriter = new(batch => cancelledReader.Apply(JsonSerializer.Deserialize<ReportBatch>(
            JsonSerializer.Serialize(batch, JsonFile.Options), JsonFile.Options)!));
        Guid currentId = Guid.Empty; long workAtContent = 0;
        using CancellationTokenSource cancellation = new();
        bool cancellationObserved;
        using (ContentScanner scanner = new(new()))
        {
            scanner.Checkpoint = state => cancelledWriter.Send(state);
            cancellationObserved = await V020ThrowsAsync<OperationCanceledException>(() => scanner.ScanRootAsync(path, cancelled,
                Options(), new NullPasswordProvider(), new V020ReviewProgress(progress =>
                {
                    // Disable only UI progress throttling so the cancellation point is exact
                    // without sleeps, large allocations or changes to production scanning.
                    progressClock.SetValue(scanner, 0L);
                    if (progress.Stage != "容器内容" || progress.CurrentItem != display || currentId != Guid.Empty) return;
                    ContainerScanNode? current = cancelled.Containers?.Nodes.SingleOrDefault(node => node.ParentId.HasValue);
                    if (current is null || current.Sha256 != hash || !current.Engines.Any(engine => engine.Engine == "SHA-256" &&
                        engine.Status == ContainerStageStatus.Complete) || current.ContentCheck != ContainerStageStatus.Pending) return;
                    currentId = current.NodeId; workAtContent = progress.Completed; cancellation.Cancel();
                }), cancellation.Token));
        }
        cancelledWriter.Send(cancelled, final: true);
        Check("0.2容器审阅 精确在首个成员SHA完成后的内容检查阶段取消",
            cancellationObserved && currentId != Guid.Empty && workAtContent > 0);
        if (!cancellationObserved || currentId == Guid.Empty || workAtContent <= 0) return;
        AssertMembers("取消", cancelled, cancelledReader.Report!, currentId, ContainerStageStatus.Cancelled);

        // Reuse the measured work boundary from the identical source. The next content read
        // exhausts the real shared budget; no fabricated reads or relaxed limits are injected.
        ScanReport limited = new(); ReportBatchReader limitedReader = new(); Guid limitedCurrentId = Guid.Empty;
        ReportBatchWriter limitedWriter = new(batch => limitedReader.Apply(JsonSerializer.Deserialize<ReportBatch>(
            JsonSerializer.Serialize(batch, JsonFile.Options), JsonFile.Options)!));
        bool limitObserved;
        using (ContentScanner scanner = new(new()))
        {
            scanner.Checkpoint = state =>
            {
                if (limitedCurrentId == Guid.Empty)
                    limitedCurrentId = state.Containers?.Nodes.SingleOrDefault(node => node.ParentId.HasValue)?.NodeId ?? Guid.Empty;
                limitedWriter.Send(state);
            };
            limitObserved = await V020ThrowsAsync<ScanResourceLimitException>(() => scanner.ScanRootAsync(path, limited,
                Options(workAtContent), new NullPasswordProvider()));
        }
        limitedWriter.Send(limited, final: true);
        Check("0.2容器审阅 实际工作预算在已发布成员内容检查阶段耗尽",
            limitObserved && limitedCurrentId != Guid.Empty &&
            limited.Containers!.Resources.ReadBytes + limited.Containers.Resources.DecodedBytes == workAtContent);
        AssertMembers("预算耗尽", limited, limitedReader.Report!, limitedCurrentId, ContainerStageStatus.LimitReached);

        void AssertMembers(string label, ScanReport report, ScanReport wire, Guid publishedId, ContainerStageStatus status)
        {
            ContainerScanNode[] members = report.Containers!.Nodes.Where(node => node.ParentId.HasValue).ToArray();
            Check("0.2容器审阅 " + label + "更新当前NodeId并分别保留同显示名同哈希兄弟",
                members.Length == 2 && members.Select(node => node.NodeId).Distinct().Count() == 2 &&
                members.Count(node => node.NodeId == publishedId) == 1 && members.All(node => node.DisplayPath == display &&
                    node.Sha256 == hash && node.Length == payload.Length && node.Integrity == ContainerStageStatus.Complete &&
                    node.ContentCheck == status && node.Overall == status && !node.RecoveredContentAvailable) &&
                members.Single(node => node.NodeId == publishedId).Recognition == ContainerStageStatus.Complete &&
                members.Single(node => node.NodeId != publishedId).Recognition == ContainerStageStatus.Pending);
            Check("0.2容器审阅 " + label + "两个成员经真实JSON检查点保留且计量不重复",
                wire.Containers is { } wireContainers && wireContainers.Nodes.Count(node => node.ParentId.HasValue) == 2 &&
                wireContainers.Nodes.Where(node => node.ParentId.HasValue).Select(node => node.NodeId).ToHashSet()
                    .SetEquals(members.Select(node => node.NodeId)) &&
                report.Metrics.ArchiveEntriesVisited == 2 && report.Metrics.ArchiveBytesExpanded == payload.Length * 2 &&
                report.Containers.Resources.CurrentTemporaryBytes == 0 && !report.Containers.Complete);
        }
    }

    private static async Task TestV020PendingSiblingEntryBudgetAsync(string directory)
    {
        byte[] first = "inert first inner member"u8.ToArray();
        byte[] second = "inert second inner member"u8.ToArray();
        byte[] later = "inert already verified outer sibling"u8.ToArray();
        byte[] inner = V020ReviewZip(("first.txt", first, CompressionLevel.NoCompression),
            ("second.txt", second, CompressionLevel.NoCompression));
        string path = Path.Combine(directory, "pending-sibling-entry-limit.zip");
        await File.WriteAllBytesAsync(path, V020ReviewZip(("inner.zip", inner, CompressionLevel.NoCompression),
            ("later.txt", later, CompressionLevel.NoCompression)));
        ScanOptions options = new()
        {
            Mode = ScanMode.Custom,
            IncludeSystem = false,
            IncludeSteam = false,
            IncludeWorkshop = false,
            UseAmsi = false,
            InspectArchives = true,
            InspectDeepSignatures = false,
            HashEveryFile = true,
            ContainerLimits = new() { MaximumEntries = 3, ReservedDiskBytes = 0 }
        };
        ScanReport report = new(); bool stopped;
        using (ContentScanner scanner = new(new()))
            stopped = await V020ThrowsAsync<ScanResourceLimitException>(() => scanner.ScanRootAsync(path, report,
                options, new NullPasswordProvider()));
        Check("0.2容器审阅 已验证外层兄弟先占全局成员限额不被内层挤到第四项",
            stopped && report.Metrics.ArchiveEntriesVisited == 3 &&
            report.Metrics.ArchiveBytesExpanded == inner.Length + later.Length + first.Length &&
            report.Containers!.Nodes.Any(node => node.DisplayPath == path + "!/inner.zip!/first.txt") &&
            report.Containers.Nodes.All(node => node.DisplayPath != path + "!/inner.zip!/second.txt"));
        Check("0.2容器审阅 嵌套成员限额保留后兄弟已验证身份及未检查状态且清理临时",
            report.Containers!.Nodes.SingleOrDefault(node => node.DisplayPath == path + "!/later.txt") is
            {
                Recognition: ContainerStageStatus.Pending, Integrity: ContainerStageStatus.Complete,
                ContentCheck: ContainerStageStatus.LimitReached, Overall: ContainerStageStatus.LimitReached,
                RecoveredContentAvailable: false
            } sibling &&
            sibling.Sha256 == Convert.ToHexString(SHA256.HashData(later)) && sibling.Length == later.Length &&
            report.Containers.Resources.CurrentTemporaryBytes == 0 && !report.Containers.Complete && report.Coverage == ScanCoverage.Partial);
    }

    private static byte[] V020ReviewZip(params (string Name, byte[] Content, CompressionLevel Compression)[] members)
    {
        using MemoryStream storage = new();
        using (ZipArchive archive = new(storage, ZipArchiveMode.Create, leaveOpen: true))
            foreach (var member in members)
            {
                using Stream output = archive.CreateEntry(member.Name, member.Compression).Open(); output.Write(member.Content);
            }
        return storage.ToArray();
    }

    private sealed class V020ReviewProgress(Action<ScanProgress> report) : IProgress<ScanProgress>
    {
        public void Report(ScanProgress value) => report(value);
    }

    private static async Task TestV020FindingCheckpointIdentityAsync(string directory, byte[] inner, byte[] payload, ScanOptions options)
    {
        string outerPath = Path.Combine(directory, "checkpoint-outer.zip");
        byte[] outer;
        using (MemoryStream storage = new())
        {
            using (ZipArchive zip = new(storage, ZipArchiveMode.Create, leaveOpen: true))
            {
                using (Stream member = zip.CreateEntry("inner.zip", CompressionLevel.NoCompression).Open()) member.Write(inner);
                using (Stream member = zip.CreateEntry("../unsafe-name.txt", CompressionLevel.NoCompression).Open()) member.Write(payload);
            }
            outer = storage.ToArray();
        }
        await File.WriteAllBytesAsync(outerPath, outer);
        const string ruleId = "INERT-V020-NESTED-HASH";
        RuleSet rules = new()
        {
            KnownHashes = [new() { Id = ruleId, Sha256 = Convert.ToHexString(SHA256.HashData(inner)),
            Label = "Inert nested checkpoint fixture", Malware = false, Remediable = true }],
            ArchiveExtensions = [".zip"]
        };
        ReportBatchReader reader = new();
        List<Finding> transmitted = [];
        ReportBatchWriter writer = new(batch =>
        {
            // Wire serialization must happen at each checkpoint; shared object references would
            // hide a late TargetSha256 mutation that the real UI never receives.
            ReportBatch copy = JsonSerializer.Deserialize<ReportBatch>(JsonSerializer.Serialize(batch, JsonFile.Options), JsonFile.Options)!;
            transmitted.AddRange(copy.Data.Findings); reader.Apply(copy);
        });
        ScanReport report = new();
        using (ContentScanner scanner = new(rules))
        {
            scanner.Checkpoint = state => writer.Send(state);
            await scanner.ScanRootAsync(outerPath, report, options, new NullPasswordProvider());
        }
        writer.Send(report, final: true);
        string expected = Convert.ToHexString(SHA256.HashData(outer));
        Check("0.2容器审阅 嵌套容器自身命中首次发帧即绑定外层SHA及内层内容路径",
            transmitted.SingleOrDefault(finding => finding.RuleId == ruleId) is { } nested &&
            nested.Target == outerPath && nested.TargetSha256 == expected && nested.ContentPath == outerPath + "!/inner.zip" &&
            reader.Report!.Findings.Single(finding => finding.RuleId == ruleId).TargetSha256 == expected);
        Check("0.2容器审阅 危险成员名首次发帧前已绑定外层修复身份",
            transmitted.SingleOrDefault(finding => finding.RuleId == "ARCHIVE-PATH-TRAVERSAL") is { } unsafeName &&
            unsafeName.Target == outerPath && unsafeName.TargetSha256 == expected && unsafeName.ContentPath == outerPath + "!/../unsafe-name.txt");
    }

    private static void TestV020CompleteStageConsistency()
    {
        foreach (string stage in new[] { nameof(ContainerScanNode.Recognition), nameof(ContainerScanNode.DirectoryRead),
            nameof(ContainerScanNode.Decryption), nameof(ContainerScanNode.Integrity), nameof(ContainerScanNode.ContentCheck) })
        {
            ContainerScanNode node = V020ReviewCompleteNode();
            typeof(ContainerScanNode).GetProperty(stage)!.SetValue(node, ContainerStageStatus.Partial);
            Check("0.2容器审阅 " + stage + "未完成时解码结束仍保持Partial",
                ContentScanner.ContainerCompletionStatus(node, []) == ContainerStageStatus.Partial);
            ScanReport invalid = new() { Containers = new() { Complete = true, Nodes = [node] } };
            int sent = 0;
            ReportBatchWriter writer = new(_ => sent++);
            Check("0.2容器审阅 " + stage + "未完成却声称Complete的分片在发送前拒绝",
                V020Throws<InvalidDataException>(() => writer.Send(invalid, final: true)) && sent == 0 && writer.Count == 0);
        }
        ContainerScanNode complete = V020ReviewCompleteNode();
        ContainerScanNode child = V020ReviewCompleteNode(); child.Overall = ContainerStageStatus.Partial;
        Check("0.2容器审阅 所有本层阶段完成仍须等待子项完成",
            ContentScanner.ContainerCompletionStatus(complete, [child]) == ContainerStageStatus.Partial);
        complete.DirectoryRead = complete.Decryption = ContainerStageStatus.NotRequested;
        Check("0.2容器审阅 明确未请求的非适用阶段允许完整叶子状态",
            ContentScanner.ContainerCompletionStatus(complete, []) == ContainerStageStatus.Complete);
        ScanReport source = new() { Containers = new() { Complete = true, Nodes = [complete] } };
        ReportBatchReader reader = new();
        ReportBatchWriter validWriter = new(batch => reader.Apply(JsonSerializer.Deserialize<ReportBatch>(
            JsonSerializer.Serialize(batch, JsonFile.Options), JsonFile.Options)!));
        validWriter.Send(source, final: true);
        Check("0.2容器审阅 一致的五阶段完成节点可经过真实JSON分片往返",
            reader.Report?.Containers is { Complete: true } && !reader.HasIncompleteContainers);
    }

    private static ContainerScanNode V020ReviewCompleteNode() => new()
    {
        DisplayPath = @"C:\Inert\stage-fixture.zip",
        OriginalTarget = @"C:\Inert\stage-fixture.zip",
        Recognition = ContainerStageStatus.Complete,
        DirectoryRead = ContainerStageStatus.Complete,
        Decryption = ContainerStageStatus.Complete,
        Integrity = ContainerStageStatus.Complete,
        ContentCheck = ContainerStageStatus.Complete,
        Overall = ContainerStageStatus.Complete
    };
}
