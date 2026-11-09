using System.IO;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using SteamSentinel.Core.Models;
using SteamSentinel.Core.Remediation;
using SteamSentinel.Core.Reporting;
using SteamSentinel.Core.Utilities;

namespace SteamSentinel.SelfTest;

internal static partial class Program
{
    private static async Task TestV031CasePersistenceAsync(string root)
    {
        const string sid = "S-1-5-21-123-456-789-1001";
        string directory = Path.Combine(root, "v031-case-persistence-" + Guid.NewGuid().ToString("N"));
        RemediationCaseStore store = new(directory, () => sid);
        RemediationCaseRecord cancelledInitial = new() { UserSid = sid };
        using (CancellationTokenSource cancelled = new())
        {
            cancelled.Cancel();
            bool stopped = false;
            try { await store.SaveAsync(cancelledInitial, cancelled.Token); }
            catch (OperationCanceledException) { stopped = true; }
            Check("大病例 首次保存取消不留下阻断恢复的空病例", stopped && cancelledInitial.Revision == 0 &&
                !Directory.Exists(Path.Combine(directory, cancelledInitial.CaseId.ToString("N"))) && (await store.ListAsync()).Count == 0);
        }
        await store.SaveAsync(cancelledInitial);
        Check("大病例 首次取消后可以按原ID正常重试", (await store.LoadAsync(cancelledInitial.CaseId))!.Revision == 1);

        // An already-existing missing record is not disposable: it might be damaged history.
        string existingRoot = Path.Combine(root, "v031-existing-incomplete-" + Guid.NewGuid().ToString("N"));
        RemediationCaseStore existingStore = new(existingRoot, () => sid);
        RemediationCaseRecord existing = new() { UserSid = sid };
        string existingDirectory = Path.Combine(existingRoot, existing.CaseId.ToString("N"));
        Directory.CreateDirectory(existingDirectory);
        string foreign = Path.Combine(existingDirectory, "foreign-evidence.txt");
        await File.WriteAllTextAsync(foreign, "preserve incomplete prior history");
        using (CancellationTokenSource cancelled = new())
        {
            cancelled.Cancel();
            try { await existingStore.SaveAsync(existing, cancelled.Token); }
            catch (OperationCanceledException) { }
        }
        Check("大病例 首次失败清理不删除已有目录或外来文件", await File.ReadAllTextAsync(foreign) == "preserve incomplete prior history" &&
            (await existingStore.ListAsync()).Single().ReadStatus == DiagnosticReadStatus.NotChecked);

        // The hash-based chunk filename alone can push normal AppData/temp paths beyond MAX_PATH.
        // Exercise both long chunk names and native directory/lock opens; do not shorten fixtures.
        string longRoot = Path.Combine(root, "v031-long-case-" + Guid.NewGuid().ToString("N"));
        while (longRoot.Length < 310) longRoot = Path.Combine(longRoot, new string('p', 40));
        RemediationCaseStore longStore = new(longRoot, () => sid);
        RemediationPlan longPlan = new() { RequestedBySid = sid };
        RemediationCaseRecord longCase = new()
        {
            UserSid = sid,
            Plans = [longPlan],
            PendingPlanIds = [longPlan.PlanId],
            OriginalScan = new() { Findings = [new() { Title = "long path metadata survives" }] }
        };
        await longStore.SaveAsync(longCase);
        RemediationCaseRecord longLoaded = (await longStore.LoadAsync(longCase.CaseId))!;
        Check("大病例 超过MAX_PATH的目录和分片可以完整读取", longRoot.Length > 260 &&
            longLoaded.OriginalScan!.Findings.Single().Title == "long path metadata survives" &&
            (await longStore.GetRecoveryPlansAsync(longCase.CaseId)).Single().PlanId == longPlan.PlanId &&
            await longStore.ContainsPlanAsync(longCase.CaseId, longPlan.PlanId));
        longLoaded.Notes.Add("long path update");
        await longStore.SaveAsync(longLoaded);
        Check("大病例 超长路径更新索引和回收均保持可用", (await longStore.LoadAsync(longCase.CaseId))!.Notes.Single() == "long path update" &&
            (await longStore.ListAsync()).Single().Revision == 2 &&
            Directory.GetFiles(Path.Combine(longRoot, longCase.CaseId.ToString("N")), "case-part-*.jsonpart").Length == 1);
        bool devicePathRejected = false;
        try { LocalNativePath.Encode(@"\\?\C:\InertCase\case.json"); }
        catch (ArgumentException) { devicePathRejected = true; }
        Check("大病例 长路径编码不放宽调用者设备路径限制", devicePathRejected);

        // One hundred thousand benign metadata nodes, not files or executable payloads. The
        // report exceeds BOTH the old 64 MiB serialized ceiling and its display-character sum.
        const int nodes = 100_001;
        string evidence = new('x', 700);
        MessageText format = MessageText.Create("Backend.Concat", evidence, "");
        ScanReport report = new() { Containers = new(), ContentScanSettings = new() { MaximumReportTextCharacters = 128L * 1024 * 1024 } };
        for (int i = 0; i < nodes; i++)
            report.Containers.Nodes.Add(new()
            {
                DisplayPath = @"C:\InertLargeCase\metadata-" + i + ".txt",
                OriginalTarget = @"C:\InertLargeCase\never-read.txt",
                FormatText = format,
                Length = i,
                Overall = ContainerStageStatus.Complete
            });
        RemediationPlan plan = new()
        {
            RequestedBySid = sid,
            Actions = [new() { Type = RemediationActionType.QuarantineFile, Target = @"C:\InertLargeCase\never-execute.txt", ExpectedSha256 = new string('A', 64) }]
        };
        RemediationCaseRecord record = new() { UserSid = sid, OriginalScan = report, Plans = [plan], PendingPlanIds = [plan.PlanId] };
        await store.SaveAsync(record);
        string casePath = Path.Combine(directory, record.CaseId.ToString("N"), "case.json");
        var manifest = JsonSerializer.Deserialize<RemediationCaseChunks.Manifest>(await File.ReadAllTextAsync(casePath), JsonFile.Options)!;
        Check("大病例 100001节点超过64MiB但使用有界分片完整保存", manifest.TotalBytes > RemediationCaseStore.MaximumCaseBytes &&
            manifest.Parts.Count > 8 && new FileInfo(casePath).Length < RemediationCaseChunks.MaximumManifestBytes);
        Check("大病例 恢复查找跳过大型报告而仍保留待处理计划", (await store.GetRecoveryPlansAsync(record.CaseId)).Single().PlanId == plan.PlanId &&
            await store.ContainsPlanAsync(record.CaseId, plan.PlanId) && !await store.ContainsPlanAsync(record.CaseId, Guid.NewGuid()));
        RemediationCaseRecord restored = (await store.LoadAsync(record.CaseId))!;
        Check("大病例 重新打开保留首尾节点和原始显示证据", restored.OriginalScan!.Containers!.Nodes.Count == nodes &&
            restored.OriginalScan.Containers.Nodes[0].NodeId == report.Containers.Nodes[0].NodeId &&
            restored.OriginalScan.Containers.Nodes[^1].NodeId == report.Containers.Nodes[^1].NodeId &&
            restored.OriginalScan.Containers.Nodes[^1].Format == format.OriginalText &&
            JsonSerializer.Serialize(restored.OriginalScan.Containers.Nodes[^1].FormatMessage) == JsonSerializer.Serialize(format.Message) &&
            restored.Plans[0].Actions[0].Target == plan.Actions[0].Target);

        string longSummary = new('测', 20_000);
        restored.Episodes.Add(new()
        {
            Summary = longSummary,
            State = CaseReverificationState.Incomplete,
            ContentFollowUp = new() { Findings = [new() { Title = "inert independent follow-up" }] }
        });
        await store.SaveAsync(restored);
        RemediationCaseRecord updated = (await store.LoadAsync(record.CaseId))!;
        Check("大病例 更新修订保留原报告和完整长摘要", updated.Revision == 2 && updated.OriginalScan!.Containers!.Nodes.Count == nodes &&
            updated.Episodes.Single().Summary == longSummary && updated.Episodes.Single().ContentFollowUp!.Findings.Single().Title == "inert independent follow-up");
        Check("大病例 小显示索引不再因长摘要阻断保存", (await store.ListAsync()).Single(summary => summary.CaseId == record.CaseId).Detail.Length <= 1024 &&
            new FileInfo(Path.Combine(Path.GetDirectoryName(casePath)!, "summary.json")).Length < 32 * 1024);

        // Hold the committed manifest against replacement to force failure only at commit, after
        // pieces were written. Both the previous revision and the caller's revision stay intact.
        updated.Notes.Add("inert interrupted update");
        bool interrupted = false;
        await using (FileStream lease = new(casePath, FileMode.Open, FileAccess.Read, FileShare.Read))
        {
            try { await store.SaveAsync(updated); }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { interrupted = true; }
        }
        Check("大病例 提交失败保留旧修订和全部分片", interrupted && updated.Revision == 2 &&
            (await store.LoadAsync(record.CaseId)) is { Revision: 2 } previous && !previous.Notes.Contains("inert interrupted update"));
        // A following successful save reclaims both prior-revision pieces and the failed write's
        // unreferenced pieces, so repeated updates do not add eight MiB per plan forever.
        updated.Notes.Remove("inert interrupted update");
        await store.SaveAsync(updated);
        var currentManifest = JsonSerializer.Deserialize<RemediationCaseChunks.Manifest>(await File.ReadAllTextAsync(casePath), JsonFile.Options)!;
        string[] currentParts = Directory.GetFiles(Path.GetDirectoryName(casePath)!, "case-part-*.jsonpart");
        Check("大病例 成功重试回收旧修订和失败写入分片", currentParts.Length == currentManifest.Parts.Select(part => part.Sha256).Distinct().Count() &&
            currentParts.Sum(path => new FileInfo(path).Length) <= currentManifest.TotalBytes);

        string exported = Path.Combine(directory, "large-case-export.zip");
        await CaseBundleExporter.ExportAsync(exported, new(), null, null, null, persistedCase: restored);
        using (ZipArchive zip = ZipFile.OpenRead(exported))
        await using (Stream stream = zip.GetEntry("remediation-case.json")!.Open())
        {
            RemediationCaseRecord exportedRecord = (await JsonSerializer.DeserializeAsync<RemediationCaseRecord>(stream, JsonFile.Options))!;
            Check("大病例 导出仍是完整普通JSON而非内部存储引用", exportedRecord.OriginalScan!.Containers!.Nodes.Count == nodes &&
                exportedRecord.Episodes.Single().Summary == longSummary && exportedRecord.Plans[0].Actions[0].ActionId == plan.Actions[0].ActionId);
        }

        // Small independent cases keep corruption tests fast and avoid repeated large allocations.
        RemediationPlan legacyPending = new() { RequestedBySid = sid }, legacyUnknown = new() { RequestedBySid = sid };
        RemediationCaseRecord legacy = new()
        {
            UserSid = sid,
            Revision = 1,
            Notes = ["legacy inline"],
            Plans = [legacyPending, legacyUnknown],
            PendingPlanIds = [legacyPending.PlanId],
            ExecutionResults = [new() { PlanId = legacyUnknown.PlanId, Disposition = RemediationRunDisposition.ExecutionUnknown }]
        };
        string legacyDirectory = Path.Combine(directory, legacy.CaseId.ToString("N"));
        Directory.CreateDirectory(legacyDirectory);
        string legacyPath = Path.Combine(legacyDirectory, "case.json");
        await File.WriteAllTextAsync(legacyPath, JsonSerializer.Serialize(legacy, JsonFile.Options));
        RemediationCaseRecord legacyLoaded = (await store.LoadAsync(legacy.CaseId))!;
        Check("大病例 兼容读取旧版内联JSON", legacyLoaded.Notes.Single() == "legacy inline" && legacyLoaded.Revision == 1);
        Check("大病例 旧版内联待处理和执行未知计划均进入恢复", (await store.GetRecoveryPlansAsync(legacy.CaseId))
            .Select(item => item.PlanId).ToHashSet().SetEquals([legacyPending.PlanId, legacyUnknown.PlanId]));
        await store.SaveAsync(legacyLoaded);
        Check("大病例 旧病例更新原子迁移且修订连续", (await store.LoadAsync(legacy.CaseId))!.Revision == 2 &&
            (await File.ReadAllTextAsync(legacyPath)).Contains(RemediationCaseChunks.Format, StringComparison.Ordinal));
        using (FileStream readerLease = new(Path.Combine(legacyDirectory, "case.lock"), FileMode.Open, FileAccess.Read, FileShare.Read))
        {
            bool writerDenied = false;
            try { await store.SaveAsync(legacyLoaded); }
            catch (System.ComponentModel.Win32Exception ex) when (ex.NativeErrorCode == 32) { writerDenied = true; }
            Check("大病例 活跃读者阻止写入和分片回收", writerDenied && legacyLoaded.Revision == 2 && (await store.LoadAsync(legacy.CaseId))!.Revision == 2);
        }
        using (FileStream writerLease = new(Path.Combine(legacyDirectory, "case.lock"), FileMode.Open, FileAccess.ReadWrite, FileShare.None))
        {
            bool loadDenied = false, recoveryDenied = false;
            try { await store.LoadAsync(legacy.CaseId); }
            catch (System.ComponentModel.Win32Exception ex) when (ex.NativeErrorCode == 32) { loadDenied = true; }
            try { await store.GetRecoveryPlansAsync(legacy.CaseId); }
            catch (System.ComponentModel.Win32Exception ex) when (ex.NativeErrorCode == 32) { recoveryDenied = true; }
            Check("大病例 写入锁阻止普通读取及恢复读取", loadDenied && recoveryDenied);
        }
        string untouched = Path.Combine(legacyDirectory, "case-part-unrelated.jsonpart");
        await File.WriteAllTextAsync(untouched, "not an owned chunk filename");
        for (int i = 0; i < 3; i++) { legacyLoaded.Notes.Add("inert revision " + i); await store.SaveAsync(legacyLoaded); }
        Check("大病例 多次更新保持当前分片磁盘大小且不删其他文件", Directory.GetFiles(legacyDirectory, "case-part-*.jsonpart").Length == 2 &&
            await File.ReadAllTextAsync(untouched) == "not an owned chunk filename");
        string goodManifest = await File.ReadAllTextAsync(legacyPath);
        var small = JsonSerializer.Deserialize<RemediationCaseChunks.Manifest>(goodManifest, JsonFile.Options)!;
        string partPath = RemediationCaseChunks.PartPath(legacyDirectory, small.Parts[0]);
        byte[] goodPart = await File.ReadAllBytesAsync(partPath);

        async Task<bool> RejectedAsync()
        {
            try { await store.LoadAsync(legacy.CaseId); return false; }
            catch (Exception ex) when (ex is InvalidDataException or JsonException or System.ComponentModel.Win32Exception or UnauthorizedAccessException) { return true; }
        }
        async Task ProbeManifestAsync(string name, RemediationCaseChunks.Manifest bad)
        {
            await File.WriteAllTextAsync(legacyPath, JsonSerializer.Serialize(bad, JsonFile.Options));
            Check(name, await RejectedAsync());
            await File.WriteAllTextAsync(legacyPath, goodManifest);
        }
        await File.WriteAllTextAsync(legacyPath, goodManifest.Replace("\"StorageFormat\":", "\"StorageFormat\":\"ignored-duplicate\",\"StorageFormat\":", StringComparison.Ordinal));
        Check("大病例 清单重复字段不允许覆盖先前值", await RejectedAsync());
        await File.WriteAllTextAsync(legacyPath, goodManifest.Replace("\"StorageFormat\"", "\"storageformat\"", StringComparison.Ordinal)
            .Replace("\"Parts\":", "\"UserSid\":\"" + sid + "\",\"Parts\":", StringComparison.Ordinal));
        Check("大病例 格式字段大小写变体不能绕过分片验证", await RejectedAsync());
        await File.WriteAllTextAsync(legacyPath, goodManifest.Replace("\"StorageFormat\": \"" + RemediationCaseChunks.Format + "\",", "\"UserSid\":\"" + sid + "\",", StringComparison.Ordinal));
        Check("大病例 缺少格式字段的分片清单不能冒充旧版病例", await RejectedAsync());
        await File.WriteAllTextAsync(legacyPath, "[]");
        Check("大病例 数组根不被当作病例对象", await RejectedAsync());
        await File.WriteAllTextAsync(legacyPath, "null");
        Check("大病例 空根不被当作病例对象", await RejectedAsync());
        await File.WriteAllTextAsync(legacyPath, goodManifest);
        await ProbeManifestAsync("大病例 分片路径不接受目录穿越", new()
        {
            CaseId = small.CaseId,
            Revision = small.Revision,
            TotalBytes = small.TotalBytes,
            Parts = [new(0, small.Parts[0].Bytes, "../" + new string('A', 61))]
        });
        await ProbeManifestAsync("大病例 分片顺序索引必须唯一连续", new()
        {
            CaseId = small.CaseId,
            Revision = small.Revision,
            TotalBytes = small.TotalBytes,
            Parts = [small.Parts[0] with { Index = 1 }]
        });
        await ProbeManifestAsync("大病例 分片总大小必须精确匹配", new() { CaseId = small.CaseId, Revision = small.Revision, TotalBytes = small.TotalBytes + 1, Parts = small.Parts });
        await ProbeManifestAsync("大病例 总输入上限在读取分片前验证", new() { CaseId = small.CaseId, Revision = small.Revision, TotalBytes = RemediationCaseStore.MaximumStoredCaseBytes + 1, Parts = small.Parts });
        await ProbeManifestAsync("大病例 缺失分片不能接受不完整报告", new()
        {
            CaseId = small.CaseId,
            Revision = small.Revision,
            TotalBytes = small.TotalBytes,
            Parts = [small.Parts[0] with { Sha256 = new string('F', 64) }]
        });

        byte[] changed = (byte[])goodPart.Clone(); changed[changed.Length / 2] ^= 1;
        await File.WriteAllBytesAsync(partPath, changed);
        Check("大病例 内容变动即使长度不变仍拒绝", await RejectedAsync());
        bool recoveryRejected = false;
        try { await store.GetRecoveryPlansAsync(legacy.CaseId); }
        catch (InvalidDataException) { recoveryRejected = true; }
        Check("大病例 恢复读取也核验全部分片哈希", recoveryRejected);
        await File.WriteAllBytesAsync(partPath, goodPart[..^1]);
        Check("大病例 截断分片拒绝", await RejectedAsync());
        await File.WriteAllBytesAsync(partPath, goodPart);
        byte[] trailing = [.. goodPart, .. Encoding.UTF8.GetBytes("{}")];
        var extra = new RemediationCaseChunks.Part(0, trailing.Length, Convert.ToHexString(SHA256.HashData(trailing)));
        await File.WriteAllBytesAsync(RemediationCaseChunks.PartPath(legacyDirectory, extra), trailing);
        await ProbeManifestAsync("大病例 校验通过但尾随额外JSON仍拒绝", new() { CaseId = small.CaseId, Revision = small.Revision, TotalBytes = trailing.Length, Parts = [extra] });
        Check("大病例 损坏尝试后原始完好修订仍可读取", (await store.LoadAsync(legacy.CaseId))!.Notes[0] == "legacy inline");
    }
}
