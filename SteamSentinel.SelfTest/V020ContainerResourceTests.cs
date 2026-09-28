using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Text.Json;
using SteamSentinel.App.Services;
using SteamSentinel.Core.Inspection;
using SteamSentinel.Core.Models;
using SteamSentinel.Core.Scanning;
using SteamSentinel.Core.Utilities;

namespace SteamSentinel.SelfTest;

internal static partial class Program
{
    // Only synthetic streams, generated inert bytes and this self-test's existing worker fixture
    // are used here. No archive sample or recovered content is launched.
    public static async Task TestV020ContainerResourcesAsync(string root)
    {
        await TestV020BoundedRangesAsync();
        TestV020ResourceAccounting();
        await TestV020TemporaryAccountingAsync();
        TestV020ContainerFragments();
        TestV020ContainerRequestOptions(root);
        await TestV020RecoverySafetyAsync(root);
        await TestV020WorkerHardTimeoutAsync(root);
    }

    private static async Task TestV020BoundedRangesAsync()
    {
        const long gib = 1024L * 1024 * 1024;
        byte[] buffer = new byte[16];
        foreach (long boundary in new[] { gib, 2 * gib, 4 * gib })
        {
            foreach (int delta in new[] { -1, 0, 1 })
            {
                long value = boundary + delta;
                using V020VirtualStream source = new(9 * gib + 64);
                using BoundedReadOnlyStream view = new(source, value, value);
                view.Seek(-1, SeekOrigin.End);
                int tailRead = await view.ReadAsync(buffer.AsMemory());
                bool tail = tailRead == 1 && buffer[0] == V020VirtualStream.ByteAt(2 * value - 1) && view.Position == value;
                bool eof = view.Read(buffer) == 0 && source.ReadCalls == 1;
                view.Seek(0, SeekOrigin.Begin);
                int headRead = view.Read(buffer);
                bool head = headRead == buffer.Length && buffer[0] == V020VirtualStream.ByteAt(value) && view.Position == buffer.Length;
                bool range = source.MinimumReadPosition == value && source.MaximumReadEnd == 2 * value &&
                    source.BytesRead == buffer.Length + 1 && source.LargestReadRequest <= buffer.Length;
                long position = view.Position;
                bool refuses = V020Throws<IOException>(() => view.Seek(value + 1, SeekOrigin.Begin)) &&
                    V020Throws<IOException>(() => view.Seek(-1, SeekOrigin.Begin)) &&
                    V020Throws<OverflowException>(() => view.Seek(long.MaxValue, SeekOrigin.Current)) && view.Position == position;
                Check($"0.2.0 64位范围与偏移 {boundary / gib} GiB {delta:+0;-0;0} 无大分配及越界读取", tail && eof && head && range && refuses);
            }
        }
        using V020VirtualStream huge = new(long.MaxValue);
        Check("0.2.0 范围相加溢出在读取前拒绝", V020Throws<ArgumentOutOfRangeException>(() =>
            new BoundedReadOnlyStream(huge, long.MaxValue - 2, 4)) && huge.ReadCalls == 0);
        using BoundedReadOnlyStream outer = new(huge, 4 * gib + 1, 64);
        using (BoundedReadOnlyStream inner = new(outer, 17, 3))
        {
            Check("0.2.0 嵌套范围保持父项相对偏移", inner.Read(buffer) == 3 && buffer[0] == V020VirtualStream.ByteAt(4 * gib + 18) &&
                inner.Read(buffer) == 0 && huge.MinimumReadPosition == 4 * gib + 18 && huge.MaximumReadEnd == 4 * gib + 21);
            Check("0.2.0 受限流拒绝写入和改变长度", !inner.CanWrite &&
                V020Throws<NotSupportedException>(() => inner.Write(buffer, 0, 1)) && V020Throws<NotSupportedException>(() => inner.SetLength(0)));
        }
        Check("0.2.0 子范围释放保留借用源流", outer.CanRead && huge.CanRead);
        using CancellationTokenSource cancelled = new();
        cancelled.Cancel();
        long readBefore = huge.BytesRead;
        Check("0.2.0 范围读取取消在触碰源流前生效", await V020ThrowsAsync<OperationCanceledException>(async () =>
            _ = await outer.ReadAsync(buffer.AsMemory(), cancelled.Token)) && huge.BytesRead == readBefore);
        ContainerResourceBudget limited = new(new() { MaximumWorkBytes = 3 });
        using V020VirtualStream chargedSource = new(16);
        using BoundedReadOnlyStream charged = new(chargedSource, 2, 8, budget: limited);
        int allowed = await charged.ReadAsync(buffer.AsMemory());
        Check("0.2.0 受限流按实际返回字节收费并在耗尽后不多读一字节", allowed == 3 && limited.Snapshot().ReadBytes == 3 &&
            V020Throws<ScanResourceLimitException>(() => _ = charged.Read(buffer)) && chargedSource.BytesRead == 3 && charged.Position == 3);
    }

    private static void TestV020ResourceAccounting()
    {
        ContainerResourceBudget budget = new(new() { MaximumWorkBytes = 96, MaximumExpandedBytes = 48, MaximumTemporaryBytes = 32 });
        budget.ChargeRead(20);
        budget.ChargeDecoded(10);
        budget.AcceptExpansion(30);
        long checkpoint = budget.AcceptedExpandedBytes;
        budget.ChargeRead(13);
        budget.ChargeDecoded(7);
        budget.AcceptExpansion(8);
        budget.ChargeRangeCopy(8);
        budget.ChargePasswordAttempt();
        budget.ChargeMetadata();
        budget.RestoreLogicalExpansion(checkpoint);
        ContainerResourceSnapshot after = budget.Snapshot();
        Check("0.2.0 密码重试回滚只退逻辑展开量保留真实读取和解码消耗", after.ReadBytes == 33 && after.DecodedBytes == 17 &&
            after.AcceptedExpandedBytes == 30 && after.RangeCopyBytes == 8 && after.PasswordAttempts == 1 && after.MetadataAttempts == 1 &&
            budget.RemainingWorkBytes == 46 && budget.ReadAllowance(128) == 46);
        Check("0.2.0 逻辑回滚拒绝负值和前移检查点", V020Throws<ArgumentOutOfRangeException>(() => budget.RestoreLogicalExpansion(-1)) &&
            V020Throws<ArgumentOutOfRangeException>(() => budget.RestoreLogicalExpansion(31)) && budget.AcceptedExpandedBytes == 30);
        budget.ChargeRead(46);
        Check("0.2.0 已消耗预算在重试回滚后仍会耗尽", budget.RemainingWorkBytes == 0 &&
            V020Throws<ScanResourceLimitException>(() => budget.ChargeDecoded(1)) && V020Throws<ScanResourceLimitException>(() => budget.ReadAllowance(1)) &&
            budget.Snapshot().ReadBytes == 79 && budget.Snapshot().DecodedBytes == 18);
        ContainerResourceBudget native = new(new() { MaximumWorkBytes = 20 });
        native.ChargeRead(5); native.ReserveNativeRead(8); native.AcceptExpansion(4); native.RestoreLogicalExpansion(0);
        Check("0.2.0 原生检查预留计入总预算且不随逻辑回滚退还", native.Snapshot().NativeReservedReadBytes == 8 &&
            native.Snapshot().ReadBytes == 5 && native.RemainingWorkBytes == 7 && native.ReadAllowance(100) == 7 &&
            V020Throws<ScanResourceLimitException>(() => native.ReserveNativeRead(8)) && native.Snapshot().NativeReservedReadBytes == 8);
        ContainerResourceBudget attempts = new(new() { MaximumPasswordAttempts = 1, MaximumMetadataAttempts = 1 });
        attempts.ChargePasswordAttempt(); attempts.ChargeMetadata();
        Check("0.2.0 元数据与密码失败尝试也受累计上限约束", V020Throws<ScanResourceLimitException>(attempts.ChargePasswordAttempt) &&
            V020Throws<ScanResourceLimitException>(attempts.ChargeMetadata) && attempts.Snapshot().PasswordAttempts == 2 && attempts.Snapshot().MetadataAttempts == 2);
        Check("0.2.0 资源配置拒绝无穷比率零时间和超64位声明上限",
            V020Throws<ArgumentOutOfRangeException>(() => new ContainerResourceBudget(new() { MaximumCompressionRatio = double.PositiveInfinity })) &&
            V020Throws<ArgumentOutOfRangeException>(() => new ContainerResourceBudget(new() { MaximumDurationSeconds = 0 })) &&
            V020Throws<ArgumentOutOfRangeException>(() => new ContainerResourceBudget(new() { MaximumEntryBytes = long.MaxValue })) &&
            V020Throws<ArgumentNullException>(() => ContainerResourceBudget.Validate(null!)));
        using CancellationTokenSource cancellation = new();
        ContainerResourceBudget cancelled = new(new(), cancellation.Token);
        cancellation.Cancel();
        Check("0.2.0 取消预算拒绝新的读取与预留", V020Throws<OperationCanceledException>(() => cancelled.ReadAllowance(1)) &&
            V020Throws<OperationCanceledException>(() => cancelled.ReserveTemporary(1)) && cancelled.Snapshot().CurrentTemporaryBytes == 0);
    }

    private static async Task TestV020TemporaryAccountingAsync()
    {
        ContainerResourceBudget budget = new(new() { MaximumTemporaryBytes = 24, ReservedDiskBytes = 0 });
        string directory;
        using (ContainerTemporaryStore store = new(budget))
        {
            directory = store.Path;
            ContainerTemporaryFile first = store.CreateFile();
            string firstPath = first.Path;
            await first.WriteAsync(new byte[16], CancellationToken.None);
            Check("0.2.0 临时内容仅用受控编号scan文件并按真实写入收费", Path.GetExtension(firstPath) == ".scan" &&
                Path.GetDirectoryName(firstPath) == store.Path && first.Length == 16 && budget.Snapshot().CurrentTemporaryBytes == 16);
            Check("0.2.0 临时限额在写入前拒绝且保持原计账", await V020ThrowsAsync<ScanResourceLimitException>(async () =>
                await first.WriteAsync(new byte[9], CancellationToken.None)) && first.Length == 16 && budget.Snapshot().CurrentTemporaryBytes == 16);
            using CancellationTokenSource cancelled = new();
            cancelled.Cancel();
            Check("0.2.0 取消临时写入不预留空间不增加文件长度", await V020ThrowsAsync<OperationCanceledException>(async () =>
                await first.WriteAsync(new byte[8], cancelled.Token)) && first.Length == 16 && budget.Snapshot().CurrentTemporaryBytes == 16);
            await first.WriteAsync(new byte[8], CancellationToken.None);
            await first.SealAsync();
            bool canonicalRead = false, rejectsWrongIdentity = false;
            try
            {
                using FileStream locked = RelatedArtifactReader.Open(firstPath);
                RelatedArtifactReader.ValidatePath(locked.SafeFileHandle, Path.GetFullPath(firstPath));
                canonicalRead = locked.Length == 24 && locked.ReadByte() == 0;
                rejectsWrongIdentity = V020Throws<UnauthorizedAccessException>(() => RelatedArtifactReader.ValidatePath(locked.SafeFileHandle,
                    Path.Combine(store.Path, "different-inert-file.scan")));
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { }
            Check("0.2.0 自有临时文件使用物理路径通过严格只读句柄校验", canonicalRead);
            Check("0.2.0 临时物理路径处理仍拒绝不同文件的路径身份", rejectsWrongIdentity);
            Check("0.2.0 封闭临时内容长度可读且不再接受写入", new FileInfo(firstPath).Length == 24 &&
                await V020ThrowsAsync<InvalidOperationException>(async () => await first.WriteAsync(new byte[1], CancellationToken.None)));
            first.Dispose(); first.Dispose();
            Check("0.2.0 临时删除成功后释放当前占用且保留峰值", !File.Exists(firstPath) &&
                budget.Snapshot().CurrentTemporaryBytes == 0 && budget.Snapshot().PeakTemporaryBytes == 24);
            ContainerTemporaryFile second = store.CreateFile();
            await second.WriteAsync(new byte[24], CancellationToken.None);
            Check("0.2.0 删除后的空间可供下一个条目复用", second.Path != firstPath && budget.Snapshot().CurrentTemporaryBytes == 24);
        }
        Check("0.2.0 临时作用域退出删除所有自有文件并结清计账", !Directory.Exists(directory) &&
            budget.Snapshot().CurrentTemporaryBytes == 0 && budget.Snapshot().PeakTemporaryBytes == 24);

        ContainerResourceBudget retained = new(new() { MaximumTemporaryBytes = 24, ReservedDiskBytes = 0 });
        using (ContainerTemporaryStore store = new(retained))
        {
            ContainerTemporaryFile file = store.CreateFile();
            await file.WriteAsync(new byte[12], CancellationToken.None);
            await file.SealAsync();
            using (FileStream held = new(file.Path, FileMode.Open, FileAccess.Read, FileShare.Read))
            {
                file.Dispose();
                Check("0.2.0 临时删除被占用拒绝时继续计入真实占用", File.Exists(file.Path) && retained.Snapshot().CurrentTemporaryBytes == 12 && held.Length == 12);
            }
        }
        Check("0.2.0 临时删除释放占用后作用域重试结清计账", retained.Snapshot().CurrentTemporaryBytes == 0 && retained.Snapshot().PeakTemporaryBytes == 12);
        Console.WriteLine("V020_WORKSPACE_PROBE=create");
        await using (WorkerWorkspace workspace = new())
        {
            Console.WriteLine("V020_WORKSPACE_PROBE=created");
            string recovery = Path.Combine(workspace.Path, "recovery");
            Directory.CreateDirectory(recovery);
            Console.WriteLine("V020_WORKSPACE_PROBE=directory-created");
            string path = Path.Combine(recovery, "inert-path-probe.scan");
            await File.WriteAllBytesAsync(path, [1, 2, 3]);
            Console.WriteLine("V020_WORKSPACE_PROBE=written");
            bool readable = false;
            try
            {
                using FileStream locked = RelatedArtifactReader.Open(path);
                Console.WriteLine("V020_WORKSPACE_PROBE=opened");
                RelatedArtifactReader.ValidatePath(locked.SafeFileHandle, Path.GetFullPath(path));
                Console.WriteLine("V020_WORKSPACE_PROBE=validated");
                readable = locked.Length == 3 && locked.ReadByte() == 1;
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { }
            Check("0.2.0 Worker会话及恢复子目录保持真实物理根和严格路径身份", readable &&
                string.Equals(Path.GetDirectoryName(workspace.Path), OwnedDirectoryPhysicalPath.ResolveForCreation(AppPaths.WorkerTemporaryRoot),
                    StringComparison.OrdinalIgnoreCase));
        }
        Console.WriteLine("V020_WORKSPACE_PROBE=disposed");
    }

    private static void TestV020ContainerFragments()
    {
        JsonSerializerOptions wireOptions = new(JsonFile.Options) { WriteIndented = false };
        ScanReport source = new() { Mode = ScanMode.Full, Coverage = ScanCoverage.Complete, CompletedAtUtc = DateTimeOffset.UtcNow, Containers = new() };
        ContainerScanNode parent = V020Node("inert.zip");
        ContainerScanNode child = V020Node("inert.zip!/payload.bin", parent.NodeId, 1);
        source.Containers.Nodes.AddRange([parent, child]);
        List<ReportBatch> frames = [];
        ReportBatchReader reader = new();
        int maximumFrame = 0;
        ReportBatchWriter writer = new(batch =>
        {
            string wire = JsonSerializer.Serialize(new WorkerMessage { Type = WorkerMessageTypes.Checkpoint, Batch = batch }, wireOptions);
            maximumFrame = Math.Max(maximumFrame, wire.Length);
            ReportBatch copy = JsonSerializer.Deserialize<WorkerMessage>(wire, wireOptions)!.Batch!;
            frames.Add(copy); reader.Apply(copy);
        });
        writer.Send(source);
        Check("0.2.0 容器检查点在footer之前保留部分结果", reader.HasIncompleteContainers && reader.Report is
        { Coverage: ScanCoverage.Partial, CompletedAtUtc: null, Containers.Complete: false } && reader.Report.Containers.Nodes.Count == 2);
        parent.Revision++; parent.Overall = ContainerStageStatus.Complete; parent.ContentCheck = ContainerStageStatus.Complete;
        parent.Integrity = ContainerStageStatus.Complete;
        child.Revision++; child.Overall = ContainerStageStatus.Complete; child.ContentCheck = ContainerStageStatus.Complete;
        child.Integrity = ContainerStageStatus.Complete;
        source.Containers.Complete = true;
        writer.Send(source, final: true);
        Check("0.2.0 节点修订分片及最终footer完整往返", reader.Count == writer.Count && !reader.HasIncompleteContainers &&
            reader.Report is { Coverage: ScanCoverage.Complete, Containers.Complete: true } && reader.Report.CompletedAtUtc == source.CompletedAtUtc &&
            JsonSerializer.Serialize(reader.Report.Containers, wireOptions) == JsonSerializer.Serialize(source.Containers, wireOptions));
        Check("0.2.0 容器数据只通过单节点有界分片传输", maximumFrame < 1024 * 1024 && frames.All(f => f.Data.Containers is null) &&
            frames.Count(f => f.ContainerFragment?.IsFinal == true) == 1);

        Guid scanId = Guid.NewGuid();
        ContainerScanMetadata Metadata(int total, bool complete = false) => new(total, complete, new(), new(), [], null);
        ReportBatch Frame(ReportBatchReader target, ContainerScanFragment fragment) => new(target.Count, new(0, 0, 0, 0, 0, 0, 0),
            new ScanReport
            {
                ScanId = scanId,
                Coverage = ScanCoverage.Complete,
                CompletedAtUtc = DateTimeOffset.UtcNow,
                Findings = [new() { Title = "Rejected changes must not be committed" }]
            })
        { ContainerFragment = fragment };
        bool RejectsWithoutMutation(ReportBatchReader target, ContainerScanFragment fragment)
        {
            string before = JsonSerializer.Serialize(target.Report, wireOptions);
            int count = target.Count;
            return V020Throws<InvalidDataException>(() => target.Apply(Frame(target, fragment))) && target.Count == count &&
                JsonSerializer.Serialize(target.Report, wireOptions) == before;
        }
        ReportBatchReader missingParent = new();
        ContainerScanNode orphan = V020Node("inert.zip!/orphan", Guid.NewGuid(), 1);
        missingParent.Apply(Frame(missingParent, new(Metadata(1), 0, orphan, false)));
        Check("0.2.0 footer拒绝缺失父节点且不部分提交其他数据", RejectsWithoutMutation(missingParent, new(Metadata(1), 1, null, true)));
        ReportBatchReader missingNode = new();
        missingNode.Apply(Frame(missingNode, new(Metadata(2), 0, V020Node("inert.zip"), false)));
        Check("0.2.0 footer缺少声明节点时拒绝完整标记", RejectsWithoutMutation(missingNode, new(Metadata(2, true), 1, null, true)) && missingNode.HasIncompleteContainers);
        ReportBatchReader unfinished = new();
        unfinished.Apply(Frame(unfinished, new(Metadata(1), 0, V020Node("inert.zip"), false)));
        Check("0.2.0 pending节点不能通过footer声明全链完成", RejectsWithoutMutation(unfinished, new(Metadata(1, true), 1, null, true)));

        ReportBatchReader revisions = new();
        ContainerScanNode versioned = V020Node("inert.zip"); versioned.Revision = 3;
        revisions.Apply(Frame(revisions, new(Metadata(1), 0, versioned, false)));
        ContainerScanNode sameRevision = V020Node(versioned.DisplayPath, id: versioned.NodeId); sameRevision.Revision = 3;
        ContainerScanNode olderRevision = V020Node(versioned.DisplayPath, id: versioned.NodeId); olderRevision.Revision = 2;
        ContainerScanNode changedIdentity = V020Node("changed.zip", id: versioned.NodeId); changedIdentity.Revision = 4;
        Check("0.2.0 节点拒绝重复和倒退revision及改写来源身份", RejectsWithoutMutation(revisions, new(Metadata(1), 0, sameRevision, false)) &&
            RejectsWithoutMutation(revisions, new(Metadata(1), 0, olderRevision, false)) && RejectsWithoutMutation(revisions, new(Metadata(1), 0, changedIdentity, false)));
        ContainerScanNode newer = V020Node(versioned.DisplayPath, id: versioned.NodeId); newer.Revision = 4;
        revisions.Apply(Frame(revisions, new(Metadata(1), 0, newer, false)));
        Check("0.2.0 合法revision更新替换原节点而非重复添加", revisions.Report!.Containers!.Nodes.Count == 1 && revisions.Report.Containers.Nodes[0].Revision == 4);
        revisions.Apply(Frame(revisions, new(Metadata(1), 1, null, true)));
        Check("0.2.0 footer结束后拒绝追加节点", RejectsWithoutMutation(revisions, new(Metadata(2), 1, V020Node("late.zip"), false)));

        ReportBatchReader huge = new();
        ContainerScanNode oversized = V020Node(new string('x', 32769));
        Check("0.2.0 单节点路径超限在提交前拒绝", RejectsWithoutMutation(huge, new(Metadata(1), 0, oversized, false)) && huge.Report is null);
        ContainerScanNode escaped = V020Node(new string('界', 32768));
        escaped.Details.AddRange(Enumerable.Repeat(new string('界', 2048), 32));
        Check("0.2.0 单节点转义后序列化字节超限在提交前拒绝", RejectsWithoutMutation(huge, new(Metadata(1), 0, escaped, false)));
        ContainerScanNode bounded = V020Node(new string('界', 12000));
        bounded.Details.AddRange(Enumerable.Repeat(new string('界', 512), 16));
        huge.Apply(Frame(huge, new(Metadata(1), 0, bounded, false)));
        Check("0.2.0 合法较大节点保持有界并可传输", huge.Report!.Containers!.Nodes.Single().DisplayPath.Length == 12000 &&
            JsonSerializer.Serialize(new WorkerMessage { Type = WorkerMessageTypes.Checkpoint, Batch = Frame(new(), new(Metadata(1), 0, bounded, false)) }, wireOptions).Length < 1024 * 1024);
        Check("0.2.0 容器分片拒绝超过总节点上限的声明", RejectsWithoutMutation(new(), new(Metadata(ContainerScanReport.MaximumNodes + 1), 0, bounded, false)));
        Check("0.2.0 容器分片拒绝负原生读取预留", RejectsWithoutMutation(new(), new(Metadata(1) with
        { Resources = new() { NativeReservedReadBytes = -1 } }, 0, bounded, false)));
        ContainerScanMetadata lastBlock = Metadata(1) with
        {
            Limits = new() { MaximumWorkBytes = 16 },
            Resources = new() { ReadBytes = 16, DecodedBytes = 128 * 1024 }
        };
        ReportBatchReader overrun = new();
        overrun.Apply(Frame(overrun, new(lastBlock, 0, V020Node("budget-limited.zip"), false)));
        overrun.Apply(Frame(overrun, new(lastBlock, 1, null, true)));
        Check("0.2.0 部分footer保留最后已读块真实超额计账且不宣称扫描完成", !overrun.HasIncompleteContainers && overrun.Report is
        { Coverage: ScanCoverage.Partial, Containers.Complete: false } && overrun.Report.Containers.Resources.ReadBytes == 16 &&
            overrun.Report.Containers.Resources.DecodedBytes == 128 * 1024);
        Check("0.2.0 完整声明拒绝超预算且部分计账也不得超最后块容差",
            RejectsWithoutMutation(new(), new(lastBlock with { Complete = true }, 0, V020Node("bad-complete.zip"), false)) &&
            RejectsWithoutMutation(new(), new(lastBlock with { Resources = new() { ReadBytes = 16, DecodedBytes = 128 * 1024 + 1 } },
                0, V020Node("bad-overrun.zip"), false)));
    }

    private static ContainerScanNode V020Node(string path, Guid? parent = null, int depth = 0, Guid? id = null) => new()
    {
        NodeId = id ?? Guid.NewGuid(),
        ParentId = parent,
        Depth = depth,
        Kind = parent is null ? ContainerNodeKind.File : ContainerNodeKind.ArchiveMember,
        DisplayPath = path,
        OriginalTarget = "inert.zip",
        Length = 32,
        Format = "ZIP",
        Recognition = ContainerStageStatus.Complete
    };

    private static void TestV020ContainerRequestOptions(string root)
    {
        string expectedRecovery = Path.Combine(root, "v020-expected-recovery");
        string otherRecovery = Path.Combine(root, "v020-other-recovery");
        Directory.CreateDirectory(expectedRecovery); Directory.CreateDirectory(otherRecovery);
        ScanOptions original = new()
        {
            Mode = ScanMode.Full,
            InspectDeepSignatures = false,
            ContainerLimits = new() { MaximumDurationSeconds = 17 },
            SupplementalVolumeDirectories = [root],
            RecoveryOutputDirectory = otherRecovery,
            RelatedRoots = ["related"],
            RelatedSignaturePaths = ["signature"],
            WorkshopAppIds = ["431960"],
            CustomRoots = ["custom"],
            ExcludedRoots = ["excluded"]
        };
        ScanOptions worker = ArchiveWorkerClient.CopyOptions(original, expectedRecovery);
        ContainerRequestValidation.Validate(worker, expectedRecovery);
        ScanOptions replay = ArchiveWorkerClient.CopyOptions(original);
        Check("0.2.0 Worker选项只替换恢复目标并保留新容器配置", worker.RecoveryOutputDirectory == expectedRecovery &&
            original.RecoveryOutputDirectory == otherRecovery && !worker.InspectDeepSignatures && worker.ContainerLimits?.MaximumDurationSeconds == 17 &&
            worker.SupplementalVolumeDirectories.SequenceEqual(original.SupplementalVolumeDirectories) && replay.RecoveryOutputDirectory is null);
        original.SupplementalVolumeDirectories.Clear(); original.RelatedRoots.Clear(); original.RelatedSignaturePaths.Clear();
        original.WorkshopAppIds.Clear(); original.CustomRoots.Clear(); original.ExcludedRoots.Clear();
        Check("0.2.0 Worker选项快照与调用方可变路径列表分离", worker.SupplementalVolumeDirectories.Count == 1 &&
            worker.RelatedRoots.Count == 1 && worker.RelatedSignaturePaths.Count == 1 && worker.WorkshopAppIds.Count == 1 &&
            worker.CustomRoots.Count == 1 && worker.ExcludedRoots.Count == 1 && replay.SupplementalVolumeDirectories.Count == 1);
        Check("0.2.0 Worker拒绝直接写入用户目录及其他会话目标", V020Throws<InvalidDataException>(() =>
            ContainerRequestValidation.Validate(new() { RecoveryOutputDirectory = otherRecovery }, expectedRecovery)));
        Check("0.2.0 补充分卷目录拒绝相对路径网络路径和过量目录", V020Throws<InvalidDataException>(() =>
            ContainerRequestValidation.Validate(new() { SupplementalVolumeDirectories = ["relative"] })) &&
            V020Throws<InvalidDataException>(() => ContainerRequestValidation.Validate(new() { SupplementalVolumeDirectories = [@"\\server\share"] })) &&
            V020Throws<InvalidDataException>(() => ContainerRequestValidation.Validate(new()
            { SupplementalVolumeDirectories = Enumerable.Repeat(root, ContainerRequestValidation.MaximumSupplementalDirectories + 1).ToList() })));
    }

    private static async Task TestV020WorkerHardTimeoutAsync(string root)
    {
        Check("0.2.0 工作进程独立截止采用Quick五分钟与完整半小时并留结束宽限",
            ArchiveWorkerClient.ScanHardTimeout(new() { Mode = ScanMode.Quick }) == TimeSpan.FromSeconds(305) &&
            ArchiveWorkerClient.ScanHardTimeout(new() { Mode = ScanMode.Full }) == TimeSpan.FromSeconds(1805) &&
            ArchiveWorkerClient.ScanHardTimeout(new() { Mode = ScanMode.Custom }) == TimeSpan.FromSeconds(1805) &&
            ArchiveWorkerClient.ScanHardTimeout(new() { ContainerLimits = new() { MaximumDurationSeconds = 1 } }) == TimeSpan.FromSeconds(6));
        Check("0.2.0 工作进程启动前拒绝无效整轮截止配置", V020Throws<ArgumentOutOfRangeException>(() =>
            ArchiveWorkerClient.ScanHardTimeout(new() { ContainerLimits = new() { MaximumDurationSeconds = 4294961 } })));
        string directory = Path.Combine(root, "v020-deadline-fixture");
        Directory.CreateDirectory(directory);
        foreach (string file in Directory.EnumerateFiles(AppContext.BaseDirectory))
            File.Copy(file, Path.Combine(directory, Path.GetFileName(file)), true);
        // checkpointcancel is the existing inert fixture: it sends one checkpoint then ignores
        // stdin for 30 seconds. It does not inspect, unpack or execute any supplied input.
        string path = Path.Combine(directory, "SteamSentinelFixture-checkpointcancel.exe");
        File.Copy(Path.Combine(AppContext.BaseDirectory, "SteamSentinel.SelfTest.exe"), path);
        File.Copy(Path.Combine(AppContext.BaseDirectory, "SteamSentinel.SelfTest.dll"), Path.ChangeExtension(path, ".dll"));
        ScanOptions options = new()
        {
            Mode = ScanMode.Custom,
            IncludeSystem = false,
            IncludeSteam = false,
            IncludeWorkshop = false,
            UseAmsi = false,
            ContainerLimits = new() { MaximumDurationSeconds = 1 }
        };
        WorkerFailureException? failure = null;
        Stopwatch elapsed = Stopwatch.StartNew();
        try
        {
            await new ArchiveWorkerClient(path).RunAsync(options,
                (request, _) => Task.FromResult(new ArchivePasswordResponse(request.RequestId, true, null, false)), null, CancellationToken.None);
        }
        catch (WorkerFailureException ex) { failure = ex; }
        Check("0.2.0 独立硬截止终止不响应取消的扫描组件且不冒充完成", failure is
        {
            Stage: WorkerStage.Scanning, NativeExitCode: null, InnerException: TimeoutException,
            PartialReport.Coverage: ScanCoverage.Partial, PartialReport.CompletedAtUtc: null
        } &&
            failure.PartialReport.Metrics.FilesVisited == 4 && failure.PartialReport.Findings.Count == 1 && elapsed.Elapsed < TimeSpan.FromSeconds(15));
        bool exited = true;
        Process[] processes = Process.GetProcessesByName(Path.GetFileNameWithoutExtension(path));
        try
        {
            foreach (Process process in processes)
            {
                try { if (!process.HasExited && string.Equals(process.MainModule?.FileName, path, StringComparison.OrdinalIgnoreCase)) exited = false; }
                catch (Exception ex) when (ex is Win32Exception or InvalidOperationException) { if (!process.HasExited) exited = false; }
            }
        }
        finally { foreach (Process process in processes) process.Dispose(); }
        Check("0.2.0 硬截止返回前已清理所属受限进程", exited);
    }

    private static bool V020Throws<T>(Action action) where T : Exception
    {
        try { action(); return false; }
        catch (T) { return true; }
    }

    private static async Task<bool> V020ThrowsAsync<T>(Func<Task> action) where T : Exception
    {
        try { await action(); return false; }
        catch (T) { return true; }
    }

    private sealed class V020VirtualStream(long length) : Stream
    {
        private long _position;
        private bool _disposed;
        public long BytesRead { get; private set; }
        public int ReadCalls { get; private set; }
        public int LargestReadRequest { get; private set; }
        public long MinimumReadPosition { get; private set; } = long.MaxValue;
        public long MaximumReadEnd { get; private set; }
        public static byte ByteAt(long absolutePosition) => (byte)(absolutePosition % 251);
        public override bool CanRead => !_disposed;
        public override bool CanSeek => !_disposed;
        public override bool CanWrite => false;
        public override long Length => length;
        public override long Position { get => _position; set => Seek(value, SeekOrigin.Begin); }
        public override long Seek(long offset, SeekOrigin origin)
        {
            long next = origin switch
            {
                SeekOrigin.Begin => offset,
                SeekOrigin.Current => checked(_position + offset),
                SeekOrigin.End => checked(length + offset),
                _ => throw new ArgumentOutOfRangeException(nameof(origin))
            };
            if (next < 0 || next > length) throw new IOException("Synthetic source boundary exceeded.");
            return _position = next;
        }
        public override int Read(byte[] buffer, int offset, int count) => Read(buffer.AsSpan(offset, count));
        public override int Read(Span<byte> buffer)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            ReadCalls++; LargestReadRequest = Math.Max(LargestReadRequest, buffer.Length);
            int count = (int)Math.Min(buffer.Length, length - _position);
            MinimumReadPosition = Math.Min(MinimumReadPosition, _position);
            for (int i = 0; i < count; i++) buffer[i] = ByteAt(_position + i);
            _position += count; BytesRead += count; MaximumReadEnd = Math.Max(MaximumReadEnd, _position);
            return count;
        }
        public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return ValueTask.FromResult(Read(buffer.Span));
        }
        public override void Flush() { }
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
        protected override void Dispose(bool disposing) { _disposed = true; base.Dispose(disposing); }
    }
}
