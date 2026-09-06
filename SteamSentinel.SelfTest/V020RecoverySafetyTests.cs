using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.Win32.SafeHandles;
using SteamSentinel.App.Services;
using SteamSentinel.Core.Models;
using SteamSentinel.Core.Scanning;

namespace SteamSentinel.SelfTest;

internal static partial class Program
{
    public static async Task TestV020RecoverySafetyAsync(string root)
    {
        string scope = Path.Combine(root, "v020-recovery-" + Guid.NewGuid().ToString("N"));
        string source = Path.Combine(scope, "source"), destination = Path.Combine(scope, "destination"), outside = Path.Combine(scope, "outside");
        Directory.CreateDirectory(source); Directory.CreateDirectory(destination); Directory.CreateDirectory(outside);
        byte[] sentinel = "inert recovery race sentinel"u8.ToArray();
        string outsideFile = Path.Combine(outside, "sentinel.scan");
        await File.WriteAllBytesAsync(outsideFile, sentinel);

        using (RecoveryDirectoryLease lease = RecoveryDirectoryLease.OpenExisting(destination))
        {
            bool targetLocked = V020RecoveryRefuses(() => Directory.Move(destination, destination + "-moved"));
            bool ancestorLocked = V020RecoveryRefuses(() => Directory.Move(scope, scope + "-moved"));
            Check("0.2.0 恢复保存全程锁定目标目录和祖先防止改名替换", targetLocked && ancestorLocked && Directory.Exists(destination));
            using RecoveryDirectoryLease child = lease.CreateDirectory("owned-output");
            Check("0.2.0 恢复输出目录原子创建后持续持有不可替换身份",
                V020RecoveryRefuses(() => Directory.Move(child.Path, child.Path + "-moved")) && Directory.Exists(child.Path));
            Check("0.2.0 恢复拒绝同名已有目录并保留原目录",
                V020RecoveryRefuses(() => { using RecoveryDirectoryLease collision = lease.CreateDirectory("owned-output"); }) && Directory.Exists(child.Path));
            bool reparseBlocked = V020RecoveryRefuses(() => V020RecoverySetJunction(child.Path, outside));
            Check("0.2.0 恢复句柄拒绝在已锁定目录上设置重解析点", reparseBlocked && (File.GetAttributes(child.Path) & FileAttributes.ReparsePoint) == 0);

            string collisionPath = Path.Combine(child.Path, "collision.scan");
            await File.WriteAllBytesAsync(collisionPath, sentinel);
            bool collisionRejected = V020RecoveryRefuses(() => { _ = child.CreateFile("collision.scan"); });
            Check("0.2.0 恢复文件碰撞拒绝覆盖且失败清理不删除已有文件",
                collisionRejected && (await File.ReadAllBytesAsync(collisionPath)).SequenceEqual(sentinel));
            Check("0.2.0 恢复文件名拒绝父级和数据流逃逸",
                V020RecoveryRefuses(() => { _ = child.CreateFile("../sentinel.scan"); }) &&
                V020RecoveryRefuses(() => { _ = child.CreateFile("sentinel.scan:stream"); }));

            RecoveryWriteFile pending = child.CreateFile("partial.scan");
            await pending.Stream.WriteAsync(sentinel);
            bool fileLocked = V020RecoveryRefuses(() => File.Move(Path.Combine(child.Path, "partial.scan"), Path.Combine(child.Path, "renamed.scan")));
            await pending.DisposeAsync();
            Check("0.2.0 未提交恢复内容不可替换且通过原句柄删除",
                fileLocked && pending.DeletedOnClose && !File.Exists(Path.Combine(child.Path, "partial.scan")));
            // A replacement created after disposal must survive repeated cleanup.
            await File.WriteAllBytesAsync(Path.Combine(child.Path, "partial.scan"), sentinel);
            await pending.DisposeAsync();
            Check("0.2.0 句柄清理幂等且不删除之后出现的同名文件",
                (await File.ReadAllBytesAsync(Path.Combine(child.Path, "partial.scan"))).SequenceEqual(sentinel));

            await using RecoveryWriteFile committed = child.CreateFile("complete.scan");
            await committed.Stream.WriteAsync(sentinel);
            await committed.CommitAsync(CancellationToken.None);
            using FileStream read = child.OpenRead("complete.scan");
            Check("0.2.0 恢复提交关闭成功后可用严格只读句柄验证", read.Length == sentinel.Length && !committed.DeletedOnClose);
        }

        string junction = Path.Combine(scope, "redirected");
        Directory.CreateDirectory(junction);
        V020RecoverySetJunction(junction, outside);
        try
        {
            Check("0.2.0 恢复拒绝已存在的重解析目录及其后代",
                V020RecoveryRefuses(() => { using RecoveryDirectoryLease redirected = RecoveryDirectoryLease.OpenExisting(junction); }));
        }
        finally { Directory.Delete(junction); }

        ScanReport success = V020RecoveryReport(sentinel);
        ContainerResourceSnapshot workerResources = new()
        {
            ReadBytes = 11,
            DecodedBytes = 7,
            NativeReservedReadBytes = 5,
            NativeReservedDecodedBytes = 3,
            RangeCopyBytes = 13,
            AcceptedExpandedBytes = 19,
            CurrentTemporaryBytes = 23,
            PeakTemporaryBytes = 29,
            PeakPrivateMemoryBytes = 31,
            MetadataAttempts = 37,
            PasswordAttempts = 3,
            ElapsedMilliseconds = 41
        };
        success.Containers!.Resources = workerResources;
        // Exactly the remaining work allowance must succeed without a one-byte EOF probe.
        success.Containers.Limits = new() { ReservedDiskBytes = 0, MaximumWorkBytes = 26 + sentinel.Length };
        ContainerScanNode goodNode = success.Containers!.Nodes[0];
        await File.WriteAllBytesAsync(Path.Combine(source, goodNode.RecoveredContentName!), sentinel);
        await ContainerRecoveryExporter.CopyAsync(success, source, destination, CancellationToken.None);
        string goodRoot = success.Containers.RecoveryOutputDirectory!;
        using (JsonDocument evidence = JsonDocument.Parse(await File.ReadAllTextAsync(Path.Combine(goodRoot, "evidence.json"))))
        {
            Check("0.2.0 恢复交付内容和证据映射都与已检查SHA256一致",
                goodNode.RecoveredContentAvailable && (await File.ReadAllBytesAsync(Path.Combine(goodRoot, goodNode.RecoveredContentName!))).SequenceEqual(sentinel) &&
                evidence.RootElement.GetProperty("DeliveredFiles").GetInt32() == 1);
            ContainerResourceSnapshot measured = success.Containers.Resources;
            JsonElement evidenceResources = evidence.RootElement.GetProperty("Resources");
            Check("0.2.0 恢复额外读取及复制纳入本轮预算并保留Worker其他快照字段",
                measured.ReadBytes == 11 + sentinel.Length && measured.RangeCopyBytes == 13 + sentinel.Length && measured.DecodedBytes == 7 &&
                measured.NativeReservedReadBytes == 5 && measured.NativeReservedDecodedBytes == 3 && measured.AcceptedExpandedBytes == 19 &&
                measured.CurrentTemporaryBytes == 23 && measured.PeakTemporaryBytes == 29 && measured.PeakPrivateMemoryBytes == 31 &&
                measured.MetadataAttempts == 37 && measured.PasswordAttempts == 3 && measured.ElapsedMilliseconds >= 41 &&
                evidenceResources.GetProperty("ReadBytes").GetInt64() == measured.ReadBytes &&
                evidenceResources.GetProperty("RangeCopyBytes").GetInt64() == measured.RangeCopyBytes &&
                evidenceResources.GetProperty("NativeReservedDecodedBytes").GetInt64() == 3 &&
                evidence.RootElement.GetProperty("Checks").EnumerateArray().Any(value => value.GetString()!.Contains("暂存快照")));
        }

        ScanReport budgetLimited = V020RecoveryReport(sentinel);
        budgetLimited.Containers!.Resources = workerResources;
        budgetLimited.Containers.Limits = new() { ReservedDiskBytes = 0, MaximumWorkBytes = 26 + sentinel.Length - 1 };
        await File.WriteAllBytesAsync(Path.Combine(source, budgetLimited.Containers.Nodes[0].RecoveredContentName!), sentinel);
        int beforeBudgetFailure = Directory.GetDirectories(destination).Length;
        bool budgetRejected = await V020RecoveryRefusesAsync(() => ContainerRecoveryExporter.CopyAsync(budgetLimited, source, destination, CancellationToken.None));
        Check("0.2.0 恢复总预算包含读取解码及两种原生预留且不足时创建前拒绝",
            budgetRejected && budgetLimited.Containers.RecoveryOutputDirectory is null && Directory.GetDirectories(destination).Length == beforeBudgetFailure &&
            budgetLimited.Containers.Resources.ReadBytes == workerResources.ReadBytes && budgetLimited.Containers.Resources.RangeCopyBytes == workerResources.RangeCopyBytes &&
            budgetLimited.Containers.Nodes.All(node => !node.RecoveredContentAvailable));

        ScanReport mismatch = V020RecoveryReport(sentinel);
        mismatch.Containers!.Resources = workerResources;
        ContainerScanNode badNode = mismatch.Containers!.Nodes[0];
        await File.WriteAllBytesAsync(Path.Combine(source, badNode.RecoveredContentName!), new byte[sentinel.Length]);
        bool hashRejected = await V020RecoveryRefusesAsync(() => ContainerRecoveryExporter.CopyAsync(mismatch, source, destination, CancellationToken.None));
        string badRoot = mismatch.Containers.RecoveryOutputDirectory!;
        using (JsonDocument evidence = JsonDocument.Parse(await File.ReadAllTextAsync(Path.Combine(badRoot, "evidence.json"))))
        {
            Check("0.2.0 恢复哈希失败只删除本次输出且证据不声称交付",
                hashRejected && !badNode.RecoveredContentAvailable && badNode.RecoveredContentName is null && Directory.GetFiles(badRoot, "*.scan").Length == 0 &&
                evidence.RootElement.GetProperty("DeliveredFiles").GetInt32() == 0);
            JsonElement resources = evidence.RootElement.GetProperty("Resources");
            Check("0.2.0 恢复哈希失败仍累计真实读取复制且失败证据保留消耗",
                mismatch.Containers.Resources.ReadBytes == 11 + sentinel.Length && mismatch.Containers.Resources.RangeCopyBytes == 13 + sentinel.Length &&
                resources.GetProperty("ReadBytes").GetInt64() == 11 + sentinel.Length && resources.GetProperty("RangeCopyBytes").GetInt64() == 13 + sentinel.Length &&
                resources.GetProperty("CurrentTemporaryBytes").GetInt64() == workerResources.CurrentTemporaryBytes);
        }

        ScanReport partial = V020RecoveryReport(sentinel);
        ContainerScanNode delivered = partial.Containers!.Nodes[0];
        ContainerScanNode missing = V020RecoveryReport(sentinel).Containers!.Nodes[0];
        partial.Containers.Nodes.Add(missing);
        await File.WriteAllBytesAsync(Path.Combine(source, delivered.RecoveredContentName!), sentinel);
        bool partialRejected = await V020RecoveryRefusesAsync(() => ContainerRecoveryExporter.CopyAsync(partial, source, destination, CancellationToken.None));
        using (JsonDocument evidence = JsonDocument.Parse(await File.ReadAllTextAsync(Path.Combine(partial.Containers.RecoveryOutputDirectory!, "evidence.json"))))
            Check("0.2.0 恢复中途失败只保留实际已交付文件及对应状态",
                partialRejected && delivered.RecoveredContentAvailable && !missing.RecoveredContentAvailable && missing.RecoveredContentName is null &&
                evidence.RootElement.GetProperty("DeliveredFiles").GetInt32() == 1 && Directory.GetFiles(partial.Containers.RecoveryOutputDirectory!, "*.scan").Length == 1);

        ScanReport cancelled = V020RecoveryReport(sentinel);
        using CancellationTokenSource cancellation = new(); cancellation.Cancel();
        int before = Directory.GetDirectories(destination).Length;
        bool cancelRejected = await V020RecoveryRefusesAsync(() => ContainerRecoveryExporter.CopyAsync(cancelled, source, destination, cancellation.Token));
        Check("0.2.0 恢复导出预取消不创建目录且不保留Worker交付声明", cancelRejected &&
            cancelled.Containers!.Nodes.All(node => !node.RecoveredContentAvailable) && cancelled.Containers.RecoveryOutputDirectory is null &&
            Directory.GetDirectories(destination).Length == before);

        ScanReport duplicate = V020RecoveryReport(sentinel);
        duplicate.Containers!.Nodes.Add(duplicate.Containers.Nodes[0]);
        bool duplicateRejected = await V020RecoveryRefusesAsync(() => ContainerRecoveryExporter.CopyAsync(duplicate, source, destination, CancellationToken.None));
        Check("0.2.0 恢复拒绝重复节点身份且尚未创建任何交付目录", duplicateRejected && duplicate.Containers.RecoveryOutputDirectory is null &&
            duplicate.Containers.Nodes.All(node => !node.RecoveredContentAvailable) && Directory.GetDirectories(destination).Length == before);
        Check("0.2.0 恢复边界失败未改变目录外哨兵文件", (await File.ReadAllBytesAsync(outsideFile)).SequenceEqual(sentinel));
    }

    private static ScanReport V020RecoveryReport(byte[] content)
    {
        ContainerScanNode node = new()
        {
            Length = content.Length,
            Sha256 = Convert.ToHexString(SHA256.HashData(content)),
            RecoveredContentAvailable = true,
            ContentCheck = ContainerStageStatus.Complete,
            Recognition = ContainerStageStatus.Complete
        };
        node.RecoveredContentName = node.NodeId.ToString("N") + ".scan";
        return new ScanReport { Containers = new() { Nodes = [node], Limits = new() { ReservedDiskBytes = 0 } } };
    }

    private static bool V020RecoveryRefuses(Action action)
    {
        try { action(); return false; }
        catch (Exception ex) when (ex is IOException or InvalidDataException or UnauthorizedAccessException or Win32Exception or ArgumentException) { return true; }
    }
    private static async Task<bool> V020RecoveryRefusesAsync(Func<Task> action)
    {
        try { await action(); return false; }
        catch (Exception ex) when (ex is IOException or InvalidDataException or UnauthorizedAccessException or Win32Exception or ArgumentException or OperationCanceledException or ScanResourceLimitException) { return true; }
    }

    // Mount-point reparse points require no symbolic-link privilege. This inert test never
    // traverses the link and removes only the link itself after the rejection assertion.
    private static void V020RecoverySetJunction(string link, string target)
    {
        using SafeFileHandle handle = V020RecoveryCreateFile(link, 0x40000000, 7, IntPtr.Zero, 3, 0x02200000, IntPtr.Zero);
        if (handle.IsInvalid) throw new Win32Exception(Marshal.GetLastWin32Error());
        byte[] substitute = Encoding.Unicode.GetBytes(@"\??\" + Path.GetFullPath(target));
        byte[] display = Encoding.Unicode.GetBytes(Path.GetFullPath(target));
        byte[] buffer = new byte[20 + substitute.Length + display.Length];
        BitConverter.GetBytes(0xA0000003u).CopyTo(buffer, 0);
        BitConverter.GetBytes(checked((ushort)(buffer.Length - 8))).CopyTo(buffer, 4);
        BitConverter.GetBytes(checked((ushort)substitute.Length)).CopyTo(buffer, 10);
        BitConverter.GetBytes(checked((ushort)(substitute.Length + 2))).CopyTo(buffer, 12);
        BitConverter.GetBytes(checked((ushort)display.Length)).CopyTo(buffer, 14);
        substitute.CopyTo(buffer, 16); display.CopyTo(buffer, 18 + substitute.Length);
        if (!V020RecoveryDeviceIoControl(handle, 0x000900A4, buffer, (uint)buffer.Length, IntPtr.Zero, 0, out _, IntPtr.Zero))
            throw new Win32Exception(Marshal.GetLastWin32Error());
    }
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true, EntryPoint = "CreateFileW")]
    private static extern SafeFileHandle V020RecoveryCreateFile(string path, uint access, uint share, IntPtr security, uint disposition, uint flags, IntPtr template);
    [DllImport("kernel32.dll", SetLastError = true, EntryPoint = "DeviceIoControl")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool V020RecoveryDeviceIoControl(SafeFileHandle handle, uint code, byte[] input, uint inputSize,
        IntPtr output, uint outputSize, out uint returned, IntPtr overlapped);
}
