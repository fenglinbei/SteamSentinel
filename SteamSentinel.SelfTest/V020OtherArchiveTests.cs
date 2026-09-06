using System.IO;
using System.IO.Compression;
using System.Security.Cryptography;
using SteamSentinel.Core.Models;
using SteamSentinel.Core.Scanning;

namespace SteamSentinel.SelfTest;

internal static partial class Program
{
    private static async Task TestV020OtherArchivesAsync(string root)
    {
        string directory = Path.Combine(root, "v020-other-archives"); Directory.CreateDirectory(directory);
        string gzip = Path.Combine(directory, "inert.gz");
        byte[] payload = new byte[8192]; new Random(20260906).NextBytes(payload);
        using (FileStream file = new(gzip, FileMode.Create, FileAccess.Write))
        using (GZipStream writer = new(file, CompressionLevel.NoCompression)) await writer.WriteAsync(payload);
        string hash = Convert.ToHexString(SHA256.HashData(payload));
        async Task<ScanReport> Scan(ContainerResourceLimits limits)
        {
            ScanReport report = new() { Mode = ScanMode.Custom };
            using ContentScanner scanner = new(new RuleSet());
            try
            {
                await scanner.ScanRootAsync(gzip, report, new()
                {
                    Mode = ScanMode.Custom,
                    IncludeSystem = false,
                    IncludeSteam = false,
                    IncludeWorkshop = false,
                    IncludeRelatedContent = false,
                    UseAmsi = false,
                    InspectArchives = true,
                    HashEveryFile = true,
                    CustomRoots = [gzip],
                    ContainerLimits = limits,
                    MaximumContentBytes = long.MaxValue
                }, new NullPasswordProvider());
            }
            catch (ScanResourceLimitException) { /* Expected global stop retains the caller's partial report. */ }
            return report;
        }
        ScanReport normal = await Scan(new());
        Check("0.2其他流格式按完整字节展开且报告独立校验边界", normal.Containers?.Nodes.Any(node => node.ParentId.HasValue && node.Sha256 == hash &&
            node.Length == payload.Length && node.Integrity == ContainerStageStatus.UnsupportedIntegrity) == true &&
            normal.Containers.Resources.DecodedBytes == payload.Length && normal.Containers.Resources.CurrentTemporaryBytes == 0 && !normal.Containers.Complete);
        ScanReport disk = await Scan(new() { MaximumTemporaryBytes = 1024 });
        Check("0.2其他流格式也不能绕过共享临时空间预算", disk.Containers?.Nodes.Any(node => node.Overall == ContainerStageStatus.LimitReached) == true &&
            disk.Containers.Resources.PeakTemporaryBytes <= 1024 && disk.Containers.Resources.CurrentTemporaryBytes == 0 && disk.Coverage == ScanCoverage.Partial);
        long limit = new FileInfo(gzip).Length * 2 + 4096;
        ScanReport work = await Scan(new() { MaximumWorkBytes = limit });
        Check("0.2其他流格式失败读取解码仍占用共享工作预算", work.Containers?.Nodes.Any(node => node.Overall == ContainerStageStatus.LimitReached) == true &&
            work.Containers.Resources.ReadBytes > 0 && work.Containers.Resources.ReadBytes + work.Containers.Resources.DecodedBytes >= limit &&
            work.Containers.Resources.ReadBytes + work.Containers.Resources.DecodedBytes <= limit + 128 * 1024 && work.Containers.Resources.CurrentTemporaryBytes == 0);
        ContainerResourceBudget native = new(new() { MaximumWorkBytes = 30 });
        native.ReserveNativeRead(8); native.ReserveNativeDecoded(9); native.AcceptExpansion(4); native.RestoreLogicalExpansion(0);
        Check("0.2原生解码保守预留单独记录且不会由逻辑回滚退还", native.Snapshot().NativeReservedDecodedBytes == 9 &&
            native.Snapshot().DecodedBytes == 0 && native.RemainingWorkBytes == 13 && V020Throws<ScanResourceLimitException>(() => native.ReserveNativeDecoded(14)));
        string later = Path.Combine(directory, "later.txt");
        await File.WriteAllTextAsync(later, "inert follow-up content");
        ScanReport local = new();
        using (ContentScanner scanner = new(new RuleSet()))
        {
            ScanOptions options = new() { Mode = ScanMode.Custom, UseAmsi = false, ContainerLimits = new() { MaximumEntryBytes = 1 } };
            await scanner.ScanRootAsync(gzip, local, options, new NullPasswordProvider());
            await scanner.ScanRootAsync(later, local, options, new NullPasswordProvider());
        }
        Check("0.2其他流单项限制保留独立缺口并继续后续根且不遗留临时数据", local.Metrics.FilesVisited == 2 &&
            local.Containers?.Nodes.Any(node => node.OriginalTarget == gzip && node.Overall == ContainerStageStatus.LimitReached) == true &&
            local.Containers.Nodes.Any(node => node.OriginalTarget == later && node.Sha256 is { Length: 64 }) &&
            local.Containers.Resources.CurrentTemporaryBytes == 0 && local.Coverage == ScanCoverage.Partial);
    }
}
