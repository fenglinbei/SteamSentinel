using System.Diagnostics;
using System.IO;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using SteamSentinel.Core.Models;
using SteamSentinel.Core.Rules;
using SteamSentinel.Core.Scanning;

namespace SteamSentinel.SelfTest;

internal static partial class Program
{
    private static async Task<int> RunScanPerformanceAsync(string output, bool matrix = false)
    {
        output = Path.GetFullPath(output);
        if (Directory.Exists(output)) throw new IOException("Benchmark evidence directory already exists.");
        Directory.CreateDirectory(output);
        List<object> measurements = [];
        (int Count, int Repeats, string Kind)[] scenarios = matrix
            ? [(128, 32, "small-text"), (512, 32, "small-text"), (2048, 32, "small-text"), (64, 32768, "large-text")]
            : [(128, 32, "small-text"), (512, 32, "small-text"), (2048, 32, "small-text")];
        foreach ((int count, int contentRepeats, string kind) in scenarios)
        {
            string corpus = Path.Combine(output, "files-" + count);
            Directory.CreateDirectory(corpus);
            byte[] content = Encoding.UTF8.GetBytes(string.Concat(Enumerable.Repeat("ordinary benchmark text 0123456789\n", contentRepeats)));
            for (int i = 0; i < count; i++) await File.WriteAllBytesAsync(Path.Combine(corpus, $"file-{i:D5}.txt"), content);
            for (int repeat = 0; repeat < 3; repeat++)
            foreach (int parallel in !matrix ? new[] { 1 } : repeat switch { 0 => new[] { 1, 2, 4 }, 1 => new[] { 4, 1, 2 }, _ => new[] { 2, 4, 1 } })
            {
                ScanOptions options = new() { Mode = ScanMode.Custom, IncludeSteam = false, IncludeSystem = false,
                    IncludeWorkshop = false, UseAmsi = false, InspectArchives = true, HashEveryFile = true,
                    CustomRoots = [corpus], MaximumParallelFiles = parallel, PerformanceMode = ScanPerformanceMode.HighThroughput,
                    MaximumWorkerMemoryBytes = 8L * 1024 * 1024 * 1024 };
                int[] collections = Enumerable.Range(0, 3).Select(GC.CollectionCount).ToArray();
                long allocated = GC.GetTotalAllocatedBytes();
                using Process process = Process.GetCurrentProcess();
                TimeSpan cpu = process.TotalProcessorTime;
                Stopwatch watch = Stopwatch.StartNew();
                ScanReport report = await new ScanCoordinator(RuleLoader.LoadEmbedded()).RunAsync(options);
                watch.Stop(); process.Refresh();
                string semantic = string.Join("\n", (report.Containers?.Nodes ?? []).Select(n =>
                    $"{Path.GetFileName(n.DisplayPath)}|{n.Length}|{n.Sha256}|{n.Overall}").Order());
                measurements.Add(new { count, corpusKind = kind, fileBytes = content.Length, repeat, parallel, actualParallel = report.ResourceAudit?.PeakParallelFiles ?? 1, elapsedMs = watch.Elapsed.TotalMilliseconds,
                    cpuMs = (process.TotalProcessorTime - cpu).TotalMilliseconds,
                    allocatedBytes = GC.GetTotalAllocatedBytes() - allocated, privateBytes = process.PrivateMemorySize64,
                    collections = Enumerable.Range(0, 3).Select(g => GC.CollectionCount(g) - collections[g]).ToArray(),
                    report.Metrics, report.Coverage, findings = report.Findings.Count,
                    nodes = report.Containers?.Nodes.Count, work = report.Containers?.Resources,
                    semanticSha256 = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(semantic))) });
                Console.WriteLine($"BENCH count={count} repeat={repeat} parallel={parallel} actual={report.ResourceAudit?.PeakParallelFiles ?? 1} ms={watch.Elapsed.TotalMilliseconds:F0} visited={report.Metrics.FilesVisited} nodes={report.Containers?.Nodes.Count}");
            }
        }
        await File.WriteAllTextAsync(Path.Combine(output, "performance.json"), JsonSerializer.Serialize(new
        { version = ProductInfo.Version, buildIdentity = ProductInfo.BuildIdentity, measurements,
          boundary = "Harmless local text corpus; AMSI disabled consistently to isolate traversal and report overhead. No malware executed." },
            new JsonSerializerOptions { WriteIndented = true }));
        return 0;
    }
}
