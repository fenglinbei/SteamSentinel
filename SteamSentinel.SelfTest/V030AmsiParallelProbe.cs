using System.IO;
using System.Text.Json;
using SteamSentinel.App.Services;
using SteamSentinel.Core.Models;
using SteamSentinel.Core.Utilities;

namespace SteamSentinel.SelfTest;

internal static partial class Program
{
    private static async Task<int> RunV030AmsiParallelProbeAsync(string output)
    {
        output = Path.GetFullPath(output); Directory.CreateDirectory(output);
        if (!ScanEnhancements.AmsiAvailable)
        {
            await JsonFile.WriteAtomicAsync(Path.Combine(output, "amsi-parallel-results.json"), new
            { executed = false, verified = false, reason = "AMSI_ENHANCEMENT_PAUSED", version = ProductInfo.Version, buildIdentity = ProductInfo.BuildIdentity });
            Console.WriteLine("AMSI_PARALLEL_NOT_EXECUTED: AMSI enhancement is paused; no native engine call was made.");
            return 2;
        }
        string corpus = Path.Combine(output, "amsi-parallel"); Directory.CreateDirectory(corpus);
        for (int index = 0; index < 16; index++) await File.WriteAllTextAsync(Path.Combine(corpus, $"ordinary-{index:D2}.ps1"),
            "Write-Output 'Harmless scanner test; this script is never executed.'\r\n");
        async Task<ScanReport> Scan(ScanPerformanceMode mode) => await new ArchiveWorkerClient(DevelopmentWorkerPath()).RunAsync(
            new ScanLimitSettings { PerformanceMode = mode }.Apply(new()
            { Mode = ScanMode.Custom, IncludeSystem = false, IncludeSteam = false, IncludeWorkshop = false, UseAmsi = true, CustomRoots = [corpus], HashEveryFile = true }),
            (request, _) => Task.FromResult(new ArchivePasswordResponse(request.RequestId, true, null, false)), null, default);
        try
        {
            ScanReport serial = await Scan(ScanPerformanceMode.LowImpact), automatic = await Scan(ScanPerformanceMode.Automatic), parallel = await Scan(ScanPerformanceMode.HighThroughput);
            static string AmsiSemantics(ScanReport report) => JsonSerializer.Serialize(new
            {
                roots = report.RootSummaries,
                notices = report.CoverageNotices.Select(notice => notice.ReasonCode),
                engines = report.Containers!.Nodes.OrderBy(node => node.DisplayPath).Select(node => new
                { node.DisplayPath, engines = node.Engines.Where(engine => engine.Engine == "AMSI").Select(engine => new { engine.Status, engine.Length, engine.AmsiDiagnostics }) })
            });
            static bool Healthy(ScanReport report) => report.Coverage == ScanCoverage.Complete && report.Containers?.Nodes.Count == 16 &&
                report.Containers.Nodes.All(node => node.Engines.Any(engine => engine.Engine == "AMSI" && engine.Status == ContainerStageStatus.Complete && engine.Length > 0 &&
                    engine.AmsiDiagnostics is { Code: "AMSI-VERDICT", HResult: >= 0, Integrity: "Low" or "Untrusted" }));
            Check("AMSI专项 真实Worker串行与四路健康结果一致", Healthy(serial) && Healthy(parallel) && parallel.ResourceAudit?.PeakParallelFiles == 4 &&
                BaselineScanSemantics(serial) == BaselineScanSemantics(parallel) && AmsiSemantics(serial) == AmsiSemantics(parallel));
            Check("AMSI专项 真实Worker串行与自动双路健康结果一致", Healthy(serial) && Healthy(automatic) && automatic.ResourceAudit?.PeakParallelFiles == 2 &&
                BaselineScanSemantics(serial) == BaselineScanSemantics(automatic) && AmsiSemantics(serial) == AmsiSemantics(automatic));
            await JsonFile.WriteAtomicAsync(Path.Combine(output, "worker-amsi-serial.json"), serial);
            await JsonFile.WriteAtomicAsync(Path.Combine(output, "worker-amsi-automatic.json"), automatic);
            await JsonFile.WriteAtomicAsync(Path.Combine(output, "worker-amsi-parallel.json"), parallel);
        }
        catch (Exception exception) { Failures.Add(exception.ToString()); Console.Error.WriteLine(exception); }
        await JsonFile.WriteAtomicAsync(Path.Combine(output, "amsi-parallel-results.json"), new
        { executed = true, verified = Failures.Count == 0, passed = _passed, failures = Failures, version = ProductInfo.Version, buildIdentity = ProductInfo.BuildIdentity });
        return Failures.Count == 0 ? 0 : 1;
    }
}
