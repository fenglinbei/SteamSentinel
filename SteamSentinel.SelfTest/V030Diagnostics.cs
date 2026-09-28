using System.IO;
using System.Text;
using SteamSentinel.App.Services;
using SteamSentinel.Core.Inspection;
using SteamSentinel.Core.Models;
using SteamSentinel.Core.Steam;
using SteamSentinel.Core.Utilities;

namespace SteamSentinel.SelfTest;

internal static partial class Program
{
    // Base acceptance is independent of optional system antimalware integration.
    // Bind the same official, inert-on-disk fixture used by the separate AMSI probe.
    private static async Task<int> RunV030BasicProbeAsync(string fixture, string output)
    {
        fixture = Path.GetFullPath(fixture); output = Path.GetFullPath(output);
        if (!ContentDiscovery.IsLocalSafePath(fixture) || Validation.ContainsReparsePoint(fixture))
            throw new InvalidDataException("The benign fixture must be a local ordinary directory.");
        (string Name, string Hash)[] expected =
        [
            ("VPet.Plugin.DemoClock.dll", "F24670CC98DB50C3440F22F1B21B2F2A0744F7EE448A8BF757D4894446210DCC"),
            ("Newtonsoft.Json.dll", "CCA49B741B584875B9445BD2127E4E7484A9B7FE82A1C3292D0626EC72843444")
        ];
        foreach (var item in expected)
        {
            string path = Path.Combine(fixture, "plugin", item.Name);
            if (Validation.ContainsReparsePoint(path) ||
                !string.Equals(await Hashing.Sha256FileAsync(path), item.Hash, StringComparison.OrdinalIgnoreCase))
                throw new InvalidDataException("Unexpected benign DLL identity.");
        }
        string[] files = Directory.GetFiles(fixture, "*", SearchOption.AllDirectories);
        if (files.Length != 8 || files.Sum(path => new FileInfo(path).Length) != 919942 ||
            files.Any(Validation.ContainsReparsePoint))
            throw new InvalidDataException("Unexpected official DemoClock fixture contents.");
        if (Directory.Exists(output)) throw new InvalidDataException("Preserve earlier evidence; use a new output directory.");
        Directory.CreateDirectory(output);
        string worker = DevelopmentWorkerPath();
        using CancellationTokenSource timeout = new(TimeSpan.FromMinutes(2));
        ScanReport report = await new ArchiveWorkerClient(worker).RunAsync(V030ContentOptions(fixture, amsi: false),
            (request, _) => Task.FromResult(new ArchivePasswordResponse(request.RequestId, true, null, false)), null, timeout.Token);
        await JsonFile.WriteAtomicAsync(Path.Combine(output, "normal-plugin-worker.json"), report);
        int amsiObservations = report.Containers?.Nodes.Sum(node => node.Engines.Count(engine => engine.Engine == "AMSI")) ?? 0;
        string coreHash = await Hashing.Sha256FileAsync(typeof(AmsiScanner).Assembly.Location);
        string workerCoreHash = await Hashing.Sha256FileAsync(Path.Combine(Path.GetDirectoryName(worker)!, "SteamSentinel.Core.dll"));
        bool verified = report.ExecutionState == ScanExecutionState.Completed && report.Coverage == ScanCoverage.Complete &&
            report.Metrics.FilesVisited == 8 && report.Metrics.BytesHashed == 919942 &&
            !report.Findings.Any(finding => finding.IsKnownMalware || finding.CanRemediate) &&
            report.ContentScanSettings is { UseAmsi: false } && amsiObservations == 0 &&
            !report.CoverageNotices.Any(notice => notice.ReasonCode == ReasonCodes.AmsiUnavailable) &&
            report.RootSummaries.Count > 0 && report.RootSummaries.All(root => root.Coverage == ScanCoverage.Complete) &&
            coreHash == workerCoreHash;
        await JsonFile.WriteAtomicAsync(Path.Combine(output, "summary.json"), new
        {
            verified,
            scope = "base-scan-without-amsi",
            amsiInvoked = false,
            amsiObservations,
            report.ExecutionState,
            report.Coverage,
            report.Metrics,
            report.WorkerDiagnostics,
            known = report.Findings.Count(finding => finding.IsKnownMalware),
            actionable = report.Findings.Count(finding => finding.CanRemediate),
            workerPath = worker,
            workerSha256 = await Hashing.Sha256FileAsync(worker),
            coreSha256 = coreHash,
            workerCoreSha256 = workerCoreHash,
            version = ProductInfo.Version,
            buildIdentity = ProductInfo.BuildIdentity,
            completedAtUtc = DateTimeOffset.UtcNow
        });
        Console.WriteLine($"BASIC_PROBE_VERIFIED={verified};FILES={report.Metrics.FilesVisited};COVERAGE={report.Coverage};AMSI_OBSERVATIONS={amsiObservations}");
        return verified ? 0 : 1;
    }

    // Explicit opt-in comparison against fixed, official benign inputs. No assembly is loaded
    // from the fixture, and the production worker retains its normal restricted token.
    private static async Task<int> RunV030AmsiProbeAsync(string fixture, string output)
    {
        if (!ScanEnhancements.AmsiAvailable)
        {
            Console.Error.WriteLine("AMSI_ENHANCEMENT_DEFERRED: system AMSI is not invoked in this base acceptance build.");
            return 2;
        }
        fixture = Path.GetFullPath(fixture); output = Path.GetFullPath(output);
        if (!ContentDiscovery.IsLocalSafePath(fixture) || Validation.ContainsReparsePoint(fixture))
            throw new InvalidDataException("The benign fixture must be a local ordinary directory.");
        (string Name, string Hash)[] expected =
        [
            ("VPet.Plugin.DemoClock.dll", "F24670CC98DB50C3440F22F1B21B2F2A0744F7EE448A8BF757D4894446210DCC"),
            ("Newtonsoft.Json.dll", "CCA49B741B584875B9445BD2127E4E7484A9B7FE82A1C3292D0626EC72843444")
        ];
        List<object> identities = [];
        foreach (var item in expected)
        {
            string path = Path.Combine(fixture, "plugin", item.Name);
            if (Validation.ContainsReparsePoint(path)) throw new InvalidDataException("Reparse fixture member.");
            string hash = await Hashing.Sha256FileAsync(path);
            if (!hash.Equals(item.Hash, StringComparison.OrdinalIgnoreCase)) throw new InvalidDataException("Unexpected benign DLL identity.");
            identities.Add(new { name = item.Name, sha256 = hash, length = new FileInfo(path).Length });
        }
        string[] files = Directory.GetFiles(fixture, "*", SearchOption.AllDirectories);
        if (files.Length != 8 || files.Sum(path => new FileInfo(path).Length) != 919942 ||
            files.Any(Validation.ContainsReparsePoint)) throw new InvalidDataException("Unexpected official DemoClock fixture contents.");
        Directory.CreateDirectory(output);
        List<object> direct = [];
        List<(AmsiScanResult Result, long ExpectedBytes)> directChecks = [];
        AmsiDiagnosticInfo initialization;
        using (AmsiScanner scanner = new())
        {
            initialization = scanner.Initialization;
            byte[] text = Encoding.UTF8.GetBytes("SteamSentinel benign AMSI diagnostic fixture.");
            AmsiScanResult textResult = scanner.Scan(text, "SteamSentinel-benign.txt");
            directChecks.Add((textResult, text.Length));
            direct.Add(new { name = "benign-text", sha256 = Hashing.Sha256Bytes(text), result = textResult });
            foreach (var item in expected)
            {
                string path = Path.Combine(fixture, "plugin", item.Name);
                AmsiScanResult result = await scanner.ScanFileAsync(path);
                directChecks.Add((result, new FileInfo(path).Length));
                direct.Add(new
                {
                    name = item.Name,
                    sha256 = item.Hash,
                    result
                });
            }
        }
        await JsonFile.WriteAtomicAsync(Path.Combine(output, "direct-amsi.json"), new
        {
            version = ProductInfo.Version,
            buildIdentity = ProductInfo.BuildIdentity,
            initialization,
            identities,
            direct,
            completedAtUtc = DateTimeOffset.UtcNow
        });
        string worker = Path.Combine(AppContext.BaseDirectory, "SteamSentinel.ArchiveWorker.exe");
        // Project references can copy the apphost without the non-referenced Worker DLL.
        // A development probe must select a complete Worker, not that orphaned apphost.
        if (!File.Exists(worker) || !File.Exists(Path.ChangeExtension(worker, ".dll")))
            worker = DevelopmentWorkerPath();
        using CancellationTokenSource timeout = new(TimeSpan.FromMinutes(2));
        ScanReport report = await new ArchiveWorkerClient(worker).RunAsync(V030ContentOptions(fixture, amsi: true),
            (request, _) => Task.FromResult(new ArchivePasswordResponse(request.RequestId, true, null, false)), null, timeout.Token);
        await JsonFile.WriteAtomicAsync(Path.Combine(output, "normal-plugin-worker.json"), report);
        var observations = report.Containers?.Nodes.SelectMany(node => node.Engines.Where(engine => engine.Engine == "AMSI")
            .Select(engine => new { node.DisplayPath, engine.Status, engine.Length, engine.AmsiDiagnostics })).ToArray() ?? [];
        bool diagnosticCompleted = report.Metrics.FilesVisited == 8 && report.Metrics.BytesHashed == 919942 &&
            !report.Findings.Any(finding => finding.IsKnownMalware || finding.CanRemediate) && observations.Length == 2 &&
            observations.All(item => item.AmsiDiagnostics is { Integrity: "Low" or "Untrusted" });
        bool amsiVerified = directChecks.Count == 3 && directChecks.All(item =>
            item.Result.Verdict is AmsiVerdict.Clean or AmsiVerdict.NotDetected &&
            item.Result.BytesSubmitted == item.ExpectedBytes && item.Result.Diagnostics is
            { Code: "AMSI-VERDICT", Operation: AmsiOperation.ScanBuffer, HResult: >= 0, InitializeHResult: >= 0, OpenSessionHResult: >= 0 }) &&
            observations.Length == 2 && observations.All(item =>
                expected.Any(input => string.Equals(item.DisplayPath, Path.Combine(fixture, "plugin", input.Name), StringComparison.OrdinalIgnoreCase)) &&
                item.Status == ContainerStageStatus.Complete && item.Length == new FileInfo(item.DisplayPath).Length &&
                item.AmsiDiagnostics is
                {
                    Code: "AMSI-VERDICT", Operation: AmsiOperation.ScanBuffer, HResult: >= 0,
                    InitializeHResult: >= 0, OpenSessionHResult: >= 0, Integrity: "Low" or "Untrusted"
                });
        bool verified = diagnosticCompleted && amsiVerified;
        await JsonFile.WriteAtomicAsync(Path.Combine(output, "summary.json"), new
        {
            verified,
            diagnosticCompleted,
            amsiVerified,
            report.Coverage,
            report.Metrics,
            known = report.Findings.Count(finding => finding.IsKnownMalware),
            actionable = report.Findings.Count(finding => finding.CanRemediate),
            observations,
            workerPath = worker,
            workerSha256 = await Hashing.Sha256FileAsync(worker),
            coreSha256 = await Hashing.Sha256FileAsync(typeof(AmsiScanner).Assembly.Location),
            workerCoreSha256 = await Hashing.Sha256FileAsync(Path.Combine(Path.GetDirectoryName(worker)!, "SteamSentinel.Core.dll")),
            completedAtUtc = DateTimeOffset.UtcNow
        });
        Console.WriteLine($"AMSI_PROBE_VERIFIED={verified};FILES={report.Metrics.FilesVisited};COVERAGE={report.Coverage}");
        return verified ? 0 : 1;
    }
}
