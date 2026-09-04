using System.IO;
using SteamSentinel.App.Services;
using SteamSentinel.Core.Models;
using SteamSentinel.Core.Utilities;

namespace SteamSentinel.SelfTest;

// Opt-in local static regression, not included in the application payload.
internal static class CorpusRegression
{
    public static async Task<int> RunBatchAsync(string root, string output)
    {
        string solution = Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "..", "..", "..", ".."));
        string worker = Path.Combine(solution, "SteamSentinel.ArchiveWorker", "bin", "Release",
            "net10.0-windows10.0.19041.0", "SteamSentinel.ArchiveWorker.exe");
        Directory.CreateDirectory(output);
        List<ArchivePasswordRequest> requests = [];
        using CancellationTokenSource timeout = new(TimeSpan.FromMinutes(8));
        ScanReport report = await new ArchiveWorkerClient(worker).RunAsync(new ScanOptions
        {
            Mode = ScanMode.Custom,
            IncludeSystem = false,
            IncludeSteam = false,
            IncludeWorkshop = false,
            UseAmsi = false,
            HashEveryFile = true,
            InspectArchives = true,
            CustomRoots = [root]
        }, (request, _) =>
        {
            requests.Add(request);
            Console.WriteLine($"PASSWORD_REQUEST #{requests.Count} {request.PromptKind} {request.ArchivePath}");
            return Task.FromResult(new ArchivePasswordResponse(request.RequestId, false, "infected", false, ArchivePasswordReuseScope.Session));
        }, null, timeout.Token);
        await JsonFile.WriteAtomicAsync(Path.Combine(output, "report.json"), report);
        await JsonFile.WriteAtomicAsync(Path.Combine(output, "password-requests.json"), requests);
        var summary = Directory.EnumerateFiles(root).Order(StringComparer.OrdinalIgnoreCase).Select(path => new
        {
            name = Path.GetFileName(path),
            known = report.Findings.Count(f => f.Target.Equals(path, StringComparison.OrdinalIgnoreCase) && f.IsKnownMalware),
            actionable = report.Findings.Count(f => f.Target.Equals(path, StringComparison.OrdinalIgnoreCase) && f.CanRemediate),
            partial = report.Findings.Any(f => f.Target.Equals(path, StringComparison.OrdinalIgnoreCase) && f.Category == FindingCategory.Coverage)
        }).ToArray();
        await JsonFile.WriteAtomicAsync(Path.Combine(output, "summary.json"), summary);
        Console.WriteLine($"BATCH files={summary.Length} actionableInputs={summary.Count(s => s.actionable > 0)} prompts={requests.Count} coverage={report.Coverage}");
        return 0;
    }

    public static async Task<int> RunAsync(string root, string output)
    {
        string solution = Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "..", "..", "..", ".."));
        string worker = Path.Combine(solution, "SteamSentinel.ArchiveWorker", "bin", "Release",
            "net10.0-windows10.0.19041.0", "SteamSentinel.ArchiveWorker.exe");
        Directory.CreateDirectory(output);
        List<object> summary = [];
        int failures = 0;
        foreach (string path in Directory.EnumerateFiles(root).Order(StringComparer.OrdinalIgnoreCase))
        {
            int prompts = 0;
            using CancellationTokenSource timeout = new(TimeSpan.FromMinutes(5));
            try
            {
                ScanReport report = await new ArchiveWorkerClient(worker).RunAsync(new ScanOptions
                {
                    Mode = ScanMode.Custom,
                    IncludeSystem = false,
                    IncludeSteam = false,
                    IncludeWorkshop = false,
                    InspectArchives = true,
                    UseAmsi = false,
                    HashEveryFile = true,
                    CustomRoots = [path]
                }, (request, _) =>
                {
                    prompts++;
                    // Public corpus password. Never written to report or process arguments.
                    return Task.FromResult(new ArchivePasswordResponse(request.RequestId, false, "infected", true));
                }, null, timeout.Token);
                string sha = await Hashing.Sha256FileAsync(path);
                await JsonFile.WriteAtomicAsync(Path.Combine(output, sha + ".json"), report);
                int known = report.Findings.Count(f => f.IsKnownMalware);
                int actionable = report.Findings.Count(f => f.CanRemediate);
                summary.Add(new
                {
                    name = Path.GetFileName(path),
                    sha256 = sha,
                    known,
                    actionable,
                    prompts,
                    coverage = report.Coverage.ToString(),
                    files = report.Metrics.FilesVisited
                });
                Console.WriteLine($"{Path.GetFileName(path)} | known={known} actionable={actionable} prompts={prompts} {report.Coverage}");
            }
            catch (Exception ex)
            {
                failures++;
                summary.Add(new { name = Path.GetFileName(path), error = ex.Message });
                Console.WriteLine($"FAILED {Path.GetFileName(path)}: {ex.Message}");
            }
            await JsonFile.WriteAtomicAsync(Path.Combine(output, "summary.json"), summary);
        }
        return failures == 0 ? 0 : 1;
    }
}
