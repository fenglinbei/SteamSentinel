using System.IO;
using System.IO.Compression;
using System.Text.Json;
using System.Text.Json.Nodes;
using SteamSentinel.Core.Models;
using SteamSentinel.Core.Remediation;
using SteamSentinel.Core.Rules;
using SteamSentinel.Core.Steam;
using SteamSentinel.Core.Utilities;

namespace SteamSentinel.SelfTest;

// Opt-in static evidence replay. Does not start Broker, quarantine, extract, or execute any scanned file.
internal static class PlanRegression
{
    public static async Task<int> RunAsync(string evidence, string sampleRoot, string output)
    {
        sampleRoot = Path.GetFullPath(sampleRoot);
        if (!ContentDiscovery.IsLocalSafePath(sampleRoot) || !Directory.Exists(sampleRoot)) throw new InvalidDataException("Unsafe corpus root");
        ScanReport scan;
        if (evidence.EndsWith(".zip", StringComparison.OrdinalIgnoreCase))
        {
            using ZipArchive zip = ZipFile.OpenRead(evidence);
            ZipArchiveEntry entry = zip.GetEntry("scan.json") ?? throw new InvalidDataException("Missing scan.json");
            if (entry.Length > 32 * 1024 * 1024) throw new InvalidDataException("Evidence too large");
            using Stream stream = entry.Open();
            scan = await JsonFile.ReadAsync<ScanReport>(stream);
        }
        else scan = await JsonFile.ReadAsync<ScanReport>(evidence);
        List<Finding> mapped = [];
        foreach (Finding finding in scan.Findings.Where(f => f.Category is FindingCategory.File or FindingCategory.Archive))
        {
            if (!ContentDiscovery.IsLocalSafePath(finding.Target)) continue;
            string path = Path.Combine(sampleRoot, Path.GetFileName(finding.Target));
            if (!File.Exists(path)) continue;
            JsonObject node = JsonSerializer.SerializeToNode(finding, JsonFile.Options)!.AsObject();
            node["Target"] = path;
            if (finding.ContentPath is { } member && member.StartsWith(finding.Target, StringComparison.OrdinalIgnoreCase))
                node["ContentPath"] = path + member[finding.Target.Length..];
            mapped.Add(node.Deserialize<Finding>(JsonFile.Options)!);
        }
        ScanReport replay = new() { Findings = mapped, Roots = [sampleRoot] };
        Finding[] selected = mapped.Where(f => f.CanRemediate &&
            !(f.ContentPath?.Contains("!/") == true && string.IsNullOrWhiteSpace(f.TargetSha256))).ToArray();
        using CancellationTokenSource timeout = new(TimeSpan.FromMinutes(8));
        RemediationBatchSession session = await new RemediationBatchPlanner(RuleLoader.LoadEmbedded()).PrepareAsync(selected, replay, true, token: timeout.Token);
        await JsonFile.WriteNewAsync(output, new
        {
            Mode = "Read-only plan replay, no Broker or file actions executed",
            SourceEvidence = Path.GetFullPath(evidence),
            ReplaySampleRoot = sampleRoot,
            Session = session
        });
        Console.WriteLine(JsonSerializer.Serialize(new
        {
            session.SelectedFindingCount,
            session.SelectedTargetCount,
            session.PlannedCount,
            BatchCount = session.Plans.Count,
            QuarantineFiles = session.Plans.Sum(p => p.Actions.Count(a => a.Type == RemediationActionType.QuarantineFile)),
            Missing = session.Targets.Where(t => t.MissingActions.Count > 0).Select(t => new { t.Target, t.Reason })
        }, JsonFile.Options));
        return session.Targets.All(t => t.MissingActions.Count == 0 && t.ActionIds.Count > 0) ? 0 : 1;
    }
}
