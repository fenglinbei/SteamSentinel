using System.IO;
using System.Security.Principal;
using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.Win32;
using SteamSentinel.App.Services;
using SteamSentinel.Broker;
using SteamSentinel.Core.Models;
using SteamSentinel.Core.Remediation;
using SteamSentinel.Core.Rules;
using SteamSentinel.Core.Scanning;
using SteamSentinel.Core.Steam;
using SteamSentinel.Core.Utilities;

namespace SteamSentinel.SelfTest;

// Private laboratory driver, absent from the application package. It exercises the real
// planner/engine under a test administrator, not the interactive UAC/confirmation workflow.
// No target DLL is loaded or invoked by this driver. VPet launches belong to the VM harness.
internal static class V030LabDriver
{
    private const string LabRoot = @"C:\Lab\Step5";
    private const string EvidenceRoot = @"C:\Lab\Step5\EvidenceV4";
    private static readonly string[] Roots =
    [
        @"C:\Steam\steamapps\common\VPet\mod",
        @"C:\Steam\steamapps\workshop\content\1920960",
        @"C:\Lab\Step5\ManualCopies"
    ];

    public static async Task<int> RunAsync(string operation, string episode)
    {
        if (operation is not ("scan" or "quarantine-known" or "quarantine-known-and-cfg" or "preflight") ||
            !Regex.IsMatch(episode, "^[a-z0-9][a-z0-9-]{0,47}$", RegexOptions.CultureInvariant))
            throw new InvalidDataException("Invalid lab operation or episode.");
        AssertLaboratory();
        foreach (string protectedPath in new[] { @"C:\Lab", LabRoot, EvidenceRoot })
            MachineStateSecurity.EnsureProtectedPath(protectedPath);
        string output = Path.Combine(EvidenceRoot, episode);
        if (Directory.Exists(output)) throw new IOException("An evidence episode may not be overwritten.");
        Directory.CreateDirectory(output);
        if (operation == "preflight")
        {
            InstallationSecurityStatus installation = InstallationSecurity.Evaluate();
            if (!installation.IsProtected) throw new UnauthorizedAccessException(installation.Message);
            MachineStateSecurity.EnsureProtectedRoots();
            await JsonFile.WriteNewAsync(Path.Combine(output, "summary.json"), new
            {
                operation,
                episode,
                installationProtected = true,
                machineStateProtected = true,
                evidenceProtected = true,
                brokerSha256 = await Hashing.Sha256FileAsync(typeof(BrokerEngine).Assembly.Location),
                coreSha256 = await Hashing.Sha256FileAsync(typeof(ScanReport).Assembly.Location),
                completedAtUtc = DateTimeOffset.UtcNow
            });
            return 0;
        }
        RuleSet rules = RuleLoader.LoadEmbedded();
        string[] existingRoots = Roots.Where(Directory.Exists).ToArray();
        foreach (string root in existingRoots)
            if (Validation.ContainsReparsePoint(root)) throw new InvalidDataException("Reparse lab scan root.");
        if (existingRoots.Length == 0) throw new InvalidDataException("No laboratory content roots.");
        using CancellationTokenSource budget = new(TimeSpan.FromMinutes(8));
        ScanReport report = await new ArchiveWorkerClient(Path.Combine(AppContext.BaseDirectory,
            "SteamSentinel.ArchiveWorker.exe")).RunAsync(new ScanOptions
            {
                Mode = ScanMode.Custom,
                IncludeSystem = false,
                IncludeSteam = false,
                IncludeWorkshop = false,
                UseAmsi = ScanEnhancements.AmsiAvailable,
                HashEveryFile = true,
                InspectArchives = true,
                CustomRoots = existingRoots.ToList()
            }, (request, _) => Task.FromResult(new ArchivePasswordResponse(request.RequestId, true, null, false)),
            null, budget.Token);
        await JsonFile.WriteNewAsync(Path.Combine(output, "content-scan.json"), report);
        ScanReport steam = new();
        await new SteamSecurityScanner(rules).ScanAsync(SteamLocator.Discover(), steam, budget.Token);
        await JsonFile.WriteNewAsync(Path.Combine(output, "steam-scan.json"), steam);

        Finding[] selected = report.Findings.Where(f => f.IsKnownMalware && f.CanRemediate &&
            f.Category == FindingCategory.File && f.TargetSha256 is { Length: 64 } &&
            Roots.Any(root => IsChild(f.Target, root))).ToArray();
        RemediationPlan? plan = null;
        RemediationRunResult? result = null;
        var knownSourceAttributes = selected.Select(f => new { f.Target, attributes = (int)File.GetAttributes(f.Target) }).ToArray();
        Finding? configuration = operation == "quarantine-known-and-cfg"
            ? await SelectObservedLabConfigurationAsync(steam, selected) : null;
        if (operation is "quarantine-known" or "quarantine-known-and-cfg")
        {
            using WindowsIdentity identity = WindowsIdentity.GetCurrent();
            if (!new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator))
                throw new UnauthorizedAccessException("The lab engine test requires a test administrator.");
            InstallationSecurityStatus installation = InstallationSecurity.Evaluate();
            if (!installation.IsProtected) throw new UnauthorizedAccessException(installation.Message);
            if (selected.Length == 0) throw new InvalidDataException("No precisely identified malicious files to quarantine.");
            Finding[] chosen = configuration is null ? selected : [.. selected, configuration];
            plan = await new RemediationPlanBuilder(rules).BuildAsync(chosen, false, budget.Token);
            if (plan.Actions.Count != chosen.Select(f => f.Target).Distinct(StringComparer.OrdinalIgnoreCase).Count() ||
                plan.Actions.Any(a => a.Type != RemediationActionType.QuarantineFile ||
                    a.ExpectedSha256 is not { Length: 64 } ||
                    !(a.IsKnownMalware && Roots.Any(root => IsChild(a.Target, root)) ||
                      configuration is not null && !a.IsKnownMalware &&
                      a.Target.Equals(LabConfigurationPath, StringComparison.OrdinalIgnoreCase) &&
                      a.ExpectedSha256.Equals(LabConfigurationSha256, StringComparison.OrdinalIgnoreCase))))
                throw new InvalidDataException("Only exact known source files and the separately verified lab configuration may be quarantined.");
            await JsonFile.WriteNewAsync(Path.Combine(output, "plan.json"), plan);
            MachineStateSecurity.EnsureProtectedRoots();
            if (!BrokerMutationLease.TryAcquire(out BrokerMutationLease? lease))
                throw new IOException("Another Broker mutation is active.");
            using (lease) result = await new BrokerEngine().ExecuteAsync(plan, budget.Token);
            await JsonFile.WriteNewAsync(Path.Combine(output, "engine-result.json"), result);
        }
        await JsonFile.WriteNewAsync(Path.Combine(output, "summary.json"), new
        {
            schema = 1,
            operation,
            episode,
            version = ProductInfo.Version,
            buildIdentity = ProductInfo.BuildIdentity,
            coreSha256 = await Hashing.Sha256FileAsync(typeof(ScanReport).Assembly.Location),
            contentCoverage = report.Coverage,
            report.Metrics,
            findings = report.Findings.Select(f => new { f.RuleId, f.Category, f.Target, f.TargetSha256, f.IsKnownMalware, f.CanRemediate }),
            selectedKnownSources = selected.Length,
            knownSourceAttributes,
            selectedConfigurationFiles = configuration is null ? 0 : 1,
            steamCoverage = steam.Coverage,
            steamFindings = steam.Findings.Select(f => new { f.RuleId, f.Target, f.TargetSha256, f.IsKnownMalware, f.CanRemediate, f.SteamUiEvidence }),
            plannedActions = plan?.Actions.Count,
            engineResult = result is null ? null : new { result.Success, result.Disposition, result.IncidentId, result.Actions, result.Errors },
            uiConfirmationTested = false,
            steamRecoveryVerified = false,
            rebootVerified = false,
            completedAtUtc = DateTimeOffset.UtcNow
        });
        Console.WriteLine(JsonSerializer.Serialize(new { operation, episode, known = selected.Length, engineSuccess = result?.Success }));
        return result is { Success: false } ? 1 : 0;
    }

    private const string LabConfigurationPath = @"C:\Steam\steam.cfg";
    private const string LabConfigurationSha256 = "C9799659EC6E3E786F68D73EEC26E7EB1190708CAAD875711096C98F1AAC4E24";

    private static async Task<Finding?> SelectObservedLabConfigurationAsync(ScanReport steam, Finding[] selected)
    {
        if (!File.Exists(LabConfigurationPath)) return null;
        Finding[] matches = steam.Findings.Where(f =>
            f.RuleId == "STEAM-CFG-UPDATE-SUPPRESSION-PAIR" && f.CanRemediate && !f.IsKnownMalware &&
            f.Target.Equals(LabConfigurationPath, StringComparison.OrdinalIgnoreCase) &&
            string.Equals(f.Sha256, LabConfigurationSha256, StringComparison.OrdinalIgnoreCase)).ToArray();
        const string chunk = @"C:\Steam\steamui\chunk~2dcc5aaf7.js";
        const string cleanChunk = "F9606B111203C9140DCDD6FC016A0EE00E4C8406AEB786187C42873F08D071FB";
        const string modifiedChunk = "76CFCA6B71CF761E186DEFAC54912753D19403A279B5078E1C4E37C77AE30449";
        if (matches.Length != 1 || selected.Length != 12 ||
            !steam.Findings.Any(f => f.RuleId == "STEAM-UI-SEMANTIC-TAMPERING" &&
                f.Target.Equals(chunk, StringComparison.OrdinalIgnoreCase)) ||
            Validation.ContainsReparsePoint(chunk) ||
            !modifiedChunk.Equals(await Hashing.Sha256FileAsync(chunk), StringComparison.OrdinalIgnoreCase))
            throw new InvalidDataException("Exact lab configuration, source count and observed Steam modification required.");
        using JsonDocument proof = ReadProtectedEvent("installed");
        JsonElement snapshot = proof.RootElement.GetProperty("data").GetProperty("snapshot");
        if (snapshot.GetProperty("steamCfg").GetProperty("present").GetBoolean() ||
            snapshot.GetProperty("steamChanged").GetArrayLength() != 0)
            throw new InvalidDataException("This operation requires a clean Steam baseline with no pre-existing steam.cfg.");
        string caseName = proof.RootElement.GetProperty("data").GetProperty("case").GetString() ?? "";
        (string workshopId, string module) = caseName switch
        {
            "SmartPet" => ("999000001", @"plugin\SmartPet.dll"),
            "TianLai" => ("999000002", @"plugin\VPet.Plugin.TianLaiZhiYin.dll"),
            "Scratch" => ("999000003", @"plugin\VPet.Plugin.ScratchCard.dll"),
            _ => throw new InvalidDataException("Unknown lab case.")
        };
        string[] exactRoots = [Path.Combine(Roots[0], "SSLab-" + caseName), Path.Combine(Roots[1], workshopId), Path.Combine(Roots[2], caseName)];
        if (selected.Any(f => !exactRoots.Any(root => IsChild(f.Target, root))) ||
            exactRoots.Any(root => selected.Count(f => IsChild(f.Target, root)) != 4))
            throw new InvalidDataException("Expected four known sources in each of the three exact case copies.");
        using JsonDocument load = ReadProtectedEvent("load-observation");
        JsonElement observation = load.RootElement.GetProperty("data");
        if (observation.GetProperty("case").GetString() != caseName ||
            !observation.GetProperty("steamCfg").GetProperty("present").GetBoolean() ||
            observation.GetProperty("steamCfg").GetProperty("sha256").GetString() != LabConfigurationSha256 ||
            !observation.GetProperty("steamChanged").EnumerateArray().Any(e =>
                e.GetProperty("path").GetString() == @"steamui\chunk~2dcc5aaf7.js" &&
                e.GetProperty("before").GetString() == cleanChunk && e.GetProperty("actual").GetString() == modifiedChunk) ||
            !observation.GetProperty("processes").EnumerateArray().Any(p =>
                p.GetProperty("path").GetString() == @"C:\Steam\steamapps\common\VPet\VPet-Simulator.Windows.exe" &&
                p.GetProperty("sha256").GetString() == "A0340846C307389A5C2C1700DAEAD32B759E86401462BC0CDC1BAB075BF7C47A" &&
                p.GetProperty("sampleModules").EnumerateArray().Any(m => string.Equals(m.GetString(),
                    Path.Combine(exactRoots[0], module), StringComparison.OrdinalIgnoreCase))))
            throw new InvalidDataException("Protected evidence must show this exact plugin loaded in official VPet and created the observed configuration and chunk change.");
        // Keep IsKnownMalware false. This is an explicit, separately evidenced lab
        // selection of an existing product action, never a new broad malware rule.
        return matches[0];
    }

    private static JsonDocument ReadProtectedEvent(string episode)
    {
        string path = Path.Combine(EvidenceRoot, "event-" + episode + ".json");
        MachineStateSecurity.EnsureProtectedPath(EvidenceRoot);
        MachineStateSecurity.EnsureProtectedPath(path);
        if (new FileInfo(path).Length > 1024 * 1024) throw new InvalidDataException("Oversized lab evidence.");
        JsonDocument proof = JsonDocument.Parse(File.ReadAllBytes(path));
        if (proof.RootElement.GetProperty("schema").GetInt32() != 2 ||
            proof.RootElement.GetProperty("runId").GetString() != "v4" ||
            proof.RootElement.GetProperty("episode").GetString() != episode)
        {
            proof.Dispose();
            throw new InvalidDataException("Wrong lab evidence identity.");
        }
        return proof;
    }

    private static void AssertLaboratory()
    {
        if (!Environment.MachineName.Equals("STEAMLAB", StringComparison.OrdinalIgnoreCase) ||
            !Directory.Exists(LabRoot) || Validation.ContainsReparsePoint(LabRoot))
            throw new UnauthorizedAccessException("This utility is restricted to the isolated STEAMLAB test VM.");
        using RegistryKey? key = Registry.LocalMachine.OpenSubKey(@"HARDWARE\DESCRIPTION\System\BIOS");
        if (!string.Equals(key?.GetValue("SystemManufacturer") as string, "Microsoft Corporation", StringComparison.Ordinal) ||
            !string.Equals(key?.GetValue("SystemProductName") as string, "Virtual Machine", StringComparison.Ordinal))
            throw new UnauthorizedAccessException("Hyper-V test guest required.");
    }

    private static bool IsChild(string path, string root) => Path.GetFullPath(path).StartsWith(
        Path.TrimEndingDirectorySeparator(Path.GetFullPath(root)) + Path.DirectorySeparatorChar,
        StringComparison.OrdinalIgnoreCase);
}
