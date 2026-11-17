using System.IO;
using System.Text;
using SteamSentinel.Core.Models;
using SteamSentinel.Core.Remediation;
using SteamSentinel.Core.Rules;
using SteamSentinel.Core.Scanning;
using SteamSentinel.Core.Steam;
using SteamSentinel.Core.Utilities;

namespace SteamSentinel.SelfTest;

internal static partial class Program
{
    private static async Task TestSteamAlertHandoffDiscoveryAsync(string root)
    {
        string fixture = Path.Combine(root, "handoff-discovery-" + Guid.NewGuid().ToString("N"));
        string temporary = Path.Combine(fixture, "Temp"), downloads = Path.Combine(fixture, "Downloads");
        string resident = Path.Combine(fixture, "SteamAlertDemo");
        foreach (string directory in new[] { temporary, downloads, resident }) Directory.CreateDirectory(directory);
        const int pid = 8124;
        string script = Path.Combine(temporary, "sa_update_" + pid + ".cmd");
        string target = Path.Combine(resident, "Application Frame Host.exe");
        string staged = Path.Combine(resident, "Application Frame Host.new.exe");
        SteamAlertUpdateHandoffDescriptor descriptor = new(script, pid, target, staged, target + ".bak");
        string text = SteamAlertUpdateHandoff.CreateTemplate(descriptor);
        await File.WriteAllTextAsync(script, text, new UTF8Encoding(true));
        await File.WriteAllTextAsync(target, "inert benign payload; never executable code");
        string scriptHash = await Hashing.Sha256FileAsync(script);
        RelatedArtifactScanner reader = new(RuleLoader.LoadEmbedded());
        ScanReport noPayload = new();
        Check("Handoff ordinary scan never upgrades a full template without a known payload",
            await reader.ReadHandoffProofAsync(script, noPayload, default) is null && noPayload.Metrics.BytesHashed > 0 &&
            noPayload.Findings.All(f => !f.CanRemediate));
        await File.AppendAllTextAsync(script, "rem altered inert fixture\r\n");
        Check("Handoff ordinary scan rejects an altered template on a fresh read",
            await reader.ReadHandoffProofAsync(script, new ScanReport(), default) is null);
        await File.WriteAllTextAsync(script, text, new UTF8Encoding(true));

        const string payloadHash = "54799E1B7B90961F29284226210CD6029CAB87EC82635B3FB7AB99D0BDB72FE2";
        // These records model already-verified evidence for pure association tests. The
        // I/O reader above still rejects the actual benign bytes at this fixture path.
        SteamAlertUpdateHandoffProof proof = new(descriptor, scriptHash, [new(target, payloadHash)]);
        Finding payloadFinding = new()
        {
            RuleId = SteamAlertInstallation.UpdatedResidentRule,
            Category = FindingCategory.File,
            Target = target,
            ContentPath = target,
            Sha256 = payloadHash,
            TargetSha256 = payloadHash,
            IsKnownMalware = true,
            CanRemediate = true,
            Score = 100,
            SuggestedActions = [SuggestedActionKind.QuarantineFile]
        };
        Dictionary<string, Finding> installed = new(StringComparer.OrdinalIgnoreCase) { [target] = payloadFinding };
        Check("Handoff current Temp template may follow only an existing exact installation proof",
            RelatedArtifactScanner.IsInstalledHandoffCandidate(proof, installed, temporary) &&
            !RelatedArtifactScanner.IsInstalledHandoffCandidate(proof, new Dictionary<string, Finding>(), temporary));
        SteamAlertUpdateHandoffProof offline = proof with { Descriptor = descriptor with { ScriptPath = Path.Combine(downloads, Path.GetFileName(script)) } };
        Check("Handoff Downloads template copy cannot follow absolute paths into the live installation",
            !RelatedArtifactScanner.IsInstalledHandoffCandidate(offline, installed, temporary));
        Check("Handoff script association rejects a different payload hash snapshot",
            !RelatedArtifactScanner.IsInstalledHandoffCandidate(proof with { Payloads = [new(target, new string('B', 64))] }, installed, temporary));

        string cmd = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "System32", "cmd.exe");
        PowerShellScriptHostSnapshot host = new()
        {
            ProcessId = 8225,
            ParentProcessId = pid,
            StartedAtUtc = DateTimeOffset.UtcNow,
            ImagePath = cmd,
            CommandLine = "\"" + cmd + "\" /c \"" + script + "\"",
            Status = ScriptHostReadStatus.Readable
        };
        string imageHash = new('A', 64);
        Finding? active = RelatedArtifactScanner.CreateHandoffHostFinding(host, host, imageHash, proof);
        Check("Handoff active updater creates an exact system-CMD host action without declaring cmd.exe malware",
            active is { CanRemediate: true, IsKnownMalware: false, ConfigurationKind: SteamAlertUpdateHandoff.ScriptHostKind } &&
            active.RelatedFileSha256 == scriptHash && active.ConfigurationSnapshot == host.CommandLine &&
            active.SuggestedActions.SequenceEqual([SuggestedActionKind.StopHostProcess]));
        Check("Handoff host needs both stable process reads and unchanged complete command line",
            RelatedArtifactScanner.CreateHandoffHostFinding(host, host with { StartedAtUtc = host.StartedAtUtc!.Value.AddSeconds(1) }, imageHash, proof) is null &&
            RelatedArtifactScanner.CreateHandoffHostFinding(host, host with { CommandLine = host.CommandLine + " & echo benign" }, imageHash, proof) is null &&
            RelatedArtifactScanner.CreateHandoffHostFinding(host, host with { Status = ScriptHostReadStatus.AccessDenied }, imageHash, proof) is null);
        Check("Handoff host cannot be authorized by template alone or unrelated payload proof",
            RelatedArtifactScanner.CreateHandoffHostFinding(host, host, imageHash, proof with { Payloads = [] }) is null &&
            RelatedArtifactScanner.CreateHandoffHostFinding(host, host, imageHash, proof with
            { Payloads = [new(Path.Combine(downloads, "unrelated.exe"), payloadHash)] }) is null);
        PowerShellScriptHostSnapshot imitation = host with { ImagePath = Path.Combine(downloads, "cmd.exe") };
        Check("Handoff host refuses an executable merely named cmd.exe",
            RelatedArtifactScanner.CreateHandoffHostFinding(imitation, imitation, imageHash, proof) is null);

        string nested = Path.Combine(temporary, "nested");
        Directory.CreateDirectory(nested);
        await File.WriteAllTextAsync(Path.Combine(nested, "sa_update_9999.cmd"), "inert");
        await File.WriteAllTextAsync(Path.Combine(temporary, "ordinary.cmd"), "inert");
        IReadOnlyList<string> discovered = RelatedArtifactScanner.DiscoverHandoffCandidates(temporary, new ScanReport());
        Check("Handoff candidate discovery only examines the top-level sa_update pattern",
            discovered.SequenceEqual([script]));
        for (int index = 0; index < 17; index++)
            await File.WriteAllTextAsync(Path.Combine(temporary, "sa_update_" + (9000 + index) + ".cmd"), "inert");
        ScanReport limited = new();
        Check("Handoff candidate enumeration is bounded with an explicit coverage limitation",
            RelatedArtifactScanner.DiscoverHandoffCandidates(temporary, limited).Count == 16 &&
            limited.CoverageTexts.Any(note => note.Message?.MessageId == "SteamAlert.Handoff.Limit"));
    }

    // Explicit opt-in static sample verification. The supplied bytes are hashed before
    // being copied into an isolated fixture; neither the PE nor the CMD is ever started.
    private static async Task TestSteamAlertHandoffStaticSampleAsync(string root, string samplePath)
    {
        byte[] sample;
        await using (FileStream source = new(samplePath, FileMode.Open, FileAccess.Read, FileShare.Read))
        {
            if (source.Length > 32 * 1024 * 1024) throw new InvalidDataException("Static sample byte limit exceeded.");
            sample = new byte[checked((int)source.Length)];
            await source.ReadExactlyAsync(sample);
        }
        string sampleHash = Hashing.Sha256Bytes(sample);
        if (sample.Length > 32 * 1024 * 1024 || SteamAlertWatchdog.RoleForHash(sampleHash) != SteamAlertWatchdog.PayloadRole)
            throw new InvalidDataException("The explicit static sample must have a compiled SteamAlert resident hash.");
        string fixture = Path.Combine(root, "handoff-static-" + Guid.NewGuid().ToString("N"));
        string resident = Path.Combine(fixture, "SteamAlertDemo"), updater = Path.Combine(fixture, "SteamAlertUpdater");
        string temporary = Path.Combine(fixture, "Temp"), downloads = Path.Combine(fixture, "Downloads");
        foreach (string directory in new[] { resident, updater, temporary, downloads }) Directory.CreateDirectory(directory);
        string staged = Path.Combine(resident, "Application Frame Host.new.exe");
        string target = Path.Combine(resident, "Application Frame Host.exe");
        await File.WriteAllBytesAsync(staged, sample);
        string script = Path.Combine(temporary, "sa_update_8124.cmd");
        SteamAlertUpdateHandoffDescriptor descriptor = new(script, 8124, target, staged, target + ".bak");
        string template = SteamAlertUpdateHandoff.CreateTemplate(descriptor);
        await File.WriteAllTextAsync(script, template, new UTF8Encoding(true));
        RuleSet rules = RuleLoader.LoadEmbedded();
        RelatedArtifactScanner scanner = new(rules);
        ScanReport ordinary = new();
        SteamAlertUpdateHandoffProof? read = await scanner.ReadHandoffProofAsync(script, ordinary, default);
        Check("Handoff ordinary scan verifies known staged payload without closure-only leases",
            read is not null && read.Payloads.Any(payload => payload.Path == staged && payload.Sha256 == sampleHash) &&
            read.ScriptSha256 == await Hashing.Sha256FileAsync(script));
        await File.AppendAllTextAsync(script, "rem changed after the first static read\r\n");
        Check("Handoff ordinary scan never reuses cached proof after the script changes",
            await scanner.ReadHandoffProofAsync(script, new ScanReport(), default) is null);
        await File.WriteAllTextAsync(script, template, new UTF8Encoding(true));
        Finding stagedFinding = new()
        {
            Category = FindingCategory.File,
            RuleId = rules.KnownHashes.Single(rule => rule.Sha256 == sampleHash).Id,
            Target = staged,
            ContentPath = staged,
            Sha256 = sampleHash,
            TargetSha256 = sampleHash,
            CanRemediate = true,
            IsKnownMalware = true,
            Score = 100,
            SuggestedActions = [SuggestedActionKind.QuarantineFile]
        };
        RelatedArtifactExpansion expanded = await new RelatedArtifactScanner(rules).ExpandLocalAsync([stagedFinding],
            new ScanReport { Findings = [stagedFinding] }, default, RelatedArtifactScanner.MaximumVerificationBytes,
            true, new SteamLayout(), resident, updater, temporary);
        Check("Handoff installed staged payload expands the matching Temp handoff with byte-bound evidence",
            expanded.Findings.Any(finding => finding.RuleId == SteamAlertUpdateHandoff.RuleId && finding.Target == script && finding.CanRemediate) &&
            expanded.Findings.Any(finding => finding.Target == staged && finding.Sha256 == sampleHash));
        string copy = Path.Combine(downloads, Path.GetFileName(script));
        File.Copy(script, copy);
        Finding candidate = new()
        {
            RuleId = "STEAMALERT-UPDATE-HANDOFF-CANDIDATE",
            Category = FindingCategory.File,
            Target = copy,
            ContentPath = copy,
            Sha256 = await Hashing.Sha256FileAsync(copy),
            CanRemediate = false,
            SuggestedActions = [SuggestedActionKind.ReviewOnly]
        };
        RelatedArtifactExpansion offline = await new RelatedArtifactScanner(rules).ExpandLocalAsync([candidate],
            new ScanReport { Findings = [candidate] }, default, RelatedArtifactScanner.MaximumVerificationBytes,
            true, new SteamLayout(), resident, updater, temporary);
        Check("Handoff offline template copy never authorizes installed payload or Temp handoff cleanup",
            !offline.Findings.Any(finding => finding.CanRemediate && (finding.Target == staged || finding.Target == script || finding.Target == copy)));
        RelatedArtifactExpansion budgeted = await new RelatedArtifactScanner(rules).ExpandLocalAsync([stagedFinding],
            new ScanReport { Findings = [stagedFinding] }, default, sample.Length,
            true, new SteamLayout(), resident, updater, temporary);
        Check("Handoff expansion cannot add a dynamic script after the verification byte budget is exhausted",
            !budgeted.Findings.Any(finding => finding.RuleId == SteamAlertUpdateHandoff.RuleId && finding.CanRemediate) &&
            budgeted.VerificationBytesRead <= sample.Length);
    }
}
