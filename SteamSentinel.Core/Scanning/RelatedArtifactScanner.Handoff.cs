using System.ComponentModel;
using SteamSentinel.Core.Models;
using SteamSentinel.Core.Remediation;
using SteamSentinel.Core.Reporting;
using SteamSentinel.Core.Steam;
using SteamSentinel.Core.Utilities;

namespace SteamSentinel.Core.Scanning;

public sealed partial class RelatedArtifactScanner
{
    private const int MaximumHandoffs = 16;
    private const long MaximumHandoffPayloadBytes = 32L * 1024 * 1024;
    private string _handoffDirectory = Path.GetTempPath();
    private readonly Dictionary<string, SteamAlertUpdateHandoffProof> _handoffProofs = new(StringComparer.OrdinalIgnoreCase);
    private readonly HashSet<string> _observedHandoffHosts = new(StringComparer.OrdinalIgnoreCase);

    internal static IReadOnlyList<string> DiscoverHandoffCandidates(string directory, ScanReport report)
    {
        try
        {
            if ((File.GetAttributes(directory) & FileAttributes.Directory) == 0) return [];
            if (!ContentDiscovery.IsLocalSafePath(directory) || Validation.ContainsReparsePoint(directory))
                throw new IOException();
            string[] candidates = Directory.EnumerateFiles(directory, "sa_update_*.cmd", SearchOption.TopDirectoryOnly)
                .Take(MaximumHandoffs + 1).ToArray();
            if (candidates.Length > MaximumHandoffs) Note(report, MessageText.Create("SteamAlert.Handoff.Limit"));
            return candidates.Take(MaximumHandoffs).ToArray();
        }
        catch (Exception error) when (error is FileNotFoundException or DirectoryNotFoundException) { return []; }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException)
        { Note(report, MessageText.Create("SteamAlert.Handoff.Incomplete")); return []; }
    }

    private async Task CollectUpdateHandoffFilesAsync(HashSet<string> candidates, ScanReport report, CancellationToken token)
    {
        IEnumerable<string> scripts = candidates.Where(path => path.EndsWith(".cmd", StringComparison.OrdinalIgnoreCase)).ToArray();
        if (_installedFamilyScope) scripts = scripts.Concat(DiscoverHandoffCandidates(_handoffDirectory, report));
        string[] bounded = scripts.Distinct(StringComparer.OrdinalIgnoreCase).Take(MaximumHandoffs + 1).ToArray();
        if (bounded.Length > MaximumHandoffs) Note(report, MessageText.Create("SteamAlert.Handoff.Limit"));
        foreach (string script in bounded.Take(MaximumHandoffs))
        {
            if (_blockedPaths.Contains(script)) continue;
            SteamAlertUpdateHandoffProof? proof = await ReadHandoffProofAsync(script, report, token);
            if (proof is null) continue;
            // A copied template is not authority to follow its absolute references into
            // the live machine. Only this user's live Temp installation chain or an exact
            // interpreter instance observed in this collection can introduce those edges.
            if (!_observedHandoffHosts.Contains(script) &&
                (!_installedFamilyScope || !IsInstalledHandoffCandidate(proof, _proofs, _handoffDirectory))) continue;
            RegisterHandoffProof(proof, candidates, report);
        }
    }

    internal static bool IsInstalledHandoffCandidate(SteamAlertUpdateHandoffProof proof,
        IReadOnlyDictionary<string, Finding> installedProofs, string temporaryDirectory) =>
        RelatedArtifactRelations.SamePath(Path.GetDirectoryName(proof.Descriptor.ScriptPath) ?? string.Empty,
            Path.TrimEndingDirectorySeparator(temporaryDirectory)) &&
        proof.Payloads.Any(payload => installedProofs.TryGetValue(payload.Path, out Finding? known) &&
            RelatedArtifactRelations.IsFileEvidence(known) &&
            string.Equals(RelatedArtifactRelations.FileHash(known), payload.Sha256, StringComparison.OrdinalIgnoreCase));

    internal async Task<SteamAlertUpdateHandoffProof?> ReadHandoffProofAsync(string path, ScanReport report, CancellationToken token)
    {
        // Cached closure proofs have identity-checked leases. Ordinary scans deliberately
        // release their temporary leases and must re-read instead of reviving a stale proof.
        if (_closureOnly && _handoffProofs.TryGetValue(path, out var cached)) return cached;
        FileStream? temporary = null;
        try
        {
            if (_handoffProofs.Count >= MaximumHandoffs && !_handoffProofs.ContainsKey(path))
            { Note(report, MessageText.Create("SteamAlert.Handoff.Limit")); return null; }
            if (_blockedPaths.Contains(path) || !ContentDiscovery.IsLocalSafePath(path) || Validation.ContainsReparsePoint(path)) return null;
            FileStream stream;
            string hash;
            if (_closureOnly && _lockedIdentities.TryGetValue(path, out var identity))
            {
                stream = identity.Stream;
                hash = identity.Hash;
            }
            else
            {
                temporary = RelatedArtifactReader.Open(path);
                stream = temporary;
                if (stream.Length > SteamAlertUpdateHandoff.MaximumScriptBytes || stream.Length > _verificationByteLimit - _relatedBytesHashed ||
                    _relatedFilesHashed >= 2048 || _closureOnly && _lockedIdentities.Count >= 64)
                { Note(report, MessageText.Create("SteamAlert.Handoff.Limit")); return null; }
                _relatedFilesHashed++;
                hash = await Hashing.Sha256StreamAsync(stream, token,
                    count => { _relatedBytesHashed += count; report.Metrics.BytesHashed += count; }, SteamAlertUpdateHandoff.MaximumScriptBytes);
                if (_closureOnly) { _lockedIdentities.Add(path, (stream, hash)); temporary = null; }
            }
            if (stream.Length > SteamAlertUpdateHandoff.MaximumScriptBytes) return null;
            stream.Position = 0;
            byte[] bytes = new byte[checked((int)stream.Length)];
            await stream.ReadExactlyAsync(bytes, token);
            RelatedArtifactReader.ValidatePath(stream.SafeFileHandle, Path.GetFullPath(path));
            if (!SteamAlertUpdateHandoff.TryParse(bytes, path, out var descriptor)) return null;
            List<SteamAlertUpdatePayloadProof> payloads = [];
            foreach (string payload in new[] { descriptor.TargetExe, descriptor.StagedExe, descriptor.BackupExe })
            {
                token.ThrowIfCancellationRequested();
                if (_blockedPaths.Contains(payload)) continue;
                string? payloadHash = await ReadHandoffPayloadHashAsync(payload, report, token);
                if (SteamAlertWatchdog.RoleForHash(payloadHash) == SteamAlertWatchdog.PayloadRole)
                    payloads.Add(new(payload, payloadHash!));
            }
            SteamAlertUpdateHandoffProof? proof = payloads.Count == 0 ? null : new(descriptor, hash, payloads.AsReadOnly());
            if (proof is null) Note(report, MessageText.Create("SteamAlert.Handoff.Unconfirmed", path));
            else _handoffProofs[path] = proof;
            return proof;
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException or Win32Exception or OverflowException)
        { Note(report, MessageText.Create("SteamAlert.Handoff.Incomplete")); return null; }
        finally { if (temporary is not null) await temporary.DisposeAsync(); }
    }

    private async Task<string?> ReadHandoffPayloadHashAsync(string path, ScanReport report, CancellationToken token)
    {
        if (_lockedIdentities.TryGetValue(path, out var locked))
            return locked.Stream.Length <= MaximumHandoffPayloadBytes ? locked.Hash : null;
        FileStream? stream = null;
        bool retained = false;
        try
        {
            stream = RelatedArtifactReader.Open(path);
            if (stream.Length > MaximumHandoffPayloadBytes || stream.Length > _verificationByteLimit - _relatedBytesHashed ||
                _relatedFilesHashed >= 2048 || _closureOnly && _lockedIdentities.Count >= 64)
            { Note(report, MessageText.Create("SteamAlert.Handoff.Limit")); return null; }
            _relatedFilesHashed++;
            string hash = await Hashing.Sha256StreamAsync(stream, token,
                count => { _relatedBytesHashed += count; report.Metrics.BytesHashed += count; }, MaximumHandoffPayloadBytes);
            RelatedArtifactReader.ValidatePath(stream.SafeFileHandle, Path.GetFullPath(path));
            if (SteamAlertWatchdog.RoleForHash(hash) != SteamAlertWatchdog.PayloadRole)
            { Note(report, MessageText.Create("SteamAlert.Handoff.Unconfirmed", path)); return null; }
            if (_closureOnly) { _lockedIdentities.Add(path, (stream, hash)); retained = true; }
            return hash;
        }
        catch (Exception error) when (error is FileNotFoundException or DirectoryNotFoundException) { return null; }
        catch (Win32Exception error) when (error.NativeErrorCode is 2 or 3) { return null; }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException or Win32Exception)
        { Note(report, MessageText.Create("SteamAlert.Handoff.Incomplete")); return null; }
        finally { if (stream is not null && !retained) await stream.DisposeAsync(); }
    }

    private bool RegisterHandoffProof(SteamAlertUpdateHandoffProof proof, HashSet<string>? candidates, ScanReport report)
    {
        string[] relatedPaths = proof.Payloads.Select(payload => payload.Path).Prepend(proof.Descriptor.ScriptPath)
            .Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
        if (relatedPaths.Any(_blockedPaths.Contains) || candidates is not null &&
            candidates.Concat(relatedPaths).Distinct(StringComparer.OrdinalIgnoreCase).Take(65).Count() > 64 ||
            _proofs.Keys.Concat(relatedPaths).Distinct(StringComparer.OrdinalIgnoreCase).Take(65).Count() > 64)
        { Note(report, MessageText.Create("SteamAlert.Handoff.Limit")); return false; }
        string path = proof.Descriptor.ScriptPath;
        Finding script = new()
        {
            RuleId = SteamAlertUpdateHandoff.RuleId,
            ReasonCode = "KnownResidentUpdateHandoff",
            Category = FindingCategory.File,
            Severity = FindingSeverity.Critical,
            Score = 100,
            Target = path,
            Sha256 = proof.ScriptSha256,
            TargetSha256 = proof.ScriptSha256,
            ContentPath = path,
            CanRemediate = true,
            IsKnownMalware = false,
            TitleText = MessageText.Create("SteamAlert.Handoff.Title"),
            DescriptionText = MessageText.Create("SteamAlert.Handoff.Description"),
            EvidenceText = MessageText.Create("SteamAlert.Handoff.Evidence", proof.Descriptor.TargetExe, proof.Descriptor.WaitProcessId),
            SuggestedActions = [SuggestedActionKind.QuarantineFile]
        };
        _proofs[path] = script;
        _observations.Remove(path);
        if (!report.Findings.Any(f => f.RuleId == script.RuleId && RelatedArtifactRelations.SamePath(f.Target, path))) report.Findings.Add(script);
        candidates?.Add(path);
        AddCandidate(path, report);
        foreach (SteamAlertUpdatePayloadProof payload in proof.Payloads)
        {
            if (_blockedPaths.Contains(payload.Path)) continue;
            Finding? file = RegisterVerifiedFileFinding(payload.Path, payload.Sha256, null);
            if (file is not null && !report.Findings.Any(f => f.Category == FindingCategory.File &&
                RelatedArtifactRelations.SamePath(f.Target, payload.Path) && RelatedArtifactRelations.FileHash(f) == payload.Sha256)) report.Findings.Add(file);
            candidates?.Add(payload.Path);
            AddCandidate(payload.Path, report);
        }
        return true;
    }

    private async Task CollectHandoffHostsAsync(ScanReport report, CancellationToken token)
    {
        IReadOnlyList<PowerShellScriptHostSnapshot> hosts = PowerShellScriptHost.ReadAllByNames(["cmd"], token);
        foreach (PowerShellScriptHostSnapshot before in hosts.Take(256))
        {
            if (!before.IsReadable)
            {
                if (before.Status != ScriptHostReadStatus.Exited && _installedFamilyScope) Note(report, MessageText.Create("SteamAlert.Handoff.Incomplete"));
                continue;
            }
            if (!SteamAlertUpdateHandoff.IsTrustedImagePath(before.ImagePath)) continue;
            if (!SteamAlertUpdateHandoff.TryParseCommandLine(before.CommandLine, out string? path))
            {
                if (_installedFamilyScope && _handoffProofs.Keys.Any(script =>
                    before.CommandLine!.Contains(script, StringComparison.OrdinalIgnoreCase)))
                    Note(report, MessageText.Create("SteamAlert.Handoff.Incomplete"));
                continue;
            }
            if (_blockedPaths.Contains(path)) continue;
            SteamAlertUpdateHandoffProof? proof = await ReadHandoffProofAsync(path, report, token);
            if (proof is null) continue;
            if (_closureOnly && !proof.Payloads.Any(payload => _proofs.TryGetValue(payload.Path, out Finding? known) &&
                RelatedArtifactRelations.IsFileEvidence(known) &&
                string.Equals(RelatedArtifactRelations.FileHash(known), payload.Sha256, StringComparison.OrdinalIgnoreCase))) continue;
            try
            {
                // The initial scan has no long-lived closure leases. Hold this exact script
                // unchanged across both process reads and the system-image hash as well.
                await using FileStream activeScript = RelatedArtifactReader.Open(path);
                if (activeScript.Length > SteamAlertUpdateHandoff.MaximumScriptBytes ||
                    activeScript.Length > _verificationByteLimit - _relatedBytesHashed)
                { Note(report, MessageText.Create("SteamAlert.Handoff.Limit")); continue; }
                string currentScriptHash = await Hashing.Sha256StreamAsync(activeScript, token,
                    bytes => { _relatedBytesHashed += bytes; report.Metrics.BytesHashed += bytes; }, SteamAlertUpdateHandoff.MaximumScriptBytes);
                if (!currentScriptHash.Equals(proof.ScriptSha256, StringComparison.OrdinalIgnoreCase))
                { Note(report, MessageText.Create("SteamAlert.Handoff.Incomplete")); continue; }
                await using FileStream image = RelatedArtifactReader.Open(before.ImagePath!);
                if (image.Length > 16L * 1024 * 1024 || image.Length > _verificationByteLimit - _relatedBytesHashed)
                { Note(report, MessageText.Create("SteamAlert.Handoff.Limit")); continue; }
                string imageHash = await Hashing.Sha256StreamAsync(image, token,
                    bytes => { _relatedBytesHashed += bytes; report.Metrics.BytesHashed += bytes; }, 16L * 1024 * 1024);
                PowerShellScriptHostSnapshot after = PowerShellScriptHost.ReadRaw(before.ProcessId);
                Finding? host = CreateHandoffHostFinding(before, after, imageHash, proof);
                if (host is null) { Note(report, MessageText.Create("SteamAlert.Handoff.Incomplete")); continue; }
                if (!RegisterHandoffProof(proof, null, report)) continue;
                _observedHandoffHosts.Add(path);
                AddCurrent(host, report);
            }
            catch (Exception error) when (error is IOException or UnauthorizedAccessException or Win32Exception)
            { Note(report, MessageText.Create("SteamAlert.Handoff.Incomplete")); }
        }
        if (hosts.Count > 256 && _installedFamilyScope) Note(report, MessageText.Create("SteamAlert.Handoff.Limit"));
    }

    internal static Finding? CreateHandoffHostFinding(PowerShellScriptHostSnapshot before, PowerShellScriptHostSnapshot after,
        string imageHash, SteamAlertUpdateHandoffProof proof)
    {
        if (before.ProcessId <= 4 || !PowerShellScriptHost.SameRawIdentity(before, after) || !SteamAlertUpdateHandoff.IsTrustedImagePath(before.ImagePath) ||
            !Validation.IsHexSha256(imageHash) || !Validation.IsHexSha256(proof.ScriptSha256) ||
            proof.Payloads.Count is < 1 or > 3 || !proof.Payloads.All(payload =>
                SteamAlertWatchdog.RoleForHash(payload.Sha256) == SteamAlertWatchdog.PayloadRole &&
                new[] { proof.Descriptor.TargetExe, proof.Descriptor.StagedExe, proof.Descriptor.BackupExe }.Any(path =>
                    RelatedArtifactRelations.SamePath(payload.Path, path))) ||
            !SteamAlertUpdateHandoff.TryParseCommandLine(before.CommandLine, out string? script) ||
            !RelatedArtifactRelations.SamePath(script, proof.Descriptor.ScriptPath)) return null;
        return new Finding
        {
            RuleId = "STEAMALERT-HANDOFF-HOST",
            ReasonCode = "KnownResidentUpdateHandoff",
            Category = FindingCategory.Process,
            Severity = FindingSeverity.Critical,
            Score = 100,
            Target = before.ImagePath!,
            Sha256 = imageHash,
            ProcessId = before.ProcessId,
            ProcessStartedAtUtc = before.StartedAtUtc,
            RelatedFilePath = script,
            RelatedFileSha256 = proof.ScriptSha256,
            ConfigurationKind = SteamAlertUpdateHandoff.ScriptHostKind,
            ConfigurationSnapshot = before.CommandLine,
            IsKnownMalware = false,
            CanRemediate = true,
            TitleText = MessageText.Create("SteamAlert.Handoff.HostTitle"),
            DescriptionText = MessageText.Create("SteamAlert.Watchdog.HostDescription"),
            EvidenceText = MessageText.Create("SteamAlert.Handoff.Evidence", proof.Descriptor.TargetExe, proof.Descriptor.WaitProcessId),
            SuggestedActions = [SuggestedActionKind.StopHostProcess]
        };
    }
}
