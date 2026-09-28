using System.Text.Json.Serialization;
using SteamSentinel.Core.Reporting;
using System.ComponentModel;
using System.Diagnostics;
using System.Xml;
using Microsoft.Win32;
using SteamSentinel.Core.Inspection;
using SteamSentinel.Core.Models;
using SteamSentinel.Core.Remediation;
using SteamSentinel.Core.Steam;
using SteamSentinel.Core.Utilities;

namespace SteamSentinel.Core.Scanning;

public sealed record RelatedArtifactExpansion(IReadOnlyList<Finding> Findings, IReadOnlyList<string> CandidatePaths, IReadOnlyList<string> Notes)
{
    public long VerificationBytesRead { get; init; }
    public IReadOnlyList<string> ScopeNotes { get; init; } = [];
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] public Dictionary<int, DisplayMessage>? NoteMessages { get => SteamSentinel.Core.Models.DisplayMessageMap.Bound(Notes, field); init => field = value; }
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] public Dictionary<int, DisplayMessage>? ScopeNoteMessages { get => SteamSentinel.Core.Models.DisplayMessageMap.Bound(ScopeNotes, field); init => field = value; }
    [JsonIgnore] public IEnumerable<MessageText> NoteTexts => DisplayMessageMap.Read(Notes, NoteMessages);
    [JsonIgnore] public IEnumerable<MessageText> ScopeTexts => DisplayMessageMap.Read(ScopeNotes, ScopeNoteMessages);
}

public sealed partial class RelatedArtifactScanner
{
    private readonly Dictionary<string, Finding> _proofs = new(StringComparer.OrdinalIgnoreCase);
    private readonly HashSet<string> _blockedPaths = new(StringComparer.OrdinalIgnoreCase);
    private Finding[] _previous = [];
    private bool _closureOnly;

    // Sessions are independent: concurrent callers cannot share budgets or stale cached hashes.
    public Task CollectAsync(SteamLayout layout, ScanReport report, ScanOptions options, CancellationToken token) =>
        new RelatedArtifactScanner(rules).CollectCoreAsync(layout, report, options, token);

    public Task<(string Path, string Hash)?> MatchCommandAsync(string command, ScanReport report, CancellationToken token) =>
        new RelatedArtifactScanner(rules).MatchCoreAsync(command, report, token);

    /// <summary>Read-only snapshot validation. CandidatePaths must be checked by the UI's Low Worker before a second expansion.</summary>
    public async Task<RelatedArtifactExpansion> ExpandAsync(IEnumerable<Finding> selectedFindings, ScanReport report, CancellationToken token = default,
        long maximumVerificationBytes = MaximumVerificationBytes)
    {
        RelatedArtifactScanner session = new(rules) { _verificationByteLimit = Math.Clamp(maximumVerificationBytes, 0, MaximumVerificationBytes) };
        try { return await session.ExpandCoreAsync(selectedFindings, report, token); }
        finally
        {
            foreach (var identity in session._lockedIdentities.Values) await identity.Stream.DisposeAsync();
            session._lockedIdentities.Clear();
        }
    }

    public Task<RelatedArtifactExpansion> ExpandAsync(ScanReport report, CancellationToken token = default) =>
        ExpandAsync(report.Findings, report, token);

    public async Task<IReadOnlyList<string>> GetCandidatePathsAsync(Finding finding, CancellationToken token = default)
    {
        ScanReport scratch = new();
        return await GetCandidatePathsCoreAsync(finding, scratch, token);
    }

    private async Task<IReadOnlyList<string>> GetCandidatePathsCoreAsync(Finding finding, ScanReport report, CancellationToken token)
    {
        token.ThrowIfCancellationRequested();
        List<string> paths = FindingReviewTargets.Get(finding);
        if (IsTask(finding))
        {
            // Never parse the finding's Evidence as XML or treat a task name as a filesystem path.
            paths.Clear();
            try
            {
                RelatedTaskSnapshot snapshot = await RelatedTaskSnapshotReader.ReadAsync(finding.Target, token);
                if (finding.Sha256 is { } expected && !expected.Equals(snapshot.Sha256, StringComparison.OrdinalIgnoreCase))
                { Note(report, MessageText.Create("Backend.Core.RelatedArtifactExpansion.GetCandidatePathsCoreAsync.01") + finding.Target); return []; }
                if (finding.ConfigurationSnapshot is { } command && !snapshot.Commands.Contains(command, StringComparer.Ordinal) &&
                    !string.Equals(command, string.Join("\n", snapshot.Commands), StringComparison.Ordinal) &&
                    !snapshot.Invocations.Contains(command, StringComparer.Ordinal) && !string.Equals(command, string.Join("\n", snapshot.Invocations), StringComparison.Ordinal))
                { Note(report, MessageText.Create("Backend.Core.RelatedArtifactExpansion.GetCandidatePathsCoreAsync.02") + finding.Target); return []; }
                paths.AddRange(snapshot.Commands.SelectMany(CommandTargets.Extract));
            }
            catch (Exception ex) when (ex is IOException or InvalidDataException or UnauthorizedAccessException or Win32Exception or XmlException)
            { Note(report, MessageText.Create("Backend.Core.RelatedArtifactExpansion.GetCandidatePathsCoreAsync.03") + finding.Target); return []; }
        }
        foreach (string directory in paths.Where(Directory.Exists).ToArray())
        {
            if (finding.RuleId is not ("STRUCT-RANDOM-PYTHON-STEALER" or "KNOWN-DROP-PATH") ||
                !Validation.IsSafeExactTarget(directory) || RelatedArtifactReader.IsProtected(directory)) continue;
            MessageTextCollection notes = [];
            paths.AddRange(ContentDiscovery.Files(directory, notes, 128, 2, token));
            foreach (MessageText note in notes.Texts) Note(report, note);
        }
        if (paths.Count > 64) Note(report, MessageText.Create("Backend.Core.RelatedArtifactExpansion.GetCandidatePathsCoreAsync.04"));
        return paths.Where(p => ContentDiscovery.IsLocalSafePath(p) && !RelatedArtifactReader.IsProtected(p) && File.Exists(p))
            .Select(Path.GetFullPath).Distinct(StringComparer.OrdinalIgnoreCase).Take(64).ToArray();
    }

    private async Task<RelatedArtifactExpansion> ExpandCoreAsync(IEnumerable<Finding> selectedFindings, ScanReport input, CancellationToken token)
    {
        token.ThrowIfCancellationRequested();
        ScanReport report = new();
        Finding[] selected = selectedFindings.Take(257).ToArray();
        if (selected.Length > 256) { selected = selected[..256]; Note(report, MessageText.Create("Backend.Core.RelatedArtifactExpansion.ExpandCoreAsync.01")); }
        _previous = input.Findings.Take(20000).Concat(selected).DistinctBy(f => f.Id).ToArray();
        if (input.Findings.Count > 20000) Note(report, MessageText.Create("Backend.Core.RelatedArtifactExpansion.ExpandCoreAsync.02"));
        _closureOnly = true;
        HashSet<string> candidates = new(StringComparer.OrdinalIgnoreCase);
        foreach (Finding finding in selected)
        {
            token.ThrowIfCancellationRequested();
            foreach (string path in await GetCandidatePathsCoreAsync(finding, report, token))
            {
                if (candidates.Count < 64) candidates.Add(path);
                else if (!candidates.Contains(path)) Note(report, MessageText.Create("Backend.Core.RelatedArtifactExpansion.ExpandCoreAsync.03"));
            }
            // Preserve informational findings; they never become evidence just because the name matches.
            if (!finding.CanRemediate) report.Findings.Add(finding);
            else if (finding.RuleId == "PERSISTENCE-STARTUP-LINK" && finding.SuggestedActions.Contains(SuggestedActionKind.QuarantineFile))
            {
                string? expected = finding.TargetSha256 ?? finding.Sha256;
                if (finding.Target.EndsWith(".lnk", StringComparison.OrdinalIgnoreCase) && Validation.IsHexSha256(expected) &&
                    string.Equals(await HashAsync(finding.Target, report, token), expected, StringComparison.OrdinalIgnoreCase))
                {
                    report.Findings.Add(finding);
                    Note(report, MessageText.Create("Backend.Core.RelatedArtifactExpansion.ExpandCoreAsync.04") + finding.Target);
                }
                else Note(report, MessageText.Create("Backend.Core.RelatedArtifactExpansion.ExpandCoreAsync.05") + finding.Target);
            }
            else if (finding.SuggestedActions.Contains(SuggestedActionKind.QuarantineDirectory))
            {
                try
                {
                    if (!Validation.IsSafeExactTarget(finding.Target) || !ContentDiscovery.IsLocalSafePath(finding.Target) ||
                        RelatedArtifactReader.IsProtected(finding.Target) || !Directory.Exists(finding.Target))
                        throw MessageExceptions.Create(MessageText.Create("Backend.Core.RelatedArtifactExpansion.ExpandCoreAsync.06"), sourceText => new InvalidDataException(sourceText));
                    string? expected = finding.TargetSha256 ?? finding.Sha256;
                    if (expected is not null && (!Validation.IsHexSha256(expected) ||
                        !expected.Equals(await RelatedDirectoryIdentity.ComputeAsync(finding.Target, token), StringComparison.OrdinalIgnoreCase)))
                        throw MessageExceptions.Create(MessageText.Create("Backend.Core.RelatedArtifactExpansion.ExpandCoreAsync.07"), sourceText => new InvalidDataException(sourceText));
                    report.Findings.Add(finding);
                    Note(report, expected is null ? MessageText.Create("Backend.Core.RelatedArtifactExpansion.ExpandCoreAsync.08") + finding.Target :
                        MessageText.Create("Backend.Core.RelatedArtifactExpansion.ExpandCoreAsync.09") + finding.Target);
                }
                catch (Exception ex) when (ex is IOException or InvalidDataException or UnauthorizedAccessException or Win32Exception)
                { Note(report, MessageText.Create("Backend.Core.RelatedArtifactExpansion.ExpandCoreAsync.10") + finding.Target + "，" + MessageExceptions.Describe(ex)); }
            }
            else if (!IsRelation(finding) && !finding.SuggestedActions.Contains(SuggestedActionKind.QuarantineFile) &&
                     !finding.SuggestedActions.Contains(SuggestedActionKind.QuarantineDirectory)) report.Findings.Add(finding);
        }

        // Validate selected identity first. A newer report is not permission to silently adopt a changed selected snapshot.
        foreach (Finding finding in selected)
        {
            string? path = RelatedArtifactRelations.FilePath(finding);
            string? expected = RelatedArtifactRelations.FileHash(finding);
            if (path is null || !candidates.Contains(path)) continue;
            if (expected is null && finding.CanRemediate && finding.SuggestedActions.Contains(SuggestedActionKind.QuarantineFile))
            { _blockedPaths.Add(path); Note(report, MessageText.Create("Backend.Core.RelatedArtifactExpansion.ExpandCoreAsync.11") + path); }
            else if (expected is not null)
            {
                string? actual = await HashAsync(path, report, token);
                if (actual is null) { _blockedPaths.Add(path); Note(report, MessageText.Create("Backend.Core.RelatedArtifactExpansion.ExpandCoreAsync.12") + path); }
                else if (!actual.Equals(expected, StringComparison.OrdinalIgnoreCase))
                { _blockedPaths.Add(path); Note(report, MessageText.Create("Backend.Core.RelatedArtifactExpansion.ExpandCoreAsync.13") + path); }
            }
        }

        foreach (string path in candidates)
        {
            token.ThrowIfCancellationRequested();
            if (_blockedPaths.Contains(path)) continue;
            Finding[] sources = _previous.Where(f => RelatedArtifactRelations.IsFileEvidence(f) &&
                RelatedArtifactRelations.SamePath(f.Target, path)).ToArray();
            string? hash = await HashAsync(path, report, token);
            if (hash is null) continue;
            // Conflicting prior actionable snapshots require a fresh user selection, not cherry-picking the latest match.
            if (sources.Any(f => !string.Equals(RelatedArtifactRelations.FileHash(f), hash, StringComparison.OrdinalIgnoreCase)))
            { _blockedPaths.Add(path); Note(report, MessageText.Create("Backend.Core.RelatedArtifactExpansion.ExpandCoreAsync.14") + path); continue; }
            Finding? source = sources.OrderByDescending(f => f.Score).FirstOrDefault();
            if (source is null && !_known.ContainsKey(hash))
            { Note(report, MessageText.Create("Backend.Core.RelatedArtifactExpansion.ExpandCoreAsync.15") + path); continue; }
            bool known = _known.ContainsKey(hash);
            Finding proof = new()
            {
                RuleId = source?.RuleId ?? "RELATION-KNOWN-HASH",
                Category = FindingCategory.File,
                Severity = known ? FindingSeverity.Critical : source!.Severity,
                Score = known ? 100 : source!.Score,
                TitleText = source?.TitleText ?? MessageText.Create("Backend.Core.RelatedArtifactExpansion.ExpandCoreAsync.16"),
                DescriptionText = MessageText.Create("Backend.Core.RelatedArtifactExpansion.ExpandCoreAsync.17"),
                Target = path,
                Sha256 = hash,
                TargetSha256 = hash,
                ContentPath = source?.ContentPath,
                EvidenceText = source?.EvidenceText ?? MessageText.Create("Backend.Core.RelatedArtifactExpansion.ExpandCoreAsync.18"),
                IsKnownMalware = known,
                CanRemediate = true,
                SuggestedActions = [SuggestedActionKind.QuarantineFile]
            };
            _proofs[path] = proof;
            report.Findings.Add(proof);
        }

        if (_proofs.Count > 0)
        {
            await CollectRunAsync(report, token);
            await CollectTasksAsync(report, token);
            await CollectServicesAsync(report, token);
            await CollectProcessesAsync(null, report, token);
        }
        foreach (Finding finding in selected.Where(f => f.CanRemediate && IsRelation(f)))
            if (!report.Findings.Any(f => f.CanRemediate && (f.Id == finding.Id || SameEntry(f, finding))))
            {
                if (!await PreserveOrphanEntryAsync(finding, report, token))
                    Note(report, MessageText.Create("Backend.Core.RelatedArtifactExpansion.ExpandCoreAsync.19") + finding.Target);
            }
        report.AddScopeNote(MessageText.Create("Backend.Core.RelatedArtifactExpansion.ExpandCoreAsync.20"));
        return new(report.Findings.DistinctBy(f => f.Id).ToArray(), candidates.ToArray(), report.CoverageNotes.Distinct().ToArray())
        {
            VerificationBytesRead = _relatedBytesHashed,
            ScopeNotes = report.ScopeNotes.ToArray(),
            ScopeNoteMessages = report.ScopeNoteMessages,
            NoteMessages = DisplayMessageMap.FromTexts(report.CoverageTexts.DistinctBy(text => text.OriginalText))
        };
    }

    private bool MatchesProof(string path, string hash) => _proofs.TryGetValue(Path.GetFullPath(path), out Finding? finding) &&
        string.Equals(RelatedArtifactRelations.FileHash(finding), hash, StringComparison.OrdinalIgnoreCase);
    private int ProofScore(string path, string hash) => _known.ContainsKey(hash) ? 100 : _proofs.GetValueOrDefault(Path.GetFullPath(path))?.Score ?? 0;
    private bool CanCloseEntry(string path, string hash, string command, bool allowPatcher) => _known.ContainsKey(hash) ||
        allowPatcher && _proofs.TryGetValue(Path.GetFullPath(path), out Finding? proof) && RelatedArtifactRelations.SupportsHeuristicEntry(proof) &&
        BoundContentEvidence.IsDirectInvocation(Environment.ExpandEnvironmentVariables(command), path);

    private static bool IsTask(Finding finding) => finding.SuggestedActions.Contains(SuggestedActionKind.RemoveScheduledTask) ||
        finding.RuleId.StartsWith("PERSISTENCE-TASK", StringComparison.Ordinal);
    private static bool IsRelation(Finding finding) => finding.RelatedFilePath is not null || finding.ProcessId is not null ||
        finding.RegistryKey is not null || IsTask(finding) || finding.RuleId.StartsWith("PERSISTENCE-SERVICE", StringComparison.Ordinal);

    private static bool SameEntry(Finding left, Finding right)
    {
        if (left.ProcessId is not null || right.ProcessId is not null) return left.ProcessId == right.ProcessId;
        if (left.RegistryKey is not null || right.RegistryKey is not null)
            return string.Equals(left.RegistryHive, right.RegistryHive, StringComparison.OrdinalIgnoreCase) &&
                string.Equals(left.RegistryView, right.RegistryView, StringComparison.OrdinalIgnoreCase) &&
                string.Equals(left.RegistryKey, right.RegistryKey, StringComparison.OrdinalIgnoreCase) &&
                string.Equals(left.RegistryValueName, right.RegistryValueName, StringComparison.OrdinalIgnoreCase);
        if (IsTask(left) || IsTask(right)) return IsTask(left) && IsTask(right) &&
            Validation.TryNormalizeScheduledTaskName(left.Target, out string l) && Validation.TryNormalizeScheduledTaskName(right.Target, out string r) && l.Equals(r, StringComparison.OrdinalIgnoreCase);
        return left.RuleId.StartsWith("PERSISTENCE-SERVICE", StringComparison.Ordinal) &&
            right.RuleId.StartsWith("PERSISTENCE-SERVICE", StringComparison.Ordinal) && string.Equals(left.Target, right.Target, StringComparison.OrdinalIgnoreCase);
    }

    private void AddCurrent(Finding finding, ScanReport report)
    {
        foreach (Finding old in _previous.Where(old => SameEntry(old, finding)))
        {
            bool changed = old.RegistryKey is not null && !string.Equals(old.Target, finding.Target, StringComparison.Ordinal) ||
                old.Sha256 is not null && !string.Equals(old.Sha256, finding.Sha256, StringComparison.OrdinalIgnoreCase) ||
                !IsTask(old) && old.ConfigurationSnapshot is not null && !string.Equals(old.ConfigurationSnapshot, finding.ConfigurationSnapshot, StringComparison.Ordinal) ||
                old.ConfigurationKind is not null && !string.Equals(old.ConfigurationKind, finding.ConfigurationKind, StringComparison.Ordinal) ||
                old.RelatedFileSha256 is not null && !string.Equals(old.RelatedFileSha256, finding.RelatedFileSha256, StringComparison.OrdinalIgnoreCase) ||
                old.ProcessId is not null && (old.ProcessStartedAtUtc != finding.ProcessStartedAtUtc || !RelatedArtifactRelations.SamePath(old.Target, finding.Target));
            if (changed) { Note(report, MessageText.Create("Backend.Core.RelatedArtifactExpansion.AddCurrent.01") + finding.Target); return; }
        }
        report.Findings.Add(finding);
        if (!finding.CanRemediate) Note(report, MessageText.Create("Backend.Core.RelatedArtifactExpansion.AddCurrent.02") + finding.Target);
    }

    private async Task<bool> PreserveOrphanEntryAsync(Finding finding, ScanReport report, CancellationToken token)
    {
        // This is the existing explicit name allowlist, not a new content-based authority.
        // Never remove a supplied related-file binding just because its target changed or disappeared.
        if (finding.RelatedFilePath is not null) return false;
        try
        {
            Finding? fresh = null;
            if (IsTask(finding) && Validation.IsHexSha256(finding.Sha256))
            {
                RelatedTaskSnapshot snapshot = await RelatedTaskSnapshotReader.ReadAsync(finding.Target, token);
                fresh = new Finding { Target = snapshot.TaskName, Sha256 = snapshot.Sha256, RuleId = "PERSISTENCE-TASK-KNOWN" };
            }
            else if (finding.RegistryHive is "HKCU" or "HKLM" &&
                     finding.RegistryKey is @"Software\Microsoft\Windows\CurrentVersion\Run" or @"Software\Microsoft\Windows\CurrentVersion\RunOnce" &&
                     finding.RegistryView is "Default" or "Registry32" or "Registry64" && finding.RegistryValueName is { } name)
            {
                using RegistryKey baseKey = RegistryKey.OpenBaseKey(finding.RegistryHive == "HKCU" ? RegistryHive.CurrentUser : RegistryHive.LocalMachine,
                    Enum.Parse<RegistryView>(finding.RegistryView));
                using RegistryKey? key = baseKey.OpenSubKey(finding.RegistryKey);
                if (key?.GetValue(name, null, RegistryValueOptions.DoNotExpandEnvironmentNames) is string current)
                    fresh = new Finding
                    {
                        Target = current,
                        RegistryHive = finding.RegistryHive,
                        RegistryView = finding.RegistryView,
                        RegistryKey = finding.RegistryKey,
                        RegistryValueName = name
                    };
            }
            Finding? preserved = fresh is null ? null : PreserveAllowlistedSnapshot(finding, fresh);
            if (preserved is null) return false;
            report.Findings.Add(preserved);
            Note(report, MessageText.Create("Backend.Core.RelatedArtifactExpansion.PreserveOrphanEntryAsync.01") + finding.Target);
            return true;
        }
        catch (Exception ex) when (ex is IOException or InvalidDataException or UnauthorizedAccessException or Win32Exception or XmlException or System.Security.SecurityException)
        { Note(report, MessageText.Create("Backend.Core.RelatedArtifactExpansion.PreserveOrphanEntryAsync.02") + finding.Target); return false; }
    }

    internal Finding? PreserveAllowlistedSnapshot(Finding previous, Finding fresh)
    {
        if (!previous.CanRemediate || previous.RelatedFilePath is not null || !SameEntry(previous, fresh)) return null;
        bool task = IsTask(previous);
        bool allowed = task
            ? Validation.IsHexSha256(previous.Sha256) && string.Equals(previous.Sha256, fresh.Sha256, StringComparison.OrdinalIgnoreCase) &&
              Validation.TryNormalizeScheduledTaskName(previous.Target, out string taskName) && rules.KnownTaskNames.Any(n =>
                  Validation.TryNormalizeScheduledTaskName(n, out string known) && taskName.Equals(known, StringComparison.OrdinalIgnoreCase))
            : previous.RegistryValueName is { } name && rules.KnownRunValueNames.Contains(name, StringComparer.OrdinalIgnoreCase) &&
              string.Equals(previous.Target, fresh.Target, StringComparison.Ordinal);
        if (!allowed) return null;
        return new Finding
        {
            RuleId = previous.RuleId,
            Category = FindingCategory.Persistence,
            Severity = previous.Severity,
            Score = previous.Score,
            TitleText = MessageText.Create("Backend.Core.RelatedArtifactExpansion.PreserveAllowlistedSnapshot.01"),
            DescriptionText = MessageText.Create("Backend.Core.RelatedArtifactExpansion.PreserveAllowlistedSnapshot.02"),
            Target = previous.Target,
            Sha256 = previous.Sha256,
            ConfigurationSnapshot = previous.ConfigurationSnapshot,
            RegistryHive = previous.RegistryHive,
            RegistryView = previous.RegistryView,
            RegistryKey = previous.RegistryKey,
            RegistryValueName = previous.RegistryValueName,
            IsKnownMalware = false,
            CanRemediate = true,
            SuggestedActions = [task ? SuggestedActionKind.RemoveScheduledTask : SuggestedActionKind.RemoveRegistryValue]
        };
    }

    private async Task CollectProcessesAsync(SteamLayout? layout, ScanReport report, CancellationToken token)
    {
        MessageText processScope = MessageText.Create("Backend.Core.RelatedArtifactExpansion.CollectProcessesAsync.01");
        if (!report.ScopeNotes.Contains(processScope)) report.AddScopeNote(processScope);
        Process[] processes = Process.GetProcesses();
        int inaccessible = 0, modules = 0;
        try
        {
            if (processes.Length > 4096) Note(report, MessageText.Create("Backend.Core.RelatedArtifactExpansion.CollectProcessesAsync.02"));
            foreach (Process process in processes.Take(4096))
            {
                token.ThrowIfCancellationRequested();
                bool relevant = _previous.Any(f => f.ProcessId == process.Id);
                try
                {
                    if (process.Id <= 4 || process.Id == Environment.ProcessId) continue;
                    string name = process.ProcessName;
                    relevant |= rules.KnownProcessNames.Contains(name + ".exe", StringComparer.OrdinalIgnoreCase) ||
                        name.Equals("steam", StringComparison.OrdinalIgnoreCase) || name.Equals("steamwebhelper", StringComparison.OrdinalIgnoreCase) ||
                        report.CandidateRoots.Any(p => Path.GetFileNameWithoutExtension(p).Equals(name, StringComparison.OrdinalIgnoreCase));
                    string? host = process.MainModule?.FileName;
                    if (host is null || !ContentDiscovery.IsLocalSafePath(host)) continue;
                    relevant |= _proofs.ContainsKey(Path.GetFullPath(host)) || layout is not null &&
                        (layout.SteamRoots.Any(root => ContentDiscovery.IsWithin(host, root)) ||
                        layout.Games.Any(g => ContentDiscovery.IsWithin(host, g.Directory)) || ContentDiscovery.IsWorkshopContentPath(host) ||
                        report.CandidateRoots.Any(root => RelatedArtifactRelations.SamePath(host, root) || ContentDiscovery.IsWithin(host, root)));
                    if (RelatedArtifactReader.IsProtected(host)) continue; // Expected scope exclusion, never a scan failure.
                    if (!_closureOnly && !relevant) continue;
                    DateTimeOffset start = process.StartTime.ToUniversalTime();
                    foreach (ProcessModule module in process.Modules)
                    {
                        token.ThrowIfCancellationRequested();
                        if (++modules > 16384) { Note(report, MessageText.Create("Backend.Core.RelatedArtifactExpansion.CollectProcessesAsync.03")); return; }
                        string path = module.FileName;
                        if (RelatedArtifactReader.IsProtected(path) || _closureOnly && !_proofs.ContainsKey(Path.GetFullPath(path))) continue;
                        string? hash = await HashAsync(path, report, token);
                        if (hash is null || !(_known.ContainsKey(hash) || MatchesProof(path, hash))) continue;
                        relevant = true;
                        string? hostHash = RelatedArtifactRelations.SamePath(host, path) ? hash : await HashAsync(host, report, token);
                        if (hostHash is null || process.HasExited || process.StartTime.ToUniversalTime() != start.UtcDateTime ||
                            !RelatedArtifactRelations.SamePath(process.MainModule?.FileName ?? "", host)) continue;
                        bool direct = RelatedArtifactRelations.SamePath(host, path), known = _known.ContainsKey(hash);
                        bool allowed = known || direct && _proofs.TryGetValue(Path.GetFullPath(path), out Finding? proof) && RelatedArtifactRelations.SupportsHeuristicEntry(proof);
                        AddCurrent(new Finding
                        {
                            RuleId = direct ? "PROCESS-RELATED-IMAGE" : "PROCESS-LOADED-MALWARE",
                            Category = FindingCategory.Process,
                            Severity = known ? FindingSeverity.Critical : FindingSeverity.High,
                            Score = ProofScore(path, hash),
                            TitleText = direct ? MessageText.Create("Backend.Core.RelatedArtifactExpansion.CollectProcessesAsync.04") : MessageText.Create("Backend.Core.RelatedArtifactExpansion.CollectProcessesAsync.05"),
                            DescriptionText = MessageText.Create("Backend.Core.RelatedArtifactExpansion.CollectProcessesAsync.06"),
                            Target = host,
                            Sha256 = hostHash,
                            ProcessId = process.Id,
                            ProcessStartedAtUtc = start,
                            RelatedFilePath = path,
                            RelatedFileSha256 = hash,
                            IsKnownMalware = known,
                            CanRemediate = allowed,
                            EvidenceText = MessageText.Create("Backend.Core.RelatedArtifactExpansion.CollectProcessesAsync.07", (process.Id), (host), (path)),
                            SuggestedActions = allowed ? [direct ? SuggestedActionKind.StopProcess : SuggestedActionKind.StopHostProcess] : [SuggestedActionKind.ReviewOnly]
                        }, report);
                    }
                }
                catch (Exception ex) when (ex is InvalidOperationException or Win32Exception or IOException or UnauthorizedAccessException or NotSupportedException)
                { if (relevant) inaccessible++; }
            }
        }
        finally
        {
            foreach (Process process in processes) process.Dispose();
            if (inaccessible > 0) Note(report, MessageText.Create("Backend.Core.RelatedArtifactExpansion.CollectProcessesAsync.08", (inaccessible)));
        }
    }

    private static void Note(ScanReport report, MessageText note)
    {
        if (report.CoverageNotes.Count < 256 && !report.CoverageNotes.Contains(note.OriginalText)) report.AddCoverageNote(note);
        report.Coverage = ScanCoverage.Partial;
    }
}
