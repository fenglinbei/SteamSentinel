using System.Text.Json.Serialization;
using SteamSentinel.Core.Reporting;
using System.Collections;
using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using System.Xml;
using System.Xml.Linq;
using Microsoft.Win32;
using Microsoft.Win32.SafeHandles;
using SteamSentinel.Core.Inspection;
using SteamSentinel.Core.Models;
using SteamSentinel.Core.Steam;

namespace SteamSentinel.Core.Scanning;

public sealed record RelatedSourceRead
{
    public string Kind { get; init; } = string.Empty;
    public string Scope { get; init; } = string.Empty;
    public string Location { get; init; } = string.Empty;
    public string RawCommand { get; init; } = string.Empty;
    public string? ExecutablePath { get; init; }
    public string? Arguments { get; init; }
    public string? WorkingDirectory { get; init; }
    public string? UserSid { get; init; }
    public string? ShortcutPath { get; init; }
    public DiagnosticReadStatus Status { get; init; } = DiagnosticReadStatus.Complete;
    public string Detail { get; init; } = string.Empty;
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public DisplayMessage? DetailMessage { get => SteamSentinel.Core.Reporting.MessageText.BoundDescriptor(field, Detail); init => field = value; }
    [JsonIgnore] public MessageText DetailText { get => new(Detail, DetailMessage); init { Detail = value.OriginalText; DetailMessage = value.Message; } }
    public int SnapshotBytesRead { get; init; }
}
[method: System.Text.Json.Serialization.JsonConstructor]
public sealed record RelatedProcessRead(int ProcessId, DateTimeOffset? StartedAtUtc, string ImagePath, DiagnosticReadStatus Status, string Detail, string? CommandLine = null, string? WorkingDirectory = null, string SignatureStatus = "NotChecked", string? SignatureDetail = null)
{
    [System.Text.Json.Serialization.JsonIgnore(Condition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull)]
    public SteamSentinel.Core.Models.DisplayMessage? DetailMessage { get => SteamSentinel.Core.Reporting.MessageText.BoundDescriptor(field, Detail); init => field = value; }

    [System.Text.Json.Serialization.JsonIgnore]
    public SteamSentinel.Core.Reporting.MessageText DetailText
    {
        get => new(Detail ?? string.Empty, DetailMessage);
        init
        {
            Detail = value.OriginalText;
            DetailMessage = value.Message;
        }
    }

    public RelatedProcessRead(int ProcessId, DateTimeOffset? StartedAtUtc, string ImagePath, DiagnosticReadStatus Status, SteamSentinel.Core.Reporting.MessageText Detail, string? CommandLine = null, string? WorkingDirectory = null, string SignatureStatus = "NotChecked", string? SignatureDetail = null) : this(ProcessId, StartedAtUtc, ImagePath, Status, Detail.OriginalText, CommandLine, WorkingDirectory, SignatureStatus, SignatureDetail)
    {
        DetailMessage = Detail.Message;
    }
}
[method: System.Text.Json.Serialization.JsonConstructor]
public sealed record RelatedModuleRead(DiagnosticReadStatus Status, string Detail, bool IdentityMatched, IReadOnlyList<string> Paths)
{
    [System.Text.Json.Serialization.JsonIgnore(Condition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull)]
    public SteamSentinel.Core.Models.DisplayMessage? DetailMessage { get => SteamSentinel.Core.Reporting.MessageText.BoundDescriptor(field, Detail); init => field = value; }

    [System.Text.Json.Serialization.JsonIgnore]
    public SteamSentinel.Core.Reporting.MessageText DetailText
    {
        get => new(Detail ?? string.Empty, DetailMessage);
        init
        {
            Detail = value.OriginalText;
            DetailMessage = value.Message;
        }
    }

    public RelatedModuleRead(DiagnosticReadStatus Status, SteamSentinel.Core.Reporting.MessageText Detail, bool IdentityMatched, IReadOnlyList<string> Paths) : this(Status, Detail.OriginalText, IdentityMatched, Paths)
    {
        DetailMessage = Detail.Message;
    }
}
[method: System.Text.Json.Serialization.JsonConstructor]
public sealed record RelatedFileRead(DiagnosticReadStatus Status, string Detail, byte[] Bytes, int BytesRead = 0)
{
    [System.Text.Json.Serialization.JsonIgnore(Condition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull)]
    public SteamSentinel.Core.Models.DisplayMessage? DetailMessage { get => SteamSentinel.Core.Reporting.MessageText.BoundDescriptor(field, Detail); init => field = value; }

    [System.Text.Json.Serialization.JsonIgnore]
    public SteamSentinel.Core.Reporting.MessageText DetailText
    {
        get => new(Detail ?? string.Empty, DetailMessage);
        init
        {
            Detail = value.OriginalText;
            DetailMessage = value.Message;
        }
    }

    public RelatedFileRead(DiagnosticReadStatus Status, SteamSentinel.Core.Reporting.MessageText Detail, byte[] Bytes, int BytesRead = 0) : this(Status, Detail.OriginalText, Bytes, BytesRead)
    {
        DetailMessage = Detail.Message;
    }
}
[method: System.Text.Json.Serialization.JsonConstructor]
public sealed record RelatedPathRead(DiagnosticReadStatus Status, string Detail, bool IsFile, bool IsDirectory, bool IsUserArea, bool IsProtected)
{
    [System.Text.Json.Serialization.JsonIgnore(Condition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull)]
    public SteamSentinel.Core.Models.DisplayMessage? DetailMessage { get => SteamSentinel.Core.Reporting.MessageText.BoundDescriptor(field, Detail); init => field = value; }

    [System.Text.Json.Serialization.JsonIgnore]
    public SteamSentinel.Core.Reporting.MessageText DetailText
    {
        get => new(Detail ?? string.Empty, DetailMessage);
        init
        {
            Detail = value.OriginalText;
            DetailMessage = value.Message;
        }
    }

    public RelatedPathRead(DiagnosticReadStatus Status, SteamSentinel.Core.Reporting.MessageText Detail, bool IsFile, bool IsDirectory, bool IsUserArea, bool IsProtected) : this(Status, Detail.OriginalText, IsFile, IsDirectory, IsUserArea, IsProtected)
    {
        DetailMessage = Detail.Message;
    }
}

/// <summary>Inputs are bounded local snapshots. Implementations must never execute a target or resolve a shell link.</summary>
public interface IRelatedComponentDataSource
{
    string? ReadCurrentUserSid();
    IReadOnlyDictionary<string, string> ReadEnvironmentVariables(string targetUserSid);
    IEnumerable<RelatedSourceRead> ReadSources(RelatedComponentDiscoveryRequest request, RelatedComponentLimits limits,
        Func<long> remainingSnapshotBytes, CancellationToken token);
    IEnumerable<RelatedProcessRead> ReadProcesses(int maximumProcesses, CancellationToken token);
    RelatedModuleRead ReadModules(RelatedProcessRead process, int maximumModules, CancellationToken token);
    RelatedPathRead ProbePath(string path);
    RelatedFileRead ReadFile(string path, int maximumBytes, CancellationToken token);
}

/// <summary>Discovers exact file candidates and provenance only. Never hashes, verifies trust, scans a directory, or grants an action.</summary>
public sealed class RelatedComponentDiscovery(IRelatedComponentDataSource? dataSource = null, TimeProvider? timeProvider = null)
{
    private readonly IRelatedComponentDataSource _source = dataSource ?? new WindowsRelatedComponentDataSource();
    private readonly TimeProvider _time = timeProvider ?? TimeProvider.System;
    private static readonly HashSet<string> ScriptExtensions = new([".bat", ".cmd", ".ps1", ".vbs", ".js", ".py"], StringComparer.OrdinalIgnoreCase);
    private static readonly HashSet<string> WrapperNames = new(["cmd", "powershell", "pwsh", "wscript", "cscript", "rundll32", "regsvr32", "python", "pythonw", "py", "mshta", "dotnet"], StringComparer.OrdinalIgnoreCase);

    public void Collect(RelatedComponentDiscoveryRequest request, RelatedComponentDiagnosticReport output,
        RelatedComponentLimits limits, CancellationToken token = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(output);
        ArgumentNullException.ThrowIfNull(limits);
        long started = _time.GetTimestamp();
        long scriptBytes = 0;
        bool stopped = false;
        Dictionary<string, RelatedComponentCandidate> candidates = output.Candidates.ToDictionary(c => c.Path, StringComparer.OrdinalIgnoreCase);
        Dictionary<string, int> candidatePriorities = output.Candidates.ToDictionary(c => c.Path, _ => 1000, StringComparer.OrdinalIgnoreCase);
        HashSet<string> seeds = new(StringComparer.OrdinalIgnoreCase);
        HashSet<string> sourceTargets = new(StringComparer.OrdinalIgnoreCase);
        Dictionary<string, HashSet<string>> pathSources = new(StringComparer.OrdinalIgnoreCase);
        HashSet<string> wrapperContexts = new(StringComparer.OrdinalIgnoreCase);
        HashSet<string> scriptSnapshots = new(StringComparer.OrdinalIgnoreCase);
        Dictionary<string, RelatedPathRead> pathSnapshots = new(StringComparer.OrdinalIgnoreCase);
        IReadOnlyDictionary<string, string> environment = new Dictionary<string, string>();

        void Check(string code, MessageText name, DiagnosticReadStatus status, MessageText detail, string? observation = null, bool required = true)
        {
            if (output.Checks.Count < 1023) output.Checks.Add(new() { CheckCode = code, NameText = name, Status = status, DetailText = detail, ObservationId = observation, Required = required });
            else if (!output.Checks.Any(c => c.CheckCode == "related.discovery_check_limit")) output.Checks.Add(new()
            { CheckCode = "related.discovery_check_limit", NameText = MessageText.Create("Backend.Core.RelatedComponentDiscovery.Collect.01"), Status = DiagnosticReadStatus.LimitReached, DetailText = MessageText.Create("Backend.Core.RelatedComponentDiscovery.Collect.02") });
        }
        bool Continue()
        {
            if (stopped) return false;
            if (token.IsCancellationRequested)
            { stopped = true; Check("related.collection", MessageText.Create("Backend.Core.RelatedComponentDiscovery.Collect.03"), DiagnosticReadStatus.Cancelled, MessageText.Create("Backend.Core.RelatedComponentDiscovery.Collect.04")); return false; }
            if (_time.GetElapsedTime(started) >= limits.MaximumDiscoveryDuration)
            { stopped = true; Check("related.discovery_time", MessageText.Create("Backend.Core.RelatedComponentDiscovery.Collect.05"), DiagnosticReadStatus.LimitReached, MessageText.Create("Backend.Core.RelatedComponentDiscovery.Collect.06")); return false; }
            try
            {
                string? current = _source.ReadCurrentUserSid();
                if (!string.IsNullOrWhiteSpace(current) && current.Equals(request.TargetUserSid, StringComparison.OrdinalIgnoreCase)) return true;
                stopped = true;
                Check("related.discovery_identity", MessageText.Create("Backend.Core.RelatedComponentDiscovery.Collect.07"), DiagnosticReadStatus.AccessDenied, MessageText.Create("Backend.Core.RelatedComponentDiscovery.Collect.08"));
                return false;
            }
            catch (Exception ex) when (IsReadException(ex))
            { stopped = true; Check("related.discovery_identity", MessageText.Create("Backend.Core.RelatedComponentDiscovery.Collect.09"), StatusFor(ex), MessageText.Create("Backend.Core.RelatedComponentDiscovery.Collect.10") + MessageExceptions.Describe(ex)); return false; }
        }
        bool Excluded(string path) => request.ExcludedRoots.Any(root => !string.IsNullOrWhiteSpace(root) && ContentDiscovery.IsWithin(path, root));
        RelatedPathRead Probe(string path)
        {
            if (pathSnapshots.TryGetValue(path, out RelatedPathRead? saved)) return saved;
            try { saved = _source.ProbePath(path); }
            catch (Exception ex) when (IsReadException(ex)) { saved = new(StatusFor(ex), MessageExceptions.Describe(ex), false, false, false, false); }
            pathSnapshots.Add(path, saved);
            return saved;
        }
        void RecordPathSource(string path, string sourceId)
        {
            if (!pathSources.TryGetValue(path, out HashSet<string>? ids)) pathSources.Add(path, ids = new(StringComparer.Ordinal));
            ids.Add(sourceId);
        }
        RelatedComponentCandidate? AddCandidate(string raw, MessageText reason, string? sourceId = null, string? hostId = null, bool requireUserArea = false, int priority = 50)
        {
            if (!Continue()) return null;
            if (!RelatedCommandResolver.TryNormalizeLocalLiteral(raw, null, out string? path, out _))
            { Check("related.candidate_scope", MessageText.Create("Backend.Core.RelatedComponentDiscovery.Collect.11"), DiagnosticReadStatus.NotChecked, MessageText.Create("Backend.Core.RelatedComponentDiscovery.Collect.12") + Short(raw), sourceId); return null; }
            RelatedPathRead probe = Probe(path!);
            if (Excluded(path!) || probe.IsProtected)
            { Check("related.candidate_scope", MessageText.Create("Backend.Core.RelatedComponentDiscovery.Collect.13"), DiagnosticReadStatus.NotChecked, MessageText.Create("Backend.Core.RelatedComponentDiscovery.Collect.14") + path, sourceId, required: false); return null; }
            if (probe.IsDirectory)
            { Check("related.exact_file", MessageText.Create("Backend.Core.RelatedComponentDiscovery.Collect.15"), DiagnosticReadStatus.NotChecked, MessageText.Create("Backend.Core.RelatedComponentDiscovery.Collect.16") + path, sourceId); return null; }
            if (requireUserArea && !probe.IsUserArea && !seeds.Contains(path!)) return null;
            if (!candidates.TryGetValue(path!, out RelatedComponentCandidate? candidate))
            {
                if (output.Candidates.Count >= limits.MaximumCandidates)
                {
                    RelatedComponentCandidate? displaced = output.Candidates.Where(c => candidatePriorities.GetValueOrDefault(c.Path, 1000) < priority)
                        .OrderBy(c => candidatePriorities[c.Path]).FirstOrDefault();
                    if (displaced is null)
                    { Check("related.candidate_count", MessageText.Create("Backend.Core.RelatedComponentDiscovery.Collect.17"), DiagnosticReadStatus.LimitReached, MessageText.Create("Backend.Core.RelatedComponentDiscovery.Collect.18", (limits.MaximumCandidates), (path)), sourceId); return null; }
                    output.Candidates.Remove(displaced);
                    candidates.Remove(displaced.Path);
                    candidatePriorities.Remove(displaced.Path);
                    output.Relations.RemoveAll(r => r.FromId == displaced.Id || r.ToId == displaced.Id);
                    Check("related.candidate_priority", MessageText.Create("Backend.Core.RelatedComponentDiscovery.Collect.19"), DiagnosticReadStatus.LimitReached,
                        MessageText.Create("Backend.Core.RelatedComponentDiscovery.Collect.20") + displaced.Path);
                }
                candidate = new()
                {
                    Path = path!,
                    ReasonText = reason,
                    ContentDetailText = MessageText.Create("Backend.Core.RelatedComponentModels.ContentDetail.01"),
                    Status = probe.Status == DiagnosticReadStatus.Complete ? DiagnosticReadStatus.NotChecked : probe.Status,
                    DetailText = probe.Status == DiagnosticReadStatus.Complete
                        ? MessageText.Create("Backend.Core.RelatedComponentDiscovery.Collect.21") : probe.DetailText
                };
                candidates.Add(path!, candidate);
                candidatePriorities.Add(path!, priority);
                output.Candidates.Add(candidate);
            }
            else candidatePriorities[path!] = Math.Max(candidatePriorities.GetValueOrDefault(path!, 1000), priority);
            if (sourceId is not null)
            {
                AddUnique(candidate.SourceObservationIds, sourceId);
                RecordPathSource(path!, sourceId);
                AddRelation(output, sourceId, candidate.Id, "SourceReferencesFile", MessageText.Create("Backend.Core.RelatedComponentDiscovery.Collect.22"));
            }
            if (hostId is not null)
            {
                AddUnique(candidate.HostObservationIds, hostId);
                AddRelation(output, hostId, candidate.Id, "ObservedLoadedModulePath", MessageText.Create("Backend.Core.RelatedComponentDiscovery.Collect.23"));
            }
            return candidate;
        }
        void ReadScript(string path, RelatedSourceObservation parent, IReadOnlyDictionary<string, string>? sourceEnvironment)
        {
            if (!Continue() || !ScriptExtensions.Contains(Path.GetExtension(path)) || !scriptSnapshots.Add(path)) return;
            if (scriptBytes >= limits.MaximumTotalScriptBytes)
            { Check("related.script_read", MessageText.Create("Backend.Core.RelatedComponentDiscovery.Collect.24"), DiagnosticReadStatus.LimitReached, MessageText.Create("Backend.Core.RelatedComponentDiscovery.Collect.25"), parent.Id); return; }
            int remaining = (int)Math.Min(limits.MaximumScriptBytes, limits.MaximumTotalScriptBytes - scriptBytes);
            RelatedFileRead read;
            try { read = _source.ReadFile(path, remaining, token); }
            catch (Exception ex) when (IsReadException(ex)) { read = new(StatusFor(ex), MessageExceptions.Describe(ex), []); }
            scriptBytes += Math.Max(read.BytesRead, read.Bytes.Length);
            if (!Continue()) return;
            if (scriptBytes > limits.MaximumTotalScriptBytes || read.Bytes.Length > remaining)
            { Check("related.script_read", MessageText.Create("Backend.Core.RelatedComponentDiscovery.Collect.26"), DiagnosticReadStatus.LimitReached, MessageText.Create("Backend.Core.RelatedComponentDiscovery.Collect.27"), parent.Id); return; }
            if (read.Status != DiagnosticReadStatus.Complete)
            { Check("related.script_read", MessageText.Create("Backend.Core.RelatedComponentDiscovery.Collect.28"), read.Status, path + "：" + read.DetailText, parent.Id); return; }
            string text = DecodeText(read.Bytes);
            RelatedCommandResolution nested = RelatedCommandResolver.ResolveScriptLiterals(text, path, sourceEnvironment);
            Check("related.script_literals", MessageText.Create("Backend.Core.RelatedComponentDiscovery.Collect.29"), nested.Status, MessageText.Join("；", nested.NoteTexts), parent.Id);
            foreach (RelatedResolvedCommandTarget target in nested.Targets)
            {
                if (!AddSourceTarget(parent, target.Path)) continue;
                AddCandidate(target.Path, MessageText.Create("Backend.Core.RelatedComponentDiscovery.Collect.30"), parent.Id, requireUserArea: false, priority: 60);
            }
        }
        bool AddSourceTarget(RelatedSourceObservation source, string path)
        {
            if (RelatedComponentRecordBounds.TryAddTarget(source, path)) return true;
            if (!output.Checks.Any(c => c.CheckCode == "related.source_target_limit" && c.ObservationId == source.Id))
                Check("related.source_target_limit", MessageText.Create("Backend.Core.RelatedComponentDiscovery.Collect.31"), DiagnosticReadStatus.LimitReached, RelatedComponentRecordBounds.SourceTargetLimitDetail, source.Id);
            return false;
        }
        try
        {
            if (limits.MaximumSources < 0 || limits.MaximumProcesses < 0 || limits.MaximumHosts < 0 || limits.MaximumModulesPerHost < 0 ||
                limits.MaximumCandidates < 0 || limits.MaximumScriptBytes < 0 || limits.MaximumTotalScriptBytes < 0 || limits.MaximumDiscoveryDuration < TimeSpan.Zero)
            { Check("related.discovery_limits", MessageText.Create("Backend.Core.RelatedComponentDiscovery.Collect.32"), DiagnosticReadStatus.Failed, MessageText.Create("Backend.Core.RelatedComponentDiscovery.Collect.33")); return; }
            if (string.IsNullOrWhiteSpace(request.TargetUserSid) || output.TargetUserSid != request.TargetUserSid)
            { Check("related.discovery_identity", MessageText.Create("Backend.Core.RelatedComponentDiscovery.Collect.34"), DiagnosticReadStatus.AccessDenied, MessageText.Create("Backend.Core.RelatedComponentDiscovery.Collect.35")); return; }
            try { _ = new SecurityIdentifier(request.TargetUserSid); }
            catch (ArgumentException) { Check("related.discovery_identity", MessageText.Create("Backend.Core.RelatedComponentDiscovery.Collect.36"), DiagnosticReadStatus.AccessDenied, MessageText.Create("Backend.Core.RelatedComponentDiscovery.Collect.37")); return; }
            if (!Continue()) return;
            try { environment = _source.ReadEnvironmentVariables(request.TargetUserSid); }
            catch (Exception ex) when (IsReadException(ex)) { Check("related.command_environment", MessageText.Create("Backend.Core.RelatedComponentDiscovery.Collect.38"), StatusFor(ex), MessageText.Create("Backend.Core.RelatedComponentDiscovery.Collect.39") + MessageExceptions.Describe(ex)); }
            foreach (string seed in request.SeedPaths.Take(Math.Max(limits.MaximumCandidates, 1) + 1))
            {
                if (!Continue()) return;
                if (RelatedCommandResolver.TryNormalizeLocalLiteral(seed, null, out string? path, out _))
                {
                    seeds.Add(path!);
                    AddCandidate(path!, MessageText.Create("Backend.Core.RelatedComponentDiscovery.Collect.40"), priority: 100);
                }
                else Check("related.seed_scope", MessageText.Create("Backend.Core.RelatedComponentDiscovery.Collect.41"), DiagnosticReadStatus.NotChecked, MessageText.Create("Backend.Core.RelatedComponentDiscovery.Collect.42") + Short(seed));
            }
            if (request.SeedPaths.Count > Math.Max(limits.MaximumCandidates, 1))
                Check("related.seed_count", MessageText.Create("Backend.Core.RelatedComponentDiscovery.Collect.43"), DiagnosticReadStatus.LimitReached, MessageText.Create("Backend.Core.RelatedComponentDiscovery.Collect.44"));

            int sourcesRead = 0;
            using (IEnumerator<RelatedSourceRead> enumerator = _source.ReadSources(request, limits,
                () => Math.Max(0, limits.MaximumTotalScriptBytes - scriptBytes), token).GetEnumerator())
            {
                while (Continue())
                {
                    if (sourcesRead >= limits.MaximumSources)
                    { Check("related.source_count", MessageText.Create("Backend.Core.RelatedComponentDiscovery.Collect.45"), DiagnosticReadStatus.LimitReached, MessageText.Create("Backend.Core.RelatedComponentDiscovery.Collect.46", (limits.MaximumSources))); break; }
                    if (!enumerator.MoveNext()) break;
                    RelatedSourceRead read = enumerator.Current;
                    if (!Continue()) break;
                    sourcesRead++;
                    scriptBytes += read.SnapshotBytesRead;
                    if (scriptBytes > limits.MaximumTotalScriptBytes)
                    { Check("related.source_bytes", MessageText.Create("Backend.Core.RelatedComponentDiscovery.Collect.47"), DiagnosticReadStatus.LimitReached, MessageText.Create("Backend.Core.RelatedComponentDiscovery.Collect.48")); break; }
                    string rawCommand = read.RawCommand;
                    string? executable = read.ExecutablePath, arguments = read.Arguments, working = read.WorkingDirectory;
                    DiagnosticReadStatus readStatus = read.Status;
                    MessageText readDetail = read.DetailText;
                    if (read.ShortcutPath is not null && readStatus == DiagnosticReadStatus.Complete)
                    {
                        int remaining = (int)Math.Max(0, Math.Min(limits.MaximumScriptBytes, limits.MaximumTotalScriptBytes - scriptBytes));
                        RelatedFileRead link = remaining == 0 ? new(DiagnosticReadStatus.LimitReached, MessageText.Create("Backend.Core.RelatedComponentDiscovery.Collect.49"), []) :
                            _source.ReadFile(read.ShortcutPath, remaining, token);
                        scriptBytes += Math.Max(link.BytesRead, link.Bytes.Length);
                        if (!Continue()) break;
                        if (scriptBytes > limits.MaximumTotalScriptBytes || link.Bytes.Length > remaining)
                            link = new(DiagnosticReadStatus.LimitReached, MessageText.Create("Backend.Core.RelatedComponentDiscovery.Collect.50"), []);
                        readStatus = link.Status;
                        readDetail += " " + link.DetailText;
                        if (link.Status == DiagnosticReadStatus.Complete)
                        {
                            ShortcutInspection shortcut = ShortcutInspector.Inspect(link.Bytes);
                            executable = shortcut.Target;
                            arguments = shortcut.Arguments;
                            working = shortcut.WorkingDirectory;
                            rawCommand = (executable is null ? "" : "\"" + executable + "\"") + (string.IsNullOrEmpty(arguments) ? "" : " " + arguments);
                            if (!shortcut.Complete) readStatus = DiagnosticReadStatus.NotChecked;
                            readDetail += " " + shortcut.DetailText;
                        }
                    }
                    RelatedSourceObservation source = new()
                    {
                        Kind = read.Kind,
                        Scope = read.Scope,
                        Location = read.Location,
                        RawCommand = rawCommand,
                        WorkingDirectory = working,
                        UserSid = read.UserSid,
                        Status = readStatus,
                        DetailText = readDetail
                    };
                    source = RelatedComponentRecordBounds.PrepareOriginal(source, out bool sourceOmitted, request.TargetUserSid);
                    output.Sources.Add(source);
                    if (sourceOmitted)
                    {
                        Check("related.source_record_limit", MessageText.Create("Backend.Core.RelatedComponentDiscovery.Collect.51"), DiagnosticReadStatus.LimitReached, RelatedComponentRecordBounds.OriginalSourceLimitDetail, source.Id);
                        continue;
                    }
                    if (string.IsNullOrWhiteSpace(rawCommand) && string.IsNullOrWhiteSpace(executable))
                    { Check("related.source_read", source.Kind, source.Status, source.DetailText, source.Id); continue; }
                    IReadOnlyDictionary<string, string>? sourceEnvironment = read.Kind is "Run" or "StartupFile" || read.UserSid == request.TargetUserSid
                        ? environment : environment.Where(p => p.Key.Equals("SystemRoot", StringComparison.OrdinalIgnoreCase) || p.Key.Equals("windir", StringComparison.OrdinalIgnoreCase))
                            .ToDictionary(p => p.Key, p => p.Value, StringComparer.OrdinalIgnoreCase);
                    RelatedCommandResolution resolution = RelatedCommandResolver.Resolve(new(rawCommand, working, executable, arguments, sourceEnvironment));
                    if (source.Status == DiagnosticReadStatus.Complete && resolution.Status != DiagnosticReadStatus.Complete) source.Status = resolution.Status;
                    if (resolution.Notes.Count > 0 && !RelatedComponentRecordBounds.TryAppendDetail(source, MessageText.Join("；", resolution.NoteTexts)))
                        Check("related.source_detail_limit", MessageText.Create("Backend.Core.RelatedComponentDiscovery.Collect.52"), DiagnosticReadStatus.LimitReached, RelatedComponentRecordBounds.SourceDetailLimitDetail, source.Id);
                    foreach (RelatedResolvedCommandTarget target in resolution.Targets)
                    {
                        if (!AddSourceTarget(source, target.Path)) continue;
                        sourceTargets.Add(target.Path);
                        RecordPathSource(target.Path, source.Id);
                        bool userOnly = source.Kind is "Service" or "ServiceDll" || source.Scope == "LocalMachine";
                        int priority = target.Kind is "ScriptArgument" or "ModuleArgument" ? 90 : target.Kind is "Executable" or "WrapperExecutable" ? 80 : 50;
                        RelatedComponentCandidate? candidate = AddCandidate(target.Path, MessageText.Create("Backend.Core.RelatedComponentDiscovery.Collect.53"), source.Id, requireUserArea: userOnly, priority: priority);
                        if (candidate is not null) ReadScript(candidate.Path, source, sourceEnvironment);
                    }
                    // This is only a bounded host search hint, not a running-instance identity match.
                    foreach (string name in WrapperNames)
                        if (rawCommand.TrimStart(' ', '"').StartsWith(name + ".exe", StringComparison.OrdinalIgnoreCase) ||
                            rawCommand.TrimStart(' ', '"').StartsWith(name + " ", StringComparison.OrdinalIgnoreCase)) wrapperContexts.Add(name);
                    Check("related.source_read", source.Kind, source.Status, source.DetailText, source.Id);
                }
            }
            if (!Continue()) return;
            List<(RelatedProcessRead Process, int Priority, MessageText Reason)> hostCandidates = [];
            int processesRead = 0;
            Dictionary<DiagnosticReadStatus, int> inaccessible = [];
            using (IEnumerator<RelatedProcessRead> enumerator = _source.ReadProcesses(limits.MaximumProcesses, token).GetEnumerator())
            {
                while (Continue())
                {
                    if (processesRead >= limits.MaximumProcesses)
                    { Check("related.process_count", MessageText.Create("Backend.Core.RelatedComponentDiscovery.Collect.54"), DiagnosticReadStatus.LimitReached, MessageText.Create("Backend.Core.RelatedComponentDiscovery.Collect.55", (limits.MaximumProcesses))); break; }
                    if (!enumerator.MoveNext()) break;
                    RelatedProcessRead process = enumerator.Current;
                    if (!Continue()) break;
                    processesRead++;
                    bool explicitPid = request.SeedProcessIds.Contains(process.ProcessId);
                    if (process.Status != DiagnosticReadStatus.Complete && !explicitPid)
                    { inaccessible[process.Status] = inaccessible.GetValueOrDefault(process.Status) + 1; continue; }
                    int score = 0;
                    MessageText reason = string.Empty;
                    if (explicitPid) { score = 100; reason = MessageText.Create("Backend.Core.RelatedComponentDiscovery.Collect.56"); }
                    else if (seeds.Contains(process.ImagePath)) { score = 90; reason = MessageText.Create("Backend.Core.RelatedComponentDiscovery.Collect.57"); }
                    else if (SameComponentDirectory(process.ImagePath, seeds))
                    { score = 85; reason = MessageText.Create("Backend.Core.RelatedComponentDiscovery.Collect.58"); }
                    else if (sourceTargets.Contains(process.ImagePath)) { score = 80; reason = MessageText.Create("Backend.Core.RelatedComponentDiscovery.Collect.59"); }
                    else if (SameComponentDirectory(process.ImagePath, sourceTargets))
                    { score = 50; reason = MessageText.Create("Backend.Core.RelatedComponentDiscovery.Collect.60"); }
                    else if (wrapperContexts.Contains(Path.GetFileNameWithoutExtension(process.ImagePath)))
                    { score = 30; reason = MessageText.Create("Backend.Core.RelatedComponentDiscovery.Collect.61"); }
                    if (score > 0 && !Excluded(process.ImagePath)) hostCandidates.Add((process, score, reason));
                }
            }
            foreach (var incomplete in inaccessible) Check("related.process_read", MessageText.Create("Backend.Core.RelatedComponentDiscovery.Collect.62"), incomplete.Key,
                MessageText.Create("Backend.Core.RelatedComponentDiscovery.Collect.63", (incomplete.Value), (incomplete.Key)));
            if (hostCandidates.Count > limits.MaximumHosts) Check("related.host_count", MessageText.Create("Backend.Core.RelatedComponentDiscovery.Collect.64"), DiagnosticReadStatus.LimitReached,
                MessageText.Create("Backend.Core.RelatedComponentDiscovery.Collect.65", (hostCandidates.Count), (limits.MaximumHosts)));
            foreach (var selection in hostCandidates.OrderByDescending(p => p.Priority).ThenBy(p => p.Process.ProcessId).Take(limits.MaximumHosts))
            {
                if (!Continue()) return;
                RelatedProcessRead process = selection.Process;
                RelatedHostObservation host = new()
                {
                    ProcessId = process.ProcessId,
                    StartedAtUtc = process.StartedAtUtc,
                    ImagePath = process.ImagePath,
                    CommandLine = process.CommandLine,
                    WorkingDirectory = process.WorkingDirectory,
                    Status = process.Status,
                    DetailText = selection.Reason + " " + process.DetailText,
                    SignatureStatus = process.SignatureStatus,
                    SignatureDetailText = process.SignatureDetail is null ? MessageText.Create("Backend.Core.RelatedComponentDiscovery.Collect.66") : (MessageText)process.SignatureDetail
                };
                if (pathSources.TryGetValue(process.ImagePath, out HashSet<string>? ids)) host.SourceObservationIds.AddRange(ids);
                output.Hosts.Add(host);
                foreach (string sourceId in host.SourceObservationIds)
                    AddRelation(output, sourceId, host.Id, "SourceAndHostImagePathMatch", MessageText.Create("Backend.Core.RelatedComponentDiscovery.Collect.67"));
                if (host.Status != DiagnosticReadStatus.Complete || process.StartedAtUtc is null || string.IsNullOrWhiteSpace(process.ImagePath))
                { Check("related.host_identity", MessageText.Create("Backend.Core.RelatedComponentDiscovery.Collect.68"), host.Status == DiagnosticReadStatus.Complete ? DiagnosticReadStatus.NotChecked : host.Status, host.DetailText, host.Id); continue; }
                if (process.CommandLine is null || process.WorkingDirectory is null)
                    Check("related.host_command", MessageText.Create("Backend.Core.RelatedComponentDiscovery.Collect.69"), DiagnosticReadStatus.NotChecked, MessageText.Create("Backend.Core.RelatedComponentDiscovery.Collect.70"), host.Id);
                RelatedModuleRead modules;
                try { modules = _source.ReadModules(process, limits.MaximumModulesPerHost, token); }
                catch (Exception ex) when (IsReadException(ex)) { modules = new(StatusFor(ex), MessageExceptions.Describe(ex), false, []); }
                if (!Continue())
                {
                    host.Status = token.IsCancellationRequested ? DiagnosticReadStatus.Cancelled :
                        _time.GetElapsedTime(started) >= limits.MaximumDiscoveryDuration ? DiagnosticReadStatus.LimitReached : DiagnosticReadStatus.AccessDenied;
                    host.DetailText += MessageText.Create("Backend.Core.RelatedComponentDiscovery.Collect.71");
                    Check("related.host_modules", MessageText.Create("Backend.Core.RelatedComponentDiscovery.Collect.72"), host.Status, host.DetailText, host.Id);
                    return;
                }
                host.Status = modules.Status;
                host.DetailText += " " + modules.DetailText;
                int metadataLimit = limits.MaximumModulesPerHost == 0 ? 0 : (int)Math.Clamp((long)limits.MaximumModulesPerHost * 16, 256, 8192);
                string[] eligibleModules = modules.Paths.Take(metadataLimit).Where(p =>
                        RelatedCommandResolver.TryNormalizeLocalLiteral(p, null, out _, out _) &&
                        !p.Equals(process.ImagePath, StringComparison.OrdinalIgnoreCase) && !Excluded(p) && !Probe(p).IsProtected)
                    .Distinct(StringComparer.OrdinalIgnoreCase).OrderByDescending(p => seeds.Contains(p) ? 100 :
                        Path.GetDirectoryName(p)?.Equals(Path.GetDirectoryName(process.ImagePath), StringComparison.OrdinalIgnoreCase) == true ? 90 : sourceTargets.Contains(p) ? 80 : 50)
                    .ThenBy(p => p, StringComparer.OrdinalIgnoreCase).ToArray();
                if (!modules.IdentityMatched)
                {
                    if (host.Status == DiagnosticReadStatus.Complete) host.Status = DiagnosticReadStatus.NotChecked;
                    host.DetailText += MessageText.Create("Backend.Core.RelatedComponentDiscovery.Collect.73");
                    foreach (string module in eligibleModules.Take(limits.MaximumModulesPerHost))
                    {
                        if (module.Equals(process.ImagePath, StringComparison.OrdinalIgnoreCase)) continue;
                        RelatedComponentCandidate? unbound = AddCandidate(module, MessageText.Create("Backend.Core.RelatedComponentDiscovery.Collect.74"), priority: 40);
                        if (unbound is not null) unbound.DetailText += MessageText.Create("Backend.Core.RelatedComponentDiscovery.Collect.75");
                    }
                }
                else foreach (string module in eligibleModules.Take(limits.MaximumModulesPerHost))
                {
                    if (!module.Equals(process.ImagePath, StringComparison.OrdinalIgnoreCase))
                        AddCandidate(module, MessageText.Create("Backend.Core.RelatedComponentDiscovery.Collect.76"), hostId: host.Id,
                            priority: Path.GetDirectoryName(module)?.Equals(Path.GetDirectoryName(process.ImagePath), StringComparison.OrdinalIgnoreCase) == true ? 95 : 85);
                }
                if (eligibleModules.Length > limits.MaximumModulesPerHost || modules.Paths.Count > metadataLimit)
                { host.Status = DiagnosticReadStatus.LimitReached; host.DetailText += MessageText.Create("Backend.Core.RelatedComponentDiscovery.Collect.77"); }
                Check("related.host_modules", MessageText.Create("Backend.Core.RelatedComponentDiscovery.Collect.78"), host.Status, host.DetailText, host.Id);
            }
            Check("related.discovery_scope", MessageText.Create("Backend.Core.RelatedComponentDiscovery.Collect.79"), DiagnosticReadStatus.Complete,
                MessageText.Create("Backend.Core.RelatedComponentDiscovery.Collect.80"), required: false);
        }
        catch (OperationCanceledException)
        { Check("related.collection", MessageText.Create("Backend.Core.RelatedComponentDiscovery.Collect.81"), DiagnosticReadStatus.Cancelled, MessageText.Create("Backend.Core.RelatedComponentDiscovery.Collect.82")); }
        catch (Exception ex) when (IsReadException(ex))
        { Check("related.collection", MessageText.Create("Backend.Core.RelatedComponentDiscovery.Collect.83"), StatusFor(ex), MessageText.Create("Backend.Core.RelatedComponentDiscovery.Collect.84") + MessageExceptions.Describe(ex)); }
    }

    private static bool SameComponentDirectory(string image, IEnumerable<string> paths)
    {
        if (!RelatedCommandResolver.TryNormalizeLocalLiteral(image, null, out string? normalized, out _)) return false;
        string? directory = Path.GetDirectoryName(normalized);
        if (directory is null || directory.Length <= 3 || directory.Equals(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), StringComparison.OrdinalIgnoreCase) ||
            ContentDiscovery.IsWithin(directory, Environment.GetFolderPath(Environment.SpecialFolder.Windows))) return false;
        return paths.Any(path => Path.GetDirectoryName(path)?.Equals(directory, StringComparison.OrdinalIgnoreCase) == true);
    }
    private static void AddRelation(RelatedComponentDiagnosticReport output, string from, string to, string kind, MessageText evidence)
    {
        if (output.Relations.Count < 4096 && !output.Relations.Any(r => r.FromId == from && r.ToId == to && r.Kind == kind))
            output.Relations.Add(new(from, to, kind, evidence));
        else if (output.Relations.Count >= 4096 && !output.Checks.Any(c => c.CheckCode == "related.relation_count")) output.Checks.Add(new()
        { CheckCode = "related.relation_count", NameText = MessageText.Create("Backend.Core.RelatedComponentDiscovery.AddRelation.01"), Status = DiagnosticReadStatus.LimitReached, DetailText = MessageText.Create("Backend.Core.RelatedComponentDiscovery.AddRelation.02") });
    }
    private static void AddUnique(List<string> values, string value) { if (!values.Contains(value, StringComparer.OrdinalIgnoreCase)) values.Add(value); }
    private static string Short(string value) => value.Length <= 256 ? value : value[..256] + "…";
    private static string DecodeText(byte[] bytes)
    {
        using MemoryStream stream = new(bytes, writable: false);
        using StreamReader reader = new(stream, Encoding.UTF8, detectEncodingFromByteOrderMarks: true);
        return reader.ReadToEnd();
    }
    internal static bool IsReadException(Exception ex) => ex is IOException or UnauthorizedAccessException or System.Security.SecurityException or
        Win32Exception or ArgumentException or InvalidOperationException or NotSupportedException or XmlException;
    internal static DiagnosticReadStatus StatusFor(Exception ex) => ex switch
    {
        UnauthorizedAccessException or System.Security.SecurityException => DiagnosticReadStatus.AccessDenied,
        FileNotFoundException or DirectoryNotFoundException => DiagnosticReadStatus.NotPresent,
        Win32Exception native when native.NativeErrorCode is 5 => DiagnosticReadStatus.AccessDenied,
        Win32Exception native when native.NativeErrorCode is 2 or 3 or 87 or 1168 => DiagnosticReadStatus.NotPresent,
        Win32Exception native when native.NativeErrorCode is 32 or 33 or 299 => DiagnosticReadStatus.NotChecked,
        _ => DiagnosticReadStatus.Failed
    };
}

/// <summary>Local registry/file/limited process queries. No WMI shell, shell-link resolution, private key, or write API.</summary>
internal sealed class WindowsRelatedComponentDataSource : IRelatedComponentDataSource
{
    private string? _processUserSid;
    public string? ReadCurrentUserSid()
    {
        using WindowsIdentity identity = WindowsIdentity.GetCurrent();
        if (_processUserSid is null)
        {
            if (!OpenProcessToken(GetCurrentProcess(), 0x0008, out SafeAccessTokenHandle token)) throw new Win32Exception(Marshal.GetLastWin32Error());
            using (token)
            using (WindowsIdentity processIdentity = new(token.DangerousGetHandle())) _processUserSid = processIdentity.User?.Value;
        }
        // Startup folders and process environment belong to the process identity, not an impersonated account.
        return identity.User?.Value == _processUserSid ? _processUserSid : null;
    }
    public IReadOnlyDictionary<string, string> ReadEnvironmentVariables(string targetUserSid)
    {
        if (ReadCurrentUserSid() != targetUserSid) throw MessageExceptions.Create(MessageText.Create("Backend.Core.RelatedComponentDiscovery.ReadEnvironmentVariables.01"), sourceText => new UnauthorizedAccessException(sourceText));
        Dictionary<string, string> variables = new(StringComparer.OrdinalIgnoreCase);
        foreach (DictionaryEntry pair in Environment.GetEnvironmentVariables())
            if (pair.Key is string key && pair.Value is string value && key.Length <= 128 && value.Length <= RelatedCommandResolver.MaximumCommandCharacters)
                variables[key] = value;
        return variables;
    }

    public IEnumerable<RelatedSourceRead> ReadSources(RelatedComponentDiscoveryRequest request, RelatedComponentLimits limits,
        Func<long> remainingSnapshotBytes, CancellationToken token)
    {
        foreach (RelatedSourceRead item in ReadRun(request.TargetUserSid, false, limits.MaximumSources, token)) yield return item;
        foreach (RelatedSourceRead item in ReadStartup(Environment.GetFolderPath(Environment.SpecialFolder.Startup), request.TargetUserSid, limits.MaximumSources, token)) yield return item;
        foreach (RelatedSourceRead item in ReadRun(request.TargetUserSid, true, limits.MaximumSources, token)) yield return item;
        foreach (RelatedSourceRead item in ReadStartup(Environment.GetFolderPath(Environment.SpecialFolder.CommonStartup), null, limits.MaximumSources, token)) yield return item;
        foreach (RelatedSourceRead item in ReadTasks(limits, remainingSnapshotBytes, token)) yield return item;
        foreach (RelatedSourceRead item in ReadServices(limits.MaximumSources, token)) yield return item;
    }

    private static IEnumerable<RelatedSourceRead> ReadRun(string sid, bool machine, int maximum, CancellationToken token)
    {
        RegistryView[] views = machine && Environment.Is64BitOperatingSystem ? [RegistryView.Registry64, RegistryView.Registry32] :
            [Environment.Is64BitOperatingSystem ? RegistryView.Registry64 : RegistryView.Registry32];
        foreach (RegistryView view in views)
            foreach (string suffix in new[] { @"Software\Microsoft\Windows\CurrentVersion\Run", @"Software\Microsoft\Windows\CurrentVersion\RunOnce" })
            {
                string keyPath = machine ? suffix : sid + "\\" + suffix;
                string location = (machine ? "HKEY_LOCAL_MACHINE\\" : "HKEY_USERS\\") + keyPath + " [" + view + "]";
                List<RelatedSourceRead> rows = [];
                try
                {
                    token.ThrowIfCancellationRequested();
                    using RegistryKey baseKey = RegistryKey.OpenBaseKey(machine ? RegistryHive.LocalMachine : RegistryHive.Users, view);
                    using RegistryKey? key = baseKey.OpenSubKey(keyPath, writable: false);
                    if (key is null) rows.Add(SourceState("Run", machine ? "LocalMachine" : "CurrentUser", location, DiagnosticReadStatus.NotPresent, MessageText.Create("Backend.Core.RelatedComponentDiscovery.ReadRun.01"), machine ? null : sid));
                    else
                    {
                        string[] names = key.GetValueNames();
                        foreach (string name in names.Take(maximum))
                        {
                            token.ThrowIfCancellationRequested();
                            try
                            {
                                object? value = key.GetValue(name, null, RegistryValueOptions.DoNotExpandEnvironmentNames);
                                rows.Add(value is string command && command.Length <= RelatedCommandResolver.MaximumCommandCharacters
                                    ? new()
                                    {
                                        Kind = "Run",
                                        Scope = machine ? "LocalMachine" : "CurrentUser",
                                        Location = location + "\\" + name,
                                        RawCommand = command,
                                        UserSid = machine ? null : sid,
                                        DetailText = MessageText.Create("Backend.Core.RelatedComponentDiscovery.ReadRun.02")
                                    }
                                    : SourceState("Run", machine ? "LocalMachine" : "CurrentUser", location + "\\" + name, DiagnosticReadStatus.NotChecked, MessageText.Create("Backend.Core.RelatedComponentDiscovery.ReadRun.03"), machine ? null : sid));
                            }
                            catch (Exception ex) when (RelatedComponentDiscovery.IsReadException(ex))
                            { rows.Add(SourceState("Run", machine ? "LocalMachine" : "CurrentUser", location + "\\" + name, RelatedComponentDiscovery.StatusFor(ex), MessageExceptions.Describe(ex), machine ? null : sid)); }
                        }
                        if (names.Length > maximum) rows.Add(SourceState("Run", machine ? "LocalMachine" : "CurrentUser", location, DiagnosticReadStatus.LimitReached, MessageText.Create("Backend.Core.RelatedComponentDiscovery.ReadRun.04"), machine ? null : sid));
                    }
                }
                catch (Exception ex) when (RelatedComponentDiscovery.IsReadException(ex))
                { rows.Add(SourceState("Run", machine ? "LocalMachine" : "CurrentUser", location, RelatedComponentDiscovery.StatusFor(ex), MessageExceptions.Describe(ex), machine ? null : sid)); }
                foreach (RelatedSourceRead row in rows) yield return row;
            }
    }

    private IEnumerable<RelatedSourceRead> ReadStartup(string root, string? sid, int maximum, CancellationToken token)
    {
        List<DiscoveryReadNote> notes = [];
        List<string> files = [];
        RelatedSourceRead? unavailable = null;
        try
        {
            token.ThrowIfCancellationRequested();
            FileAttributes attributes = File.GetAttributes(root);
            if ((attributes & FileAttributes.ReparsePoint) != 0 || !ContentDiscovery.IsLocalSafePath(root))
                unavailable = SourceState("StartupDirectory", sid is null ? "LocalMachine" : "CurrentUser", root,
                    DiagnosticReadStatus.NotChecked, MessageText.Create("Backend.Core.RelatedComponentDiscovery.ReadStartup.01"), sid);
            else
            {
                string[] entries = Directory.EnumerateFileSystemEntries(root).Take(maximum < int.MaxValue ? maximum + 1 : maximum).ToArray();
                foreach (string entry in entries.Take(maximum))
                {
                    token.ThrowIfCancellationRequested();
                    try
                    {
                        FileAttributes item = File.GetAttributes(entry);
                        if ((item & FileAttributes.ReparsePoint) != 0) { notes.Add(new(DiagnosticReadStatus.NotChecked, ReasonCodes.UnsafePath, MessageText.Create("Backend.Core.RelatedComponentDiscovery.ReadStartup.02") + entry)); continue; }
                        if ((item & FileAttributes.Directory) == 0) files.Add(entry);
                    }
                    catch (Exception ex) when (RelatedComponentDiscovery.IsReadException(ex))
                    { notes.Add(new(RelatedComponentDiscovery.StatusFor(ex), ReasonCodes.ForFailureType(ex.GetType().Name), MessageText.Create("Backend.Core.RelatedComponentDiscovery.ReadStartup.03") + entry + "；" + MessageExceptions.Describe(ex))); }
                }
                if (entries.Length > maximum) notes.Add(new(DiagnosticReadStatus.LimitReached, ReasonCodes.ResourceLimit, MessageText.Create("Backend.Core.RelatedComponentDiscovery.ReadStartup.04")));
            }
        }
        catch (Exception ex) when (RelatedComponentDiscovery.IsReadException(ex))
        { unavailable = SourceState("StartupDirectory", sid is null ? "LocalMachine" : "CurrentUser", root, RelatedComponentDiscovery.StatusFor(ex), MessageExceptions.Describe(ex), sid); }
        if (unavailable is not null) yield return unavailable;
        foreach (string file in files)
        {
            token.ThrowIfCancellationRequested();
            if (file.EndsWith("desktop.ini", StringComparison.OrdinalIgnoreCase)) continue;
            yield return new()
            {
                Kind = "StartupFile",
                Scope = sid is null ? "LocalMachine" : "CurrentUser",
                Location = file,
                UserSid = sid,
                RawCommand = file.EndsWith(".lnk", StringComparison.OrdinalIgnoreCase) ? "" : "\"" + file + "\"",
                ExecutablePath = file.EndsWith(".lnk", StringComparison.OrdinalIgnoreCase) ? null : file,
                ShortcutPath = file.EndsWith(".lnk", StringComparison.OrdinalIgnoreCase) ? file : null,
                DetailText = MessageText.Create("Backend.Core.RelatedComponentDiscovery.ReadStartup.05")
            };
        }
        foreach (DiscoveryReadNote note in notes) yield return SourceState("StartupDirectory", sid is null ? "LocalMachine" : "CurrentUser", root,
            note.Status, note.DetailText, sid);
    }

    private IEnumerable<RelatedSourceRead> ReadTasks(RelatedComponentLimits limits, Func<long> remainingSnapshotBytes, CancellationToken token)
    {
        string root = RelatedTaskSnapshotReader.TaskRoot;
        MessageTextCollection notes = [];
        List<DiscoveryReadNote> readNotes = [];
        foreach (string path in ContentDiscovery.Files(root, notes, limits.MaximumSources, 8, token, readNotes))
        {
            token.ThrowIfCancellationRequested();
            int budget = (int)Math.Max(0, Math.Min(limits.MaximumScriptBytes, remainingSnapshotBytes()));
            RelatedFileRead read = ReadFile(path, budget, token);
            if (read.Status != DiagnosticReadStatus.Complete)
            { yield return SourceState("Task", "LocalMachine", path, read.Status, read.DetailText) with { SnapshotBytesRead = read.BytesRead }; continue; }
            List<RelatedSourceRead> rows = [];
            try
            {
                using MemoryStream input = new(read.Bytes, writable: false);
                using XmlReader reader = XmlReader.Create(input, new()
                {
                    DtdProcessing = DtdProcessing.Prohibit,
                    XmlResolver = null,
                    MaxCharactersInDocument = Math.Min(limits.MaximumScriptBytes, RelatedTaskSnapshotReader.MaximumBytes),
                    MaxCharactersFromEntities = 1024
                });
                XDocument document = XDocument.Load(reader);
                if (document.Root?.Name.LocalName != "Task") throw MessageExceptions.Create(MessageText.Create("Backend.Core.RelatedComponentDiscovery.ReadTasks.01"), sourceText => new InvalidDataException(sourceText));
                string? principal = document.Descendants().FirstOrDefault(e => e.Name.LocalName == "UserId")?.Value;
                XElement[] actions = document.Root.Elements().Where(e => e.Name.LocalName == "Actions").SelectMany(e => e.Elements()).ToArray();
                int index = 0;
                foreach (XElement action in actions.Take(32))
                {
                    if (action.Name.LocalName != "Exec")
                    { rows.Add(SourceState("Task", "LocalMachine", path, DiagnosticReadStatus.NotChecked, MessageText.Create("Backend.Core.RelatedComponentDiscovery.ReadTasks.02"), principal)); continue; }
                    string[] commands = action.Elements().Where(e => e.Name.LocalName == "Command").Select(e => e.Value).ToArray();
                    string[] arguments = action.Elements().Where(e => e.Name.LocalName == "Arguments").Select(e => e.Value).ToArray();
                    string[] working = action.Elements().Where(e => e.Name.LocalName == "WorkingDirectory").Select(e => e.Value).ToArray();
                    if (commands.Length != 1 || arguments.Length > 1 || working.Length > 1 || commands.Concat(arguments).Concat(working).Any(s => s.Length > RelatedCommandResolver.MaximumCommandCharacters))
                    { rows.Add(SourceState("Task", "LocalMachine", path, DiagnosticReadStatus.NotChecked, MessageText.Create("Backend.Core.RelatedComponentDiscovery.ReadTasks.03"), principal)); continue; }
                    rows.Add(new()
                    {
                        Kind = "Task",
                        Scope = principal == ReadCurrentUserSid() ? "CurrentUser" : "LocalMachine",
                        Location = path + "#Exec" + (++index),
                        UserSid = principal,
                        ExecutablePath = commands[0],
                        Arguments = arguments.FirstOrDefault(),
                        WorkingDirectory = working.FirstOrDefault(),
                        RawCommand = "\"" + commands[0] + "\"" + (arguments.Length == 0 ? "" : " " + arguments[0]),
                        DetailText = MessageText.Create("Backend.Core.RelatedComponentDiscovery.ReadTasks.04")
                    });
                }
                if (actions.Length > 32) rows.Add(SourceState("Task", "LocalMachine", path, DiagnosticReadStatus.LimitReached, MessageText.Create("Backend.Core.RelatedComponentDiscovery.ReadTasks.05"), principal));
            }
            catch (Exception ex) when (RelatedComponentDiscovery.IsReadException(ex))
            { rows.Add(SourceState("Task", "LocalMachine", path, RelatedComponentDiscovery.StatusFor(ex), MessageExceptions.Describe(ex))); }
            if (rows.Count == 0) rows.Add(SourceState("Task", "LocalMachine", path, DiagnosticReadStatus.Complete, MessageText.Create("Backend.Core.RelatedComponentDiscovery.ReadTasks.06")));
            rows[0] = rows[0] with { SnapshotBytesRead = Math.Max(read.BytesRead, read.Bytes.Length) };
            foreach (RelatedSourceRead row in rows) yield return row;
        }
        foreach (DiscoveryReadNote note in readNotes) yield return SourceState("TaskEnumeration", "LocalMachine", root,
            note.Status, note.DetailText);
    }

    private static IEnumerable<RelatedSourceRead> ReadServices(int maximum, CancellationToken token)
    {
        List<RelatedSourceRead> rows = [];
        const string rootPath = @"SYSTEM\CurrentControlSet\Services";
        try
        {
            using RegistryKey? root = Registry.LocalMachine.OpenSubKey(rootPath, writable: false);
            if (root is null) rows.Add(SourceState("Service", "LocalMachine", rootPath, DiagnosticReadStatus.NotPresent, MessageText.Create("Backend.Core.RelatedComponentDiscovery.ReadServices.01")));
            else
            {
                string[] names = root.GetSubKeyNames();
                foreach (string name in names.Take(maximum))
                {
                    token.ThrowIfCancellationRequested();
                    string location = "HKEY_LOCAL_MACHINE\\" + rootPath + "\\" + name;
                    try
                    {
                        using RegistryKey? key = root.OpenSubKey(name, writable: false);
                        if (key is null) { rows.Add(SourceState("Service", "LocalMachine", location, DiagnosticReadStatus.NotPresent, MessageText.Create("Backend.Core.RelatedComponentDiscovery.ReadServices.02"))); continue; }
                        object? image = key.GetValue("ImagePath", null, RegistryValueOptions.DoNotExpandEnvironmentNames);
                        if (image is string command && command.Length <= RelatedCommandResolver.MaximumCommandCharacters)
                            rows.Add(new()
                            {
                                Kind = "Service",
                                Scope = "LocalMachine",
                                Location = location + "\\ImagePath",
                                RawCommand = command,
                                DetailText = MessageText.Create("Backend.Core.RelatedComponentDiscovery.ReadServices.03")
                            });
                        else if (image is not null) rows.Add(SourceState("Service", "LocalMachine", location + "\\ImagePath", DiagnosticReadStatus.NotChecked, MessageText.Create("Backend.Core.RelatedComponentDiscovery.ReadServices.04")));
                        using RegistryKey? parameters = key.OpenSubKey("Parameters", writable: false);
                        object? dll = parameters?.GetValue("ServiceDll", null, RegistryValueOptions.DoNotExpandEnvironmentNames);
                        if (dll is string module && module.Length <= RelatedCommandResolver.MaximumCommandCharacters)
                            rows.Add(new()
                            {
                                Kind = "ServiceDll",
                                Scope = "LocalMachine",
                                Location = location + "\\Parameters\\ServiceDll",
                                RawCommand = "\"" + module + "\"",
                                ExecutablePath = module,
                                DetailText = MessageText.Create("Backend.Core.RelatedComponentDiscovery.ReadServices.05")
                            });
                    }
                    catch (Exception ex) when (RelatedComponentDiscovery.IsReadException(ex))
                    { rows.Add(SourceState("Service", "LocalMachine", location, RelatedComponentDiscovery.StatusFor(ex), MessageExceptions.Describe(ex))); }
                }
                if (names.Length > maximum) rows.Add(SourceState("ServiceEnumeration", "LocalMachine", rootPath, DiagnosticReadStatus.LimitReached, MessageText.Create("Backend.Core.RelatedComponentDiscovery.ReadServices.06")));
            }
        }
        catch (Exception ex) when (RelatedComponentDiscovery.IsReadException(ex))
        { rows.Add(SourceState("ServiceEnumeration", "LocalMachine", rootPath, RelatedComponentDiscovery.StatusFor(ex), MessageExceptions.Describe(ex))); }
        foreach (RelatedSourceRead row in rows) yield return row;
    }

    public IEnumerable<RelatedProcessRead> ReadProcesses(int maximumProcesses, CancellationToken token)
    {
        Process[] processes = Process.GetProcesses();
        try
        {
            foreach (Process process in processes.OrderBy(p => p.Id).Take(maximumProcesses < int.MaxValue ? maximumProcesses + 1 : maximumProcesses))
            { token.ThrowIfCancellationRequested(); yield return ReadProcess(process.Id); }
        }
        finally { foreach (Process process in processes) process.Dispose(); }
    }

    public RelatedModuleRead ReadModules(RelatedProcessRead expected, int maximumModules, CancellationToken token)
    {
        token.ThrowIfCancellationRequested();
        if (maximumModules <= 0) return new(DiagnosticReadStatus.LimitReached, MessageText.Create("Backend.Core.RelatedComponentDiscovery.ReadModules.01"), false, []);
        RelatedProcessRead before = ReadProcess(expected.ProcessId);
        if (!SameProcess(expected, before)) return new(DiagnosticReadStatus.NotChecked, MessageText.Create("Backend.Core.RelatedComponentDiscovery.ReadModules.02"), false, []);
        List<string> paths = [];
        DiagnosticReadStatus status = DiagnosticReadStatus.Complete;
        MessageText detail = MessageText.Create("Backend.Core.RelatedComponentDiscovery.ReadModules.03");
        try
        {
            using Process process = Process.GetProcessById(expected.ProcessId);
            int visited = 0, maximumMetadata = (int)Math.Clamp((long)maximumModules * 16, 256, 8192);
            foreach (ProcessModule module in process.Modules)
            {
                token.ThrowIfCancellationRequested();
                if (++visited > maximumMetadata)
                { status = DiagnosticReadStatus.LimitReached; detail += MessageText.Create("Backend.Core.RelatedComponentDiscovery.ReadModules.04", (maximumMetadata)); break; }
                string path = module.FileName;
                if (path.Equals(expected.ImagePath, StringComparison.OrdinalIgnoreCase) || RelatedArtifactReader.IsProtected(path)) continue;
                if (paths.Count >= maximumModules)
                { status = DiagnosticReadStatus.LimitReached; detail += MessageText.Create("Backend.Core.RelatedComponentDiscovery.ReadModules.05"); break; }
                paths.Add(path);
            }
            detail += MessageText.Create("Backend.Core.RelatedComponentDiscovery.ReadModules.06", (maximumModules), (maximumMetadata));
        }
        catch (Exception ex) when (RelatedComponentDiscovery.IsReadException(ex))
        { status = RelatedComponentDiscovery.StatusFor(ex); detail += " " + MessageExceptions.Describe(ex); }
        RelatedProcessRead after = ReadProcess(expected.ProcessId);
        bool matches = SameProcess(expected, after);
        if (!matches) { status = DiagnosticReadStatus.NotChecked; detail += MessageText.Create("Backend.Core.RelatedComponentDiscovery.ReadModules.07"); }
        return new(status, detail, matches, paths);
    }

    public RelatedPathRead ProbePath(string path)
    {
        if (!ContentDiscovery.IsLocalSafePath(path)) return new(DiagnosticReadStatus.NotChecked, MessageText.Create("Backend.Core.RelatedComponentDiscovery.ProbePath.01"), false, false, false, false);
        bool protectedPath = RelatedArtifactReader.IsProtected(path);
        bool user = new[] { Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), Path.GetTempPath() }
            .Any(root => !string.IsNullOrWhiteSpace(root) && ContentDiscovery.IsWithin(path, root));
        try
        {
            FileAttributes attributes = File.GetAttributes(path);
            bool directory = (attributes & FileAttributes.Directory) != 0;
            return new(DiagnosticReadStatus.Complete, MessageText.Create("Backend.Core.RelatedComponentDiscovery.ProbePath.02"), !directory, directory, user, protectedPath);
        }
        catch (Exception ex) when (RelatedComponentDiscovery.IsReadException(ex))
        { return new(RelatedComponentDiscovery.StatusFor(ex), MessageExceptions.Describe(ex), false, false, user, protectedPath); }
    }

    public RelatedFileRead ReadFile(string path, int maximumBytes, CancellationToken token)
    {
        if (maximumBytes <= 0) return new(DiagnosticReadStatus.LimitReached, MessageText.Create("Backend.Core.RelatedComponentDiscovery.ReadFile.01"), []);
        int bytesRead = 0;
        try
        {
            token.ThrowIfCancellationRequested();
            using FileStream stream = RelatedArtifactReader.Open(path);
            if (stream.Length > maximumBytes) return new(DiagnosticReadStatus.LimitReached, MessageText.Create("Backend.Core.RelatedComponentDiscovery.ReadFile.02"), []);
            byte[] bytes = new byte[checked((int)stream.Length)];
            while (bytesRead < bytes.Length)
            {
                token.ThrowIfCancellationRequested();
                int read = stream.Read(bytes, bytesRead, Math.Min(64 * 1024, bytes.Length - bytesRead));
                if (read == 0) throw MessageExceptions.Create(MessageText.Create("Backend.Core.RelatedComponentDiscovery.ReadFile.03"), sourceText => new EndOfStreamException(sourceText));
                bytesRead += read;
            }
            RelatedArtifactReader.ValidatePath(stream.SafeFileHandle, Path.GetFullPath(path));
            return new(DiagnosticReadStatus.Complete, MessageText.Create("Backend.Core.RelatedComponentDiscovery.ReadFile.04"), bytes, bytesRead);
        }
        catch (Exception ex) when (RelatedComponentDiscovery.IsReadException(ex))
        { return new(RelatedComponentDiscovery.StatusFor(ex), ex is Win32Exception { NativeErrorCode: 32 or 33 } ? MessageText.Create("Backend.Core.RelatedComponentDiscovery.ReadFile.05") : MessageExceptions.Describe(ex), [], bytesRead); }
    }

    private static RelatedSourceRead SourceState(string kind, string scope, string location, DiagnosticReadStatus status, MessageText detail, string? sid = null) =>
        new() { Kind = kind, Scope = scope, Location = location, Status = status, DetailText = detail, UserSid = sid };
    private static bool SameProcess(RelatedProcessRead expected, RelatedProcessRead actual) => actual.Status == DiagnosticReadStatus.Complete &&
        expected.ProcessId == actual.ProcessId && expected.StartedAtUtc is not null && expected.StartedAtUtc == actual.StartedAtUtc &&
        expected.ImagePath.Equals(actual.ImagePath, StringComparison.OrdinalIgnoreCase);
    private static RelatedProcessRead ReadProcess(int pid)
    {
        // Public limited-query APIs: https://learn.microsoft.com/windows/win32/api/winbase/nf-winbase-queryfullprocessimagenamew
        using SafeProcessHandle handle = OpenProcess(0x1000, false, pid);
        if (handle.IsInvalid)
        {
            Win32Exception ex = new(Marshal.GetLastWin32Error());
            return new(pid, null, "", RelatedComponentDiscovery.StatusFor(ex), MessageText.Create("Backend.Core.RelatedComponentDiscovery.ReadProcess.01") + MessageExceptions.Describe(ex));
        }
        StringBuilder image = new(RelatedCommandResolver.MaximumCommandCharacters);
        uint length = (uint)image.Capacity;
        if (!QueryFullProcessImageName(handle, 0, image, ref length) || !GetProcessTimes(handle, out long created, out _, out _, out _))
        {
            Win32Exception ex = new(Marshal.GetLastWin32Error());
            return new(pid, null, image.ToString(), RelatedComponentDiscovery.StatusFor(ex), MessageText.Create("Backend.Core.RelatedComponentDiscovery.ReadProcess.02") + MessageExceptions.Describe(ex));
        }
        try
        {
            return new(pid, DateTimeOffset.FromFileTime(created).ToUniversalTime(), image.ToString(), DiagnosticReadStatus.Complete,
            MessageText.Create("Backend.Core.RelatedComponentDiscovery.ReadProcess.03"));
        }
        catch (ArgumentOutOfRangeException ex) { return new(pid, null, image.ToString(), DiagnosticReadStatus.Failed, MessageExceptions.Describe(ex)); }
    }
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern SafeProcessHandle OpenProcess(uint access, [MarshalAs(UnmanagedType.Bool)] bool inheritHandle, int processId);
    [DllImport("kernel32.dll")]
    private static extern IntPtr GetCurrentProcess();
    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool OpenProcessToken(IntPtr process, uint access, out SafeAccessTokenHandle token);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, EntryPoint = "QueryFullProcessImageNameW", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool QueryFullProcessImageName(SafeProcessHandle process, uint flags, StringBuilder name, ref uint size);
    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetProcessTimes(SafeProcessHandle process, out long creation, out long exit, out long kernel, out long user);
}
