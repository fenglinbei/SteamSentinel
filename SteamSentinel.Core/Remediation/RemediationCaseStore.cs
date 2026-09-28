using SteamSentinel.Core.Reporting;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text.Json;
using Microsoft.Win32.SafeHandles;
using SteamSentinel.Core.Models;
using SteamSentinel.Core.Scanning;
using SteamSentinel.Core.Steam;
using SteamSentinel.Core.Utilities;

namespace SteamSentinel.Core.Remediation;

/// <summary>Bounded user-owned case persistence. Loading a record never authorizes a mutation.</summary>
public sealed class RemediationCaseStore
{
    private static readonly JsonSerializerOptions SnapshotComparison = CreateSnapshotComparison();
    private static JsonSerializerOptions CreateSnapshotComparison()
    {
        var resolver = new System.Text.Json.Serialization.Metadata.DefaultJsonTypeInfoResolver();
        resolver.Modifiers.Add(info =>
        {
            foreach (var property in info.Properties)
                if (property.PropertyType == typeof(DisplayMessage) || property.PropertyType == typeof(List<DisplayMessage?>) ||
                    property.PropertyType == typeof(Dictionary<int, DisplayMessage>)) property.ShouldSerialize = (_, _) => false;
        });
        return new(JsonFile.Options) { TypeInfoResolver = resolver };
    }
    public const int MaximumCases = 128, MaximumPlans = 512, MaximumActions = 32768, MaximumEpisodes = 32;
    public const long MaximumCaseBytes = 64L * 1024 * 1024;
    private const int MaximumSummaryBytes = 32 * 1024;
    private readonly string _root;
    private readonly Func<string> _currentUserSid;

    public RemediationCaseStore(string? rootDirectory = null, Func<string>? currentUserSid = null)
    {
        _root = Path.TrimEndingDirectorySeparator(Path.GetFullPath(rootDirectory ?? Path.Combine(AppPaths.UserStateRoot, "Cases")));
        if (!ContentDiscovery.IsLocalSafePath(_root) || _root.Equals(Path.GetPathRoot(_root), StringComparison.OrdinalIgnoreCase))
            throw MessageExceptions.Create(MessageText.Create("Backend.Core.RemediationCaseStore.Constructor.01"), sourceText => new ArgumentException(sourceText, nameof(rootDirectory)));
        _currentUserSid = currentUserSid ?? CurrentUserSid;
    }

    public string RootDirectory => _root;

    public async Task SaveAsync(RemediationCaseRecord record, CancellationToken token = default)
    {
        ArgumentNullException.ThrowIfNull(record);
        string sid = _currentUserSid();
        ValidateRecord(record, sid);
        string directory = CaseDirectory(record.CaseId);
        CheckPath(_root); CheckPath(directory);
        Directory.CreateDirectory(_root);
        using SafeFileHandle rootLease = OpenDirectory(_root);
        if (!Directory.Exists(directory) && Directory.EnumerateDirectories(_root).Take(MaximumCases).Count() >= MaximumCases)
            throw MessageExceptions.Create(MessageText.Create("Backend.Core.RemediationCaseStore.SaveAsync.01", (MaximumCases)), sourceText => new InvalidDataException(sourceText));
        Directory.CreateDirectory(directory);
        using SafeFileHandle directoryLease = OpenDirectory(directory);
        using FileStream writeLock = OpenWriteLock(Path.Combine(directory, "case.lock"));
        token.ThrowIfCancellationRequested();
        RequireSameSid(sid);
        string path = Path.Combine(directory, "case.json");
        RemediationCaseRecord? previous = await ReadRecordAsync(path, token).ConfigureAwait(false);
        if (previous is not null)
        {
            ValidateRecord(previous, sid);
            if (previous.CaseId != record.CaseId || previous.Revision != record.Revision)
                throw MessageExceptions.Create(MessageText.Create("Backend.Core.RemediationCaseStore.SaveAsync.02"), sourceText => new InvalidDataException(sourceText));
        }
        else if (record.Revision != 0) throw MessageExceptions.Create(MessageText.Create("Backend.Core.RemediationCaseStore.SaveAsync.03"), sourceText => new InvalidDataException(sourceText));
        long oldRevision = record.Revision;
        DateTimeOffset oldUpdated = record.UpdatedAtUtc;
        record.Revision = checked(oldRevision + 1);
        record.UpdatedAtUtc = DateTimeOffset.UtcNow;
        bool committed = false;
        try
        {
            ValidateDirectoryLeases(rootLease, directoryLease, directory);
            // Keep exact identities and original command snapshots locally. Public export applies
            // ReportPrivacy separately; redacted values must never replace comparison snapshots.
            await AtomicFile.WriteAsync(path, async stream =>
            {
                RelatedArtifactReader.ValidatePath(stream.SafeFileHandle, Path.GetFullPath(stream.Name));
                using CappedWriteStream bounded = new(stream, MaximumCaseBytes);
                await JsonSerializer.SerializeAsync(bounded, record, JsonFile.Options, token).ConfigureAwait(false);
                RequireSameSid(sid);
                ValidateDirectoryLeases(rootLease, directoryLease, directory);
            }, token).ConfigureAwait(false);
            committed = true;
            RemediationCaseSummary summary = Summary(record);
            await AtomicFile.WriteAsync(Path.Combine(directory, "summary.json"), async stream =>
            {
                RelatedArtifactReader.ValidatePath(stream.SafeFileHandle, Path.GetFullPath(stream.Name));
                using CappedWriteStream bounded = new(stream, MaximumSummaryBytes);
                await JsonSerializer.SerializeAsync(bounded, summary, JsonFile.Options, token).ConfigureAwait(false);
                RequireSameSid(sid);
                ValidateDirectoryLeases(rootLease, directoryLease, directory);
            }, token).ConfigureAwait(false);
        }
        catch
        {
            // If only the display index failed, the authoritative case is already durable.
            // Keep its new revision so the caller can retry saving without overwriting history.
            if (!committed) { record.Revision = oldRevision; record.UpdatedAtUtc = oldUpdated; }
            throw;
        }
    }

    public async Task<RemediationCaseRecord?> LoadAsync(Guid caseId, CancellationToken token = default)
    {
        string sid = _currentUserSid(), directory = CaseDirectory(caseId);
        CheckPath(_root); CheckPath(directory);
        if (!Directory.Exists(directory)) return null;
        using SafeFileHandle rootLease = OpenDirectory(_root);
        using SafeFileHandle directoryLease = OpenDirectory(directory);
        RemediationCaseRecord? result = await ReadRecordAsync(Path.Combine(directory, "case.json"), token).ConfigureAwait(false);
        RequireSameSid(sid);
        ValidateDirectoryLeases(rootLease, directoryLease, directory);
        if (result is null) return null;
        ValidateRecord(result, sid);
        if (result.CaseId != caseId) throw MessageExceptions.Create(MessageText.Create("Backend.Core.RemediationCaseStore.LoadAsync.01"), sourceText => new InvalidDataException(sourceText));
        return result;
    }

    /// <summary>The small index is a display hint. LoadAsync always validates the actual case before use.</summary>
    public async Task<IReadOnlyList<RemediationCaseSummary>> ListAsync(CancellationToken token = default)
    {
        string sid = _currentUserSid();
        ValidateSid(sid);
        CheckPath(_root);
        if (!Directory.Exists(_root)) return [];
        using SafeFileHandle rootLease = OpenDirectory(_root);
        string[] directories = Directory.EnumerateDirectories(_root).Take(MaximumCases + 1).ToArray();
        if (directories.Length > MaximumCases) throw MessageExceptions.Create(MessageText.Create("Backend.Core.RemediationCaseStore.ListAsync.01"), sourceText => new InvalidDataException(sourceText));
        List<RemediationCaseSummary> summaries = [];
        foreach (string directory in directories.Where(IsCaseDirectory))
        {
            token.ThrowIfCancellationRequested();
            Guid id = Guid.ParseExact(Path.GetFileName(directory), "N");
            try
            {
                CheckPath(directory);
                using SafeFileHandle directoryLease = OpenDirectory(directory);
                await using FileStream stream = RelatedArtifactReader.Open(Path.Combine(directory, "summary.json"));
                if (stream.Length > MaximumSummaryBytes) throw MessageExceptions.Create(MessageText.Create("Backend.Core.RemediationCaseStore.ListAsync.02"), sourceText => new InvalidDataException(sourceText));
                RemediationCaseSummary summary = await JsonFile.ReadAsync<RemediationCaseSummary>(stream, MessageText.Create("Backend.Core.RemediationCaseStore.ListAsync.03"), token).ConfigureAwait(false);
                if (summary.CaseId != id || summary.UserSid != sid || summary.Revision <= 0 || summary.EpisodeCount is < 0 or > MaximumEpisodes ||
                    summary.PendingExecutionCount is < 0 or > MaximumPlans || !Enum.IsDefined(summary.State))
                    throw MessageExceptions.Create(MessageText.Create("Backend.Core.RemediationCaseStore.ListAsync.04"), sourceText => new InvalidDataException(sourceText));
                summaries.Add(summary);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or Win32Exception or JsonException or ArgumentException)
            {
                summaries.Add(new()
                {
                    CaseId = id,
                    UserSid = sid,
                    ReadStatus = DiagnosticReadStatus.NotChecked,
                    State = CaseReverificationState.Incomplete,
                    DetailText = MessageText.Create("Backend.Core.RemediationCaseStore.ListAsync.05") + MessageExceptions.Describe(ex).Limit(2048)
                });
            }
        }
        RequireSameSid(sid);
        RelatedArtifactReader.ValidatePath(rootLease, _root);
        return summaries.OrderByDescending(s => s.UpdatedAtUtc).ToArray();
    }

    internal static void ValidateRecord(RemediationCaseRecord record, string sid)
    {
        ValidateSid(sid);
        if (record.SchemaVersion != 1 || record.CaseId == Guid.Empty || record.UserSid != sid || record.Revision < 0 ||
            record.CreatedAtUtc == default || record.UpdatedAtUtc == default || !Enum.IsDefined(record.SessionRequirement))
            throw MessageExceptions.Create(MessageText.Create("Backend.Core.RemediationCaseStore.ValidateRecord.01"), sourceText => new InvalidDataException(sourceText));
        if (record.Plans is null || record.ExecutionResults is null || record.PendingPlanIds is null || record.Episodes is null || record.Notes is null ||
            record.Plans.Count > MaximumPlans || record.ExecutionResults.Count > MaximumPlans || record.PendingPlanIds.Count > MaximumPlans ||
            record.Episodes.Count > MaximumEpisodes || record.Notes.Count > 2048 || record.Notes.Any(n => n is null || n.Length > 8192))
            throw MessageExceptions.Create(MessageText.Create("Backend.Core.RemediationCaseStore.ValidateRecord.02"), sourceText => new InvalidDataException(sourceText));
        if (record.Plans.Any(p => p is null) || record.ExecutionResults.Any(r => r is null) || record.Episodes.Any(e => e is null) ||
            record.BatchSession is { } supplied && (supplied.Plans is null || supplied.Results is null || supplied.Targets is null ||
                supplied.Plans.Any(p => p is null) || supplied.Results.Any(r => r is null) || supplied.Targets.Any(t => t is null || t.MissingActions is null || t.ActionIds is null)))
            throw MessageExceptions.Create(MessageText.Create("Backend.Core.RemediationCaseStore.ValidateRecord.03"), sourceText => new InvalidDataException(sourceText));
        RemediationPlan[] plans = AllPlans(record);
        if (plans.Length > MaximumPlans || plans.Sum(p => (long)(p.Actions?.Count ?? MaximumActions + 1)) > MaximumActions)
            throw MessageExceptions.Create(MessageText.Create("Backend.Core.RemediationCaseStore.ValidateRecord.04"), sourceText => new InvalidDataException(sourceText));
        HashSet<Guid> planIds = [], actionIds = [];
        foreach (RemediationPlan plan in plans)
        {
            if (plan.PlanId == Guid.Empty || !planIds.Add(plan.PlanId) || plan.RequestedBySid != sid || plan.Actions is null || plan.Actions.Count > 64)
                throw MessageExceptions.Create(MessageText.Create("Backend.Core.RemediationCaseStore.ValidateRecord.05"), sourceText => new InvalidDataException(sourceText));
            foreach (RemediationAction action in plan.Actions)
                if (action is null || action.ActionId == Guid.Empty || !actionIds.Add(action.ActionId) || !Enum.IsDefined(action.Type) ||
                    action.Target is null || action.Target.Length > 32768 || action.DisplayName is null || action.DisplayName.Length > 8192 ||
                    action.Domains is null || action.Domains.Count > 256 || action.Domains.Any(d => d is null || d.Length > 2048) ||
                    action.DependsOnActionIds is null || action.DependsOnActionIds.Count > 64)
                    throw MessageExceptions.Create(MessageText.Create("Backend.Core.RemediationCaseStore.ValidateRecord.06"), sourceText => new InvalidDataException(sourceText));
        }
        if (record.PendingPlanIds.Any(id => !planIds.Contains(id)) || record.PendingPlanIds.Distinct().Count() != record.PendingPlanIds.Count)
            throw MessageExceptions.Create(MessageText.Create("Backend.Core.RemediationCaseStore.ValidateRecord.07"), sourceText => new InvalidDataException(sourceText));
        RemediationRunResult[] results = AllResults(record);
        if (results.Length > MaximumPlans || results.Any(r => r.Actions is null || r.Actions.Count > 64 || r.Actions.Any(a => a is null) ||
            r.Errors is null || r.Errors.Count > 256 || r.Errors.Any(e => e is null) || !Enum.IsDefined(r.Disposition) || !Enum.IsDefined(r.VerificationStatus)))
            throw MessageExceptions.Create(MessageText.Create("Backend.Core.RemediationCaseStore.ValidateRecord.08"), sourceText => new InvalidDataException(sourceText));
        foreach (RemediationRunResult result in results)
        {
            RemediationPlan? plan = plans.FirstOrDefault(p => p.PlanId == result.PlanId);
            if (plan is null || result.Actions.Select(a => a.ActionId).Distinct().Count() != result.Actions.Count ||
                result.Actions.Any(a => !Enum.IsDefined(a.ExecutionStatus) || !Enum.IsDefined(a.VerificationStatus) || a.Verifications is null ||
                    a.Verifications.Count > 256 || a.Verifications.Any(v => v is null || !Enum.IsDefined(v.Status)) ||
                    !plan.Actions.Any(p => p.ActionId == a.ActionId && p.Type == a.Type && p.Target == a.Target)))
                throw MessageExceptions.Create(MessageText.Create("Backend.Core.RemediationCaseStore.ValidateRecord.09"), sourceText => new InvalidDataException(sourceText));
        }
        if (record.BaselineSession is { } baseline && baseline.UserSid != sid) throw MessageExceptions.Create(MessageText.Create("Backend.Core.RemediationCaseStore.ValidateRecord.10"), sourceText => new InvalidDataException(sourceText));
        if (record.Episodes.Select(e => e.EpisodeId).Distinct().Count() != record.Episodes.Count) throw MessageExceptions.Create(MessageText.Create("Backend.Core.RemediationCaseStore.ValidateRecord.11"), sourceText => new InvalidDataException(sourceText));
        foreach (CaseVerificationEpisode episode in record.Episodes)
        {
            if (episode is null || episode.EpisodeId == Guid.Empty || episode.Targets is null || episode.Checks is null || episode.Targets.Count > 256 ||
                episode.Checks.Count > 2048 || !Enum.IsDefined(episode.State) || !Enum.IsDefined(episode.Transition) ||
                episode.Session is { } session && session.UserSid != sid && episode.State != CaseReverificationState.SessionUnknown)
                throw MessageExceptions.Create(MessageText.Create("Backend.Core.RemediationCaseStore.ValidateRecord.12"), sourceText => new InvalidDataException(sourceText));
            if (episode.Checks.Any(c => c is null || !Enum.IsDefined(c.Status)) ||
                episode.Targets.Any(t => t is null || !Enum.IsDefined(t.Status) || !planIds.Contains(t.PlanId) || !actionIds.Contains(t.ActionId) ||
                !plans.Any(p => p.PlanId == t.PlanId && p.Actions.Any(a => a.ActionId == t.ActionId && a.Type == t.Type && a.Target == t.Target))))
                throw MessageExceptions.Create(MessageText.Create("Backend.Core.RemediationCaseStore.ValidateRecord.13"), sourceText => new InvalidDataException(sourceText));
        }
        CaseMessageValidation.Validate(record, record.Plans.Concat(record.BatchSession?.Plans ?? []),
            record.ExecutionResults.Concat(record.BatchSession?.Results ?? []));
    }

    internal static RemediationPlan[] AllPlans(RemediationCaseRecord record)
    {
        if (record.BatchSession is { } batch && (batch.Plans is null || batch.Plans.Count > MaximumPlans || batch.Results is null || batch.Results.Count > MaximumPlans))
            throw MessageExceptions.Create(MessageText.Create("Backend.Core.RemediationCaseStore.AllPlans.01"), sourceText => new InvalidDataException(sourceText));
        return record.Plans.Concat(record.BatchSession?.Plans ?? []).GroupBy(p => p.PlanId).Select(g =>
        {
            RemediationPlan first = g.First();
            if (g.Skip(1).Any(p => JsonSerializer.Serialize(p, SnapshotComparison) != JsonSerializer.Serialize(first, SnapshotComparison)))
                throw MessageExceptions.Create(MessageText.Create("Backend.Core.RemediationCaseStore.AllPlans.02"), sourceText => new InvalidDataException(sourceText));
            return first;
        }).ToArray();
    }

    internal static RemediationRunResult[] AllResults(RemediationCaseRecord record) =>
        record.ExecutionResults.Concat(record.BatchSession?.Results ?? []).GroupBy(r => r.PlanId).Select(g =>
        {
            RemediationRunResult first = g.First();
            if (g.Skip(1).Any(r => JsonSerializer.Serialize(r, SnapshotComparison) != JsonSerializer.Serialize(first, SnapshotComparison)))
                throw MessageExceptions.Create(MessageText.Create("Backend.Core.RemediationCaseStore.AllResults.01"), sourceText => new InvalidDataException(sourceText));
            return first;
        }).ToArray();

    private async Task<RemediationCaseRecord?> ReadRecordAsync(string path, CancellationToken token)
    {
        CheckPath(path);
        FileStream stream;
        try { stream = RelatedArtifactReader.Open(path); }
        catch (Win32Exception ex) when (ex.NativeErrorCode is 2 or 3) { return null; }
        await using (stream)
        {
            if (stream.Length is <= 0 or > MaximumCaseBytes) throw MessageExceptions.Create(MessageText.Create("Backend.Core.RemediationCaseStore.ReadRecordAsync.01"), sourceText => new InvalidDataException(sourceText));
            return await JsonFile.ReadAsync<RemediationCaseRecord>(stream, MessageText.Create("Backend.Core.RemediationCaseStore.ReadRecordAsync.02"), token).ConfigureAwait(false);
        }
    }

    private static RemediationCaseSummary Summary(RemediationCaseRecord record) => new()
    {
        CaseId = record.CaseId,
        UserSid = record.UserSid,
        Revision = record.Revision,
        UpdatedAtUtc = record.UpdatedAtUtc,
        PendingExecutionCount = record.PendingPlanIds.Count,
        EpisodeCount = record.Episodes.Count,
        State = record.PendingPlanIds.Count > 0 || record.BatchSession is { ExecutionStarted: true, ExecutionFinished: false } ||
            AllResults(record).Any(r => r.Disposition == RemediationRunDisposition.ExecutionUnknown ||
                r.CompletedAtUtc is null && r.Disposition != RemediationRunDisposition.NotStarted ||
                r.Actions.Any(a => a.ExecutionStatus == RemediationExecutionStatus.ExecutionUnknown))
            ? CaseReverificationState.ExecutionUncertain : record.Episodes.LastOrDefault()?.State ?? CaseReverificationState.NotChecked,
        DetailText = record.Episodes.LastOrDefault()?.SummaryText ?? MessageText.Create("Backend.Core.RemediationCaseStore.Summary.01")
    };

    private string CaseDirectory(Guid id) => id == Guid.Empty ? throw MessageExceptions.Create(MessageText.Create("Backend.Core.RemediationCaseStore.CaseDirectory.01"), sourceText => new ArgumentException(sourceText, nameof(id))) : Path.Combine(_root, id.ToString("N"));
    private static bool IsCaseDirectory(string path) => Guid.TryParseExact(Path.GetFileName(path), "N", out Guid id) && id != Guid.Empty;
    private void RequireSameSid(string sid) { if (_currentUserSid() != sid) throw MessageExceptions.Create(MessageText.Create("Backend.Core.RemediationCaseStore.RequireSameSid.01"), sourceText => new UnauthorizedAccessException(sourceText)); }
    private static string CurrentUserSid() { using WindowsIdentity identity = WindowsIdentity.GetCurrent(); return identity.User?.Value ?? string.Empty; }
    private static void ValidateSid(string sid)
    {
        if (string.IsNullOrWhiteSpace(sid) || sid.Length > 184) throw MessageExceptions.Create(MessageText.Create("Backend.Core.RemediationCaseStore.ValidateSid.01"), sourceText => new InvalidDataException(sourceText));
        try { _ = new SecurityIdentifier(sid); } catch (ArgumentException ex) { throw MessageExceptions.Create(MessageText.Create("Backend.Core.RemediationCaseStore.ValidateSid.02"), sourceText => new InvalidDataException(sourceText, ex)); }
    }

    private static void CheckPath(string path)
    {
        if (!ContentDiscovery.IsLocalSafePath(path)) throw MessageExceptions.Create(MessageText.Create("Backend.Core.RemediationCaseStore.CheckPath.01"), sourceText => new UnauthorizedAccessException(sourceText));
        string full = Path.GetFullPath(path), current = Path.GetPathRoot(full)!;
        foreach (string part in full[current.Length..].Split(Path.DirectorySeparatorChar, StringSplitOptions.RemoveEmptyEntries))
        {
            current = Path.Combine(current, part);
            try { if ((File.GetAttributes(current) & FileAttributes.ReparsePoint) != 0) throw MessageExceptions.Create(MessageText.Create("Backend.Core.RemediationCaseStore.CheckPath.02"), sourceText => new UnauthorizedAccessException(sourceText)); }
            catch (FileNotFoundException) { }
            catch (DirectoryNotFoundException) { }
        }
    }

    private static SafeFileHandle OpenDirectory(string directory)
    {
        CheckPath(directory);
        SafeFileHandle handle = CreateFile(directory, 0x80, 3, IntPtr.Zero, 3, 0x02200000, IntPtr.Zero);
        if (handle.IsInvalid) { int error = Marshal.GetLastWin32Error(); handle.Dispose(); throw MessageExceptions.Create(MessageText.Create("Backend.Core.RemediationCaseStore.OpenDirectory.01"), sourceText => new Win32Exception(error, sourceText)); }
        try { RelatedArtifactReader.ValidatePath(handle, directory); return handle; }
        catch { handle.Dispose(); throw; }
    }

    private static FileStream OpenWriteLock(string path)
    {
        SafeFileHandle handle = CreateFile(path, 0xC0000000, 0, IntPtr.Zero, 4, 0x00200000, IntPtr.Zero);
        if (handle.IsInvalid) { int error = Marshal.GetLastWin32Error(); handle.Dispose(); throw MessageExceptions.Create(MessageText.Create("Backend.Core.RemediationCaseStore.OpenWriteLock.01"), sourceText => new Win32Exception(error, sourceText)); }
        try { RelatedArtifactReader.ValidatePath(handle, path); return new FileStream(handle, FileAccess.ReadWrite); }
        catch { handle.Dispose(); throw; }
    }

    private void ValidateDirectoryLeases(SafeFileHandle root, SafeFileHandle directory, string path)
    { RelatedArtifactReader.ValidatePath(root, _root); RelatedArtifactReader.ValidatePath(directory, path); CheckPath(path); }

    [DllImport("kernel32.dll", EntryPoint = "CreateFileW", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern SafeFileHandle CreateFile(string path, uint access, uint share, IntPtr security, uint disposition, uint flags, IntPtr template);

    private sealed class CappedWriteStream(Stream inner, long maximum) : Stream
    {
        private long _written;
        public override bool CanRead => false;
        public override bool CanSeek => false;
        public override bool CanWrite => true;
        public override long Length => inner.Length;
        public override long Position { get => inner.Position; set => throw new NotSupportedException(); }
        private void Charge(int count) { if (count < 0 || count > maximum - _written) throw MessageExceptions.Create(MessageText.Create("Backend.Core.RemediationCaseStore.Charge.01"), sourceText => new InvalidDataException(sourceText)); _written += count; }
        public override void Write(byte[] buffer, int offset, int count) { Charge(count); inner.Write(buffer, offset, count); }
        public override void Write(ReadOnlySpan<byte> buffer) { Charge(buffer.Length); inner.Write(buffer); }
        public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken token) { Charge(count); return inner.WriteAsync(buffer, offset, count, token); }
        public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken token = default) { Charge(buffer.Length); return inner.WriteAsync(buffer, token); }
        public override void Flush() => inner.Flush();
        public override Task FlushAsync(CancellationToken token) => inner.FlushAsync(token);
        public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
    }
}
