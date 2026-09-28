using System.Diagnostics;
using SteamSentinel.Core.Models;

namespace SteamSentinel.Core.Scanning;

/// <summary>One bounded decision channel per scan; only typed budget keys can authorize changes.</summary>
public sealed class ScanResourceSession : IDisposable
{
    private static readonly AsyncLocal<ScanResourceSession?> Active = new();
    private static readonly AsyncLocal<string?> TargetPath = new();
    private readonly ScanResourceSession? _previous;
    private readonly Func<ScanLimitRequest, ScanLimitResponse> _decide;
    private readonly CancellationToken _token;
    private readonly object _gate = new();
    private readonly HashSet<(string Key, string Target)> _declined = [];
    private ScanReport? _report;
    private Func<ContainerResourceSnapshot>? _resources;
    public ScanOptions Options { get; }
    public ScanResourceAudit Audit { get; } = new();
    public long WaitingMilliseconds => Audit.WaitingMilliseconds;
    public bool RaisedResources { get; private set; }
    public static ScanResourceSession? Current => Active.Value;
    public static IDisposable Suppress() => new SuppressionScope();
    private sealed class SuppressionScope : IDisposable
    {
        private readonly ScanResourceSession? _saved = Active.Value;
        public SuppressionScope() => Active.Value = null;
        public void Dispose() => Active.Value = _saved;
    }

    public ScanResourceSession(ScanOptions options, Func<ScanLimitRequest, ScanLimitResponse> decide, CancellationToken token)
    {
        Options = options; _decide = decide; _token = token;
        _previous = Active.Value; Active.Value = this;
    }
    public void Bind(ScanReport report) { _report = report; report.ResourceAudit = Audit; }
    public void ObserveResources(Func<ContainerResourceSnapshot> resources) => _resources = resources;
    public static IDisposable EnterTarget(string path) => new TargetScope(path);
    private sealed class TargetScope : IDisposable
    {
        private readonly string? _previous = TargetPath.Value;
        public TargetScope(string path) => TargetPath.Value = path.Length > 2048 ? path[..2048] : path;
        public void Dispose() => TargetPath.Value = _previous;
    }
    public static bool Allow(string key, long required, long used = 0, bool known = true) =>
        Current?.TryIncrease(key, required, used, known) == true;

    public bool TryIncrease(string key, long required, long used, bool known)
    {
        lock (_gate)
        {
            _token.ThrowIfCancellationRequested();
            long current = ScanLimitAccess.Get(Options, key);
            if (required <= current) return true;
            string target = TargetPath.Value ?? string.Empty;
            string declineScope = IsPerItem(key) ? target : string.Empty;
            if (Audit.Decisions.Count >= ScanResourceAudit.MaximumDecisions || _declined.Contains((key, declineScope))) return false;
            using Process process = Process.GetCurrentProcess();
            ContainerResourceSnapshot? resources = _resources?.Invoke() ?? _report?.Containers?.Resources;
            ScanLimitRequest request = new(Guid.NewGuid().ToString("N"), key, current, required, Math.Max(0, used), known,
                target, process.PrivateMemorySize64, resources?.CurrentTemporaryBytes ?? 0,
                checked((resources?.ReadBytes ?? 0) + (resources?.DecodedBytes ?? 0) +
                    (resources?.NativeReservedReadBytes ?? 0) + (resources?.NativeReservedDecodedBytes ?? 0)), resources?.AcceptedExpandedBytes ?? 0);
            request.Validate();
            Audit.Phase = ScanResourcePhase.AwaitingDecision;
            Stopwatch waiting = Stopwatch.StartNew();
            ScanLimitResponse response;
            try { response = _decide(request); }
            finally
            {
                Audit.WaitingMilliseconds = checked(Audit.WaitingMilliseconds + waiting.ElapsedMilliseconds);
                Audit.Phase = ScanResourcePhase.Running;
            }
            if (response.RequestId != request.RequestId || !Enum.IsDefined(response.Decision) || !ResourceDecisionReasons.IsValid(response.ReasonCode) || response.Changes is null ||
                response.Decision != ResourceDecisionKind.Approve && response.Changes.Count != 0)
                throw new InvalidDataException("Invalid resource response.");
            if (response.Decision == ResourceDecisionKind.Approve)
            {
                if (!response.Changes.Any(c => c.LimitKey == key && c.After >= required))
                    throw new InvalidDataException("Resource grant does not cover the blocked operation.");
                ScanLimitAccess.Apply(Options, response.Changes);
                RaisedResources = true;
            }
            Audit.Decisions.Add(new(request, response.Decision, [.. response.Changes], DateTimeOffset.UtcNow, response.ReasonCode ?? ResourceDecisionReasons.For(response.Decision)));
            if (response.Decision == ResourceDecisionKind.Stop) throw new OperationCanceledException(_token);
            if (response.Decision == ResourceDecisionKind.Skip) _declined.Add((key, declineScope));
            return response.Decision == ResourceDecisionKind.Approve;
        }
    }
    private static bool IsPerItem(string key) => key.StartsWith("RangeLimits.", StringComparison.Ordinal) || key is
        "MaximumQuickFileBytes" or "MaximumStringScanBytes" or "MaximumAmsiBytes" or "MaximumStructureDurationSeconds" or
        "ContainerLimits.MaximumEntryBytes" or "ContainerLimits.MaximumDepth" or "ContainerLimits.MaximumCompressionRatio";
    public void Dispose() { Audit.Phase = ScanResourcePhase.Finished; Active.Value = _previous; }
}
