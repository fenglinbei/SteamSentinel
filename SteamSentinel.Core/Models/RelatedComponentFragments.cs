namespace SteamSentinel.Core.Models;

public sealed record RelatedComponentCounts(int Sources, int Hosts, int Candidates, int Checks, int Relations, int Rounds);
public sealed record RelatedComponentLimitSnapshot(int MaximumRounds, int MaximumSources, int MaximumProcesses,
    int MaximumHosts, int MaximumModulesPerHost, int MaximumCandidates, int MaximumScriptBytes,
    long MaximumTotalScriptBytes, long MaximumFileBytes, long MaximumTotalBytes,
    TimeSpan MaximumDiscoveryDuration, TimeSpan MaximumDuration)
{
    internal static RelatedComponentLimitSnapshot? From(RelatedComponentLimits? value) => value is null ? null : new(
        value.MaximumRounds, value.MaximumSources, value.MaximumProcesses, value.MaximumHosts, value.MaximumModulesPerHost,
        value.MaximumCandidates, value.MaximumScriptBytes, value.MaximumTotalScriptBytes, value.MaximumFileBytes,
        value.MaximumTotalBytes, value.MaximumDiscoveryDuration, value.MaximumDuration);
    internal RelatedComponentLimits ToLimits() => new()
    {
        MaximumRounds = MaximumRounds,
        MaximumSources = MaximumSources,
        MaximumProcesses = MaximumProcesses,
        MaximumHosts = MaximumHosts,
        MaximumModulesPerHost = MaximumModulesPerHost,
        MaximumCandidates = MaximumCandidates,
        MaximumScriptBytes = MaximumScriptBytes,
        MaximumTotalScriptBytes = MaximumTotalScriptBytes,
        MaximumFileBytes = MaximumFileBytes,
        MaximumTotalBytes = MaximumTotalBytes,
        MaximumDiscoveryDuration = MaximumDiscoveryDuration,
        MaximumDuration = MaximumDuration
    };
}
public sealed record RelatedComponentMetadata(int SchemaVersion, DateTimeOffset StartedAtUtc, DateTimeOffset? CompletedAtUtc,
    string TargetUserSid, RelatedComponentLimitSnapshot? AppliedLimits, RelatedComponentCounts Counts);

/// <summary>One bounded observation per fragment; this transport adds no remediation authority.</summary>
public sealed record RelatedComponentFragment(RelatedComponentMetadata Metadata, RelatedComponentCounts Offsets, bool IsFinal)
{
    public RelatedSourceObservation? Source { get; init; }
    public RelatedHostObservation? Host { get; init; }
    public RelatedComponentCandidate? Candidate { get; init; }
    public DiagnosticCheck? Check { get; init; }
    public DiagnosticRelation? Relation { get; init; }
    public RelatedScanRound? Round { get; init; }
}

internal static class RelatedComponentFragments
{
    internal const int MaximumSources = 512, MaximumHosts = 32, MaximumCandidates = 128;
    internal const int MaximumChecks = 2048, MaximumRelations = 4096, MaximumRounds = 2;
    internal const int MaximumRecordCharacters = 96 * 1024;
    internal const long MaximumTextCharacters = 16L * 1024 * 1024;

    internal static IReadOnlyList<RelatedComponentFragment> Create(RelatedComponentDiagnosticReport source)
    {
        if (source.Sources is null || source.Hosts is null || source.Candidates is null || source.Checks is null || source.Relations is null || source.Rounds is null)
            throw Invalid("诊断集合缺失。");
        RelatedComponentMetadata metadata = new(source.SchemaVersion, source.StartedAtUtc, source.CompletedAtUtc,
            source.TargetUserSid, RelatedComponentLimitSnapshot.From(source.AppliedLimits), Counts(source));
        ValidateMetadata(metadata);
        List<RelatedComponentFragment> fragments = [];
        RelatedComponentCounts offsets = new(0, 0, 0, 0, 0, 0);
        foreach (RelatedSourceObservation value in source.Sources)
        { Require(value); fragments.Add(new(metadata, offsets, false) { Source = value }); offsets = offsets with { Sources = offsets.Sources + 1 }; }
        foreach (RelatedHostObservation value in source.Hosts)
        { Require(value); fragments.Add(new(metadata, offsets, false) { Host = value }); offsets = offsets with { Hosts = offsets.Hosts + 1 }; }
        foreach (RelatedComponentCandidate value in source.Candidates)
        { Require(value); fragments.Add(new(metadata, offsets, false) { Candidate = value }); offsets = offsets with { Candidates = offsets.Candidates + 1 }; }
        foreach (DiagnosticCheck value in source.Checks)
        { Require(value); fragments.Add(new(metadata, offsets, false) { Check = value }); offsets = offsets with { Checks = offsets.Checks + 1 }; }
        foreach (DiagnosticRelation value in source.Relations)
        { Require(value); fragments.Add(new(metadata, offsets, false) { Relation = value }); offsets = offsets with { Relations = offsets.Relations + 1 }; }
        foreach (RelatedScanRound value in source.Rounds)
        { Require(value); fragments.Add(new(metadata, offsets, false) { Round = value }); offsets = offsets with { Rounds = offsets.Rounds + 1 }; }
        if (fragments.Count == 0) fragments.Add(new(metadata, offsets, true));
        else fragments[^1] = fragments[^1] with { IsFinal = true };
        RelatedComponentAssembly validation = new();
        foreach (RelatedComponentFragment fragment in fragments) validation.Commit(validation.Prepare(fragment));
        return fragments;
    }

    internal static RelatedComponentCounts Counts(RelatedComponentDiagnosticReport? value) => value is null ? new(0, 0, 0, 0, 0, 0) :
        new(value.Sources.Count, value.Hosts.Count, value.Candidates.Count, value.Checks.Count, value.Relations.Count, value.Rounds.Count);
    internal static void ValidateMetadata(RelatedComponentMetadata metadata)
    {
        if (metadata is null || metadata.Counts is null || metadata.SchemaVersion != 1 || metadata.StartedAtUtc == default || metadata.CompletedAtUtc < metadata.StartedAtUtc)
            throw Invalid("元数据版本或时间无效。");
        TrustProxyDiagnosticFragments.ValidateSid(metadata.TargetUserSid, allowEmpty: true);
        RelatedComponentCounts c = metadata.Counts;
        if (c.Sources is < 0 or > MaximumSources || c.Hosts is < 0 or > MaximumHosts || c.Candidates is < 0 or > MaximumCandidates ||
            c.Checks is < 0 or > MaximumChecks || c.Relations is < 0 or > MaximumRelations || c.Rounds is < 0 or > MaximumRounds)
            throw Invalid("诊断声明数量超限。");
        if (metadata.AppliedLimits is { } l && (l.MaximumRounds is < 0 or > MaximumRounds || l.MaximumSources is < 0 or > MaximumSources ||
            l.MaximumHosts is < 0 or > MaximumHosts || l.MaximumCandidates is < 0 or > MaximumCandidates || l.MaximumProcesses < 0 ||
            l.MaximumModulesPerHost < 0 || l.MaximumScriptBytes < 0 || l.MaximumTotalScriptBytes < 0 || l.MaximumFileBytes < 0 ||
            l.MaximumTotalBytes < 0 || l.MaximumDiscoveryDuration < TimeSpan.Zero || l.MaximumDuration < TimeSpan.Zero ||
            c.Sources > l.MaximumSources || c.Hosts > l.MaximumHosts || c.Candidates > l.MaximumCandidates || c.Rounds > l.MaximumRounds))
            throw Invalid("应用限额无效或记录超过应用限额。");
    }
    private static void Require(object? value) { if (value is null) throw Invalid("诊断记录为空。"); }
    internal static InvalidDataException Invalid(string reason) => new("组件关联分片被拒绝：" + reason);
}

/// <summary>Prepare validates without mutation; ReportBatchReader commits all states together.</summary>
internal sealed class RelatedComponentAssembly
{
    private RelatedComponentMetadata? _metadata;
    private readonly Dictionary<string, string> _ids = new(StringComparer.Ordinal);
    private long _textCharacters;
    internal RelatedComponentDiagnosticReport? Report { get; private set; }
    internal bool IsComplete { get; private set; }

    internal PreparedRelatedComponentFragment Prepare(RelatedComponentFragment fragment)
    {
        if (fragment is null || fragment.Offsets is null || IsComplete) throw RelatedComponentFragments.Invalid("分片结构缺失或诊断已经完成。");
        RelatedComponentFragments.ValidateMetadata(fragment.Metadata);
        if (_metadata is not null && _metadata != fragment.Metadata) throw RelatedComponentFragments.Invalid("跨片元数据、身份或限额发生变化。");
        RelatedComponentCounts offsets = RelatedComponentFragments.Counts(Report), totals = fragment.Metadata.Counts;
        if (fragment.Offsets != offsets) throw RelatedComponentFragments.Invalid("分片偏移不连续。");
        int number = (fragment.Source is null ? 0 : 1) + (fragment.Host is null ? 0 : 1) + (fragment.Candidate is null ? 0 : 1) +
            (fragment.Check is null ? 0 : 1) + (fragment.Relation is null ? 0 : 1) + (fragment.Round is null ? 0 : 1);
        RelatedComponentCounts next = new(offsets.Sources + (fragment.Source is null ? 0 : 1), offsets.Hosts + (fragment.Host is null ? 0 : 1),
            offsets.Candidates + (fragment.Candidate is null ? 0 : 1), offsets.Checks + (fragment.Check is null ? 0 : 1),
            offsets.Relations + (fragment.Relation is null ? 0 : 1), offsets.Rounds + (fragment.Round is null ? 0 : 1));
        if (number > 1 || next.Sources > totals.Sources || next.Hosts > totals.Hosts || next.Candidates > totals.Candidates ||
            next.Checks > totals.Checks || next.Relations > totals.Relations || next.Rounds > totals.Rounds ||
            fragment.IsFinal != (next == totals) || number == 0 && (Report is not null || next != totals))
            throw RelatedComponentFragments.Invalid("单片记录或结束标记与总数量不一致。");

        long text = 0;
        string? addedId = null, addedKind = null;
        void Field(string? value, int maximum, bool required = false, bool allowNull = false)
        {
            if (value is null) { if (!allowNull) throw RelatedComponentFragments.Invalid("必需文本缺失。"); return; }
            if (value.Length > maximum || required && string.IsNullOrWhiteSpace(value)) throw RelatedComponentFragments.Invalid("记录字段缺失或超长。");
            text += value.Length;
        }
        void Id(string id, string kind)
        {
            Field(id, 128, true);
            if (_ids.ContainsKey(id)) throw RelatedComponentFragments.Invalid("观察 ID 重复。");
            addedId = id; addedKind = kind;
        }
        void Reference(string id, string? kind = null)
        {
            Field(id, 128, true);
            if (kind is null ? !_ids.ContainsKey(id) : !_ids.TryGetValue(id, out string? actual) || actual != kind)
                throw RelatedComponentFragments.Invalid("引用不存在或不是对应类型的真实观察。");
        }
        void References(List<string> values, int maximum, string? kind = null)
        {
            if (values is null || values.Count > maximum || values.Distinct(StringComparer.Ordinal).Count() != values.Count)
                throw RelatedComponentFragments.Invalid("引用列表缺失、重复或数量超限。");
            foreach (string id in values) Reference(id, kind);
        }
        void Status(DiagnosticReadStatus status) { if (!Enum.IsDefined(status)) throw RelatedComponentFragments.Invalid("读取状态无效。"); }
        void Hash(string? hash) { Field(hash, 64, allowNull: true); if (hash is not null && (hash.Length != 64 || hash.Any(c => !Uri.IsHexDigit(c)))) throw RelatedComponentFragments.Invalid("SHA-256 格式无效。"); }
        if (fragment.Source is { } source)
        {
            Id(source.Id, "source"); Field(source.Kind, 128, true); Field(source.Scope, 128, true); Field(source.Location, 32768);
            Field(source.RawCommand, 65536); Field(source.WorkingDirectory, 32768, allowNull: true); Field(source.UserSid, 512, allowNull: true); Field(source.Detail, 8192); Status(source.Status);
            if (source.Scope.Equals("CurrentUser", StringComparison.OrdinalIgnoreCase) && (source.UserSid != fragment.Metadata.TargetUserSid || string.IsNullOrEmpty(source.UserSid)))
                throw RelatedComponentFragments.Invalid("当前用户来源与目标 SID 不匹配。");
            if (source.ResolvedTargets is null || source.ResolvedTargets.Count > 128) throw RelatedComponentFragments.Invalid("来源目标列表缺失或超限。");
            foreach (string path in source.ResolvedTargets) Field(path, 32768, true);
        }
        if (fragment.Host is { } host)
        {
            Id(host.Id, "host"); if (host.ProcessId <= 0) throw RelatedComponentFragments.Invalid("宿主 PID 无效。");
            Field(host.ImagePath, 32768); Field(host.CommandLine, 65536, allowNull: true); Field(host.WorkingDirectory, 32768, allowNull: true); Hash(host.ImageSha256);
            Field(host.SignatureStatus, 128, true); Field(host.SignatureDetail, 8192); Field(host.Detail, 8192); Status(host.Status);
            References(host.SourceObservationIds, RelatedComponentFragments.MaximumSources, "source");
        }
        if (fragment.Candidate is { } candidate)
        {
            Id(candidate.Id, "candidate"); Field(candidate.Path, 32768, true); Field(candidate.Reason, 8192); Field(candidate.Detail, 8192);
            Field(candidate.ContentDetail, 8192); Hash(candidate.Sha256); Status(candidate.Status); Status(candidate.ContentStatus);
            if (candidate.Length < 0) throw RelatedComponentFragments.Invalid("候选文件长度无效。");
            References(candidate.SourceObservationIds, RelatedComponentFragments.MaximumSources, "source");
            References(candidate.HostObservationIds, RelatedComponentFragments.MaximumHosts, "host");
            References(candidate.EvidenceObservationIds, 256);
        }
        if (fragment.Check is { } check)
        {
            Id(check.Id, "check"); Field(check.Name, 512, true); Field(check.Detail, 8192); Status(check.Status);
            if (check.ObservationId is not null) Reference(check.ObservationId);
        }
        if (fragment.Relation is { } relation)
        { Reference(relation.FromId); Reference(relation.ToId); Field(relation.Kind, 128, true); Field(relation.Evidence, 8192); }
        if (fragment.Round is { } round)
        {
            if (round.Number != offsets.Rounds + 1 || round.StartedAtUtc == default || round.CompletedAtUtc < round.StartedAtUtc || round.BytesRead < 0 || round.MaximumBytes < 0)
                throw RelatedComponentFragments.Invalid("关联轮次或字节/时间值无效。");
            Field(round.Detail, 8192); Status(round.Status); References(round.CandidateIds, RelatedComponentFragments.MaximumCandidates, "candidate");
        }
        if (text > RelatedComponentFragments.MaximumRecordCharacters || _textCharacters + text > RelatedComponentFragments.MaximumTextCharacters)
            throw RelatedComponentFragments.Invalid("单记录或累计文本预算超限。");
        return new(fragment, addedId, addedKind, text);
    }

    internal void Commit(PreparedRelatedComponentFragment prepared)
    {
        RelatedComponentFragment fragment = prepared.Fragment;
        _metadata ??= fragment.Metadata;
        Report ??= new()
        {
            SchemaVersion = fragment.Metadata.SchemaVersion,
            StartedAtUtc = fragment.Metadata.StartedAtUtc,
            TargetUserSid = fragment.Metadata.TargetUserSid,
            AppliedLimits = fragment.Metadata.AppliedLimits?.ToLimits()
        };
        if (fragment.Source is { } source) Report.Sources.Add(source);
        if (fragment.Host is { } host) Report.Hosts.Add(host);
        if (fragment.Candidate is { } candidate) Report.Candidates.Add(candidate);
        if (fragment.Check is { } check) Report.Checks.Add(check);
        if (fragment.Relation is { } relation) Report.Relations.Add(relation);
        if (fragment.Round is { } round) Report.Rounds.Add(round);
        if (prepared.Id is not null) _ids.Add(prepared.Id, prepared.Kind!);
        _textCharacters += prepared.TextCharacters;
        IsComplete = fragment.IsFinal;
        Report.CompletedAtUtc = IsComplete ? fragment.Metadata.CompletedAtUtc : null;
    }
}
internal sealed record PreparedRelatedComponentFragment(RelatedComponentFragment Fragment, string? Id, string? Kind, long TextCharacters);
