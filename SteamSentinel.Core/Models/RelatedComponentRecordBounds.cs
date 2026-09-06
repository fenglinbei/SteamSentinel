namespace SteamSentinel.Core.Models;

/// <summary>Bounds derived path lists while retaining the source's original command and identity.</summary>
internal static class RelatedComponentRecordBounds
{
    internal const int MaximumSourceTargets = 128;
    internal const int MaximumDetailCharacters = 8192;
    internal const string SourceTargetLimitDetail = "来源目标列表达到 128 项、路径长度或记录文本上限；原始命令已保留，超出目标未纳入，关联检查未完成。";
    internal const string OriginalSourceLimitDetail = "原始来源超过记录限额，未完整纳入/未解析；原始命令与工作目录未纳入，未据此解析或增加候选。来源位置或类型过长时仅保留有界标识片段。";
    internal const string SourceDetailLimitDetail = "来源解析说明超过记录限额，部分说明未纳入；原始命令保持不变。";

    internal static RelatedSourceObservation PrepareOriginal(RelatedSourceObservation source, out bool omitted, string? targetUserSid = null)
    {
        omitted = !Fits(source);
        if (!omitted) return source;
        string scope = Bounded(source.Scope, 128, "Unknown");
        string? sid = source.UserSid is { Length: <= 512 } ? source.UserSid : null;
        // A missing or oversized identity cannot continue to claim a CurrentUser binding.
        if (scope.Equals("CurrentUser", StringComparison.OrdinalIgnoreCase) &&
            (string.IsNullOrWhiteSpace(sid) || targetUserSid is not null && sid != targetUserSid)) scope = "UnverifiedSource";
        return new()
        {
            Id = Bounded(source.Id, 128, Guid.NewGuid().ToString("N")),
            Kind = Bounded(source.Kind, 128, "Unknown"),
            Scope = scope,
            Location = Bounded(source.Location, 32768, "<来源位置未取得>"),
            UserSid = sid,
            RawCommand = "",
            WorkingDirectory = null,
            Status = DiagnosticReadStatus.LimitReached,
            Detail = OriginalSourceLimitDetail
        };
    }

    internal static bool TryAppendDetail(RelatedSourceObservation source, string detail)
    {
        int maximum = DetailCapacity(source);
        if ((long)source.Detail.Length + detail.Length + 1 <= maximum) { source.Detail += " " + detail; return true; }
        source.Status = DiagnosticReadStatus.LimitReached;
        source.Detail = LimitedDetail(source.Detail, SourceDetailLimitDetail, maximum);
        return false;
    }

    internal static bool TryAddTarget(RelatedSourceObservation source, string path)
    {
        if (source.ResolvedTargets.Contains(path, StringComparer.OrdinalIgnoreCase)) return true;
        long targetCharacters = source.ResolvedTargets.Sum(value => (long)value.Length);
        // Reserve the full Detail allowance: later command/script diagnostics can append notes.
        long fixedCharacters = FixedCharacters(source) + MaximumDetailCharacters;
        if (source.ResolvedTargets.Count >= MaximumSourceTargets || path.Length is 0 or > 32768 ||
            fixedCharacters + targetCharacters + path.Length > RelatedComponentFragments.MaximumRecordCharacters)
        {
            MarkLimited(source);
            return false;
        }
        source.ResolvedTargets.Add(path);
        return true;
    }

    /// <returns>True when any target was omitted; callers should preserve a LimitReached check.</returns>
    internal static bool MergeTargets(RelatedSourceObservation source, IEnumerable<string> values)
    {
        bool truncated = false;
        foreach (string value in values)
            if (!TryAddTarget(source, value)) truncated = true;
        return truncated;
    }

    private static void MarkLimited(RelatedSourceObservation source)
    {
        source.Status = DiagnosticReadStatus.LimitReached;
        if (source.Detail.Contains(SourceTargetLimitDetail, StringComparison.Ordinal)) return;
        source.Detail = LimitedDetail(source.Detail, SourceTargetLimitDetail, DetailCapacity(source));
    }

    private static bool Fits(RelatedSourceObservation source) => Valid(source.Id, 128, true) && Valid(source.Kind, 128, true) &&
        Valid(source.Scope, 128, true) && Valid(source.Location, 32768) && Valid(source.RawCommand, 65536) &&
        (source.WorkingDirectory is null || source.WorkingDirectory.Length <= 32768) && (source.UserSid is null || source.UserSid.Length <= 512) &&
        Valid(source.Detail, MaximumDetailCharacters) && source.ResolvedTargets is { Count: <= MaximumSourceTargets } &&
        source.ResolvedTargets.All(path => Valid(path, 32768, true)) &&
        FixedCharacters(source) + source.Detail.Length + source.ResolvedTargets.Sum(path => (long)path.Length) <= RelatedComponentFragments.MaximumRecordCharacters;
    private static bool Valid(string? value, int maximum, bool required = false) => value is not null && value.Length <= maximum && (!required || !string.IsNullOrWhiteSpace(value));
    private static string Bounded(string? value, int maximum, string fallback) => string.IsNullOrWhiteSpace(value) ? fallback : value.Length <= maximum ? value : value[..(maximum - 1)] + "…";
    private static long FixedCharacters(RelatedSourceObservation source) => (long)source.Id.Length + source.Kind.Length + source.Scope.Length + source.Location.Length +
        source.RawCommand.Length + (source.WorkingDirectory?.Length ?? 0) + (source.UserSid?.Length ?? 0);
    private static int DetailCapacity(RelatedSourceObservation source) => (int)Math.Max(0, Math.Min(MaximumDetailCharacters,
        RelatedComponentFragments.MaximumRecordCharacters - FixedCharacters(source) - source.ResolvedTargets.Sum(value => (long)value.Length)));
    private static string LimitedDetail(string original, string note, int maximum)
    {
        if (maximum <= note.Length) return note[..maximum];
        int keep = Math.Min(original.Length, maximum - note.Length - 1);
        return original[..keep] + " " + note;
    }
}
