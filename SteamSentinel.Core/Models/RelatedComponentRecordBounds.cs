using SteamSentinel.Core.Reporting;
namespace SteamSentinel.Core.Models;

/// <summary>Bounds derived path lists while retaining the source's original command and identity.</summary>
internal static class RelatedComponentRecordBounds
{
    internal const int MaximumSourceTargets = 128;
    internal const int MaximumDetailCharacters = 8192;
    internal static readonly MessageText SourceTargetLimitDetail = MessageText.Create("Backend.Core.RelatedComponentRecordBounds.SourceTargetLimitDetail.01");
    internal static readonly MessageText OriginalSourceLimitDetail = MessageText.Create("Backend.Core.RelatedComponentRecordBounds.OriginalSourceLimitDetail.01");
    internal static readonly MessageText SourceDetailLimitDetail = MessageText.Create("Backend.Core.RelatedComponentRecordBounds.SourceDetailLimitDetail.01");

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
            Location = Bounded(source.Location, 32768, MessageText.Create("Backend.Core.RelatedComponentRecordBounds.PrepareOriginal.01")),
            UserSid = sid,
            RawCommand = "",
            WorkingDirectory = null,
            Status = DiagnosticReadStatus.LimitReached,
            DetailText = OriginalSourceLimitDetail
        };
    }

    internal static bool TryAppendDetail(RelatedSourceObservation source, MessageText detail)
    {
        int maximum = DetailCapacity(source);
        if ((long)source.Detail.Length + detail.OriginalText.Length + 1 <= maximum) { source.DetailText += " " + detail; return true; }
        source.Status = DiagnosticReadStatus.LimitReached;
        source.DetailText = LimitedDetail(source.DetailText, SourceDetailLimitDetail, maximum);
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
        source.DetailText = LimitedDetail(source.DetailText, SourceTargetLimitDetail, DetailCapacity(source));
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
    private static MessageText LimitedDetail(MessageText original, MessageText note, int maximum)
    {
        if (maximum <= note.OriginalText.Length) return note.Limit(maximum);
        int keep = Math.Min(original.OriginalText.Length, maximum - note.OriginalText.Length - 1);
        return original.Limit(keep) + " " + note;
    }
}
