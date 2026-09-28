namespace SteamSentinel.Core.Scanning;

/// <summary>Bound forced collections; the separate memory stop remains effective on every probe.</summary>
public sealed class MemoryReclaimPolicy
{
    private long? _lastCollection;
    public bool ShouldCollect(long privateBytes, long limit, long milliseconds)
    {
        if (limit <= 0 || privateBytes < limit / 8 * 5) return false;
        if (_lastCollection is long previous && milliseconds - previous < 30_000) return false;
        _lastCollection = milliseconds;
        return true;
    }
}
