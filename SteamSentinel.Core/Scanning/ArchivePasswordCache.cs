using SteamSentinel.Core.Models;

namespace SteamSentinel.Core.Scanning;

internal sealed class ArchivePasswordCache
{
    private const int Capacity = 8;
    private readonly List<(string Password, string Root, ArchivePasswordReuseScope Scope)> _validated = [];
    private const int HistoryCapacity = 512;
    private readonly Dictionary<string, History> _history = new(StringComparer.OrdinalIgnoreCase);
    private readonly Queue<string> _historyOrder = new();

    public ArchivePasswordReuseScope PreferredScope { get; set; } = ArchivePasswordReuseScope.ArchiveTree;

    private sealed class History
    {
        public HashSet<string> Failed { get; } = new(StringComparer.Ordinal);
        public bool Deferred { get; set; }
    }

    private History GetHistory(string sha256)
    {
        if (_history.TryGetValue(sha256, out History? existing)) return existing;
        if (_history.Count >= HistoryCapacity) _history.Remove(_historyOrder.Dequeue());
        History history = new();
        _history.Add(sha256, history);
        _historyOrder.Enqueue(sha256);
        return history;
    }

    public bool HasFailed(string sha256, string password) =>
        _history.TryGetValue(sha256, out History? history) && history.Failed.Contains(password);

    public void RememberFailure(string sha256, string password)
    {
        History history = GetHistory(sha256);
        if (history.Failed.Count < 16) history.Failed.Add(password);
    }

    public bool IsDeferred(string sha256) => _history.TryGetValue(sha256, out History? history) && history.Deferred;
    public void Defer(string sha256) => GetHistory(sha256).Deferred = true;

    public IEnumerable<string> Candidates(string root) => _validated.AsEnumerable().Reverse()
        .Where(x => x.Scope == ArchivePasswordReuseScope.Session || x.Root.Equals(root, StringComparison.OrdinalIgnoreCase))
        .Select(x => x.Password).Distinct(StringComparer.Ordinal).Take(Capacity);

    public void Remember(string password, string root, ArchivePasswordReuseScope scope)
    {
        if (scope == ArchivePasswordReuseScope.CurrentOnly) return;
        if (_validated.Any(x => x.Password == password && x.Scope == ArchivePasswordReuseScope.Session)) return;
        _validated.RemoveAll(x => x.Password == password && (scope == ArchivePasswordReuseScope.Session || x.Root == root));
        _validated.Add((password, root, scope));
        if (_validated.Count > Capacity) _validated.RemoveAt(0);
    }

    public void Clear()
    {
        _validated.Clear();
        _history.Clear();
        _historyOrder.Clear();
        PreferredScope = ArchivePasswordReuseScope.ArchiveTree;
    }
}
