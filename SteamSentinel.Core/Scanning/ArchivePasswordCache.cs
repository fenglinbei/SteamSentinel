using System.Buffers.Binary;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using SteamSentinel.Core.Models;

namespace SteamSentinel.Core.Scanning;

internal sealed class ArchivePasswordCache
{
    internal const int MaximumPasswordDecodeAttempts = 512;
    private const int ValidatedCapacity = 8;
    private const int CandidateBatchCapacity = 8;
    private readonly List<(string Password, string Root, ArchivePasswordReuseScope Scope)> _validated = [];
    private readonly List<CandidateBatch> _candidateBatches = [];
    private const int HistoryCapacity = 512;
    private readonly Dictionary<string, History> _history = new(StringComparer.OrdinalIgnoreCase);
    private readonly Queue<string> _historyOrder = new();
    private byte[] _historyKey = RandomNumberGenerator.GetBytes(32);

    public ArchivePasswordReuseScope PreferredScope { get; set; } = ArchivePasswordReuseScope.ArchiveTree;
    public bool SkipAllEncrypted { get; private set; }

    private sealed record CandidateBatch(string Root, ArchivePasswordReuseScope Scope, string[] Passwords);
    internal readonly record struct Candidate(
        string Password,
        ArchivePasswordReuseScope ValidationScope,
        bool IsValidated);

    private sealed class History
    {
        public HashSet<PasswordFingerprint> Failed { get; } = [];
        public bool Deferred { get; set; }
    }

    private readonly record struct PasswordFingerprint(ulong A, ulong B, ulong C, ulong D);

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
        _history.TryGetValue(sha256, out History? history) && history.Failed.Contains(Fingerprint(password));

    public void RememberFailure(string sha256, string password)
    {
        History history = GetHistory(sha256);
        if (history.Failed.Count < MaximumPasswordDecodeAttempts)
            history.Failed.Add(Fingerprint(password));
    }

    private PasswordFingerprint Fingerprint(string password)
    {
        Span<byte> digest = stackalloc byte[32];
        try
        {
            _ = HMACSHA256.HashData(_historyKey, MemoryMarshal.AsBytes(password.AsSpan()), digest);
            return new PasswordFingerprint(
                BinaryPrimitives.ReadUInt64LittleEndian(digest),
                BinaryPrimitives.ReadUInt64LittleEndian(digest[8..]),
                BinaryPrimitives.ReadUInt64LittleEndian(digest[16..]),
                BinaryPrimitives.ReadUInt64LittleEndian(digest[24..]));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(digest);
        }
    }

    public bool IsDeferred(string sha256) => _history.TryGetValue(sha256, out History? history) && history.Deferred;
    public void Defer(string sha256) => GetHistory(sha256).Deferred = true;

    public IReadOnlyList<Candidate> CandidateEntries(string root)
    {
        List<Candidate> result = [];
        HashSet<string> seen = new(StringComparer.Ordinal);
        CandidateBatch? treeBatch = _candidateBatches.LastOrDefault(x =>
            x.Scope == ArchivePasswordReuseScope.ArchiveTree &&
            x.Root.Equals(root, StringComparison.OrdinalIgnoreCase));
        CandidateBatch? sessionBatch = _candidateBatches.LastOrDefault(x =>
            x.Scope == ArchivePasswordReuseScope.Session);
        if (treeBatch is not null)
            foreach (string password in treeBatch.Passwords)
                if (seen.Add(password)) result.Add(new Candidate(password, ArchivePasswordReuseScope.ArchiveTree, false));
        if (sessionBatch is not null)
            foreach (string password in sessionBatch.Passwords)
                if (seen.Add(password)) result.Add(new Candidate(password, ArchivePasswordReuseScope.Session, false));
        foreach ((string password, string candidateRoot, ArchivePasswordReuseScope scope) in _validated.AsEnumerable().Reverse())
        {
            if (scope != ArchivePasswordReuseScope.Session &&
                !candidateRoot.Equals(root, StringComparison.OrdinalIgnoreCase)) continue;
            if (seen.Add(password)) result.Add(new Candidate(password, ArchivePasswordReuseScope.CurrentOnly, true));
        }
        return result;
    }

    public IReadOnlyList<string> Candidates(string root) =>
        CandidateEntries(root).Select(candidate => candidate.Password).ToArray();

    public IReadOnlyList<string> ValidatedCandidates(string root) => _validated.AsEnumerable().Reverse()
        .Where(candidate => candidate.Scope == ArchivePasswordReuseScope.Session ||
            candidate.Root.Equals(root, StringComparison.OrdinalIgnoreCase))
        .Select(candidate => candidate.Password).Distinct(StringComparer.Ordinal).ToArray();

    public void SetUserCandidates(IReadOnlyList<string> passwords, string root, ArchivePasswordReuseScope scope)
    {
        if (scope == ArchivePasswordReuseScope.CurrentOnly || passwords.Count == 0) return;
        _candidateBatches.RemoveAll(x => x.Scope == scope &&
            (scope == ArchivePasswordReuseScope.Session || x.Root.Equals(root, StringComparison.OrdinalIgnoreCase)));
        while (_candidateBatches.Count >= CandidateBatchCapacity)
        {
            int remove = _candidateBatches.FindIndex(x => x.Scope == ArchivePasswordReuseScope.ArchiveTree);
            _candidateBatches.RemoveAt(remove >= 0 ? remove : 0);
        }
        _candidateBatches.Add(new CandidateBatch(root, scope, passwords.ToArray()));
    }

    public void EnableSkipAllEncrypted() => SkipAllEncrypted = true;

    public void Remember(string password, string root, ArchivePasswordReuseScope scope)
    {
        if (scope == ArchivePasswordReuseScope.CurrentOnly) return;
        if (_validated.Any(x => x.Password == password && x.Scope == ArchivePasswordReuseScope.Session)) return;
        _validated.RemoveAll(x => x.Password == password && (scope == ArchivePasswordReuseScope.Session ||
            x.Root.Equals(root, StringComparison.OrdinalIgnoreCase)));
        _validated.Add((password, root, scope));
        if (_validated.Count > ValidatedCapacity) _validated.RemoveAt(0);
    }

    public void Clear()
    {
        _validated.Clear();
        _candidateBatches.Clear();
        _history.Clear();
        _historyOrder.Clear();
        CryptographicOperations.ZeroMemory(_historyKey);
        _historyKey = RandomNumberGenerator.GetBytes(32);
        PreferredScope = ArchivePasswordReuseScope.ArchiveTree;
        SkipAllEncrypted = false;
    }
}
