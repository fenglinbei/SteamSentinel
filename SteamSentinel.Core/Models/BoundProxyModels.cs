namespace SteamSentinel.Core.Models;

public enum BoundProxyField { Flags, ProxyServer, ProxyBypass, AutoConfigUrl }
public enum BoundProxyPolicyStatus { Unverified, Unmanaged, PolicyControlled, Unsupported, ReadFailed }
public enum BoundProxyMutationState { Prepared, Unchanged, Applied, Indeterminate, Restored }

public sealed class BoundProxyString
{
    public bool Present { get; init; }
    public string? Value { get; init; }
}

public sealed class BoundProxyPolicyGuard
{
    public BoundProxyPolicyStatus Status { get; init; }
    public string Fingerprint { get; init; } = string.Empty;
    public string Detail { get; init; } = string.Empty;
}

public sealed class BoundProxySnapshot
{
    public uint Flags { get; init; }
    public BoundProxyString ProxyServer { get; init; } = new();
    public BoundProxyString ProxyBypass { get; init; } = new();
    public BoundProxyString AutoConfigUrl { get; init; } = new();
    public BoundProxyPolicyGuard PolicyGuard { get; init; } = new();
}

public sealed class BoundProxyTarget
{
    public string TargetUserSid { get; init; } = string.Empty;
    public string Source { get; init; } = "WinInetCurrentUserLan";
    public BoundProxySnapshot Before { get; init; } = new();
    public BoundProxySnapshot Desired { get; init; } = new();
    public List<BoundProxyField> ChangedFields { get; init; } = [];
}

// Broker must persist this record before Apply, and again in a finally block afterwards.
// A failed setter or notification can leave actual changes; state is never inferred from an exception alone.
public sealed class BoundProxyBackup
{
    public string TargetUserSid { get; init; } = string.Empty;
    public string Source { get; init; } = "WinInetCurrentUserLan";
    public BoundProxySnapshot Before { get; init; } = new();
    public BoundProxySnapshot After { get; init; } = new();
    public List<BoundProxyField> ChangedFields { get; init; } = [];
    public bool WriteAttempted { get; set; }
    public bool WriteSucceeded { get; set; }
    public bool SettingsChangedNotified { get; set; }
    public bool RefreshNotified { get; set; }
    public bool ReadBackMatched { get; set; }
    public bool RestoreAttempted { get; set; }
    public bool RestoreWriteSucceeded { get; set; }
    public bool RestoreSettingsChangedNotified { get; set; }
    public bool RestoreRefreshNotified { get; set; }
    public bool RestoreReadBackMatched { get; set; }
    public BoundProxyMutationState MutationState { get; set; }
    public string Diagnostic { get; set; } = string.Empty;
}
