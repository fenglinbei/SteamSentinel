namespace SteamSentinel.Core.Remediation;

/// <summary>Reviewed byte identities, not names or a user supplied report, identify this family.</summary>
public static class SteamAlertWatchdog
{
    public const string ScriptHostKind = "SteamAlertScriptHost";
    public const string WatchdogRole = "STEAMALERT-WATCHDOG";
    public const string UpdaterRole = "STEAMALERT-UPDATER";
    public const string LauncherRole = "STEAMALERT-LAUNCHER";
    public const string PayloadRole = "STEAMALERT-RESIDENT";
    public const string LoaderRole = "STEAMALERT-MOD-LOADER";

    public const string WatchdogHash = "94FCA6D53A1D7DF49E0AAA6C8388950B1527DF7439969FE3F16FB64832E12699";
    public const string UpdaterHash = "35233E36BF0F03B4CEA2F2DCD296E927CCD014F35ACCB126D2BAF9861D49BBA8";
    public const string LauncherHash = "3CFBC8C910FB4F24E88380948655873486DD3D0A505F451816FD9A50C362940F";
    public const string ResidentHash = "54799E1B7B90961F29284226210CD6029CAB87EC82635B3FB7AB99D0BDB72FE2";
    public const string WatchdogResourceHash = "4D68A9C6F0C2802339BC572CF3E4EFF0462C01D1E894CFF9E8B578F9C2736FFF";
    public const string UpdaterResourceHash = "0EC69EF47D19F52DA69B88FCA57191F5323D3CFD7DE9F3A933313A44EA090150";
    public const string LauncherResourceHash = "DFD442A5B61AF0607A94F5E2AEFF69E8F68F3B89264C424A91BFEA6D2184FD4B";

    private static readonly IReadOnlyDictionary<string, string> Roles = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
    {
        [WatchdogHash] = WatchdogRole,
        [UpdaterHash] = UpdaterRole,
        [LauncherHash] = LauncherRole,
        [WatchdogResourceHash] = WatchdogRole,
        [UpdaterResourceHash] = UpdaterRole,
        [LauncherResourceHash] = LauncherRole,
        [ResidentHash] = PayloadRole,
        ["86E0D69C3F7A0B376D88BFDF9DBEFDDA314541A8389FB66E399E4DD2A06C290B"] = PayloadRole,
        ["20510416665705F7D3B55DE60F22B6072295B8A5BFB51139FE972E916B53F272"] = LoaderRole
    };

    public static string? RoleForHash(string? hash) => hash is not null && Roles.TryGetValue(hash, out string? role) ? role : null;
    public static bool IsScriptHash(string? hash) => RoleForHash(hash) is WatchdogRole or UpdaterRole or LauncherRole;
    public static bool IsFamilyHash(string? hash) => RoleForHash(hash) is not null;
}
