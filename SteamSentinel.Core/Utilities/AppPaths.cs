namespace SteamSentinel.Core.Utilities;

public static class AppPaths
{
    public static string UserStateRoot => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "SteamSentinel");

    public static string PlansRoot => Path.Combine(UserStateRoot, "Plans");
    public static string ReportsRoot => Path.Combine(UserStateRoot, "Reports");
    public static string TemporaryRoot => Path.Combine(UserStateRoot, "Temp");
    public static string MachineStateRoot => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
        "SteamSentinel");
    public static string QuarantineRoot => Path.Combine(MachineStateRoot, "Quarantine");
}
