namespace SteamSentinel.Core.Utilities;

public enum StartupRole { App, Broker, Worker }
public enum StartupMode { Standard, Compat }

/// <summary>Fixed startup-host mappings. A mode is a compatibility preference, never an authorization.</summary>
public static class StartupCompatibility
{
    public const string ProbeArgument = "--startup-probe";
    public const string ReadyPrefix = "STEAMSENTINEL_STARTUP_READY/1";
    public const int InvalidProbeExitCode = 2;
    // Emitted only by the native Broker wrapper before any business child has started.
    public const int BrokerPreflightNotStartedExitCode = 0x53530001;

    public static string RoleName(StartupRole role) => role switch
    {
        StartupRole.App => "app",
        StartupRole.Broker => "broker",
        StartupRole.Worker => "worker",
        _ => throw new ArgumentOutOfRangeException(nameof(role))
    };

    public static string ModeName(StartupMode mode) => mode switch
    {
        StartupMode.Standard => "standard",
        StartupMode.Compat => "compat",
        _ => throw new ArgumentOutOfRangeException(nameof(mode))
    };

    public static string AssemblyBaseName(StartupRole role) => role switch
    {
        StartupRole.App => "SteamSentinel",
        StartupRole.Broker => "SteamSentinel.Broker",
        StartupRole.Worker => "SteamSentinel.ArchiveWorker",
        _ => throw new ArgumentOutOfRangeException(nameof(role))
    };

    public static string HostFileName(StartupRole role, StartupMode mode) =>
        AssemblyBaseName(role) + (mode switch
        {
            StartupMode.Standard => ".Standard.exe",
            StartupMode.Compat => ".Compat.exe",
            _ => throw new ArgumentOutOfRangeException(nameof(mode))
        });

    public static bool TryIdentifyHost(string? processPath, StartupRole role, out StartupMode mode, out bool unified)
    {
        mode = StartupMode.Standard;
        unified = false;
        if (string.IsNullOrEmpty(processPath)) return false;
        string name = Path.GetFileName(processPath);
        if (name.Equals(HostFileName(role, StartupMode.Standard), StringComparison.OrdinalIgnoreCase))
            unified = true;
        else if (name.Equals(HostFileName(role, StartupMode.Compat), StringComparison.OrdinalIgnoreCase))
        {
            unified = true;
            mode = StartupMode.Compat;
        }
        else if (!name.Equals(AssemblyBaseName(role) + ".exe", StringComparison.OrdinalIgnoreCase))
            return false;
        return true;
    }

    public static bool IsUnifiedHost(string? processPath) =>
        Enum.GetValues<StartupRole>().Any(role => TryIdentifyHost(processPath, role, out _, out bool unified) && unified);

    public static string WorkerPath(string baseDirectory, string? appProcessPath)
    {
        string name = TryIdentifyHost(appProcessPath, StartupRole.App, out StartupMode mode, out bool unified) && unified
            ? HostFileName(StartupRole.Worker, mode)
            : AssemblyBaseName(StartupRole.Worker) + ".exe";
        return Path.Combine(baseDirectory, name);
    }

    public static string WorkerAssemblyPath(string workerPath) =>
        TryIdentifyHost(workerPath, StartupRole.Worker, out _, out _)
            ? Path.Combine(Path.GetDirectoryName(workerPath) ?? string.Empty, AssemblyBaseName(StartupRole.Worker) + ".dll")
            : Path.ChangeExtension(workerPath, ".dll"); // Inert SelfTest fixtures retain their own assembly names.

    /// <summary>Handle probes before WPF, plans, scanning, settings or filesystem setup.</summary>
    public static bool TryRunProbe(string[] args, StartupRole role, out int exitCode) =>
        TryRunProbe(args, role, Environment.ProcessPath, Console.Out, out exitCode);

    internal static bool TryRunProbe(string[] args, StartupRole role, string? processPath, TextWriter output, out int exitCode)
    {
        exitCode = InvalidProbeExitCode;
        // Reserve malformed/case-mismatched variants too: they must not fall through into business startup.
        if (!args.Any(arg => arg.StartsWith(ProbeArgument, StringComparison.OrdinalIgnoreCase))) return false;
        if (args.Length != 2 || args[0] != ProbeArgument || args[1].Length != 32 ||
            !args[1].All(char.IsAsciiHexDigit) || !TryIdentifyHost(processPath, role, out StartupMode mode, out _))
            return true;
        output.WriteLine($"{ReadyPrefix}|{RoleName(role)}|{ModeName(mode)}|{args[1]}");
        output.Flush();
        exitCode = 0;
        return true;
    }
}
