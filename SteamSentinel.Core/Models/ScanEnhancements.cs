namespace SteamSentinel.Core.Models;

/// <summary>Optional engines are independent of the baseline scan's release requirements.</summary>
public static class ScanEnhancements
{
    // This release pauses the system-engine enhancement. Keep historical options intact;
    // apply this policy only to an execution or a newly produced report.
    public static bool AmsiAvailable => false;

    public static bool UseAmsi(ScanOptions options) => AmsiAvailable && options.UseAmsi;

    public static ScanOptions ForExecution(ScanOptions options)
    {
        bool useAmsi = UseAmsi(options);
        return options.UseAmsi == useAmsi ? options : options.CopyWithAmsi(useAmsi);
    }
}
