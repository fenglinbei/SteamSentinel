namespace SteamSentinel.Core.Models;

/// <summary>Optional engines are independent of the baseline scan's release requirements.</summary>
public static class ScanEnhancements
{
    // 温和启用可选系统引擎增强（默认关闭，仅在用户勾选时启用并在不可用或超限时静默降级）。
    public static bool AmsiAvailable => true;

    public static bool UseAmsi(ScanOptions options) => AmsiAvailable && options.UseAmsi;

    public static ScanOptions ForExecution(ScanOptions options)
    {
        bool useAmsi = UseAmsi(options);
        return options.UseAmsi == useAmsi ? options : options.CopyWithAmsi(useAmsi);
    }
}
