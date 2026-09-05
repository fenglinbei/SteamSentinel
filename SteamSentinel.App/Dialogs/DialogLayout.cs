using System.Windows;

namespace SteamSentinel.App.Dialogs;

internal static class DialogLayout
{
    internal static void ConstrainToWorkArea(Window window)
    {
        // WorkArea is already expressed in WPF device-independent units, including DPI scaling.
        // Shrink the minimums first so WPF does not coerce a small screen back to an oversized window.
        Rect area = SystemParameters.WorkArea;
        window.MinWidth = Math.Min(window.MinWidth, area.Width);
        window.MinHeight = Math.Min(window.MinHeight, area.Height);
        window.Width = Math.Min(window.Width, area.Width);
        window.Height = Math.Min(window.Height, area.Height);
    }
}
