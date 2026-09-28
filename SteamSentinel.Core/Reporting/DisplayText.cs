using System.Globalization;
using System.Resources;

namespace SteamSentinel.Core.Reporting;

/// <summary>Local display resources only. Text and culture must never authorize or classify an operation.</summary>
public static class DisplayText
{
    private static readonly ResourceManager Resources = new("SteamSentinel.Core.Reporting.PresentationMessages", typeof(DisplayText).Assembly);
    private static readonly AsyncLocal<CultureInfo?> SelectedCulture = new();
    private static CultureInfo? _applicationCulture;
    public static CultureInfo Chinese { get; } = CultureInfo.GetCultureInfo("zh-Hans");
    public static CultureInfo English { get; } = CultureInfo.GetCultureInfo("en-US");

    // The application sets this before creating any windows. Worker/Broker defaults
    // remain unchanged; explicit render scopes take precedence over the process default.
    public static CultureInfo ApplicationCulture => Volatile.Read(ref _applicationCulture) ?? Chinese;
    public static CultureInfo Culture => SelectedCulture.Value ?? ApplicationCulture;
    public static void InitializeApplicationCulture(CultureInfo culture) =>
        Volatile.Write(ref _applicationCulture, Resolve(culture));
    public static CultureInfo Resolve(CultureInfo culture) => culture.TwoLetterISOLanguageName == "zh" ? Chinese : English;

    /// <summary>A render scope flows across awaits, is isolated between tasks, and never changes OS/thread culture.</summary>
    public static IDisposable UseCulture(CultureInfo? culture) => new CultureScope(culture);
    private static string? Template(string id) => id.StartsWith("Status.", StringComparison.Ordinal)
        ? StatusPresentation.Template(id[7..], Culture) : Resources.GetString(id, Culture);
    public static string Get(string id) => Template(id) ?? Missing(id);
    private static string Missing(string id) => string.Format(Culture, Resources.GetString("Display.Unknown", Culture)!, id);
    public static string Format(string id, params object?[] arguments)
    {
        string? template = Template(id);
        if (template is null) return Missing(id);
        try { return string.Format(Culture, template, arguments); }
        catch (FormatException) { return Missing(id); }
    }

    internal static bool TryFormat(string id, object?[] arguments, out string text)
    {
        text = string.Empty;
        string? template = Template(id);
        if (template is null) return false;
        try { text = string.Format(Culture, template, arguments); return true; }
        catch (FormatException) { return false; }
    }

    private sealed class CultureScope : IDisposable
    {
        private readonly CultureInfo? _previous = SelectedCulture.Value;
        private bool _disposed;
        public CultureScope(CultureInfo? culture)
        {
            if (culture is not null) SelectedCulture.Value = Resolve(culture);
        }
        public void Dispose()
        {
            if (_disposed) return;
            SelectedCulture.Value = _previous;
            _disposed = true;
        }
    }
}
