using System.Globalization;
using System.Text.Json;
using SteamSentinel.App.Services;
using SteamSentinel.Core.Reporting;
using SteamSentinel.Core.Utilities;

namespace SteamSentinel.App.Localization;

internal enum LanguagePreference { Automatic, SimplifiedChinese, English }
internal enum LanguageSettingsError { None, Invalid, Unreadable }
internal sealed record LanguageSettingsRead(LanguagePreference Preference, LanguageSettingsError Error);
internal sealed record LanguageStartupState(LanguagePreference Preference, CultureInfo Culture,
    bool AdministratorWindowRequested, bool InheritedLanguage, bool IgnoredArguments, LanguageSettingsError SettingsError);
internal sealed record LanguageOption(LanguagePreference Value, string Label);

internal static class LanguageSettings
{
    internal const int MaximumFileBytes = 4096;
    internal const string LanguageArgument = "--ui-language";
    internal static string DefaultPath => Path.Combine(AppPaths.UserStateRoot, "ui-language.json");

    // Autonyms stay recognizable even when the surrounding interface is in another language.
    internal const string ChineseAutonym = "简体中文";
    internal const string EnglishAutonym = "English";

    internal static LanguageOption[] Options() =>
    [
        new(LanguagePreference.Automatic, DisplayText.Get("Ui.Language.Automatic")),
        new(LanguagePreference.SimplifiedChinese, ChineseAutonym),
        new(LanguagePreference.English, EnglishAutonym)
    ];

    internal static string Code(LanguagePreference value) => value switch
    {
        LanguagePreference.Automatic => "auto",
        LanguagePreference.SimplifiedChinese => "zh-Hans",
        LanguagePreference.English => "en",
        _ => throw new ArgumentOutOfRangeException(nameof(value))
    };

    internal static CultureInfo Resolve(LanguagePreference value, CultureInfo windowsUiLanguage) => value switch
    {
        LanguagePreference.Automatic => DisplayText.Resolve(windowsUiLanguage),
        LanguagePreference.SimplifiedChinese => DisplayText.Chinese,
        LanguagePreference.English => DisplayText.English,
        _ => throw new ArgumentOutOfRangeException(nameof(value))
    };

    internal static string CultureCode(CultureInfo culture) =>
        DisplayText.Resolve(culture) == DisplayText.Chinese ? "zh-Hans" : "en";

    internal static string CultureLabel(CultureInfo culture) =>
        DisplayText.Resolve(culture) == DisplayText.Chinese ? ChineseAutonym : EnglishAutonym;

    internal static LanguagePreference Load(string path)
    {
        FileStream stream;
        try { stream = new(path, FileMode.Open, FileAccess.Read, FileShare.Read); }
        catch (FileNotFoundException) { return LanguagePreference.Automatic; }
        catch (DirectoryNotFoundException) { return LanguagePreference.Automatic; }
        using (stream)
        {
            byte[] bytes = new byte[MaximumFileBytes + 1];
            int count = stream.ReadAtLeast(bytes, bytes.Length, throwOnEndOfStream: false);
            if (count > MaximumFileBytes) throw InvalidSettings();
            using JsonDocument document = JsonDocument.Parse(bytes.AsMemory(0, count), new() { MaxDepth = 4 });
            JsonElement root = document.RootElement;
            if (root.ValueKind != JsonValueKind.Object) throw InvalidSettings();
            JsonProperty[] properties = root.EnumerateObject().ToArray();
            if (properties.Length != 2 || properties.Select(p => p.Name).Distinct(StringComparer.Ordinal).Count() != 2 ||
                !root.TryGetProperty("SchemaVersion", out JsonElement version) || version.ValueKind != JsonValueKind.Number || !version.TryGetInt32(out int number) || number != 1 ||
                !root.TryGetProperty("Language", out JsonElement language) || language.ValueKind != JsonValueKind.String)
                throw InvalidSettings();
            return language.GetString() switch
            {
                "auto" => LanguagePreference.Automatic,
                "zh-Hans" => LanguagePreference.SimplifiedChinese,
                "en" => LanguagePreference.English,
                _ => throw InvalidSettings()
            };
        }
    }

    internal static LanguageSettingsRead Read(string path)
    {
        try { return new(Load(path), LanguageSettingsError.None); }
        catch (Exception ex) when (ex is JsonException or InvalidDataException)
        { return new(LanguagePreference.Automatic, LanguageSettingsError.Invalid); }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or System.Security.SecurityException)
        { return new(LanguagePreference.Automatic, LanguageSettingsError.Unreadable); }
    }

    internal static void Save(string path, LanguagePreference preference)
    {
        string code = Code(preference); // Validate before creating or replacing any file.
        string full = Path.GetFullPath(path);
        Directory.CreateDirectory(Path.GetDirectoryName(full)!);
        string temporary = full + "." + Guid.NewGuid().ToString("N") + ".tmp";
        try
        {
            using (FileStream stream = new(temporary, FileMode.CreateNew, FileAccess.Write, FileShare.None))
            {
                JsonSerializer.Serialize(stream, new { SchemaVersion = 1, Language = code }, new JsonSerializerOptions { WriteIndented = true });
                stream.Flush(flushToDisk: true);
            }
            File.Move(temporary, full, overwrite: true);
        }
        finally { if (File.Exists(temporary)) File.Delete(temporary); }
    }

    internal static LanguageStartupState ResolveStartup(IReadOnlyList<string> arguments, string settingsPath, CultureInfo windowsUiLanguage)
    {
        LanguageSettingsRead saved = Read(settingsPath);
        bool administrator = arguments.Count == 1 && arguments[0] == ElevationService.WindowArgument;
        CultureInfo? inherited = null;
        if (arguments.Count == 3 && arguments[0] == ElevationService.WindowArgument && arguments[1] == LanguageArgument)
        {
            inherited = arguments[2] switch { "zh-Hans" => DisplayText.Chinese, "en" => DisplayText.English, _ => null };
            administrator = inherited is not null;
        }
        return new(saved.Preference, inherited ?? Resolve(saved.Preference, windowsUiLanguage), administrator,
            inherited is not null, arguments.Count > 0 && !administrator, saved.Error);
    }

    internal static string ErrorText(LanguageSettingsError error) => error switch
    {
        LanguageSettingsError.Invalid => DisplayText.Get("Ui.Language.InvalidSettings"),
        LanguageSettingsError.Unreadable => DisplayText.Get("Ui.Language.UnreadableSettings"),
        _ => string.Empty
    };

    private static InvalidDataException InvalidSettings() => new("Invalid display-language settings.");
}
