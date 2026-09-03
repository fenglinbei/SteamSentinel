using System.Diagnostics;
using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.Win32;

namespace SteamSentinel.Core.Steam;

public sealed class SteamLayout
{
    public List<string> SteamRoots { get; } = [];
    public List<string> LibraryRoots { get; } = [];
    public List<string> WorkshopRoots { get; } = [];
    public List<string> WallpaperProjectRoots { get; } = [];
}

public sealed record WallpaperProject(
    string Directory,
    string WorkshopId,
    string? Title,
    string? Type,
    string? EntryFile,
    string? PreviewFile,
    string? ParseError);

public static partial class SteamLocator
{
    [GeneratedRegex("\\\"path\\\"\\s*\\\"(?<path>(?:\\\\.|[^\\\"])*)\\\"", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex LibraryPathRegex();

    public static SteamLayout Discover()
    {
        SteamLayout layout = new();
        HashSet<string> steamRoots = new(StringComparer.OrdinalIgnoreCase);

        AddRegistryPath(Registry.CurrentUser, @"Software\Valve\Steam", "SteamPath", steamRoots);
        AddRegistryPath(Registry.LocalMachine, @"Software\Valve\Steam", "InstallPath", steamRoots);
        AddRegistryPath(Registry.LocalMachine, @"Software\WOW6432Node\Valve\Steam", "InstallPath", steamRoots);

        foreach (Process process in Process.GetProcessesByName("steam"))
        {
            try
            {
                string? directory = Path.GetDirectoryName(process.MainModule?.FileName);
                if (directory is not null) AddExisting(directory, steamRoots);
            }
            catch
            {
                // Some protected processes cannot expose MainModule to a standard user.
            }
            finally
            {
                process.Dispose();
            }
        }

        AddExisting(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86), "Steam"), steamRoots);
        AddExisting(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "Steam"), steamRoots);

        HashSet<string> libraries = new(StringComparer.OrdinalIgnoreCase);
        foreach (string steamRoot in steamRoots)
        {
            AddExisting(steamRoot, libraries);
            string vdf = Path.Combine(steamRoot, "steamapps", "libraryfolders.vdf");
            if (!File.Exists(vdf)) continue;
            try
            {
                string text = File.ReadAllText(vdf);
                foreach (Match match in LibraryPathRegex().Matches(text))
                {
                    string path = Regex.Unescape(match.Groups["path"].Value);
                    AddExisting(path, libraries);
                }
            }
            catch
            {
                // A malformed VDF should not abort all discovery.
            }
        }

        layout.SteamRoots.AddRange(steamRoots.Order(StringComparer.OrdinalIgnoreCase));
        layout.LibraryRoots.AddRange(libraries.Order(StringComparer.OrdinalIgnoreCase));

        foreach (string library in libraries)
        {
            AddExisting(Path.Combine(library, "steamapps", "workshop", "content", "431960"), layout.WorkshopRoots);
            AddExisting(Path.Combine(library, "steamapps", "common", "wallpaper_engine", "projects"), layout.WallpaperProjectRoots);
        }

        return layout;
    }

    public static WallpaperProject ReadWallpaperProject(string directory)
    {
        string id = new DirectoryInfo(directory).Name;
        string projectJson = Path.Combine(directory, "project.json");
        if (!File.Exists(projectJson))
        {
            return new WallpaperProject(directory, id, null, null, null, null, "缺少 project.json");
        }

        try
        {
            using JsonDocument document = JsonDocument.Parse(File.ReadAllText(projectJson));
            JsonElement root = document.RootElement;
            return new WallpaperProject(
                directory,
                id,
                GetString(root, "title"),
                GetString(root, "type"),
                GetString(root, "file"),
                GetString(root, "preview"),
                null);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or JsonException)
        {
            return new WallpaperProject(directory, id, null, null, null, null, ex.Message);
        }
    }

    private static string? GetString(JsonElement root, string name) =>
        root.TryGetProperty(name, out JsonElement value) && value.ValueKind == JsonValueKind.String
            ? value.GetString()
            : null;

    private static void AddRegistryPath(RegistryKey hive, string keyPath, string valueName, ISet<string> paths)
    {
        try
        {
            using RegistryKey? key = hive.OpenSubKey(keyPath);
            if (key?.GetValue(valueName) is string value) AddExisting(value, paths);
        }
        catch
        {
            // Registry view may not be accessible.
        }
    }

    private static void AddExisting(string path, ISet<string> paths)
    {
        try
        {
            string full = Path.TrimEndingDirectorySeparator(Path.GetFullPath(path.Replace('/', Path.DirectorySeparatorChar)));
            if (Directory.Exists(full)) paths.Add(full);
        }
        catch
        {
            // Ignore malformed paths from external configuration.
        }
    }

    private static void AddExisting(string path, ICollection<string> paths)
    {
        try
        {
            string full = Path.TrimEndingDirectorySeparator(Path.GetFullPath(path));
            if (Directory.Exists(full) && !paths.Contains(full, StringComparer.OrdinalIgnoreCase)) paths.Add(full);
        }
        catch
        {
            // Ignore malformed paths from external configuration.
        }
    }
}
