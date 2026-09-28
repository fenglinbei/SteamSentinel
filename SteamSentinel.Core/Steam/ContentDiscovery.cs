using SteamSentinel.Core.Reporting;
using System.Text.RegularExpressions;
using SteamSentinel.Core.Models;

namespace SteamSentinel.Core.Steam;

[method: System.Text.Json.Serialization.JsonConstructor]
public sealed record DiscoveryReadNote(DiagnosticReadStatus Status, string ReasonCode, string Detail)
{
    [System.Text.Json.Serialization.JsonIgnore(Condition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull)]
    public SteamSentinel.Core.Models.DisplayMessage? DetailMessage { get => SteamSentinel.Core.Reporting.MessageText.BoundDescriptor(field, Detail); init => field = value; }

    [System.Text.Json.Serialization.JsonIgnore]
    public SteamSentinel.Core.Reporting.MessageText DetailText
    {
        get => new(Detail ?? string.Empty, DetailMessage);
        init
        {
            Detail = value.OriginalText;
            DetailMessage = value.Message;
        }
    }

    public DiscoveryReadNote(DiagnosticReadStatus Status, string ReasonCode, SteamSentinel.Core.Reporting.MessageText Detail) : this(Status, ReasonCode, Detail.OriginalText)
    {
        DetailMessage = Detail.Message;
    }
}
[method: System.Text.Json.Serialization.JsonConstructor]
public sealed record ContentRoot(string Path, string AppId, string Kind, string Name)
{
    [System.Text.Json.Serialization.JsonIgnore(Condition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull)]
    public SteamSentinel.Core.Models.DisplayMessage? NameMessage { get => SteamSentinel.Core.Reporting.MessageText.BoundDescriptor(field, Name); init => field = value; }

    [System.Text.Json.Serialization.JsonIgnore]
    public SteamSentinel.Core.Reporting.MessageText NameText
    {
        get => new(Name ?? string.Empty, NameMessage);
        init
        {
            Name = value.OriginalText;
            NameMessage = value.Message;
        }
    }

    public ContentRoot(string Path, string AppId, string Kind, SteamSentinel.Core.Reporting.MessageText Name) : this(Path, AppId, Kind, Name.OriginalText)
    {
        NameMessage = Name.Message;
    }
}
public sealed record InstalledGame(string AppId, string Name, string Directory);

/// <summary>Local metadata only. Never resolves shortcuts, accesses UNC shares or follows reparse points.</summary>
public static class ContentDiscovery
{
    private static readonly Regex Pair = new("\"(?<key>appid|name|installdir)\"\\s*\"(?<value>[^\"\\r\\n]{0,1024})\"",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant, TimeSpan.FromMilliseconds(100));
    public static bool IsNumericId(string value) => value.Length is > 0 and <= 20 && value.All(char.IsAsciiDigit);

    public static bool IsLocalSafePath(string path)
    {
        try
        {
            if (!Path.IsPathFullyQualified(path) || path.StartsWith(@"\\", StringComparison.Ordinal)) return false;
            string full = System.IO.Path.GetFullPath(path);
            if (full.IndexOf(':', 2) >= 0) return false;
            string? drive = System.IO.Path.GetPathRoot(full);
            if (drive is null || new DriveInfo(drive).DriveType == DriveType.Network) return false;
            for (string? current = full; current is not null; current = System.IO.Path.GetDirectoryName(current))
            {
                try { if ((File.GetAttributes(current) & FileAttributes.ReparsePoint) != 0) return false; }
                catch (FileNotFoundException) { }
                catch (DirectoryNotFoundException) { }
            }
            return true;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException) { return false; }
    }

    public static bool IsWithin(string path, string root)
    {
        try
        {
            string full = System.IO.Path.GetFullPath(path);
            string parent = System.IO.Path.TrimEndingDirectorySeparator(System.IO.Path.GetFullPath(root));
            return full.Equals(parent, StringComparison.OrdinalIgnoreCase) ||
                   full.StartsWith(parent + System.IO.Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase);
        }
        catch { return false; }
    }

    public static IReadOnlyList<string> Children(string root, bool directories, List<string> notes, int maximum = 4096)
    {
        List<string> results = [];
        if (!Directory.Exists(root)) return results;
        if (!IsLocalSafePath(root)) { AddNote(notes, MessageText.Create("Backend.Core.ContentDiscovery.Children.01", (root))); return results; }
        try
        {
            int visited = 0;
            foreach (string item in Directory.EnumerateFileSystemEntries(root))
            {
                if (++visited > maximum) { AddNote(notes, MessageText.Create("Backend.Core.ContentDiscovery.Children.02", (maximum), (root))); break; }
                if (!IsLocalSafePath(item)) { AddNote(notes, MessageText.Create("Backend.Core.ContentDiscovery.Children.03", (item))); continue; }
                FileAttributes attributes = File.GetAttributes(item);
                if (((attributes & FileAttributes.Directory) != 0) == directories) results.Add(item);
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        { AddNote(notes, MessageText.Create("Backend.Core.ContentDiscovery.Children.04", (root), (MessageExceptions.Describe(ex)))); }
        return results;
    }

    public static IEnumerable<string> Files(string root, List<string> notes, int maximumEntries,
        int maximumDepth, CancellationToken token = default, List<DiscoveryReadNote>? structuredNotes = null)
    {
        void Note(DiagnosticReadStatus status, string reason, MessageText detail)
        {
            AddNote(notes, detail);
            structuredNotes?.Add(new(status, reason, detail));
        }
        Stack<(string Path, int Depth)> pending = new();
        pending.Push((root, 0));
        int visited = 0;
        while (pending.TryPop(out var next))
        {
            token.ThrowIfCancellationRequested();
            if (!IsLocalSafePath(next.Path)) { Note(DiagnosticReadStatus.NotChecked, ReasonCodes.UnsafePath, MessageText.Create("Backend.Core.ContentDiscovery.Files.01", (next.Path))); continue; }
            string[] entries;
            try { entries = Directory.EnumerateFileSystemEntries(next.Path).Take(Math.Max(0, maximumEntries - visited) + 1).ToArray(); }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            { Note(ex is UnauthorizedAccessException ? DiagnosticReadStatus.AccessDenied : DiagnosticReadStatus.Failed, ReasonCodes.ForFailureType(ex.GetType().Name), MessageText.Create("Backend.Core.ContentDiscovery.Files.02", (next.Path), (MessageExceptions.Describe(ex)))); continue; }
            foreach (string entry in entries)
            {
                token.ThrowIfCancellationRequested();
                if (++visited > maximumEntries) { Note(DiagnosticReadStatus.LimitReached, ReasonCodes.ResourceLimit, MessageText.Create("Backend.Core.ContentDiscovery.Files.03", (maximumEntries), (root))); yield break; }
                if (!IsLocalSafePath(entry)) { Note(DiagnosticReadStatus.NotChecked, ReasonCodes.UnsafePath, MessageText.Create("Backend.Core.ContentDiscovery.Files.04", (entry))); continue; }
                if (Directory.Exists(entry))
                {
                    if (next.Depth >= maximumDepth) Note(DiagnosticReadStatus.LimitReached, ReasonCodes.ResourceLimit, MessageText.Create("Backend.Core.ContentDiscovery.Files.05", (entry)));
                    else pending.Push((entry, next.Depth + 1));
                }
                else if (File.Exists(entry)) yield return entry;
            }
        }
    }

    public static void Populate(SteamLayout layout)
    {
        MessageTextCollection notes = [];
        layout.ContentRoots.Clear();
        layout.Games.Clear();
        foreach (string library in layout.LibraryRoots)
        {
            string workshop = System.IO.Path.Combine(library, "steamapps", "workshop", "content");
            foreach (string appRoot in Children(workshop, true, notes))
            {
                string appId = System.IO.Path.GetFileName(appRoot);
                if (!IsNumericId(appId)) continue;
                Add(appRoot, layout.WorkshopRoots);
                layout.ContentRoots.Add(new(appRoot, appId, "workshop", appId switch
                {
                    "431960" => (MessageText)"Wallpaper Engine",
                    VPetDiscovery.AppId => (MessageText)"VPet Simulator",
                    _ => MessageText.Create("Backend.Core.ContentDiscovery.Populate.01", (appId))
                }));
            }
            string projects = System.IO.Path.Combine(library, "steamapps", "common", "wallpaper_engine", "projects");
            Add(projects, layout.WallpaperProjectRoots);
            if (Directory.Exists(projects) && IsLocalSafePath(projects)) layout.ContentRoots.Add(new(projects, "431960", "local-wallpaper", MessageText.Create("Backend.Core.ContentDiscovery.Populate.02")));
            foreach (string manifest in Children(System.IO.Path.Combine(library, "steamapps"), false, notes))
            {
                if (!System.IO.Path.GetFileName(manifest).StartsWith("appmanifest_", StringComparison.OrdinalIgnoreCase) ||
                    !manifest.EndsWith(".acf", StringComparison.OrdinalIgnoreCase)) continue;
                try
                {
                    if (new FileInfo(manifest).Length > 1024 * 1024) { notes.AddText(MessageText.Create("Backend.Core.ContentDiscovery.Populate.03", (manifest))); continue; }
                    var values = Pair.Matches(File.ReadAllText(manifest)).Cast<Match>().GroupBy(m => m.Groups["key"].Value, StringComparer.OrdinalIgnoreCase)
                        .ToDictionary(g => g.Key, g => g.Last().Groups["value"].Value, StringComparer.OrdinalIgnoreCase);
                    if (!values.TryGetValue("appid", out string? appId) || !IsNumericId(appId) ||
                        !values.TryGetValue("installdir", out string? dir) || string.IsNullOrWhiteSpace(dir) ||
                        dir.IndexOfAny(['\\', '/', ':']) >= 0 || dir is "." or "..") continue;
                    string common = System.IO.Path.Combine(library, "steamapps", "common");
                    string game = System.IO.Path.Combine(common, dir);
                    if (!IsLocalSafePath(game) || !Directory.Exists(game) || !IsWithin(game, common)) continue;
                    string name = values.GetValueOrDefault("name", dir);
                    layout.Games.Add(new(appId, name, game));
                    string[] modPaths = appId == VPetDiscovery.AppId
                        ? [VPetDiscovery.ModDirectoryName, "Mods", "BepInEx/plugins"]
                        : appId == "3167020" || dir.Contains("Duckov", StringComparison.OrdinalIgnoreCase)
                        ? ["Duckov_Data/Mods", "Mods", "BepInEx/plugins"]
                        : ["Mods", "BepInEx/plugins"];
                    foreach (string relative in modPaths)
                    {
                        string mod = System.IO.Path.Combine(game, relative.Replace('/', System.IO.Path.DirectorySeparatorChar));
                        if (Directory.Exists(mod) && IsLocalSafePath(mod))
                            layout.ContentRoots.Add(new(mod, appId, "mod", name));
                    }
                }
                catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException or RegexMatchTimeoutException)
                { notes.AddText(MessageText.Create("Backend.Core.ContentDiscovery.Populate.04", (manifest), (MessageExceptions.Describe(ex)))); }
            }
        }
        foreach (string steam in layout.SteamRoots)
        {
            string plugins = System.IO.Path.Combine(steam, "millennium", "plugins");
            if (Directory.Exists(plugins) && IsLocalSafePath(plugins)) layout.ContentRoots.Add(new(plugins, "", "plugin", MessageText.Create("Backend.Core.ContentDiscovery.Populate.05")));
        }
        string localMods = System.IO.Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "AppData", "LocalLow", "TeamSoda", "Duckov", "Mods");
        if (Directory.Exists(localMods) && IsLocalSafePath(localMods)) layout.ContentRoots.Add(new(localMods, "3167020", "mod", MessageText.Create("Backend.Core.ContentDiscovery.Populate.06")));
        foreach (MessageText note in notes.Texts) layout.AddDiscoveryNote(note);
    }

    private static void AddNote(List<string> notes, MessageText detail)
    {
        if (notes is MessageTextCollection messages) messages.AddText(detail);
        else notes.Add(detail.OriginalText);
    }

    private static void Add(string path, ICollection<string> output)
    {
        if (Directory.Exists(path) && IsLocalSafePath(path) && !output.Contains(path, StringComparer.OrdinalIgnoreCase)) output.Add(path);
    }

    public static string WorkshopAppId(string root) => IsNumericId(System.IO.Path.GetFileName(root)) ? System.IO.Path.GetFileName(root) : "";
    public static bool IsWorkshopContentPath(string path)
    {
        if (!IsLocalSafePath(path)) return false;
        string[] parts = System.IO.Path.GetFullPath(path).Replace('/', '\\').Split('\\', StringSplitOptions.RemoveEmptyEntries);
        for (int i = 0; i + 4 < parts.Length; i++)
            if (parts[i].Equals("steamapps", StringComparison.OrdinalIgnoreCase) &&
                parts[i + 1].Equals("workshop", StringComparison.OrdinalIgnoreCase) &&
                parts[i + 2].Equals("content", StringComparison.OrdinalIgnoreCase) &&
                IsNumericId(parts[i + 3]) && IsNumericId(parts[i + 4])) return true;
        return false;
    }
}
