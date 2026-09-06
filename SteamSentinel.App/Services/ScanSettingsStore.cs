using System.Text.Json;
using SteamSentinel.Core.Models;
using SteamSentinel.Core.Utilities;

namespace SteamSentinel.App.Services;

internal static class ScanSettingsStore
{
    internal static string DefaultPath => Path.Combine(AppPaths.UserStateRoot, "scan-limits.json");

    internal static ScanLimitSettings Load(string path)
    {
        if (!File.Exists(path)) return new();
        if (new FileInfo(path).Length > 128 * 1024) throw new InvalidDataException("扫描设置文件过大。");
        ScanLimitSettings value = JsonSerializer.Deserialize<ScanLimitSettings>(File.ReadAllText(path))
            ?? throw new InvalidDataException("扫描设置为空。");
        value.Validate();
        return value;
    }

    internal static void Save(string path, ScanLimitSettings value)
    {
        value.Validate();
        string full = Path.GetFullPath(path);
        Directory.CreateDirectory(Path.GetDirectoryName(full)!);
        string temporary = full + "." + Guid.NewGuid().ToString("N") + ".tmp";
        try
        {
            File.WriteAllText(temporary, JsonSerializer.Serialize(value, new JsonSerializerOptions { WriteIndented = true }));
            File.Move(temporary, full, overwrite: true);
        }
        finally { if (File.Exists(temporary)) File.Delete(temporary); }
    }
}
