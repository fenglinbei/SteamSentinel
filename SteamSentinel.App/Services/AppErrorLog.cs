using System.IO;
using System.Text;
using SteamSentinel.Core.Inspection;
using SteamSentinel.Core.Models;
using SteamSentinel.Core.Utilities;

namespace SteamSentinel.App.Services;

internal static class AppErrorLog
{
    internal static string Format(string stage, Exception error)
    {
        string text = ScriptSignals.Redact($"SteamSentinel {ProductInfo.Version}\nUTC: {DateTimeOffset.UtcNow:O}\nStage: {stage}\n{error}");
        return text[..Math.Min(text.Length, 16_384)];
    }

    internal static void Write(string stage, Exception error)
    {
        try
        {
            string directory = Path.Combine(AppPaths.UserStateRoot, "Logs");
            if (Validation.ContainsReparsePoint(directory)) return;
            Directory.CreateDirectory(directory);
            if (Validation.ContainsReparsePoint(directory) || Directory.EnumerateFiles(directory, "error-*.log").Take(50).Count() >= 50) return;
            string path = Path.Combine(directory, $"error-{DateTime.UtcNow:yyyyMMdd-HHmmss}-{Guid.NewGuid():N}.log");
            using FileStream stream = new(path, FileMode.CreateNew, FileAccess.Write, FileShare.Read);
            using StreamWriter writer = new(stream, new UTF8Encoding(false));
            writer.Write(Format(stage, error));
        }
        catch { /* Best effort only, never overwrite results or existing logs. */ }
    }
}
