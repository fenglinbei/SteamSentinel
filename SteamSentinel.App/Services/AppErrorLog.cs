using System.IO;
using System.Text;
using System.Runtime.InteropServices;
using System.Text.RegularExpressions;
using SteamSentinel.Core.Inspection;
using SteamSentinel.Core.Models;
using SteamSentinel.Core.Utilities;

namespace SteamSentinel.App.Services;

internal static class AppErrorLog
{
    internal const int MaximumReportBytes = 128 * 1024;
    private const int MaximumExceptions = 64;
    private static readonly UTF8Encoding ReportEncoding = new(false);
    private static readonly Regex HeaderSecret = new(
        @"(?im)(authorization\s*[:=]\s*|cookie\s*[:=]\s*|(?:api[_-]?key|client[_-]?secret)\s*[:=]\s*)[^\r\n]+",
        RegexOptions.CultureInvariant, TimeSpan.FromMilliseconds(100));
    [ThreadStatic] private static bool _writing;

    internal static string Format(string stage, Exception error)
    {
        string text = FormatReport(stage, error, null);
        return text[..Math.Min(text.Length, 16_384)];
    }

    internal static string FormatReport(string stage, Exception error, string? directory, string? alternateStartupDirectory = null)
    {
        StringBuilder report = new();
        report.AppendLine("SteamSentinel local error report / 1");
        report.AppendLine($"UTC: {DateTimeOffset.UtcNow:O}");
        report.AppendLine($"Version: {ProductInfo.Version}");
        report.AppendLine($"BuildIdentity: {ProductInfo.BuildIdentity}");
        report.AppendLine($"Stage: {Redact(stage, 256)}");
        report.AppendLine($"Runtime: {RuntimeInformation.FrameworkDescription}; CLR {Environment.Version}");
        report.AppendLine($"OS: {RuntimeInformation.OSDescription}; {Environment.OSVersion.Version}");
        report.AppendLine($"Architecture: OS={RuntimeInformation.OSArchitecture}; Process={RuntimeInformation.ProcessArchitecture}");
        string? processPath = Environment.ProcessPath;
        report.AppendLine($"Process: {Redact(Path.GetFileName(processPath) ?? "unknown", 256)}");
        bool identified = false;
        foreach (StartupRole role in Enum.GetValues<StartupRole>())
        {
            if (!StartupCompatibility.TryIdentifyHost(processPath, role, out StartupMode mode, out bool unified)) continue;
            report.AppendLine($"Startup: role={StartupCompatibility.RoleName(role)}; mode={StartupCompatibility.ModeName(mode)}; unified={unified}");
            identified = true;
            break;
        }
        if (!identified) report.AppendLine("Startup: role=unknown; mode=unknown (development/test host)");
        report.AppendLine("Collection: local only; no automatic upload; no environment-variable dump, exception Data or scanned-file content.");
        report.AppendLine();
        report.AppendLine("Recent native startup reports (path references only):");
        try
        {
            string[] recent = FindRecentStartupReports(directory, alternateStartupDirectory);
            if (recent.Length == 0) report.AppendLine("(none found)");
            foreach (string path in recent) report.AppendLine(Redact(path, 4096));
        }
        catch { report.AppendLine("(startup report index unavailable)"); }
        report.AppendLine();
        report.AppendLine("Exception chain (bounded; messages and stacks are redacted):");
        Queue<(Exception Error, string Link)> pending = new();
        HashSet<Exception> seen = new(ReferenceEqualityComparer.Instance);
        pending.Enqueue((error, "root"));
        while (pending.Count > 0 && seen.Count < MaximumExceptions && report.Length < MaximumReportBytes)
        {
            (Exception current, string link) = pending.Dequeue();
            if (!seen.Add(current)) continue;
            report.AppendLine($"[{seen.Count}] {link}: {current.GetType().FullName}; HResult=0x{current.HResult:X8}");
            report.AppendLine("Message: " + ReadExceptionField(() => current.Message, 4096));
            report.AppendLine("Stack: " + ReadExceptionField(() => current.StackTrace, 16_384));
            if (current is AggregateException aggregate)
            {
                int take = Math.Min(aggregate.InnerExceptions.Count, MaximumExceptions - seen.Count);
                for (int i = 0; i < take; i++) pending.Enqueue((aggregate.InnerExceptions[i], $"inner[{i}] of {seen.Count}"));
                if (take != aggregate.InnerExceptions.Count) report.AppendLine("[additional aggregate exceptions omitted]");
            }
            else if (current.InnerException is { } inner) pending.Enqueue((inner, $"inner of {seen.Count}"));
        }
        if (pending.Count > 0) report.AppendLine("[additional exceptions omitted by report limit]");
        return LimitUtf8(report.ToString(), MaximumReportBytes);
    }

    private static string[] FindRecentStartupReports(params string?[] directories)
    {
        // Enumerate metadata only and retain two candidates. Truncating the enumeration before
        // sorting could hide the newest report after the application has been started many times.
        List<(DateTime Timestamp, string Path)> recent = new(3);
        foreach (string directory in directories.Where(path => path is not null).Cast<string>().Distinct(StringComparer.OrdinalIgnoreCase))
        {
            if (!Directory.Exists(directory) || Validation.ContainsReparsePoint(directory)) continue;
            foreach (string path in Directory.EnumerateFiles(directory, "startup-*.txt", SearchOption.TopDirectoryOnly))
            {
                try
                {
                    if ((File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0) continue;
                    recent.Add((File.GetLastWriteTimeUtc(path), path));
                    recent.Sort((left, right) =>
                    {
                        int time = right.Timestamp.CompareTo(left.Timestamp);
                        return time != 0 ? time : StringComparer.OrdinalIgnoreCase.Compare(right.Path, left.Path);
                    });
                    if (recent.Count > 2) recent.RemoveAt(2);
                }
                catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { }
            }
        }
        return recent.Select(item => item.Path).ToArray();
    }

    private static string ReadExceptionField(Func<string?> read, int limit)
    {
        try { return Redact(read() ?? "(not available)", limit); }
        catch { return "(exception field unavailable)"; }
    }

    private static string Redact(string text, int limit)
    {
        bool truncated = text.Length > limit;
        string bounded = text[..Math.Min(text.Length, limit)];
        string redacted = ScriptSignals.RedactSecrets(bounded);
        try { redacted = HeaderSecret.Replace(redacted, "$1[REDACTED]"); }
        catch (RegexMatchTimeoutException) { return "[redacted: pattern timeout]"; }
        string profile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        if (!string.IsNullOrWhiteSpace(profile)) redacted = redacted.Replace(profile, "[USERPROFILE]", StringComparison.OrdinalIgnoreCase);
        return redacted + (truncated ? " [truncated]" : string.Empty);
    }

    private static string LimitUtf8(string text, int maximumBytes)
    {
        if (ReportEncoding.GetByteCount(text) <= maximumBytes) return text;
        const string suffix = "\n[report truncated at UTF-8 byte limit]\n";
        int budget = maximumBytes - ReportEncoding.GetByteCount(suffix);
        int low = 0, high = text.Length;
        while (low < high)
        {
            int mid = low + (high - low + 1) / 2;
            if (ReportEncoding.GetByteCount(text.AsSpan(0, mid)) <= budget) low = mid;
            else high = mid - 1;
        }
        if (low > 0 && char.IsHighSurrogate(text[low - 1])) low--;
        return text[..low] + suffix;
    }

    internal static string? Write(string stage, Exception error, string? directoryOverride = null)
    {
        if (_writing) return null;
        _writing = true;
        try
        {
            string directory = directoryOverride ?? Path.Combine(AppPaths.UserStateRoot, "Logs");
            string? alternateStartup = directoryOverride is null ? Path.Combine(Path.GetTempPath(), "SteamSentinel-Startup-Reports") : null;
            string? path = WriteInDirectory(stage, error, directory, directory, alternateStartup);
            if (path is not null || directoryOverride is not null) return path;
            return WriteInDirectory(stage, error, Path.Combine(Path.GetTempPath(), "SteamSentinel-Error-Reports"), directory, alternateStartup);
        }
        catch { return null; /* Best effort only; reporting must not cause another unhandled exception. */ }
        finally { _writing = false; }
    }

    private static string? WriteInDirectory(string stage, Exception error, string directory, string startupDirectory, string? alternateStartupDirectory)
    {
        try
        {
            if (Validation.ContainsReparsePoint(directory)) return null;
            Directory.CreateDirectory(directory);
            if (Validation.ContainsReparsePoint(directory) || Directory.EnumerateFiles(directory, "error-*.log").Take(50).Count() >= 50) return null;
            string report = FormatReport(stage, error, startupDirectory, alternateStartupDirectory);
            string path = Path.Combine(directory, $"error-{DateTime.UtcNow:yyyyMMdd-HHmmss}-{Guid.NewGuid():N}.log");
            using FileStream stream = new(path, FileMode.CreateNew, FileAccess.Write, FileShare.Read);
            using StreamWriter writer = new(stream, ReportEncoding);
            writer.Write(report);
            writer.Flush();
            return path;
        }
        catch { return null; }
    }
}
