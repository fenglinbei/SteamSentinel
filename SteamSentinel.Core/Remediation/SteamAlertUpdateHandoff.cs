using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using SteamSentinel.Core.Utilities;

namespace SteamSentinel.Core.Remediation;

public sealed record SteamAlertUpdateHandoffDescriptor(string ScriptPath, int WaitProcessId, string TargetExe, string StagedExe, string BackupExe);
public sealed record SteamAlertUpdatePayloadProof(string Path, string Sha256);
public sealed record SteamAlertUpdateHandoffProof(SteamAlertUpdateHandoffDescriptor Descriptor, string ScriptSha256,
    IReadOnlyList<SteamAlertUpdatePayloadProof> Payloads);

/// <summary>
/// Exact, non-executing recognition of the reviewed resident's temporary update script.
/// A matching template alone is not malware evidence: VerifyAsync also binds a resident payload's bytes.
/// </summary>
public static class SteamAlertUpdateHandoff
{
    public const string ScriptHostKind = "SteamAlertUpdateHandoff";
    public const string RuleId = "STEAMALERT-UPDATE-HANDOFF";
    public const int MaximumScriptBytes = 64 * 1024;
    private const int MaximumPayloadBytes = 32 * 1024 * 1024;
    private static readonly Regex Command = new("^[ \\t]*(?:\"(?<host>[^\"\\r\\n]+)\"|(?<host>[^\\s\"\\r\\n]+))[ \\t]+/c[ \\t]+\"(?<path>[^\"\\r\\n]+)\"[ \\t]*$",
        RegexOptions.CultureInvariant | RegexOptions.IgnoreCase | RegexOptions.ExplicitCapture, TimeSpan.FromMilliseconds(100));

    public static bool IsTrustedImagePath(string? path)
    {
        if (!IsSafePath(path)) return false;
        string windows = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        if (string.IsNullOrWhiteSpace(windows) || !new[] { "System32", "SysWOW64" }.Any(system =>
            path!.Equals(Path.Combine(windows, system, "cmd.exe"), StringComparison.OrdinalIgnoreCase))) return false;
        try { return !Validation.ContainsReparsePoint(path!); }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException or ArgumentException) { return false; }
    }

    public static bool TryParseCommandLine(string? commandLine, [NotNullWhen(true)] out string? scriptPath)
    {
        scriptPath = null;
        if (string.IsNullOrWhiteSpace(commandLine) || commandLine.Length > 32768 ||
            commandLine.Any(character => char.IsControl(character) && character != '\t')) return false;
        Match match = Command.Match(commandLine);
        if (!match.Success) return false;
        string host = match.Groups["host"].Value, path = match.Groups["path"].Value;
        if (!host.Equals("cmd.exe", StringComparison.OrdinalIgnoreCase) && !IsTrustedImagePath(host)) return false;
        if (!IsSafePath(path) || !TryFilePid(path, out _)) return false;
        scriptPath = path;
        return true;
    }

    public static bool TryParse(byte[] bytes, string path, [NotNullWhen(true)] out SteamAlertUpdateHandoffDescriptor? descriptor)
    {
        descriptor = null;
        if (bytes.Length == 0 || bytes.Length > MaximumScriptBytes) return false;
        try
        {
            // The reviewed .NET Framework resident uses Encoding.Default. A BOM explicitly identifies UTF-8;
            // otherwise use Windows' actual ANSI code page, not the UI culture or the agent's shell encoding.
            string text;
            if (bytes.AsSpan().StartsWith(new byte[] { 0xEF, 0xBB, 0xBF })) text = new UTF8Encoding(false, true).GetString(bytes.AsSpan(3));
            else
            {
                int codePage = OperatingSystem.IsWindows() ? checked((int)GetACP()) : 65001;
                Encoding? encoding = codePage == 65001 ? new UTF8Encoding(false, true) :
                    CodePagesEncodingProvider.Instance.GetEncoding(codePage, EncoderFallback.ExceptionFallback, DecoderFallback.ExceptionFallback);
                if (encoding is null) return false;
                text = encoding.GetString(bytes);
            }
            return TryParse(text, path, out descriptor);
        }
        catch (Exception error) when (error is ArgumentException or DecoderFallbackException or OverflowException) { return false; }
    }

    public static bool TryParse(string text, string path, [NotNullWhen(true)] out SteamAlertUpdateHandoffDescriptor? descriptor)
    {
        descriptor = null;
        if (text.Length == 0 || text.Length > MaximumScriptBytes || !IsSafePath(path) || !TryFilePid(path, out int filePid)) return false;
        string[] lines = text.Split("\r\n", StringSplitOptions.None);
        if (lines.Length != 23) return false;
        const string waitPrefix = "tasklist /FI \"PID eq ";
        if (!lines[3].StartsWith(waitPrefix, StringComparison.Ordinal)) return false;
        int quote = lines[3].IndexOf('"', waitPrefix.Length);
        if (quote <= waitPrefix.Length || !int.TryParse(lines[3][waitPrefix.Length..quote], NumberStyles.None,
            CultureInfo.InvariantCulture, out int waitPid) || waitPid != filePid) return false;
        string[] backupCopy = lines[8].Split('"'), installCopy = lines[9].Split('"');
        if (backupCopy.Length != 5 || installCopy.Length != 5) return false;
        string target = backupCopy[1], backup = backupCopy[3], staged = installCopy[1];
        if (!IsSafePath(target) || !IsSafePath(backup) || !IsSafePath(staged) ||
            !Path.GetExtension(target).Equals(".exe", StringComparison.OrdinalIgnoreCase) ||
            !Path.GetFileName(staged).Equals("Application Frame Host.new.exe", StringComparison.OrdinalIgnoreCase) ||
            !backup.Equals(target + ".bak", StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(Path.GetDirectoryName(target), Path.GetDirectoryName(staged), StringComparison.OrdinalIgnoreCase) ||
            target.Equals(staged, StringComparison.OrdinalIgnoreCase)) return false;
        SteamAlertUpdateHandoffDescriptor candidate = new(path, waitPid, target, staged, backup);
        if (!text.Equals(CreateTemplate(candidate), StringComparison.Ordinal)) return false;
        descriptor = candidate;
        return true;
    }

    public static async Task<SteamAlertUpdateHandoffProof?> VerifyAsync(string path, string expectedHash, CancellationToken token = default)
    {
        if (!Validation.IsHexSha256(expectedHash) || !IsSafePath(path)) return null;
        try
        {
            if (Validation.ContainsReparsePoint(path)) return null;
            byte[]? bytes = await ReadBoundedAsync(path, MaximumScriptBytes, token).ConfigureAwait(false);
            if (bytes is null || !Convert.ToHexString(SHA256.HashData(bytes)).Equals(expectedHash, StringComparison.OrdinalIgnoreCase) ||
                !TryParse(bytes, path, out SteamAlertUpdateHandoffDescriptor? descriptor)) return null;
            List<SteamAlertUpdatePayloadProof> payloads = [];
            foreach (string payload in new[] { descriptor.TargetExe, descriptor.StagedExe, descriptor.BackupExe })
            {
                token.ThrowIfCancellationRequested();
                try
                {
                    if (Validation.ContainsReparsePoint(payload)) continue;
                    byte[]? content = await ReadBoundedAsync(payload, MaximumPayloadBytes, token).ConfigureAwait(false);
                    if (content is null) continue;
                    string hash = Convert.ToHexString(SHA256.HashData(content));
                    if (SteamAlertWatchdog.RoleForHash(hash) == SteamAlertWatchdog.PayloadRole) payloads.Add(new(payload, hash));
                }
                catch (Exception error) when (error is IOException or UnauthorizedAccessException or ArgumentException) { }
            }
            return payloads.Count == 0 ? null : new(descriptor, expectedHash.ToUpperInvariant(), payloads.AsReadOnly());
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException or ArgumentException) { return null; }
    }

    private static async Task<byte[]?> ReadBoundedAsync(string path, int maximum, CancellationToken token)
    {
        await using FileStream stream = new(path, FileMode.Open, FileAccess.Read, FileShare.Read | FileShare.Delete, 64 * 1024,
            FileOptions.Asynchronous | FileOptions.SequentialScan);
        if (stream.Length <= 0 || stream.Length > maximum) return null;
        byte[] bytes = new byte[checked((int)stream.Length)];
        await stream.ReadExactlyAsync(bytes, token).ConfigureAwait(false);
        if (stream.Position != stream.Length) return null;
        return bytes;
    }

    private static bool TryFilePid(string path, out int processId)
    {
        processId = 0;
        string name = Path.GetFileName(path);
        if (!name.StartsWith("sa_update_", StringComparison.OrdinalIgnoreCase) || !name.EndsWith(".cmd", StringComparison.OrdinalIgnoreCase)) return false;
        string digits = name[10..^4];
        return int.TryParse(digits, NumberStyles.None, CultureInfo.InvariantCulture, out processId) && processId > 4 &&
            digits.Equals(processId.ToString(CultureInfo.InvariantCulture), StringComparison.Ordinal);
    }

    private static bool IsSafePath(string? path)
    {
        if (string.IsNullOrWhiteSpace(path) || path.Length < 4 || path.Length > 32767 || !char.IsAsciiLetter(path[0]) ||
            path[1] != ':' || path[2] != '\\' || path.Any(char.IsControl) ||
            path.IndexOfAny(['/', '*', '?', '"', '<', '>', '|', '&', '^', '%', '!', '(', ')']) >= 0 || path[2..].Contains(':')) return false;
        try
        {
            if (!Path.GetFullPath(path).Equals(path, StringComparison.OrdinalIgnoreCase)) return false;
            return path[3..].Split('\\').All(segment => segment.Length > 0 && segment is not ("." or "..") &&
                !segment.EndsWith('.') && !segment.EndsWith(' ') && !IsDeviceSegment(segment));
        }
        catch (Exception error) when (error is ArgumentException or NotSupportedException or PathTooLongException) { return false; }
    }

    private static bool IsDeviceSegment(string segment)
    {
        string stem = segment.Split('.')[0].ToUpperInvariant();
        return stem is "CON" or "PRN" or "AUX" or "NUL" or "CLOCK$" ||
            (stem.Length == 4 && stem[3] is >= '1' and <= '9' && (stem.StartsWith("COM", StringComparison.Ordinal) || stem.StartsWith("LPT", StringComparison.Ordinal)));
    }

    internal static string CreateTemplate(SteamAlertUpdateHandoffDescriptor item) =>
        "@echo off\r\nsetlocal enableextensions\r\n:wait\r\ntasklist /FI \"PID eq " + item.WaitProcessId.ToString(CultureInfo.InvariantCulture) +
        "\" 2>nul | find \"" + item.WaitProcessId.ToString(CultureInfo.InvariantCulture) +
        "\" >nul\r\nif not errorlevel 1 (\r\n  timeout /t 1 /nobreak >nul\r\n  goto wait\r\n)\r\ncopy /Y \"" + item.TargetExe + "\" \"" + item.BackupExe +
        "\" >nul\r\ncopy /Y \"" + item.StagedExe + "\" \"" + item.TargetExe +
        "\" >nul\r\nif errorlevel 1 goto fail\r\nstart \"\" \"" + item.TargetExe +
        "\"\r\nif errorlevel 1 goto fail\r\ndel \"" + item.StagedExe +
        "\" >nul\r\ndel \"%~f0\" >nul\r\nexit /b 0\r\n:fail\r\ncopy /Y \"" + item.BackupExe + "\" \"" + item.TargetExe +
        "\" >nul\r\nstart \"\" \"" + item.TargetExe + "\"\r\ndel \"" + item.StagedExe + "\" >nul\r\ndel \"%~f0\" >nul\r\nexit /b 1\r\n";

    [DllImport("kernel32.dll")]
    private static extern uint GetACP();
}
