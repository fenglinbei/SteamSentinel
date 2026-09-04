using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using SteamSentinel.Core.Inspection;
using SteamSentinel.Core.Scanning;
using SteamSentinel.Core.Utilities;

namespace SteamSentinel.Core.Remediation;

/// <summary>Raw bytes only. Caller must keep its identity-checked lease open until the mutation finishes.</summary>
public static class BoundContentEvidence
{
    public const long MaximumBytes = 8L * 1024 * 1024;

    // Intentionally not a shell parser. Ambiguous/indirect syntax must be reviewed, never guessed.
    public static bool IsDirectInvocation(string command, string target)
    {
        if (command.Length > 32768 || command.Count(character => character == '"') % 2 != 0 ||
            command.Any(character => char.IsControl(character) && character != '\t') ||
            command.IndexOfAny(['&', '|', ';', '`', '>', '<', '\'']) >= 0) return false;
        Match[] parts = Regex.Matches(command.Trim(), "\"[^\"]*\"|[^\\s\"]+", RegexOptions.CultureInvariant,
            TimeSpan.FromMilliseconds(100)).ToArray();
        for (int index = 1; index < parts.Length; index++)
            if (parts[index].Index == parts[index - 1].Index + parts[index - 1].Length) return false;
        string[] arguments = parts.Select(match => match.Value.Trim('"')).ToArray();
        if (arguments.Length == 0) return false;
        bool Same(string value) => Path.IsPathFullyQualified(value) &&
            string.Equals(Path.GetFullPath(value), Path.GetFullPath(target), StringComparison.OrdinalIgnoreCase);
        if (Same(arguments[0])) return true;
        string host = Path.GetFileName(arguments[0]).ToLowerInvariant();
        if (host is "powershell.exe" or "powershell" or "pwsh.exe" or "pwsh")
        {
            int index = 1;
            while (index < arguments.Length)
            {
                string option = arguments[index++].ToLowerInvariant();
                if (option == "-file") return index < arguments.Length && Same(arguments[index]);
                if (option is "-noprofile" or "-noninteractive" or "-nologo") continue;
                if (option == "-executionpolicy" && index < arguments.Length) { index++; continue; }
                return false;
            }
            return false;
        }
        if (host is "wscript.exe" or "cscript.exe" or "python.exe" or "pythonw.exe" or "python" or "node.exe" or "node")
        {
            int index = 1;
            while (index < arguments.Length && (arguments[index].Equals("//B", StringComparison.OrdinalIgnoreCase) ||
                arguments[index].Equals("//Nologo", StringComparison.OrdinalIgnoreCase))) index++;
            return index < arguments.Length && Same(arguments[index]);
        }
        return false;
    }

    public static async Task<string?> VerifyAsync(string path, string expectedSha256, CancellationToken token = default)
    {
        if (!Validation.IsHexSha256(expectedSha256) || Validation.ContainsReparsePoint(path)) return null;
        await using FileStream stream = new(path, FileMode.Open, FileAccess.Read, FileShare.Read | FileShare.Delete,
            64 * 1024, FileOptions.Asynchronous | FileOptions.SequentialScan);
        if (stream.Length > MaximumBytes) return null;
        using IncrementalHash hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        byte[] buffer = new byte[64 * 1024 + 256];
        HashSet<string> tokens = new(StringComparer.OrdinalIgnoreCase);
        int retained = 0;
        long total = 0;
        bool headerChecked = false;
        while (true)
        {
            int read = await stream.ReadAsync(buffer.AsMemory(retained, 64 * 1024), token).ConfigureAwait(false);
            if (read == 0) break;
            hash.AppendData(buffer, retained, read);
            total += read;
            if (total > MaximumBytes) return null;
            int count = read + retained;
            if (!headerChecked)
            {
                FileTypeResult kind = FileTypeDetector.Detect(buffer.AsSpan(0, count), Path.GetExtension(path));
                if (kind.IsArchive || kind.Type is DetectedFileType.CompoundDocument or DetectedFileType.Shortcut) return null;
                headerChecked = true;
            }
            Inspect(Encoding.UTF8.GetString(buffer, 0, count));
            int alignment = (int)((total - count) & 1);
            Inspect(Encoding.Unicode.GetString(buffer, alignment, (count - alignment) & ~1));
            retained = Math.Min(256, count);
            Buffer.BlockCopy(buffer, count - retained, buffer, 0, retained);
        }
        if (!Convert.ToHexString(hash.GetHashAndReset()).Equals(expectedSha256, StringComparison.OrdinalIgnoreCase)) return null;
        HeuristicMatch? proof = ContentHeuristics.Match(tokens.Contains, path);
        return proof?.Id is "HEUR-STEAM-UI-PATCHER" or "HEUR-STEAM-TOKEN-STEALER" or "HEUR-STEAM-CREDENTIAL-PLUGIN" ? proof.Id : null;

        void Inspect(string text)
        {
            foreach (string needle in ContentHeuristics.Tokens)
                if (text.Contains(needle, StringComparison.OrdinalIgnoreCase)) tokens.Add(needle);
        }
    }
}
