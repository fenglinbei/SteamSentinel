using System.Buffers;
using System.Text;
using SteamSentinel.Core.Inspection;

namespace SteamSentinel.Core.Scanning;

/// <summary>Accumulates matched signals, never the full decoded file. No script execution.</summary>
internal static class StreamingStringInspection
{
    internal const int ChunkBytes = 256 * 1024;
    // Covers bounded Base64 expressions and literal joins in ScriptSignals, in either encoding.
    private const int OverlapBytes = 144 * 1024;

    internal static async Task<(HashSet<string> Raw, HashSet<string> Script)> ReadAsync(
        string path, IEnumerable<string> ruleTokens, IEnumerable<string> domainTokens, long limit, CancellationToken token)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(limit);
        HashSet<string> domains = domainTokens.Where(value => !string.IsNullOrWhiteSpace(value))
            .ToHashSet(StringComparer.OrdinalIgnoreCase);
        string[] needles = ruleTokens.Concat(domains).Concat(ContentHeuristics.Tokens)
            .Where(value => !string.IsNullOrWhiteSpace(value)).Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
        HashSet<string> raw = new(StringComparer.OrdinalIgnoreCase), script = new(StringComparer.OrdinalIgnoreCase);
        byte[] buffer = ArrayPool<byte>.Shared.Rent(ChunkBytes + OverlapBytes);
        try
        {
            await using FileStream stream = new(path, FileMode.Open, FileAccess.Read, FileShare.Read, 64 * 1024,
                FileOptions.Asynchronous | FileOptions.SequentialScan);
            long total = 0;
            int retained = 0;
            while (true)
            {
                token.ThrowIfCancellationRequested();
                int read = await stream.ReadAsync(buffer.AsMemory(retained, (int)Math.Min(ChunkBytes, limit - total + 1)), token);
                if (read == 0) break;
                total += read;
                if (total > limit) throw new InvalidDataException("文件在读取期间超过文本检查上限。");
                int count = retained + read;
                Inspect(Encoding.UTF8.GetString(buffer, 0, count));
                // Preserve UTF-16LE byte alignment even if the stream returns a short, odd-sized read.
                int alignment = (int)((total - count) & 1);
                Inspect(Encoding.Unicode.GetString(buffer, alignment, (count - alignment) & ~1));
                Inspect(Encoding.BigEndianUnicode.GetString(buffer, alignment, (count - alignment) & ~1));
                retained = Math.Min(OverlapBytes, count);
                Buffer.BlockCopy(buffer, count - retained, buffer, 0, retained);
            }
            return (raw, script);
        }
        finally { ArrayPool<byte>.Shared.Return(buffer, clearArray: true); }

        void Inspect(string text)
        {
            foreach (string needle in needles)
                if (!raw.Contains(needle) && (domains.Contains(needle)
                        ? ContainsDomain(text, needle)
                        : text.Contains(needle, StringComparison.OrdinalIgnoreCase))) raw.Add(needle);
            string normalized = ScriptSignals.Normalize(text);
            foreach (string needle in ScriptSignals.Tokens)
                if (!script.Contains(needle) && normalized.Contains(needle, StringComparison.OrdinalIgnoreCase)) script.Add(needle);
        }
    }

    private static bool ContainsDomain(string text, string domain)
    {
        int start = 0;
        while (start <= text.Length - domain.Length)
        {
            int index = text.IndexOf(domain, start, StringComparison.OrdinalIgnoreCase);
            if (index < 0) return false;
            bool left = index == 0 || text[index - 1] == '.' || !IsDomainCharacter(text[index - 1]);
            int end = index + domain.Length;
            bool right = end == text.Length || !IsDomainCharacter(text[end]);
            if (left && right) return true;
            start = index + 1;
        }
        return false;
    }

    private static bool IsDomainCharacter(char value) => char.IsAsciiLetterOrDigit(value) || value is '-' or '.';
}
