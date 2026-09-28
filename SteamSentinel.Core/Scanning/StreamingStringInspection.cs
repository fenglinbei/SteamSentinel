using SteamSentinel.Core.Reporting;
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

    internal sealed record TokenObservation(string Token, long WindowByteOffset, string Encoding, bool Normalized);
    internal sealed record InspectionResult(HashSet<string> Raw, HashSet<string> Script, IReadOnlyList<TokenObservation> Observations);

    internal static async Task<InspectionResult> ReadAsync(
        string path, IEnumerable<string> ruleTokens, IEnumerable<string> domainTokens, long limit, CancellationToken token)
    {
        await using FileStream stream = new(path, FileMode.Open, FileAccess.Read, FileShare.Read, 64 * 1024,
            FileOptions.Asynchronous | FileOptions.SequentialScan);
        return await ReadAsync(stream, ruleTokens, domainTokens, limit, token);
    }

    internal static async Task<InspectionResult> ReadAsync(
        Stream stream, IEnumerable<string> ruleTokens, IEnumerable<string> domainTokens, long limit, CancellationToken token)
    {
        stream.Position = 0;
        ArgumentOutOfRangeException.ThrowIfNegative(limit);
        HashSet<string> domains = domainTokens.Where(value => !string.IsNullOrWhiteSpace(value))
            .ToHashSet(StringComparer.OrdinalIgnoreCase);
        string[] needles = ruleTokens.Concat(domains).Concat(ContentHeuristics.Tokens)
            .Where(value => !string.IsNullOrWhiteSpace(value)).Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
        HashSet<string> raw = new(StringComparer.OrdinalIgnoreCase), script = new(StringComparer.OrdinalIgnoreCase);
        List<TokenObservation> observations = [];
        byte[] buffer = ArrayPool<byte>.Shared.Rent(ChunkBytes + OverlapBytes);
        try
        {
            long total = 0;
            int retained = 0;
            while (true)
            {
                token.ThrowIfCancellationRequested();
                int read = await stream.ReadAsync(buffer.AsMemory(retained, (int)Math.Min(ChunkBytes, limit - total + 1)), token);
                if (read == 0) break;
                total += read;
                if (total > limit) throw MessageExceptions.Create(MessageText.Create("Backend.Core.StreamingStringInspection.ReadAsync.01"), sourceText => new InvalidDataException(sourceText));
                int count = retained + read;
                Inspect(Encoding.UTF8.GetString(buffer, 0, count), total - count, "UTF-8");
                // Preserve UTF-16LE byte alignment even if the stream returns a short, odd-sized read.
                int alignment = (int)((total - count) & 1);
                Inspect(Encoding.Unicode.GetString(buffer, alignment, (count - alignment) & ~1), total - count + alignment, "UTF-16LE");
                Inspect(Encoding.BigEndianUnicode.GetString(buffer, alignment, (count - alignment) & ~1), total - count + alignment, "UTF-16BE");
                retained = Math.Min(OverlapBytes, count);
                Buffer.BlockCopy(buffer, count - retained, buffer, 0, retained);
            }
            return new(raw, script, observations);
        }
        finally { ArrayPool<byte>.Shared.Return(buffer, clearArray: true); }

        void Inspect(string text, long windowByteOffset, string encoding)
        {
            foreach (string needle in needles)
                if (!raw.Contains(needle) && (domains.Contains(needle)
                        ? ContainsDomain(text, needle)
                        : text.Contains(needle, StringComparison.OrdinalIgnoreCase))) raw.Add(needle);
            string normalized = ScriptSignals.Normalize(text);
            foreach (string needle in ScriptSignals.Tokens)
                if (!script.Contains(needle) && normalized.Contains(needle, StringComparison.OrdinalIgnoreCase))
                {
                    script.Add(needle);
                    // One bounded, fixed-vocabulary observation per token. No user text or secrets.
                    // This is the decoding window start, not an exact token offset after normalization.
                    observations.Add(new(needle, windowByteOffset, encoding,
                        !text.Contains(needle, StringComparison.OrdinalIgnoreCase)));
                }
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
