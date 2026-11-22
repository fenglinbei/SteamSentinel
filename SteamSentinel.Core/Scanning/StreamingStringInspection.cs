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
        List<(string Needle, byte[] Pattern)> nonAsciiLePatterns = [];
        List<(string Needle, byte[] Pattern)> nonAsciiBePatterns = [];
        bool hasCaseSensitiveNonAscii = false;
        foreach (string needle in needles)
        {
            if (needle.All(char.IsAscii)) continue;
            if (needle.All(ch => char.ToUpperInvariant(ch) == ch && char.ToLowerInvariant(ch) == ch))
            {
                nonAsciiLePatterns.Add((needle, Encoding.Unicode.GetBytes(needle)));
                nonAsciiBePatterns.Add((needle, Encoding.BigEndianUnicode.GetBytes(needle)));
            }
            else
            {
                hasCaseSensitiveNonAscii = true;
            }
        }
        HashSet<string> raw = new(StringComparer.OrdinalIgnoreCase), script = new(StringComparer.OrdinalIgnoreCase);
        List<TokenObservation> observations = [];
        byte[] buffer = ArrayPool<byte>.Shared.Rent(ChunkBytes + OverlapBytes);
        try
        {
            long total = 0;
            int retained = 0;
            bool seenUtf16LeBom = false;
            bool seenUtf16BeBom = false;
            while (true)
            {
                token.ThrowIfCancellationRequested();
                int read = await stream.ReadAsync(buffer.AsMemory(retained, (int)Math.Min(ChunkBytes, limit - total + 1)), token);
                if (read == 0) break;
                bool firstWindow = total == 0;
                total += read;
                if (total > limit) throw MessageExceptions.Create(MessageText.Create("Backend.Core.StreamingStringInspection.ReadAsync.01"), sourceText => new InvalidDataException(sourceText));
                int count = retained + read;
                if (firstWindow && count >= 2)
                {
                    seenUtf16LeBom = buffer[0] == 0xFF && buffer[1] == 0xFE;
                    seenUtf16BeBom = buffer[0] == 0xFE && buffer[1] == 0xFF;
                }
                Inspect(Encoding.UTF8.GetString(buffer, 0, count), total - count, "UTF-8");
                // 保持 UTF-16 偶字节对齐；仅在存在对应零字节特征、BOM 或大小写敏感非 ASCII 规则时才解码，避免无条件三编码复制内存。
                int alignment = (int)((total - count) & 1);
                int length16 = (count - alignment) & ~1;
                if (length16 > 0)
                {
                    ReadOnlySpan<byte> slice16 = buffer.AsSpan(alignment, length16);
                    bool decodeLe = seenUtf16LeBom || hasCaseSensitiveNonAscii || HasZeroAtParity(slice16, parity: 1);
                    if (decodeLe)
                        Inspect(Encoding.Unicode.GetString(buffer, alignment, length16), total - count + alignment, "UTF-16LE");
                    else if (nonAsciiLePatterns.Count > 0)
                        MatchNonAsciiBytes(slice16, nonAsciiLePatterns, raw);

                    bool decodeBe = seenUtf16BeBom || hasCaseSensitiveNonAscii || HasZeroAtParity(slice16, parity: 0);
                    if (decodeBe)
                        Inspect(Encoding.BigEndianUnicode.GetString(buffer, alignment, length16), total - count + alignment, "UTF-16BE");
                    else if (nonAsciiBePatterns.Count > 0)
                        MatchNonAsciiBytes(slice16, nonAsciiBePatterns, raw);
                }
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

    private static bool HasZeroAtParity(ReadOnlySpan<byte> slice, int parity)
    {
        int firstZero = slice.IndexOf((byte)0);
        if (firstZero < 0) return false;
        int start = (firstZero & 1) == parity ? firstZero : firstZero + 1;
        for (int i = start; i < slice.Length; i += 2)
            if (slice[i] == 0) return true;
        return false;
    }

    private static void MatchNonAsciiBytes(ReadOnlySpan<byte> slice, List<(string Needle, byte[] Pattern)> patterns, HashSet<string> raw)
    {
        foreach (var (needle, pattern) in patterns)
        {
            if (raw.Contains(needle) || pattern.Length == 0 || pattern.Length > slice.Length) continue;
            int offset = 0;
            while (offset <= slice.Length - pattern.Length)
            {
                int hit = slice[offset..].IndexOf(pattern);
                if (hit < 0) break;
                int absolute = offset + hit;
                if ((absolute & 1) == 0)
                {
                    raw.Add(needle);
                    break;
                }
                offset = absolute + 1;
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
