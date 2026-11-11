using System.Net;

namespace SteamSentinel.Core.Inspection;

internal sealed record LoopbackScriptReference(string Endpoint, bool MatchesSteamAlertEndpoint);

/// <summary>Recognizes literal script creation, assignment and insertion in Steam UI JavaScript without evaluating it.</summary>
internal static class SteamUiLoopbackInspector
{
    internal static LoopbackScriptReference? Find(string text)
    {
        if (!text.Contains("createElement", StringComparison.Ordinal) || !text.Contains("http", StringComparison.OrdinalIgnoreCase) ||
            !text.Contains("append", StringComparison.Ordinal)) return null;

        LoopbackScriptReference? first = null;
        TokenReader reader = new(text);
        while (!reader.Done)
        {
            ReadOnlySpan<char> token = reader.Next();
            if (token is not ("var" or "let" or "const")) continue;
            TokenReader probe = reader;
            ReadOnlySpan<char> variable = probe.Next();
            if (variable.IsEmpty || variable.Length > 128 || !IsIdentifierStart(variable[0]) ||
                !probe.Take("=") || !probe.Take("document") || !probe.Take(".") || !probe.Take("createElement") ||
                !probe.Take("(") || !probe.TakeString().Equals("script", StringComparison.OrdinalIgnoreCase) || !probe.Take(")")) continue;
            probe.Take(";");
            if (!probe.Take(variable) || !probe.Take(".") || !probe.Take("src") || !probe.Take("=")) continue;
            ReadOnlySpan<char> source = probe.TakeString();
            if (source.IsEmpty || source.Length > 512) continue;
            if (probe.Take("+") && (!source.Contains('?') || !probe.Take("Date") || !probe.Take(".") ||
                !probe.Take("now") || !probe.Take("(") || !probe.Take(")"))) continue;
            probe.Take(";");
            if (!probe.Take("document") || !probe.Take(".") || probe.Next() is not ("head" or "body" or "documentElement") ||
                !probe.Take(".") || probe.Next() is not ("append" or "appendChild") || !probe.Take("(") ||
                !probe.Take(variable) || !probe.Take(")")) continue;
            if (!Uri.TryCreate(source.ToString(), UriKind.Absolute, out Uri? uri) ||
                uri.Scheme is not ("http" or "https") || uri.UserInfo.Length != 0 || !uri.IsLoopback ||
                !uri.AbsolutePath.EndsWith(".js", StringComparison.OrdinalIgnoreCase)) continue;
            string host = uri.IdnHost;
            if (!host.Equals("localhost", StringComparison.OrdinalIgnoreCase) &&
                !(IPAddress.TryParse(host, out IPAddress? address) && IPAddress.IsLoopback(address))) continue;
            bool familyEndpoint = uri.Scheme == "http" && uri.Port == 8137 && uri.AbsolutePath == "/x.js";
            // Exclude query/fragment data, which may contain local access tokens.
            LoopbackScriptReference match = new(uri.GetLeftPart(UriPartial.Path), familyEndpoint);
            if (familyEndpoint) return match;
            first ??= match;
            reader = probe;
        }
        return first;
    }

    private static bool IsIdentifierStart(char ch) => char.IsLetter(ch) || ch is '_' or '$';

    private ref struct TokenReader(string text)
    {
        private readonly ReadOnlySpan<char> _text = text.AsSpan();
        private int _index;
        public readonly bool Done => _index >= _text.Length;

        public bool Take(ReadOnlySpan<char> expected)
        {
            int start = _index;
            if (Next().SequenceEqual(expected)) return true;
            _index = start;
            return false;
        }

        public ReadOnlySpan<char> TakeString()
        {
            ReadOnlySpan<char> token = Next();
            return token.Length >= 2 && token[0] is '\'' or '"' && token[^1] == token[0] &&
                !token.Contains('\\') ? token[1..^1] : [];
        }

        public ReadOnlySpan<char> Next()
        {
            while (!Done)
            {
                int start = _index;
                char ch = _text[_index++];
                if (char.IsWhiteSpace(ch)) continue;
                if (ch == '/' && !Done && _text[_index] == '/')
                {
                    while (!Done && _text[_index] is not ('\r' or '\n' or '\u2028' or '\u2029')) _index++;
                    continue;
                }
                if (ch == '/' && !Done && _text[_index] == '*')
                {
                    _index++;
                    int end = _text[_index..].IndexOf("*/", StringComparison.Ordinal);
                    _index = end < 0 ? _text.Length : _index + end + 2;
                    continue;
                }
                if (ch is '\'' or '"' or '`')
                {
                    while (!Done)
                    {
                        char next = _text[_index++];
                        if (next == ch) break;
                        if (next == '\\' && !Done) _index++;
                    }
                }
                else if (IsIdentifierStart(ch))
                    while (!Done && (IsIdentifierStart(_text[_index]) || char.IsDigit(_text[_index]))) _index++;
                return _text[start.._index];
            }
            return [];
        }
    }
}
