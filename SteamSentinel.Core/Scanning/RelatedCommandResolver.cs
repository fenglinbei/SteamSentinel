using System.Text;
using System.Text.RegularExpressions;
using SteamSentinel.Core.Models;

namespace SteamSentinel.Core.Scanning;

public sealed record RelatedCommandInput(string RawCommand, string? WorkingDirectory = null,
    string? ExecutablePath = null, string? Arguments = null,
    IReadOnlyDictionary<string, string>? EnvironmentVariables = null);

public sealed record RelatedResolvedCommandTarget(string Path, string Kind, string OriginalToken, string ResolutionBasis);
public sealed record RelatedCommandResolution(DiagnosticReadStatus Status,
    IReadOnlyList<RelatedResolvedCommandTarget> Targets, IReadOnlyList<string> Notes);

/// <summary>
/// Bounded lexical parsing, never a shell, PATH search, file read, or command execution.
/// Resolved literals are inspection candidates, not evidence that Windows ran the command.
/// Environment values and relative-path bases must be supplied by the observed source.
/// </summary>
public static class RelatedCommandResolver
{
    public const int MaximumCommandCharacters = 32768;
    public const int MaximumTargets = 32;
    private const int MaximumTokens = 256;
    private static readonly Regex EnvironmentVariable = new(@"%(?<name>[A-Za-z_][A-Za-z0-9_]{0,127})%|\$env:(?<name>[A-Za-z_][A-Za-z0-9_]{0,127})",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant, TimeSpan.FromMilliseconds(100));
    private static readonly Regex AbsoluteLiteral = new("(?<![A-Za-z0-9_\\\\/?:])(?<path>[A-Za-z]:[\\\\/][^\\r\\n\\\"'<>|;&]*?\\.(?:exe|dll|bat|cmd|ps1|vbs|vbe|js|jse|py|pyc|lnk|hta|com|scr|jar))(?=[\\s\\\"'&,)]|$)",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant, TimeSpan.FromMilliseconds(100));
    private static readonly HashSet<string> ScriptExtensions = new([".bat", ".cmd", ".ps1", ".vbs", ".vbe", ".js", ".jse", ".py", ".pyc", ".hta"], StringComparer.OrdinalIgnoreCase);

    public static RelatedCommandResolution Resolve(RelatedCommandInput input)
    {
        ArgumentNullException.ThrowIfNull(input);
        State state = new(input);
        if (input.RawCommand.Length > MaximumCommandCharacters || input.ExecutablePath?.Length > MaximumCommandCharacters ||
            input.Arguments?.Length > MaximumCommandCharacters || input.WorkingDirectory?.Length > MaximumCommandCharacters)
        {
            state.Limit("命令或工作目录超过 32768 字符上限，未截取成可执行目标。");
            return state.Result();
        }
        string command = input.ExecutablePath is null ? input.RawCommand :
            "\"" + input.ExecutablePath.Trim().Trim('"') + "\"" + (string.IsNullOrWhiteSpace(input.Arguments) ? "" : " " + input.Arguments);
        state.Parse(command, 0);
        return state.Result();
    }

    /// <summary>Only returns literal references in an already bounded script snapshot; no decoding or evaluation.</summary>
    public static RelatedCommandResolution ResolveScriptLiterals(string script, string scriptPath,
        IReadOnlyDictionary<string, string>? environmentVariables = null)
    {
        ArgumentNullException.ThrowIfNull(script);
        State state = new(new(scriptPath, EnvironmentVariables: environmentVariables));
        if (script.Length > 256 * 1024)
        {
            state.Limit("脚本正文超过 256 KiB 字符上限，未解析正文。");
            return state.Result();
        }
        if (!TryNormalizeLocalLiteral(scriptPath, null, out string? normalized, out _))
        {
            state.Partial("脚本自身不是明确的本地绝对路径，未猜测脚本目录。");
            return state.Result();
        }
        string directory = Path.GetDirectoryName(normalized)!;
        string expanded = script;
        foreach ((string token, string replacement) in new[] { ("%~dp0", directory.TrimEnd('\\') + "\\"), ("${PSScriptRoot}", directory), ("$PSScriptRoot", directory) })
        {
            int occurrences = 0, offset = 0;
            while ((offset = expanded.IndexOf(token, offset, StringComparison.OrdinalIgnoreCase)) >= 0) { occurrences++; offset += token.Length; }
            if (expanded.Length + (long)occurrences * (replacement.Length - token.Length) > 256 * 1024)
            { state.Limit("脚本目录字面替换后将超过 256 KiB 字符上限，未构造展开正文。"); return state.Result(); }
            expanded = expanded.Replace(token, replacement, StringComparison.OrdinalIgnoreCase);
        }
        state.ExtractLiterals(expanded, "ScriptLiteralReference");
        state.Partial("只提取脚本字面路径；未执行脚本、还原计算表达式或证明这些分支实际运行。");
        return state.Result();
    }

    internal static bool TryNormalizeLocalLiteral(string value, string? workingDirectory, out string? path, out string basis)
    {
        path = null;
        basis = string.Empty;
        string candidate = value.Trim().Trim('"');
        if (candidate.Length is 0 or > MaximumCommandCharacters || candidate.IndexOfAny(['\0', '\r', '\n', '"', '<', '>', '|', '*', '?']) >= 0 ||
            candidate.StartsWith("\\", StringComparison.Ordinal) || candidate.StartsWith("/", StringComparison.Ordinal) ||
            candidate.Contains("%", StringComparison.Ordinal) || candidate.Contains("$", StringComparison.Ordinal)) return false;
        try
        {
            bool absolute = candidate.Length >= 3 && char.IsAsciiLetter(candidate[0]) && candidate[1] == ':' && candidate[2] is '\\' or '/';
            if (!absolute)
            {
                if (candidate.Contains(':') || string.IsNullOrWhiteSpace(workingDirectory)) return false;
                if (!TryNormalizeLocalLiteral(workingDirectory, null, out string? directory, out _)) return false;
                candidate = Path.Combine(directory!, candidate);
            }
            if (candidate.IndexOf(':', 2) >= 0) return false;
            string full = Path.GetFullPath(candidate);
            if (full.Length <= 3 || full.StartsWith("\\", StringComparison.Ordinal) || full.IndexOf(':', 2) >= 0) return false;
            path = full;
            basis = absolute ? "AbsoluteLiteral" : "ExplicitWorkingDirectory";
            return true;
        }
        catch (Exception ex) when (ex is ArgumentException or NotSupportedException or PathTooLongException) { return false; }
    }

    private sealed class State(RelatedCommandInput input)
    {
        private readonly List<RelatedResolvedCommandTarget> _targets = [];
        private readonly List<string> _notes = [];
        private DiagnosticReadStatus _status = DiagnosticReadStatus.Complete;
        private readonly HashSet<string> _keys = new(StringComparer.OrdinalIgnoreCase);

        internal RelatedCommandResolution Result()
        {
            if (_targets.Count == 0 && _status == DiagnosticReadStatus.Complete)
                Partial("未取得可静态定位的本地文件；未搜索 PATH 或猜测当前目录。");
            return new(_status, _targets.ToArray(), _notes.ToArray());
        }
        internal void Partial(string note)
        {
            if (_status == DiagnosticReadStatus.Complete) _status = DiagnosticReadStatus.NotChecked;
            if (_notes.Count < 32 && !_notes.Contains(note, StringComparer.Ordinal)) _notes.Add(note);
        }
        internal void Limit(string note)
        {
            _status = DiagnosticReadStatus.LimitReached;
            if (_notes.Count < 32 && !_notes.Contains(note, StringComparer.Ordinal)) _notes.Add(note);
        }
        private string Expand(string value)
        {
            try
            {
                int maximum = value.Length > MaximumCommandCharacters ? 256 * 1024 : MaximumCommandCharacters;
                long expandedLength = value.Length;
                return EnvironmentVariable.Replace(value, match =>
                {
                    string name = match.Groups["name"].Value;
                    KeyValuePair<string, string>? pair = input.EnvironmentVariables?.FirstOrDefault(p => p.Key.Equals(name, StringComparison.OrdinalIgnoreCase));
                    if (pair is { } found && !string.IsNullOrEmpty(found.Key) && found.Value.Length <= MaximumCommandCharacters)
                    {
                        long nextLength = expandedLength + found.Value.Length - match.Length;
                        if (nextLength > maximum) { Limit("环境变量替换后将超过字符预算，保留未展开变量。"); return match.Value; }
                        expandedLength = nextLength;
                        return found.Value;
                    }
                    Partial("环境变量未在此来源身份下取得，未借用其他账户值：" + name);
                    return match.Value;
                });
            }
            catch (RegexMatchTimeoutException) { Limit("环境变量字面替换达到时间上限。"); return value; }
        }
        private void Add(string value, string kind)
        {
            string expanded = Expand(value);
            if (expanded.Length > MaximumCommandCharacters) { Limit("单个展开路径超过字符上限，未纳入目标。"); return; }
            string? working = input.WorkingDirectory is null ? null : Expand(input.WorkingDirectory);
            if (!TryNormalizeLocalLiteral(expanded, working, out string? path, out string basis))
            {
                Partial("目标不是明确本地绝对路径，或相对路径缺少可信工作目录：" + Short(value));
                return;
            }
            string key = path + "\n" + kind;
            if (_keys.Contains(key)) return;
            if (_targets.Count >= MaximumTargets) { Limit("单条命令达到 32 个字面目标上限。"); return; }
            _keys.Add(key);
            _targets.Add(new(path!, kind, value, basis));
        }
        internal void ExtractLiterals(string text, string kind)
        {
            string expanded = Expand(text);
            try
            {
                foreach (Match match in AbsoluteLiteral.Matches(expanded))
                {
                    Add(match.Groups["path"].Value, kind);
                    if (_targets.Count >= MaximumTargets) { Limit("字面引用达到 32 项上限，其余内容未解析。"); break; }
                }
            }
            catch (RegexMatchTimeoutException) { Limit("命令字面路径解析达到时间上限。"); }
        }

        internal void Parse(string command, int depth)
        {
            if (depth > 4) { Limit("脚本包装器超过 4 层，未继续解析。"); return; }
            if (command.Length > MaximumCommandCharacters) { Limit("展开后的命令超过字符上限。"); return; }
            List<Token> tokens = Tokenize(command, out bool complete, out bool limited);
            if (!complete) Partial("引号或转义不完整，保留可见字面路径但不确认调用语义。");
            if (limited) Limit("命令参数超过 256 个词法单元上限。");
            if (tokens.Count == 0) { Partial("命令为空。"); return; }
            Token first = tokens[0];
            string executable = Expand(first.Value);
            string name = Path.GetFileNameWithoutExtension(executable.Replace('/', '\\')).ToLowerInvariant();
            bool recognizedWrapper = name is "cmd" or "powershell" or "pwsh" or "wscript" or "cscript" or
                "rundll32" or "regsvr32" or "python" or "pythonw" or "py" or "mshta" or "dotnet" or "java" or "javaw";
            bool qualified = executable.Contains('\\') || executable.Contains('/') || executable.Contains(':');
            if (qualified || !recognizedWrapper)
            {
                if (Path.HasExtension(executable)) Add(executable, recognizedWrapper ? "WrapperExecutable" : "Executable");
                else Partial("未加引号的程序路径或缺少扩展名，Windows 实际可执行文件选择尚未确认。");
            }
            else Partial("包装器只有名称，未查询 PATH 或断言其实际映像位置：" + name);

            if (name == "cmd")
            {
                int index = tokens.FindIndex(1, t => t.Value.Equals("/c", StringComparison.OrdinalIgnoreCase) || t.Value.Equals("/k", StringComparison.OrdinalIgnoreCase));
                if (index < 0 || index + 1 >= tokens.Count) Partial("cmd 没有可静态解析的 /c 或 /k 子命令。");
                else
                {
                    string nested = command[tokens[index + 1].Start..].Trim();
                    if (nested.StartsWith("\"\"", StringComparison.Ordinal) && nested.EndsWith('"')) nested = nested[1..^1];
                    if (nested.StartsWith("call ", StringComparison.OrdinalIgnoreCase)) nested = nested[5..].TrimStart();
                    if (HasShellOperators(nested)) Partial("cmd 包含复合运算符或重定向，字面路径不证明实际执行顺序。");
                    else Parse(nested, depth + 1);
                }
            }
            else if (name is "powershell" or "pwsh")
            {
                int file = tokens.FindIndex(1, t => t.Value.Equals("-file", StringComparison.OrdinalIgnoreCase) || t.Value.Equals("-f", StringComparison.OrdinalIgnoreCase));
                if (file >= 0 && file + 1 < tokens.Count) Add(tokens[file + 1].Value, "ScriptArgument");
                else Partial("PowerShell 未使用明确的 -File 参数；内联/编码命令只保留字面引用，未执行或解码。");
            }
            else if (name == "rundll32")
            {
                if (tokens.Count > 1) Add(tokens[1].Value.Split(',', 2)[0], "ModuleArgument");
                else Partial("rundll32 缺少 DLL 参数。");
            }
            else if (name is "regsvr32" or "dotnet")
            {
                Token? module = tokens.Skip(1).FirstOrDefault(t => !t.Value.StartsWith('/') && !t.Value.StartsWith('-') && t.Value.EndsWith(".dll", StringComparison.OrdinalIgnoreCase));
                if (module is not null) Add(module.Value, "ModuleArgument");
                else Partial("包装器未提供明确的本地 DLL 参数。");
            }
            else if (name is "wscript" or "cscript" or "python" or "pythonw" or "py" or "mshta")
            {
                Token? script = tokens.Skip(1).FirstOrDefault(t => !t.Value.StartsWith('/') && !t.Value.StartsWith('-') && ScriptExtensions.Contains(Path.GetExtension(t.Value)));
                if (script is not null) Add(script.Value, "ScriptArgument");
                else Partial("脚本包装器未提供可静态定位的脚本文件。");
            }
            else if (name is "java" or "javaw")
            {
                int jar = tokens.FindIndex(1, t => t.Value.Equals("-jar", StringComparison.OrdinalIgnoreCase));
                if (jar >= 0 && jar + 1 < tokens.Count) Add(tokens[jar + 1].Value, "ScriptArgument");
                else Partial("Java 命令没有明确的 -jar 文件，未解析类路径。");
            }
            if (HasShellOperators(command)) Partial("命令包含 shell 元字符，只记录字面路径，未求值。");
            ExtractLiterals(command, "LiteralReference");
        }
        private static string Short(string value) => value.Length <= 180 ? value : value[..180] + "…";
    }

    private sealed record Token(string Value, int Start);
    private static List<Token> Tokenize(string command, out bool complete, out bool limited)
    {
        List<Token> tokens = [];
        complete = true;
        limited = false;
        int offset = 0;
        while (offset < command.Length)
        {
            while (offset < command.Length && char.IsWhiteSpace(command[offset])) offset++;
            if (offset >= command.Length) break;
            if (tokens.Count >= MaximumTokens) { limited = true; break; }
            int start = offset;
            bool quoted = false;
            StringBuilder value = new();
            while (offset < command.Length && (quoted || !char.IsWhiteSpace(command[offset])))
            {
                int slashes = 0;
                while (offset < command.Length && command[offset] == '\\') { slashes++; offset++; }
                if (offset < command.Length && command[offset] == '"')
                {
                    value.Append('\\', slashes / 2);
                    if ((slashes & 1) != 0) value.Append('"');
                    else quoted = !quoted;
                    offset++;
                }
                else
                {
                    value.Append('\\', slashes);
                    if (offset < command.Length && (quoted || !char.IsWhiteSpace(command[offset]))) value.Append(command[offset++]);
                }
            }
            if (quoted) complete = false;
            tokens.Add(new(value.ToString(), start));
        }
        return tokens;
    }

    private static bool HasShellOperators(string value)
    {
        bool quoted = false;
        foreach (char c in value)
        {
            if (c == '"') quoted = !quoted;
            else if (!quoted && c is '&' or '|' or '<' or '>' or '^' or '`' or ';') return true;
        }
        return false;
    }
}
