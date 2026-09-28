using System.Text.RegularExpressions;
using SteamSentinel.Core.Models;

namespace SteamSentinel.Core.Inspection;

/// <summary>Finite references between already-read local files. Does not interpret JavaScript or fetch referenced URLs.</summary>
internal sealed class VPetSteamUiInspector(IEnumerable<string> domains)
{
    private static Regex Pattern(string value, bool ignoreCase = false) => new(value,
        RegexOptions.CultureInvariant | RegexOptions.NonBacktracking | (ignoreCase ? RegexOptions.IgnoreCase : 0), TimeSpan.FromMilliseconds(150));
    private const string Property = "(?:window|self|globalThis)\\s*(?:\\.\\s*(?<property>__px[SH])|\\[\\s*[\"'](?<property>__px[SH])[\"']\\s*\\])";
    private static readonly Regex Definition = Pattern(Property + "\\s*=[^=]");
    private static readonly Regex Route = Pattern("(?:[\"'](?<route>SupportMessages|HelpAppPage|HelpFrontPage)[\"']|\\b(?<route>SupportMessages|HelpAppPage|HelpFrontPage)\\b)\\s*:\\s*" + Property);
    private static readonly Regex Marker = Pattern(@"/\*px:(?<edge>[be])\*/");
    private static readonly Regex UrlLiteral = Pattern("[\"'](?<url>https?://[^\\s\"'<>]{1,2048})[\"']");
    private static readonly Regex Script = Pattern("<script\\b[^>]*\\bsrc\\s*=\\s*[\"'](?<path>[^\"'<>]+)[\"'][^>]*>", true);
    private static readonly Regex Css = Pattern("(?:\\.URLBar|#ReportItemBtn)[^{]{0,120}\\{[^}]{0,512}(?:display\\s*:\\s*none|visibility\\s*:\\s*hidden)", true);
    private readonly string[] _domains = domains.ToArray();
    private readonly Dictionary<string, Facts> _files = new(StringComparer.OrdinalIgnoreCase);
    internal bool Incomplete { get; private set; }
    private sealed class Facts(string path, string hash)
    {
        internal string Path { get; } = path;
        internal string Hash { get; } = hash;
        internal string Scope => Path.Split('/')[0];
        internal HashSet<string> Definitions { get; } = new(StringComparer.Ordinal);
        internal Dictionary<string, string> Routes { get; } = new(StringComparer.Ordinal);
        internal HashSet<string> References { get; } = new(StringComparer.OrdinalIgnoreCase);
        internal List<string> Signals { get; } = [];
        internal bool Provider => Signals.Contains("PX-BOUNDED-BLOCK") && Signals.Contains("KNOWN-DOMAIN") && Definitions.Count == 2;
        internal SteamUiEvidenceFile Evidence => new(Path, Hash, Signals.ToArray());
    }

    internal void Observe(string relativePath, string hash, string text)
    {
        string path = relativePath.Replace('\\', '/');
        if (_files.Count >= 512) { Incomplete = true; return; }
        Facts facts = new(path, hash);
        try
        {
            if (path.EndsWith(".html", StringComparison.OrdinalIgnoreCase))
            {
                // Browser-root /sp.js resolves inside this local UI root, never the filesystem root.
                bool hasBase = text.Contains("<base", StringComparison.OrdinalIgnoreCase);
                Match[] references = Script.Matches(text).Cast<Match>().Take(65).ToArray();
                if (references.Length > 64) Incomplete = true;
                foreach (Match match in references.Take(64))
                {
                    if (InsideHtmlComment(text, match.Index)) continue;
                    if (match.Length > 4096 || match.Groups["path"].Length > 1024) { Incomplete = true; continue; }
                    string value = match.Groups["path"].Value;
                    if (hasBase && !value.StartsWith('/')) { Incomplete = true; continue; }
                    if (LocalReference(path, value) is { } reference) facts.References.Add(reference);
                }
                if (facts.References.Count > 0) facts.Signals.Add("LOCAL-SCRIPT-REFERENCES");
            }
            else if (path.EndsWith(".js", StringComparison.OrdinalIgnoreCase) && text.Contains("__px", StringComparison.Ordinal))
            {
                Match[] definitions = Definition.Matches(text).Cast<Match>().Take(65).ToArray();
                Match[] routes = Route.Matches(text).Cast<Match>().Take(65).ToArray();
                if (definitions.Length > 64 || routes.Length > 64) Incomplete = true;
                Match[] markers = Marker.Matches(text).Cast<Match>().Take(33).ToArray();
                Match[] urls = UrlLiteral.Matches(text).Cast<Match>().Take(65).ToArray();
                if (markers.Length > 32 || urls.Length > 64) Incomplete = true;
                HashSet<int> code = CodePositions(text, definitions.Concat(routes).Concat(markers).Concat(urls).Select(m => m.Index).ToHashSet());
                Match[] realMarkers = markers.Where(m => code.Contains(m.Index)).ToArray();
                int begin = -1, end = -1;
                if (realMarkers.Length == 2 && realMarkers[0].Groups["edge"].Value == "b" && realMarkers[1].Groups["edge"].Value == "e")
                    (begin, end) = (realMarkers[0].Index, realMarkers[1].Index);
                else if (realMarkers.Length > 0) Incomplete = true;
                bool block = begin >= 0 && end > begin && end - begin <= 256 * 1024;
                foreach (Match match in definitions.Take(64).Where(match => code.Contains(match.Index) && block && match.Index > begin && match.Index < end))
                    facts.Definitions.Add(match.Groups["property"].Value);
                foreach (Match match in routes.Take(64).Where(match => code.Contains(match.Index)))
                {
                    string key = match.Groups["route"].Value, value = match.Groups["property"].Value;
                    if (facts.Routes.TryGetValue(key, out string? existing) && existing != value) { Incomplete = true; facts.Routes.Clear(); break; }
                    facts.Routes[key] = value;
                }
                if (block) facts.Signals.Add("PX-BOUNDED-BLOCK");
                else if (begin >= 0) Incomplete = true;
                if (facts.Definitions.Count > 0) facts.Signals.Add("GLOBAL-PX-ROUTE-DEFINITION");
                if (facts.Routes.Count > 0) facts.Signals.Add("SUPPORT-ROUTE-TO-PX-PROPERTY");
                if (facts.Definitions.Count > 0 && urls.Any(m => code.Contains(m.Index) && m.Index > begin && m.Index < end &&
                    IsKnownUrl(m.Groups["url"].Value))) facts.Signals.Add("KNOWN-DOMAIN");
                if (text.Contains("__pxA", StringComparison.Ordinal) &&
                    (text.Contains("Date", StringComparison.Ordinal) || text.Contains("fetch", StringComparison.Ordinal) || text.Contains("setInterval", StringComparison.Ordinal)))
                    facts.Signals.Add("ACTIVATION-GATE-NOT-EVALUATED");
            }
            else if (path.EndsWith(".css", StringComparison.OrdinalIgnoreCase) && Css.IsMatch(text))
                facts.Signals.Add("RELATED-UI-SUPPRESSION-STYLE");
        }
        catch (RegexMatchTimeoutException) { Incomplete = true; return; }
        if (facts.Signals.Count != 0 && !_files.TryAdd(path, facts)) Incomplete = true;
    }

    private bool IsKnownUrl(string value) => Uri.TryCreate(value, UriKind.Absolute, out Uri? uri) &&
        uri.Scheme is "http" or "https" && _domains.Any(domain => uri.Host.Equals(domain, StringComparison.OrdinalIgnoreCase) ||
            uri.Host.EndsWith("." + domain, StringComparison.OrdinalIgnoreCase));

    internal IReadOnlyList<(string Target, string Hash, SteamUiEvidence Evidence)> Complete()
    {
        List<(string, string, SteamUiEvidence)> results = [];
        Facts[] providers = _files.Values.Where(f => f.Provider).ToArray();
        HashSet<Facts> linked = [];
        foreach (Facts route in _files.Values.Where(f => f.Routes.Count >= 2 && f.Routes.Values.Distinct().Count() == 2))
        {
            Facts[] candidates = providers.Where(f => f.Scope == route.Scope && route.Routes.Values.All(f.Definitions.Contains)).Take(2).ToArray();
            if (candidates.Length > 1) { Incomplete = true; continue; }
            Facts? provider = candidates.SingleOrDefault();
            if (provider is null) continue;
            linked.Add(provider);
            Add(route, provider, true);
            if (results.Count == 64) { Incomplete = true; break; }
        }
        foreach (Facts provider in providers.Where(f => !linked.Contains(f)))
        {
            if (results.Count == 64) { Incomplete = true; break; }
            Add(provider, provider, false);
        }
        return results;

        void Add(Facts route, Facts provider, bool routesLinked)
        {
            Facts? entry = _files.Values.FirstOrDefault(f => f.Scope == route.Scope && f.References.Contains(provider.Path));
            List<Facts> participants = [route];
            if (provider != route) participants.Add(provider);
            if (entry is not null) participants.Add(entry);
            participants.AddRange(_files.Values.Where(f => f.Signals.Contains("RELATED-UI-SUPPRESSION-STYLE") &&
                (f.Scope == route.Scope || f.Path.Equals("resource/webkit.css", StringComparison.OrdinalIgnoreCase))).Take(2));
            SteamUiEvidence evidence = new()
            {
                EntryReferenceVerified = entry is not null,
                SupportRoutesLinked = routesLinked,
                ActivationGateObserved = provider.Signals.Contains("ACTIVATION-GATE-NOT-EVALUATED"),
                Files = participants.Select(f => f.Evidence).ToList(),
                Signals = [routesLinked ? "VPET-SUPPORT-ROUTE-PROVIDER-LINK" : "VPET-PX-PROVIDER-WITHOUT-ROUTE-LINK", "VPET-PX-BLOCK-AND-KNOWN-DOMAIN",
                    entry is null ? "VPET-HTML-REFERENCE-NOT-ESTABLISHED" : "VPET-HTML-LOCAL-SCRIPT-LINK"]
            };
            evidence.Validate(); results.Add((route.Path, route.Hash, evidence));
        }
    }

    private static string? LocalReference(string source, string value)
    {
        value = value.Split('?', '#')[0];
        if (value.Length == 0 || value.StartsWith("//", StringComparison.Ordinal) || value.Any(c => c is ':' or '\\' or '%' || char.IsControl(c))) return null;
        string[] parts = value.Split('/', StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length == 0 || parts.Any(part => part is "." or "..")) return null;
        if (source.LastIndexOf('/') < 1) return null;
        string directory = value.StartsWith('/') ? source.Split('/')[0] : source[..source.LastIndexOf('/')];
        string combined = directory + "/" + string.Join('/', parts);
        return combined.StartsWith(source.Split('/')[0] + "/", StringComparison.OrdinalIgnoreCase) ? combined : null;
    }

    private static bool InsideHtmlComment(string text, int position)
    {
        int begin = text.LastIndexOf("<!--", position, StringComparison.Ordinal);
        return begin >= 0 && text.LastIndexOf("-->", position, StringComparison.Ordinal) < begin;
    }

    private static HashSet<int> CodePositions(string text, HashSet<int> candidates)
    {
        HashSet<int> result = []; int state = 0; bool escaped = false, regexAllowed = true, characterClass = false;
        int end = candidates.Count == 0 ? -1 : candidates.Max();
        for (int i = 0; i <= end; i++)
        {
            char c = text[i], next = i + 1 < text.Length ? text[i + 1] : '\0';
            if (state == 0)
            {
                if (candidates.Contains(i)) result.Add(i);
                if (c == '/' && next == '/') { state = 4; i++; }
                else if (c == '/' && next == '*') { state = 5; i++; }
                else if (c == '/' && regexAllowed) { state = 6; characterClass = false; }
                else if (c == '\'') state = 1;
                else if (c == '"') state = 2;
                else if (c == '`') state = 3;
                else if (char.IsAsciiLetter(c) || c is '_' or '$')
                {
                    int start = i;
                    while (i + 1 < text.Length && (char.IsAsciiLetterOrDigit(text[i + 1]) || text[i + 1] is '_' or '$')) i++;
                    regexAllowed = text.AsSpan(start, i - start + 1) is "return" or "throw" or "case" or "delete" or "void" or "typeof" or "yield" or "await";
                }
                else if (!char.IsWhiteSpace(c)) regexAllowed = c is '(' or '[' or '{' or '=' or ':' or ',' or ';' or '!' or '?' or '&' or '|' or '+' or '-' or '*' or '/' or '%' or '^' or '~' or '<' or '>';
            }
            else if (state == 4) { if (c is '\r' or '\n') state = 0; }
            else if (state == 5) { if (c == '*' && next == '/') { state = 0; i++; } }
            else if (escaped) escaped = false;
            else if (c == '\\') escaped = true;
            else if (state == 6)
            {
                if (c == '[') characterClass = true;
                else if (c == ']') characterClass = false;
                else if (c == '/' && !characterClass) { state = 0; regexAllowed = false; }
            }
            else if (state == 1 && c == '\'' || state == 2 && c == '"' || state == 3 && c == '`') { state = 0; regexAllowed = false; }
        }
        return result;
    }
}
