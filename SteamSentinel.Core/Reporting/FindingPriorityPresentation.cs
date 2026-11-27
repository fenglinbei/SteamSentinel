using System.Globalization;
using System.Net;
using System.Net.Sockets;
using SteamSentinel.Core.Inspection;
using SteamSentinel.Core.Models;

namespace SteamSentinel.Core.Reporting;

/// <summary>Presentation grouping only; never changes scan evidence or remediation eligibility.</summary>
public static class FindingPriorityPresentation
{
    private const string MismatchRule = "CONTENT-EXTENSION-MISMATCH";
    private const string MismatchDescription = "Backend.Core.ContentScanner.Containers.AddContainerFileFindings.04";
    private const string FormatMessagePrefix = "Backend.Core.FileTypeDetector.Label.";
    private static readonly string[] LocalizedFormats = ["PortableExecutable", "CompoundDocument", "Zip", "Rar", "Cabinet", "SevenZip",
        "GZip", "BZip2", "Xz", "Zstandard", "Tar", "Mp4", "Shortcut", "PowerShell", "Batch", "Empty"];
    private static readonly Dictionary<string, DetectedFileType> FormatNames = BuildFormatNames();

    public static IReadOnlySet<string> ReferenceFindingIds(ScanReport report)
    {
        ArgumentNullException.ThrowIfNull(report);
        HashSet<string> result = new(StringComparer.Ordinal);
        Dictionary<string, int> idCounts = new(StringComparer.OrdinalIgnoreCase);
        Dictionary<string, FormatEvidence> formats = new(StringComparer.OrdinalIgnoreCase);
        PathGroups groups = new();
        foreach (Finding finding in report.Findings)
        {
            if (!string.IsNullOrWhiteSpace(finding.Id))
                idCounts[finding.Id] = idCounts.GetValueOrDefault(finding.Id) + 1;
            groups.Link(finding.Target, finding.ContentPath, finding.RelatedFilePath);
        }
        if (report.Containers is { } containers)
        {
            foreach (ContainerScanNode node in containers.Nodes)
            {
                groups.Link(node.DisplayPath, node.OriginalTarget);
                string? path = NormalizePath(node.DisplayPath);
                if (path is null) continue;
                DetectedFileType? type = ReadFormat(node.FormatText);
                FormatEvidence evidence = new(type, node.Recognition == ContainerStageStatus.Complete && type.HasValue);
                if (formats.TryGetValue(path, out FormatEvidence previous))
                    evidence = new(type, previous.Usable && evidence.Usable && previous.Type == type);
                formats[path] = evidence;
            }
        }

        bool hasNetworkOrCertificateAlert = HasNetworkOrCertificateAlert(report);
        bool[] candidates = new bool[report.Findings.Count];
        HashSet<string> blocked = new(StringComparer.OrdinalIgnoreCase);
        HashSet<string> blockedRawTargets = new(StringComparer.OrdinalIgnoreCase);
        HashSet<string> blockedCoveragePaths = new(StringComparer.OrdinalIgnoreCase);
        HashSet<string> blockedCoverageRawTargets = new(StringComparer.OrdinalIgnoreCase);
        for (int i = 0; i < report.Findings.Count; i++)
        {
            Finding finding = report.Findings[i];
            candidates[i] = !string.IsNullOrWhiteSpace(finding.Id) && idCounts[finding.Id] == 1 &&
                (IsPlainMismatch(finding, formats) || IsExtendedReference(finding, report, hasNetworkOrCertificateAlert));
            if (!candidates[i])
            {
                if (finding.Category == FindingCategory.Coverage)
                {
                    // 覆盖缺口仅精确阻塞其自身目标路径，不因外层或兄弟成员触发预算上限而连坐折叠无威胁成员
                    string? exactCoveragePath = NormalizePath(string.IsNullOrWhiteSpace(finding.ContentPath) ? finding.Target : finding.ContentPath);
                    if (exactCoveragePath is not null) blockedCoveragePaths.Add(exactCoveragePath);
                    string? relatedCoveragePath = NormalizePath(finding.RelatedFilePath);
                    if (relatedCoveragePath is not null) blockedCoveragePaths.Add(relatedCoveragePath);
                    if (exactCoveragePath is null && relatedCoveragePath is null && !string.IsNullOrWhiteSpace(finding.Target))
                        blockedCoverageRawTargets.Add(finding.Target.Trim());
                }
                else
                {
                    // 同一物理路径/容器或同一非路径目标存在任何非覆盖类非折叠发现时，禁止折叠该容器组上的参考提示项
                    if (groups.Find(finding.Target, finding.ContentPath, finding.RelatedFilePath) is { } group)
                        blocked.Add(group);
                    else if (!string.IsNullOrWhiteSpace(finding.Target))
                        blockedRawTargets.Add(finding.Target.Trim());
                }
            }
        }
        for (int i = 0; i < report.Findings.Count; i++)
        {
            if (!candidates[i]) continue;
            Finding finding = report.Findings[i];
            if (groups.Find(finding.Target, finding.ContentPath, finding.RelatedFilePath) is { } group)
            {
                if (blocked.Contains(group)) continue;
            }
            else if (!string.IsNullOrWhiteSpace(finding.Target) && blockedRawTargets.Contains(finding.Target.Trim()))
            {
                continue;
            }

            string? candidateExactPath = NormalizePath(string.IsNullOrWhiteSpace(finding.ContentPath) ? finding.Target : finding.ContentPath);
            string? candidateRelatedPath = NormalizePath(finding.RelatedFilePath);
            if ((candidateExactPath is not null && blockedCoveragePaths.Contains(candidateExactPath)) ||
                (candidateRelatedPath is not null && blockedCoveragePaths.Contains(candidateRelatedPath)))
                continue;
            if (candidateExactPath is null && candidateRelatedPath is null &&
                !string.IsNullOrWhiteSpace(finding.Target) && blockedCoverageRawTargets.Contains(finding.Target.Trim()))
                continue;

            result.Add(finding.Id);
        }
        return result;
    }

    private static bool HasNetworkOrCertificateAlert(ScanReport report) =>
        report.Findings.Any(finding =>
            finding.RuleId == "CERTIFICATE-NAME-REVIEW" ||
            finding.Category is FindingCategory.Network or FindingCategory.Certificate &&
            (finding.IsKnownMalware || finding.CanRemediate || finding.Severity >= FindingSeverity.High));

    private static bool IsExtendedReference(Finding finding, ScanReport report, bool hasNetworkOrCertificateAlert)
    {
        if (finding.Category == FindingCategory.Coverage ||
            finding.IsKnownMalware || finding.CanRemediate || finding.UserSelectedRisk ||
            finding.HandlingReason is FindingHandlingReason.IncompleteInspection or FindingHandlingReason.PrerequisiteNotMet or FindingHandlingReason.UnsupportedAction ||
            finding.SuggestedActions.Any(action => action is not (SuggestedActionKind.None or SuggestedActionKind.ReviewOnly)))
            return false;

        return finding.RuleId switch
        {
            "STEAM-CFG-PRESENT" =>
                finding.Severity < FindingSeverity.Medium && finding.ReasonCode is null,
            "NETWORK-C2-BLOCKED" or "STEAM-MOD-MILLENNIUM" or "WORKSHOP-PROJECT-METADATA" or "ASSOCIATION-HOST-SIGNATURE" =>
                finding.Severity < FindingSeverity.High,
            "INSTALLER-STRUCTURE" =>
                finding.Severity < FindingSeverity.Medium && finding.ReasonCode is null,
            "CONTENT-SUSPICIOUS-STRINGS" =>
                finding.Severity == FindingSeverity.Information,
            "NETWORK-PROXY-PRESENT" =>
                finding.Severity == FindingSeverity.Information &&
                !hasNetworkOrCertificateAlert &&
                IsLoopbackProxyTarget(finding.Target) &&
                !HasLinkedPacObservation(finding, report),
            _ => false
        };
    }

    private static bool HasLinkedPacObservation(Finding finding, ScanReport report)
    {
        if (report.TrustProxyDiagnostics is not { } diagnostics || finding.DiagnosticObservationIds.Count == 0)
            return false;
        return diagnostics.Proxies.Any(proxy =>
            finding.DiagnosticObservationIds.Contains(proxy.Id, StringComparer.Ordinal) &&
            !string.IsNullOrWhiteSpace(proxy.AutoConfigUrl));
    }

    /// <summary>
    /// 仅匹配纯本地环回代理主机端口（如 127.0.0.1:7897、localhost:7890、[::1]:7890 或分协议 http=127.0.0.1:7890;https=127.0.0.1:7890），
    /// 严格排除任何含协议头的 PAC URL（如 http://.../proxy.pac）及任何非环回远端地址。
    /// </summary>
    internal static bool IsLoopbackProxyTarget(string? target)
    {
        if (string.IsNullOrWhiteSpace(target) || target.Length > 1024) return false;
        if (target.Contains("://", StringComparison.Ordinal) ||
            target.IndexOfAny(['/', '\\', '?', '#', '@']) >= 0)
            return false;

        string[] segments = target.Split(';', StringSplitOptions.TrimEntries);
        if (segments.Length == 0) return false;
        foreach (string rawSegment in segments)
        {
            if (string.IsNullOrEmpty(rawSegment)) return false;
            ReadOnlySpan<char> endpoint = rawSegment.AsSpan();
            int equals = endpoint.IndexOf('=');
            if (equals >= 0)
            {
                ReadOnlySpan<char> scheme = endpoint[..equals].Trim();
                if (!IsSupportedProxySchemePrefix(scheme)) return false;
                endpoint = endpoint[(equals + 1)..].Trim();
            }
            if (!IsSingleLoopbackHostPort(endpoint)) return false;
        }
        return true;
    }

    private static bool IsSupportedProxySchemePrefix(ReadOnlySpan<char> scheme) =>
        scheme.Equals("http", StringComparison.OrdinalIgnoreCase) ||
        scheme.Equals("https", StringComparison.OrdinalIgnoreCase) ||
        scheme.Equals("socks", StringComparison.OrdinalIgnoreCase) ||
        scheme.Equals("socks4", StringComparison.OrdinalIgnoreCase) ||
        scheme.Equals("socks5", StringComparison.OrdinalIgnoreCase) ||
        scheme.Equals("ftp", StringComparison.OrdinalIgnoreCase);

    private static bool IsSingleLoopbackHostPort(ReadOnlySpan<char> endpoint)
    {
        if (endpoint.IsEmpty) return false;
        foreach (char ch in endpoint)
            if (char.IsWhiteSpace(ch) || char.IsControl(ch)) return false;

        ReadOnlySpan<char> host;
        ReadOnlySpan<char> portSpan;
        if (endpoint[0] == '[')
        {
            int close = endpoint.IndexOf(']');
            if (close <= 1 || close + 2 > endpoint.Length || endpoint[close + 1] != ':') return false;
            host = endpoint[1..close];
            portSpan = endpoint[(close + 2)..];
            if (!IPAddress.TryParse(host, out IPAddress? ipv6) ||
                ipv6.AddressFamily != AddressFamily.InterNetworkV6 ||
                !IPAddress.IsLoopback(ipv6))
                return false;
        }
        else
        {
            int colon = endpoint.LastIndexOf(':');
            if (colon <= 0 || colon + 1 >= endpoint.Length || endpoint[..colon].IndexOf(':') >= 0) return false;
            host = endpoint[..colon];
            portSpan = endpoint[(colon + 1)..];
            if (!host.Equals("localhost", StringComparison.OrdinalIgnoreCase))
            {
                if (!IPAddress.TryParse(host, out IPAddress? ipv4) ||
                    ipv4.AddressFamily != AddressFamily.InterNetwork ||
                    !IPAddress.IsLoopback(ipv4) ||
                    !host.Equals(ipv4.ToString(), StringComparison.Ordinal))
                    return false;
            }
        }

        if (portSpan.Length is < 1 or > 5) return false;
        foreach (char digit in portSpan)
            if (!char.IsAsciiDigit(digit)) return false;
        return int.TryParse(portSpan, NumberStyles.None, CultureInfo.InvariantCulture, out int port) &&
            port is >= 1 and <= 65535;
    }

    private static bool IsPlainMismatch(Finding finding, Dictionary<string, FormatEvidence> formats)
    {
        if (finding.RuleId != MismatchRule || finding.Category is not (FindingCategory.File or FindingCategory.Archive) ||
            finding.Severity >= FindingSeverity.High || finding.IsKnownMalware || finding.CanRemediate || finding.UserSelectedRisk ||
            finding.HandlingReason != FindingHandlingReason.None ||
            finding.SuggestedActions.Any(action => action is not (SuggestedActionKind.None or SuggestedActionKind.ReviewOnly)))
            return false;
        string? path = NormalizePath(string.IsNullOrWhiteSpace(finding.ContentPath) ? finding.Target : finding.ContentPath);
        if (path is null) return false;
        DetectedFileType? described = null;
        DisplayMessage? description = finding.DescriptionMessage;
        if (description is not null)
        {
            try { description.Validate(); }
            catch (InvalidDataException) { return false; }
            if (description.MessageId != MismatchDescription || description.Arguments.Count != 2) return false;
            DisplayArgument argument = description.Arguments[1];
            described = ReadFormat(new(argument.OriginalText, argument.Message));
            if (!IsReferenceFormat(described)) return false;
        }
        if (formats.TryGetValue(path, out FormatEvidence evidence))
            return evidence.Usable && IsReferenceFormat(evidence.Type) && (!described.HasValue || described == evidence.Type);
        // Reports can retain finding descriptors without the optional container graph.
        // Legacy prose alone is not enough to infer a format.
        return IsReferenceFormat(described);
    }

    private static bool IsReferenceFormat(DetectedFileType? type) => type is
        DetectedFileType.CompoundDocument or DetectedFileType.Zip or DetectedFileType.Rar or DetectedFileType.Cabinet or
        DetectedFileType.SevenZip or DetectedFileType.GZip or DetectedFileType.BZip2 or DetectedFileType.Xz or
        DetectedFileType.Zstandard or DetectedFileType.Tar or DetectedFileType.Mp4 or DetectedFileType.Pdf or
        DetectedFileType.Png or DetectedFileType.Jpeg or DetectedFileType.Gif;

    private static DetectedFileType? ReadFormat(MessageText text)
    {
        if (text.Message is { } message)
        {
            try { message.Validate(); }
            catch (InvalidDataException) { return null; }
            if (MessageText.BoundDescriptor(message, text.OriginalText) is null) return null;
            // Archive expansion rewrites FormatText as the archive enum plus an empty
            // suffix (single volume) or the known volume-count message. Unwrap only those
            // structural combinations; an arbitrary descriptor is not a format label.
            if (message.MessageId == "Backend.Concat" && message.Arguments.Count == 2)
            {
                DisplayArgument left = message.Arguments[0], right = message.Arguments[1];
                if (left.Message is null && left.OriginalText.Length == 0)
                    return ReadFormat(new(right.OriginalText, right.Message));
                DetectedFileType? combinedType = ReadFormat(new(left.OriginalText, left.Message));
                if (right.Message is null && right.OriginalText.Length == 0) return combinedType;
                return combinedType is DetectedFileType.Zip or DetectedFileType.Rar or DetectedFileType.SevenZip && IsVolumeCountSuffix(right)
                    ? combinedType : null;
            }
            if (message.Arguments.Count != 0 ||
                !message.MessageId.StartsWith(FormatMessagePrefix, StringComparison.Ordinal) ||
                !message.MessageId.EndsWith(".01", StringComparison.Ordinal)) return null;
            string name = message.MessageId[FormatMessagePrefix.Length..^3];
            return LocalizedFormats.Contains(name, StringComparer.Ordinal) && Enum.TryParse(name, out DetectedFileType type) ? type : null;
        }
        return FormatNames.TryGetValue(text.OriginalText, out DetectedFileType known) ? known : null;
    }

    private static bool IsVolumeCountSuffix(DisplayArgument argument) =>
        argument.Message is { MessageId: "Backend.Core.ContentScanner.ArchiveGraph.ScanContainerArchiveAsync.01", Arguments.Count: 1 } suffix &&
        MessageText.BoundDescriptor(suffix, argument.OriginalText) is not null && suffix.Arguments[0].Message is null &&
        int.TryParse(suffix.Arguments[0].OriginalText, System.Globalization.NumberStyles.None,
            System.Globalization.CultureInfo.InvariantCulture, out int volumes) && volumes > 1;

    private static Dictionary<string, DetectedFileType> BuildFormatNames()
    {
        Dictionary<string, DetectedFileType> names = new(StringComparer.OrdinalIgnoreCase);
        foreach (DetectedFileType type in Enum.GetValues<DetectedFileType>()) names[type.ToString()] = type;
        foreach (string name in LocalizedFormats)
        {
            DetectedFileType type = Enum.Parse<DetectedFileType>(name);
            string id = FormatMessagePrefix + name + ".01";
            names[MessageText.Create(id).OriginalText] = type;
            using (DisplayText.UseCulture(DisplayText.English)) names[DisplayText.Get(id)] = type;
        }
        return names;
    }

    private readonly record struct FormatEvidence(DetectedFileType? Type, bool Usable);

    private static string? NormalizePath(string? path)
    {
        if (string.IsNullOrWhiteSpace(path)) return null;
        string value = path.Replace('/', '\\');
        int member = value.IndexOf("!\\", StringComparison.Ordinal);
        string physical = member < 0 ? value : value[..member];
        try
        {
            if (!Path.IsPathFullyQualified(physical)) return null;
            physical = Path.GetFullPath(physical);
            if (physical.StartsWith("\\\\?\\UNC\\", StringComparison.OrdinalIgnoreCase)) physical = "\\\\" + physical[8..];
            else if (physical.StartsWith("\\\\?\\", StringComparison.Ordinal)) physical = physical[4..];
            return physical + (member < 0 ? "" : value[member..]);
        }
        catch (Exception exception) when (exception is ArgumentException or NotSupportedException or PathTooLongException)
        { return null; }
    }

    // Union by size plus path compression keeps large result sets near linear. Container
    // members and RelatedFilePath aliases share the physical target's presentation group.
    private sealed class PathGroups
    {
        private readonly Dictionary<string, string> _parents = new(StringComparer.OrdinalIgnoreCase);
        private readonly Dictionary<string, int> _sizes = new(StringComparer.OrdinalIgnoreCase);

        public void Link(params string?[] paths)
        {
            string? first = null;
            foreach (string? source in paths)
            {
                string? path = NormalizePath(source);
                if (path is null) continue;
                Add(path);
                int member = path.IndexOf("!\\", StringComparison.Ordinal);
                if (member >= 0) { string outer = path[..member]; Add(outer); Union(path, outer); }
                if (first is null) first = path;
                else Union(first, path);
            }
        }

        public string? Find(params string?[] paths)
        {
            foreach (string? source in paths)
                if (NormalizePath(source) is { } path && _parents.ContainsKey(path)) return Root(path);
            return null;
        }

        private void Add(string path)
        {
            if (_parents.TryAdd(path, path)) _sizes.Add(path, 1);
        }

        private string Root(string path)
        {
            string root = path;
            while (!_parents.Comparer.Equals(root, _parents[root])) root = _parents[root];
            while (!_parents.Comparer.Equals(path, root)) { string next = _parents[path]; _parents[path] = root; path = next; }
            return root;
        }

        private void Union(string left, string right)
        {
            left = Root(left); right = Root(right);
            if (_parents.Comparer.Equals(left, right)) return;
            if (_sizes[left] < _sizes[right]) (left, right) = (right, left);
            _parents[right] = left;
            _sizes[left] += _sizes[right];
        }
    }
}
