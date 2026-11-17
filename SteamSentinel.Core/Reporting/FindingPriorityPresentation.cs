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

        bool[] candidates = new bool[report.Findings.Count];
        HashSet<string> blocked = new(StringComparer.OrdinalIgnoreCase);
        for (int i = 0; i < report.Findings.Count; i++)
        {
            Finding finding = report.Findings[i];
            candidates[i] = !string.IsNullOrWhiteSpace(finding.Id) && idCounts[finding.Id] == 1 &&
                IsPlainMismatch(finding, formats);
            // Another observation on this physical file/container prevents treating the
            // format difference as an isolated reference item, including an inspection gap.
            if (!candidates[i] && groups.Find(finding.Target, finding.ContentPath, finding.RelatedFilePath) is { } group)
                blocked.Add(group);
        }
        for (int i = 0; i < report.Findings.Count; i++)
        {
            Finding finding = report.Findings[i];
            if (candidates[i] && groups.Find(finding.Target, finding.ContentPath, finding.RelatedFilePath) is { } group &&
                !blocked.Contains(group)) result.Add(finding.Id);
        }
        return result;
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
