using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace SteamSentinel.Core.Inspection;

public static partial class ArchiveVolumeResolver
{
    [GeneratedRegex("^(.*)\\.part([0-9]{1,9})\\.rar$", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex RarNumbered();
    [GeneratedRegex("^(.*)\\.([r-z])([0-9]{2})$", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex RarLegacy();
    [GeneratedRegex("^(.*\\.(?:zip|7z))\\.([0-9]{3,9})$", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex NumericSplit();
    [GeneratedRegex("^(.*)\\.z([0-9]{2,9})$", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex ZipSpanned();

    private sealed record Name(ArchiveVolumeFormat Format, ArchiveVolumeLayout Layout, string Family, int Index);

    public static ArchiveVolumePlan Resolve(ArchiveVolumeCandidate selected,
        IEnumerable<ArchiveVolumeCandidate> candidates, ArchiveVolumeLimits? limits = null)
    {
        limits ??= new(); limits.Validate();
        ValidateCandidate(selected);
        string logical = Normalize(selected.DisplayName);
        string directory = DirectoryOf(logical);
        Name? selectedName = Parse(Leaf(logical));
        if (selectedName is null) return Result(ArchiveVolumeStatus.NotArchive, "不是已知分卷命名。");
        List<(ArchiveVolumeCandidate Candidate, Name Name)> matching = [];
        int seen = 0;
        bool found = false;
        foreach (ArchiveVolumeCandidate candidate in candidates)
        {
            if (++seen > limits.MaximumCandidates) return Result(ArchiveVolumeStatus.LimitExceeded, "同目录候选数达到上限。");
            ValidateCandidate(candidate);
            string name = Normalize(candidate.DisplayName);
            if (!string.Equals(DirectoryOf(name), directory, StringComparison.OrdinalIgnoreCase)) continue;
            Name? parsed = Parse(Leaf(name));
            if (parsed is null || parsed.Format != selectedName.Format ||
                !string.Equals(parsed.Family, selectedName.Family, StringComparison.OrdinalIgnoreCase)) continue;
            matching.Add((candidate, parsed));
            found |= string.Equals(Path.GetFullPath(candidate.PhysicalPath), Path.GetFullPath(selected.PhysicalPath), StringComparison.OrdinalIgnoreCase) &&
                string.Equals(name, logical, StringComparison.OrdinalIgnoreCase) && candidate.Offset == selected.Offset && candidate.Length == selected.Length;
            if (matching.Count > limits.MaximumVolumes) return Result(ArchiveVolumeStatus.LimitExceeded, "分卷数量达到上限。");
        }
        if (!found) return Result(ArchiveVolumeStatus.Unavailable, "选中卷未包含在明确提供的候选中。");
        ArchiveVolumeLayout layout = selectedName.Layout;
        ArchiveVolumeLayout[] layouts = matching.Select(m => m.Name.Layout).Distinct().ToArray();
        if (layouts.Contains(ArchiveVolumeLayout.NumericSplit) && layouts.Length != 1 ||
            layouts.Contains(ArchiveVolumeLayout.RarNumbered) && layouts.Length != 1)
            return Result(ArchiveVolumeStatus.MixedVolumes, "同名归档混用了不同分卷方案。");
        if (layouts.Contains(ArchiveVolumeLayout.RarLegacy)) layout = ArchiveVolumeLayout.RarLegacy;
        if (layouts.Contains(ArchiveVolumeLayout.ZipSpanned)) layout = ArchiveVolumeLayout.ZipSpanned;
        List<(ArchiveVolumeCandidate Candidate, int Index)> indexed = matching.Select(m => (m.Candidate,
            m.Name.Layout == ArchiveVolumeLayout.Single && layout == ArchiveVolumeLayout.ZipSpanned ? int.MaxValue : m.Name.Index)).ToList();
        if (indexed.Select(m => m.Index).Distinct().Count() != indexed.Count ||
            indexed.Select(m => Path.GetFullPath(m.Candidate.PhysicalPath)).Distinct(StringComparer.OrdinalIgnoreCase).Count() != indexed.Count)
            return Result(ArchiveVolumeStatus.DuplicateVolume, "分卷序号或物理文件重复。");
        indexed.Sort((a, b) => a.Index.CompareTo(b.Index));
        int first = layout is ArchiveVolumeLayout.RarNumbered or ArchiveVolumeLayout.NumericSplit or ArchiveVolumeLayout.ZipSpanned ? 1 : 0;
        int count = indexed.Count;
        if (layout == ArchiveVolumeLayout.ZipSpanned)
        {
            if (indexed[^1].Index != int.MaxValue) return Result(ArchiveVolumeStatus.MissingVolume, "ZIP 分盘归档缺少最终 .zip 卷。");
            count--;
        }
        for (int i = 0; i < count; i++)
            if (indexed[i].Index != first + i) return Result(ArchiveVolumeStatus.MissingVolume, "分卷首卷缺失或编号不连续。");
        return new(ArchiveVolumeStatus.Ready, selectedName.Format, layout, Key(directory, selectedName.Family),
            indexed.Select(m => m.Candidate), "命名归组完成，尚需验证各卷元数据。", limits);

        ArchiveVolumePlan Result(ArchiveVolumeStatus status, string detail) => new(status,
            selectedName?.Format ?? ArchiveVolumeFormat.Zip, selectedName?.Layout ?? ArchiveVolumeLayout.Single,
            selectedName is null ? "" : Key(directory, selectedName.Family), [], detail, limits);
    }

    /// <summary>For content-signature detection, including safely extracted payloads without a known extension.</summary>
    public static ArchiveVolumePlan Single(ArchiveVolumeCandidate candidate, ArchiveVolumeFormat format,
        ArchiveVolumeLimits? limits = null)
    {
        limits ??= new(); limits.Validate(); ValidateCandidate(candidate);
        if (!Enum.IsDefined(format)) throw new ArgumentOutOfRangeException(nameof(format));
        return new(ArchiveVolumeStatus.Ready, format, ArchiveVolumeLayout.Single,
            Key(DirectoryOf(Normalize(candidate.DisplayName)), Leaf(Normalize(candidate.DisplayName))),
            [candidate], "单一明确输入，尚需验证归档元数据。", limits);
    }

    private static Name? Parse(string leaf)
    {
        Match match = RarNumbered().Match(leaf);
        if (match.Success) return new(ArchiveVolumeFormat.Rar, ArchiveVolumeLayout.RarNumbered,
            match.Groups[1].Value + ".rar", Number(match.Groups[2].Value));
        // .z01 belongs to ZIP in this bounded adapter; obsolete RAR rollovers beyond .y99
        // are deliberately not guessed from this ambiguous suffix.
        match = ZipSpanned().Match(leaf);
        if (match.Success) return new(ArchiveVolumeFormat.Zip, ArchiveVolumeLayout.ZipSpanned,
            match.Groups[1].Value + ".zip", Number(match.Groups[2].Value));
        match = RarLegacy().Match(leaf);
        if (match.Success) return new(ArchiveVolumeFormat.Rar, ArchiveVolumeLayout.RarLegacy,
            match.Groups[1].Value + ".rar", 1 + 100 * (char.ToLowerInvariant(match.Groups[2].Value[0]) - 'r') + Number(match.Groups[3].Value));
        match = NumericSplit().Match(leaf);
        if (match.Success) return new(match.Groups[1].Value.EndsWith(".7z", StringComparison.OrdinalIgnoreCase)
            ? ArchiveVolumeFormat.SevenZip : ArchiveVolumeFormat.Zip, ArchiveVolumeLayout.NumericSplit,
            match.Groups[1].Value, Number(match.Groups[2].Value));
        if (leaf.EndsWith(".rar", StringComparison.OrdinalIgnoreCase)) return new(ArchiveVolumeFormat.Rar, ArchiveVolumeLayout.Single, leaf, 0);
        if (leaf.EndsWith(".7z", StringComparison.OrdinalIgnoreCase)) return new(ArchiveVolumeFormat.SevenZip, ArchiveVolumeLayout.Single, leaf, 0);
        if (leaf.EndsWith(".zip", StringComparison.OrdinalIgnoreCase)) return new(ArchiveVolumeFormat.Zip, ArchiveVolumeLayout.Single, leaf, 0);
        return null;
    }

    private static int Number(string value) => int.Parse(value, NumberStyles.None, CultureInfo.InvariantCulture);
    private static string Normalize(string value) => value.Replace('\\', '/');
    private static string DirectoryOf(string value) => value.LastIndexOf('/') is int index && index >= 0 ? value[..index] : "";
    private static string Leaf(string value) => value[(value.LastIndexOf('/') + 1)..];
    private static string Key(string directory, string family) => Convert.ToHexString(SHA256.HashData(
        Encoding.UTF8.GetBytes("SteamSentinel.ArchiveGroup.v1\n" + directory.ToUpperInvariant() + "\n" + family.ToUpperInvariant())));
    private static void ValidateCandidate(ArchiveVolumeCandidate candidate)
    {
        ArgumentNullException.ThrowIfNull(candidate);
        if (string.IsNullOrEmpty(candidate.PhysicalPath) || candidate.PhysicalPath.Length > 32768 ||
            !Path.IsPathFullyQualified(candidate.PhysicalPath) || string.IsNullOrEmpty(candidate.DisplayName) ||
            candidate.DisplayName.Length > 65536 || candidate.DisplayName.Any(char.IsControl) ||
            candidate.PhysicalPath.Any(char.IsControl) || Leaf(Normalize(candidate.DisplayName)).Length == 0 ||
            candidate.Offset < 0 || candidate.Length is <= 0)
            throw new ArgumentException("归档候选路径或逻辑名称无效。", nameof(candidate));
    }
}
