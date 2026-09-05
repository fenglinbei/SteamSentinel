using System.Diagnostics;
using System.ComponentModel;
using System.Xml;
using System.Xml.Linq;
using Microsoft.Win32;
using SteamSentinel.Core.Inspection;
using SteamSentinel.Core.Models;
using SteamSentinel.Core.Steam;
using SteamSentinel.Core.Utilities;

namespace SteamSentinel.Core.Scanning;

public sealed partial class RelatedArtifactScanner(RuleSet rules)
{
    public const long MaximumVerificationBytes = 4L * 1024 * 1024 * 1024;
    private readonly Dictionary<string, HashRule> _known = rules.KnownHashes.Where(rule => rule.Malware)
        .ToDictionary(rule => rule.Sha256, StringComparer.OrdinalIgnoreCase);
    private long _relatedBytesHashed;
    private int _relatedFilesHashed;
    private readonly Dictionary<string, (FileStream Stream, string Hash)> _lockedIdentities = new(StringComparer.OrdinalIgnoreCase);
    internal long VerificationBytesRead => _relatedBytesHashed;

    private async Task CollectCoreAsync(SteamLayout layout, ScanReport report, ScanOptions options, CancellationToken token)
    {
        foreach (string template in rules.KnownPathTemplates)
        {
            string path = Environment.ExpandEnvironmentVariables(template);
            if (Directory.Exists(path)) AddCandidate(path, report);
        }
        string programs = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Programs");
        List<string> notes = [];
        foreach (string directory in ContentDiscovery.Children(programs, true, notes, 1024))
        {
            token.ThrowIfCancellationRequested();
            bool loader = File.Exists(Path.Combine(directory, "lib", "library.zip")) &&
                (File.Exists(Path.Combine(directory, "payload.bin")) || Directory.Exists(Path.Combine(directory, "data")) ||
                 Directory.Exists(Path.Combine(directory, "lib", "pymem")));
            if (loader) AddCandidate(directory, report);
        }
        await CollectRunAsync(report, token);
        await CollectTasksAsync(report, token);
        await CollectServicesAsync(report, token);
        foreach (string startup in new[] { Environment.GetFolderPath(Environment.SpecialFolder.Startup), Environment.GetFolderPath(Environment.SpecialFolder.CommonStartup) })
            foreach (string file in ContentDiscovery.Children(startup, false, notes, 512))
            {
                try
                {
                    token.ThrowIfCancellationRequested();
                    if (!file.EndsWith(".lnk", StringComparison.OrdinalIgnoreCase)) { AddCandidate(file, report); continue; }
                    byte[] bytes;
                    await using (FileStream stream = RelatedArtifactReader.Open(file))
                    {
                        if (stream.Length > 1024 * 1024 || stream.Length > MaximumVerificationBytes - _relatedBytesHashed)
                        { Note(report, "启动快捷方式超过单项或关联读取预算：" + file); continue; }
                        bytes = new byte[checked((int)stream.Length)];
                        await stream.ReadExactlyAsync(bytes, token);
                    }
                    _relatedBytesHashed += bytes.Length;
                    report.Metrics.BytesHashed += bytes.Length;
                    ShortcutInspection shortcut = ShortcutInspector.Inspect(bytes);
                    string command = shortcut.Target + " " + shortcut.Arguments;
                    foreach (string target in CommandTargets.Extract(command)) AddCandidate(target, report);
                    var bound = await MatchCoreAsync(command, report, token);
                    if (bound is null) continue;
                    string hash = Hashing.Sha256Bytes(bytes);
                    report.Findings.Add(new Finding
                    {
                        RuleId = "PERSISTENCE-STARTUP-LINK",
                        Category = FindingCategory.Persistence,
                        Severity = FindingSeverity.Critical,
                        Score = 95,
                        Title = "启动快捷方式指向已确认的恶意组件",
                        Description = "只读解析启动目录快捷方式，未启动目标。",
                        Target = file,
                        Sha256 = hash,
                        RelatedFilePath = bound.Value.Path,
                        RelatedFileSha256 = bound.Value.Hash,
                        Evidence = ScriptSignals.Redact(command),
                        CanRemediate = true,
                        SuggestedActions = [SuggestedActionKind.QuarantineFile]
                    });
                }
                catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or Win32Exception)
                { notes.Add("启动目录文件无法读取：" + file); }
            }
        await CollectProcessesAsync(layout, report, token);
        if (options.IncludeExecutionHistory) CollectHistory(report);
        foreach (string note in notes) { report.CoverageNotes.Add(note); report.Coverage = ScanCoverage.Partial; }
    }

    private async Task<(string Path, string Hash)?> MatchCoreAsync(string command, ScanReport report, CancellationToken token)
    {
        string[] paths = CommandTargets.Extract(command).Where(path => !_closureOnly || _proofs.ContainsKey(Path.GetFullPath(path))).ToArray();
        foreach (string path in paths)
        {
            AddCandidate(path, report);
            if (IsCandidate(path)) AddCandidate(Path.GetDirectoryName(path)!, report);
        }
        foreach (string path in paths)
        {
            string? hash = await HashAsync(path, report, token);
            if (hash is not null && (_known.ContainsKey(hash) || MatchesProof(path, hash))) return (path, hash);
        }
        return null;
    }

    private async Task CollectRunAsync(ScanReport report, CancellationToken token)
    {
        foreach ((RegistryHive hive, RegistryView view) in new[] { (RegistryHive.CurrentUser, RegistryView.Default),
            (RegistryHive.LocalMachine, RegistryView.Registry64), (RegistryHive.LocalMachine, RegistryView.Registry32) })
            foreach (string keyPath in new[] { @"Software\Microsoft\Windows\CurrentVersion\Run", @"Software\Microsoft\Windows\CurrentVersion\RunOnce" })
            {
                try
                {
                    using RegistryKey baseKey = RegistryKey.OpenBaseKey(hive, view);
                    using RegistryKey? key = baseKey.OpenSubKey(keyPath);
                    if (key is null) continue;
                    foreach (string name in key.GetValueNames().Take(1024))
                    {
                        token.ThrowIfCancellationRequested();
                        string command = key.GetValue(name, null, RegistryValueOptions.DoNotExpandEnvironmentNames)?.ToString() ?? "";
                        var match = await MatchCoreAsync(command, report, token);
                        if (match is null) continue;
                        bool allowed = CanCloseEntry(match.Value.Path, match.Value.Hash, command, allowPatcher: true);
                        AddCurrent(new Finding
                        {
                            RuleId = "PERSISTENCE-RUN-BOUND",
                            Category = FindingCategory.Persistence,
                            Severity = FindingSeverity.Critical,
                            Score = ProofScore(match.Value.Path, match.Value.Hash),
                            Title = "启动项关联已验证的风险文件",
                            Description = "名称可能变化，按实际目标与文件哈希确认，未知哈希不标记为已知恶意。",
                            Target = command,
                            RegistryHive = hive == RegistryHive.CurrentUser ? "HKCU" : "HKLM",
                            RegistryView = view.ToString(),
                            RegistryKey = keyPath,
                            RegistryValueName = name,
                            RelatedFilePath = match.Value.Path,
                            RelatedFileSha256 = match.Value.Hash,
                            ConfigurationSnapshot = command,
                            Evidence = ScriptSignals.Redact(command),
                            IsKnownMalware = _known.ContainsKey(match.Value.Hash),
                            CanRemediate = allowed,
                            SuggestedActions = allowed ? [SuggestedActionKind.RemoveRegistryValue] : [SuggestedActionKind.ReviewOnly]
                        }, report);
                    }
                }
                catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or System.Security.SecurityException)
                { report.CoverageNotes.Add("关联启动项未完整读取：" + ex.Message); report.Coverage = ScanCoverage.Partial; }
            }
    }

    private async Task CollectTasksAsync(ScanReport report, CancellationToken token)
    {
        string root = RelatedTaskSnapshotReader.TaskRoot;
        List<string> notes = [];
        if (!Directory.Exists(root)) return;
        long xmlBytes = 0;
        foreach (string path in ContentDiscovery.Files(root, notes, 4096, 8, token))
        {
            try
            {
                if (xmlBytes >= 64L * 1024 * 1024) { notes.Add("任务 XML 总读取达到 64 MiB 预算上限。"); break; }
                string task = "\\" + Path.GetRelativePath(root, path);
                RelatedTaskSnapshot snapshot = await RelatedTaskSnapshotReader.ReadUnderRootAsync(task, root, token,
                    count => xmlBytes += count, (int)Math.Min(RelatedTaskSnapshotReader.MaximumBytes, 64L * 1024 * 1024 - xmlBytes));
                foreach (string command in snapshot.Invocations)
                {
                    var match = await MatchCoreAsync(command, report, token);
                    if (match is null) continue;
                    bool allowed = CanCloseEntry(match.Value.Path, match.Value.Hash, command, allowPatcher: true);
                    AddCurrent(new Finding
                    {
                        RuleId = "PERSISTENCE-TASK-BOUND",
                        Category = FindingCategory.Persistence,
                        Severity = FindingSeverity.Critical,
                        Score = ProofScore(match.Value.Path, match.Value.Hash),
                        Title = "计划任务关联已验证的风险文件",
                        Description = "任务配置与目标文件分别核对哈希，仅支持管理员组件可独立复核的内容证据。",
                        Target = task,
                        Sha256 = snapshot.Sha256,
                        RelatedFilePath = match.Value.Path,
                        RelatedFileSha256 = match.Value.Hash,
                        ConfigurationSnapshot = string.Join("\n", snapshot.Invocations),
                        Evidence = ScriptSignals.Redact(command),
                        IsKnownMalware = _known.ContainsKey(match.Value.Hash),
                        CanRemediate = allowed,
                        SuggestedActions = allowed ? [SuggestedActionKind.RemoveScheduledTask] : [SuggestedActionKind.ReviewOnly]
                    }, report);
                    break;
                }
            }
            catch (Exception ex) when (ex is IOException or InvalidDataException or UnauthorizedAccessException or XmlException or Win32Exception)
            { notes.Add($"任务未完整检查：{path}，{ex.Message}"); }
        }
        foreach (string note in notes) { report.CoverageNotes.Add(note); report.Coverage = ScanCoverage.Partial; }
    }

    private async Task CollectServicesAsync(ScanReport report, CancellationToken token)
    {
        try
        {
            using RegistryKey? root = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services");
            if (root is null) return;
            foreach (string name in root.GetSubKeyNames().Take(4096))
            {
                token.ThrowIfCancellationRequested();
                using RegistryKey? service = root.OpenSubKey(name);
                int type = service?.GetValue("Type") is int serviceType ? serviceType : 0;
                if ((type & 0x30) == 0 || (type & 3) != 0) continue; // Never propose driver actions.
                string command = service?.GetValue("ImagePath", null, RegistryValueOptions.DoNotExpandEnvironmentNames)?.ToString() ?? "";
                var match = await MatchCoreAsync(command, report, token);
                if (match is null) continue;
                int start = service?.GetValue("Start") is int serviceStart ? serviceStart : -1;
                if (start is < 2 or > 4) continue;
                bool allowed = CanCloseEntry(match.Value.Path, match.Value.Hash, command, allowPatcher: false);
                AddCurrent(new Finding
                {
                    RuleId = "PERSISTENCE-SERVICE-BOUND",
                    Category = FindingCategory.Persistence,
                    Severity = FindingSeverity.Critical,
                    Score = ProofScore(match.Value.Path, match.Value.Hash),
                    Title = "服务启动链关联已验证的风险文件",
                    Description = "仅已知恶意文件允许禁用此服务启动，不删除服务，也不操作驱动，其他证据仅供核对。",
                    Target = name,
                    ConfigurationSnapshot = command,
                    ConfigurationKind = start.ToString(System.Globalization.CultureInfo.InvariantCulture),
                    RelatedFilePath = match.Value.Path,
                    RelatedFileSha256 = match.Value.Hash,
                    Evidence = ScriptSignals.Redact(command),
                    IsKnownMalware = _known.ContainsKey(match.Value.Hash),
                    CanRemediate = allowed,
                    SuggestedActions = allowed ? [SuggestedActionKind.DisableService] : [SuggestedActionKind.ReviewOnly]
                }, report);
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or System.Security.SecurityException)
        { report.CoverageNotes.Add("服务关联未完整读取：" + ex.Message); report.Coverage = ScanCoverage.Partial; }
    }

    private static void CollectHistory(ScanReport report)
    {
        using RegistryKey? key = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU");
        if (key is null) return;
        foreach (string name in key.GetValueNames().Where(name => name.Length == 1).Take(26))
        {
            string value = key.GetValue(name)?.ToString() ?? "";
            IReadOnlyList<string> signals = ScriptSignals.Analyze(value);
            if (signals.Count == 0) continue;
            report.Findings.Add(new Finding
            {
                RuleId = "HISTORY-CLICKFIX",
                Category = FindingCategory.Persistence,
                Severity = FindingSeverity.High,
                Score = 75,
                Title = "运行历史中出现可疑验证执行链",
                Description = "历史记录不是当前仍在运行的证明，其他启动方式可能不留此记录。",
                Target = "RunMRU/" + name,
                Evidence = string.Join("，", signals),
                CanRemediate = false,
                SuggestedActions = [SuggestedActionKind.ReviewOnly]
            });
        }
    }

    private async Task<string?> HashAsync(string path, ScanReport report, CancellationToken token)
    {
        token.ThrowIfCancellationRequested();
        if (!ContentDiscovery.IsLocalSafePath(path) || !File.Exists(path)) return null;
        if (RelatedArtifactReader.IsProtected(path)) return null;
        path = Path.GetFullPath(path);
        try
        {
            if (_lockedIdentities.TryGetValue(path, out var identity))
            {
                RelatedArtifactReader.ValidatePath(identity.Stream.SafeFileHandle, path);
                return identity.Hash;
            }
            if (_relatedFilesHashed >= 2048 || _relatedBytesHashed >= MaximumVerificationBytes)
            { Note(report, "本批核验达到 4 GiB 或 2048 个文件上限，未核验：" + path); return null; }
            FileStream stream = RelatedArtifactReader.Open(path);
            bool retained = false;
            try
            {
                if (stream.Length > 256L * 1024 * 1024)
                { Note(report, "文件超过单文件 256 MiB 核验上限，未核验：" + path); return null; }
                if (stream.Length > MaximumVerificationBytes - _relatedBytesHashed)
                { Note(report, "本批 4 GiB 核验额度不足，未核验：" + path); return null; }
                _relatedFilesHashed++;
                string hash = await Hashing.Sha256StreamAsync(stream, token, size => { _relatedBytesHashed += size; report.Metrics.BytesHashed += size; });
                // Only one preparation expansion owns these deny-write/delete leases. Never cache across calls or execution.
                if (_closureOnly && _lockedIdentities.Count < 64)
                { _lockedIdentities.Add(path, (stream, hash)); retained = true; }
                return hash;
            }
            finally { if (!retained) await stream.DisposeAsync(); }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or Win32Exception)
        { Note(report, "关联文件无法验证：" + path); return null; }
    }

    private static bool IsCandidate(string path) =>
        ContentDiscovery.IsLocalSafePath(path) && !ContentDiscovery.IsWithin(path, Environment.GetFolderPath(Environment.SpecialFolder.Windows)) &&
        (ContentDiscovery.IsWorkshopContentPath(path) || path.Contains("\\millennium\\", StringComparison.OrdinalIgnoreCase) ||
         path.Contains("\\ServiceApp\\", StringComparison.OrdinalIgnoreCase) ||
         File.Exists(Path.Combine(Path.GetDirectoryName(path) ?? "", "lib", "library.zip")));

    private static bool IsDirect(string command, string target) => CommandTargets.Extract(command).Contains(target, StringComparer.OrdinalIgnoreCase);

    private static void AddCandidate(string path, ScanReport report)
    {
        if (!ContentDiscovery.IsLocalSafePath(path) || RelatedArtifactReader.IsProtected(path) || !File.Exists(path) && !Directory.Exists(path)) return;
        path = Path.GetFullPath(path);
        if (report.CandidateRoots.Contains(path, StringComparer.OrdinalIgnoreCase)) return;
        if (report.CandidateRoots.Count >= 128)
        {
            Note(report, "关联候选路径达到 128 项上限");
            int directoryIndex = report.CandidateRoots.FindLastIndex(Directory.Exists);
            if (!File.Exists(path) || directoryIndex < 0) return;
            report.CandidateRoots.RemoveAt(directoryIndex);
        }
        // Exact command targets precede optional structural directory candidates.
        if (File.Exists(path)) report.CandidateRoots.Insert(report.CandidateRoots.FindIndex(Directory.Exists) is var index && index >= 0 ? index : report.CandidateRoots.Count, path);
        else report.CandidateRoots.Add(path);
    }
}
