using SteamSentinel.Core.Reporting;
using System.ComponentModel;
using System.Diagnostics;
using System.Globalization;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Xml;
using System.Xml.Linq;
using Microsoft.Win32;
using SteamSentinel.Core.Inspection;
using SteamSentinel.Core.Models;
using SteamSentinel.Core.Remediation;
using SteamSentinel.Core.Steam;
using SteamSentinel.Core.Utilities;

namespace SteamSentinel.Core.Scanning;

public sealed partial class SystemScanner
{
    private const int MaximumRandomProgramDirectories = 4096;
    private const int MaximumRandomProgramEntries = 20_000;
    private const int MaximumRandomProgramDepth = 16;
    private readonly RuleSet _rules;
    private readonly Dictionary<string, HashRule> _hashRules;
    private readonly string[] _expandedKnownPaths;

    [GeneratedRegex("^[a-z0-9]{12,32}$", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex RandomDirectoryNameRegex();

    public SystemScanner(RuleSet rules)
    {
        _rules = rules;
        _hashRules = rules.KnownHashes.Where(rule => Validation.IsHexSha256(rule.Sha256))
            .GroupBy(rule => rule.Sha256, StringComparer.OrdinalIgnoreCase)
            .ToDictionary(group => group.Key, group => group.First(), StringComparer.OrdinalIgnoreCase);
        // 构造时预展开路径模板，避免在遍历上千条服务与自启动项时重复展开环境变量
        _expandedKnownPaths = rules.KnownPathTemplates
            .Select(Environment.ExpandEnvironmentVariables)
            .Where(value => !string.IsNullOrWhiteSpace(value))
            .ToArray();
    }

    public async Task ScanAsync(
        ScanReport report,
        ScanOptions options,
        IProgress<ScanProgress>? progress = null,
        CancellationToken cancellationToken = default)
    {
        progress?.Report(new ScanProgress(MessageText.Create("Backend.Core.SystemScanner.ScanAsync.01"), MessageText.Create("Backend.Core.SystemScanner.ScanAsync.02"), 0, 4, MessageText.Create("Backend.Core.SystemScanner.ScanAsync.03")));
        await ScanProcessesAsync(report, cancellationToken);
        cancellationToken.ThrowIfCancellationRequested();

        progress?.Report(new ScanProgress(MessageText.Create("Backend.Core.SystemScanner.ScanAsync.04"), MessageText.Create("Backend.Core.SystemScanner.ScanAsync.05"), 1, 4, MessageText.Create("Backend.Core.SystemScanner.ScanAsync.06")));
        await ScanKnownPathsAsync(report, cancellationToken);
        ScanRandomProgramDirectories(report, cancellationToken);

        progress?.Report(new ScanProgress(MessageText.Create("Backend.Core.SystemScanner.ScanAsync.07"), MessageText.Create("Backend.Core.SystemScanner.ScanAsync.08"), 2, 4, MessageText.Create("Backend.Core.SystemScanner.ScanAsync.09")));
        ScanRunKeys(report);
        await ScanTaskFilesAsync(report, cancellationToken);
        ScanServiceRegistry(report);

        progress?.Report(new ScanProgress(MessageText.Create("Backend.Core.SystemScanner.ScanAsync.10"), MessageText.Create("Backend.Core.SystemScanner.ScanAsync.11"), 3, 4, MessageText.Create("Backend.Core.SystemScanner.ScanAsync.12")));
        new TrustProxyDiagnosticScanner().Collect(report, progress, cancellationToken);
        ScanHosts(report);
        await ScanSecurityControlsAsync(report, cancellationToken);
    }

    private async Task ScanProcessesAsync(ScanReport report, CancellationToken cancellationToken)
    {
        foreach (Process process in Process.GetProcesses())
        {
            cancellationToken.ThrowIfCancellationRequested();
            report.Metrics.ProcessesVisited++;
            try
            {
                string processName = process.ProcessName;
                string? path = process.MainModule?.FileName;
                bool knownName = _rules.KnownProcessNames.Contains(
                    processName.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) ? processName : processName + ".exe",
                    StringComparer.OrdinalIgnoreCase);
                if (path is null && !knownName) continue;

                string? sha256 = null;
                HashRule? hashRule = null;
                if (path is not null && File.Exists(path) && (knownName || IsSuspiciousProgramPath(path)))
                {
                    long length = new FileInfo(path).Length;
                    // 非已知进程名且超过 64 MiB 的大型宿主进程跳过全量哈希，防止拖慢常规扫描
                    if (knownName || length <= 64L * 1024 * 1024)
                    {
                        sha256 = await Hashing.Sha256FileAsync(path, cancellationToken,
                            bytes => report.Metrics.BytesHashed += bytes, maximumBytes: length);
                        _hashRules.TryGetValue(sha256, out hashRule);
                    }
                }

                if (knownName || hashRule is not null)
                {
                    bool confirmed = hashRule?.Malware == true;
                    report.Findings.Add(new Finding
                    {
                        RuleId = hashRule?.Id ?? "PROCESS-KNOWN-NAME",
                        Category = FindingCategory.Process,
                        Severity = confirmed ? FindingSeverity.Critical : FindingSeverity.Medium,
                        Score = confirmed ? 100 : 45,
                        TitleText = confirmed ? MessageText.Create("Backend.Core.SystemScanner.ScanProcessesAsync.01") : MessageText.Create("Backend.Core.SystemScanner.ScanProcessesAsync.02"),
                        DescriptionText = hashRule?.LabelText ?? MessageText.Create("Backend.Core.SystemScanner.ScanProcessesAsync.03"),
                        Target = path ?? processName,
                        EvidenceText = MessageText.Create("Backend.Core.SystemScanner.ScanProcessesAsync.04", process.Id, path is null ? MessageText.Create("Backend.Core.SystemScanner.ScanProcessesAsync.05") : (MessageText)path),
                        Sha256 = sha256,
                        ProcessId = process.Id,
                        ProcessStartedAtUtc = process.StartTime.ToUniversalTime(),
                        IsKnownMalware = confirmed,
                        CanRemediate = confirmed && path is not null,
                        SuggestedActions = confirmed && path is not null
                            ? [SuggestedActionKind.StopProcess, SuggestedActionKind.QuarantineFile, SuggestedActionKind.BlockKnownDomains]
                            : [SuggestedActionKind.ReviewOnly]
                    });
                }
            }
            catch (Exception ex) when (ex is InvalidOperationException or System.ComponentModel.Win32Exception or IOException or UnauthorizedAccessException)
            {
                // Protected process; skipped without turning the entire scan partial.
            }
            finally
            {
                process.Dispose();
            }
        }
    }

    private async Task ScanKnownPathsAsync(ScanReport report, CancellationToken cancellationToken)
    {
        foreach (string template in _rules.KnownPathTemplates)
        {
            cancellationToken.ThrowIfCancellationRequested();
            string path = Environment.ExpandEnvironmentVariables(template);
            if (!File.Exists(path) && !Directory.Exists(path)) continue;

            string? sha256 = null;
            bool known = false;
            if (File.Exists(path))
            {
                long length = new FileInfo(path).Length;
                sha256 = await Hashing.Sha256FileAsync(path, cancellationToken,
                    bytes => report.Metrics.BytesHashed += bytes, maximumBytes: length);
                known = _hashRules.TryGetValue(sha256, out HashRule? matchedRule) && matchedRule.Malware;
            }

            report.Findings.Add(new Finding
            {
                RuleId = "KNOWN-DROP-PATH",
                Category = FindingCategory.File,
                Severity = known ? FindingSeverity.Critical : FindingSeverity.Low,
                Score = known ? 100 : 20,
                ReasonCode = known ? null : "KnownPathOnly",
                TitleText = known ? MessageText.Create("Backend.Core.SystemScanner.ScanKnownPathsAsync.01") : MessageText.Create("Backend.Core.SystemScanner.ScanKnownPathsAsync.02"),
                DescriptionText = known
                    ? MessageText.Create("Backend.Core.SystemScanner.ScanKnownPathsAsync.03")
                    : Directory.Exists(path)
                        ? MessageText.Create("Backend.Core.SystemScanner.ScanKnownPathsAsync.04")
                        : MessageText.Create("Backend.Core.SystemScanner.ScanKnownPathsAsync.05"),
                Target = path,
                EvidenceText = template,
                Sha256 = sha256,
                IsKnownMalware = known,
                CanRemediate = known && File.Exists(path),
                SuggestedActions = known && File.Exists(path)
                    ? [SuggestedActionKind.QuarantineFile, SuggestedActionKind.BlockKnownDomains]
                    : [SuggestedActionKind.ReviewOnly]
            });
        }
    }

    private void ScanRandomProgramDirectories(ScanReport report, CancellationToken cancellationToken)
    {
        string programs = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Programs");
        ScanRandomProgramDirectoriesUnderRoot(programs, report, cancellationToken);
    }

    /// <summary>
    /// 扫描指定 Programs 根目录下的随机命名 Python 窃密目录；
    /// 保留目录级结构观察记录，并在高置信（score &gt;= 80）且存在安全本地宿主文件时额外产出可隔离的文件级发现。
    /// </summary>
    internal static void ScanRandomProgramDirectoriesUnderRoot(
        string programs,
        ScanReport report,
        CancellationToken cancellationToken)
    {
        if (!Directory.Exists(programs)) return;

        int visitedDirectories = 0;
        int skippedDirectories = 0;
        string? skippedExample = null;
        try
        {
            foreach (string directory in Directory.EnumerateDirectories(programs))
            {
                cancellationToken.ThrowIfCancellationRequested();
                if (++visitedDirectories > MaximumRandomProgramDirectories)
                {
                    AddCoverage(report, MessageText.Create("Backend.Core.SystemScanner.ScanRandomProgramDirectories.01", (MaximumRandomProgramDirectories)), programs);
                    break;
                }
                if (!ContentDiscovery.IsLocalSafePath(directory))
                {
                    skippedDirectories++;
                    skippedExample ??= directory;
                    continue;
                }
                string name = Path.GetFileName(directory);
                if (!RandomDirectoryNameRegex().IsMatch(name)) continue;
                int score = 10;
                List<MessageText> evidence = [MessageText.Create("Backend.Core.SystemScanner.ScanRandomProgramDirectories.02")];
                string hostExePath = Path.Combine(directory, "WindowsUpdatem.exe");
                bool hasHostExe = File.Exists(hostExePath);
                if (hasHostExe) { score += 45; evidence.Add("WindowsUpdatem.exe"); }
                RandomProgramStructure structure = InspectRandomProgramDirectory(directory, cancellationToken);
                if (structure.CoverageNote is not null) AddCoverage(report, structure.CoverageNote, directory);
                if (structure.HasPython) { score += 15; evidence.Add(MessageText.Create("Backend.Core.SystemScanner.ScanRandomProgramDirectories.03")); }
                if (structure.HasPymem) { score += 20; evidence.Add("pymem"); }
                if (structure.HasWin32Crypt) { score += 15; evidence.Add("win32crypt"); }
                if (score < 45) continue;

                int boundedScore = Math.Min(score, 100);
                report.Findings.Add(new Finding
                {
                    RuleId = "STRUCT-RANDOM-PYTHON-STEALER",
                    Category = FindingCategory.File,
                    Severity = score >= 80 ? FindingSeverity.Critical : FindingSeverity.High,
                    Score = boundedScore,
                    TitleText = MessageText.Create("Backend.Core.SystemScanner.ScanRandomProgramDirectories.04"),
                    DescriptionText = MessageText.List(evidence),
                    Target = directory,
                    EvidenceText = MessageText.Create("Backend.Core.SystemScanner.ScanRandomProgramDirectories.05"),
                    IsKnownMalware = false,
                    CanRemediate = false,
                    SuggestedActions = [SuggestedActionKind.ReviewOnly]
                });

                if (score >= 80 && hasHostExe && TryHashSafeLocalFile(hostExePath, report, cancellationToken) is { } hostHash)
                {
                    string fullHostPath = Path.GetFullPath(hostExePath);
                    report.Findings.Add(new Finding
                    {
                        RuleId = "STRUCT-RANDOM-PYTHON-STEALER-HOST",
                        Category = FindingCategory.File,
                        Severity = FindingSeverity.Critical,
                        Score = boundedScore,
                        TitleText = MessageText.Create("Backend.Core.SystemScanner.ScanRandomProgramDirectories.04"),
                        DescriptionText = MessageText.List(evidence),
                        Target = fullHostPath,
                        ContentPath = fullHostPath,
                        Sha256 = hostHash,
                        TargetSha256 = hostHash,
                        EvidenceText = MessageText.Create("Backend.Core.SystemScanner.ScanRandomProgramDirectories.05"),
                        IsKnownMalware = false,
                        CanRemediate = true,
                        SuggestedActions = [SuggestedActionKind.QuarantineFile]
                    });
                }
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            AddCoverage(report, MessageText.Create("Backend.Core.SystemScanner.ScanRandomProgramDirectories.06", (MessageExceptions.Describe(ex))), programs);
        }
        if (skippedDirectories > 0)
            AddCoverage(report, MessageText.Create("Backend.Core.SystemScanner.ScanRandomProgramDirectories.07", (System.FormattableString.Invariant($"{skippedDirectories:N0}")), (skippedExample)), programs);
    }

    private static RandomProgramStructure InspectRandomProgramDirectory(
        string root, CancellationToken cancellationToken)
    {
        bool python = false, pymem = false, win32Crypt = false;
        MessageText? coverageNote = null;
        int visited = 0;
        Stack<(string Path, int Depth)> pending = new();
        pending.Push((root, 0));
        while (pending.TryPop(out var current))
        {
            cancellationToken.ThrowIfCancellationRequested();
            try
            {
                foreach (string entry in Directory.EnumerateFileSystemEntries(current.Path)
                             .Take(Math.Max(0, MaximumRandomProgramEntries - visited) + 1))
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    if (++visited > MaximumRandomProgramEntries)
                    {
                        coverageNote ??= MessageText.Create("Backend.Core.SystemScanner.InspectRandomProgramDirectory.01", (MaximumRandomProgramEntries));
                        return new(python, pymem, win32Crypt, coverageNote);
                    }
                    FileAttributes attributes = File.GetAttributes(entry);
                    if ((attributes & FileAttributes.ReparsePoint) != 0)
                    {
                        coverageNote ??= MessageText.Create("Backend.Core.SystemScanner.InspectRandomProgramDirectory.02", (entry));
                        continue;
                    }
                    string name = Path.GetFileName(entry);
                    if ((attributes & FileAttributes.Directory) != 0)
                    {
                        if (name.Equals("pymem", StringComparison.OrdinalIgnoreCase)) pymem = true;
                        if (current.Depth >= MaximumRandomProgramDepth)
                            coverageNote ??= MessageText.Create("Backend.Core.SystemScanner.InspectRandomProgramDirectory.03", (MaximumRandomProgramDepth), (entry));
                        else pending.Push((entry, current.Depth + 1));
                    }
                    else
                    {
                        if (current.Depth == 0 && name.StartsWith("python3", StringComparison.OrdinalIgnoreCase) &&
                            name.EndsWith(".dll", StringComparison.OrdinalIgnoreCase)) python = true;
                        if (name.Contains("win32crypt", StringComparison.OrdinalIgnoreCase)) win32Crypt = true;
                    }
                    if (python && pymem && win32Crypt) return new(true, true, true, coverageNote);
                }
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                coverageNote ??= MessageText.Create("Backend.Core.SystemScanner.InspectRandomProgramDirectory.04", (current.Path), (MessageExceptions.Describe(ex)));
            }
        }
        return new(python, pymem, win32Crypt, coverageNote);
    }

    private sealed record RandomProgramStructure(bool HasPython, bool HasPymem, bool HasWin32Crypt, MessageText? CoverageNote);

    private void ScanRunKeys(ScanReport report)
    {
        (RegistryHive Hive, RegistryView View, string Name)[] hives =
        [
            (RegistryHive.CurrentUser, RegistryView.Default, "HKCU"),
            (RegistryHive.LocalMachine, RegistryView.Registry64, "HKLM"),
            (RegistryHive.LocalMachine, RegistryView.Registry32, "HKLM32")
        ];
        string[] keys =
        [
            @"Software\Microsoft\Windows\CurrentVersion\Run",
            @"Software\Microsoft\Windows\CurrentVersion\RunOnce"
        ];

        foreach ((RegistryHive hive, RegistryView view, string hiveName) in hives)
            foreach (string keyPath in keys)
            {
                try
                {
                    using RegistryKey baseKey = RegistryKey.OpenBaseKey(hive, view);
                    using RegistryKey? key = baseKey.OpenSubKey(keyPath);
                    if (key is null) continue;
                    foreach (string valueName in key.GetValueNames())
                    {
                        report.Metrics.PersistenceItemsVisited++;
                        string value = key.GetValue(valueName)?.ToString() ?? string.Empty;
                        bool knownName = _rules.KnownRunValueNames.Contains(valueName, StringComparer.OrdinalIgnoreCase);
                        bool knownIndicator = ContainsKnownIndicator(value);
                        bool confirmed = IsConfirmedRunIndicator(valueName, value);
                        if (!knownName && !knownIndicator) continue;

                        report.Findings.Add(new Finding
                        {
                            RuleId = "PERSISTENCE-RUN-KNOWN",
                            Category = FindingCategory.Persistence,
                            Severity = confirmed ? FindingSeverity.Critical : FindingSeverity.High,
                            Score = confirmed ? 100 : 75,
                            TitleText = MessageText.Create("Backend.Core.SystemScanner.ScanRunKeys.01"),
                            DescriptionText = $"{hiveName}\\{keyPath}\\{valueName}",
                            Target = value,
                            EvidenceText = value,
                            RegistryHive = hiveName.StartsWith("HKCU", StringComparison.Ordinal) ? "HKCU" : "HKLM",
                            RegistryView = view.ToString(),
                            RegistryKey = keyPath,
                            RegistryValueName = valueName,
                            IsKnownMalware = confirmed,
                            CanRemediate = knownName,
                            SuggestedActions = knownName
                                ? [SuggestedActionKind.RemoveRegistryValue, SuggestedActionKind.BlockKnownDomains]
                                : [SuggestedActionKind.ReviewOnly]
                        });
                    }
                }
                catch
                {
                    // A single inaccessible registry view should not abort scanning.
                }
            }
    }

    private async Task ScanTaskFilesAsync(ScanReport report, CancellationToken cancellationToken)
    {
        string root = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "System32", "Tasks");
        if (!Directory.Exists(root)) return;
        MessageTextCollection discoveryNotes = [];
        try
        {
            foreach (string file in ContentDiscovery.Files(root, discoveryNotes, 100_000, 32, cancellationToken))
            {
                cancellationToken.ThrowIfCancellationRequested();
                report.Metrics.PersistenceItemsVisited++;
                string relative = Path.GetRelativePath(root, file);
                string taskName = "\\" + relative.Replace(Path.DirectorySeparatorChar, '\\');
                bool normalized = Validation.TryNormalizeScheduledTaskName(taskName, out string normalizedTask);
                bool knownName = normalized && _rules.KnownTaskNames.Any(name =>
                    Validation.TryNormalizeScheduledTaskName(name, out string normalizedKnown) &&
                    normalizedTask.Equals(normalizedKnown, StringComparison.OrdinalIgnoreCase));
                string text = string.Empty;
                byte[]? taskBytes = null;
                try
                {
                    await using FileStream stream = new(file, FileMode.Open, FileAccess.Read, FileShare.Read,
                        64 * 1024, FileOptions.Asynchronous | FileOptions.SequentialScan);
                    if (stream.Length <= 2 * 1024 * 1024)
                    {
                        taskBytes = new byte[checked((int)stream.Length)];
                        await stream.ReadExactlyAsync(taskBytes, cancellationToken);
                        using StreamReader reader = new(new MemoryStream(taskBytes, writable: false), System.Text.Encoding.UTF8, detectEncodingFromByteOrderMarks: true);
                        text = await reader.ReadToEndAsync(cancellationToken);
                    }
                }
                catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { }
                if (!knownName && !ContainsKnownIndicator(text)) continue;
                string? taskSha256 = null;
                if (taskBytes is not null)
                {
                    taskSha256 = Hashing.Sha256Bytes(taskBytes);
                    report.Metrics.BytesHashed += taskBytes.Length;
                }
                else
                {
                    try
                    {
                        taskSha256 = await Hashing.Sha256FileAsync(file, cancellationToken,
                            bytes => report.Metrics.BytesHashed += bytes, maximumBytes: new FileInfo(file).Length);
                    }
                    catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
                    {
                        // The finding remains visible, but an unbound task is not offered for removal.
                    }
                }

                report.Findings.Add(new Finding
                {
                    RuleId = "PERSISTENCE-TASK-KNOWN",
                    Category = FindingCategory.Persistence,
                    Severity = knownName ? FindingSeverity.Critical : FindingSeverity.High,
                    Score = knownName ? 95 : 70,
                    TitleText = MessageText.Create("Backend.Core.SystemScanner.ScanTaskFilesAsync.01"),
                    DescriptionText = knownName ? MessageText.Create("Backend.Core.SystemScanner.ScanTaskFilesAsync.02") : MessageText.Create("Backend.Core.SystemScanner.ScanTaskFilesAsync.03"),
                    Target = taskName,
                    EvidenceText = file,
                    Sha256 = taskSha256,
                    ConfigurationSnapshot = TaskCommandSnapshot(text),
                    IsKnownMalware = knownName,
                    CanRemediate = knownName && taskSha256 is not null,
                    SuggestedActions = knownName && taskSha256 is not null
                        ? [SuggestedActionKind.RemoveScheduledTask]
                        : [SuggestedActionKind.ReviewOnly]
                });
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            AddCoverage(report, MessageText.Create("Backend.Core.SystemScanner.ScanTaskFilesAsync.04", (MessageExceptions.Describe(ex))), root);
        }
        foreach (MessageText note in discoveryNotes.Texts.DistinctBy(n => n.OriginalText).Take(16)) AddCoverage(report, note, root);
        if (discoveryNotes.Count > 16)
            AddCoverage(report, MessageText.Create("Backend.Core.SystemScanner.ScanTaskFilesAsync.05", (System.FormattableString.Invariant($"{discoveryNotes.Count - 16:N0}"))), root);
    }

    private static string? TaskCommandSnapshot(string text)
    {
        if (text.Length == 0 || text.Length > 2 * 1024 * 1024) return null;
        try
        {
            using XmlReader reader = XmlReader.Create(new StringReader(text), new XmlReaderSettings
            { DtdProcessing = DtdProcessing.Prohibit, XmlResolver = null, MaxCharactersInDocument = 2 * 1024 * 1024 });
            XDocument document = XDocument.Load(reader);
            string command = string.Join("\n", document.Descendants().Where(e => e.Name.LocalName == "Exec")
                .Select(e => string.Join(" ", e.Elements().Where(c => c.Name.LocalName is "Command" or "Arguments").Select(c => c.Value))));
            return command.Length is > 0 and <= 32768 ? command : null;
        }
        catch (XmlException) { return null; }
    }

    private void ScanServiceRegistry(ScanReport report)
    {
        try
        {
            using RegistryKey? services = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services");
            if (services is null) return;
            foreach (string serviceName in services.GetSubKeyNames())
            {
                using RegistryKey? service = services.OpenSubKey(serviceName);
                if (service is null) continue;
                // 读取未展开环境变量的原始 ImagePath，确保与 Broker DisableServiceAsync 的注册表快照比对完全一致
                string rawImagePath = service.GetValue("ImagePath", null, RegistryValueOptions.DoNotExpandEnvironmentNames)?.ToString() ?? string.Empty;
                int serviceType = service.GetValue("Type") is int typeValue ? typeValue : 0;
                int startType = service.GetValue("Start") is int startValue ? startValue : -1;
                report.Metrics.PersistenceItemsVisited++;
                if (InspectServiceEntry(serviceName, rawImagePath, serviceType, startType, report) is { } finding)
                    report.Findings.Add(finding);
            }
        }
        catch
        {
            // 普通用户访问受限服务项时不中断整体扫描
        }
    }

    /// <summary>
    /// 评估单条 Windows 服务注册表项：若可执行宿主为本地安全文件且精确命中已知恶意哈希（且满足 Win32 服务类型与启动类型边界），
    /// 则升级为可停用服务（DisableService）；若仅命中服务名或路径子串则保持只读复核（ReviewOnly）。
    /// </summary>
    internal Finding? InspectServiceEntry(
        string serviceName,
        string rawImagePath,
        int serviceType = 0x10,
        int startType = 2,
        ScanReport? report = null,
        CancellationToken cancellationToken = default)
    {
        string expandedImagePath = string.IsNullOrEmpty(rawImagePath)
            ? string.Empty
            : Environment.ExpandEnvironmentVariables(rawImagePath);
        bool indicatorHit = ContainsKnownIndicator(serviceName) ||
            ContainsKnownIndicator(rawImagePath) ||
            ContainsKnownIndicator(expandedImagePath);

        string? exePath = TryExtractServiceExecutablePath(rawImagePath);
        string? hash = null;
        bool knownMalwareHash = false;
        if (exePath is not null && (indicatorHit || IsSuspiciousProgramPath(exePath)))
        {
            hash = TryHashSafeLocalFile(exePath, report, cancellationToken);
            knownMalwareHash = hash is not null &&
                _hashRules.TryGetValue(hash, out HashRule? matchedRule) &&
                matchedRule.Malware &&
                !SteamAlertWatchdog.IsScriptHash(hash);
        }

        if (!indicatorHit && !knownMalwareHash) return null;

        bool validServiceName = serviceName.Length is >= 1 and <= 256 &&
            !serviceName.Any(c => char.IsControl(c) || c is '/' or '\\' or ':');
        bool win32Service = (serviceType & 0x30) != 0 && (serviceType & 3) == 0;
        bool validStart = startType is >= 2 and <= 4;
        bool validSnapshot = !string.IsNullOrWhiteSpace(rawImagePath) && rawImagePath.Length <= 32_768 &&
            exePath is not null && CommandTargets.Extract(rawImagePath).Any(target => PathsEquivalent(target, exePath));

        if (knownMalwareHash && validServiceName && win32Service && validStart && validSnapshot)
        {
            // 与 PERSISTENCE-SERVICE-BOUND、RelatedArtifactExpansion.AddCurrent 及 RemediationPlanBuilder.BoundAction 对齐：
            // Sha256 保持 null（服务注册表项无独立文件本体），宿主二进制哈希写入 RelatedFileSha256 与 TargetSha256，
            // Target 设为服务名以匹配 Broker 停用服务及同计划去重契约。
            return new Finding
            {
                RuleId = "PERSISTENCE-SERVICE-KNOWN",
                Category = FindingCategory.Persistence,
                Severity = FindingSeverity.Critical,
                Score = 95,
                TitleText = MessageText.Create("Backend.Core.SystemScanner.ScanServiceRegistry.01"),
                DescriptionText = serviceName,
                Target = serviceName,
                EvidenceText = ScriptSignals.Redact(rawImagePath),
                TargetSha256 = hash,
                RelatedFilePath = exePath,
                RelatedFileSha256 = hash,
                ConfigurationKind = startType.ToString(CultureInfo.InvariantCulture),
                ConfigurationSnapshot = rawImagePath,
                IsKnownMalware = true,
                CanRemediate = true,
                SuggestedActions = [SuggestedActionKind.DisableService]
            };
        }

        string fallbackTarget = string.IsNullOrWhiteSpace(expandedImagePath) ? serviceName : expandedImagePath;
        return new Finding
        {
            RuleId = "PERSISTENCE-SERVICE-KNOWN",
            Category = FindingCategory.Persistence,
            Severity = FindingSeverity.High,
            Score = 75,
            TitleText = MessageText.Create("Backend.Core.SystemScanner.ScanServiceRegistry.01"),
            DescriptionText = serviceName,
            Target = fallbackTarget,
            EvidenceText = ScriptSignals.Redact(string.IsNullOrWhiteSpace(rawImagePath) ? fallbackTarget : rawImagePath),
            ConfigurationSnapshot = string.IsNullOrWhiteSpace(rawImagePath) || rawImagePath.Length > 32_768 ? null : rawImagePath,
            IsKnownMalware = false,
            CanRemediate = false,
            SuggestedActions = [SuggestedActionKind.ReviewOnly]
        };
    }

    /// <summary>
    /// 从服务 ImagePath 命令行中安全提取主可执行文件本地物理路径（支持引号包裹、环境变量展开与启动参数剥离）。
    /// 受保护系统目录、重解析点、网络路径与不存在目标均返回 null。
    /// </summary>
    internal static string? TryExtractServiceExecutablePath(string? imagePath)
    {
        if (string.IsNullOrWhiteSpace(imagePath) || imagePath.Length > 32_768) return null;
        string expanded;
        try
        {
            expanded = Environment.ExpandEnvironmentVariables(imagePath.Trim()).Trim();
        }
        catch (ArgumentException)
        {
            return null;
        }
        if (expanded.StartsWith(@"\??\", StringComparison.Ordinal))
            expanded = expanded[4..].TrimStart();
        if (expanded.Length == 0) return null;

        if (expanded[0] == '"')
        {
            int endQuote = expanded.IndexOf('"', 1);
            if (endQuote <= 1) return null;
            return ValidateSafeLocalServiceExecutable(expanded[1..endQuote].Trim());
        }

        // 未加引号的 ImagePath：按从左到右出现的 ".exe" + 空白/结尾边界定位主程序路径
        int searchStart = 0;
        while (searchStart < expanded.Length)
        {
            int exeIndex = expanded.IndexOf(".exe", searchStart, StringComparison.OrdinalIgnoreCase);
            if (exeIndex < 0) break;
            int end = exeIndex + 4;
            if (end == expanded.Length || char.IsWhiteSpace(expanded[end]))
            {
                string prefix = expanded[..end].Trim();
                if (ValidateSafeLocalServiceExecutable(prefix) is { } valid) return valid;
                // 若首个 ".exe" 前缀即已不是合法存在的本地安全程序，不再跨参数拼接后续片段，防止误取参数中的路径
                return null;
            }
            searchStart = end;
        }

        return null;
    }

    private static string? ValidateSafeLocalServiceExecutable(string candidate)
    {
        if (string.IsNullOrWhiteSpace(candidate) || candidate.Contains('%', StringComparison.Ordinal)) return null;
        if (!candidate.EndsWith(".exe", StringComparison.OrdinalIgnoreCase)) return null;
        if (!Validation.IsSafeExactTarget(candidate) || !ContentDiscovery.IsLocalSafePath(candidate)) return null;
        try
        {
            string fullPath = Path.GetFullPath(candidate);
            if (!File.Exists(fullPath) || Directory.Exists(fullPath) ||
                Validation.ContainsReparsePoint(fullPath) || RelatedArtifactReader.IsProtected(fullPath))
                return null;
            return fullPath;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException)
        {
            return null;
        }
    }

    /// <summary>
    /// 使用只读防重定向句柄（RelatedArtifactReader.Open）安全计算普通本地文件的 SHA-256，遇到权限、重解析点或超限异常时返回 null。
    /// </summary>
    internal static string? TryHashSafeLocalFile(
        string path,
        ScanReport? report = null,
        CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(path) || !Validation.IsSafeExactTarget(path) || !ContentDiscovery.IsLocalSafePath(path))
            return null;
        try
        {
            string fullPath = Path.GetFullPath(path);
            if (!File.Exists(fullPath) || Directory.Exists(fullPath) ||
                Validation.ContainsReparsePoint(fullPath) || RelatedArtifactReader.IsProtected(fullPath))
                return null;
            using FileStream stream = RelatedArtifactReader.Open(fullPath);
            long length = stream.Length;
            if (length > 256L * 1024 * 1024) return null;
            using IncrementalHash hasher = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
            byte[] buffer = new byte[64 * 1024];
            long totalRead = 0;
            while (true)
            {
                cancellationToken.ThrowIfCancellationRequested();
                int read = stream.Read(buffer, 0, buffer.Length);
                if (read <= 0) break;
                totalRead += read;
                if (totalRead > 256L * 1024 * 1024) return null;
                hasher.AppendData(buffer, 0, read);
                if (report is not null) report.Metrics.BytesHashed += read;
            }
            RelatedArtifactReader.ValidatePath(stream.SafeFileHandle, fullPath);
            return Convert.ToHexString(hasher.GetHashAndReset());
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or Win32Exception or ArgumentException or NotSupportedException)
        {
            return null;
        }
    }

    private void ScanHosts(ScanReport report)
    {
        string hosts = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "drivers", "etc", "hosts");
        try
        {
            if (!File.Exists(hosts)) return;
            string[] lines = File.ReadAllLines(hosts);
            List<string> blocked = [];
            List<string> redirected = [];
            foreach (string raw in lines)
            {
                string line = raw.Split('#')[0].Trim();
                if (line.Length == 0) continue;
                string[] parts = line.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries);
                if (parts.Length < 2) continue;
                foreach (string domain in parts.Skip(1))
                {
                    if (!_rules.KnownDomains.Contains(domain, StringComparer.OrdinalIgnoreCase)) continue;
                    if (parts[0] is "0.0.0.0" or "127.0.0.1" or "::" or "::1") blocked.Add(domain);
                    else redirected.Add($"{domain} → {parts[0]}");
                }
            }

            if (blocked.Count > 0)
            {
                report.Findings.Add(new Finding
                {
                    RuleId = "NETWORK-C2-BLOCKED",
                    Category = FindingCategory.Network,
                    Severity = FindingSeverity.Information,
                    Score = 0,
                    TitleText = MessageText.Create("Backend.Core.SystemScanner.ScanHosts.01"),
                    DescriptionText = string.Join("、", blocked.Distinct(StringComparer.OrdinalIgnoreCase)),
                    Target = hosts,
                    EvidenceText = MessageText.Create("Backend.Core.SystemScanner.ScanHosts.02"),
                    CanRemediate = false,
                    SuggestedActions = [SuggestedActionKind.None]
                });
            }

            if (redirected.Count > 0)
            {
                report.Findings.Add(new Finding
                {
                    RuleId = "NETWORK-C2-HOSTS-REDIRECT",
                    Category = FindingCategory.Network,
                    Severity = FindingSeverity.High,
                    Score = 70,
                    TitleText = MessageText.Create("Backend.Core.SystemScanner.ScanHosts.03"),
                    DescriptionText = string.Join("；", redirected),
                    Target = hosts,
                    EvidenceText = MessageText.Create("Backend.Core.SystemScanner.ScanHosts.04"),
                    CanRemediate = true,
                    SuggestedActions = [SuggestedActionKind.BlockKnownDomains]
                });
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            AddCoverage(report, MessageText.Create("Backend.Core.SystemScanner.ScanHosts.05", (MessageExceptions.Describe(ex))), hosts);
        }
    }

    private async Task ScanSecurityControlsAsync(ScanReport report, CancellationToken cancellationToken)
    {
        const string script = "$m=$null;$p=$null;$f=@();$tp=@();$me=$false;$fe=$false;try{$m=Get-MpComputerStatus -ErrorAction Stop}catch{$me=$true};try{$p=Get-MpPreference -ErrorAction Stop}catch{};try{$f=@(Get-NetFirewallProfile -ErrorAction Stop)}catch{$fe=$true};try{$tp=@(Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct -ErrorAction Stop|?{$_.displayName -and $_.displayName -notmatch 'Windows Defender|Microsoft Defender' -and ($null -eq $_.productState -or (([int]$_.productState -band 0x1000) -ne 0))}|%{$_.displayName})}catch{};[pscustomobject]@{AntivirusEnabled=if($m){[bool]$m.AntivirusEnabled}else{$false};RealTimeProtectionEnabled=if($m){[bool]$m.RealTimeProtectionEnabled}else{$false};BehaviorMonitorEnabled=if($m){[bool]$m.BehaviorMonitorEnabled}else{$false};DefenderUnavailable=$me;FirewallUnavailable=$fe;ThirdPartyAntivirus=@($tp);FirewallDisabled=@($f|?{-not $_.Enabled}|% Name);ExclusionPath=if($p -and $p.ExclusionPath){@($p.ExclusionPath)}else{@()}}|ConvertTo-Json -Compress";
        using JsonDocument? document = await PowerShellProbe.RunJsonAsync(script, TimeSpan.FromSeconds(15), cancellationToken);
        if (document is null)
        {
            AddCoverage(report, MessageText.Create("Backend.Core.SystemScanner.ScanSecurityControlsAsync.01"), "Windows Security");
            return;
        }

        ProcessSecurityControlsJson(document.RootElement, report, _rules);
    }

    /// <summary>
    /// 解析系统安全控制探测 JSON，在存在已启用第三方杀毒软件时避免对被动/停用的 Defender 误报 Partial 或高危告警。
    /// </summary>
    internal static void ProcessSecurityControlsJson(JsonElement root, ScanReport report, RuleSet rules)
    {
        bool antivirus = root.TryGetProperty("AntivirusEnabled", out JsonElement av) && av.ValueKind == JsonValueKind.True;
        bool realtime = root.TryGetProperty("RealTimeProtectionEnabled", out JsonElement rt) && rt.ValueKind == JsonValueKind.True;
        bool behavior = root.TryGetProperty("BehaviorMonitorEnabled", out JsonElement bm) && bm.ValueKind == JsonValueKind.True;
        bool defenderUnavailable = root.TryGetProperty("DefenderUnavailable", out JsonElement du) && du.ValueKind == JsonValueKind.True;
        bool firewallUnavailable = root.TryGetProperty("FirewallUnavailable", out JsonElement fu) && fu.ValueKind == JsonValueKind.True;

        List<string> thirdPartyAntivirus = [];
        if (root.TryGetProperty("ThirdPartyAntivirus", out JsonElement tp))
        {
            if (tp.ValueKind == JsonValueKind.Array)
            {
                thirdPartyAntivirus.AddRange(tp.EnumerateArray()
                    .Select(item => item.ValueKind == JsonValueKind.String ? item.GetString() : item.ToString())
                    .Where(name => !string.IsNullOrWhiteSpace(name))!);
            }
            else if (tp.ValueKind == JsonValueKind.String && !string.IsNullOrWhiteSpace(tp.GetString()))
            {
                thirdPartyAntivirus.Add(tp.GetString()!);
            }
        }
        bool hasThirdPartyAntivirus = thirdPartyAntivirus.Count > 0;

        if ((defenderUnavailable || firewallUnavailable) && !hasThirdPartyAntivirus)
        {
            AddCoverage(report, MessageText.Create("Backend.Core.SystemScanner.ScanSecurityControlsAsync.01"), "Windows Security");
        }

        List<string> disabledProfiles = [];
        if (root.TryGetProperty("FirewallDisabled", out JsonElement disabled))
        {
            if (disabled.ValueKind == JsonValueKind.Array)
            {
                disabledProfiles.AddRange(disabled.EnumerateArray().Select(item => item.ToString()));
            }
            else if (disabled.ValueKind == JsonValueKind.String && !string.IsNullOrWhiteSpace(disabled.GetString()))
            {
                disabledProfiles.Add(disabled.GetString()!);
            }
        }

        bool defenderDisabled = !hasThirdPartyAntivirus && !defenderUnavailable && (!antivirus || !realtime || !behavior);
        if (defenderDisabled || disabledProfiles.Count > 0)
        {
            report.Findings.Add(new Finding
            {
                RuleId = "SECURITY-CONTROLS-DISABLED",
                Category = FindingCategory.SecurityControl,
                Severity = FindingSeverity.High,
                Score = 80,
                TitleText = MessageText.Create("Backend.Core.SystemScanner.ScanSecurityControlsAsync.02"),
                DescriptionText = $"Antivirus={antivirus}; RealTime={realtime}; Behavior={behavior}; ThirdParty={string.Join(',', thirdPartyAntivirus)}; FirewallDisabled={string.Join(',', disabledProfiles)}",
                Target = "Windows Security",
                EvidenceText = MessageText.Create("Backend.Core.SystemScanner.ScanSecurityControlsAsync.03"),
                CanRemediate = true,
                SuggestedActions = [SuggestedActionKind.RestoreSecurityControls]
            });
        }

        if (root.TryGetProperty("ExclusionPath", out JsonElement exclusions))
        {
            IEnumerable<string> values = exclusions.ValueKind switch
            {
                JsonValueKind.Array => exclusions.EnumerateArray().Select(item => item.ToString()),
                JsonValueKind.String => [exclusions.GetString() ?? string.Empty],
                _ => []
            };
            foreach (string exclusion in values.Where(value => !string.IsNullOrWhiteSpace(value)))
            {
                string expanded = Environment.ExpandEnvironmentVariables(exclusion);
                bool known = rules.KnownPathTemplates.Any(template =>
                    PathsEquivalent(expanded, Environment.ExpandEnvironmentVariables(template)) ||
                    expanded.StartsWith(
                        Path.TrimEndingDirectorySeparator(Environment.ExpandEnvironmentVariables(template)) + Path.DirectorySeparatorChar,
                        StringComparison.OrdinalIgnoreCase));
                if (!known) continue;
                report.Findings.Add(new Finding
                {
                    RuleId = "DEFENDER-KNOWN-EXCLUSION",
                    Category = FindingCategory.SecurityControl,
                    Severity = FindingSeverity.High,
                    Score = 80,
                    TitleText = MessageText.Create("Backend.Core.SystemScanner.ScanSecurityControlsAsync.04"),
                    DescriptionText = MessageText.Create("Backend.Core.SystemScanner.ScanSecurityControlsAsync.05"),
                    Target = expanded,
                    EvidenceText = exclusion,
                    CanRemediate = true,
                    SuggestedActions = [SuggestedActionKind.RemoveDefenderExclusion]
                });
            }
        }
    }

    private bool ContainsKnownIndicator(string value)
    {
        if (string.IsNullOrEmpty(value)) return false;
        return _rules.KnownProcessNames.Any(name => value.Contains(name, StringComparison.OrdinalIgnoreCase)) ||
               _rules.KnownRunValueNames.Any(name => value.Contains(name, StringComparison.OrdinalIgnoreCase)) ||
               _rules.KnownTaskNames.Any(name => value.Contains(name, StringComparison.OrdinalIgnoreCase)) ||
               _rules.KnownDomains.Any(domain => ContainsDomain(value, domain)) ||
               _expandedKnownPaths.Any(path => value.Contains(path, StringComparison.OrdinalIgnoreCase));
    }

    public bool IsConfirmedRunIndicator(string valueName, string value) =>
        _rules.KnownRunValueNames.Contains(valueName, StringComparer.OrdinalIgnoreCase) &&
        ContainsKnownIndicator(value);

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

    private static bool IsSuspiciousProgramPath(string path)
    {
        string localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        string appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        string programData = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
        string? publicDirectory = Environment.GetEnvironmentVariable("PUBLIC");
        string desktop = Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory);
        string downloads = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads");
        string temp = Path.GetTempPath();
        return (!string.IsNullOrWhiteSpace(localAppData) && IsWithin(path, localAppData)) ||
               (!string.IsNullOrWhiteSpace(appData) && IsWithin(path, appData)) ||
               (!string.IsNullOrWhiteSpace(programData) && IsWithin(path, programData)) ||
               (!string.IsNullOrWhiteSpace(publicDirectory) && IsWithin(path, publicDirectory)) ||
               IsWithin(path, desktop) || IsWithin(path, downloads) || IsWithin(path, temp) ||
               IsWallpaperWorkshopContentPath(path) || Steam.ContentDiscovery.IsWorkshopContentPath(path);
    }

    public static bool IsWallpaperWorkshopContentPath(string path)
    {
        try
        {
            string separator = Path.DirectorySeparatorChar.ToString();
            string normalized = Path.GetFullPath(path)
                .Replace(Path.AltDirectorySeparatorChar, Path.DirectorySeparatorChar);
            string marker = string.Join(separator, "", "steamapps", "workshop", "content", "431960", "");
            return normalized.Contains(marker, StringComparison.OrdinalIgnoreCase);
        }
        catch
        {
            return false;
        }
    }

    private static bool IsWithin(string path, string root)
    {
        try
        {
            string fullPath = Path.GetFullPath(path);
            string fullRoot = Path.TrimEndingDirectorySeparator(Path.GetFullPath(root));
            return fullPath.StartsWith(fullRoot + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase);
        }
        catch
        {
            return false;
        }
    }

    private static bool PathsEquivalent(string left, string right)
    {
        try
        {
            return string.Equals(Path.TrimEndingDirectorySeparator(Path.GetFullPath(left)),
                Path.TrimEndingDirectorySeparator(Path.GetFullPath(right)), StringComparison.OrdinalIgnoreCase);
        }
        catch
        {
            return false;
        }
    }

    private static void AddCoverage(ScanReport report, MessageText message, string target)
    {
        report.Coverage = ScanCoverage.Partial;
        report.AddCoverageNote(message);
        report.Findings.Add(new Finding
        {
            RuleId = "SYSTEM-SCAN-PARTIAL",
            Category = FindingCategory.Coverage,
            Severity = FindingSeverity.Medium,
            Score = 30,
            TitleText = MessageText.Create("Backend.Core.SystemScanner.AddCoverage.01"),
            DescriptionText = message,
            Target = target,
            CanRemediate = false,
            SuggestedActions = [SuggestedActionKind.ReviewOnly]
        });
    }
}
