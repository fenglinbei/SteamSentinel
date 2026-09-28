using SteamSentinel.Core.Reporting;
using System.Diagnostics;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Xml;
using System.Xml.Linq;
using Microsoft.Win32;
using SteamSentinel.Core.Inspection;
using SteamSentinel.Core.Models;
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

    [GeneratedRegex("^[a-z0-9]{12,32}$", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex RandomDirectoryNameRegex();

    public SystemScanner(RuleSet rules)
    {
        _rules = rules;
        _hashRules = rules.KnownHashes.Where(rule => Validation.IsHexSha256(rule.Sha256))
            .GroupBy(rule => rule.Sha256, StringComparer.OrdinalIgnoreCase)
            .ToDictionary(group => group.Key, group => group.First(), StringComparer.OrdinalIgnoreCase);
    }

    public async Task ScanAsync(
        ScanReport report,
        ScanOptions options,
        IProgress<ScanProgress>? progress = null,
        CancellationToken cancellationToken = default)
    {
        progress?.Report(new ScanProgress(MessageText.Create("Backend.Core.SystemScanner.ScanAsync.01"), MessageText.Create("Backend.Core.SystemScanner.ScanAsync.02"), 0, null, MessageText.Create("Backend.Core.SystemScanner.ScanAsync.03")));
        await ScanProcessesAsync(report, cancellationToken);
        cancellationToken.ThrowIfCancellationRequested();

        progress?.Report(new ScanProgress(MessageText.Create("Backend.Core.SystemScanner.ScanAsync.04"), MessageText.Create("Backend.Core.SystemScanner.ScanAsync.05"), 0, null, MessageText.Create("Backend.Core.SystemScanner.ScanAsync.06")));
        await ScanKnownPathsAsync(report, cancellationToken);
        ScanRandomProgramDirectories(report, cancellationToken);

        progress?.Report(new ScanProgress(MessageText.Create("Backend.Core.SystemScanner.ScanAsync.07"), MessageText.Create("Backend.Core.SystemScanner.ScanAsync.08"), 0, null, MessageText.Create("Backend.Core.SystemScanner.ScanAsync.09")));
        ScanRunKeys(report);
        await ScanTaskFilesAsync(report, cancellationToken);
        ScanServiceRegistry(report);

        progress?.Report(new ScanProgress(MessageText.Create("Backend.Core.SystemScanner.ScanAsync.10"), MessageText.Create("Backend.Core.SystemScanner.ScanAsync.11"), 0, null, MessageText.Create("Backend.Core.SystemScanner.ScanAsync.12")));
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
                    sha256 = await Hashing.Sha256FileAsync(path, cancellationToken,
                        bytes => report.Metrics.BytesHashed += bytes, maximumBytes: length);
                    _hashRules.TryGetValue(sha256, out hashRule);
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
                Severity = known ? FindingSeverity.Critical : FindingSeverity.High,
                Score = known ? 100 : 70,
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
                if (File.Exists(Path.Combine(directory, "WindowsUpdatem.exe"))) { score += 45; evidence.Add("WindowsUpdatem.exe"); }
                RandomProgramStructure structure = InspectRandomProgramDirectory(directory, cancellationToken);
                if (structure.CoverageNote is not null) AddCoverage(report, structure.CoverageNote, directory);
                if (structure.HasPython) { score += 15; evidence.Add(MessageText.Create("Backend.Core.SystemScanner.ScanRandomProgramDirectories.03")); }
                if (structure.HasPymem) { score += 20; evidence.Add("pymem"); }
                if (structure.HasWin32Crypt) { score += 15; evidence.Add("win32crypt"); }
                if (score < 45) continue;

                report.Findings.Add(new Finding
                {
                    RuleId = "STRUCT-RANDOM-PYTHON-STEALER",
                    Category = FindingCategory.File,
                    Severity = score >= 80 ? FindingSeverity.Critical : FindingSeverity.High,
                    Score = Math.Min(score, 100),
                    TitleText = MessageText.Create("Backend.Core.SystemScanner.ScanRandomProgramDirectories.04"),
                    DescriptionText = MessageText.List(evidence),
                    Target = directory,
                    EvidenceText = MessageText.Create("Backend.Core.SystemScanner.ScanRandomProgramDirectories.05"),
                    IsKnownMalware = false,
                    CanRemediate = false,
                    SuggestedActions = [SuggestedActionKind.ReviewOnly]
                });
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
                try
                {
                    FileInfo info = new(file);
                    if (info.Length <= 2 * 1024 * 1024) text = await File.ReadAllTextAsync(file, cancellationToken);
                }
                catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { }
                if (!knownName && !ContainsKnownIndicator(text)) continue;
                string? taskSha256 = null;
                try
                {
                    taskSha256 = await Hashing.Sha256FileAsync(file, cancellationToken,
                        bytes => report.Metrics.BytesHashed += bytes, maximumBytes: new FileInfo(file).Length);
                }
                catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
                {
                    // The finding remains visible, but an unbound task is not offered for removal.
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
                string imagePath = service?.GetValue("ImagePath")?.ToString() ?? string.Empty;
                report.Metrics.PersistenceItemsVisited++;
                if (!ContainsKnownIndicator(serviceName) && !ContainsKnownIndicator(imagePath)) continue;
                report.Findings.Add(new Finding
                {
                    RuleId = "PERSISTENCE-SERVICE-KNOWN",
                    Category = FindingCategory.Persistence,
                    Severity = FindingSeverity.High,
                    Score = 75,
                    TitleText = MessageText.Create("Backend.Core.SystemScanner.ScanServiceRegistry.01"),
                    DescriptionText = serviceName,
                    Target = imagePath,
                    EvidenceText = imagePath,
                    CanRemediate = false,
                    SuggestedActions = [SuggestedActionKind.ReviewOnly]
                });
            }
        }
        catch
        {
            // Standard users may have restricted service key access.
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
        const string script = "$m=Get-MpComputerStatus; $p=Get-MpPreference; $f=Get-NetFirewallProfile; [pscustomobject]@{AntivirusEnabled=$m.AntivirusEnabled;RealTimeProtectionEnabled=$m.RealTimeProtectionEnabled;BehaviorMonitorEnabled=$m.BehaviorMonitorEnabled;FirewallDisabled=@($f|?{-not $_.Enabled}|% Name);ExclusionPath=@($p.ExclusionPath)}|ConvertTo-Json -Compress";
        using JsonDocument? document = await PowerShellProbe.RunJsonAsync(script, TimeSpan.FromSeconds(15), cancellationToken);
        if (document is null)
        {
            AddCoverage(report, MessageText.Create("Backend.Core.SystemScanner.ScanSecurityControlsAsync.01"), "Windows Security");
            return;
        }

        JsonElement root = document.RootElement;
        bool antivirus = root.TryGetProperty("AntivirusEnabled", out JsonElement av) && av.ValueKind == JsonValueKind.True;
        bool realtime = root.TryGetProperty("RealTimeProtectionEnabled", out JsonElement rt) && rt.ValueKind == JsonValueKind.True;
        bool behavior = root.TryGetProperty("BehaviorMonitorEnabled", out JsonElement bm) && bm.ValueKind == JsonValueKind.True;
        List<string> disabledProfiles = [];
        if (root.TryGetProperty("FirewallDisabled", out JsonElement disabled))
        {
            if (disabled.ValueKind == JsonValueKind.Array)
            {
                disabledProfiles.AddRange(disabled.EnumerateArray().Select(item => item.ToString()));
            }
            else if (disabled.ValueKind == JsonValueKind.String)
            {
                disabledProfiles.Add(disabled.GetString()!);
            }
        }

        if (!antivirus || !realtime || !behavior || disabledProfiles.Count > 0)
        {
            report.Findings.Add(new Finding
            {
                RuleId = "SECURITY-CONTROLS-DISABLED",
                Category = FindingCategory.SecurityControl,
                Severity = FindingSeverity.High,
                Score = 80,
                TitleText = MessageText.Create("Backend.Core.SystemScanner.ScanSecurityControlsAsync.02"),
                DescriptionText = $"Antivirus={antivirus}; RealTime={realtime}; Behavior={behavior}; FirewallDisabled={string.Join(',', disabledProfiles)}",
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
                bool known = _rules.KnownPathTemplates.Any(template =>
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
               _rules.KnownPathTemplates.Any(template => value.Contains(
                   Environment.ExpandEnvironmentVariables(template), StringComparison.OrdinalIgnoreCase));
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
        string localPrograms = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Programs");
        string desktop = Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory);
        string downloads = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads");
        string temp = Path.GetTempPath();
        return IsWithin(path, localPrograms) || IsWithin(path, desktop) || IsWithin(path, downloads) || IsWithin(path, temp) ||
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
