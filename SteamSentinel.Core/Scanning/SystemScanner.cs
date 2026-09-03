using System.Diagnostics;
using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.Win32;
using SteamSentinel.Core.Inspection;
using SteamSentinel.Core.Models;
using SteamSentinel.Core.Utilities;

namespace SteamSentinel.Core.Scanning;

public sealed partial class SystemScanner
{
    private readonly RuleSet _rules;
    private readonly Dictionary<string, HashRule> _hashRules;

    [GeneratedRegex("^[a-z0-9]{12,32}$", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex RandomDirectoryNameRegex();

    public SystemScanner(RuleSet rules)
    {
        _rules = rules;
        _hashRules = rules.KnownHashes.ToDictionary(rule => rule.Sha256, StringComparer.OrdinalIgnoreCase);
    }

    public async Task ScanAsync(
        ScanReport report,
        ScanOptions options,
        IProgress<ScanProgress>? progress = null,
        CancellationToken cancellationToken = default)
    {
        progress?.Report(new ScanProgress("系统扫描", "活动进程", 0, null, "检查进程映像与已知哈希"));
        await ScanProcessesAsync(report, cancellationToken);
        cancellationToken.ThrowIfCancellationRequested();

        progress?.Report(new ScanProgress("系统扫描", "已知落地点", 0, null, "检查本机落地路径"));
        await ScanKnownPathsAsync(report, cancellationToken);
        ScanRandomProgramDirectories(report);

        progress?.Report(new ScanProgress("系统扫描", "自启动与任务", 0, null, "检查 Run、任务和服务"));
        ScanRunKeys(report);
        ScanTaskFiles(report);
        ScanServiceRegistry(report);

        progress?.Report(new ScanProgress("系统扫描", "安全与网络配置", 0, null, "检查代理、hosts、Defender 和防火墙"));
        ScanProxy(report);
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
                    sha256 = await Hashing.Sha256FileAsync(path, cancellationToken,
                        bytes => report.Metrics.BytesHashed += bytes);
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
                        Title = confirmed ? "已确认恶意进程正在运行" : "进程名称需要哈希复核",
                        Description = hashRule?.Label ?? "进程名称与已知样本相同，但名称也可能被正常程序复用。未命中确认哈希时不会自动处置。",
                        Target = path ?? processName,
                        Evidence = $"PID {process.Id}；映像：{path ?? "无法读取"}",
                        Sha256 = sha256,
                        ProcessId = process.Id,
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
                sha256 = await Hashing.Sha256FileAsync(path, cancellationToken,
                    bytes => report.Metrics.BytesHashed += bytes);
                known = _hashRules.TryGetValue(sha256, out HashRule? matchedRule) && matchedRule.Malware;
            }

            report.Findings.Add(new Finding
            {
                RuleId = "KNOWN-DROP-PATH",
                Category = FindingCategory.File,
                Severity = known ? FindingSeverity.Critical : FindingSeverity.High,
                Score = known ? 100 : 70,
                Title = known ? "已确认恶意落地点仍然存在" : "已知落地点路径需要哈希复核",
                Description = known
                    ? "路径与精确恶意哈希同时命中。"
                    : "路径与已知事件相同，但没有命中精确恶意哈希。路径名可能被其他软件复用，因此不会自动处置。",
                Target = path,
                Evidence = template,
                Sha256 = sha256,
                IsKnownMalware = known,
                CanRemediate = known && File.Exists(path),
                SuggestedActions = known && File.Exists(path)
                    ? [SuggestedActionKind.QuarantineFile, SuggestedActionKind.BlockKnownDomains]
                    : [SuggestedActionKind.ReviewOnly]
            });
        }
    }

    private void ScanRandomProgramDirectories(ScanReport report)
    {
        string programs = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Programs");
        if (!Directory.Exists(programs)) return;

        IEnumerable<string> directories;
        try { directories = Directory.EnumerateDirectories(programs).ToArray(); }
        catch { return; }

        foreach (string directory in directories)
        {
            try
            {
                string name = Path.GetFileName(directory);
                if (!RandomDirectoryNameRegex().IsMatch(name)) continue;
                int score = 10;
                List<string> evidence = ["随机样式目录名"];
                if (File.Exists(Path.Combine(directory, "WindowsUpdatem.exe"))) { score += 45; evidence.Add("WindowsUpdatem.exe"); }
                if (Directory.EnumerateFiles(directory, "python3*.dll", SearchOption.TopDirectoryOnly).Any()) { score += 15; evidence.Add("内嵌 Python"); }
                if (Directory.Exists(Path.Combine(directory, "pymem")) || Directory.EnumerateDirectories(directory, "pymem", SearchOption.AllDirectories).Take(1).Any()) { score += 20; evidence.Add("pymem"); }
                if (Directory.EnumerateFileSystemEntries(directory, "*win32crypt*", SearchOption.AllDirectories).Take(1).Any()) { score += 15; evidence.Add("win32crypt"); }
                if (score < 45) continue;

                report.Findings.Add(new Finding
                {
                    RuleId = "STRUCT-RANDOM-PYTHON-STEALER",
                    Category = FindingCategory.File,
                    Severity = score >= 80 ? FindingSeverity.Critical : FindingSeverity.High,
                    Score = Math.Min(score, 100),
                    Title = "随机程序目录符合 Steam 窃密加载器结构",
                    Description = string.Join("、", evidence),
                    Target = directory,
                    Evidence = "多项结构证据关联命中，处置前请查看目录清单。",
                    IsKnownMalware = false,
                    CanRemediate = false,
                    SuggestedActions = [SuggestedActionKind.ReviewOnly]
                });
            }
            catch
            {
                // Continue with other candidate directories.
            }
        }
    }

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
                            Title = "命中假红信家族自启动项",
                            Description = $"{hiveName}\\{keyPath}\\{valueName}",
                            Target = value,
                            Evidence = value,
                            RegistryHive = hiveName.StartsWith("HKCU", StringComparison.Ordinal) ? "HKCU" : "HKLM",
                            RegistryKey = keyPath,
                            RegistryValueName = valueName,
                            IsKnownMalware = confirmed,
                            CanRemediate = true,
                            SuggestedActions = [SuggestedActionKind.RemoveRegistryValue, SuggestedActionKind.BlockKnownDomains]
                        });
                    }
                }
                catch
                {
                    // A single inaccessible registry view should not abort scanning.
                }
            }
    }

    private void ScanTaskFiles(ScanReport report)
    {
        string root = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "System32", "Tasks");
        if (!Directory.Exists(root)) return;
        try
        {
            foreach (string file in Directory.EnumerateFiles(root, "*", SearchOption.AllDirectories))
            {
                report.Metrics.PersistenceItemsVisited++;
                string relative = Path.GetRelativePath(root, file);
                bool knownName = _rules.KnownTaskNames.Any(name => relative.EndsWith(name, StringComparison.OrdinalIgnoreCase));
                string text = string.Empty;
                try
                {
                    FileInfo info = new(file);
                    if (info.Length <= 2 * 1024 * 1024) text = File.ReadAllText(file);
                }
                catch { }
                if (!knownName && !ContainsKnownIndicator(text)) continue;

                report.Findings.Add(new Finding
                {
                    RuleId = "PERSISTENCE-TASK-KNOWN",
                    Category = FindingCategory.Persistence,
                    Severity = knownName ? FindingSeverity.Critical : FindingSeverity.High,
                    Score = knownName ? 95 : 70,
                    Title = "计划任务包含已知假红信家族指标",
                    Description = knownName ? "任务名称与已确认家族一致，处置前仍应核对任务 XML。" : "任务内容命中指标，但名称未知，首版仅报告。",
                    Target = "\\" + relative.Replace(Path.DirectorySeparatorChar, '\\'),
                    Evidence = file,
                    IsKnownMalware = knownName,
                    CanRemediate = knownName,
                    SuggestedActions = knownName
                        ? [SuggestedActionKind.RemoveScheduledTask]
                        : [SuggestedActionKind.ReviewOnly]
                });
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            AddCoverage(report, $"无法完整读取计划任务：{ex.Message}", root);
        }
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
                    Title = "服务项包含已知假红信家族指标",
                    Description = serviceName,
                    Target = imagePath,
                    Evidence = imagePath,
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

    private static void ScanProxy(ScanReport report)
    {
        try
        {
            using RegistryKey? key = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Internet Settings");
            int enabled = Convert.ToInt32(key?.GetValue("ProxyEnable") ?? 0);
            string server = key?.GetValue("ProxyServer")?.ToString() ?? string.Empty;
            string pac = key?.GetValue("AutoConfigURL")?.ToString() ?? string.Empty;
            if (enabled == 0 && string.IsNullOrWhiteSpace(pac)) return;
            report.Findings.Add(new Finding
            {
                RuleId = "NETWORK-PROXY-PRESENT",
                Category = FindingCategory.Network,
                Severity = FindingSeverity.Information,
                Score = 5,
                Title = "检测到用户代理配置",
                Description = "代理本身不是恶意证据，Clash、调试代理和企业网络都可能合法使用。",
                Target = enabled != 0 ? server : pac,
                Evidence = $"ProxyEnable={enabled}; ProxyServer={server}; AutoConfigURL={pac}",
                CanRemediate = false,
                SuggestedActions = [SuggestedActionKind.ReviewOnly]
            });
        }
        catch
        {
            // Ignore unreadable user proxy settings.
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
                    Title = "已知 C2 已在 hosts 中阻断",
                    Description = string.Join("、", blocked.Distinct(StringComparer.OrdinalIgnoreCase)),
                    Target = hosts,
                    Evidence = "防御性配置，无需删除。",
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
                    Title = "已知 C2 域名被重定向到非阻断地址",
                    Description = string.Join("；", redirected),
                    Target = hosts,
                    Evidence = "需要人工核对 hosts。",
                    CanRemediate = true,
                    SuggestedActions = [SuggestedActionKind.BlockKnownDomains]
                });
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            AddCoverage(report, $"无法读取 hosts：{ex.Message}", hosts);
        }
    }

    private async Task ScanSecurityControlsAsync(ScanReport report, CancellationToken cancellationToken)
    {
        const string script = "$m=Get-MpComputerStatus; $p=Get-MpPreference; $f=Get-NetFirewallProfile; [pscustomobject]@{AntivirusEnabled=$m.AntivirusEnabled;RealTimeProtectionEnabled=$m.RealTimeProtectionEnabled;BehaviorMonitorEnabled=$m.BehaviorMonitorEnabled;FirewallDisabled=@($f|?{-not $_.Enabled}|% Name);ExclusionPath=@($p.ExclusionPath)}|ConvertTo-Json -Compress";
        using JsonDocument? document = await PowerShellProbe.RunJsonAsync(script, TimeSpan.FromSeconds(15), cancellationToken);
        if (document is null)
        {
            AddCoverage(report, "无法通过系统接口读取 Defender/防火墙状态。", "Windows Security");
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
                Title = "Windows 安全防护未完全开启",
                Description = $"Antivirus={antivirus}; RealTime={realtime}; Behavior={behavior}; FirewallDisabled={string.Join(',', disabledProfiles)}",
                Target = "Windows Security",
                Evidence = "可由受控管理员 Broker 恢复基础安全开关。",
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
                    Title = "Defender 排除项指向已知恶意落地点",
                    Description = "排除项可能使恶意目录逃避实时扫描。",
                    Target = expanded,
                    Evidence = exclusion,
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
               _rules.KnownDomains.Any(domain => value.Contains(domain, StringComparison.OrdinalIgnoreCase)) ||
               _rules.KnownPathTemplates.Any(template => value.Contains(
                   Environment.ExpandEnvironmentVariables(template), StringComparison.OrdinalIgnoreCase));
    }

    public bool IsConfirmedRunIndicator(string valueName, string value) =>
        _rules.KnownRunValueNames.Contains(valueName, StringComparer.OrdinalIgnoreCase) &&
        ContainsKnownIndicator(value);

    private static bool IsSuspiciousProgramPath(string path)
    {
        string localPrograms = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Programs");
        string desktop = Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory);
        string downloads = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads");
        string temp = Path.GetTempPath();
        return IsWithin(path, localPrograms) || IsWithin(path, desktop) || IsWithin(path, downloads) || IsWithin(path, temp) ||
               IsWallpaperWorkshopContentPath(path);
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

    private static void AddCoverage(ScanReport report, string message, string target)
    {
        report.Coverage = ScanCoverage.Partial;
        report.CoverageNotes.Add(message);
        report.Findings.Add(new Finding
        {
            RuleId = "SYSTEM-SCAN-PARTIAL",
            Category = FindingCategory.Coverage,
            Severity = FindingSeverity.Medium,
            Score = 30,
            Title = "系统扫描未完整",
            Description = message,
            Target = target,
            CanRemediate = false,
            SuggestedActions = [SuggestedActionKind.ReviewOnly]
        });
    }
}
