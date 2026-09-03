using System.Diagnostics;
using System.Text;
using Microsoft.Win32;
using SteamSentinel.Core.Models;
using SteamSentinel.Core.Rules;
using SteamSentinel.Core.Steam;
using SteamSentinel.Core.Utilities;

namespace SteamSentinel.Broker;

internal sealed class BrokerEngine
{
    private readonly RuleSet _rules = RuleLoader.LoadEmbedded();
    private readonly SteamLayout _steamLayout = SteamLocator.Discover();
    private RemediationRunResult _result = null!;
    private QuarantineManifest _manifest = null!;
    private string _incidentRoot = string.Empty;
    private string _manifestPath = string.Empty;
    private bool _persistOwnManifest;

    public async Task<RemediationRunResult> ExecuteAsync(RemediationPlan plan, CancellationToken cancellationToken = default)
    {
        ValidatePlan(plan);
        foreach (RemediationAction action in plan.Actions) ValidateAction(action);
        _result = new RemediationRunResult { PlanId = plan.PlanId };
        _persistOwnManifest = plan.Actions[0].Type is not (RemediationActionType.RollbackIncident or RemediationActionType.DeleteIncident);
        if (_persistOwnManifest)
        {
            _incidentRoot = Path.Combine(AppPaths.QuarantineRoot, _result.IncidentId.ToString("D"));
            _manifestPath = Path.Combine(_incidentRoot, "manifest.json");
            Directory.CreateDirectory(_incidentRoot);
            _manifest = new QuarantineManifest
            {
                IncidentId = _result.IncidentId,
                PlanId = plan.PlanId
            };
            _result.ManifestPath = _manifestPath;
            await PersistManifestAsync(cancellationToken);
        }

        foreach (RemediationAction action in plan.Actions)
        {
            cancellationToken.ThrowIfCancellationRequested();
            RemediationActionResult actionResult = new()
            {
                ActionId = action.ActionId,
                Type = action.Type,
                Target = action.Target
            };
            try
            {
                ValidateAction(action);
                actionResult.Message = await ExecuteActionAsync(action, cancellationToken);
                actionResult.Success = true;
            }
            catch (Exception ex)
            {
                actionResult.Success = false;
                actionResult.Message = $"{ex.GetType().Name}: {ex.Message}";
                _result.Errors.Add($"{action.DisplayName}: {actionResult.Message}");
            }
            _result.Actions.Add(actionResult);
            if (_persistOwnManifest) await PersistManifestAsync(cancellationToken);
        }

        _result.CompletedAtUtc = DateTimeOffset.UtcNow;
        _result.Success = _result.Errors.Count == 0 && _result.Actions.All(action => action.Success);
        if (_persistOwnManifest) await PersistManifestAsync(cancellationToken);
        return _result;
    }

    private void ValidatePlan(RemediationPlan plan)
    {
        if (plan.SchemaVersion != "1") throw new InvalidDataException("不支持的处置计划版本。");
        DateTimeOffset now = DateTimeOffset.UtcNow;
        if (plan.CreatedAtUtc > now.AddMinutes(2) || plan.ExpiresAtUtc < now ||
            plan.ExpiresAtUtc - plan.CreatedAtUtc > TimeSpan.FromHours(1))
        {
            throw new InvalidDataException("处置计划已过期或时间范围异常，请重新生成。");
        }
        if (plan.Actions.Count is < 1 or > 64) throw new InvalidDataException("处置动作数量不在允许范围内。");
        if (plan.RequestedBy.Length > 256 || plan.RequestedBySid.Length > 184)
            throw new InvalidDataException("处置计划请求者字段异常。");
        bool hasIncidentLifecycleAction = plan.Actions.Any(action =>
            action.Type is RemediationActionType.RollbackIncident or RemediationActionType.DeleteIncident);
        if (hasIncidentLifecycleAction && plan.Actions.Count != 1)
            throw new InvalidDataException("回滚或永久删除必须使用单独的处置计划。");
    }

    private void ValidateAction(RemediationAction action)
    {
        if (action.Target.Length > 32_768 || action.DisplayName.Length > 500)
            throw new InvalidDataException("动作字段过长。");

        switch (action.Type)
        {
            case RemediationActionType.StopProcess:
                if (action.ProcessId is null or <= 4 || !Path.IsPathFullyQualified(action.Target) ||
                    !Validation.IsHexSha256(action.ExpectedSha256))
                    throw new InvalidDataException("进程动作缺少有效 PID、映像路径或 SHA-256。");
                break;
            case RemediationActionType.QuarantineFile:
                ValidateQuarantinePath(action.Target, isDirectory: false, action.ExpectedSha256);
                break;
            case RemediationActionType.QuarantineDirectory:
                ValidateQuarantinePath(action.Target, isDirectory: true, action.ExpectedSha256);
                break;
            case RemediationActionType.RemoveRegistryValue:
                if (action.RegistryHive is not ("HKCU" or "HKLM") ||
                    action.RegistryKey is not (@"Software\Microsoft\Windows\CurrentVersion\Run" or @"Software\Microsoft\Windows\CurrentVersion\RunOnce") ||
                    string.IsNullOrWhiteSpace(action.RegistryValueName) ||
                    action.ExpectedValueData is null ||
                    action.RegistryView is not ("Default" or "Registry32" or "Registry64") ||
                    !_rules.KnownRunValueNames.Contains(action.RegistryValueName, StringComparer.OrdinalIgnoreCase))
                {
                    throw new UnauthorizedAccessException("Broker 只允许删除内置规则确认的 Run/RunOnce 值。");
                }
                break;
            case RemediationActionType.RemoveScheduledTask:
                string taskName = action.TaskName ?? action.Target;
                if (!Validation.TryNormalizeScheduledTaskName(taskName, out string normalizedTask) ||
                    !Validation.IsHexSha256(action.ExpectedSha256) ||
                    !_rules.KnownTaskNames.Any(known =>
                        Validation.TryNormalizeScheduledTaskName(known, out string normalizedKnown) &&
                        normalizedTask.Equals(normalizedKnown, StringComparison.OrdinalIgnoreCase)))
                    throw new UnauthorizedAccessException("任务名称不在内置规则允许列表。");
                break;
            case RemediationActionType.RemoveDefenderExclusion:
                if (!IsKnownPath(action.Target))
                    throw new UnauthorizedAccessException("Defender 排除项不是内置规则确认的恶意路径。");
                break;
            case RemediationActionType.AddProgramFirewallBlock:
                if (!Path.IsPathFullyQualified(action.Target) || !Validation.IsHexSha256(action.ExpectedSha256))
                    throw new InvalidDataException("程序阻断动作缺少绝对路径或 SHA-256。");
                if (!IsAllowedFileTarget(action.Target, action.ExpectedSha256))
                    throw new UnauthorizedAccessException("程序路径不在允许范围，且哈希未命中内置恶意规则。");
                break;
            case RemediationActionType.BlockKnownDomains:
                if (action.Domains.Count == 0 || action.Domains.Any(domain =>
                        !_rules.KnownDomains.Contains(domain, StringComparer.OrdinalIgnoreCase)))
                    throw new UnauthorizedAccessException("域名阻断请求包含非内置规则域名。");
                break;
            case RemediationActionType.RestoreSecurityControls:
                if (action.Target != "Windows Security") throw new InvalidDataException("安全恢复动作目标无效。");
                break;
            case RemediationActionType.RollbackIncident:
            case RemediationActionType.DeleteIncident:
                if (!Guid.TryParse(action.IncidentId ?? action.Target, out _)) throw new InvalidDataException("隔离事件 ID 无效。");
                break;
            default:
                throw new NotSupportedException($"不支持的处置动作：{action.Type}");
        }
    }

    private async Task<string> ExecuteActionAsync(RemediationAction action, CancellationToken cancellationToken) => action.Type switch
    {
        RemediationActionType.StopProcess => await StopProcessAsync(action, cancellationToken),
        RemediationActionType.QuarantineFile => await QuarantineFileAsync(action, cancellationToken),
        RemediationActionType.QuarantineDirectory => await QuarantineDirectoryAsync(action, cancellationToken),
        RemediationActionType.RemoveRegistryValue => await RemoveRegistryValueAsync(action, cancellationToken),
        RemediationActionType.RemoveScheduledTask => await RemoveScheduledTaskAsync(action, cancellationToken),
        RemediationActionType.RemoveDefenderExclusion => await ChangeDefenderExclusionAsync(action, add: false, cancellationToken),
        RemediationActionType.AddProgramFirewallBlock => await AddFirewallRuleAsync(action, cancellationToken),
        RemediationActionType.BlockKnownDomains => await BlockDomainsAsync(action, cancellationToken),
        RemediationActionType.RestoreSecurityControls => await RestoreSecurityControlsAsync(cancellationToken),
        RemediationActionType.RollbackIncident => await RollbackIncidentAsync(action, cancellationToken),
        RemediationActionType.DeleteIncident => await DeleteIncidentAsync(action, cancellationToken),
        _ => throw new NotSupportedException()
    };

    private static async Task<string> StopProcessAsync(RemediationAction action, CancellationToken cancellationToken)
    {
        using Process process = Process.GetProcessById(action.ProcessId!.Value);
        string? image = process.MainModule?.FileName;
        if (image is null || !PathsEquivalent(image, action.Target))
            throw new InvalidOperationException("PID 当前映像与扫描时路径不一致，已拒绝终止。");
        await using SecureFileLease lease = SecureFileLease.Open(image);
        string currentHash = await lease.ComputeSha256Async(cancellationToken);
        if (!currentHash.Equals(action.ExpectedSha256, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("进程映像哈希已变化，已拒绝终止。");
        if (!PathsEquivalent(process.MainModule?.FileName ?? string.Empty, lease.FinalPath))
            throw new InvalidOperationException("进程映像在确认期间发生变化，已拒绝终止。");
        process.Kill(entireProcessTree: true);
        await process.WaitForExitAsync(cancellationToken);
        return $"已终止 PID {action.ProcessId}。";
    }

    private async Task<string> QuarantineFileAsync(RemediationAction action, CancellationToken cancellationToken)
    {
        string source = Path.GetFullPath(action.Target);
        if (!File.Exists(source)) return "目标文件已不存在，无需隔离。";
        await using SecureFileLease lease = SecureFileLease.Open(source);
        if (!IsAllowedFileTarget(lease.FinalPath, action.ExpectedSha256))
            throw new UnauthorizedAccessException("目标文件最终路径不在允许范围。");
        string currentHash = await lease.ComputeSha256Async(cancellationToken);
        if (!currentHash.Equals(action.ExpectedSha256, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("目标文件哈希已变化，已拒绝隔离。");

        string itemRoot = Path.Combine(_incidentRoot, "items", action.ActionId.ToString("N"));
        Directory.CreateDirectory(itemRoot);
        string destination = Path.Combine(itemRoot, SafeName(Path.GetFileName(source)) + ".quarantined");
        QuarantineRecord record = new()
        {
            ActionId = action.ActionId,
            Type = action.Type,
            OriginalTarget = lease.FinalPath,
            QuarantinedPath = destination,
            Sha256 = currentHash
        };
        _manifest.Records.Add(record);
        await PersistManifestAsync(cancellationToken);
        await lease.CopyToAsync(destination, currentHash, cancellationToken);
        lease.DeleteOnClose();
        return $"已隔离文件到 {destination}";
    }

    private async Task<string> QuarantineDirectoryAsync(RemediationAction action, CancellationToken cancellationToken)
    {
        string source = Path.TrimEndingDirectorySeparator(Path.GetFullPath(action.Target));
        if (!Directory.Exists(source)) return "目标目录已不存在，无需隔离。";
        EnsureTreeHasNoReparsePoints(source);
        string currentFingerprint = await DirectoryFingerprint.ComputeAsync(source, cancellationToken);
        if (!currentFingerprint.Equals(action.ExpectedSha256, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("目标目录内容在扫描后发生变化，已拒绝隔离。");
        string itemRoot = Path.Combine(_incidentRoot, "items", action.ActionId.ToString("N"));
        Directory.CreateDirectory(itemRoot);
        string destination = Path.Combine(itemRoot, SafeName(Path.GetFileName(source)) + ".quarantined");
        QuarantineRecord record = new()
        {
            ActionId = action.ActionId,
            Type = action.Type,
            OriginalTarget = source,
            QuarantinedPath = destination,
            Sha256 = currentFingerprint
        };
        _manifest.Records.Add(record);
        await PersistManifestAsync(cancellationToken);

        if (SameVolume(source, destination))
        {
            EnsureTreeHasNoReparsePoints(source);
            string finalFingerprint = await DirectoryFingerprint.ComputeAsync(source, cancellationToken);
            if (!finalFingerprint.Equals(currentFingerprint, StringComparison.OrdinalIgnoreCase))
                throw new InvalidOperationException("目标目录在隔离前发生变化，已拒绝操作。");
            Directory.Move(source, destination);
            EnsureTreeHasNoReparsePoints(destination);
        }
        else
        {
            await CopyDirectoryVerifiedAsync(source, destination, currentFingerprint, cancellationToken);
            await DeleteDirectorySnapshotAsync(source, currentFingerprint, cancellationToken);
        }
        return $"已隔离目录到 {destination}";
    }

    private async Task<string> RemoveRegistryValueAsync(RemediationAction action, CancellationToken cancellationToken)
    {
        RegistryView view = Enum.Parse<RegistryView>(action.RegistryView!, ignoreCase: false);
        RegistryHive hive = action.RegistryHive == "HKCU" ? RegistryHive.CurrentUser : RegistryHive.LocalMachine;
        using RegistryKey baseKey = RegistryKey.OpenBaseKey(hive, view);
        using RegistryKey? key = baseKey.OpenSubKey(action.RegistryKey!, writable: true);
        if (key is null) return "注册表键不存在。";
        object? value = key.GetValue(action.RegistryValueName!, null, RegistryValueOptions.DoNotExpandEnvironmentNames);
        if (value is null) return "注册表值已不存在。";
        if (!string.Equals(value.ToString(), action.ExpectedValueData, StringComparison.Ordinal))
            throw new InvalidOperationException("启动项内容在扫描后发生变化，已拒绝删除。");
        RegistryValueKind kind = key.GetValueKind(action.RegistryValueName!);
        if (kind is not (RegistryValueKind.String or RegistryValueKind.ExpandString))
            throw new InvalidDataException("启动项不是字符串类型，已拒绝自动删除。");
        QuarantineRecord record = new()
        {
            ActionId = action.ActionId,
            Type = action.Type,
            OriginalTarget = action.Target,
            RegistryHive = action.RegistryHive,
            RegistryView = action.RegistryView,
            RegistryKey = action.RegistryKey,
            RegistryValueName = action.RegistryValueName,
            RegistryValueData = value.ToString(),
            RegistryValueKind = (int)kind
        };
        _manifest.Records.Add(record);
        await PersistManifestAsync(cancellationToken);
        key.DeleteValue(action.RegistryValueName!, throwOnMissingValue: false);
        return $"已删除 {action.RegistryHive}\\{action.RegistryKey}\\{action.RegistryValueName}";
    }

    private async Task<string> RemoveScheduledTaskAsync(RemediationAction action, CancellationToken cancellationToken)
    {
        Validation.TryNormalizeScheduledTaskName(action.TaskName ?? action.Target, out string taskName);
        string relative = taskName.TrimStart('\\').Replace('\\', Path.DirectorySeparatorChar);
        string tasksRoot = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "System32", "Tasks");
        string taskFile = Path.GetFullPath(Path.Combine(tasksRoot, relative));
        if (!IsWithin(taskFile, tasksRoot) || Validation.ContainsReparsePoint(Path.GetDirectoryName(taskFile)!))
            throw new UnauthorizedAccessException("计划任务文件路径不安全。");
        string? backup = null;
        if (File.Exists(taskFile))
        {
            backup = Path.Combine(_incidentRoot, "tasks", action.ActionId.ToString("N") + ".xml");
            Directory.CreateDirectory(Path.GetDirectoryName(backup)!);
            await using SecureFileLease taskLease = SecureFileLease.Open(taskFile);
            string taskHash = await taskLease.ComputeSha256Async(cancellationToken);
            if (!taskHash.Equals(action.ExpectedSha256, StringComparison.OrdinalIgnoreCase))
                throw new InvalidOperationException("计划任务内容在扫描后发生变化，已拒绝删除。");
            await taskLease.CopyToAsync(backup, taskHash, cancellationToken);
        }
        _manifest.Records.Add(new QuarantineRecord
        {
            ActionId = action.ActionId,
            Type = action.Type,
            OriginalTarget = taskName,
            QuarantinedPath = backup,
            TaskName = taskName,
            Sha256 = action.ExpectedSha256
        });
        await PersistManifestAsync(cancellationToken);
        ProcessResult result = await RunProcessAsync(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "schtasks.exe"),
            ["/Delete", "/TN", taskName, "/F"], cancellationToken);
        if (result.ExitCode != 0 && File.Exists(taskFile)) throw new InvalidOperationException(result.Error);
        return "计划任务已删除或原本不存在。";
    }

    private async Task<string> ChangeDefenderExclusionAsync(RemediationAction action, bool add, CancellationToken cancellationToken)
    {
        string path = action.Target;
        string operation = add ? "Add-MpPreference" : "Remove-MpPreference";
        string script = "$p=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($env:STEAMSENTINEL_PATH_B64));" +
                        operation + " -ExclusionPath $p -ErrorAction Stop";
        ProcessResult result = await RunEncodedPowerShellAsync(script,
            new Dictionary<string, string> { ["STEAMSENTINEL_PATH_B64"] = Convert.ToBase64String(Encoding.UTF8.GetBytes(path)) },
            cancellationToken);
        if (result.ExitCode != 0) throw new InvalidOperationException(result.Error);
        if (!add)
        {
            _manifest.Records.Add(new QuarantineRecord
            {
                ActionId = action.ActionId,
                Type = action.Type,
                OriginalTarget = path,
                DefenderExclusionPath = path
            });
            await PersistManifestAsync(cancellationToken);
        }
        return add ? "已恢复 Defender 排除项。" : "已移除 Defender 排除项。";
    }

    private async Task<string> AddFirewallRuleAsync(RemediationAction action, CancellationToken cancellationToken)
    {
        if (File.Exists(action.Target))
        {
            if (Validation.ContainsReparsePoint(action.Target))
                throw new UnauthorizedAccessException("程序路径包含重解析点，拒绝添加关联规则。");
            string hash = await Hashing.Sha256FileExclusiveAsync(action.Target, cancellationToken);
            if (!hash.Equals(action.ExpectedSha256, StringComparison.OrdinalIgnoreCase))
                throw new InvalidOperationException("程序哈希已变化，拒绝添加关联规则。");
        }
        else if (!_rules.KnownHashes.Any(rule => rule.Malware && rule.Sha256.Equals(action.ExpectedSha256, StringComparison.OrdinalIgnoreCase)))
        {
            throw new FileNotFoundException("程序已不存在，且计划哈希不是内置已知恶意哈希。", action.Target);
        }

        string name = $"SteamSentinel-{_result.IncidentId:N}-{action.ActionId:N}";
        string netsh = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "netsh.exe");
        ProcessResult command = await RunProcessAsync(netsh,
            ["advfirewall", "firewall", "add", "rule", $"name={name}", "dir=out", "action=block", "enable=yes", "profile=any", $"program={action.Target}"],
            cancellationToken);
        if (command.ExitCode != 0) throw new InvalidOperationException(command.Error);
        _manifest.Records.Add(new QuarantineRecord
        {
            ActionId = action.ActionId,
            Type = action.Type,
            OriginalTarget = action.Target,
            FirewallRuleName = name,
            Sha256 = action.ExpectedSha256
        });
        await PersistManifestAsync(cancellationToken);
        return $"已添加出站阻断规则 {name}";
    }

    private async Task<string> BlockDomainsAsync(RemediationAction action, CancellationToken cancellationToken)
    {
        string hosts = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "drivers", "etc", "hosts");
        string original = File.Exists(hosts) ? await File.ReadAllTextAsync(hosts, cancellationToken) : string.Empty;
        string marker = _result.IncidentId.ToString("N");
        if (original.Contains($"# SteamSentinel BEGIN {marker}", StringComparison.Ordinal)) return "本事件的 hosts 阻断已存在。";

        List<string> domains = action.Domains.Distinct(StringComparer.OrdinalIgnoreCase).ToList();
        StringBuilder addition = new();
        if (original.Length > 0 && !original.EndsWith('\n')) addition.AppendLine();
        addition.AppendLine($"# SteamSentinel BEGIN {marker}");
        foreach (string domain in domains)
        {
            addition.AppendLine($"0.0.0.0 {domain}");
            addition.AppendLine($":: {domain}");
        }
        addition.AppendLine($"# SteamSentinel END {marker}");

        _manifest.Records.Add(new QuarantineRecord
        {
            ActionId = action.ActionId,
            Type = action.Type,
            OriginalTarget = hosts,
            HostsDomains = domains
        });
        await PersistManifestAsync(cancellationToken);
        await File.AppendAllTextAsync(hosts, addition.ToString(), new UTF8Encoding(false), cancellationToken);
        return $"已阻断 {domains.Count} 个内置 C2 域名。";
    }

    private static async Task<string> RestoreSecurityControlsAsync(CancellationToken cancellationToken)
    {
        const string script = "Set-MpPreference -DisableRealtimeMonitoring $false -ErrorAction SilentlyContinue; Set-MpPreference -DisableBehaviorMonitoring $false -ErrorAction SilentlyContinue; Set-NetFirewallProfile -All -Enabled True -ErrorAction Stop";
        ProcessResult result = await RunEncodedPowerShellAsync(script, null, cancellationToken);
        if (result.ExitCode != 0) throw new InvalidOperationException(result.Error);
        return "已请求开启 Defender 实时/行为监控及全部防火墙配置。";
    }

    private async Task<string> RollbackIncidentAsync(RemediationAction action, CancellationToken cancellationToken)
    {
        Guid incidentId = Guid.Parse(action.IncidentId ?? action.Target);
        string incidentRoot = GetIncidentRoot(incidentId);
        string manifestPath = Path.Combine(incidentRoot, "manifest.json");
        if (Validation.ContainsReparsePoint(incidentRoot))
            throw new UnauthorizedAccessException("隔离事件包含重解析点，拒绝回滚。");
        QuarantineManifest manifest = await JsonFile.ReadAsync<QuarantineManifest>(manifestPath, cancellationToken);
        if (manifest.SchemaVersion != "1" || manifest.IncidentId != incidentId)
            throw new InvalidDataException("隔离清单身份与目录不一致。");
        if (manifest.Records.Count > 64 || manifest.Records.Select(record => record.ActionId).Distinct().Count() != manifest.Records.Count)
            throw new InvalidDataException("隔离清单记录数量或动作 ID 异常。");
        foreach (QuarantineRecord record in manifest.Records)
            ValidateQuarantineRecord(record, incidentRoot, incidentId);

        foreach (QuarantineRecord record in manifest.Records.AsEnumerable().Reverse())
        {
            if (record.RolledBack) continue;
            switch (record.Type)
            {
                case RemediationActionType.QuarantineFile:
                    await RestoreFileAsync(record, cancellationToken);
                    break;
                case RemediationActionType.QuarantineDirectory:
                    await RestoreDirectoryAsync(record, cancellationToken);
                    break;
                case RemediationActionType.RemoveRegistryValue:
                    RestoreRegistryValue(record);
                    break;
                case RemediationActionType.RemoveScheduledTask:
                    await RestoreScheduledTaskAsync(record, cancellationToken);
                    break;
                case RemediationActionType.RemoveDefenderExclusion:
                    await ChangeDefenderExclusionAsync(new RemediationAction
                    {
                        Type = RemediationActionType.RemoveDefenderExclusion,
                        Target = record.DefenderExclusionPath ?? record.OriginalTarget
                    }, add: true, cancellationToken);
                    break;
                case RemediationActionType.AddProgramFirewallBlock:
                    await RemoveFirewallRuleAsync(record.FirewallRuleName, cancellationToken);
                    break;
                case RemediationActionType.BlockKnownDomains:
                    await RemoveHostsMarkerAsync(incidentId, record.OriginalTarget, cancellationToken);
                    break;
            }
            record.RolledBack = true;
            await JsonFile.WriteAtomicAsync(manifestPath, manifest, cancellationToken);
        }
        return $"隔离事件 {incidentId:D} 已回滚。";
    }

    private static async Task<string> DeleteIncidentAsync(RemediationAction action, CancellationToken cancellationToken)
    {
        Guid incidentId = Guid.Parse(action.IncidentId ?? action.Target);
        string incidentRoot = GetIncidentRoot(incidentId);
        if (!Directory.Exists(incidentRoot)) return "隔离事件已不存在。";
        string manifest = Path.Combine(incidentRoot, "manifest.json");
        if (!File.Exists(manifest)) throw new InvalidDataException("隔离目录缺少 manifest.json，拒绝删除。");
        QuarantineManifest manifestData = await JsonFile.ReadAsync<QuarantineManifest>(manifest, cancellationToken);
        if (manifestData.SchemaVersion != "1" || manifestData.IncidentId != incidentId)
            throw new InvalidDataException("隔离清单身份与目录不一致。");
        if (manifestData.Records.Any(record => !record.RolledBack))
        {
            DateTimeOffset currentBootTime = DateTimeOffset.UtcNow - TimeSpan.FromMilliseconds(Environment.TickCount64);
            if (currentBootTime <= manifestData.MachineBootTimeUtc.AddMinutes(1))
                throw new InvalidOperationException("含隔离内容的事件必须在至少一次系统重启后才能永久删除。");
        }
        if (Validation.ContainsReparsePoint(incidentRoot)) throw new UnauthorizedAccessException("隔离事件包含重解析点，拒绝删除。");
        DeleteDirectoryContentsExact(incidentRoot);
        Directory.Delete(incidentRoot, recursive: false);
        return $"隔离事件 {incidentId:D} 已永久删除。";
    }

    private async Task RestoreFileAsync(QuarantineRecord record, CancellationToken cancellationToken)
    {
        if (record.QuarantinedPath is null || !File.Exists(record.QuarantinedPath)) return;
        if (File.Exists(record.OriginalTarget) || Directory.Exists(record.OriginalTarget))
            throw new IOException($"原位置已被占用，拒绝覆盖：{record.OriginalTarget}");
        if (!IsAllowedFileTarget(record.OriginalTarget, record.Sha256) ||
            Validation.ContainsReparsePoint(Path.GetDirectoryName(record.OriginalTarget)!))
            throw new UnauthorizedAccessException("文件原位置不在允许范围或父目录包含重解析点。");
        if (!Directory.Exists(Path.GetDirectoryName(record.OriginalTarget)!))
            throw new DirectoryNotFoundException("文件原位置的父目录已不存在，请人工核对后恢复。");
        await using SecureFileLease lease = SecureFileLease.Open(record.QuarantinedPath);
        string hash = await lease.ComputeSha256Async(cancellationToken);
        if (!hash.Equals(record.Sha256, StringComparison.OrdinalIgnoreCase))
            throw new InvalidDataException("隔离文件哈希与清单不一致。");
        await lease.CopyToAsync(record.OriginalTarget, hash, cancellationToken);
        lease.DeleteOnClose();
    }

    private async Task RestoreDirectoryAsync(QuarantineRecord record, CancellationToken cancellationToken)
    {
        if (record.QuarantinedPath is null || !Directory.Exists(record.QuarantinedPath)) return;
        if (File.Exists(record.OriginalTarget) || Directory.Exists(record.OriginalTarget))
            throw new IOException($"原位置已被占用，拒绝覆盖：{record.OriginalTarget}");
        if (!IsAllowedDirectoryTarget(record.OriginalTarget) ||
            Validation.ContainsReparsePoint(Path.GetDirectoryName(record.OriginalTarget)!))
            throw new UnauthorizedAccessException("目录原位置不在允许范围或父目录包含重解析点。");
        string fingerprint = await DirectoryFingerprint.ComputeAsync(record.QuarantinedPath, cancellationToken);
        if (!fingerprint.Equals(record.Sha256, StringComparison.OrdinalIgnoreCase))
            throw new InvalidDataException("隔离目录指纹与清单不一致。");
        if (!Directory.Exists(Path.GetDirectoryName(record.OriginalTarget)!))
            throw new DirectoryNotFoundException("目录原位置的父目录已不存在，请人工核对后恢复。");
        if (SameVolume(record.QuarantinedPath, record.OriginalTarget))
        {
            Directory.Move(record.QuarantinedPath, record.OriginalTarget);
        }
        else
        {
            await CopyDirectoryVerifiedAsync(record.QuarantinedPath, record.OriginalTarget, fingerprint, cancellationToken);
            await DeleteDirectorySnapshotAsync(record.QuarantinedPath, fingerprint, cancellationToken);
        }
    }

    private static void RestoreRegistryValue(QuarantineRecord record)
    {
        RegistryView view = Enum.Parse<RegistryView>(record.RegistryView!, ignoreCase: false);
        RegistryHive hive = record.RegistryHive == "HKCU" ? RegistryHive.CurrentUser : RegistryHive.LocalMachine;
        using RegistryKey baseKey = RegistryKey.OpenBaseKey(hive, view);
        using RegistryKey key = baseKey.CreateSubKey(record.RegistryKey!, writable: true);
        if (key.GetValue(record.RegistryValueName!) is not null)
            throw new IOException("注册表原值位置已被占用，拒绝覆盖。");
        key.SetValue(record.RegistryValueName!, record.RegistryValueData ?? string.Empty,
            (RegistryValueKind)(record.RegistryValueKind ?? (int)RegistryValueKind.String));
    }

    private static async Task RestoreScheduledTaskAsync(QuarantineRecord record, CancellationToken cancellationToken)
    {
        if (record.QuarantinedPath is null || !File.Exists(record.QuarantinedPath) || record.TaskName is null) return;
        if (!Validation.TryNormalizeScheduledTaskName(record.TaskName, out string normalizedTask))
            throw new InvalidDataException("隔离清单中的计划任务名称无效。");
        string tasksRoot = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "System32", "Tasks");
        string taskFile = Path.Combine(tasksRoot, normalizedTask.TrimStart('\\').Replace('\\', Path.DirectorySeparatorChar));
        if (File.Exists(taskFile)) throw new IOException("计划任务原位置已被占用，拒绝覆盖。");
        string backupHash = await Hashing.Sha256FileExclusiveAsync(record.QuarantinedPath, cancellationToken);
        if (!backupHash.Equals(record.Sha256, StringComparison.OrdinalIgnoreCase))
            throw new InvalidDataException("计划任务备份哈希与隔离清单不一致。");
        ProcessResult result = await RunProcessAsync(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "schtasks.exe"),
            ["/Create", "/TN", normalizedTask, "/XML", record.QuarantinedPath], cancellationToken);
        if (result.ExitCode != 0) throw new InvalidOperationException(result.Error);
    }

    private static async Task RemoveFirewallRuleAsync(string? name, CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(name)) return;
        ProcessResult result = await RunProcessAsync(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "netsh.exe"),
            ["advfirewall", "firewall", "delete", "rule", $"name={name}"], cancellationToken);
        if (result.ExitCode != 0) throw new InvalidOperationException(result.Error);
    }

    private static async Task RemoveHostsMarkerAsync(Guid incidentId, string hosts, CancellationToken cancellationToken)
    {
        if (!File.Exists(hosts)) return;
        string begin = $"# SteamSentinel BEGIN {incidentId:N}";
        string end = $"# SteamSentinel END {incidentId:N}";
        string[] lines = await File.ReadAllLinesAsync(hosts, cancellationToken);
        List<string> kept = [];
        bool inside = false;
        foreach (string line in lines)
        {
            if (line.Trim().Equals(begin, StringComparison.Ordinal)) { inside = true; continue; }
            if (inside && line.Trim().Equals(end, StringComparison.Ordinal)) { inside = false; continue; }
            if (!inside) kept.Add(line);
        }
        if (inside) throw new InvalidDataException("hosts 中的 SteamSentinel 标记不完整，拒绝自动改写。");
        await File.WriteAllLinesAsync(hosts, kept, new UTF8Encoding(false), cancellationToken);
    }

    private void ValidateQuarantineRecord(QuarantineRecord record, string incidentRoot, Guid incidentId)
    {
        if (record.OriginalTarget.Length is 0 or > 32_768)
            throw new InvalidDataException("隔离清单包含无效原目标。");
        if (record.QuarantinedPath is { } quarantined)
        {
            if (!IsWithin(quarantined, incidentRoot))
                throw new UnauthorizedAccessException("隔离清单中的备份路径越界。");
            string existing = File.Exists(quarantined) || Directory.Exists(quarantined)
                ? quarantined
                : Path.GetDirectoryName(quarantined)!;
            if (Validation.ContainsReparsePoint(existing))
                throw new UnauthorizedAccessException("隔离清单中的备份路径包含重解析点。");
        }

        switch (record.Type)
        {
            case RemediationActionType.QuarantineFile:
                if (!Validation.IsHexSha256(record.Sha256) || !IsAllowedFileTarget(record.OriginalTarget, record.Sha256))
                    throw new InvalidDataException("隔离文件记录缺少有效哈希或原路径越界。");
                break;
            case RemediationActionType.QuarantineDirectory:
                if (!Validation.IsHexSha256(record.Sha256) || !IsAllowedDirectoryTarget(record.OriginalTarget))
                    throw new InvalidDataException("隔离目录记录缺少有效指纹或原路径越界。");
                break;
            case RemediationActionType.RemoveRegistryValue:
                if (record.RegistryHive is not ("HKCU" or "HKLM") ||
                    record.RegistryView is not ("Default" or "Registry32" or "Registry64") ||
                    record.RegistryKey is not (@"Software\Microsoft\Windows\CurrentVersion\Run" or @"Software\Microsoft\Windows\CurrentVersion\RunOnce") ||
                    string.IsNullOrWhiteSpace(record.RegistryValueName) ||
                    record.RegistryValueKind is not ((int)RegistryValueKind.String or (int)RegistryValueKind.ExpandString) ||
                    !_rules.KnownRunValueNames.Contains(record.RegistryValueName, StringComparer.OrdinalIgnoreCase))
                    throw new InvalidDataException("隔离清单中的注册表记录不在允许范围。");
                break;
            case RemediationActionType.RemoveScheduledTask:
                if (!Validation.IsHexSha256(record.Sha256) ||
                    !Validation.TryNormalizeScheduledTaskName(record.TaskName, out string normalizedTask) ||
                    !_rules.KnownTaskNames.Any(known =>
                        Validation.TryNormalizeScheduledTaskName(known, out string normalizedKnown) &&
                        normalizedTask.Equals(normalizedKnown, StringComparison.OrdinalIgnoreCase)))
                    throw new InvalidDataException("隔离清单中的计划任务不在允许范围。");
                break;
            case RemediationActionType.RemoveDefenderExclusion:
                if (!IsKnownPath(record.DefenderExclusionPath ?? record.OriginalTarget))
                    throw new InvalidDataException("隔离清单中的 Defender 排除项不在允许范围。");
                break;
            case RemediationActionType.AddProgramFirewallBlock:
                if (record.FirewallRuleName is null ||
                    !record.FirewallRuleName.StartsWith($"SteamSentinel-{incidentId:N}-", StringComparison.Ordinal))
                    throw new InvalidDataException("隔离清单中的防火墙规则名称无效。");
                break;
            case RemediationActionType.BlockKnownDomains:
                string expectedHosts = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "drivers", "etc", "hosts");
                if (!PathsEquivalent(record.OriginalTarget, expectedHosts) ||
                    record.HostsDomains.Any(domain => !_rules.KnownDomains.Contains(domain, StringComparer.OrdinalIgnoreCase)))
                    throw new InvalidDataException("隔离清单中的 hosts 记录无效。");
                break;
            default:
                throw new InvalidDataException("隔离清单包含不支持的记录类型。");
        }
    }

    private void ValidateQuarantinePath(string path, bool isDirectory, string? expectedHash)
    {
        if (!Validation.IsSafeExactTarget(path) || Validation.ContainsReparsePoint(path))
            throw new UnauthorizedAccessException("目标路径不安全或包含重解析点。");
        if (isDirectory)
        {
            if (!Directory.Exists(path) || !Validation.IsHexSha256(expectedHash) || !IsAllowedDirectoryTarget(path))
                throw new UnauthorizedAccessException("目录不在用户数据、已知落地点或工坊项目范围，或缺少有效目录指纹。");
        }
        else
        {
            if (!File.Exists(path) || !Validation.IsHexSha256(expectedHash) || !IsAllowedFileTarget(path, expectedHash))
                throw new UnauthorizedAccessException("文件不在允许范围，或缺少有效哈希。");
        }
    }

    private bool IsAllowedDirectoryTarget(string path)
    {
        if (IsWithin(path, AppPaths.UserStateRoot) || IsWithin(path, AppPaths.MachineStateRoot) ||
            IsWithin(path, AppContext.BaseDirectory) ||
            IsWithin(path, Environment.GetFolderPath(Environment.SpecialFolder.Windows))) return false;
        return IsKnownPath(path) || IsWithin(path, Environment.GetFolderPath(Environment.SpecialFolder.UserProfile)) ||
               _steamLayout.WorkshopRoots.Any(root => IsWithin(path, root));
    }

    private bool IsAllowedFileTarget(string path, string? hash)
    {
        if (IsWithin(path, Environment.GetFolderPath(Environment.SpecialFolder.Windows))) return false;
        if (IsWithin(path, AppPaths.MachineStateRoot) || IsWithin(path, AppContext.BaseDirectory)) return false;
        if (IsKnownPath(path) || IsWithin(path, Environment.GetFolderPath(Environment.SpecialFolder.UserProfile)) ||
            _steamLayout.SteamRoots.Any(root => IsWithin(path, root)) ||
            _steamLayout.LibraryRoots.Any(root => IsWithin(path, root))) return true;
        return Validation.IsHexSha256(hash) && _rules.KnownHashes.Any(rule =>
            rule.Malware && rule.Sha256.Equals(hash, StringComparison.OrdinalIgnoreCase));
    }

    private bool IsKnownPath(string path) => _rules.KnownPathTemplates.Any(template =>
        PathsEquivalent(path, Environment.ExpandEnvironmentVariables(template)) ||
        IsWithin(path, Environment.ExpandEnvironmentVariables(template)));

    private static bool IsWithin(string candidate, string root)
    {
        if (string.IsNullOrWhiteSpace(root)) return false;
        try
        {
            string fullCandidate = Path.TrimEndingDirectorySeparator(Path.GetFullPath(candidate));
            string fullRoot = Path.TrimEndingDirectorySeparator(Path.GetFullPath(root));
            return fullCandidate.Equals(fullRoot, StringComparison.OrdinalIgnoreCase) ||
                   fullCandidate.StartsWith(fullRoot + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase);
        }
        catch { return false; }
    }

    private static bool PathsEquivalent(string left, string right)
    {
        try
        {
            return Path.TrimEndingDirectorySeparator(Path.GetFullPath(left))
                .Equals(Path.TrimEndingDirectorySeparator(Path.GetFullPath(right)), StringComparison.OrdinalIgnoreCase);
        }
        catch { return false; }
    }

    private static async Task CopyDirectoryVerifiedAsync(
        string source,
        string destination,
        string expectedFingerprint,
        CancellationToken cancellationToken)
    {
        DirectoryFingerprintSnapshot snapshot = await DirectoryFingerprint.CaptureAsync(source, cancellationToken);
        if (!snapshot.Sha256.Equals(expectedFingerprint, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("目录内容在复制前发生变化。");
        if (File.Exists(destination) || Directory.Exists(destination))
            throw new IOException("目录隔离目标已存在。");

        Directory.CreateDirectory(destination);
        bool completed = false;
        try
        {
            foreach (DirectoryFingerprintEntry entry in snapshot.Entries.Where(entry => entry.IsDirectory))
            {
                string targetDirectory = ResolveSnapshotPath(destination, entry.RelativePath);
                Directory.CreateDirectory(targetDirectory);
            }
            foreach (DirectoryFingerprintEntry entry in snapshot.Entries.Where(entry => !entry.IsDirectory))
            {
                cancellationToken.ThrowIfCancellationRequested();
                string sourceFile = ResolveSnapshotPath(source, entry.RelativePath);
                string targetFile = ResolveSnapshotPath(destination, entry.RelativePath);
                await using SecureFileLease lease = SecureFileLease.Open(sourceFile);
                if (!IsWithin(lease.FinalPath, source))
                    throw new UnauthorizedAccessException("目录文件最终路径越界。");
                string sourceHash = await lease.ComputeSha256Async(cancellationToken);
                if (!sourceHash.Equals(entry.Sha256, StringComparison.OrdinalIgnoreCase))
                    throw new InvalidOperationException($"目录文件在复制前发生变化：{entry.RelativePath}");
                await lease.CopyToAsync(targetFile, sourceHash, cancellationToken);
            }

            string sourceAfter = await DirectoryFingerprint.ComputeAsync(source, cancellationToken);
            string destinationAfter = await DirectoryFingerprint.ComputeAsync(destination, cancellationToken);
            if (!sourceAfter.Equals(expectedFingerprint, StringComparison.OrdinalIgnoreCase) ||
                !destinationAfter.Equals(expectedFingerprint, StringComparison.OrdinalIgnoreCase))
                throw new IOException("目录复制后的双向指纹校验失败。");
            completed = true;
        }
        finally
        {
            if (!completed && Directory.Exists(destination) && !Validation.ContainsReparsePoint(destination))
            {
                try
                {
                    DeleteDirectoryContentsExact(destination);
                    Directory.Delete(destination, recursive: false);
                }
                catch { }
            }
        }
    }

    private static async Task DeleteDirectorySnapshotAsync(
        string source,
        string expectedFingerprint,
        CancellationToken cancellationToken)
    {
        DirectoryFingerprintSnapshot snapshot = await DirectoryFingerprint.CaptureAsync(source, cancellationToken);
        if (!snapshot.Sha256.Equals(expectedFingerprint, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("目录内容在删除原件前发生变化，已保留原目录与隔离副本。");

        foreach (DirectoryFingerprintEntry entry in snapshot.Entries.Where(entry => !entry.IsDirectory))
        {
            string sourceFile = ResolveSnapshotPath(source, entry.RelativePath);
            await using SecureFileLease lease = SecureFileLease.Open(sourceFile);
            if (!IsWithin(lease.FinalPath, source))
                throw new UnauthorizedAccessException("待删除目录文件最终路径越界。");
            string currentHash = await lease.ComputeSha256Async(cancellationToken);
            if (!currentHash.Equals(entry.Sha256, StringComparison.OrdinalIgnoreCase))
                throw new InvalidOperationException($"目录文件在删除前发生变化：{entry.RelativePath}");
            lease.DeleteOnClose();
        }

        foreach (DirectoryFingerprintEntry entry in snapshot.Entries.Where(entry => entry.IsDirectory)
                     .OrderByDescending(entry => entry.RelativePath.Count(c => c == '/'))
                     .ThenByDescending(entry => entry.RelativePath.Length))
        {
            string directory = ResolveSnapshotPath(source, entry.RelativePath);
            if ((File.GetAttributes(directory) & FileAttributes.ReparsePoint) != 0)
                throw new UnauthorizedAccessException("目录删除阶段发现重解析点，已停止。");
            Directory.Delete(directory, recursive: false);
        }
        Directory.Delete(source, recursive: false);
    }

    private static string ResolveSnapshotPath(string root, string relative)
    {
        string fullRoot = Path.TrimEndingDirectorySeparator(Path.GetFullPath(root));
        string result = Path.GetFullPath(Path.Combine(fullRoot, relative.Replace('/', Path.DirectorySeparatorChar)));
        if (!result.StartsWith(fullRoot + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase))
            throw new UnauthorizedAccessException("目录快照路径越界。");
        return result;
    }

    private static void EnsureTreeHasNoReparsePoints(string root)
    {
        if (Validation.ContainsReparsePoint(root)) throw new UnauthorizedAccessException("路径包含重解析点。");
        _ = EnumerateTreeWithoutReparsePoints(root);
    }

    private static void DeleteDirectoryContentsExact(string root)
    {
        string fullRoot = Path.TrimEndingDirectorySeparator(Path.GetFullPath(root));
        if (!Validation.IsSafeExactTarget(fullRoot) || Validation.ContainsReparsePoint(fullRoot))
            throw new UnauthorizedAccessException("拒绝删除不安全目录。");
        string[] entries = EnumerateTreeWithoutReparsePoints(fullRoot);
        foreach (string file in entries.Where(File.Exists)) File.Delete(file);
        foreach (string directory in entries.Where(Directory.Exists).OrderByDescending(value => value.Length))
            Directory.Delete(directory, recursive: false);
    }

    private static string[] EnumerateTreeWithoutReparsePoints(string root)
    {
        List<string> entries = [];
        Stack<string> pending = new();
        pending.Push(root);
        while (pending.Count > 0)
        {
            string directory = pending.Pop();
            if (Validation.ContainsReparsePoint(directory))
                throw new UnauthorizedAccessException($"目录树包含重解析点：{directory}");
            foreach (string entry in Directory.EnumerateFileSystemEntries(directory, "*", SearchOption.TopDirectoryOnly))
            {
                FileAttributes attributes = File.GetAttributes(entry);
                if ((attributes & FileAttributes.ReparsePoint) != 0)
                    throw new UnauthorizedAccessException($"目录树包含重解析点：{entry}");
                entries.Add(entry);
                if ((attributes & FileAttributes.Directory) != 0) pending.Push(entry);
            }
        }
        return [.. entries];
    }

    private static bool SameVolume(string left, string right) =>
        string.Equals(Path.GetPathRoot(Path.GetFullPath(left)), Path.GetPathRoot(Path.GetFullPath(right)), StringComparison.OrdinalIgnoreCase);

    private static string SafeName(string name)
    {
        string safe = string.Concat(name.Select(c => Path.GetInvalidFileNameChars().Contains(c) ? '_' : c));
        return string.IsNullOrWhiteSpace(safe) ? "item" : safe[..Math.Min(safe.Length, 120)];
    }

    private static string GetIncidentRoot(Guid incidentId)
    {
        string root = Path.TrimEndingDirectorySeparator(Path.GetFullPath(AppPaths.QuarantineRoot));
        string incident = Path.GetFullPath(Path.Combine(root, incidentId.ToString("D")));
        if (!incident.StartsWith(root + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase))
            throw new UnauthorizedAccessException("隔离事件路径越界。");
        return incident;
    }

    private Task PersistManifestAsync(CancellationToken cancellationToken) =>
        JsonFile.WriteAtomicAsync(_manifestPath, _manifest, cancellationToken);

    private static async Task<ProcessResult> RunEncodedPowerShellAsync(
        string fixedScript,
        IReadOnlyDictionary<string, string>? environment,
        CancellationToken cancellationToken)
    {
        string encoded = Convert.ToBase64String(Encoding.Unicode.GetBytes(
            "$ProgressPreference='SilentlyContinue';$ErrorActionPreference='Stop';$PSModuleAutoLoadingPreference='All';" + fixedScript));
        return await RunProcessAsync(
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "WindowsPowerShell", "v1.0", "powershell.exe"),
            ["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "RemoteSigned", "-EncodedCommand", encoded],
            cancellationToken,
            environment);
    }

    private static async Task<ProcessResult> RunProcessAsync(
        string fileName,
        IEnumerable<string> arguments,
        CancellationToken cancellationToken,
        IReadOnlyDictionary<string, string>? environment = null)
    {
        ProcessStartInfo startInfo = new()
        {
            FileName = fileName,
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true,
            WorkingDirectory = AppContext.BaseDirectory
        };
        startInfo.Environment.Clear();
        string windows = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        string system = Environment.GetFolderPath(Environment.SpecialFolder.System);
        string programFiles = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
        startInfo.Environment["SystemRoot"] = windows;
        startInfo.Environment["WINDIR"] = windows;
        startInfo.Environment["COMSPEC"] = Path.Combine(system, "cmd.exe");
        startInfo.Environment["PATH"] = system;
        startInfo.Environment["TEMP"] = AppPaths.BrokerTemporaryRoot;
        startInfo.Environment["TMP"] = AppPaths.BrokerTemporaryRoot;
        startInfo.Environment["ProgramFiles"] = programFiles;
        startInfo.Environment["PROGRAMDATA"] = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
        startInfo.Environment["PSModulePath"] = string.Join(Path.PathSeparator,
            Path.Combine(system, "WindowsPowerShell", "v1.0", "Modules"),
            Path.Combine(programFiles, "WindowsPowerShell", "Modules"));
        foreach (string argument in arguments) startInfo.ArgumentList.Add(argument);
        if (environment is not null)
        {
            foreach ((string key, string value) in environment) startInfo.Environment[key] = value;
        }
        using Process process = new() { StartInfo = startInfo };
        process.Start();
        Task<string> output = process.StandardOutput.ReadToEndAsync(cancellationToken);
        Task<string> error = process.StandardError.ReadToEndAsync(cancellationToken);
        using CancellationTokenSource timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(TimeSpan.FromSeconds(60));
        try
        {
            await process.WaitForExitAsync(timeout.Token);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            try { process.Kill(entireProcessTree: true); } catch { }
            throw new TimeoutException($"系统命令超时：{Path.GetFileName(fileName)}");
        }
        return new ProcessResult(process.ExitCode, await output, await error);
    }

    private sealed record ProcessResult(int ExitCode, string Output, string Error);
}
