using System.Diagnostics;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using Microsoft.Win32;
using SteamSentinel.Core.Models;
using SteamSentinel.Core.Remediation;
using SteamSentinel.Core.Rules;
using SteamSentinel.Core.Steam;
using SteamSentinel.Core.Utilities;

namespace SteamSentinel.Broker;

internal sealed partial class BrokerEngine
{
    internal const string DirectoryRollbackSafetyMessage =
        "为防原目录父路径在管理员回滚期间被替换，当前版本不自动恢复整目录；隔离副本保持不变。请保留隔离并由受信任的救援环境人工核对，勿为清理事件而恢复可疑内容。";
    private const int MaximumManifestBytes = 1024 * 1024;
    private readonly RuleSet _rules = RuleLoader.LoadEmbedded();
    private readonly SteamLayout _steamLayout = SteamLocator.Discover();
    private readonly IIncidentTrustStore _incidentTrustStore;
    private readonly IIncidentStateSecurity _incidentStateSecurity;
    private RemediationRunResult _result = null!;
    private QuarantineManifest _manifest = null!;
    private string _incidentRoot = string.Empty;
    private string _manifestPath = string.Empty;
    private bool _persistOwnManifest;
    private string _requestedBySid = string.Empty;
    private RemediationVerification _verification = null!;

    internal BrokerEngine() : this(new RegistryIncidentTrustStore(), new WindowsIncidentStateSecurity()) { }

    internal BrokerEngine(IIncidentTrustStore incidentTrustStore) :
        this(incidentTrustStore, new WindowsIncidentStateSecurity())
    { }

    internal BrokerEngine(IIncidentTrustStore incidentTrustStore, IIncidentStateSecurity incidentStateSecurity)
    {
        _incidentTrustStore = incidentTrustStore ?? throw new ArgumentNullException(nameof(incidentTrustStore));
        _incidentStateSecurity = incidentStateSecurity ?? throw new ArgumentNullException(nameof(incidentStateSecurity));
    }

    public async Task<RemediationRunResult> ExecuteAsync(RemediationPlan plan, CancellationToken cancellationToken = default)
    {
        ValidatePlan(plan);
        foreach (RemediationAction action in plan.Actions) ValidateAction(action);
        _requestedBySid = plan.RequestedBySid;
        _result = new RemediationRunResult { PlanId = plan.PlanId };
        _contentProofs.Clear();
        _verification = new(new WindowsRemediationStateProbe(async (script, token) =>
        {
            ProcessResult output = await RunEncodedPowerShellAsync(script, null, token);
            return output.ExitCode == 0 && output.Output.Length <= 16_384 ? output.Output.Trim() : null;
        }, _result.IncidentId));
        _persistOwnManifest = plan.Actions[0].Type is not (RemediationActionType.RollbackIncident or RemediationActionType.DeleteIncident);
        if (_persistOwnManifest)
        {
            _incidentRoot = Path.Combine(AppPaths.QuarantineRoot, _result.IncidentId.ToString("D"));
            _manifestPath = Path.Combine(_incidentRoot, "manifest.json");
            MachineStateSecurity.PrepareIncidentDirectory(_incidentRoot, plan.RequestedBySid);
            _manifest = new QuarantineManifest
            {
                IncidentId = _result.IncidentId,
                PlanId = plan.PlanId,
                TrustId = Guid.NewGuid(),
                RequestedBySid = plan.RequestedBySid
            };
            _result.ManifestPath = _manifestPath;
            await InitializeManifestAsync(cancellationToken);
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
                if (_persistOwnManifest)
                {
                    bool confirmedRecord = false;
                    foreach (QuarantineRecord record in _manifest.Records.Where(record => record.ActionId == action.ActionId))
                    {
                        if (record.MutationConfirmed) continue;
                        record.MutationConfirmed = true;
                        confirmedRecord = true;
                    }
                    if (confirmedRecord) await PersistManifestAsync(cancellationToken);
                }
                actionResult.Success = true;
            }
            catch (Exception ex)
            {
                actionResult.Success = false;
                actionResult.Message = RemediationVerification.Limit($"{ex.GetType().Name}: {ex.Message}", 700);
                if (action.Type is RemediationActionType.QuarantineFile or RemediationActionType.QuarantineDirectory &&
                    ex is IOException or System.ComponentModel.Win32Exception or UnauthorizedAccessException)
                {
                    actionResult.Occupancy = FileOccupancy.Inspect(action.Target, action.Type == RemediationActionType.QuarantineDirectory);
                    actionResult.Message += " " + FileOccupancy.Describe(actionResult.Occupancy);
                }
                _result.Errors.Add(RemediationVerification.Limit($"{action.DisplayName}: {actionResult.Message}", 1700));
            }
            actionResult.Message = RemediationVerification.Limit(actionResult.Message, 1700);
            await _verification.ObserveAsync(action, actionResult, 1, cancellationToken);
            _result.Actions.Add(actionResult);
            if (_persistOwnManifest) await PersistManifestAsync(cancellationToken);
        }

        await _verification.CompleteAsync(plan, _result, cancellationToken);
        _result.CompletedAtUtc = DateTimeOffset.UtcNow;
        _result.Success = _result.Errors.Count == 0 && _result.Actions.All(action => action.Success);
        if (_persistOwnManifest) await PersistManifestAsync(cancellationToken);
        return _result;
    }

    private void ValidatePlan(RemediationPlan plan)
    {
        if (plan.SchemaVersion != "1") throw new InvalidDataException("不支持的处置计划版本。");
        if (plan.PlanId == Guid.Empty) throw new InvalidDataException("处置计划 ID 不能为空。");
        DateTimeOffset now = DateTimeOffset.UtcNow;
        if (plan.CreatedAtUtc == default || plan.ExpiresAtUtc == default ||
            plan.CreatedAtUtc > now.AddMinutes(2) || plan.ExpiresAtUtc < now ||
            plan.ExpiresAtUtc <= plan.CreatedAtUtc ||
            plan.ExpiresAtUtc - plan.CreatedAtUtc > TimeSpan.FromHours(1))
        {
            throw new InvalidDataException("处置计划已过期或时间范围异常，请重新生成。");
        }
        if (plan.Actions is null || plan.Actions.Count is < 1 or > 64)
            throw new InvalidDataException("处置动作数量不在允许范围内。");
        if (string.IsNullOrWhiteSpace(plan.RequestedBy) || plan.RequestedBy.Length > 256 ||
            string.IsNullOrWhiteSpace(plan.RequestedBySid) || plan.RequestedBySid.Length > 184)
            throw new InvalidDataException("处置计划请求者字段异常。");
        SecurityIdentifier requester;
        try { requester = new SecurityIdentifier(plan.RequestedBySid); }
        catch (ArgumentException ex) { throw new InvalidDataException("处置计划请求者 SID 无效。", ex); }
        string currentSid = WindowsIdentity.GetCurrent().User?.Value ?? string.Empty;
        if (!requester.Value.Equals(currentSid, StringComparison.OrdinalIgnoreCase))
            throw new UnauthorizedAccessException("处置计划请求者与当前 Broker 身份不一致。");
        if (plan.Actions.Any(action => action is null || action.ActionId == Guid.Empty) ||
            plan.Actions.Select(action => action.ActionId).Distinct().Count() != plan.Actions.Count)
            throw new InvalidDataException("处置动作 ID 为空或重复。");
        bool hasIncidentLifecycleAction = plan.Actions.Any(action =>
            action.Type is RemediationActionType.RollbackIncident or RemediationActionType.DeleteIncident);
        if (hasIncidentLifecycleAction && plan.Actions.Count != 1)
            throw new InvalidDataException("回滚或永久删除必须使用单独的处置计划。");
    }

    private void ValidateAction(RemediationAction action)
    {
        if (string.IsNullOrWhiteSpace(action.Target) || action.Target.Length > 32_768 ||
            action.DisplayName is null || action.DisplayName.Length > 500)
            throw new InvalidDataException("动作字段过长。");

        switch (action.Type)
        {
            case RemediationActionType.StopProcess:
                if (action.ProcessId is null or <= 4 || action.ProcessStartedAtUtc is null || !Path.IsPathFullyQualified(action.Target) ||
                    !Validation.IsHexSha256(action.ExpectedSha256) ||
                    IsWithin(action.Target, Environment.GetFolderPath(Environment.SpecialFolder.Windows)) || IsWithin(action.Target, AppContext.BaseDirectory) ||
                    !IsKnownImageHash(action.ExpectedSha256) && !HasDirectStrongBinding(action))
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
                    (!_rules.KnownRunValueNames.Contains(action.RegistryValueName, StringComparer.OrdinalIgnoreCase) && !HasPersistenceBinding(action)))
                {
                    throw new UnauthorizedAccessException("Broker 只允许删除内置规则确认的 Run/RunOnce 值。");
                }
                break;
            case RemediationActionType.RemoveScheduledTask:
                string taskName = action.TaskName ?? action.Target;
                if (!Validation.TryNormalizeScheduledTaskName(taskName, out string normalizedTask) ||
                    !Validation.IsHexSha256(action.ExpectedSha256) ||
                    (!_rules.KnownTaskNames.Any(known =>
                        Validation.TryNormalizeScheduledTaskName(known, out string normalizedKnown) &&
                        normalizedTask.Equals(normalizedKnown, StringComparison.OrdinalIgnoreCase)) && !HasPersistenceBinding(action)))
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
            case RemediationActionType.StopHostProcess:
            case RemediationActionType.DisableService:
            case RemediationActionType.RemoveRelatedDefenderExclusion:
            case RemediationActionType.DisableRelatedFirewallRule:
                ValidateBoundAction(action);
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
        RemediationActionType.StopHostProcess => await StopHostAsync(action, cancellationToken),
        RemediationActionType.DisableService => await DisableServiceAsync(action, cancellationToken),
        RemediationActionType.RemoveRelatedDefenderExclusion => await ChangeRelatedExclusionAsync(action, false, cancellationToken),
        RemediationActionType.DisableRelatedFirewallRule => await ChangeRelatedFirewallAsync(action, false, cancellationToken),
        RemediationActionType.RollbackIncident => await RollbackIncidentAsync(action, cancellationToken),
        RemediationActionType.DeleteIncident => await DeleteIncidentAsync(action, cancellationToken),
        _ => throw new NotSupportedException()
    };

    private async Task<string> StopProcessAsync(RemediationAction action, CancellationToken cancellationToken)
    {
        using Process process = Process.GetProcessById(action.ProcessId!.Value);
        if (action.ProcessStartedAtUtc is { } expectedStart && process.StartTime.ToUniversalTime() != expectedStart.UtcDateTime)
            throw new InvalidOperationException("进程已重启或 PID 被复用，请重新扫描。");
        string? image = process.MainModule?.FileName;
        if (image is null || !PathsEquivalent(image, action.Target))
            throw new InvalidOperationException("PID 当前映像与扫描时路径不一致，已拒绝终止。");
        await using SecureFileLease lease = SecureFileLease.Open(image);
        string currentHash = await lease.ComputeSha256Async(cancellationToken);
        if (!currentHash.Equals(action.ExpectedSha256, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("进程映像哈希已变化，已拒绝终止。");
        await VerifyDirectProcessContentAsync(action, lease, cancellationToken);
        if (!PathsEquivalent(process.MainModule?.FileName ?? string.Empty, lease.FinalPath))
            throw new InvalidOperationException("进程映像在确认期间发生变化，已拒绝终止。");
        process.Kill(entireProcessTree: false);
        using CancellationTokenSource timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(TimeSpan.FromSeconds(15));
        await process.WaitForExitAsync(timeout.Token);
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
        MachineStateSecurity.PreparePayloadDirectory(itemRoot);
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
        MachineStateSecurity.ProtectPayloadFile(destination);
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
        MachineStateSecurity.PreparePayloadDirectory(itemRoot);
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

        // Always copy into a newly ACL-protected tree. A same-volume rename would preserve
        // attacker-controlled source ACLs and make the elevated rollback input writable.
        await CopyDirectoryVerifiedAsync(source, destination, currentFingerprint, cancellationToken);
        MachineStateSecurity.EnsureProtectedSubtree(destination);
        await DeleteDirectorySnapshotAsync(source, currentFingerprint, cancellationToken);
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
        await using SecureFileLease? bound = HasPersistenceBinding(action)
            ? await OpenBoundLeaseAsync(action, value.ToString(), cancellationToken) : null;
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
            RegistryValueKind = (int)kind,
            MutationConfirmed = false,
            RelatedFilePath = action.RelatedFilePath,
            RelatedFileSha256 = action.RelatedFileSha256,
            VerifiedContentRuleId = _contentProofs.GetValueOrDefault(action.ActionId)
        };
        _manifest.Records.Add(record);
        await PersistManifestAsync(cancellationToken);
        object? latest = key.GetValue(action.RegistryValueName!, null, RegistryValueOptions.DoNotExpandEnvironmentNames);
        if (!string.Equals(latest?.ToString(), action.ExpectedValueData, StringComparison.Ordinal) || key.GetValueKind(action.RegistryValueName!) != kind)
            throw new InvalidOperationException("启动项在处置确认期间发生变化，已拒绝删除，请重新扫描。");
        key.DeleteValue(action.RegistryValueName!, throwOnMissingValue: false);
        record.MutationConfirmed = true;
        await PersistManifestAsync(cancellationToken);
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
        await using SecureFileLease? bound = HasPersistenceBinding(action) ? await OpenBoundLeaseAsync(action, action.ConfigurationSnapshot, cancellationToken) : null;
        if (!File.Exists(taskFile)) throw new InvalidOperationException("无法读取计划任务快照，不能确认任务已不存在，请重新扫描。");
        if (File.Exists(taskFile))
        {
            backup = Path.Combine(_incidentRoot, "tasks", action.ActionId.ToString("N") + ".xml");
            MachineStateSecurity.PreparePayloadDirectory(Path.GetDirectoryName(backup)!);
            await using SecureFileLease taskLease = SecureFileLease.Open(taskFile);
            string taskHash = await taskLease.ComputeSha256Async(cancellationToken);
            RequireTaskSnapshotHash(taskHash, action.ExpectedSha256);
            await taskLease.CopyToAsync(backup, taskHash, cancellationToken);
            MachineStateSecurity.ProtectPayloadFile(backup);
            if (HasPersistenceBinding(action))
            {
                string xml = await File.ReadAllTextAsync(backup, cancellationToken);
                if (!CommandTargetsAreBound(action, TaskCommands(xml))) throw new InvalidOperationException("任务实际命令与绑定不符。");
            }
        }
        _manifest.Records.Add(new QuarantineRecord
        {
            ActionId = action.ActionId,
            Type = action.Type,
            OriginalTarget = taskName,
            QuarantinedPath = backup,
            TaskName = taskName,
            Sha256 = action.ExpectedSha256,
            MutationConfirmed = false,
            RelatedFilePath = action.RelatedFilePath,
            RelatedFileSha256 = action.RelatedFileSha256,
            VerifiedContentRuleId = _contentProofs.GetValueOrDefault(action.ActionId)
        });
        await PersistManifestAsync(cancellationToken);
        // Scheduler deletion cannot share our deny-delete lease. Recheck after all awaited backup work,
        // then release immediately before invoking the fixed, exact-name Scheduler operation.
        await using (SecureFileLease finalTask = SecureFileLease.Open(taskFile))
            RequireTaskSnapshotHash(await finalTask.ComputeSha256Async(cancellationToken), action.ExpectedSha256);
        ProcessResult result = await RunProcessAsync(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "schtasks.exe"),
            ["/Delete", "/TN", taskName, "/F"], cancellationToken);
        if (result.ExitCode != 0) throw new InvalidOperationException(result.Error);
        _manifest.Records.Last(record => record.ActionId == action.ActionId).MutationConfirmed = true;
        await PersistManifestAsync(cancellationToken);
        return "计划任务删除命令已成功，任务注册状态由只读复验确认。";
    }

    private async Task<string> ChangeDefenderExclusionAsync(RemediationAction action, bool add, CancellationToken cancellationToken)
    {
        string path = action.Target;
        string operation = add ? "Add-MpPreference" : "Remove-MpPreference";
        string script = "$p=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($env:STEAMSENTINEL_PATH_B64));" +
                        operation + " -ExclusionPath $p -ErrorAction Stop";
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
        ProcessResult result = await RunEncodedPowerShellAsync(script,
            new Dictionary<string, string> { ["STEAMSENTINEL_PATH_B64"] = Convert.ToBase64String(Encoding.UTF8.GetBytes(path)) },
            cancellationToken);
        if (result.ExitCode != 0) throw new InvalidOperationException(result.Error);
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
        _manifest.Records.Add(new QuarantineRecord
        {
            ActionId = action.ActionId,
            Type = action.Type,
            OriginalTarget = action.Target,
            FirewallRuleName = name,
            Sha256 = action.ExpectedSha256
        });
        await PersistManifestAsync(cancellationToken);
        string netsh = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "netsh.exe");
        ProcessResult command = await RunProcessAsync(netsh,
            ["advfirewall", "firewall", "add", "rule", $"name={name}", "dir=out", "action=block", "enable=yes", "profile=any", $"program={action.Target}"],
            cancellationToken);
        if (command.ExitCode != 0) throw new InvalidOperationException(command.Error);
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
        const string script = "$problems=[Collections.Generic.List[string]]::new();$mayChange=$false;" +
            "try{$m=Get-MpComputerStatus -ErrorAction Stop;$av=@(Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct -ErrorAction Stop|" +
            "Where-Object {$_.displayName -notmatch '^(Microsoft|Windows) Defender'});" +
            "$mayChange=($m.AMRunningMode -eq 'Normal' -and $av.Count -eq 0);" +
            "if(-not $mayChange){$problems.Add('Defender mode/third-party antivirus requires manual review, no Defender changes requested')}}catch{$problems.Add('Cannot confirm antivirus ownership: '+$_.Exception.Message)};" +
            "if($mayChange){try{Set-MpPreference -DisableRealtimeMonitoring $false -ErrorAction Stop}catch{$problems.Add('Realtime: '+$_.Exception.Message)};" +
            "try{Set-MpPreference -DisableBehaviorMonitoring $false -ErrorAction Stop}catch{$problems.Add('Behavior: '+$_.Exception.Message)}};" +
            "try{Set-NetFirewallProfile -All -Enabled True -ErrorAction Stop}catch{$problems.Add('Firewall: '+$_.Exception.Message)};" +
            "if($problems.Count -gt 0){throw ($problems -join ', ')}";
        ProcessResult result = await RunEncodedPowerShellAsync(script, null, cancellationToken);
        if (result.ExitCode != 0) throw new InvalidOperationException("安全恢复未全部完成或无法确认主防护，未强制改变第三方/被动模式。" + result.Error);
        return "已请求开启 Defender 实时/行为监控及全部防火墙配置。";
    }

    private async Task<string> RollbackIncidentAsync(RemediationAction action, CancellationToken cancellationToken)
    {
        Guid incidentId = Guid.Parse(action.IncidentId ?? action.Target);
        string incidentRoot = GetIncidentRoot(incidentId);
        string manifestPath = Path.Combine(incidentRoot, "manifest.json");
        QuarantineManifest manifest = await LoadTrustedManifestAsync(incidentId, incidentRoot, manifestPath, cancellationToken);
        foreach (QuarantineRecord record in manifest.Records)
            ValidateQuarantineRecord(record, incidentRoot, incidentId);
        foreach (QuarantineRecord record in manifest.Records)
            await VerifyRecordedContentAsync(record, manifest, cancellationToken);

        foreach (QuarantineRecord record in manifest.Records.AsEnumerable().Reverse())
        {
            if (record.RolledBack) continue;
            if (!record.MutationConfirmed) throw new InvalidOperationException("上次处置操作的完成状态不确定，请人工核对；未自动恢复或覆盖当前状态。");
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
                case RemediationActionType.DisableService:
                    await RestoreServiceAsync(record, cancellationToken);
                    break;
                case RemediationActionType.RemoveRelatedDefenderExclusion:
                    await ChangeRelatedExclusionAsync(FromRecord(record), true, cancellationToken);
                    break;
                case RemediationActionType.DisableRelatedFirewallRule:
                    await ChangeRelatedFirewallAsync(FromRecord(record), true, cancellationToken);
                    break;
            }
            record.RolledBack = true;
            await PersistTrustedManifestAsync(manifestPath, manifest, cancellationToken);
        }
        return $"隔离事件 {incidentId:D} 已回滚。";
    }

    private async Task<string> DeleteIncidentAsync(RemediationAction action, CancellationToken cancellationToken)
    {
        Guid incidentId = Guid.Parse(action.IncidentId ?? action.Target);
        string incidentRoot = GetIncidentRoot(incidentId);
        if (!Directory.Exists(incidentRoot)) return "隔离事件已不存在。";
        string manifestPath = Path.Combine(incidentRoot, "manifest.json");
        QuarantineManifest manifestData = await LoadTrustedManifestAsync(
            incidentId, incidentRoot, manifestPath, cancellationToken);
        EnsureIncidentDeletionAllowed(manifestData);
        DeleteDirectoryContentsExact(incidentRoot);
        Directory.Delete(incidentRoot, recursive: false);
        _incidentTrustStore.Delete(incidentId);
        return $"隔离事件 {incidentId:D} 已永久删除。";
    }

    internal static void EnsureIncidentDeletionAllowed(QuarantineManifest manifest)
    {
        if (manifest.Records.Any(record => !record.RolledBack))
        {
            throw new InvalidOperationException(
                "该事件仍有活动隔离记录。当前 Broker 不接受可由普通进程伪造的“干净复扫”作为永久删除授权；" +
                "请保留隔离，不要为了删除事件而回滚可疑样本。仅所有记录原本就已安全回滚的空事件可以清理。");
        }
    }

    private async Task RestoreFileAsync(QuarantineRecord record, CancellationToken cancellationToken)
    {
        if (record.QuarantinedPath is null || !File.Exists(record.QuarantinedPath))
            throw new FileNotFoundException("隔离文件副本缺失，不能把该记录标记为已回滚；请保留事件记录并人工核对。", record.QuarantinedPath);
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

    private static Task RestoreDirectoryAsync(QuarantineRecord record, CancellationToken cancellationToken)
    {
        if (record.QuarantinedPath is null || !Directory.Exists(record.QuarantinedPath))
            throw new DirectoryNotFoundException("隔离目录副本缺失，不能把该记录标记为已回滚；请保留事件记录并人工核对。");
        cancellationToken.ThrowIfCancellationRequested();
        throw new InvalidOperationException(DirectoryRollbackSafetyMessage);
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
        if (record.QuarantinedPath is null || !File.Exists(record.QuarantinedPath) || record.TaskName is null)
            throw new FileNotFoundException("计划任务隔离快照缺失，不能自动回滚；请保留事件记录并人工核对。", record.QuarantinedPath);
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
                    (!_rules.KnownRunValueNames.Contains(record.RegistryValueName, StringComparer.OrdinalIgnoreCase) && !HasKnownBinding(FromRecord(record)) && !HasHeuristicRecord(record)))
                    throw new InvalidDataException("隔离清单中的注册表记录不在允许范围。");
                break;
            case RemediationActionType.RemoveScheduledTask:
                if (!Validation.IsHexSha256(record.Sha256) ||
                    !Validation.TryNormalizeScheduledTaskName(record.TaskName, out string normalizedTask) ||
                    (!_rules.KnownTaskNames.Any(known =>
                        Validation.TryNormalizeScheduledTaskName(known, out string normalizedKnown) &&
                        normalizedTask.Equals(normalizedKnown, StringComparison.OrdinalIgnoreCase)) && !HasKnownBinding(FromRecord(record)) && !HasHeuristicRecord(record)))
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
            case RemediationActionType.DisableService:
            case RemediationActionType.RemoveRelatedDefenderExclusion:
            case RemediationActionType.DisableRelatedFirewallRule:
                ValidateBoundAction(FromRecord(record));
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

        MachineStateSecurity.PreparePayloadDirectory(destination);
        bool completed = false;
        try
        {
            foreach (DirectoryFingerprintEntry entry in snapshot.Entries.Where(entry => entry.IsDirectory))
            {
                string targetDirectory = ResolveSnapshotPath(destination, entry.RelativePath);
                MachineStateSecurity.PreparePayloadDirectory(targetDirectory);
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
                MachineStateSecurity.ProtectPayloadFile(targetFile);
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
            SecureDirectoryDeletion.DeleteEmpty(directory);
        }
        SecureDirectoryDeletion.DeleteEmpty(source);
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

    private async Task InitializeManifestAsync(CancellationToken cancellationToken)
    {
        byte[] content = SerializeManifest(_manifest);
        string sha256 = Convert.ToHexString(SHA256.HashData(content));
        _incidentTrustStore.RegisterPending(_manifest, sha256);
        await WriteManifestAtomicAsync(_manifestPath, content, _manifest.RequestedBySid, cancellationToken);
        _incidentTrustStore.CommitManifestUpdate(_manifest.IncidentId, sha256);
    }

    private Task PersistManifestAsync(CancellationToken cancellationToken) =>
        PersistTrustedManifestAsync(_manifestPath, _manifest, cancellationToken);

    private async Task PersistTrustedManifestAsync(
        string manifestPath,
        QuarantineManifest manifest,
        CancellationToken cancellationToken)
    {
        byte[] content = SerializeManifest(manifest);
        string sha256 = Convert.ToHexString(SHA256.HashData(content));
        _incidentTrustStore.BeginManifestUpdate(manifest.IncidentId, sha256);
        await WriteManifestAtomicAsync(manifestPath, content, manifest.RequestedBySid, cancellationToken);
        _incidentTrustStore.CommitManifestUpdate(manifest.IncidentId, sha256);
    }

    internal async Task<QuarantineManifest> LoadTrustedManifestAsync(
        Guid incidentId,
        string incidentRoot,
        string manifestPath,
        CancellationToken cancellationToken,
        string? requestedBySidForTest = null)
    {
        IncidentTrustRecord trust = _incidentTrustStore.GetRequired(incidentId);
        _incidentStateSecurity.EnsureProtectedPath(incidentRoot);
        _incidentStateSecurity.EnsureProtectedPath(manifestPath);
        QuarantineManifest manifest;
        string actualSha256;
        await using (SecureFileLease lease = SecureFileLease.Open(manifestPath))
        {
            if (lease.Length is <= 0 or > MaximumManifestBytes)
                throw new InvalidDataException("隔离清单大小异常。");
            actualSha256 = await lease.ComputeSha256Async(cancellationToken);
            if (!trust.AcceptsManifestHash(actualSha256))
                throw new UnauthorizedAccessException("隔离清单与 Broker 受保护可信索引不一致，已拒绝管理员生命周期操作。");
            manifest = await lease.ReadJsonAsync<QuarantineManifest>(cancellationToken);
        }

        if (manifest.SchemaVersion != "1" || !trust.MatchesIdentity(manifest) || manifest.IncidentId != incidentId)
            throw new InvalidDataException("隔离清单身份与受保护可信索引不一致。");
        string expectedRequester = requestedBySidForTest ?? _requestedBySid;
        if (!manifest.RequestedBySid.Equals(expectedRequester, StringComparison.OrdinalIgnoreCase))
            throw new UnauthorizedAccessException("隔离事件不属于当前 UAC 请求者。");
        if (manifest.Records is null || manifest.Records.Count > 64 ||
            manifest.Records.Any(record => record is null || record.ActionId == Guid.Empty) ||
            manifest.Records.Select(record => record.ActionId).Distinct().Count() != manifest.Records.Count)
        {
            throw new InvalidDataException("隔离清单记录数量或动作 ID 异常。");
        }

        // The registry keeps both committed and pending hashes. If a broker crashed after the
        // atomic file replacement, accepting only that pre-authorized pending hash recovers safely.
        if (!actualSha256.Equals(trust.ManifestSha256, StringComparison.OrdinalIgnoreCase))
            _incidentTrustStore.CommitManifestUpdate(incidentId, actualSha256);
        _incidentStateSecurity.EnsureProtectedSubtree(incidentRoot);
        return manifest;
    }

    private static byte[] SerializeManifest(QuarantineManifest manifest)
    {
        byte[] content = JsonSerializer.SerializeToUtf8Bytes(manifest, JsonFile.Options);
        if (content.Length is <= 0 or > MaximumManifestBytes)
            throw new InvalidDataException("隔离清单大小异常。");
        return content;
    }

    private static async Task WriteManifestAtomicAsync(
        string path,
        byte[] content,
        string requestedBySid,
        CancellationToken cancellationToken)
    {
        string fullPath = Path.GetFullPath(path);
        string directory = Path.GetDirectoryName(fullPath)
            ?? throw new InvalidOperationException("隔离清单没有父目录。");
        MachineStateSecurity.EnsureProtectedPath(directory);
        string temporary = Path.Combine(directory, $".{Path.GetFileName(path)}.{Guid.NewGuid():N}.tmp");
        try
        {
            await using (FileStream stream = new(
                             temporary,
                             FileMode.CreateNew,
                             FileAccess.Write,
                             FileShare.None,
                             bufferSize: 64 * 1024,
                             FileOptions.Asynchronous | FileOptions.WriteThrough))
            {
                await stream.WriteAsync(content, cancellationToken);
                await stream.FlushAsync(cancellationToken);
                stream.Flush(flushToDisk: true);
            }
            File.Move(temporary, fullPath, overwrite: true);
            MachineStateSecurity.ProtectManifestFile(fullPath, requestedBySid);
        }
        finally
        {
            if (File.Exists(temporary) && !Validation.ContainsReparsePoint(temporary))
            {
                try { File.Delete(temporary); } catch { }
            }
        }
    }

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
        catch (OperationCanceledException)
        {
            try { process.Kill(entireProcessTree: true); } catch { }
            cancellationToken.ThrowIfCancellationRequested();
            throw new TimeoutException($"系统命令超时：{Path.GetFileName(fileName)}");
        }
        return new ProcessResult(process.ExitCode, await output, await error);
    }

    private sealed record ProcessResult(int ExitCode, string Output, string Error);
}
