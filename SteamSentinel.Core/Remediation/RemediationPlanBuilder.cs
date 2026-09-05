using SteamSentinel.Core.Models;
using SteamSentinel.Core.Scanning;
using SteamSentinel.Core.Utilities;

namespace SteamSentinel.Core.Remediation;

public sealed class RemediationPlanBuilder(RuleSet rules)
{
    public async Task<RemediationPlan> BuildAsync(
        IEnumerable<Finding> selectedFindings,
        bool addKnownDomainBlock,
        CancellationToken cancellationToken = default,
        IEnumerable<Finding>? allFindings = null)
    {
        RemediationPlan plan = new();
        Dictionary<string, RemediationAction> deduplication = new(StringComparer.OrdinalIgnoreCase);
        bool shouldBlockDomains = addKnownDomainBlock;
        Finding[] selected = selectedFindings.Take(257).ToArray();
        if (selected.Length > 256) throw new InvalidDataException("处置计划超过安全上限，请按关联组分批处理。");
        IEnumerable<Finding> expanded = allFindings is null ? selected : RelatedArtifactRelations.SelectForPlan(selected, allFindings, rules);

        foreach (Finding finding in expanded.Where(item => item.CanRemediate))
        {
            cancellationToken.ThrowIfCancellationRequested();
            // A selected startup link is quarantined by its own scanned bytes. Its payload is a separate action/identity.
            if (finding.RelatedFilePath is { } related && !(finding.RuleId == "PERSISTENCE-STARTUP-LINK" &&
                finding.SuggestedActions.Count == 1 && finding.SuggestedActions[0] == SuggestedActionKind.QuarantineFile))
                await VerifyFileIdentityAsync(related, finding.RelatedFileSha256, cancellationToken);
            if (finding.SuggestedActions.Any(a => a is SuggestedActionKind.StopProcess or SuggestedActionKind.StopHostProcess))
            {
                if (finding.ProcessId is null or <= 4 || finding.ProcessStartedAtUtc is null)
                    throw new InvalidDataException("运行进程缺少 PID/启动时间绑定，请重新扫描。");
                await VerifyFileIdentityAsync(finding.Target, finding.Sha256, cancellationToken);
            }
            shouldBlockDomains |= (finding.IsKnownMalware && finding.Category is FindingCategory.Process or FindingCategory.Persistence or FindingCategory.Steam) ||
                                  finding.SuggestedActions.Contains(SuggestedActionKind.BlockKnownDomains);

            foreach (SuggestedActionKind suggested in finding.SuggestedActions)
            {
                RemediationAction? action = suggested switch
                {
                    SuggestedActionKind.StopProcess when finding.ProcessId is not null => new RemediationAction
                    {
                        Type = RemediationActionType.StopProcess,
                        DisplayName = $"停止进程 PID {finding.ProcessId}",
                        Target = finding.Target,
                        ProcessId = finding.ProcessId,
                        ProcessStartedAtUtc = finding.ProcessStartedAtUtc,
                        ExpectedSha256 = finding.Sha256,
                        RelatedFilePath = finding.RelatedFilePath,
                        RelatedFileSha256 = finding.RelatedFileSha256,
                        IsKnownMalware = finding.IsKnownMalware,
                        ConfidenceScore = finding.Score
                    },
                    SuggestedActionKind.RemoveRegistryValue when finding.RegistryKey is not null && finding.RegistryValueName is not null => new RemediationAction
                    {
                        Type = RemediationActionType.RemoveRegistryValue,
                        DisplayName = $"删除启动项 {finding.RegistryValueName}",
                        Target = finding.Target,
                        RegistryHive = finding.RegistryHive,
                        RegistryView = finding.RegistryView,
                        RegistryKey = finding.RegistryKey,
                        RegistryValueName = finding.RegistryValueName,
                        ExpectedValueData = finding.Target,
                        RelatedFilePath = finding.RelatedFilePath,
                        RelatedFileSha256 = finding.RelatedFileSha256,
                        IsKnownMalware = finding.IsKnownMalware,
                        ConfidenceScore = finding.Score
                    },
                    SuggestedActionKind.RemoveScheduledTask => new RemediationAction
                    {
                        Type = RemediationActionType.RemoveScheduledTask,
                        DisplayName = "删除已验证的关联计划任务",
                        Target = finding.Target,
                        TaskName = finding.Target,
                        RelatedFilePath = finding.RelatedFilePath,
                        RelatedFileSha256 = finding.RelatedFileSha256,
                        ConfigurationSnapshot = finding.ConfigurationSnapshot,
                        ExpectedSha256 = finding.Sha256,
                        IsKnownMalware = finding.IsKnownMalware,
                        ConfidenceScore = finding.Score
                    },
                    SuggestedActionKind.RemoveDefenderExclusion => new RemediationAction
                    {
                        Type = RemediationActionType.RemoveDefenderExclusion,
                        DisplayName = "移除已知恶意 Defender 排除项",
                        Target = finding.Target,
                        IsKnownMalware = finding.IsKnownMalware,
                        ConfidenceScore = finding.Score
                    },
                    SuggestedActionKind.StopHostProcess => BoundAction(finding, RemediationActionType.StopHostProcess, "关闭已加载恶意组件的宿主程序"),
                    SuggestedActionKind.DisableService => BoundAction(finding, RemediationActionType.DisableService, "禁用关联恶意文件的服务"),
                    SuggestedActionKind.RemoveRelatedDefenderExclusion => BoundAction(finding, RemediationActionType.RemoveRelatedDefenderExclusion, "移除关联恶意插件的安全排除项"),
                    SuggestedActionKind.DisableRelatedFirewallRule => BoundAction(finding, RemediationActionType.DisableRelatedFirewallRule, "禁用关联投递链的防火墙放行规则"),
                    SuggestedActionKind.QuarantineFile when File.Exists(finding.Target) => await CreateFileActionAsync(finding, cancellationToken),
                    SuggestedActionKind.QuarantineDirectory when Directory.Exists(finding.Target) =>
                        await CreateDirectoryActionAsync(finding, cancellationToken),
                    SuggestedActionKind.RestoreSecurityControls => new RemediationAction
                    {
                        Type = RemediationActionType.RestoreSecurityControls,
                        DisplayName = "恢复 Defender 与 Windows 防火墙",
                        Target = "Windows Security",
                        IsKnownMalware = finding.IsKnownMalware,
                        ConfidenceScore = finding.Score
                    },
                    _ => null
                };

                if (action is null) continue;
                string key = $"{action.Type}|{action.Target}|{action.ProcessId}|{action.RegistryHive}|{action.RegistryView}|{action.RegistryKey}|{action.RegistryValueName}";
                if (deduplication.TryGetValue(key, out RemediationAction? previous))
                {
                    if (!string.Equals(previous.ExpectedSha256, action.ExpectedSha256, StringComparison.OrdinalIgnoreCase) ||
                        previous.ProcessStartedAtUtc != action.ProcessStartedAtUtc || previous.ExpectedValueData != action.ExpectedValueData ||
                        previous.ConfigurationSnapshot != action.ConfigurationSnapshot)
                        throw new InvalidDataException("同一处置目标存在冲突快照，请重新扫描。");
                }
                else { deduplication.Add(key, action); plan.Actions.Add(action); }
                if (plan.Actions.Count > 64) throw new InvalidDataException("完整处置计划超过 64 个动作，请按关联组分批处理。");
            }

            if (finding.IsKnownMalware && !finding.SuggestedActions.Contains(SuggestedActionKind.StopHostProcess) &&
                finding.Target.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) && File.Exists(finding.Target))
            {
                string hash = await VerifyTargetIdentityAsync(finding, cancellationToken);
                RemediationAction firewall = new()
                {
                    Type = RemediationActionType.AddProgramFirewallBlock,
                    DisplayName = "阻断恶意程序出站连接",
                    Target = Path.GetFullPath(finding.Target),
                    ExpectedSha256 = hash,
                    IsKnownMalware = true,
                    ConfidenceScore = finding.Score
                };
                string key = $"{firewall.Type}|{firewall.Target}";
                if (deduplication.TryAdd(key, firewall)) plan.Actions.Add(firewall);
            }
        }

        if (shouldBlockDomains && rules.KnownDomains.Count > 0)
        {
            plan.Actions.Add(new RemediationAction
            {
                Type = RemediationActionType.BlockKnownDomains,
                DisplayName = "在 hosts 中阻断已知 C2 域名",
                Target = "hosts",
                Domains = [.. rules.KnownDomains],
                IsKnownMalware = true,
                ConfidenceScore = 100
            });
        }

        if (plan.Actions.Count > 64) throw new InvalidDataException("完整处置计划超过 64 个动作，请按关联组分批处理。");
        OrderActionsForSafeExecution(plan.Actions);

        return plan;
    }

    internal static void OrderActionsForSafeExecution(List<RemediationAction> actions)
    {
        RemediationAction[] ordered = actions
            .Select((action, index) => (Action: action, Index: index))
            .OrderBy(item => ExecutionPhase(item.Action.Type))
            .ThenBy(item => item.Index)
            .Select(item => item.Action)
            .ToArray();
        actions.Clear();
        actions.AddRange(ordered);
    }

    private static int ExecutionPhase(RemediationActionType type) => type switch
    {
        RemediationActionType.StopProcess or RemediationActionType.StopHostProcess => 0,
        RemediationActionType.RemoveRegistryValue or
        RemediationActionType.RemoveScheduledTask or
        RemediationActionType.RemoveDefenderExclusion or RemediationActionType.DisableService or
        RemediationActionType.RemoveRelatedDefenderExclusion or RemediationActionType.DisableRelatedFirewallRule => 1,
        RemediationActionType.AddProgramFirewallBlock or
        RemediationActionType.BlockKnownDomains => 2,
        RemediationActionType.QuarantineFile or
        RemediationActionType.QuarantineDirectory => 3,
        _ => 4
    };

    private static async Task<RemediationAction> CreateFileActionAsync(Finding finding, CancellationToken cancellationToken)
    {
        string path = Path.GetFullPath(finding.Target);
        string hash = await VerifyTargetIdentityAsync(finding, cancellationToken);
        return new RemediationAction
        {
            Type = RemediationActionType.QuarantineFile,
            DisplayName = "隔离文件",
            Target = path,
            ExpectedSha256 = hash,
            IsKnownMalware = finding.IsKnownMalware,
            ConfidenceScore = finding.Score
        };
    }

    private static RemediationAction BoundAction(Finding finding, RemediationActionType type, string label) => new()
    {
        Type = type,
        DisplayName = label,
        Target = finding.Target,
        ExpectedSha256 = finding.Sha256,
        ProcessId = finding.ProcessId,
        ProcessStartedAtUtc = finding.ProcessStartedAtUtc,
        RelatedFilePath = finding.RelatedFilePath,
        RelatedFileSha256 = finding.RelatedFileSha256,
        ConfigurationKind = finding.ConfigurationKind,
        ConfigurationSnapshot = finding.ConfigurationSnapshot,
        IsKnownMalware = finding.IsKnownMalware,
        ConfidenceScore = finding.Score
    };

    private static async Task<RemediationAction> CreateDirectoryActionAsync(
        Finding finding,
        CancellationToken cancellationToken)
    {
        string path = Path.TrimEndingDirectorySeparator(Path.GetFullPath(finding.Target));
        string fingerprint = await RelatedDirectoryIdentity.ComputeAsync(path, cancellationToken);
        string? expected = finding.TargetSha256 ?? finding.Sha256;
        if (expected is not null && (!Validation.IsHexSha256(expected) || !expected.Equals(fingerprint, StringComparison.OrdinalIgnoreCase)))
            throw new InvalidDataException("目录在扫描后发生变化，请重新扫描：" + path);
        return new RemediationAction
        {
            Type = RemediationActionType.QuarantineDirectory,
            DisplayName = "隔离目录",
            Target = path,
            ExpectedSha256 = fingerprint,
            IsKnownMalware = finding.IsKnownMalware,
            ConfidenceScore = finding.Score
        };
    }

    private static async Task<string> VerifyTargetIdentityAsync(Finding finding, CancellationToken cancellationToken)
    {
        string? expected = finding.TargetSha256 ?? (finding.ContentPath is null || RelatedArtifactRelations.SamePath(finding.Target, finding.ContentPath) ? finding.Sha256 : null);
        return await VerifyFileIdentityAsync(finding.Target, expected, cancellationToken);
    }

    private static async Task<string> VerifyFileIdentityAsync(string path, string? expected, CancellationToken cancellationToken)
    {
        if (!Validation.IsHexSha256(expected) || RelatedArtifactReader.IsProtected(path))
            throw new InvalidDataException($"目标缺少扫描身份或属于受保护范围，请重新扫描：{path}");
        await using FileStream stream = RelatedArtifactReader.Open(path);
        if (stream.Length > 256L * 1024 * 1024) throw new InvalidDataException("处置身份复核超过单文件 256 MiB 上限，请单独复查：" + path);
        string hash = await Hashing.Sha256StreamAsync(stream, cancellationToken);
        if (!expected!.Equals(hash, StringComparison.OrdinalIgnoreCase))
            throw new InvalidDataException($"目标在扫描后发生变化，请重新扫描：{path}");
        return hash;
    }
}
