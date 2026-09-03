using SteamSentinel.Core.Models;
using SteamSentinel.Core.Utilities;

namespace SteamSentinel.Core.Remediation;

public sealed class RemediationPlanBuilder(RuleSet rules)
{
    public async Task<RemediationPlan> BuildAsync(
        IEnumerable<Finding> selectedFindings,
        bool addKnownDomainBlock,
        CancellationToken cancellationToken = default)
    {
        RemediationPlan plan = new();
        HashSet<string> deduplication = new(StringComparer.OrdinalIgnoreCase);
        bool shouldBlockDomains = addKnownDomainBlock;

        foreach (Finding finding in selectedFindings.Where(item => item.CanRemediate))
        {
            cancellationToken.ThrowIfCancellationRequested();
            shouldBlockDomains |= finding.IsKnownMalware ||
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
                        ExpectedSha256 = finding.Sha256,
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
                        IsKnownMalware = finding.IsKnownMalware,
                        ConfidenceScore = finding.Score
                    },
                    SuggestedActionKind.RemoveScheduledTask => new RemediationAction
                    {
                        Type = RemediationActionType.RemoveScheduledTask,
                        DisplayName = "删除已知恶意计划任务",
                        Target = finding.Target,
                        TaskName = finding.Target,
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
                string key = $"{action.Type}|{action.Target}|{action.ProcessId}|{action.RegistryKey}|{action.RegistryValueName}";
                if (deduplication.Add(key)) plan.Actions.Add(action);
            }

            if (finding.IsKnownMalware && finding.Target.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) && File.Exists(finding.Target))
            {
                string hash = finding.Sha256 ?? await Hashing.Sha256FileAsync(finding.Target, cancellationToken);
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
                if (deduplication.Add(key)) plan.Actions.Add(firewall);
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

        OrderActionsForSafeExecution(plan.Actions);

        return plan;
    }

    private static void OrderActionsForSafeExecution(List<RemediationAction> actions)
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
        RemediationActionType.StopProcess => 0,
        RemediationActionType.RemoveRegistryValue or
        RemediationActionType.RemoveScheduledTask or
        RemediationActionType.RemoveDefenderExclusion => 1,
        RemediationActionType.AddProgramFirewallBlock or
        RemediationActionType.BlockKnownDomains => 2,
        RemediationActionType.QuarantineFile or
        RemediationActionType.QuarantineDirectory => 3,
        _ => 4
    };

    private static async Task<RemediationAction> CreateFileActionAsync(Finding finding, CancellationToken cancellationToken)
    {
        string path = Path.GetFullPath(finding.Target);
        string hash = await Hashing.Sha256FileAsync(path, cancellationToken);
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

    private static async Task<RemediationAction> CreateDirectoryActionAsync(
        Finding finding,
        CancellationToken cancellationToken)
    {
        string path = Path.TrimEndingDirectorySeparator(Path.GetFullPath(finding.Target));
        string fingerprint = await DirectoryFingerprint.ComputeAsync(path, cancellationToken);
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
}
