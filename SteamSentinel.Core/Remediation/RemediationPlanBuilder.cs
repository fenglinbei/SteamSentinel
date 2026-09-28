using SteamSentinel.Core.Reporting;
using SteamSentinel.Core.Models;
using SteamSentinel.Core.Scanning;
using SteamSentinel.Core.Steam;
using SteamSentinel.Core.Utilities;

namespace SteamSentinel.Core.Remediation;

public sealed class RemediationPlanBuilder(RuleSet rules)
{
    private readonly Lazy<SteamLayout> _steamLayout = new(SteamLocator.Discover);

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
        if (selected.Length > 256) throw MessageExceptions.Create(MessageText.Create("Backend.Core.RemediationPlanBuilder.BuildAsync.01"), sourceText => new InvalidDataException(sourceText));
        // Old reports keep their original flags. Retired token-only evidence must be
        // rejected before it can seed related actions or silently disappear from a plan.
        foreach (Finding finding in selected) RemediationEvidencePolicy.RequireActionableEvidence(finding);
        IEnumerable<Finding> expanded = allFindings is null ? selected : RelatedArtifactRelations.SelectForPlan(selected, allFindings, rules);

        foreach (Finding finding in expanded)
        {
            cancellationToken.ThrowIfCancellationRequested();
            RemediationEvidencePolicy.RequireActionableEvidence(finding);
            if (!finding.CanRemediate) continue;
            // A selected startup link is quarantined by its own scanned bytes. Its payload is a separate action/identity.
            if (finding.RelatedFilePath is { } related && !(finding.RuleId == "PERSISTENCE-STARTUP-LINK" &&
                finding.SuggestedActions.Count == 1 && finding.SuggestedActions[0] == SuggestedActionKind.QuarantineFile))
                await VerifyFileIdentityAsync(related, finding.RelatedFileSha256, cancellationToken);
            if (finding.SuggestedActions.Any(a => a is SuggestedActionKind.StopProcess or SuggestedActionKind.StopHostProcess))
            {
                if (finding.ProcessId is null or <= 4 || finding.ProcessStartedAtUtc is null)
                    throw MessageExceptions.Create(MessageText.Create("Backend.Core.RemediationPlanBuilder.BuildAsync.02"), sourceText => new InvalidDataException(sourceText));
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
                        DisplayNameText = MessageText.Create("Backend.Core.RemediationPlanBuilder.BuildAsync.StopProcess.01", (finding.ProcessId)),
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
                        DisplayNameText = MessageText.Create("Backend.Core.RemediationPlanBuilder.BuildAsync.RemoveRegistryValue.01", (finding.RegistryValueName)),
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
                        DisplayNameText = MessageText.Create("Backend.Core.RemediationPlanBuilder.BuildAsync.RemoveScheduledTask.01"),
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
                        DisplayNameText = MessageText.Create("Backend.Core.RemediationPlanBuilder.BuildAsync.RemoveDefenderExclusion.01"),
                        Target = finding.Target,
                        IsKnownMalware = finding.IsKnownMalware,
                        ConfidenceScore = finding.Score
                    },
                    SuggestedActionKind.StopHostProcess => BoundAction(finding, RemediationActionType.StopHostProcess, MessageText.Create("Backend.Core.RemediationPlanBuilder.BuildAsync.StopHostProcess.01")),
                    SuggestedActionKind.DisableService => BoundAction(finding, RemediationActionType.DisableService, MessageText.Create("Backend.Core.RemediationPlanBuilder.BuildAsync.DisableService.01")),
                    SuggestedActionKind.RemoveRelatedDefenderExclusion => BoundAction(finding, RemediationActionType.RemoveRelatedDefenderExclusion, MessageText.Create("Backend.Core.RemediationPlanBuilder.BuildAsync.RemoveRelatedDefenderExclusion.01")),
                    SuggestedActionKind.DisableRelatedFirewallRule => BoundAction(finding, RemediationActionType.DisableRelatedFirewallRule, MessageText.Create("Backend.Core.RemediationPlanBuilder.BuildAsync.DisableRelatedFirewallRule.01")),
                    SuggestedActionKind.QuarantineFile when File.Exists(finding.Target) => await CreateFileActionAsync(finding, cancellationToken),
                    SuggestedActionKind.QuarantineDirectory when Directory.Exists(finding.Target) =>
                        await CreateDirectoryActionAsync(finding, cancellationToken),
                    SuggestedActionKind.RestoreSecurityControls => new RemediationAction
                    {
                        Type = RemediationActionType.RestoreSecurityControls,
                        DisplayNameText = MessageText.Create("Backend.Core.RemediationPlanBuilder.BuildAsync.RestoreSecurityControls.01"),
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
                        throw MessageExceptions.Create(MessageText.Create("Backend.Core.RemediationPlanBuilder.BuildAsync.03"), sourceText => new InvalidDataException(sourceText));
                }
                else { deduplication.Add(key, action); plan.Actions.Add(action); }
                if (plan.Actions.Count > 64) throw MessageExceptions.Create(MessageText.Create("Backend.Core.RemediationPlanBuilder.BuildAsync.04"), sourceText => new InvalidDataException(sourceText));
            }

            if (finding.IsKnownMalware && !finding.SuggestedActions.Contains(SuggestedActionKind.StopHostProcess) &&
                finding.Target.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) && File.Exists(finding.Target))
            {
                string hash = await VerifyTargetIdentityAsync(finding, cancellationToken);
                RemediationAction firewall = new()
                {
                    Type = RemediationActionType.AddProgramFirewallBlock,
                    DisplayNameText = MessageText.Create("Backend.Core.RemediationPlanBuilder.BuildAsync.05"),
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
                DisplayNameText = MessageText.Create("Backend.Core.RemediationPlanBuilder.BuildAsync.06"),
                Target = "hosts",
                Domains = [.. rules.KnownDomains],
                IsKnownMalware = true,
                ConfidenceScore = 100
            });
        }

        if (plan.Actions.Count > 64) throw MessageExceptions.Create(MessageText.Create("Backend.Core.RemediationPlanBuilder.BuildAsync.07"), sourceText => new InvalidDataException(sourceText));
        OrderActionsForSafeExecution(plan.Actions);

        return plan;
    }

    internal static void OrderActionsForSafeExecution(List<RemediationAction> actions)
    {
        RemediationDependencies.AssignAndOrder(actions);
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

    private async Task<RemediationAction> CreateFileActionAsync(Finding finding, CancellationToken cancellationToken)
    {
        string path = Path.GetFullPath(finding.Target);
        string hash = await VerifyTargetIdentityAsync(finding, cancellationToken);
        if (!FileRemediationScope.IsAllowed(path, hash, rules, _steamLayout.Value))
            throw MessageExceptions.Create(MessageText.Create("Remediation.FileScopeNotApproved",
                    path.Length <= 4096 ? path : path[..2046] + " … " + path[^2046..]),
                sourceText => new FileRemediationScopeException(sourceText));
        return new RemediationAction
        {
            Type = RemediationActionType.QuarantineFile,
            DisplayNameText = MessageText.Create("Backend.Core.RemediationPlanBuilder.CreateFileActionAsync.01"),
            Target = path,
            ExpectedSha256 = hash,
            IsKnownMalware = finding.IsKnownMalware,
            ConfidenceScore = finding.Score
        };
    }

    private static RemediationAction BoundAction(Finding finding, RemediationActionType type, MessageText label) => new()
    {
        Type = type,
        DisplayNameText = label,
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
            throw MessageExceptions.Create(MessageText.Create("Backend.Core.RemediationPlanBuilder.CreateDirectoryActionAsync.01") + path, sourceText => new InvalidDataException(sourceText));
        return new RemediationAction
        {
            Type = RemediationActionType.QuarantineDirectory,
            DisplayNameText = MessageText.Create("Backend.Core.RemediationPlanBuilder.CreateDirectoryActionAsync.02"),
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
            throw MessageExceptions.Create(MessageText.Create("Backend.Core.RemediationPlanBuilder.VerifyFileIdentityAsync.01", (path)), sourceText => new InvalidDataException(sourceText));
        await using FileStream stream = RelatedArtifactReader.Open(path);
        if (stream.Length > 256L * 1024 * 1024) throw MessageExceptions.Create(MessageText.Create("Backend.Core.RemediationPlanBuilder.VerifyFileIdentityAsync.02") + path, sourceText => new InvalidDataException(sourceText));
        string hash = await Hashing.Sha256StreamAsync(stream, cancellationToken);
        if (!expected!.Equals(hash, StringComparison.OrdinalIgnoreCase))
            throw MessageExceptions.Create(MessageText.Create("Backend.Core.RemediationPlanBuilder.VerifyFileIdentityAsync.03", (path)), sourceText => new InvalidDataException(sourceText));
        return hash;
    }
}
