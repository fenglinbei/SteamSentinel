using System.Diagnostics;
using System.IO;
using System.Text.Json;
using SteamSentinel.Core.Models;
using SteamSentinel.Core.Remediation;
using SteamSentinel.Core.Reporting;
using SteamSentinel.Core.Utilities;

namespace SteamSentinel.SelfTest;

internal static partial class Program
{
    // Recorded results only: no sample files, process execution, or remediation effects.
    private static RemediationBatchSession CreateRemediationFailureDetailsFixture()
    {
        const string root = @"C:\Lab\RemediationDetails";
        string executable = Path.Combine(root, "SteamAlertDemo", "Application Frame Host.exe");
        RemediationAction firewall = new()
        {
            Type = RemediationActionType.AddProgramFirewallBlock,
            Target = executable,
            ExpectedSha256 = SteamAlertWatchdog.ResidentHash,
            IsKnownMalware = true
        };
        RemediationAction quarantine = new()
        {
            Type = RemediationActionType.QuarantineFile,
            Target = executable,
            ExpectedSha256 = SteamAlertWatchdog.ResidentHash,
            IsKnownMalware = true,
            DependsOnActionIds = [firewall.ActionId]
        };
        RemediationAction[] scripts = new[] { ("sa_watch.ps1", SteamAlertWatchdog.WatchdogHash),
            ("sa_updater.ps1", SteamAlertWatchdog.UpdaterHash), ("update.ps1", SteamAlertWatchdog.UpdaterHash),
            ("sa_launch.ps1", SteamAlertWatchdog.LauncherHash) }.Select(item => new RemediationAction
            {
                Type = RemediationActionType.QuarantineFile,
                Target = Path.Combine(root, "SteamAlertUpdater", item.Item1),
                ExpectedSha256 = item.Item2,
                IsKnownMalware = true,
                DependsOnActionIds = [firewall.ActionId]
            }).ToArray();
        RemediationAction hosts = new() { Type = RemediationActionType.BlockKnownDomains, Target = "hosts" };
        List<RemediationAction> actions = [.. scripts, quarantine, firewall, hosts];
        RemediationDependencies.AssignAndOrder(actions);
        RemediationPlan plan = new() { Actions = actions };
        RemediationActionResult firewallResult = new()
        {
            ActionId = firewall.ActionId,
            Type = firewall.Type,
            Target = firewall.Target,
            Success = true,
            ExecutionStatus = RemediationExecutionStatus.Succeeded,
            VerificationStatus = RemediationVerificationStatus.Verified,
            Message = "INERT_FIREWALL_CREATED",
            VerificationSummary = "INERT_SECOND_PASS_CLEAR",
            Verifications =
            [
                new() { Pass = 1, Status = RemediationVerificationStatus.Unknown, MessageText = MessageText.Create("RemediationVerification.ObserveAsync.03") },
                new() { Pass = 2, Status = RemediationVerificationStatus.Verified, Message = "INERT_SECOND_PASS_CLEAR" }
            ]
        };
        RemediationActionResult Result(RemediationAction action) => action == firewall ? firewallResult : action == hosts
            ? new()
            {
                ActionId = action.ActionId,
                Type = action.Type,
                Target = action.Target,
                Success = true,
                ExecutionStatus = RemediationExecutionStatus.Succeeded,
                VerificationStatus = RemediationVerificationStatus.Verified,
                Message = "INERT_HOSTS_COMPLETED"
            }
            : new()
            {
                ActionId = action.ActionId,
                Type = action.Type,
                Target = action.Target,
                ExecutionStatus = RemediationExecutionStatus.SkippedDependency,
                VerificationStatus = RemediationVerificationStatus.Unknown,
                MessageText = MessageText.Create("Backend.Broker.DependencyBlocked", string.Join(", ", action.DependsOnActionIds))
            };
        RemediationBatchSession batch = new()
        {
            SelectedFindingCount = 5,
            ExecutionStarted = true,
            ExecutionFinished = true,
            Plans = [plan],
            Results = [new() { PlanId = plan.PlanId, Actions = actions.Select(Result).Reverse().ToList() }],
            Targets =
            [
                .. scripts.Select(action => new RemediationTargetOutcome { Key = action.Target, Target = action.Target, ActionIds = [action.ActionId] }),
                // Preparation lists quarantine before the implicit firewall action.
                new() { Key = "executable", Target = executable, ActionIds = [quarantine.ActionId, firewall.ActionId] },
                new() { Key = "hosts", Target = "hosts", AddedByAssociation = true, ActionIds = [hosts.ActionId] }
            ]
        };
        RemediationBatchPlanner.RefreshOutcomes(batch);
        return batch;
    }

    private static RemediationBatchSession CreateRemediationIdentityFailureFixture()
    {
        RemediationBatchSession batch = CreateRemediationFailureDetailsFixture();
        string executable = batch.Targets.Single(target => target.Key == "executable").Target;
        foreach (RemediationActionResult result in batch.Results.Single().Actions)
        {
            if (result.Type == RemediationActionType.AddProgramFirewallBlock)
                result.Verifications[0] = new() { Pass = 1, Status = RemediationVerificationStatus.Verified, Message = "INERT_FIRST_PASS_CLEAR" };
            if (result.Type != RemediationActionType.QuarantineFile || result.Target == executable) continue;
            result.ExecutionStatus = RemediationExecutionStatus.Failed;
            result.VerificationStatus = RemediationVerificationStatus.ResidualDetected;
            result.MessageText = MessageText.Create("Backend.Exception", nameof(UnauthorizedAccessException), MessageText.Create("Scope.IdentityChanged"));
        }
        RemediationBatchPlanner.RefreshOutcomes(batch);
        return batch;
    }

    private static void TestRemediationFailureDetails()
    {
        RemediationBatchSession batch = CreateRemediationFailureDetailsFixture();
        RemediationTargetOutcome target = batch.Targets.Single(item => item.Key == "executable");
        RemediationActionResult firewall = batch.Results.Single().Actions.Single(action => action.Type == RemediationActionType.AddProgramFirewallBlock);
        string timeout = firewall.Verifications[0].Message;
        Check("Remediation details keep six target rows distinct from seven underlying actions",
            batch.Targets.Count == 6 && batch.Results.Single().Actions.Count == 7 && batch.CompletedCount == 1 && batch.FailedCount == 0 && batch.UnfinishedCount == 5 &&
            batch.Targets.Single(item => item.State == RemediationTargetState.Completed).Target == "hosts");
        Check("Remediation details keep the first failed pass when the firewall second pass is clear",
            firewall.Success && firewall.VerificationStatus == RemediationVerificationStatus.Verified &&
            target.ReasonDetails!.Contains(timeout, StringComparison.Ordinal) &&
            target.ReasonDetails.Contains(ReportExporter.ActionLabel(firewall.Type, DisplayText.Chinese), StringComparison.Ordinal));
        RemediationBatchSession timedOutTwice = CreateRemediationFailureDetailsFixture();
        RemediationActionResult fieldFirewall = timedOutTwice.Results.Single().Actions.Single(action => action.Type == RemediationActionType.AddProgramFirewallBlock);
        fieldFirewall.VerificationStatus = RemediationVerificationStatus.Unknown;
        fieldFirewall.VerificationSummaryText = MessageText.Create("RemediationVerification.ObserveAsync.03");
        fieldFirewall.Verifications[1] = new()
        {
            Pass = 2,
            Status = RemediationVerificationStatus.Unknown,
            MessageText = MessageText.Create("RemediationVerification.ObserveAsync.03")
        };
        RemediationBatchPlanner.RefreshOutcomes(timedOutTwice);
        Check("Remediation details reproduce the field result with two firewall timeouts, five skipped quarantines, and completed hosts",
            fieldFirewall.Success && fieldFirewall.Verifications.All(pass => pass.Status == RemediationVerificationStatus.Unknown) &&
            timedOutTwice.CompletedCount == 1 && timedOutTwice.FailedCount == 0 && timedOutTwice.UnfinishedCount == 5 &&
            timedOutTwice.Targets.Where(item => item.State == RemediationTargetState.SkippedDependency).Count(item => item.ReasonDetails!.Contains(timeout, StringComparison.Ordinal)) == 5 &&
            timedOutTwice.Results.Single().Actions.Count(action => action.ExecutionStatus == RemediationExecutionStatus.SkippedDependency) == 5);
        IReadOnlyList<RemediationActionResult> selected = RemediationResultPresentation.TargetActions(batch, target);
        Check("Remediation details follow plan order and omit the independent successful hosts action",
            selected.Count == 6 && selected[0].ActionId == firewall.ActionId && selected[^1].Target == target.Target &&
            selected[^1].Type == RemediationActionType.QuarantineFile && selected.All(action => action.Target != "hosts"));
        foreach (var culture in new[] { DisplayText.Chinese, DisplayText.English })
        {
            using IDisposable language = DisplayText.UseCulture(culture);
            string details = RemediationResultPresentation.DescribeTarget(batch, target);
            string firstPass = DisplayText.Format("Result.VerificationPass", 1, RemediationVerification.Label(RemediationVerificationStatus.Unknown),
                firewall.Verifications[0].MessageText.Display);
            string secondPass = DisplayText.Format("Result.VerificationPass", 2, RemediationVerification.Label(RemediationVerificationStatus.Verified),
                firewall.Verifications[1].MessageText.Display);
            Check($"Remediation details {culture.Name} preserve both ordered passes and typed execution labels",
                details.IndexOf(firstPass, StringComparison.Ordinal) >= 0 &&
                details.IndexOf(secondPass, StringComparison.Ordinal) > details.IndexOf(firstPass, StringComparison.Ordinal) &&
                details.Contains(ReportExporter.ActionLabel(firewall.Type), StringComparison.Ordinal) &&
                details.Contains(RemediationResultPresentation.ExecutionLabel(RemediationExecutionStatus.SkippedDependency), StringComparison.Ordinal) &&
                target.Reason.Contains(firewall.Verifications[0].MessageText.Display, StringComparison.Ordinal));
        }
        RemediationTargetOutcome script = batch.Targets[0];
        IReadOnlyList<RemediationActionResult> scriptResults = RemediationResultPresentation.TargetActions(batch, script);
        Check("Remediation details resolve a skipped script to its exact recorded prerequisite only",
            scriptResults.Count == 2 && scriptResults[0].ActionId == firewall.ActionId && scriptResults[1].Target == script.Target &&
            script.ReasonDetails!.Contains(timeout, StringComparison.Ordinal));
        string planBefore = JsonSerializer.Serialize(batch.Plans, JsonFile.Options);
        string resultsBefore = JsonSerializer.Serialize(batch.Results, JsonFile.Options);
        RemediationBatchSession restored = JsonSerializer.Deserialize<RemediationBatchSession>(JsonSerializer.Serialize(batch, JsonFile.Options), JsonFile.Options)!;
        RemediationBatchPlanner.RefreshOutcomes(restored);
        Check("Remediation details retain the first failure across record persistence without changing the plan or action results",
            restored.Targets.Single(item => item.Key == "executable").ReasonDetails!.Contains(timeout, StringComparison.Ordinal) &&
            JsonSerializer.Serialize(batch.Plans, JsonFile.Options) == planBefore && JsonSerializer.Serialize(batch.Results, JsonFile.Options) == resultsBefore);
        RemediationBatchSession lateTimeout = CreateRemediationFailureDetailsFixture();
        RemediationTargetOutcome lateTarget = lateTimeout.Targets.Single(item => item.Key == "executable");
        RemediationActionResult lateFirewall = lateTimeout.Results.Single().Actions.Single(action => action.Type == RemediationActionType.AddProgramFirewallBlock);
        lateFirewall.VerificationStatus = RemediationVerificationStatus.Unknown;
        lateFirewall.VerificationSummary = "INERT_LATE_FIREWALL_TIMEOUT";
        lateFirewall.Verifications[0] = new() { Pass = 1, Status = RemediationVerificationStatus.Verified, Message = "INERT_FIRST_PASS_CLEAR" };
        lateFirewall.Verifications[1] = new() { Pass = 2, Status = RemediationVerificationStatus.Unknown, Message = "INERT_LATE_FIREWALL_TIMEOUT" };
        foreach (RemediationActionResult action in lateTimeout.Results.Single().Actions.Where(action => action.Type == RemediationActionType.QuarantineFile))
        {
            bool actualFailure = action.Target == lateTarget.Target;
            action.Success = !actualFailure;
            action.ExecutionStatus = actualFailure ? RemediationExecutionStatus.Failed : RemediationExecutionStatus.Succeeded;
            action.VerificationStatus = actualFailure ? RemediationVerificationStatus.Unknown : RemediationVerificationStatus.NoResidual;
            action.Message = actualFailure ? "INERT_QUARANTINE_EXECUTION_FAILURE" : "INERT_QUARANTINE_COMPLETED";
        }
        RemediationBatchPlanner.RefreshOutcomes(lateTimeout);
        Check("Remediation details do not blame a later firewall timeout for an earlier quarantine execution failure",
            lateTarget.ReasonDetails!.Contains("INERT_QUARANTINE_EXECUTION_FAILURE", StringComparison.Ordinal) &&
            !lateTarget.ReasonDetails.Contains("INERT_LATE_FIREWALL_TIMEOUT", StringComparison.Ordinal) &&
            RemediationResultPresentation.DescribeTarget(lateTimeout, lateTarget).Contains("INERT_LATE_FIREWALL_TIMEOUT", StringComparison.Ordinal));
        RemediationBatchSession preflight = CreateRemediationFailureDetailsFixture();
        RemediationTargetOutcome preflightTarget = preflight.Targets.Single(item => item.Key == "executable");
        RemediationRunResult refused = new() { PlanId = preflight.Plans.Single().PlanId, Disposition = RemediationRunDisposition.NotStarted };
        refused.AddError("INERT_EXACT_PREFLIGHT_REFUSAL");
        preflight.Results.Clear(); preflight.Results.Add(refused);
        RemediationAction unrelated = new() { Type = RemediationActionType.QuarantineFile, Target = @"C:\Lab\Unrelated.txt" };
        RemediationPlan unrelatedPlan = new() { Actions = [unrelated] };
        preflight.Plans.Add(unrelatedPlan);
        RemediationRunResult unrelatedRun = new() { PlanId = unrelatedPlan.PlanId, Disposition = RemediationRunDisposition.NotStarted };
        unrelatedRun.AddError("INERT_UNRELATED_PLAN_ERROR"); preflight.Results.Add(unrelatedRun);
        RemediationBatchPlanner.RefreshOutcomes(preflight);
        string refusedDetails = RemediationResultPresentation.DescribeTarget(preflight, preflightTarget);
        Check("Remediation details retain an empty-action preflight refusal and exclude unrelated run errors",
            refusedDetails.Contains("INERT_EXACT_PREFLIGHT_REFUSAL", StringComparison.Ordinal) &&
            refusedDetails.Contains(RemediationResultPresentation.RunLabel(RemediationRunDisposition.NotStarted), StringComparison.Ordinal) &&
            refusedDetails.Contains(preflightTarget.Reason, StringComparison.Ordinal) &&
            !refusedDetails.Contains("INERT_UNRELATED_PLAN_ERROR", StringComparison.Ordinal));
        RemediationBatchSession interrupted = CreateRemediationFailureDetailsFixture();
        RemediationTargetOutcome interruptedTarget = interrupted.Targets.Single(item => item.Key == "executable");
        RemediationRunResult partial = interrupted.Results.Single();
        partial.Actions.RemoveAll(action => action.Type != RemediationActionType.AddProgramFirewallBlock);
        partial.Disposition = RemediationRunDisposition.ExecutionUnknown;
        partial.AddError("INERT_RUN_INTERRUPTED_AFTER_FIREWALL");
        RemediationBatchPlanner.RefreshOutcomes(interrupted);
        Guid missingId = interrupted.Plans.Single().Actions.Single(action => action.Type == RemediationActionType.QuarantineFile && action.Target == interruptedTarget.Target).ActionId;
        string missing = DisplayText.Format("Result.MissingAction", ReportExporter.ActionLabel(RemediationActionType.QuarantineFile), missingId);
        string interruptedDetails = RemediationResultPresentation.DescribeTarget(interrupted, interruptedTarget);
        Check("Remediation details keep the selected target outcome, missing result, and run error beside its recorded predecessor",
            interruptedDetails.Contains(interruptedTarget.Reason, StringComparison.Ordinal) && interruptedDetails.Contains(missing, StringComparison.Ordinal) &&
            interruptedDetails.Contains("INERT_RUN_INTERRUPTED_AFTER_FIREWALL", StringComparison.Ordinal) &&
            interruptedDetails.Contains("INERT_FIREWALL_CREATED", StringComparison.Ordinal));
        firewall.Success = false;
        firewall.ExecutionStatus = RemediationExecutionStatus.Failed;
        firewall.Message = "INERT_FIRST_EXECUTION_FAILURE";
        RemediationBatchPlanner.RefreshOutcomes(batch);
        Check("Remediation details place a direct firewall execution failure before the later skipped quarantine",
            target.ReasonDetails!.Contains(firewall.Message, StringComparison.Ordinal) &&
            !target.ReasonDetails.Contains("Backend.Broker.DependencyBlocked", StringComparison.Ordinal) && batch.CompletedCount == 1 && batch.FailedCount == 1 && batch.UnfinishedCount == 4);
        firewall.Message = "INERT_LONG_ROOT_CAUSE:" + new string('x', 12_000) + ":INERT_FULL_DETAIL_END";
        RemediationBatchPlanner.RefreshOutcomes(batch);
        Check("Remediation details bound each stored summary while complete selected records remain copyable",
            batch.Targets.All(item => (item.ReasonDetails?.Length ?? 0) <= RemediationResultPresentation.MaximumTargetSummaryCharacters) &&
            target.ReasonDetails!.StartsWith(ReportExporter.ActionLabel(firewall.Type, DisplayText.Chinese), StringComparison.Ordinal) &&
            RemediationResultPresentation.DescribeTarget(batch, target).Contains(":INERT_FULL_DETAIL_END", StringComparison.Ordinal));
        RemediationAction quarantine = batch.Plans.Single().Actions.Single(action => action.Type == RemediationActionType.QuarantineFile && action.Target == target.Target);
        Check("Remediation details preserve explicit firewall and script safety dependencies",
            quarantine.DependsOnActionIds.Count == 5 && quarantine.DependsOnActionIds.Contains(firewall.ActionId) &&
            RemediationDependencies.Build(batch.Plans.Single().Actions)[quarantine.ActionId].Count == 5);
        TestFirewallBestEffortDecoupling(batch.Targets.Single(item => item.Key == "executable").Target);
        RemediationAction[] many = Enumerable.Range(0, 65).Select(index => new RemediationAction
        { Type = RemediationActionType.QuarantineFile, Target = @"C:\Lab\OldRecord\" + index }).ToArray();
        RemediationTargetOutcome manyTarget = new() { Target = "inert legacy aggregate", ActionIds = many.Select(action => action.ActionId).ToList() };
        RemediationBatchSession oldAggregate = new()
        {
            Plans = many.Chunk(64).Select(group => new RemediationPlan { Actions = group.ToList() }).ToList(),
            Targets = [manyTarget]
        };
        Check("Remediation details disclose the bounded view instead of silently hiding oversized legacy action sets",
            RemediationResultPresentation.DescribeTarget(oldAggregate, manyTarget).Contains(
                DisplayText.Format("Result.TargetDetailsLimit", RemediationResultPresentation.MaximumTargetDetailActions), StringComparison.Ordinal));
        TestRemediationDependencyAttribution();
        TestRemediationFailureDetailsLargeBatch();
    }

    private static void TestFirewallBestEffortDecoupling(string executable)
    {
        string directory = Path.GetDirectoryName(executable)!;
        RemediationAction implicitFirewall = new()
        {
            Type = RemediationActionType.AddProgramFirewallBlock,
            Target = executable,
            ExpectedSha256 = SteamAlertWatchdog.ResidentHash,
            IsKnownMalware = true
        };
        RemediationAction implicitQuarantine = new()
        {
            Type = RemediationActionType.QuarantineFile,
            Target = executable,
            ExpectedSha256 = SteamAlertWatchdog.ResidentHash,
            IsKnownMalware = true
        };
        RemediationAction[] implicitScripts = new[]
        {
            ("sa_watch.ps1", SteamAlertWatchdog.WatchdogHash),
            ("sa_updater.ps1", SteamAlertWatchdog.UpdaterHash)
        }.Select(item => new RemediationAction
        {
            Type = RemediationActionType.QuarantineFile,
            Target = Path.Combine(directory, item.Item1),
            ExpectedSha256 = item.Item2,
            IsKnownMalware = true
        }).ToArray();
        List<RemediationAction> implicitActions = [.. implicitScripts, implicitQuarantine, implicitFirewall];
        RemediationDependencies.AssignAndOrder(implicitActions);
        var built = RemediationDependencies.Build(implicitActions);
        Check("防火墙动作不隐式阻断文件隔离而脚本安全依赖保留",
            !built[implicitQuarantine.ActionId].Contains(implicitFirewall.ActionId) &&
            implicitScripts.All(script => built[implicitQuarantine.ActionId].Contains(script.ActionId) &&
                                          !built[script.ActionId].Contains(implicitFirewall.ActionId)) &&
            implicitActions.IndexOf(implicitFirewall) < implicitActions.IndexOf(implicitQuarantine));

        RemediationRunResult runResult = new();
        SteamSentinel.Broker.BrokerActionSequencer.RunAsync(new() { Actions = implicitActions }, runResult, new Dictionary<Guid, string>(),
            (action, _) => action == implicitFirewall
                ? Task.FromException<string>(new InvalidOperationException("Inert firewall service disabled"))
                : Task.FromResult("Inert quarantine succeeded"),
            (action, outcome, _) =>
            {
                outcome.VerificationStatus = action == implicitFirewall
                    ? RemediationVerificationStatus.Unknown
                    : RemediationVerificationStatus.NoResidual;
                return Task.CompletedTask;
            },
            _ => Task.CompletedTask).GetAwaiter().GetResult();
        Check("防火墙失败或超时不跳过后续文件隔离",
            runResult.Actions.Single(r => r.ActionId == implicitFirewall.ActionId).ExecutionStatus == RemediationExecutionStatus.Failed &&
            runResult.Actions.Single(r => r.ActionId == implicitQuarantine.ActionId).ExecutionStatus == RemediationExecutionStatus.Succeeded &&
            implicitScripts.All(s => runResult.Actions.Single(r => r.ActionId == s.ActionId).ExecutionStatus == RemediationExecutionStatus.Succeeded));

        RemediationAction batchTwoAction = new() { Type = RemediationActionType.RepairSteamConfiguration, Target = @"C:\Lab\steam.cfg" };
        RemediationPlan planOne = new() { Actions = implicitActions };
        RemediationPlan planTwo = new() { Actions = [batchTwoAction] };
        RemediationBatchSession session = new() { Plans = [planOne, planTwo] };
        int executedBatches = 0;
        RemediationBatchPlanner.ExecuteAsync(session, plan =>
        {
            executedBatches++;
            if (plan.PlanId == planOne.PlanId)
            {
                return Task.FromResult(new RemediationRunResult
                {
                    PlanId = plan.PlanId,
                    Disposition = RemediationRunDisposition.Completed,
                    Success = false,
                    Errors = ["Inert firewall failure only"],
                    Actions = plan.Actions.Select(a => new RemediationActionResult
                    {
                        ActionId = a.ActionId,
                        Type = a.Type,
                        Target = a.Target,
                        Success = a != implicitFirewall,
                        ExecutionStatus = a == implicitFirewall ? RemediationExecutionStatus.Failed : RemediationExecutionStatus.Succeeded,
                        VerificationStatus = a == implicitFirewall ? RemediationVerificationStatus.Unknown : RemediationVerificationStatus.NoResidual
                    }).ToList()
                });
            }
            return Task.FromResult(new RemediationRunResult
            {
                PlanId = plan.PlanId,
                Disposition = RemediationRunDisposition.Completed,
                Success = true,
                VerificationStatus = RemediationVerificationStatus.Verified,
                Actions = [new()
                {
                    ActionId = batchTwoAction.ActionId, Type = batchTwoAction.Type, Target = batchTwoAction.Target,
                    Success = true, ExecutionStatus = RemediationExecutionStatus.Succeeded, VerificationStatus = RemediationVerificationStatus.Verified
                }]
            });
        }).GetAwaiter().GetResult();
        Check("批次仅防火墙失败时继续执行后续批次恢复",
            executedBatches == 2 && session.InterruptionReasonCode is null && session.Results.Count == 2 &&
            session.Results[1].Actions.Single().ExecutionStatus == RemediationExecutionStatus.Succeeded);
    }

    private static void TestRemediationDependencyAttribution()
    {
        RemediationBatchSession batch = CreateRemediationIdentityFailureFixture();
        RemediationTargetOutcome executable = batch.Targets.Single(target => target.Key == "executable");
        RemediationAction firstScript = batch.Plans.Single().Actions.First(action => action.Type == RemediationActionType.QuarantineFile && action.Target != executable.Target);
        RemediationActionResult skipped = batch.Results.Single().Actions.Single(action => action.Type == RemediationActionType.QuarantineFile && action.Target == executable.Target);
        string plansBefore = JsonSerializer.Serialize(batch.Plans, JsonFile.Options);
        string resultsBefore = JsonSerializer.Serialize(batch.Results, JsonFile.Options);
        Check("Remediation attribution separates four failed scripts from the skipped executable",
            batch.FailedCount == 4 && batch.UnfinishedCount == 1 && batch.CompletedCount == 1 &&
            executable.State == RemediationTargetState.SkippedDependency && executable.ReasonCode == ReasonCodes.DependencyBlocked &&
            batch.Targets.Where(target => target.Key is not ("executable" or "hosts")).All(target => target.State == RemediationTargetState.Failed));
        foreach (var culture in new[] { DisplayText.Chinese, DisplayText.English })
        {
            using IDisposable language = DisplayText.UseCulture(culture);
            string skip = DisplayText.Format("Result.DependencySkip", ReportExporter.ActionLabel(skipped.Type));
            string cause = DisplayText.Format("Result.PrerequisiteCause", ReportExporter.ActionLabel(firstScript.Type), firstScript.Target,
                batch.Results.Single().Actions.Single(action => action.ActionId == firstScript.ActionId).MessageText.Display);
            Check($"Remediation attribution {culture.Name} names the skipped action and the failing prerequisite file",
                executable.ReasonDetailsText.Display.StartsWith(skip, StringComparison.Ordinal) &&
                executable.ReasonDetailsText.Display.Contains(cause, StringComparison.Ordinal) &&
                !executable.ReasonDetailsText.Display.Contains(executable.Target, StringComparison.Ordinal) &&
                executable.Status == StatusPresentation.Target(RemediationTargetState.SkippedDependency, culture));
        }
        RemediationBatchSession restored = JsonSerializer.Deserialize<RemediationBatchSession>(JsonSerializer.Serialize(batch, JsonFile.Options), JsonFile.Options)!;
        // Prior versions persisted every unsuccessful target as Failed. Rebuild the display
        // from the original typed action results without rewriting their execution evidence.
        restored.Targets.Single(target => target.Key == "executable").SetState(RemediationTargetState.Failed, ReasonCodes.ActionFailed);
        RemediationBatchPlanner.RefreshOutcomes(restored);
        Check("Remediation attribution refreshes old failed target summaries without modifying saved action evidence",
            restored.Targets.Single(target => target.Key == "executable").State == RemediationTargetState.SkippedDependency &&
            JsonSerializer.Serialize(restored.Plans, JsonFile.Options) == plansBefore &&
            JsonSerializer.Serialize(restored.Results, JsonFile.Options) == resultsBefore);
        RemediationBatchSession withoutPlan = new()
        {
            Results = [new() { Actions = [skipped] }],
            Targets = [new() { Target = skipped.Target, ActionIds = [skipped.ActionId] }]
        };
        RemediationBatchPlanner.RefreshOutcomes(withoutPlan);
        Check("Remediation attribution keeps a legacy skip without a plan and does not invent a prerequisite path",
            withoutPlan.Targets.Single().State == RemediationTargetState.SkippedDependency &&
            withoutPlan.Targets.Single().ReasonDetails!.Contains(skipped.Message, StringComparison.Ordinal) &&
            !withoutPlan.Targets.Single().ReasonDetails!.Contains(firstScript.Target, StringComparison.Ordinal));
        RemediationActionResult untyped = JsonSerializer.Deserialize<RemediationActionResult>(
            "{\"ActionId\":\"" + skipped.ActionId + "\",\"Type\":\"QuarantineFile\",\"Target\":\"C:\\\\Lab\\\\legacy.exe\",\"Success\":false,\"Message\":\"INERT_OLD_UNTYPED_RESULT\"}", JsonFile.Options)!;
        withoutPlan.Results.Single().Actions.Clear(); withoutPlan.Results.Single().Actions.Add(untyped);
        RemediationBatchPlanner.RefreshOutcomes(withoutPlan);
        Check("Remediation attribution never infers a skipped execution from legacy free text",
            withoutPlan.Targets.Single().State == RemediationTargetState.Failed &&
            withoutPlan.Targets.Single().ReasonDetails!.Contains(untyped.Message, StringComparison.Ordinal));
        skipped.ExecutionStatus = RemediationExecutionStatus.Failed;
        skipped.Message = "INERT_EXECUTABLE_OWN_FAILURE";
        RemediationBatchPlanner.RefreshOutcomes(batch);
        Check("Remediation attribution prefers an executable's own failure over a failed prerequisite",
            executable.State == RemediationTargetState.Failed && executable.ReasonDetails!.Contains(skipped.Message, StringComparison.Ordinal) &&
            !executable.ReasonDetails.Contains(firstScript.Target, StringComparison.Ordinal));
    }

    private static void TestRemediationFailureDetailsLargeBatch()
    {
        const int batches = 100, targetsPerBatch = 50;
        RemediationBatchSession session = new() { ExecutionStarted = true, ExecutionFinished = true };
        Dictionary<Guid, string> expectedCauses = [];
        for (int batch = 0; batch < batches; batch++)
        {
            string cause = "INERT_LARGE_BATCH_FIRST_PASS_" + batch.ToString("D3");
            RemediationAction firewall = new()
            {
                Type = RemediationActionType.AddProgramFirewallBlock,
                Target = $@"C:\Lab\NeverCreated\Batch{batch}\payload.exe",
                ExpectedSha256 = SteamAlertWatchdog.ResidentHash
            };
            RemediationPlan plan = new() { Actions = [firewall] };
            RemediationRunResult result = new()
            {
                PlanId = plan.PlanId,
                Disposition = RemediationRunDisposition.Completed,
                Actions = [new()
                {
                    ActionId = firewall.ActionId, Type = firewall.Type, Target = firewall.Target, Success = true,
                    ExecutionStatus = RemediationExecutionStatus.Succeeded, VerificationStatus = RemediationVerificationStatus.Verified,
                    Verifications =
                    [
                        new() { Pass = 1, Status = RemediationVerificationStatus.Unknown, Message = cause },
                        new() { Pass = 2, Status = RemediationVerificationStatus.Verified, Message = "INERT_LARGE_BATCH_SECOND_PASS_CLEAR" }
                    ]
                }]
            };
            for (int target = 0; target < targetsPerBatch; target++)
            {
                RemediationAction quarantine = new()
                {
                    Type = RemediationActionType.QuarantineFile,
                    Target = $@"C:\Lab\NeverCreated\Batch{batch}\script{target}.ps1",
                    ExpectedSha256 = SteamAlertWatchdog.WatchdogHash,
                    DependsOnActionIds = [firewall.ActionId]
                };
                plan.Actions.Add(quarantine);
                result.Actions.Add(new()
                {
                    ActionId = quarantine.ActionId,
                    Type = quarantine.Type,
                    Target = quarantine.Target,
                    ExecutionStatus = RemediationExecutionStatus.SkippedDependency,
                    VerificationStatus = RemediationVerificationStatus.Unknown,
                    Message = "INERT_BLOCKED_BY:" + firewall.ActionId
                });
                expectedCauses.Add(quarantine.ActionId, cause);
                session.Targets.Add(new() { Key = quarantine.Target, Target = quarantine.Target, ActionIds = [quarantine.ActionId] });
            }
            session.Plans.Add(plan);
            session.Results.Add(result);
        }
        string plansBefore = JsonSerializer.Serialize(session.Plans, JsonFile.Options);
        string resultsBefore = JsonSerializer.Serialize(session.Results, JsonFile.Options);
        long allocatedBefore = GC.GetAllocatedBytesForCurrentThread();
        Stopwatch elapsed = Stopwatch.StartNew();
        RemediationBatchPlanner.RefreshOutcomes(session);
        elapsed.Stop();
        long allocated = GC.GetAllocatedBytesForCurrentThread() - allocatedBefore;
        Console.WriteLine($"Remediation detail large batch: targets={session.Targets.Count}; elapsedMs={elapsed.ElapsedMilliseconds}; allocatedBytes={allocated}");
        Check("Remediation details refresh 5000 skipped targets within bounded time and allocation",
            elapsed.Elapsed < TimeSpan.FromSeconds(5) && allocated < 256L * 1024 * 1024);
        Check("Remediation details keep all large-batch causes and summaries without changing plans or action evidence",
            session.Targets.Count == 5000 && session.FailedCount == 0 && session.UnfinishedCount == 5000 &&
            session.Targets.All(target => target.State == RemediationTargetState.SkippedDependency) &&
            session.Targets.All(target => target.ReasonDetails is { Length: > 0 } details &&
                details.Length <= RemediationResultPresentation.MaximumTargetSummaryCharacters &&
                details.Contains(expectedCauses[target.ActionIds.Single()], StringComparison.Ordinal)) &&
            JsonSerializer.Serialize(session.Plans, JsonFile.Options) == plansBefore &&
            JsonSerializer.Serialize(session.Results, JsonFile.Options) == resultsBefore);
    }
}
