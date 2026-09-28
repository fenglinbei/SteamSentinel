using System.ComponentModel;
using System.Text.Json;
using SteamSentinel.Core.Inspection;
using SteamSentinel.Core.Models;
using SteamSentinel.Core.Scanning;
using SteamSentinel.Core.Reporting;
using SteamSentinel.Core.Steam;
using SteamSentinel.Core.Utilities;

namespace SteamSentinel.Core.Remediation;

/// <summary>Preparation only. Every returned child plan still passes the unchanged Broker limits and identity checks.</summary>
public sealed class RemediationBatchPlanner(RuleSet rules)
{
    public const int MaximumSelectedFindings = 20000;
    public const long PreparationBatchBytes = 512L * 1024 * 1024;

    public async Task<RemediationBatchSession> PrepareAsync(IEnumerable<Finding> selection, ScanReport original,
        bool blockDomains, Func<IReadOnlyList<string>, CancellationToken, Task<ScanReport>>? inspectCandidates = null,
        IProgress<ScanProgress>? progress = null, CancellationToken token = default)
    {
        Finding[] requested = selection.Take(MaximumSelectedFindings + 1).ToArray();
        if (requested.Length > MaximumSelectedFindings) throw MessageExceptions.Create(MessageText.Create("Backend.Core.RemediationBatchPlanner.PrepareAsync.01"), sourceText => new InvalidDataException(sourceText));
        // Keep explicitly requested retired findings in the preview and account for their refusal.
        Finding[] selected = requested.Where(f => f.CanRemediate || RemediationEvidencePolicy.IsReviewOnlyEvidence(f)).ToArray();
        RemediationBatchSession session = new()
        {
            SelectedFindingCount = selected.Length,
            OriginalContentSettings = CloneOptions(original.ContentScanSettings),
            Targets = selected.GroupBy(GoalKey, StringComparer.OrdinalIgnoreCase).Select(g => new RemediationTargetOutcome
            {
                Key = g.Key,
                Target = g.First().Target,
                FindingIds = g.Select(f => f.Id).Distinct().ToList(),
                RequiredActions = g.SelectMany(RequiredActionKeys).Distinct(StringComparer.OrdinalIgnoreCase).ToList()
            }).ToList()
        };
        List<Finding> verified = [];
        MessageTextCollection notes = [];
        void Record(IEnumerable<Finding> findings, IEnumerable<MessageText> details, string reason)
        {
            MessageText[] captured = details.ToArray();
            foreach (MessageText detail in captured) notes.AddText(detail);
            foreach (Finding finding in findings)
                foreach (MessageText detail in captured.Take(5))
                    if (session.PreparationNotes.Count < 4096)
                        session.PreparationNotes.Add(new(finding.Target, reason, detail));
        }
        foreach (Finding finding in selected.Where(RemediationEvidencePolicy.IsReviewOnlyEvidence))
            Record([finding], [RemediationEvidencePolicy.ReviewOnlyMessage(finding)], ReasonCodes.ActionsNotIncluded);
        List<Finding[]> batches = PackSelection(selected.Where(RemediationEvidencePolicy.CanRemediate).ToArray(), notes, session.PreparationNotes);
        for (int index = 0; index < batches.Count; index++)
        {
            token.ThrowIfCancellationRequested();
            progress?.Report(new(MessageText.Create("Backend.Core.RemediationBatchPlanner.PrepareAsync.02"), MessageText.Create("Backend.Core.RemediationBatchPlanner.PrepareAsync.03", (index + 1), (batches.Count)), index, batches.Count, MessageText.Create("Backend.Core.RemediationBatchPlanner.PrepareAsync.04")));
            using CancellationTokenSource timeout = CancellationTokenSource.CreateLinkedTokenSource(token);
            timeout.CancelAfter(TimeSpan.FromMinutes(3));
            try
            {
                RelatedArtifactExpansion expansion = await new RelatedArtifactScanner(rules).ExpandAsync(batches[index], original, timeout.Token);
                if (inspectCandidates is not null && expansion.CandidatePaths.Count > 0)
                {
                    ScanReport additional = await inspectCandidates(expansion.CandidatePaths, timeout.Token);
                    ScanReport combined = ScanReportMerger.Merge(original, additional);
                    expansion = await new RelatedArtifactScanner(rules).ExpandAsync(batches[index], combined, timeout.Token);
                    Record(batches[index], additional.CoverageTexts, ReasonCodes.EvidenceUnavailable);
                }
                verified.AddRange(expansion.Findings);
                Record(batches[index], expansion.NoteTexts, ReasonCodes.EvidenceUnavailable);
            }
            catch (OperationCanceledException) when (!token.IsCancellationRequested)
            { Record(batches[index], [MessageText.Create("Backend.Core.RemediationBatchPlanner.PrepareAsync.05")], ReasonCodes.ResourceLimit); }
            catch (Exception ex) when (ex is IOException or InvalidDataException or UnauthorizedAccessException or Win32Exception)
            { Record(batches[index], [MessageText.Create("Backend.Core.RemediationBatchPlanner.PrepareAsync.06") + MessageExceptions.Describe(ex)], ReasonCodes.EvidenceUnavailable); }
        }
        token.ThrowIfCancellationRequested();
        // Live discovery may connect initial batches through a shared host/entry. Regroup ALL verified edges before packing actions.
        List<List<RemediationAction>> actionGroups = [];
        bool needDomains = blockDomains;
        RemediationPlanBuilder planBuilder = new(rules);
        foreach (Finding finding in verified.Where(RemediationEvidencePolicy.IsReviewOnlyEvidence))
            Record([finding], [RemediationEvidencePolicy.ReviewOnlyMessage(finding)], ReasonCodes.ActionsNotIncluded);
        foreach (Finding[] group in DependencyGroups(verified.Where(RemediationEvidencePolicy.CanRemediate).ToArray()))
        {
            token.ThrowIfCancellationRequested();
            try
            {
                RemediationPlan plan = await planBuilder.BuildAsync(Coalesce(group), false, token, allFindings: group);
                needDomains |= plan.Actions.Any(a => a.Type == RemediationActionType.BlockKnownDomains);
                List<RemediationAction> actions = plan.Actions.Where(a => a.Type != RemediationActionType.BlockKnownDomains).ToList();
                if (actions.Count > 0) actionGroups.Add(actions);
            }
            catch (RemediationEvidenceException ex)
            { Record(group, [MessageExceptions.Describe(ex)], ReasonCodes.ActionsNotIncluded); }
            catch (FileRemediationScopeException ex)
            { Record(group, [MessageExceptions.Describe(ex)], ReasonCodes.ActionsNotIncluded); }
            catch (Exception ex) when (ex is IOException or InvalidDataException or UnauthorizedAccessException or Win32Exception)
            { Record(group, [MessageText.Create("Backend.Core.RemediationBatchPlanner.PrepareAsync.07") + MessageExceptions.Describe(ex)], ReasonCodes.EvidenceUnavailable); }
        }
        session.Plans.AddRange(PackActions(actionGroups));
        if (session.Plans.Count > 0 && needDomains && rules.KnownDomains.Count > 0)
        {
            RemediationAction block = new()
            {
                Type = RemediationActionType.BlockKnownDomains,
                Target = "hosts",
                DisplayNameText = MessageText.Create("Backend.Core.RemediationBatchPlanner.PrepareAsync.08"),
                Domains = [.. rules.KnownDomains],
                IsKnownMalware = true,
                ConfidenceScore = 100
            };
            if (session.Plans[0].Actions.Count == 64) session.Plans.Insert(0, new() { Actions = [block] });
            else { session.Plans[0].Actions.Add(block); RemediationPlanBuilder.OrderActionsForSafeExecution(session.Plans[0].Actions); }
        }
        foreach (MessageText note in notes.Texts.DistinctBy(n => n.OriginalText).Take(4096)) session.AddNote(note);
        if (notes.Distinct().Skip(4096).Any()) session.AddNote(MessageText.Create("Backend.Core.RemediationBatchPlanner.PrepareAsync.09"));
        HashSet<string> goalKeys = session.Targets.Select(t => t.Key).ToHashSet(StringComparer.OrdinalIgnoreCase);
        HashSet<string> plannedKeys = session.Plans.SelectMany(p => p.Actions).Select(ActionKey).ToHashSet(StringComparer.OrdinalIgnoreCase);
        foreach (var group in verified.Where(RemediationEvidencePolicy.CanRemediate).GroupBy(GoalKey, StringComparer.OrdinalIgnoreCase))
            if (goalKeys.Add(group.Key) && group.SelectMany(RequiredActionKeys).Any(plannedKeys.Contains))
                session.Targets.Add(new()
                {
                    Key = group.Key,
                    Target = group.First().Target,
                    AddedByAssociation = true,
                    FindingIds = group.Select(f => f.Id).ToList(),
                    RequiredActions = group.SelectMany(RequiredActionKeys).Distinct(StringComparer.OrdinalIgnoreCase).ToList()
                });
        // Account for implicit, previewed actions too (for example executable outbound block and hosts block).
        foreach (RemediationAction action in session.Plans.SelectMany(p => p.Actions))
        {
            string key = action.RegistryKey is not null ? $"registry|{action.RegistryHive}|{action.RegistryView}|{action.RegistryKey}|{action.RegistryValueName}"
                : action.ProcessId is not null ? $"process|{action.ProcessId}|{action.Target}"
                : (action.Type == RemediationActionType.RemoveScheduledTask ? "task|" : "target|") + Normalize(action.Target);
            RemediationTargetOutcome? target = session.Targets.FirstOrDefault(t => t.Key.Equals(key, StringComparison.OrdinalIgnoreCase));
            if (target is null) { target = new() { Key = key, Target = action.Target, AddedByAssociation = true }; session.Targets.Add(target); }
            string actionKey = ActionKey(action);
            if (!target.RequiredActions.Contains(actionKey, StringComparer.OrdinalIgnoreCase)) target.RequiredActions.Add(actionKey);
        }
        MapOutcomes(session);
        return session;
    }

    public static ScanOptions? CloneOptions(ScanOptions? options)
    {
        if (options is null) return null;
        System.Text.Json.Nodes.JsonObject json = JsonSerializer.SerializeToNode(options, JsonFile.Options)!.AsObject();
        // Recovery content is a one-time explicit export. A repair follow-up never carries
        // that write authorization into another boot, logon or automatic verification.
        json[nameof(ScanOptions.RecoveryOutputDirectory)] = null;
        return json.Deserialize<ScanOptions>(JsonFile.Options);
    }

    private static Finding[] Coalesce(IEnumerable<Finding> input) => input.GroupBy(f =>
        // Archive findings can share the same outer identity while retaining all inner evidence in the original report.
        JsonSerializer.Serialize(new
        {
            Key = GoalKey(f),
            Hash = RelatedArtifactRelations.FileHash(f),
            RawHash = f.RelatedFilePath is null && f.SuggestedActions.Count == 1 && f.SuggestedActions[0] == SuggestedActionKind.QuarantineFile ? null : f.Sha256,
            f.RelatedFilePath,
            f.RelatedFileSha256,
            f.ConfigurationSnapshot,
            f.ConfigurationKind,
            f.ProcessStartedAtUtc,
            Actions = string.Join(',', f.SuggestedActions.Order())
        }), StringComparer.Ordinal)
        .Select(g => g.OrderByDescending(f => f.Score).ThenByDescending(f => f.IsKnownMalware).First()).ToArray();

    internal static List<Finding[]> PackSelection(Finding[] selected, List<string> notes, List<RemediationPreparationNote>? preparationNotes = null)
    {
        List<Finding[]> batches = []; List<Finding> current = []; long size = 0; int paths = 0;
        foreach (Finding[] rawGroup in DependencyGroups(selected))
        {
            Finding[] group = Coalesce(rawGroup);
            string[] files = group.SelectMany(FileKeys).Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
            long bytes = files.Sum(FileBytes);
            if (group.Length > 256 || files.Length > 64 || bytes > RelatedArtifactScanner.MaximumVerificationBytes)
            {
                foreach (Finding f in rawGroup)
                {
                    MessageText detail = MessageText.Create("Backend.Core.RemediationBatchPlanner.PackSelection.01") + f.Target;
                    if (notes is MessageTextCollection localized) localized.AddText(detail); else notes.Add(detail.OriginalText);
                    if (preparationNotes is { Count: < 4096 }) preparationNotes.Add(new(f.Target, ReasonCodes.ResourceLimit, detail));
                }
                continue;
            }
            if (current.Count > 0 && (current.Count + group.Length > 256 || paths + files.Length > 32 || size + bytes > PreparationBatchBytes))
            { batches.Add(current.ToArray()); current.Clear(); size = 0; paths = 0; }
            current.AddRange(group); size += bytes; paths += files.Length;
        }
        if (current.Count > 0) batches.Add(current.ToArray());
        return batches;
    }

    internal static List<RemediationPlan> PackActions(IEnumerable<List<RemediationAction>> groups)
    {
        List<RemediationPlan> plans = []; RemediationPlan current = new(); long bytes = 0;
        foreach (List<RemediationAction> group in groups)
        {
            if (group.Count > 64) throw MessageExceptions.Create(MessageText.Create("Backend.Core.RemediationBatchPlanner.PackActions.01"), sourceText => new InvalidDataException(sourceText));
            long groupBytes = group.Select(a => a.RelatedFilePath ?? a.Target).Distinct(StringComparer.OrdinalIgnoreCase).Sum(FileBytes);
            if (current.Actions.Count > 0 && (current.Actions.Count + group.Count > 64 || bytes + groupBytes > PreparationBatchBytes))
            { RemediationPlanBuilder.OrderActionsForSafeExecution(current.Actions); plans.Add(current); current = new(); bytes = 0; }
            current.Actions.AddRange(group); bytes += groupBytes;
        }
        if (current.Actions.Count > 0) { RemediationPlanBuilder.OrderActionsForSafeExecution(current.Actions); plans.Add(current); }
        return plans;
    }

    internal static List<Finding[]> DependencyGroups(Finding[] findings)
    {
        int[] parent = Enumerable.Range(0, findings.Length).ToArray();
        int Root(int x) { while (parent[x] != x) { parent[x] = parent[parent[x]]; x = parent[x]; } return x; }
        void Union(int a, int b) { parent[Root(a)] = Root(b); }
        Dictionary<string, int> owners = new(StringComparer.OrdinalIgnoreCase);
        Dictionary<string, int> fileOwners = new(StringComparer.OrdinalIgnoreCase);
        List<(string Path, int Index)> directories = [];
        for (int i = 0; i < findings.Length; i++)
        {
            Finding f = findings[i];
            IEnumerable<string> keys = FileKeys(f).Select(p => "file:" + p).Append("goal:" + GoalKey(f));
            if (f.ProcessId is not null) keys = keys.Append("pid:" + f.ProcessId);
            foreach (string key in keys)
            { if (owners.TryGetValue(key, out int old)) Union(i, old); else owners[key] = i; }
            foreach (string path in FileKeys(f)) fileOwners.TryAdd(path, i);
            if (f.SuggestedActions.Contains(SuggestedActionKind.QuarantineDirectory) && ContentDiscovery.IsLocalSafePath(f.Target))
                directories.Add((Path.GetFullPath(f.Target), i));
        }
        foreach (var directory in directories)
            foreach (var entry in fileOwners)
                if (ContentDiscovery.IsWithin(entry.Key, directory.Path)) Union(directory.Index, entry.Value);
        return Enumerable.Range(0, findings.Length).GroupBy(Root).Select(g => g.Select(i => findings[i]).ToArray()).ToList();
    }

    private static IEnumerable<string> FileKeys(Finding f) => new[] { f.Target, f.RelatedFilePath }
        .OfType<string>().Concat(CommandTargets.Extract(f.ConfigurationSnapshot ?? f.Target))
        .Where(ContentDiscovery.IsLocalSafePath).Select(Path.GetFullPath).Distinct(StringComparer.OrdinalIgnoreCase);
    private static long FileBytes(string path)
    {
        try { return ContentDiscovery.IsLocalSafePath(path) && File.Exists(path) ? new FileInfo(path).Length : 0; }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { return 0; }
    }
    internal static string GoalKey(Finding f) => f.RegistryKey is not null
        ? $"registry|{f.RegistryHive}|{f.RegistryView}|{f.RegistryKey}|{f.RegistryValueName}"
        : f.ProcessId is not null ? $"process|{f.ProcessId}|{f.Target}"
        : (f.SuggestedActions.Contains(SuggestedActionKind.RemoveScheduledTask) ? "task|" : "target|") + Normalize(f.Target);
    private static string Normalize(string target) => ContentDiscovery.IsLocalSafePath(target) ? Path.GetFullPath(target) : target;
    internal static string ActionKey(RemediationAction a) => $"{a.Type}|{Normalize(a.Target)}|{a.ProcessId}|{a.RegistryHive}|{a.RegistryView}|{a.RegistryKey}|{a.RegistryValueName}";
    private static IEnumerable<string> RequiredActionKeys(Finding f)
    {
        foreach (SuggestedActionKind kind in f.SuggestedActions)
            if (kind is not (SuggestedActionKind.None or SuggestedActionKind.ReviewOnly) && Enum.TryParse(kind.ToString(), out RemediationActionType type))
                yield return ActionKey(new()
                {
                    Type = type,
                    Target = f.Target,
                    ProcessId = f.ProcessId,
                    RegistryHive = f.RegistryHive,
                    RegistryView = f.RegistryView,
                    RegistryKey = f.RegistryKey,
                    RegistryValueName = f.RegistryValueName
                });
    }

    internal static void MapOutcomes(RemediationBatchSession session)
    {
        var actions = session.Plans.SelectMany((p, i) => p.Actions.Select(a => (Action: a, Batch: i + 1))).ToArray();
        foreach (RemediationTargetOutcome target in session.Targets)
        {
            foreach (string key in target.RequiredActions)
            {
                var matches = actions.Where(x => ActionKey(x.Action).Equals(key, StringComparison.OrdinalIgnoreCase)).ToArray();
                if (matches.Length == 0) target.MissingActions.Add(key);
                else foreach (var match in matches) { target.ActionIds.Add(match.Action.ActionId); if (!target.Batches.Contains(match.Batch)) target.Batches.Add(match.Batch); }
            }
            RemediationTargetState state = target.ActionIds.Count == 0 ? RemediationTargetState.NotIncluded
                : target.MissingActions.Count > 0 ? RemediationTargetState.PartiallyIncluded : RemediationTargetState.Ready;
            RemediationPreparationNote[] relevant = session.PreparationNotes
                .Where(n => n.Target.Equals(target.Target, StringComparison.OrdinalIgnoreCase))
                .OrderBy(n => n.ReasonCode == ReasonCodes.ActionsNotIncluded ? 0 : 1).Take(5).ToArray();
            string reason = state == RemediationTargetState.Ready ? ReasonCodes.PlanReady
                : relevant.Length > 0 ? relevant[0].ReasonCode
                : File.Exists(target.Target) || Directory.Exists(target.Target) ? ReasonCodes.EvidenceUnavailable : ReasonCodes.TargetUnavailable;
            target.SetState(state, reason, state == RemediationTargetState.Ready || relevant.Length == 0 ? null
                : MessageText.Status("Preparation.Context") + "\n" + MessageText.Join("\n", relevant.Select(n => n.DetailText)));
        }
    }

    public static void RefreshOutcomes(RemediationBatchSession session)
    {
        Dictionary<Guid, RemediationActionResult> results = session.Results.SelectMany(r => r.Actions).GroupBy(a => a.ActionId).ToDictionary(g => g.Key, g => g.Last());
        foreach (RemediationTargetOutcome target in session.Targets.Where(t => t.ActionIds.Count > 0))
        {
            var executed = target.ActionIds.Where(results.ContainsKey).Select(id => results[id]).ToArray();
            bool unknown = session.Results.Any(r => r.Disposition == RemediationRunDisposition.ExecutionUnknown &&
                session.Plans.Any(p => p.PlanId == r.PlanId && p.Actions.Any(a => target.ActionIds.Contains(a.ActionId))));
            if (unknown || executed.Any(a => a.ExecutionStatus == RemediationExecutionStatus.ExecutionUnknown))
                target.SetState(RemediationTargetState.ReviewRequired, ReasonCodes.ExecutionOutcomeUnknown);
            else if (executed.Any(a => !a.Success))
                target.SetState(RemediationTargetState.Failed, ReasonCodes.ActionFailed, MessageText.Join("\n", executed.Where(a => !a.Success).Select(a => a.MessageText)));
            else if (target.MissingActions.Count > 0)
                target.SetState(RemediationTargetState.PartiallyIncluded, ReasonCodes.ActionsNotIncluded, target.ReasonDetailsText);
            else if (executed.Length < target.ActionIds.Count)
                target.SetState(RemediationTargetState.NotExecuted, session.InterruptionReasonCode ?? ReasonCodes.WaitingBatches, session.InterruptionText);
            else if (executed.Any(a => a.VerificationStatus is not (RemediationVerificationStatus.Verified or RemediationVerificationStatus.NoResidual)))
                target.SetState(RemediationTargetState.ReviewRequired, ReasonCodes.VerificationIncomplete, MessageText.Join("\n", executed.Select(a => a.VerificationSummaryText)));
            else target.SetState(RemediationTargetState.Completed, ReasonCodes.ActionsVerified);
        }
    }

    public static async Task ExecuteAsync(RemediationBatchSession session,
        Func<RemediationPlan, Task<RemediationRunResult>> execute, IProgress<ScanProgress>? progress = null)
    {
        if (session.ExecutionStarted) throw MessageExceptions.Create(MessageText.Create("Backend.Core.RemediationBatchPlanner.ExecuteAsync.01"), sourceText => new InvalidOperationException(sourceText));
        session.ExecutionStarted = true;
        RefreshOutcomes(session);
        try
        {
            for (int i = 0; i < session.Plans.Count; i++)
            {
                RemediationPlan plan = session.Plans[i];
                if (plan.ExpiresAtUtc <= DateTimeOffset.UtcNow) { session.InterruptionReasonCode = ReasonCodes.PlanExpired; session.InterruptionText = MessageText.Status(ReasonCodes.PlanExpired); break; }
                progress?.Report(new(MessageText.Create("Backend.Core.RemediationBatchPlanner.ExecuteAsync.02"), MessageText.Create("Backend.Core.RemediationBatchPlanner.ExecuteAsync.03", (i + 1), (session.Plans.Count)), i, session.Plans.Count, StatusPresentation.BatchText(session)));
                RemediationRunResult result = await execute(plan);
                if (result.PlanId != plan.PlanId) throw MessageExceptions.Create(MessageText.Create("Backend.Core.RemediationBatchPlanner.ExecuteAsync.04"), sourceText => new InvalidDataException(sourceText));
                if (result.Actions.Select(a => a.ActionId).Distinct().Count() != result.Actions.Count ||
                    result.Actions.Any(r => !plan.Actions.Any(a => a.ActionId == r.ActionId && r.Type == a.Type && r.Target == a.Target)))
                    throw MessageExceptions.Create(MessageText.Create("Backend.Core.RemediationBatchPlanner.ExecuteAsync.05"), sourceText => new InvalidDataException(sourceText));
                session.Results.Add(result);
                if (!result.Success || result.Actions.Count != plan.Actions.Count ||
                    result.Errors.Count > 0 || result.Actions.Any(a => !a.Success || a.VerificationStatus is not (RemediationVerificationStatus.Verified or RemediationVerificationStatus.NoResidual)) ||
                    result.VerificationStatus is not (RemediationVerificationStatus.Verified or RemediationVerificationStatus.NoResidual))
                { session.InterruptionReasonCode = ReasonCodes.BatchIncomplete; session.InterruptionText = MessageText.Status(ReasonCodes.BatchIncomplete); break; }
                RefreshOutcomes(session);
            }
        }
        catch (Exception ex) { session.InterruptionReasonCode = ReasonCodes.ExecutionInterrupted; session.InterruptionText = MessageText.Status(ReasonCodes.ExecutionInterrupted) + "\n" + MessageExceptions.Describe(ex); }
        finally { session.ExecutionFinished = true; RefreshOutcomes(session); }
    }
}
