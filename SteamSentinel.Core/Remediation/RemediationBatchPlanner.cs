using System.ComponentModel;
using System.Text.Json;
using SteamSentinel.Core.Inspection;
using SteamSentinel.Core.Models;
using SteamSentinel.Core.Scanning;
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
        Finding[] selected = selection.Where(f => f.CanRemediate).Take(MaximumSelectedFindings + 1).ToArray();
        if (selected.Length > MaximumSelectedFindings) throw new InvalidDataException("所选发现超过 20000 条，没有生成处置计划，请缩小范围。");
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
        List<string> notes = [];
        List<Finding[]> batches = PackSelection(selected, notes);
        for (int index = 0; index < batches.Count; index++)
        {
            token.ThrowIfCancellationRequested();
            progress?.Report(new("核对处置方案", $"第 {index + 1}/{batches.Count} 批", index, batches.Count, "只读核验，尚未开始处置"));
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
                    notes.AddRange(additional.CoverageNotes);
                }
                verified.AddRange(expansion.Findings);
                notes.AddRange(expansion.Notes);
            }
            catch (OperationCanceledException) when (!token.IsCancellationRequested)
            { foreach (Finding f in batches[index]) notes.Add("本批核验超过 3 分钟，未纳入：" + f.Target); }
            catch (Exception ex) when (ex is IOException or InvalidDataException or UnauthorizedAccessException or Win32Exception)
            { foreach (Finding f in batches[index]) notes.Add("本批核验未完成，未纳入：" + f.Target + "，" + ex.Message); }
        }
        token.ThrowIfCancellationRequested();
        // Live discovery may connect initial batches through a shared host/entry. Regroup ALL verified edges before packing actions.
        List<List<RemediationAction>> actionGroups = [];
        bool needDomains = blockDomains;
        foreach (Finding[] group in DependencyGroups(verified.Where(f => f.CanRemediate).ToArray()))
        {
            token.ThrowIfCancellationRequested();
            try
            {
                RemediationPlan plan = await new RemediationPlanBuilder(rules).BuildAsync(Coalesce(group), false, token, allFindings: group);
                needDomains |= plan.Actions.Any(a => a.Type == RemediationActionType.BlockKnownDomains);
                List<RemediationAction> actions = plan.Actions.Where(a => a.Type != RemediationActionType.BlockKnownDomains).ToList();
                if (actions.Count > 0) actionGroups.Add(actions);
            }
            catch (Exception ex) when (ex is IOException or InvalidDataException or UnauthorizedAccessException or Win32Exception)
            { foreach (Finding f in group) notes.Add("关联组未纳入处置，未拆开执行：" + f.Target + "，" + ex.Message); }
        }
        session.Plans.AddRange(PackActions(actionGroups));
        if (session.Plans.Count > 0 && needDomains && rules.KnownDomains.Count > 0)
        {
            RemediationAction block = new()
            {
                Type = RemediationActionType.BlockKnownDomains,
                Target = "hosts",
                DisplayName = "在 hosts 中阻断已知 C2 域名",
                Domains = [.. rules.KnownDomains],
                IsKnownMalware = true,
                ConfidenceScore = 100
            };
            if (session.Plans[0].Actions.Count == 64) session.Plans.Insert(0, new() { Actions = [block] });
            else { session.Plans[0].Actions.Add(block); RemediationPlanBuilder.OrderActionsForSafeExecution(session.Plans[0].Actions); }
        }
        session.Notes.AddRange(notes.Distinct().Take(4096));
        if (notes.Distinct().Skip(4096).Any()) session.Notes.Add("补充说明超过显示上限，未纳入目标仍逐项列出。");
        HashSet<string> goalKeys = session.Targets.Select(t => t.Key).ToHashSet(StringComparer.OrdinalIgnoreCase);
        HashSet<string> plannedKeys = session.Plans.SelectMany(p => p.Actions).Select(ActionKey).ToHashSet(StringComparer.OrdinalIgnoreCase);
        foreach (var group in verified.Where(f => f.CanRemediate).GroupBy(GoalKey, StringComparer.OrdinalIgnoreCase))
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

    public static ScanOptions? CloneOptions(ScanOptions? options) => options is null ? null :
        JsonSerializer.Deserialize<ScanOptions>(JsonSerializer.Serialize(options, JsonFile.Options), JsonFile.Options);

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

    internal static List<Finding[]> PackSelection(Finding[] selected, List<string> notes)
    {
        List<Finding[]> batches = []; List<Finding> current = []; long size = 0; int paths = 0;
        foreach (Finding[] rawGroup in DependencyGroups(selected))
        {
            Finding[] group = Coalesce(rawGroup);
            string[] files = group.SelectMany(FileKeys).Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
            long bytes = files.Sum(FileBytes);
            if (group.Length > 256 || files.Length > 64 || bytes > RelatedArtifactScanner.MaximumVerificationBytes)
            { foreach (Finding f in rawGroup) notes.Add("单个关联组超过本批安全上限，未拆开执行：" + f.Target); continue; }
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
            if (group.Count > 64) throw new InvalidDataException("单个关联组超过 64 个动作，不能拆开执行。");
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
            target.Status = target.ActionIds.Count == 0 ? "未处理" : target.MissingActions.Count > 0 ? "部分纳入" : "待执行";
            target.Reason = target.MissingActions.Count > 0 || target.ActionIds.Count == 0
                ? string.Join("\n", session.Notes.Where(n => n.Contains(target.Target, StringComparison.OrdinalIgnoreCase)).Take(5)) : "已纳入方案，执行前还会独立核验身份。";
            if (string.IsNullOrWhiteSpace(target.Reason)) target.Reason = File.Exists(target.Target) || Directory.Exists(target.Target)
                ? "缺少可执行证据，或关联核验未完成，没有执行这些动作。请进一步检查。" : "目标已不存在、无法读取或未能重新验证，没有执行这些动作。";
        }
    }

    public static void RefreshOutcomes(RemediationBatchSession session)
    {
        Dictionary<Guid, RemediationActionResult> results = session.Results.SelectMany(r => r.Actions).GroupBy(a => a.ActionId).ToDictionary(g => g.Key, g => g.Last());
        foreach (RemediationTargetOutcome target in session.Targets.Where(t => t.ActionIds.Count > 0))
        {
            var executed = target.ActionIds.Where(results.ContainsKey).Select(id => results[id]).ToArray();
            if (executed.Any(a => !a.Success)) { target.Status = "未完成"; target.Reason = string.Join("\n", executed.Where(a => !a.Success).Select(a => a.Message)); }
            else if (target.MissingActions.Count > 0) { target.Status = "部分纳入"; }
            else if (executed.Length < target.ActionIds.Count) { target.Status = "尚未执行"; target.Reason = session.Interruption ?? "等待后续批次，不表示已完成。"; }
            else if (executed.Any(a => a.VerificationStatus is not (RemediationVerificationStatus.Verified or RemediationVerificationStatus.NoResidual)))
            { target.Status = "需复核"; target.Reason = string.Join("\n", executed.Select(a => a.VerificationSummary)); }
            else { target.Status = "已完成"; target.Reason = "所选动作已执行并完成目标核验，不代表整台电脑安全。"; }
        }
    }

    public static async Task ExecuteAsync(RemediationBatchSession session,
        Func<RemediationPlan, Task<RemediationRunResult>> execute, IProgress<ScanProgress>? progress = null)
    {
        if (session.ExecutionStarted) throw new InvalidOperationException("此批次会话已开始执行，请重新扫描，不能重复提交。");
        session.ExecutionStarted = true;
        RefreshOutcomes(session);
        try
        {
            for (int i = 0; i < session.Plans.Count; i++)
            {
                RemediationPlan plan = session.Plans[i];
                if (plan.ExpiresAtUtc <= DateTimeOffset.UtcNow) { session.Interruption = "后续方案已过期，已暂停，需重新扫描并确认，未自动更新身份。"; break; }
                progress?.Report(new("正在分批处置", $"第 {i + 1}/{session.Plans.Count} 批", i, session.Plans.Count, session.Summary));
                RemediationRunResult result = await execute(plan);
                if (result.PlanId != plan.PlanId) throw new InvalidDataException("批次结果与计划不匹配，后续批次已暂停。");
                if (result.Actions.Select(a => a.ActionId).Distinct().Count() != result.Actions.Count ||
                    result.Actions.Any(r => !plan.Actions.Any(a => a.ActionId == r.ActionId && r.Type == a.Type && r.Target == a.Target)))
                    throw new InvalidDataException("批次返回了重复或不匹配的动作，结果不可作为成功依据，后续批次已暂停。");
                session.Results.Add(result);
                if (!result.Success || result.Actions.Count != plan.Actions.Count ||
                    result.Errors.Count > 0 || result.Actions.Any(a => !a.Success || a.VerificationStatus is not (RemediationVerificationStatus.Verified or RemediationVerificationStatus.NoResidual)) ||
                    result.VerificationStatus is not (RemediationVerificationStatus.Verified or RemediationVerificationStatus.NoResidual))
                { session.Interruption = "本批存在失败、残留或尚未确认的结果，后续批次已暂停，请查看逐项结果后重新扫描。"; break; }
                RefreshOutcomes(session);
            }
        }
        catch (Exception ex) { session.Interruption = "处置中断，后续批次未执行：" + ex.Message; }
        finally { session.ExecutionFinished = true; RefreshOutcomes(session); }
    }
}
