using SteamSentinel.Core.Models;
using SteamSentinel.Core.Utilities;

namespace SteamSentinel.Core.Remediation;

/// <summary>Dependencies are reconstructed by the Broker; client chain labels cannot remove them.</summary>
public static class RemediationDependencies
{
    public static int Phase(RemediationActionType type) => type switch
    {
        RemediationActionType.StopProcess or RemediationActionType.StopHostProcess => 0,
        RemediationActionType.RemoveRegistryValue or RemediationActionType.RemoveScheduledTask or
        RemediationActionType.RemoveDefenderExclusion or RemediationActionType.DisableService or
        RemediationActionType.RemoveRelatedDefenderExclusion or RemediationActionType.DisableRelatedFirewallRule => 1,
        RemediationActionType.AddProgramFirewallBlock or RemediationActionType.BlockKnownDomains => 2,
        RemediationActionType.QuarantineFile or RemediationActionType.QuarantineDirectory => 3,
        _ => 4
    };

    public static IReadOnlyDictionary<Guid, HashSet<Guid>> Build(IReadOnlyList<RemediationAction> actions, bool requireOrder = true)
    {
        if (actions.Count > 64 || actions.Any(a => a is null || a.ActionId == Guid.Empty) ||
            actions.Select(a => a.ActionId).Distinct().Count() != actions.Count)
            throw new InvalidDataException("依赖图动作 ID 无效或超过上限。");
        Dictionary<Guid, int> indices = actions.Select((a, i) => (a.ActionId, i)).ToDictionary(x => x.ActionId, x => x.i);
        Dictionary<Guid, HashSet<Guid>> result = actions.ToDictionary(a => a.ActionId, _ => new HashSet<Guid>());
        foreach (RemediationAction action in actions)
        {
            if (action.ChainId == Guid.Empty || action.DependsOnActionIds is null || action.DependsOnActionIds.Count > 63 ||
                action.DependsOnActionIds.Distinct().Count() != action.DependsOnActionIds.Count)
                throw new InvalidDataException("处置关联链或前置动作列表无效。");
            foreach (Guid dependency in action.DependsOnActionIds)
            {
                if (dependency == action.ActionId || !indices.ContainsKey(dependency))
                    throw new InvalidDataException("前置动作不存在或依赖自身。");
                result[action.ActionId].Add(dependency);
            }
        }
        foreach (List<RemediationAction> group in Groups(actions))
            foreach (RemediationAction action in group)
                foreach (RemediationAction predecessor in group.Where(a => Phase(a.Type) < Phase(action.Type)))
                    result[action.ActionId].Add(predecessor.ActionId);
        HashSet<Guid> active = [], done = [];
        void Visit(Guid id)
        {
            if (done.Contains(id)) return;
            if (!active.Add(id)) throw new InvalidDataException("处置依赖图存在循环。");
            foreach (Guid dependency in result[id])
            {
                if (requireOrder && indices[dependency] >= indices[id])
                    throw new InvalidDataException("前置动作必须在依赖它的动作之前执行。");
                Visit(dependency);
            }
            active.Remove(id); done.Add(id);
        }
        foreach (Guid id in result.Keys) Visit(id);
        return result;
    }

    public static List<List<RemediationAction>> Groups(IReadOnlyList<RemediationAction> actions)
    {
        int[] parents = Enumerable.Range(0, actions.Count).ToArray();
        int Root(int i) { while (parents[i] != i) { parents[i] = parents[parents[i]]; i = parents[i]; } return i; }
        void Join(int a, int b) => parents[Root(a)] = Root(b);
        Dictionary<string, int> keys = new(StringComparer.OrdinalIgnoreCase);
        Dictionary<Guid, int> ids = actions.Select((a, i) => (a.ActionId, i)).ToDictionary(x => x.ActionId, x => x.i);
        for (int i = 0; i < actions.Count; i++)
        {
            RemediationAction action = actions[i];
            foreach (string key in Keys(action))
                if (keys.TryGetValue(key, out int other)) Join(i, other); else keys[key] = i;
            foreach (Guid dependency in action.DependsOnActionIds ?? [])
                if (ids.TryGetValue(dependency, out int other)) Join(i, other);
        }
        // A directory quarantine is dependent on all explicitly planned children, regardless of client labels.
        for (int i = 0; i < actions.Count; i++)
            if (actions[i].Type == RemediationActionType.QuarantineDirectory && LocalPath(actions[i].Target) is { } directory)
                for (int j = 0; j < actions.Count; j++)
                    if (new[] { actions[j].Target, actions[j].RelatedFilePath }.Any(p => LocalPath(p) is { } child &&
                        child.StartsWith(Path.TrimEndingDirectorySeparator(directory) + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase))) Join(i, j);
        return Enumerable.Range(0, actions.Count).GroupBy(Root).Select(g => g.Select(i => actions[i]).ToList()).ToList();
    }

    private static IEnumerable<string> Keys(RemediationAction action)
    {
        if (action.ChainId is { } chain) yield return "chain:" + chain;
        if (action.ProcessId is { } pid) yield return "pid:" + pid + ":" + action.ProcessStartedAtUtc?.ToUniversalTime().ToString("O");
        foreach (string? hash in new[] { action.ExpectedSha256, action.RelatedFileSha256 })
            if (Validation.IsHexSha256(hash)) yield return "sha256:" + hash!.ToUpperInvariant();
        foreach (string? path in new[] { action.Target, action.RelatedFilePath })
            if (LocalPath(path) is { } canonical) yield return "file:" + canonical;
    }

    private static string? LocalPath(string? path)
    {
        try
        {
            return !string.IsNullOrWhiteSpace(path) && Path.IsPathFullyQualified(path) && !path.StartsWith(@"\\", StringComparison.Ordinal)
            ? Path.GetFullPath(path) : null;
        }
        catch (Exception ex) when (ex is ArgumentException or NotSupportedException or PathTooLongException) { return null; }
    }

    public static void AssignAndOrder(List<RemediationAction> actions)
    {
        var dependencies = Build(actions, requireOrder: false);
        foreach (List<RemediationAction> group in Groups(actions).Where(g => g.Count > 1))
        {
            Guid chain = group.Select(a => a.ChainId).FirstOrDefault(id => id is not null) ?? Guid.NewGuid();
            foreach (RemediationAction action in group) action.ChainId = chain;
        }
        foreach (RemediationAction action in actions)
        {
            action.DependsOnActionIds.Clear();
            action.DependsOnActionIds.AddRange(dependencies[action.ActionId].Order());
        }
        List<RemediationAction> pending = actions.OrderBy(a => Phase(a.Type)).ToList(), ordered = [];
        HashSet<Guid> emitted = [];
        while (pending.Count > 0)
        {
            int next = pending.FindIndex(a => dependencies[a.ActionId].All(emitted.Contains));
            if (next < 0) throw new InvalidDataException("处置依赖图存在循环。");
            RemediationAction action = pending[next]; pending.RemoveAt(next); ordered.Add(action); emitted.Add(action.ActionId);
        }
        actions.Clear(); actions.AddRange(ordered);
        _ = Build(actions);
    }

    public static IReadOnlyList<Guid> Unmet(Guid actionId, IReadOnlyDictionary<Guid, HashSet<Guid>> dependencies,
        IEnumerable<RemediationActionResult> results)
    {
        HashSet<Guid> succeeded = results.Where(r => r.Success &&
            (r.ExecutionStatus == RemediationExecutionStatus.NotStarted || r.ExecutionStatus == RemediationExecutionStatus.Succeeded &&
                r.VerificationStatus is RemediationVerificationStatus.Verified or RemediationVerificationStatus.NoResidual)).Select(r => r.ActionId).ToHashSet();
        return dependencies[actionId].Where(id => !succeeded.Contains(id)).Order().ToArray();
    }

    public static IReadOnlyList<QuarantineRecord> RollbackOrder(QuarantineManifest manifest)
    {
        if (manifest.ActionOrder is null || manifest.ActionOrder.Count > 64 ||
            manifest.ActionOrder.Any(id => id == Guid.Empty) || manifest.ActionOrder.Distinct().Count() != manifest.ActionOrder.Count)
            throw new InvalidDataException("受信清单的动作顺序无效。");
        if (manifest.ActionOrder.Count == 0)
        {
            if (manifest.Records.Any(r => r.Type is RemediationActionType.RemoveBoundCertificate or RemediationActionType.RestoreBoundProxyConfiguration))
                throw new InvalidDataException("专用配置清单缺少原动作顺序，不能按预备备份的写入顺序回滚。");
            return manifest.Records.AsEnumerable().Reverse().ToArray();
        }
        Dictionary<Guid, int> order = manifest.ActionOrder.Select((id, index) => (id, index)).ToDictionary(x => x.id, x => x.index);
        if (manifest.Records.Any(r => !order.ContainsKey(r.ActionId))) throw new InvalidDataException("备份记录不属于原计划动作顺序。");
        return manifest.Records.OrderByDescending(r => order[r.ActionId]).ToArray();
    }
}
