namespace SteamSentinel.Core.Models;

public sealed class RemediationBatchSession
{
    public Guid SessionId { get; init; } = Guid.NewGuid();
    public int SelectedFindingCount { get; init; }
    public List<RemediationTargetOutcome> Targets { get; init; } = [];
    public List<RemediationPlan> Plans { get; init; } = [];
    public List<RemediationRunResult> Results { get; init; } = [];
    public List<string> Notes { get; init; } = [];
    public string? Interruption { get; set; }
    public bool ExecutionStarted { get; set; }
    public bool ExecutionFinished { get; set; }
    public ScanOptions? OriginalContentSettings { get; init; }
    public int PlannedCount => Targets.Count(t => t.ActionIds.Count > 0);
    public int SelectedTargetCount => Targets.Count(t => !t.AddedByAssociation);
    private string TargetSummary => $"已选 {SelectedTargetCount} 个目标" + (Targets.Count > SelectedTargetCount ? $"，关联新增 {Targets.Count - SelectedTargetCount} 个" : "");
    public string Summary => !ExecutionStarted
        ? TargetSummary + $"，本次拟处理 {PlannedCount} 个，{Targets.Count(t => t.MissingActions.Count > 0 || t.ActionIds.Count == 0)} 个存在未纳入动作，共 {Plans.Count} 批。"
        : TargetSummary + $"，完成 {Targets.Count(t => t.Status == "已完成")} 个，需复核 {Targets.Count(t => t.Status == "需复核")} 个，失败 {Targets.Count(t => t.Status == "未完成")} 个，未全部处理 {Targets.Count(t => t.Status is "未处理" or "部分纳入" or "尚未执行")} 个。";
}

public sealed class RemediationTargetOutcome
{
    public string Key { get; init; } = string.Empty;
    public string Target { get; init; } = string.Empty;
    public bool AddedByAssociation { get; init; }
    public List<string> FindingIds { get; init; } = [];
    public List<string> RequiredActions { get; init; } = [];
    public List<string> MissingActions { get; init; } = [];
    public List<Guid> ActionIds { get; init; } = [];
    public List<int> Batches { get; init; } = [];
    public string Status { get; set; } = "待核验";
    public string Reason { get; set; } = string.Empty;
}
