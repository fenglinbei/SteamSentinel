using SteamSentinel.Core.Models;

namespace SteamSentinel.Core.Reporting;

public sealed record FindingHandlingInfo(FindingDisposition Disposition, string Label, string Reason, string NextStep, bool CanSelect);
public sealed record FindingHandlingCounts(int Actionable, int NeedsReview, int Unsupported, int Blocked, int Informational)
{
    public int AttentionCount => NeedsReview + Unsupported + Blocked;
    public string Summary => $"可处理 {Actionable} 项 · 待确认 {NeedsReview} 项 · 暂不支持 {Unsupported} 项 · 条件未满足 {Blocked} 项 · 普通说明 {Informational} 项";
}

/// <summary>Eligibility only. Never infer execution failure/success from CanRemediate.</summary>
public static class FindingHandlingPresentation
{
    public static bool IsTrustProxyFinding(Finding finding) => finding.RuleId == "NETWORK-PROXY-PRESENT" ||
        finding.SourceKind == "trust-proxy-diagnostics" || finding.DiagnosticObservationIds.Count > 0;

    public static FindingHandlingInfo Get(Finding finding)
    {
        bool boundContainer = finding.ContentPath?.Contains("!/", StringComparison.Ordinal) != true ||
            !string.IsNullOrWhiteSpace(finding.TargetSha256);
        if (finding.CanRemediate && boundContainer)
            return new(FindingDisposition.Actionable, "可选择处理", "已有可核验的处理目标，仍需确认预览。", "核对目标后选择处理。", true);
        if (finding.CanRemediate && !boundContainer)
            return new(FindingDisposition.Blocked, "检查未完成", "外层文件尚未完成哈希读取，暂不能隔离。", "对外层文件执行完整内容检查。", false);
        if (finding.HandlingReason == FindingHandlingReason.UnsupportedAction)
            return new(FindingDisposition.Unsupported, "暂不支持自动处理", finding.HandlingDetails ?? "当前版本没有此问题对应的自动处理能力。", "查看证据并导出诊断记录。", false);
        if (finding.HandlingReason is FindingHandlingReason.IncompleteInspection or FindingHandlingReason.PrerequisiteNotMet)
            return new(FindingDisposition.Blocked, "暂不能处理", finding.HandlingDetails ?? "关键检查或执行条件尚未满足。", "查看具体原因并完成相应检查。", false);
        bool diagnostic = IsTrustProxyFinding(finding);
        if (finding.HandlingReason == FindingHandlingReason.InsufficientEvidence || diagnostic || finding.IsKnownMalware ||
            finding.Category != FindingCategory.Coverage && (finding.Severity >= FindingSeverity.Medium || finding.SuggestedActions.Contains(SuggestedActionKind.ReviewOnly)))
            return new(FindingDisposition.NeedsReview, "需进一步确认", finding.HandlingDetails ?? (diagnostic
                ? "检测到配置线索，但尚不能确认其来源或是否恶意，暂不能自动处理。"
                : "尚无足够依据执行处置，需要进一步核对。"), diagnostic
                ? "检查代理与证书，或导出诊断记录。" : "对适用目标进一步检查，或导出诊断记录。", false);
        return new(FindingDisposition.Informational, "信息提示", "此项为普通说明，没有要求执行处理。", "可查看详情。", false);
    }

    public static FindingHandlingCounts Count(IEnumerable<Finding> findings)
    {
        FindingDisposition[] states = findings.Where(f => f.Category != FindingCategory.Coverage).Select(f => Get(f).Disposition).ToArray();
        return new(states.Count(s => s == FindingDisposition.Actionable), states.Count(s => s == FindingDisposition.NeedsReview),
            states.Count(s => s == FindingDisposition.Unsupported), states.Count(s => s == FindingDisposition.Blocked),
            states.Count(s => s == FindingDisposition.Informational));
    }
}
