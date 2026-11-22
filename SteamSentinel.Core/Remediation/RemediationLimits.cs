namespace SteamSentinel.Core.Remediation;

/// <summary>处置计划、清单与结果的统一安全上限常量。</summary>
public static class RemediationLimits
{
    public const int MaximumActionsPerPlan = 256;
    public const int MaximumDependenciesPerAction = MaximumActionsPerPlan - 1;
    public const int MaximumPlanBytes = 4 * 1024 * 1024;
    public const int MaximumManifestBytes = 4 * 1024 * 1024;
    public const int MaximumResultBytes = 4 * 1024 * 1024;
    public const int MaximumResultErrors = 512;
    public const int MaximumResultDisplayCharacters = 1024 * 1024;
}
