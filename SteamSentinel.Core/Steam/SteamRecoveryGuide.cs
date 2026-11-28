using SteamSentinel.Core.Inspection;
using SteamSentinel.Core.Models;
using SteamSentinel.Core.Reporting;

namespace SteamSentinel.Core.Steam;

/// <summary>Steam 主程序 Authenticode 校验记录（仅只读检测）。</summary>
public sealed record SteamClientSignatureCheck(
    string SteamRoot,
    string SteamExePath,
    bool Exists,
    SignatureStatus Status,
    bool IsValveSigner,
    string? SignerSubject);

/// <summary>只读 Steam 客户端恢复建议评估结果。</summary>
public sealed record SteamRecoveryRecommendation(
    bool HasUiTamperingOrRemoval,
    bool AllSteamExecutablesValveSigned,
    IReadOnlyList<SteamClientSignatureCheck> ClientChecks,
    string GuidanceText)
{
    public IReadOnlyList<MessageText> Lines { get; init; } = [];
}

/// <summary>
/// 生成纯只读的 Steam 官方分包还原、正版自检拉起与 SteamSetup.exe 覆盖恢复指引。
/// 本类自身不执行任何下载、进程启动或二进制修改。
/// </summary>
public static class SteamRecoveryGuide
{
    private static readonly string[] UiTamperingRules =
    [
        "STEAM-UI-SEMANTIC-TAMPERING",
        "STEAM-UI-EXTERNAL-SCRIPT",
        "STEAM-UI-LOOPBACK-SCRIPT",
        "STEAM-UI-CSS-SUPPRESSION",
        "STEAMALERT-UI-INJECTION",
        "STEAM-CLIENT-BINARY-MISSING",
        "STEAM-CLIENT-BINARY-TAMPERED"
    ];

    /// <summary>仅对本地已发现的安全 Steam 根目录校验 steam.exe Valve 签名并生成只读恢复指引。</summary>
    public static SteamRecoveryRecommendation Evaluate(
        SteamLayout? layout,
        bool hasUiTamperingOrRemoval,
        Func<string, SignatureResult>? verifier = null)
    {
        Func<string, SignatureResult> verify = verifier ?? AuthenticodeVerifier.Verify;
        List<SteamClientSignatureCheck> checks = [];
        if (layout is not null)
        {
            foreach (string rawRoot in layout.SteamRoots.Where(ContentDiscovery.IsLocalSafePath)
                .Select(Path.GetFullPath).Distinct(StringComparer.OrdinalIgnoreCase))
            {
                string steamExe = Path.Combine(rawRoot, "steam.exe");
                if (!ContentDiscovery.IsLocalSafePath(steamExe)) continue;
                bool exists = File.Exists(steamExe);
                if (!exists)
                {
                    checks.Add(new SteamClientSignatureCheck(rawRoot, steamExe, false, SignatureStatus.Error, false, null));
                    continue;
                }
                SignatureResult result = verify(steamExe);
                bool trustedValve = result.IsValveSigner || AuthenticodeVerifier.IsTrustedValveSigner(result.Status, result.SignerSubject);
                checks.Add(new SteamClientSignatureCheck(rawRoot, steamExe, true, result.Status, trustedValve, result.SignerSubject));
            }
        }

        bool allSigned = checks.Count > 0 && checks.All(item => item.Exists && item.IsValveSigner);
        List<MessageText> lines = [];
        if (hasUiTamperingOrRemoval || !allSigned)
        {
            lines.Add(MessageText.Create("Steam.RecoveryGuide.Header"));
            if (checks.Count == 0)
            {
                lines.Add(MessageText.Create("Steam.RecoveryGuide.NoSteamRoot"));
            }
            else if (allSigned)
            {
                lines.Add(MessageText.Create("Steam.RecoveryGuide.RestartValveSigned", checks.Count));
            }
            else
            {
                int untrustedCount = checks.Count(item => !item.Exists || !item.IsValveSigner);
                lines.Add(MessageText.Create("Steam.RecoveryGuide.UntrustedSteamBinary", untrustedCount));
            }
            lines.Add(MessageText.Create("Steam.RecoveryGuide.OfficialInstaller"));
            lines.Add(MessageText.Create("Steam.RecoveryGuide.GeneralNote"));
        }

        string guidanceText = lines.Count == 0
            ? string.Empty
            : string.Join(Environment.NewLine, lines.Select(line => line.Display));
        return new SteamRecoveryRecommendation(hasUiTamperingOrRemoval, allSigned, checks, guidanceText)
        {
            Lines = lines
        };
    }

    /// <summary>结合批量处置会话和复扫结果生成适用于摘要与结果弹窗的只读恢复建议文本。</summary>
    public static string BuildGuidance(
        SteamLayout? layout,
        RemediationBatchSession? batch,
        ScanReport? followUp = null,
        Func<string, SignatureResult>? verifier = null)
    {
        bool uiInActions = batch?.Plans.SelectMany(plan => plan.Actions).Any(action =>
            action.Type == RemediationActionType.RepairSteamConfiguration &&
            action.ConfigurationKind is SteamConfigurationRepair.UiFile or SteamConfigurationRepair.PackageRestore) == true;
        bool uiInFollowUp = followUp?.Findings.Any(finding =>
            finding.ConfigurationKind is SteamConfigurationRepair.UiFile or SteamConfigurationRepair.PackageRestore ||
            UiTamperingRules.Contains(finding.RuleId, StringComparer.OrdinalIgnoreCase)) == true;
        if (!uiInActions && !uiInFollowUp) return string.Empty;

        SteamRecoveryRecommendation recommendation = Evaluate(layout, true, verifier);
        return string.IsNullOrEmpty(recommendation.GuidanceText)
            ? string.Empty
            : Environment.NewLine + Environment.NewLine + recommendation.GuidanceText;
    }
}
