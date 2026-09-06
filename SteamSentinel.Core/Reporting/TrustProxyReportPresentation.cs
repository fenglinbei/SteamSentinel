using System.Text;
using SteamSentinel.Core.Inspection;
using SteamSentinel.Core.Models;
using SteamSentinel.Core.Scanning;

namespace SteamSentinel.Core.Reporting;

public static class TrustProxyReportPresentation
{
    public static string StatusLabel(DiagnosticReadStatus status) => status switch
    {
        DiagnosticReadStatus.Complete => "已读取",
        DiagnosticReadStatus.NotPresent => "未配置／来源不存在",
        DiagnosticReadStatus.NotChecked => "未检查",
        DiagnosticReadStatus.AccessDenied => "权限不足",
        DiagnosticReadStatus.LimitReached => "达到检查上限",
        DiagnosticReadStatus.Cancelled => "已取消",
        _ => "读取失败"
    };

    public static string Describe(TrustProxyDiagnosticReport diagnostic)
    {
        StringBuilder text = new();
        text.AppendLine("证书与代理诊断（本机只读）");
        text.AppendLine($"目标用户 SID：{Display(diagnostic.TargetUserSid)}");
        text.AppendLine($"采集时间：{diagnostic.StartedAtUtc:O} 至 {diagnostic.CompletedAtUtc:O}");
        text.AppendLine($"代理来源 {diagnostic.Proxies.Count} 个；证书来源 {diagnostic.CertificateStores.Count} 个；公开证书记录 {diagnostic.Certificates.Count} 条；未完成必要检查 {diagnostic.Checks.Count(TrustProxyCorrelator.IsIncomplete)} 项。");
        text.AppendLine("读取完成只表示取得该范围的证据，不等于配置安全或已清除病毒。本次未修改代理和证书。");
        text.AppendLine();
        text.AppendLine("代理配置来源");
        foreach (ProxyConfigurationObservation proxy in diagnostic.Proxies)
        {
            text.AppendLine($"[{StatusLabel(proxy.Status)}] {Display(proxy.Source)} · {Display(proxy.Scope)} · ID {proxy.Id}");
            text.AppendLine($"  位置：{Display(proxy.Location)}；用户 SID：{Display(proxy.UserSid)}");
            text.AppendLine($"  手动代理：{Boolean(proxy.ProxyEnabled)}；自动检测：{Boolean(proxy.AutoDetect)}");
            text.AppendLine($"  代理服务器：{Display(proxy.ProxyServer)}；绕过列表：{Display(proxy.ProxyBypass)}");
            text.AppendLine($"  PAC 地址：{Display(proxy.AutoConfigUrl)}");
            foreach (DiagnosticConfigurationValue value in proxy.Values)
                text.AppendLine($"  {Display(value.Name)} ({Display(value.Kind)})：{(value.Present ? Display(value.Value) : value.ReadStatus == DiagnosticReadStatus.NotPresent || value.Kind == "Missing" ? "值不存在" : "未读取／存在性未知")}{(value.Redacted ? " [凭据已隐藏]" : "")}");
            text.AppendLine("  说明：" + Display(proxy.Detail));
        }
        text.AppendLine();
        text.AppendLine("证书真实来源与公开证书");
        foreach (CertificateStoreObservation store in diagnostic.CertificateStores)
        {
            text.AppendLine($"[{StatusLabel(store.Status)}] {Display(store.Scope)}/{Display(store.StoreName)} · {Display(store.Provider)} · {store.CertificatesRead} 条 · ID {store.Id}");
            text.AppendLine($"  用户 SID：{Display(store.UserSid)}；{Display(store.Detail)}");
            foreach (CertificateObservation certificate in diagnostic.Certificates.Where(c => c.StoreObservationId == store.Id))
            {
                text.AppendLine("  证书 ID：" + certificate.Id);
                text.AppendLine("    主体：" + Display(certificate.Subject));
                text.AppendLine("    颁发者：" + Display(certificate.Issuer));
                text.AppendLine("    DER SHA-256：" + Display(certificate.DerSha256));
                text.AppendLine("    SHA-1 指纹：" + Display(certificate.Sha1Thumbprint));
                text.AppendLine($"    有效期：{certificate.NotBeforeUtc:O} 至 {certificate.NotAfterUtc:O}；安装时间：未知");
                text.AppendLine($"    CA：{Boolean(certificate.IsCertificateAuthority)}；路径长度约束：{(certificate.HasPathLengthConstraint == true ? certificate.PathLengthConstraint?.ToString() ?? "未知" : certificate.HasPathLengthConstraint == false ? "无" : "未取得")}；KeyUsage：{Display(certificate.KeyUsage)}");
                text.AppendLine($"    EKU：{Display(string.Join(", ", certificate.EnhancedKeyUsages))}；主体与颁发者相同：{certificate.SubjectEqualsIssuer}；自签名密码学校验：{Boolean(certificate.SelfSignatureVerified)}");
                text.AppendLine($"    离线链检查：{StatusLabel(certificate.ChainStatus)}；标志：{Display(string.Join(", ", certificate.ChainFlags))}");
                text.AppendLine("    链范围：" + Display(certificate.ChainScope) + "；" + Display(certificate.ChainDetail));
            }
        }
        text.AppendLine();
        text.AppendLine("检查状态与本次范围");
        foreach (DiagnosticCheck check in diagnostic.Checks)
            text.AppendLine($"[{StatusLabel(check.Status)}] {Display(check.Name)}{(check.Required ? "" : "（本次范围外）")}：{Display(check.Detail)}");
        text.AppendLine();
        text.AppendLine($"已保存 {diagnostic.Relations.Count} 条证书来源或 DER 对应关系，完整 ID 关系及公开 DER 见 JSON。代理与证书同机出现不等于确认拦截或写入关系。");
        return text.ToString();
    }

    private static string Boolean(bool? value) => value.HasValue ? value.Value ? "是" : "否" : "未检查／未取得";
    private static string Display(string? value) => string.IsNullOrEmpty(value) ? "未取得／空值" :
        ScriptSignals.RedactSecrets(value).Replace("\r", " ").Replace("\n", " ").Replace("\t", " ");
}
