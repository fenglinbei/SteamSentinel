using System.Security.Principal;
using SteamSentinel.Core.Models;

namespace SteamSentinel.Core.Scanning;

public sealed class TrustProxyDiagnosticScanner
{
    private readonly Action<TrustProxyDiagnosticReport, DiagnosticScanLimits, CancellationToken> _proxies;
    private readonly Action<TrustProxyDiagnosticReport, DiagnosticScanLimits, CancellationToken> _certificates;
    private readonly Func<string> _userSid;

    public TrustProxyDiagnosticScanner() : this(new ProxyConfigurationScanner().Collect, new CertificateStoreScanner().Collect,
        CurrentUserSid)
    { }

    private static string CurrentUserSid()
    {
        using WindowsIdentity identity = WindowsIdentity.GetCurrent();
        return identity.User?.Value ?? string.Empty;
    }

    internal TrustProxyDiagnosticScanner(Action<TrustProxyDiagnosticReport, DiagnosticScanLimits, CancellationToken> proxies,
        Action<TrustProxyDiagnosticReport, DiagnosticScanLimits, CancellationToken> certificates, Func<string> userSid)
    { _proxies = proxies; _certificates = certificates; _userSid = userSid; }

    public void Collect(ScanReport report, IProgress<ScanProgress>? progress = null,
        CancellationToken cancellationToken = default, DiagnosticScanLimits? limits = null)
    {
        limits ??= new();
        string sid;
        try { sid = _userSid(); }
        catch (Exception ex) when (ex is System.Security.SecurityException or UnauthorizedAccessException or PlatformNotSupportedException)
        { sid = string.Empty; }
        TrustProxyDiagnosticReport diagnostic = new() { TargetUserSid = sid };
        report.ScopeNotes.Add("证书与代理诊断：只读采集当前 Windows 用户、机器和策略代理配置及 Root/CA 证书的真实来源；不修改配置或信任库。");
        report.ScopeNotes.Add("证书与代理诊断：离线证书链限于采集快照，不做联网撤销检查；不下载或执行 PAC，不进行网站 TLS 探测，不定位写入者。");
        try
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (string.IsNullOrWhiteSpace(sid))
                diagnostic.Checks.Add(new() { Name = "扫描用户身份", Status = DiagnosticReadStatus.Failed, Detail = "无法取得目标用户 SID，未执行代理或证书采集。" });
            else
            {
                progress?.Report(new("证书与代理诊断", "代理配置", 0, 2, "只读取得配置来源与检查状态"));
                RunCollector(_proxies, "代理配置采集", diagnostic, limits, cancellationToken);
                cancellationToken.ThrowIfCancellationRequested();
                progress?.Report(new("证书与代理诊断", "证书真实存储", 1, 2, "只读取得公开证书与离线链状态"));
                RunCollector(_certificates, "证书存储采集", diagnostic, limits, cancellationToken);
            }
        }
        catch (OperationCanceledException)
        { diagnostic.Checks.Add(new() { Name = "本机诊断", Status = DiagnosticReadStatus.Cancelled, Detail = "诊断已取消，已读取的观察结果保留，其他内容未完成检查。" }); }
        diagnostic.Checks.AddRange([
            new() { Name = "PAC 正文", Status = DiagnosticReadStatus.NotChecked, Required = false, Detail = "本次仅读取 PAC 配置地址，未下载、分析或执行脚本正文。" },
            new() { Name = "实际请求路径与 TLS 连接链", Status = DiagnosticReadStatus.NotChecked, Required = false, Detail = "本次未发起站点连接，不能据配置或离线链判断 Steam 实际采用的代理和证书。" },
            new() { Name = "证书安装时间与配置写入者", Status = DiagnosticReadStatus.NotChecked, Required = false, Detail = "证书有效期不是安装时间；本次未定位安装者或代理写入进程。" }
        ]);
        diagnostic.CompletedAtUtc = DateTimeOffset.UtcNow;
        TrustProxyCorrelator.Apply(report, diagnostic);
    }

    private static void RunCollector(Action<TrustProxyDiagnosticReport, DiagnosticScanLimits, CancellationToken> collector,
        string name, TrustProxyDiagnosticReport diagnostic, DiagnosticScanLimits limits, CancellationToken token)
    {
        try { collector(diagnostic, limits, token); }
        catch (OperationCanceledException) { throw; }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            diagnostic.Checks.Add(new()
            {
                Name = name,
                Status = ex is UnauthorizedAccessException or System.Security.SecurityException
            ? DiagnosticReadStatus.AccessDenied : DiagnosticReadStatus.Failed,
                Detail = name + "失败：" + ex.Message
            });
        }
    }
}
