using System.IO;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using SteamSentinel.Core.Models;
using SteamSentinel.Core.Remediation;
using SteamSentinel.Core.Reporting;
using SteamSentinel.Core.Utilities;

namespace SteamSentinel.SelfTest;

internal static partial class Program
{
    private static async Task<int> RunPhase3NativeSmokeAsync(string outputDirectory)
    {
        string output = Path.GetFullPath(outputDirectory);
        Directory.CreateDirectory(output);
        string sid = WindowsIdentity.GetCurrent().User?.Value ?? string.Empty;
        List<object> observations = [];
        using CancellationTokenSource budget = new(TimeSpan.FromSeconds(45));
        try
        {
            CaseSessionObservation session = await new WindowsCaseSessionReader().ReadAsync(budget.Token).WaitAsync(TimeSpan.FromSeconds(8), budget.Token);
            Check("第三批原生只读 会话读取保持本用户且字段状态明确", Enum.IsDefined(session.IdentityStatus) &&
                (session.IdentityStatus != DiagnosticReadStatus.Complete || session.UserSid == sid));
            observations.Add(new { Kind = "Session", Observation = session });
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        { observations.Add(new { Kind = "Session", Status = "Unknown", Detail = ex.Message }); }
        try
        {
            BoundProxySnapshot proxy = new WindowsBoundProxySettings().ReadCurrentUserLan();
            Check("第三批原生只读 LAN API返回原始字段与政策守卫", proxy.PolicyGuard is not null && Enum.IsDefined(proxy.PolicyGuard.Status));
            observations.Add(new { Kind = "WinInetCurrentUserLan", Snapshot = proxy });
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        { observations.Add(new { Kind = "WinInetCurrentUserLan", Status = "Unknown", Detail = ex.Message }); }
        string absentDerHash = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes("SteamSentinel inert no-import probe " + Guid.NewGuid())));
        BoundCertificateRepair certificates = new(new WindowsBoundCertificateStore(), () => sid);
        foreach (string location in new[] { "CurrentUser", "LocalMachine" })
            foreach (string name in new[] { "Root", "CA" })
            {
                budget.Token.ThrowIfCancellationRequested();
                BoundCertificateProbe probe = certificates.Probe(new()
                { TargetUserSid = sid, StoreLocation = location, StoreName = name, DerSha256 = absentDerHash });
                Check($"第三批原生只读 {location}/{name}精确DER探针有明确状态", Enum.IsDefined(probe.Status) && probe.Detail.Length > 0);
                observations.Add(new { Kind = "PhysicalCertificate", StoreLocation = location, StoreName = name, probe.Status, probe.Detail });
            }
        string file = Path.Combine(output, "phase3-readonly-native.json");
        await using (FileStream stream = new(file, FileMode.Create, FileAccess.Write, FileShare.None))
            await System.Text.Json.JsonSerializer.SerializeAsync(stream, new
            {
                CompletedAtUtc = DateTimeOffset.UtcNow,
                ReadOnly = true,
                ImportedCertificates = 0,
                DeletedCertificates = 0,
                ProxyWrites = 0,
                Reboots = 0,
                SampleExecutions = 0,
                Observations = observations,
                Scope = "只读原生接口烟测；明确Unknown也保留。没有测试真实存储变更、样本行为、真实重启或实际Steam请求路径。"
            }, ReportPrivacy.ExportOptions);
        Console.WriteLine($"PHASE3_NATIVE_PASS={_passed};FAIL={Failures.Count};Report={file}");
        return Failures.Count == 0 ? 0 : 1;
    }
}
