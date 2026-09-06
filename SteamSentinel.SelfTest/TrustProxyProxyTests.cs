using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.Win32;
using SteamSentinel.Core.Models;
using SteamSentinel.Core.Reporting;
using SteamSentinel.Core.Scanning;

namespace SteamSentinel.SelfTest;

internal static partial class Program
{
    private static void TestTrustProxyProxy()
    {
        const string sid = "S-1-5-21-100-200-300-1001";
        static TrustProxyDiagnosticReport Report() => new() { TargetUserSid = sid };
        static ProxySourceRead Values(params ProxyValueRead[] values) => new(DiagnosticReadStatus.Complete, "fixture", values);
        static ProxyValueRead Value(string name, string kind, string? value) => new(name, kind, value, DiagnosticReadStatus.Complete);

        ProxyTestReader reader = new(sid)
        {
            UserSettings = Values(Value("ProxyEnable", "REG_DWORD", "0"), Value("ProxyServer", "REG_SZ", ""),
                Value("AutoConfigURL", "REG_SZ", "http://pac.example.invalid/proxy.pac"))
        };
        TrustProxyDiagnosticReport report = Report();
        new ProxyConfigurationScanner(reader).Collect(report, new DiagnosticScanLimits());
        ProxyConfigurationObservation user = report.Proxies.Single(p => p.Source == "WinINetRegistry" && p.Scope == "CurrentUser");
        Check("代理诊断 ProxyEnable=0 仍保留 PAC", user.Status == DiagnosticReadStatus.Complete && user.ProxyEnabled == false &&
            user.AutoConfigUrl == "http://pac.example.invalid/proxy.pac" && user.ProxyServer == "");
        Check("代理诊断注册表显式绑定目标 SID", reader.UserPaths.Count == 3 && reader.UserPaths.All(p => p.StartsWith(sid + "\\", StringComparison.Ordinal)) && user.UserSid == sid);
        Check("代理诊断独立覆盖八个来源", report.Proxies.Count == 8 && reader.MachineReads == 3 && reader.WinHttpReads == 1 && reader.WinInetReads == 1 &&
            report.Proxies.Any(p => p.Source == "WinINetPolicyRegistry" && p.Scope == "LocalMachine") &&
            report.Proxies.All(p => p.Detail.Contains("不代表 Steam", StringComparison.Ordinal)));
        Check("代理诊断原值有稳定摘要", user.Values.Single(v => v.Name == "AutoConfigURL") is { Redacted: false, Sha256: not null } pac &&
            pac.Sha256 == Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes("http://pac.example.invalid/proxy.pac"))).ToLowerInvariant());

        reader = new(sid)
        {
            UserSettings = Values(Value("ProxyEnable", "REG_DWORD", "0")),
            MachinePolicy = Values(Value("ProxySettingsPerUser", "REG_DWORD", "0")),
            WinHttpConfiguration = Values(Value("AccessType", "DWORD", "3"), Value("ProxyServer", "LPWSTR", "machine-proxy.example.invalid:8080")),
            WinInetConfiguration = Values(Value("AutoDetect", "BOOL", "-1"), Value("AutoConfigURL", "LPWSTR", "http://connection.example.invalid/proxy.pac"))
        };
        report = Report();
        new ProxyConfigurationScanner(reader).Collect(report, new DiagnosticScanLimits());
        Check("代理诊断机器策略保留原值且不覆盖其他来源", report.Proxies.Single(p => p.Source == "WinINetPolicyRegistry" && p.Scope == "LocalMachine")
            .Values.Single(v => v.Name == "ProxySettingsPerUser") is { Kind: "REG_DWORD", Value: "0" } && report.Proxies[0].ProxyEnabled == false);
        Check("代理诊断 WinHTTP 默认与 WinINet 当前连接分开记录", report.Proxies.Single(p => p.Source == "WinHttpDefault").ProxyEnabled == true &&
            report.Proxies.Single(p => p.Source == "WinINetCurrentConnection") is { AutoDetect: true, ProxyEnabled: null, AutoConfigUrl: "http://connection.example.invalid/proxy.pac" });

        reader = new(sid)
        {
            UserSettings = Values(new ProxyValueRead("ProxyEnable", "Missing", null, DiagnosticReadStatus.NotPresent, false),
                new ProxyValueRead("AutoConfigURL", "Missing", null, DiagnosticReadStatus.NotPresent, false))
        };
        report = Report();
        new ProxyConfigurationScanner(reader).Collect(report, new DiagnosticScanLimits());
        user = report.Proxies[0];
        Check("代理诊断缺值不等同禁用", user.Status == DiagnosticReadStatus.Complete && user.ProxyEnabled is null && user.AutoConfigUrl is null &&
            user.Values.All(v => !v.Present && v.Kind == "Missing") && user.Detail.Contains("NotPresent", StringComparison.Ordinal));
        Check("代理诊断不存在的来源单独标记", report.Proxies.Any(p => p.Source == "WinINetPolicyRegistry" && p.Status == DiagnosticReadStatus.NotPresent));

        reader = new(sid) { UserSettings = Values(Value("ProxyEnable", "REG_SZ", "0"), Value("AutoConfigURL", "REG_DWORD", "42")) };
        report = Report();
        new ProxyConfigurationScanner(reader).Collect(report, new DiagnosticScanLimits());
        user = report.Proxies[0];
        Check("代理诊断错误类型不强制转换", user.Status == DiagnosticReadStatus.Failed && user.ProxyEnabled is null && user.AutoConfigUrl is null &&
            user.Values.Single(v => v.Name == "ProxyEnable") is { Kind: "REG_SZ", Value: "0", Present: true });

        reader = new(sid) { DenyUserSettings = true };
        report = Report();
        new ProxyConfigurationScanner(reader).Collect(report, new DiagnosticScanLimits());
        Check("代理诊断权限失败不静默吞掉", report.Proxies[0].Status == DiagnosticReadStatus.AccessDenied &&
            report.Checks.Any(c => c.Name == "Proxy.WinINetRegistry.CurrentUser" && c.Status == DiagnosticReadStatus.AccessDenied) && reader.MachineReads == 3);

        reader = new("S-1-5-21-100-200-300-1002");
        report = Report();
        new ProxyConfigurationScanner(reader).Collect(report, new DiagnosticScanLimits());
        Check("代理诊断 SID 不符拒绝所有用户来源", reader.UserPaths.Count == 0 && reader.WinInetReads == 0 && reader.MachineReads == 3 && reader.WinHttpReads == 1 &&
            report.Proxies.Where(p => p.Scope == "CurrentUser").All(p => p.Status == DiagnosticReadStatus.NotChecked) &&
            report.Checks.Single(c => c.Name == "Proxy.TargetUserIdentity").Status == DiagnosticReadStatus.NotChecked);

        reader = new(sid) { UserSettings = Values(Value("AutoConfigURL", "REG_SZ", new string('x', 65))) };
        report = Report();
        new ProxyConfigurationScanner(reader).Collect(report, new DiagnosticScanLimits { MaximumProxyValueCharacters = 64 });
        Check("代理诊断字符预算不保留截断凭据", report.Proxies[0].Status == DiagnosticReadStatus.LimitReached && report.Proxies[0].AutoConfigUrl is null &&
            report.Proxies[0].Values.Single().Value is null && report.Proxies[0].Values.Single().Sha256 is null);

        reader = new(sid);
        report = Report();
        new ProxyConfigurationScanner(reader).Collect(report, new DiagnosticScanLimits { MaximumDuration = TimeSpan.Zero });
        Check("代理诊断耗时预算停止读取并覆盖缺口", reader.TotalReads == 0 && report.Proxies.Count == 8 && report.Proxies.All(p => p.Status == DiagnosticReadStatus.LimitReached));
        using (CancellationTokenSource cancellation = new())
        {
            cancellation.Cancel();
            reader = new(sid);
            report = Report();
            new ProxyConfigurationScanner(reader).Collect(report, new DiagnosticScanLimits(), cancellation.Token);
            Check("代理诊断预取消不访问配置", reader.TotalReads == 0 && report.Proxies.All(p => p.Status == DiagnosticReadStatus.Cancelled));
        }
        using (CancellationTokenSource cancellation = new())
        {
            reader = new(sid) { OnUserSettingsRead = cancellation.Cancel };
            report = Report();
            new ProxyConfigurationScanner(reader).Collect(report, new DiagnosticScanLimits(), cancellation.Token);
            Check("代理诊断同步读取返回后取消阻止后续来源", reader.TotalReads == 1 && report.Proxies.All(p => p.Status == DiagnosticReadStatus.Cancelled));
        }

        const string secretUrl = "http://alice:super-secret@pac.example.invalid/proxy.pac?token=fixture-token";
        reader = new(sid)
        {
            UserSettings = Values(Value("AutoConfigURL", "REG_SZ", secretUrl),
                Value("ProxyServer", "REG_SZ", "http=alice:server-secret@proxy.example.invalid:8080;https=other.example.invalid:8443"))
        };
        report = Report();
        new ProxyConfigurationScanner(reader).Collect(report, new DiagnosticScanLimits());
        string plainJson = JsonSerializer.Serialize(report);
        string exportedJson = JsonSerializer.Serialize(report, ReportPrivacy.ExportOptions);
        DiagnosticConfigurationValue sanitized = report.Proxies[0].Values.Single(v => v.Name == "AutoConfigURL");
        Check("代理诊断报告边界已隐藏 URL 和代理列表凭据", !plainJson.Contains("alice", StringComparison.Ordinal) && !plainJson.Contains("super-secret", StringComparison.Ordinal) &&
            !plainJson.Contains("fixture-token", StringComparison.Ordinal) && !plainJson.Contains("server-secret", StringComparison.Ordinal) &&
            !exportedJson.Contains("super-secret", StringComparison.Ordinal) && sanitized.Redacted && sanitized.Value!.Contains("pac.example.invalid", StringComparison.Ordinal));
        Check("代理诊断脱敏摘要对应原值", sanitized.Sha256 == Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(secretUrl))).ToLowerInvariant());

        ProxyValueRead odd = WindowsProxyConfigurationReader.DecodeRegistryValue("ProxyServer", 1, [65, 0, 66], 64);
        ProxyValueRead surrogate = WindowsProxyConfigurationReader.DecodeRegistryValue("ProxyServer", 1, [0, 216, 0, 0], 64);
        ProxyValueRead dword = WindowsProxyConfigurationReader.DecodeRegistryValue("ProxyEnable", 4, [0, 0, 0, 0], 64);
        ProxyValueRead expand = WindowsProxyConfigurationReader.DecodeRegistryValue("AutoConfigURL", 2, Encoding.Unicode.GetBytes("%PROXY%/proxy.pac\0"), 64);
        Check("代理诊断原始注册表解码检查长度与类型", odd.Status == DiagnosticReadStatus.Failed && surrogate.Status == DiagnosticReadStatus.Failed && dword is { Kind: "REG_DWORD", Value: "0" } &&
            expand is { Kind: "REG_EXPAND_SZ", Value: "%PROXY%/proxy.pac" });
    }

    private sealed class ProxyTestReader(string sid) : IProxyConfigurationReader
    {
        public ProxySourceRead UserSettings { get; init; } = new(DiagnosticReadStatus.Complete, "fixture", []);
        public ProxySourceRead? MachinePolicy { get; init; }
        public ProxySourceRead? WinHttpConfiguration { get; init; }
        public ProxySourceRead? WinInetConfiguration { get; init; }
        public Action? OnUserSettingsRead { get; init; }
        public bool DenyUserSettings { get; init; }
        public List<string> UserPaths { get; } = [];
        public int MachineReads { get; private set; }
        public int WinHttpReads { get; private set; }
        public int WinInetReads { get; private set; }
        public int TotalReads => UserPaths.Count + MachineReads + WinHttpReads + WinInetReads;
        public string? ReadCurrentUserSid() => sid;
        public ProxySourceRead ReadRegistry(RegistryHive hive, RegistryView view, string subkey, IReadOnlyList<string> names,
            int maximumCharacters, CancellationToken token)
        {
            token.ThrowIfCancellationRequested();
            if (hive == RegistryHive.Users) UserPaths.Add(subkey); else MachineReads++;
            if (hive == RegistryHive.Users && !subkey.Contains("Policies", StringComparison.Ordinal))
            {
                if (DenyUserSettings) throw new UnauthorizedAccessException("fixture secret must not escape");
                OnUserSettingsRead?.Invoke();
                return UserSettings;
            }
            if (hive == RegistryHive.LocalMachine && MachinePolicy is not null &&
                subkey.Contains(@"Policies\Microsoft\Windows", StringComparison.Ordinal)) return MachinePolicy;
            return new ProxySourceRead(DiagnosticReadStatus.NotPresent, "fixture key missing",
                names.Select(n => new ProxyValueRead(n, "Missing", null, DiagnosticReadStatus.NotPresent, false)).ToArray());
        }
        public ProxySourceRead ReadWinHttpDefault(int maximumCharacters, CancellationToken token)
        {
            WinHttpReads++;
            return WinHttpConfiguration ?? new ProxySourceRead(DiagnosticReadStatus.Complete, "fixture default", [new("AccessType", "DWORD", "1", DiagnosticReadStatus.Complete)]);
        }
        public ProxySourceRead ReadWinInetCurrentUser(int maximumCharacters, CancellationToken token)
        {
            WinInetReads++;
            return WinInetConfiguration ?? new ProxySourceRead(DiagnosticReadStatus.Complete, "fixture active connection", [new("AutoDetect", "BOOL", "0", DiagnosticReadStatus.Complete)]);
        }
    }
}
