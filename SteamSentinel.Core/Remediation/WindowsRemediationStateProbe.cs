using System.Diagnostics;
using System.Text;
using System.Text.Json;
using Microsoft.Win32;
using SteamSentinel.Core.Models;
using SteamSentinel.Core.Utilities;

namespace SteamSentinel.Core.Remediation;

/// <summary>Only reads actual state. The injected fixed-script runner must use a trusted system environment.</summary>
public sealed class WindowsRemediationStateProbe(Func<string, CancellationToken, Task<string?>> runReadOnlyScript, Guid? incidentId = null) : IRemediationStateProbe
{
    public const string SecurityStatusScript =
        "$m=$null;$mpError=$false;try{$m=Get-MpComputerStatus -ErrorAction Stop}catch{$mpError=$true};" +
        "$f=@();$fwError=$false;try{$f=@(Get-NetFirewallProfile -PolicyStore ActiveStore -ErrorAction Stop)}catch{$fwError=$true};" +
        "$av=$null;try{$av=@(Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct -ErrorAction Stop|" +
        "Where-Object {$_.displayName -notmatch '^(Microsoft|Windows) Defender'})}catch{};" +
        "[pscustomobject]@{Mode=$m.AMRunningMode;Antivirus=$m.AntivirusEnabled;Realtime=$m.RealTimeProtectionEnabled;" +
        "Behavior=$m.BehaviorMonitorEnabled;RebootRequired=$m.RebootRequired;DefenderError=$mpError;" +
        "FirewallError=$fwError;FirewallCount=$f.Count;FirewallEnabled=@($f|Where-Object {[int]$_.Enabled -eq 1}).Count;" +
        "ThirdPartyKnown=($null -ne $av);ThirdParty=($null -ne $av -and $av.Count -gt 0)}|ConvertTo-Json -Compress";

    public async Task<RemediationVerificationObservation> ObserveAsync(RemediationAction action, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        switch (action.Type)
        {
            case RemediationActionType.QuarantineFile:
            case RemediationActionType.QuarantineDirectory:
                return PathState(action.Target);
            case RemediationActionType.StopProcess:
            case RemediationActionType.StopHostProcess:
                return ProcessState(action);
            case RemediationActionType.RemoveRegistryValue:
                return RegistryState(action);
            case RemediationActionType.RemoveScheduledTask:
                if (!Validation.TryNormalizeScheduledTaskName(action.TaskName ?? action.Target, out string name))
                    return State(RemediationVerificationStatus.Unknown, "计划任务名无效。");
                // Enumerating the parent collection avoids treating every GetTask error as 'missing'.
                string parent = name[..(name.LastIndexOf('\\') + 1)];
                string leaf = name[(name.LastIndexOf('\\') + 1)..];
                return await ScriptStateAsync("$s=New-Object -ComObject Schedule.Service;$s.Connect();$folder=$null;" +
                    "try{$folder=$s.GetFolder(" + Literal(parent) + ")}catch{if($_.Exception.HResult -eq -2147024894 -or $_.Exception.HResult -eq -2147024893){'NoResidual';exit};throw};" +
                    "$tasks=$folder.GetTasks(1);$present=$false;foreach($t in $tasks){if($t.Name -ieq " + Literal(leaf) + "){$present=$true}};" +
                    "if($present){'ResidualDetected'}else{'NoResidual'}", "任务注册状态", cancellationToken);
            case RemediationActionType.DisableService:
                return await ScriptStateAsync("$s=@(Get-CimInstance Win32_Service -ErrorAction Stop|Where-Object {$_.Name -ceq " + Literal(action.Target) + "});" +
                    "if($s.Count -eq 0){'NoResidual'}elseif($s.Count -ne 1){'Unknown'}elseif($s[0].StartMode -ne 'Disabled'){'ResidualDetected'}" +
                    "elseif($s[0].State -eq 'Stopped'){'Verified'}elseif($s[0].State -in @('Running','Stop Pending','Paused')){'PendingReboot'}else{'Unknown'}",
                    "服务必须已禁用且停止，待重启复验表示仍未停止，需重启复扫，并非已清除", cancellationToken);
            case RemediationActionType.RestoreSecurityControls:
                string? security = await runReadOnlyScript(SecurityStatusScript, cancellationToken);
                if (security is null) return State(RemediationVerificationStatus.Unknown, "无法读取安全产品实际状态。");
                using (JsonDocument document = JsonDocument.Parse(security)) return AssessSecurity(document.RootElement);
            case RemediationActionType.RemoveDefenderExclusion:
            case RemediationActionType.RemoveRelatedDefenderExclusion:
                string kind = action.Type == RemediationActionType.RemoveDefenderExclusion ? "ExclusionPath" : action.ConfigurationKind ?? "";
                if (kind is not ("ExclusionPath" or "AttackSurfaceReductionOnlyExclusions")) return State(RemediationVerificationStatus.Unknown, "排除项类型未知。");
                return await ScriptStateAsync("$p=Get-MpPreference -ErrorAction Stop;if(@($p." + kind + "|Where-Object {$_ -ieq " + Literal(action.Target) + "}).Count -gt 0){'ResidualDetected'}else{'NoResidual'}",
                    "Defender 排除项实际状态", cancellationToken);
            case RemediationActionType.DisableRelatedFirewallRule:
                return await ScriptStateAsync("$r=@(Get-NetFirewallRule -PolicyStore ActiveStore -ErrorAction Stop|Where-Object {$_.Name -ceq " + Literal(action.Target) + "});" +
                    "if($r.Count -eq 0){'NoResidual'}elseif(@($r|Where-Object {[int]$_.Enabled -ne 2}).Count -eq 0){'Verified'}else{'ResidualDetected'}",
                    "防火墙活动策略规则实际状态", cancellationToken);
            case RemediationActionType.AddProgramFirewallBlock:
                if (incidentId is null) return State(RemediationVerificationStatus.Unknown, "缺少事件身份，无法验证本次创建的防火墙规则。");
                string ruleName = $"SteamSentinel-{incidentId:N}-{action.ActionId:N}";
                return await ScriptStateAsync("$r=@(Get-NetFirewallRule -PolicyStore ActiveStore -ErrorAction Stop|Where-Object {$_.DisplayName -ceq " + Literal(ruleName) + "});" +
                    "if($r.Count -eq 0){'ResidualDetected';exit};if($r.Count -ne 1){'Unknown';exit};$r=$r[0];" +
                    "$a=@($r|Get-NetFirewallApplicationFilter -ErrorAction Stop);$p=@($r|Get-NetFirewallPortFilter -ErrorAction Stop);" +
                    "$d=@($r|Get-NetFirewallAddressFilter -ErrorAction Stop);$s=@($r|Get-NetFirewallServiceFilter -ErrorAction Stop);" +
                    "$i=@($r|Get-NetFirewallInterfaceFilter -ErrorAction Stop);$t=@($r|Get-NetFirewallInterfaceTypeFilter -ErrorAction Stop);" +
                    "$f=@(Get-NetFirewallProfile -PolicyStore ActiveStore -ErrorAction Stop);" +
                    "if([string]$r.Enabled -eq 'True' -and [string]$r.Action -eq 'Block' -and [string]$r.Direction -eq 'Outbound' -and [string]$r.Profile -eq 'Any' -and " +
                    "$a.Count -eq 1 -and $a[0].Program -ieq " + Literal(action.Target) + " -and " +
                    "$p.Count -eq 1 -and [string]$p[0].Protocol -eq 'Any' -and [string]$p[0].LocalPort -eq 'Any' -and [string]$p[0].RemotePort -eq 'Any' -and " +
                    "$d.Count -eq 1 -and [string]$d[0].LocalAddress -eq 'Any' -and [string]$d[0].RemoteAddress -eq 'Any' -and " +
                    "$s.Count -eq 1 -and $s[0].Service -eq 'Any' -and $i.Count -eq 1 -and [string]$i[0].InterfaceAlias -eq 'Any' -and " +
                    "$t.Count -eq 1 -and [string]$t[0].InterfaceType -eq 'Any' -and $f.Count -eq 3 -and @($f|Where-Object {[int]$_.Enabled -ne 1}).Count -eq 0)" +
                    "{'Verified'}else{'ResidualDetected'}", "本事件的精确程序出站规则及活动防火墙配置，非网络连通性测试", cancellationToken);
            case RemediationActionType.BlockKnownDomains:
                string hosts = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "drivers", "etc", "hosts");
                await using (FileStream stream = new(hosts, FileMode.Open, FileAccess.Read, FileShare.Read, 16 * 1024, FileOptions.Asynchronous))
                {
                    if (stream.Length > 1024 * 1024) return State(RemediationVerificationStatus.Unknown, "hosts 超过 1 MiB 只读验证上限。");
                    using StreamReader reader = new(stream);
                    return AssessHosts(await reader.ReadToEndAsync(cancellationToken), action.Domains);
                }
            default:
                return State(RemediationVerificationStatus.Unknown, "此动作不在只读复验覆盖范围，执行成功不代表已经验证。");
        }
    }

    public static RemediationVerificationObservation AssessSecurity(JsonElement state)
    {
        bool? Bool(string property) => state.TryGetProperty(property, out JsonElement value) ?
            value.ValueKind == JsonValueKind.True ? true : value.ValueKind == JsonValueKind.False ? false : null : null;
        int? Number(string property) => state.TryGetProperty(property, out JsonElement value) && value.TryGetInt32(out int number) ? number : null;
        string? mode = state.TryGetProperty("Mode", out JsonElement modeValue) && modeValue.ValueKind == JsonValueKind.String ? modeValue.GetString() : null;
        if (Bool("FirewallError") == false && Number("FirewallCount") == 3 && Number("FirewallEnabled") is { } enabled && enabled < 3)
            return State(RemediationVerificationStatus.ResidualDetected, "活动策略仍有防火墙配置未开启。");
        if (Bool("DefenderError") != false || Bool("FirewallError") != false || Number("FirewallCount") != 3 ||
            Number("FirewallEnabled") != 3 || Bool("ThirdPartyKnown") != true || Bool("ThirdParty") != false ||
            !string.Equals(mode, "Normal", StringComparison.OrdinalIgnoreCase))
            return State(RemediationVerificationStatus.Unknown, "安全状态不能完整确认：Defender 模式=" + RemediationVerification.Limit(mode, 80) +
                "，可能为第三方杀软/被动模式、策略管理或探测不可用，不推断主防护已恢复。");
        if (Bool("Antivirus") == true && Bool("Realtime") == true && Bool("Behavior") == true)
            return State(RemediationVerificationStatus.Verified, "已读取实际状态：Defender 正常模式、实时/行为防护及三个活动防火墙配置均开启。");
        if (Bool("RebootRequired") == true)
            return State(RemediationVerificationStatus.PendingReboot, "Defender 明确报告需要重启，防护恢复尚未验证，重启后复扫。");
        if (Bool("Antivirus") == false || Bool("Realtime") == false || Bool("Behavior") == false)
            return State(RemediationVerificationStatus.ResidualDetected, "实际 Defender 防护尚未全部开启，不能以设置请求成功替代验证。");
        return State(RemediationVerificationStatus.Unknown, "Defender 返回字段不完整，恢复状态未知。");
    }

    public static RemediationVerificationObservation AssessHosts(string contents, IReadOnlyCollection<string> domains)
    {
        if (domains.Count == 0 || domains.Count > 256 || domains.Any(domain => !Validation.IsSafeDomain(domain)) || contents.Length > 1024 * 1024)
            return State(RemediationVerificationStatus.Unknown, "域名或 hosts 文本超出只读验证范围。");
        Dictionary<string, HashSet<string>> mappings = domains.Distinct(StringComparer.OrdinalIgnoreCase)
            .ToDictionary(domain => domain, _ => new HashSet<string>(StringComparer.OrdinalIgnoreCase), StringComparer.OrdinalIgnoreCase);
        foreach (string line in contents.Split('\n'))
        {
            string[] fields = line.Split('#')[0].Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries);
            if (fields.Length < 2) continue;
            foreach (string domain in fields.Skip(1)) if (mappings.TryGetValue(domain, out HashSet<string>? addresses)) addresses.Add(fields[0]);
        }
        bool blocked = mappings.Values.All(addresses => addresses.SetEquals(["0.0.0.0", "::"]));
        return State(blocked ? RemediationVerificationStatus.Verified : RemediationVerificationStatus.ResidualDetected,
            blocked ? "已验证所有指定域名的精确 hosts 双栈阻断行，不代表 DNS 缓存/应用内解析或实际网络连通性已验证。" : "指定域名的 hosts 阻断行缺失或存在冲突映射。");
    }

    public static RemediationVerificationObservation AssessProcessIdentity(DateTimeOffset? expected, DateTimeOffset? actual, bool exists)
    {
        if (!exists) return State(RemediationVerificationStatus.NoResidual, "原 PID 已不存在，不代表不存在其他新进程。");
        if (expected is null || actual is null) return State(RemediationVerificationStatus.Unknown, "无法确认 PID 启动时间身份。");
        return expected.Value.UtcDateTime == actual.Value.UtcDateTime
            ? State(RemediationVerificationStatus.ResidualDetected, "原 PID 及启动时间对应的进程仍存在。")
            : State(RemediationVerificationStatus.NoResidual, "PID 已复用，原启动时间对应的进程已停止，未操作复用 PID 的新进程。");
    }

    public static RemediationVerificationObservation PathState(string path)
    {
        // File.Exists hides access errors. Only definite file/path-not-found is absence.
        try { _ = File.GetAttributes(path); return State(RemediationVerificationStatus.ResidualDetected, "隔离原路径仍存在（包括类型被替换的目标）。"); }
        catch (FileNotFoundException) { return State(RemediationVerificationStatus.NoResidual, "隔离原路径已不存在。"); }
        catch (DirectoryNotFoundException) { return State(RemediationVerificationStatus.NoResidual, "隔离原路径已不存在。"); }
        catch (Exception ex) { return State(RemediationVerificationStatus.Unknown, "无法读取隔离原路径状态：" + ex.Message); }
    }

    private static RemediationVerificationObservation ProcessState(RemediationAction action)
    {
        if (action.ProcessId is null) return State(RemediationVerificationStatus.Unknown, "PID 缺失。");
        Process process;
        try { process = Process.GetProcessById(action.ProcessId.Value); }
        catch (ArgumentException) { return AssessProcessIdentity(action.ProcessStartedAtUtc, null, false); }
        using (process)
        {
            if (process.HasExited) return AssessProcessIdentity(action.ProcessStartedAtUtc, null, false);
            return AssessProcessIdentity(action.ProcessStartedAtUtc, new DateTimeOffset(process.StartTime.ToUniversalTime()), true);
        }
    }

    private static RemediationVerificationObservation RegistryState(RemediationAction action)
    {
        if (action.RegistryHive is not ("HKCU" or "HKLM") || !Enum.TryParse(action.RegistryView, out RegistryView view))
            return State(RemediationVerificationStatus.Unknown, "Run 注册表定位字段无效。");
        using RegistryKey root = RegistryKey.OpenBaseKey(action.RegistryHive == "HKCU" ? RegistryHive.CurrentUser : RegistryHive.LocalMachine, view);
        using RegistryKey? key = root.OpenSubKey(action.RegistryKey!, writable: false);
        bool present = key?.GetValueNames().Contains(action.RegistryValueName, StringComparer.OrdinalIgnoreCase) == true;
        return State(present ? RemediationVerificationStatus.ResidualDetected : RemediationVerificationStatus.NoResidual,
            present ? "相同 Run/RunOnce 值名称仍存在（即使数据已变化）。" : "指定 Run/RunOnce 值已不存在。");
    }

    private async Task<RemediationVerificationObservation> ScriptStateAsync(string script, string message, CancellationToken token)
    {
        string? output = await runReadOnlyScript(script, token);
        RemediationVerificationStatus status = output is not null && Enum.TryParse(output.Trim(), out RemediationVerificationStatus parsed) &&
            Enum.IsDefined(parsed) ? parsed : RemediationVerificationStatus.Unknown;
        return State(status, message + "：" + RemediationVerification.Label(status));
    }
    private static string Literal(string text) => "([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('" +
        Convert.ToBase64String(Encoding.UTF8.GetBytes(text)) + "')))";
    private static RemediationVerificationObservation State(RemediationVerificationStatus status, string message) =>
        new() { Status = status, Message = RemediationVerification.Limit(message) };
}
