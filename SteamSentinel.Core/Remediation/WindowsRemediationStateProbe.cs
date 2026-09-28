using SteamSentinel.Core.Reporting;
using System.Diagnostics;
using System.Text;
using System.Text.Json;
using System.Security.Principal;
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
            case RemediationActionType.RemoveBoundCertificate:
                if (action.BoundCertificate is null) return State(RemediationVerificationStatus.Unknown, MessageText.Create("WindowsRemediationStateProbe.ObserveAsync.01"));
                BoundCertificateProbe certificate = await Task.Run(() => new BoundCertificateRepair(new WindowsBoundCertificateStore(),
                    () => WindowsIdentity.GetCurrent().User?.Value ?? string.Empty).Probe(action.BoundCertificate), cancellationToken);
                return State(certificate.Status switch
                {
                    BoundCertificateProbeStatus.Absent => RemediationVerificationStatus.NoResidual,
                    BoundCertificateProbeStatus.Present => RemediationVerificationStatus.ResidualDetected,
                    _ => RemediationVerificationStatus.Unknown
                }, certificate.DetailText);
            case RemediationActionType.RestoreBoundProxyConfiguration:
                if (action.BoundProxy is null) return State(RemediationVerificationStatus.Unknown, MessageText.Create("WindowsRemediationStateProbe.ObserveAsync.02"));
                return await Task.Run(() => new BoundProxyRepair(new WindowsBoundProxySettings(),
                    () => WindowsIdentity.GetCurrent().User?.Value ?? string.Empty).Probe(action.BoundProxy), cancellationToken);
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
                    return State(RemediationVerificationStatus.Unknown, MessageText.Create("WindowsRemediationStateProbe.ObserveAsync.03"));
                // Enumerating the parent collection avoids treating every GetTask error as 'missing'.
                string parent = name[..(name.LastIndexOf('\\') + 1)];
                string leaf = name[(name.LastIndexOf('\\') + 1)..];
                return await ScriptStateAsync("$s=New-Object -ComObject Schedule.Service;$s.Connect();$folder=$null;" +
                    "try{$folder=$s.GetFolder(" + Literal(parent) + ")}catch{if($_.Exception.HResult -eq -2147024894 -or $_.Exception.HResult -eq -2147024893){'NoResidual';exit};throw};" +
                    "$tasks=$folder.GetTasks(1);$present=$false;foreach($t in $tasks){if($t.Name -ieq " + Literal(leaf) + "){$present=$true}};" +
                    "if($present){'ResidualDetected'}else{'NoResidual'}", MessageText.Create("WindowsRemediationStateProbe.ObserveAsync.04"), cancellationToken);
            case RemediationActionType.DisableService:
                return await ScriptStateAsync("$s=@(Get-CimInstance Win32_Service -ErrorAction Stop|Where-Object {$_.Name -ceq " + Literal(action.Target) + "});" +
                    "if($s.Count -eq 0){'NoResidual'}elseif($s.Count -ne 1){'Unknown'}elseif($s[0].StartMode -ne 'Disabled'){'ResidualDetected'}" +
                    "elseif($s[0].State -eq 'Stopped'){'Verified'}elseif($s[0].State -in @('Running','Stop Pending','Paused')){'PendingReboot'}else{'Unknown'}",
                    MessageText.Create("WindowsRemediationStateProbe.ObserveAsync.05"), cancellationToken);
            case RemediationActionType.RestoreSecurityControls:
                string? security = await runReadOnlyScript(SecurityStatusScript, cancellationToken);
                if (security is null) return State(RemediationVerificationStatus.Unknown, MessageText.Create("WindowsRemediationStateProbe.ObserveAsync.06"));
                using (JsonDocument document = JsonDocument.Parse(security)) return AssessSecurity(document.RootElement);
            case RemediationActionType.RemoveDefenderExclusion:
            case RemediationActionType.RemoveRelatedDefenderExclusion:
                string kind = action.Type == RemediationActionType.RemoveDefenderExclusion ? "ExclusionPath" : action.ConfigurationKind ?? "";
                if (kind is not ("ExclusionPath" or "AttackSurfaceReductionOnlyExclusions")) return State(RemediationVerificationStatus.Unknown, MessageText.Create("WindowsRemediationStateProbe.ObserveAsync.07"));
                return await ScriptStateAsync("$p=Get-MpPreference -ErrorAction Stop;if(@($p." + kind + "|Where-Object {$_ -ieq " + Literal(action.Target) + "}).Count -gt 0){'ResidualDetected'}else{'NoResidual'}",
                    MessageText.Create("WindowsRemediationStateProbe.ObserveAsync.08"), cancellationToken);
            case RemediationActionType.DisableRelatedFirewallRule:
                return await ScriptStateAsync("$r=@(Get-NetFirewallRule -PolicyStore ActiveStore -ErrorAction Stop|Where-Object {$_.Name -ceq " + Literal(action.Target) + "});" +
                    "if($r.Count -eq 0){'NoResidual'}elseif(@($r|Where-Object {[int]$_.Enabled -ne 2}).Count -eq 0){'Verified'}else{'ResidualDetected'}",
                    MessageText.Create("WindowsRemediationStateProbe.ObserveAsync.09"), cancellationToken);
            case RemediationActionType.AddProgramFirewallBlock:
                if (incidentId is null) return State(RemediationVerificationStatus.Unknown, MessageText.Create("WindowsRemediationStateProbe.ObserveAsync.10"));
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
                    "{'Verified'}else{'ResidualDetected'}", MessageText.Create("WindowsRemediationStateProbe.ObserveAsync.11"), cancellationToken);
            case RemediationActionType.BlockKnownDomains:
                string hosts = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "drivers", "etc", "hosts");
                await using (FileStream stream = new(hosts, FileMode.Open, FileAccess.Read, FileShare.Read, 16 * 1024, FileOptions.Asynchronous))
                {
                    if (stream.Length > 1024 * 1024) return State(RemediationVerificationStatus.Unknown, MessageText.Create("WindowsRemediationStateProbe.ObserveAsync.12"));
                    using StreamReader reader = new(stream);
                    return AssessHosts(await reader.ReadToEndAsync(cancellationToken), action.Domains);
                }
            default:
                return State(RemediationVerificationStatus.Unknown, MessageText.Create("WindowsRemediationStateProbe.ObserveAsync.13"));
        }
    }

    public static RemediationVerificationObservation AssessSecurity(JsonElement state)
    {
        bool? Bool(string property) => state.TryGetProperty(property, out JsonElement value) ?
            value.ValueKind == JsonValueKind.True ? true : value.ValueKind == JsonValueKind.False ? false : null : null;
        int? Number(string property) => state.TryGetProperty(property, out JsonElement value) && value.TryGetInt32(out int number) ? number : null;
        string? mode = state.TryGetProperty("Mode", out JsonElement modeValue) && modeValue.ValueKind == JsonValueKind.String ? modeValue.GetString() : null;
        if (Bool("FirewallError") == false && Number("FirewallCount") == 3 && Number("FirewallEnabled") is { } enabled && enabled < 3)
            return State(RemediationVerificationStatus.ResidualDetected, MessageText.Create("WindowsRemediationStateProbe.AssessSecurity.01"));
        if (Bool("DefenderError") != false || Bool("FirewallError") != false || Number("FirewallCount") != 3 ||
            Number("FirewallEnabled") != 3 || Bool("ThirdPartyKnown") != true || Bool("ThirdParty") != false ||
            !string.Equals(mode, "Normal", StringComparison.OrdinalIgnoreCase))
            return State(RemediationVerificationStatus.Unknown, MessageText.Create("Verification.SecurityUnknown", RemediationVerification.Limit(mode, 80)));
        if (Bool("Antivirus") == true && Bool("Realtime") == true && Bool("Behavior") == true)
            return State(RemediationVerificationStatus.Verified, MessageText.Create("WindowsRemediationStateProbe.AssessSecurity.04"));
        if (Bool("RebootRequired") == true)
            return State(RemediationVerificationStatus.PendingReboot, MessageText.Create("WindowsRemediationStateProbe.AssessSecurity.05"));
        if (Bool("Antivirus") == false || Bool("Realtime") == false || Bool("Behavior") == false)
            return State(RemediationVerificationStatus.ResidualDetected, MessageText.Create("WindowsRemediationStateProbe.AssessSecurity.06"));
        return State(RemediationVerificationStatus.Unknown, MessageText.Create("WindowsRemediationStateProbe.AssessSecurity.07"));
    }

    public static RemediationVerificationObservation AssessHosts(string contents, IReadOnlyCollection<string> domains)
    {
        if (domains.Count == 0 || domains.Count > 256 || domains.Any(domain => !Validation.IsSafeDomain(domain)) || contents.Length > 1024 * 1024)
            return State(RemediationVerificationStatus.Unknown, MessageText.Create("WindowsRemediationStateProbe.AssessHosts.01"));
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
            blocked ? MessageText.Create("WindowsRemediationStateProbe.AssessHosts.02") : MessageText.Create("WindowsRemediationStateProbe.AssessHosts.03"));
    }

    public static RemediationVerificationObservation AssessProcessIdentity(DateTimeOffset? expected, DateTimeOffset? actual, bool exists)
    {
        if (!exists) return State(RemediationVerificationStatus.NoResidual, MessageText.Create("WindowsRemediationStateProbe.AssessProcessIdentity.01"));
        if (expected is null || actual is null) return State(RemediationVerificationStatus.Unknown, MessageText.Create("WindowsRemediationStateProbe.AssessProcessIdentity.02"));
        return expected.Value.UtcDateTime == actual.Value.UtcDateTime
            ? State(RemediationVerificationStatus.ResidualDetected, MessageText.Create("WindowsRemediationStateProbe.AssessProcessIdentity.03"))
            : State(RemediationVerificationStatus.NoResidual, MessageText.Create("WindowsRemediationStateProbe.AssessProcessIdentity.04"));
    }

    public static RemediationVerificationObservation PathState(string path)
    {
        // File.Exists hides access errors. Only definite file/path-not-found is absence.
        try { _ = File.GetAttributes(path); return State(RemediationVerificationStatus.ResidualDetected, MessageText.Create("WindowsRemediationStateProbe.PathState.01")); }
        catch (FileNotFoundException) { return State(RemediationVerificationStatus.NoResidual, MessageText.Create("WindowsRemediationStateProbe.PathState.02")); }
        catch (DirectoryNotFoundException) { return State(RemediationVerificationStatus.NoResidual, MessageText.Create("WindowsRemediationStateProbe.PathState.03")); }
        catch (Exception ex) { return State(RemediationVerificationStatus.Unknown, MessageText.Create("WindowsRemediationStateProbe.PathState.04") + MessageExceptions.Describe(ex)); }
    }

    private static RemediationVerificationObservation ProcessState(RemediationAction action)
    {
        if (action.ProcessId is null) return State(RemediationVerificationStatus.Unknown, MessageText.Create("WindowsRemediationStateProbe.ProcessState.01"));
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
            return State(RemediationVerificationStatus.Unknown, MessageText.Create("WindowsRemediationStateProbe.RegistryState.01"));
        using RegistryKey root = RegistryKey.OpenBaseKey(action.RegistryHive == "HKCU" ? RegistryHive.CurrentUser : RegistryHive.LocalMachine, view);
        using RegistryKey? key = root.OpenSubKey(action.RegistryKey!, writable: false);
        bool present = key?.GetValueNames().Contains(action.RegistryValueName, StringComparer.OrdinalIgnoreCase) == true;
        return State(present ? RemediationVerificationStatus.ResidualDetected : RemediationVerificationStatus.NoResidual,
            present ? MessageText.Create("WindowsRemediationStateProbe.RegistryState.02") : MessageText.Create("WindowsRemediationStateProbe.RegistryState.03"));
    }

    private async Task<RemediationVerificationObservation> ScriptStateAsync(string script, MessageText message, CancellationToken token)
    {
        string? output = await runReadOnlyScript(script, token);
        RemediationVerificationStatus status = output is not null && Enum.TryParse(output.Trim(), out RemediationVerificationStatus parsed) &&
            Enum.IsDefined(parsed) ? parsed : RemediationVerificationStatus.Unknown;
        return State(status, MessageText.Create("Common.LabelValue", message, RemediationVerification.LabelText(status)));
    }
    private static string Literal(string text) => "([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('" +
        Convert.ToBase64String(Encoding.UTF8.GetBytes(text)) + "')))";
    private static RemediationVerificationObservation State(RemediationVerificationStatus status, MessageText message) =>
        new() { Status = status, MessageText = RemediationVerification.Limit(message) };
}
