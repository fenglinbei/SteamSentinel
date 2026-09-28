using SteamSentinel.Core.Reporting;
using System.Text.Json;
using SteamSentinel.Core.Models;
using SteamSentinel.Core.Steam;
using SteamSentinel.Core.Utilities;

namespace SteamSentinel.Core.Scanning;

public sealed record FirewallSnapshot(string Name, string DisplayName, string Program, int Direction, int Action, int Enabled, int Profile);

public static class ProtectionConfiguration
{
    public static string? PluginRoot(SteamLayout layout, string file) => layout.SteamRoots.FirstOrDefault(root =>
        ContentDiscovery.IsWithin(file, Path.Combine(root, "millennium", "plugins", "steamprocess")));

    public static bool IsRelatedExclusion(string steam, string path) =>
        new[] { "wsock32.dll", "millennium", "millennium/plugins/steamprocess", "millennium/lib", "millennium/bin" }
            .Any(relative => string.Equals(Path.GetFullPath(Path.Combine(steam, relative.Replace('/', Path.DirectorySeparatorChar))),
                Path.GetFullPath(path), StringComparison.OrdinalIgnoreCase));

    public static bool IsRelatedFirewall(string steam, FirewallSnapshot item) =>
        item.Name.Length is > 0 and <= 256 && item.DisplayName.StartsWith("steamconn-", StringComparison.OrdinalIgnoreCase) &&
        item.Action == 2 && item.Enabled == 1 && item.Direction is 1 or 2 && item.Profile is >= 0 and <= 2147483647 &&
        new[] { "steam.exe", "bin/cef/cef.win7x64/steamwebhelper.exe", "bin/cef/cef.win7/steamwebhelper.exe" }
            .Any(relative => string.Equals(Path.GetFullPath(Path.Combine(steam, relative.Replace('/', Path.DirectorySeparatorChar))),
                item.Program, StringComparison.OrdinalIgnoreCase));

    public static async Task CollectAsync(SteamLayout layout, ScanReport report, CancellationToken token)
    {
        Finding? binding = report.Findings.FirstOrDefault(f => f.IsKnownMalware && (f.ContentPath is null || f.ContentPath.Equals(f.Target, StringComparison.OrdinalIgnoreCase)) &&
            f.Sha256 is not null && File.Exists(f.Target) && PluginRoot(layout, f.Target) is not null &&
            f.Category == FindingCategory.File);
        if (binding is null) return;
        string steam = PluginRoot(layout, binding.Target)!;
        const string script = "[Console]::OutputEncoding=[Text.Encoding]::UTF8;$p=$null;$e=$null;try{$p=Get-MpPreference -ErrorAction Stop}catch{$e=$_.Exception.Message};" +
            "$f=@();$fe=$null;try{$f=@(Get-NetFirewallRule -PolicyStore PersistentStore -ErrorAction Stop | Where-Object {$_.DisplayName -like 'steamconn-*'} | Select-Object -First 128 | ForEach-Object {$a=$_|Get-NetFirewallApplicationFilter -ErrorAction Stop;" +
            "[pscustomobject]@{Name=$_.Name;DisplayName=$_.DisplayName;Program=$a.Program;Direction=[int]$_.Direction;Action=[int]$_.Action;Enabled=[int]$_.Enabled;Profile=[int]$_.Profile}})}catch{$fe=$_.Exception.Message};" +
            "[pscustomobject]@{ExclusionPath=@($p.ExclusionPath);AttackSurfaceReductionOnlyExclusions=@($p.AttackSurfaceReductionOnlyExclusions);Firewall=$f;DefenderError=$e;FirewallError=$fe}|ConvertTo-Json -Depth 5 -Compress";
        using JsonDocument? result = await PowerShellProbe.RunJsonAsync(script, TimeSpan.FromSeconds(25), token);
        if (result is null) { Partial(report, MessageText.Create("Backend.Core.ProtectionConfiguration.CollectAsync.01")); return; }
        foreach (string field in new[] { "DefenderError", "FirewallError" })
            if (result.RootElement.TryGetProperty(field, out JsonElement error) && error.ValueKind == JsonValueKind.String)
                Partial(report, MessageText.Create("Backend.Core.ProtectionConfiguration.CollectAsync.02") + field);
        foreach (string kind in new[] { "ExclusionPath", "AttackSurfaceReductionOnlyExclusions" })
        {
            if (!result.RootElement.TryGetProperty(kind, out JsonElement entries) || entries.ValueKind != JsonValueKind.Array) continue;
            foreach (JsonElement entry in entries.EnumerateArray().Take(4096))
            {
                string? path = entry.GetString();
                if (path is null || !ContentDiscovery.IsLocalSafePath(path) || !IsRelatedExclusion(steam, path)) continue;
                report.Findings.Add(new Finding
                {
                    RuleId = "CONFIG-PLUGIN-EXCLUSION",
                    Category = FindingCategory.SecurityControl,
                    Severity = FindingSeverity.High,
                    Score = 90,
                    TitleText = MessageText.Create("Backend.Core.ProtectionConfiguration.CollectAsync.03"),
                    DescriptionText = MessageText.Create("Backend.Core.ProtectionConfiguration.CollectAsync.04"),
                    Target = path,
                    ConfigurationKind = kind,
                    ConfigurationSnapshot = path,
                    RelatedFilePath = binding.Target,
                    RelatedFileSha256 = binding.Sha256,
                    EvidenceText = kind + "：" + path,
                    CanRemediate = true,
                    SuggestedActions = [SuggestedActionKind.RemoveRelatedDefenderExclusion]
                });
            }
        }
        if (result.RootElement.TryGetProperty("Firewall", out JsonElement firewall) && firewall.ValueKind == JsonValueKind.Array)
            foreach (JsonElement entry in firewall.EnumerateArray().Take(128))
            {
                FirewallSnapshot? item = entry.Deserialize<FirewallSnapshot>();
                if (item is null || !IsRelatedFirewall(steam, item)) continue;
                report.Findings.Add(new Finding
                {
                    RuleId = "CONFIG-PLUGIN-FIREWALL",
                    Category = FindingCategory.Network,
                    Severity = FindingSeverity.High,
                    Score = 90,
                    TitleText = MessageText.Create("Backend.Core.ProtectionConfiguration.CollectAsync.05"),
                    DescriptionText = MessageText.Create("Backend.Core.ProtectionConfiguration.CollectAsync.06"),
                    Target = item.Name,
                    ConfigurationKind = "Firewall",
                    ConfigurationSnapshot = JsonSerializer.Serialize(item),
                    RelatedFilePath = binding.Target,
                    RelatedFileSha256 = binding.Sha256,
                    EvidenceText = item.DisplayName + "：" + item.Program,
                    CanRemediate = true,
                    SuggestedActions = [SuggestedActionKind.DisableRelatedFirewallRule]
                });
            }
    }

    private static void Partial(ScanReport report, MessageText note) { report.Coverage = ScanCoverage.Partial; report.AddCoverageNote(note); }
}
