using SteamSentinel.Core.Reporting;
using SteamSentinel.Core.Inspection;
using SteamSentinel.Core.Models;

namespace SteamSentinel.Core.Scanning;

public sealed partial class ContentScanner
{
    private static readonly string[] VPetSignals = ["__pxS", "__pxH", "__pxPoll", "/*px:b*/", "/*px:e*/",
        "SupportMessages", "HelpFrontPage", "ReadProcessMemory", "CryptUnprotectData", "ConnectCache",
        "loginusers.vdf", "WinHttpSendRequest", "upload uid", "[VDF]"];

    private async Task ScanVPetFamilyAsync(Stream input, ContainerContext context, ContainerScanNode node)
    {
        using VPetFamilyResult? result = await VPetFamilyDecoder.InspectAsync(input, node.Sha256!, context.Token,
            context.Budget, Math.Min(context.Options.MaximumEntryBytes, VPetFamilyDecoder.MaximumInputBytes));
        if (result is null) return;
        VPetFamilyEvidence evidence = result.Evidence; node.VPetFamily = evidence;
        ContainerEngineObservation engine = new()
        {
            Engine = "VPetFamily",
            Status = ContainerStageStatus.Pending,
            Offset = 0,
            Length = result.Decoded?.Length ?? 0,
            Detail = evidence.ReasonCode
        };
        node.Engines.Add(engine);
        if (evidence.Status is VPetFamilyStatus.Malformed or VPetFamilyStatus.Unsupported or VPetFamilyStatus.LimitReached)
        {
            engine.Status = evidence.Status == VPetFamilyStatus.LimitReached ? ContainerStageStatus.LimitReached : ContainerStageStatus.Partial;
            ContainerGap(context, node, engine.Status, MessageText.Create("Backend.Core.ContentScanner.VPetFamily.ScanVPetFamilyAsync.01", (evidence.ReasonCode)), evidence.ReasonCode);
            if (evidence.Signals.Contains("VPET-KNOWN-CODE-SECTION"))
                AddVPetReview(context, node, MessageText.Create("Backend.Core.ContentScanner.VPetFamily.ScanVPetFamilyAsync.02", (evidence.ReasonCode)));
            return;
        }
        if (result.Decoded is { } bytes)
        {
            if (bytes.Length > context.Options.MaximumStringScanBytes)
            {
                engine.Status = ContainerStageStatus.LimitReached;
                ContainerGap(context, node, engine.Status, MessageText.Create("Backend.Core.ContentScanner.VPetFamily.ScanVPetFamilyAsync.03"), "VPET-DECODED-STRING-LIMIT");
                return;
            }
            using MemoryStream memory = new(bytes, writable: false);
            using BoundedReadOnlyStream decoded = new(memory, 0, memory.Length, budget: context.Budget);
            var signals = await StreamingStringInspection.ReadAsync(decoded, VPetSignals.Concat(_rules.SuspiciousStrings.Select(rule => rule.Value)),
                _rules.KnownDomains, context.Options.MaximumStringScanBytes, context.Token);
            bool Has(string value) => signals.Raw.Contains(value);
            if (ContentHeuristics.Match(Has, "payload.dll") is { } oldMatch) evidence.Signals.Add(oldMatch.Id);
            if (Has("__pxS") && Has("__pxH") && Has("SupportMessages") && Has("HelpFrontPage") && Has("/*px:b*/") && Has("/*px:e*/"))
                evidence.Signals.Add("VPET-UI-ROUTES-AND-PX-BLOCK");
            if (Has("ReadProcessMemory") && Has("CryptUnprotectData") && Has("ConnectCache") && Has("loginusers.vdf") &&
                Has("WinHttpSendRequest") && (Has("upload uid") || Has("[VDF]")))
                evidence.Signals.Add("VPET-CREDENTIAL-READ-AND-UPLOAD");
            if (_rules.KnownDomains.Any(Has)) evidence.Signals.Add("VPET-KNOWN-DOMAIN");
        }
        engine.Status = ContainerStageStatus.Complete;
        engine.DetailText = MessageText.Create("Backend.Core.ContentScanner.VPetFamily.ScanVPetFamilyAsync.04", (evidence.ReasonCode), (evidence.Role), (evidence.DecoderId)) +
            (evidence.DerivedSha256 is null ? MessageText.Create("Backend.Core.ContentScanner.VPetFamily.ScanVPetFamilyAsync.05") : MessageText.Create("Backend.Core.ContentScanner.VPetFamily.ScanVPetFamilyAsync.06", (evidence.DerivedSha256))) + string.Join(", ", evidence.Signals);
        bool recognized = evidence.Signals.Contains("VPET-KNOWN-CODE-SECTION") || evidence.Signals.Contains("VPET-WRAPPER-THREADED-SIDECAR") ||
            evidence.Signals.Contains("VPET-KNOWN-DOMAIN") && evidence.Signals.Any(s => s is "VPET-UI-ROUTES-AND-PX-BLOCK" or "VPET-CREDENTIAL-READ-AND-UPLOAD");
        if (recognized) AddVPetReview(context, node, engine.DetailText);
    }

    private void AddVPetReview(ContainerContext context, ContainerScanNode node, MessageText detail)
    {
        if (!_rules.KnownHashes.Any(rule => rule.Malware && rule.Sha256.Equals(node.Sha256, StringComparison.OrdinalIgnoreCase)))
            context.Report.Findings.Add(new()
            {
                RuleId = "VPET-FAMILY-STRUCTURE",
                Category = FindingCategory.File,
                Severity = FindingSeverity.High,
                Score = 90,
                TitleText = MessageText.Create("Backend.Core.ContentScanner.VPetFamily.AddVPetReview.01"),
                DescriptionText = MessageText.Create("Backend.Core.ContentScanner.VPetFamily.AddVPetReview.02"),
                Target = node.OriginalTarget,
                Sha256 = node.Sha256,
                TargetSha256 = node.OriginalTargetSha256,
                ContentPath = node.DisplayPath,
                WorkshopId = context.WorkshopId,
                EvidenceText = detail,
                IsKnownMalware = false,
                CanRemediate = false,
                SuggestedActions = [SuggestedActionKind.ReviewOnly]
            });
    }
}
