using System.Text;
using SteamSentinel.Core.Models;
using SteamSentinel.Core.Utilities;

namespace SteamSentinel.Core.Reporting;

public static class ReportExporter
{
    public static string CoverageLabel(ScanCoverage value, System.Globalization.CultureInfo culture)
    {
        using IDisposable scope = DisplayText.UseCulture(culture);
        return CoverageLabel(value);
    }

    public static string CategoryLabel(FindingCategory value, System.Globalization.CultureInfo culture)
    {
        using IDisposable scope = DisplayText.UseCulture(culture);
        return CategoryLabel(value);
    }

    public static string ActionLabel(RemediationActionType value, System.Globalization.CultureInfo culture)
    {
        using IDisposable scope = DisplayText.UseCulture(culture);
        return ActionLabel(value);
    }

    public static string SeverityLabel(FindingSeverity value, System.Globalization.CultureInfo culture)
    {
        using IDisposable scope = DisplayText.UseCulture(culture);
        return SeverityLabel(value);
    }
    public static async Task ExportMarkdownAsync(ScanReport report, string path, System.Globalization.CultureInfo culture, CancellationToken cancellationToken = default)
    {
        using IDisposable scope = DisplayText.UseCulture(culture);
        await ExportMarkdownAsync(report, path, cancellationToken).ConfigureAwait(false);
    }

    public static Task ExportJsonAsync(ScanReport report, string path, CancellationToken cancellationToken = default) =>
        JsonFile.WriteAtomicAsync(path, report, cancellationToken, ReportPrivacy.ExportOptions);

    public static async Task ExportMarkdownAsync(ScanReport report, string path, CancellationToken cancellationToken = default)
    {
        StringBuilder text = new();
        text.AppendLine(DisplayText.Format("Report.ExportMarkdownAsync.01", DisplayText.Get("Product.DisplayName")));
        text.AppendLine();
        text.AppendLine(DisplayText.Get("Report.OriginalTextNotice"));
        text.AppendLine();
        text.AppendLine(DisplayText.Format("Report.ExportMarkdownAsync.02", (report.ProductVersion)));
        text.AppendLine(DisplayText.Format("Report.ExportMarkdownAsync.03", (Escape(report.BuildIdentity))));
        text.AppendLine(DisplayText.Format("Report.ExportMarkdownAsync.04", (report.RuleSetVersion)));
        text.AppendLine(DisplayText.Format("Report.ExportMarkdownAsync.05", (report.ScanId)));
        text.AppendLine(DisplayText.Format("Report.ExportMarkdownAsync.06", (report.StartedAtUtc.ToLocalTime())));
        text.AppendLine(DisplayText.Format("Report.ExportMarkdownAsync.07", (report.CompletedAtUtc?.ToLocalTime())));
        text.AppendLine(DisplayText.Format("Report.ExportMarkdownAsync.08", (CoverageLabel(report.Coverage))));
        text.AppendLine(DisplayText.Format("Report.ExportMarkdownAsync.09", (SeverityLabel(report.HighestSeverity))));
        text.AppendLine(DisplayText.Format("Report.ExportMarkdownAsync.10", (report.ExecutionStatus)));
        text.AppendLine(DisplayText.Format("Report.ExportMarkdownAsync.11", (report.ExecutionState), (report.ExecutionReasonCode ?? ReasonCodes.Unspecified)));
        if (report.LegacyExecutionStatus is { } legacy) text.AppendLine(DisplayText.Format("Report.ExportMarkdownAsync.12", (legacy)));
        text.AppendLine(DisplayText.Format("Report.ExportMarkdownAsync.13", (report.RiskFindingCount)));
        text.AppendLine(DisplayText.Get("Report.ExportMarkdownAsync.14") + FindingHandlingPresentation.Count(report.Findings).Summary);
        foreach (MessageText scope in report.ScopeTexts) text.AppendLine(DisplayText.Get("Report.ExportMarkdownAsync.15") + Escape(scope.Display));
        text.AppendLine();
        text.AppendLine(DisplayText.Get("Report.ExportMarkdownAsync.16"));
        text.AppendLine();

        text.AppendLine(DisplayText.Get("Report.ExportMarkdownAsync.17"));
        text.AppendLine();
        text.AppendLine(DisplayText.Format("Report.ExportMarkdownAsync.18", (report.Metrics.FilesVisited)));
        text.AppendLine(DisplayText.Format("Report.ExportMarkdownAsync.19", (report.Metrics.ProcessesVisited)));
        text.AppendLine(DisplayText.Format("Report.ExportMarkdownAsync.20", (report.Metrics.PersistenceItemsVisited)));
        text.AppendLine(DisplayText.Format("Report.ExportMarkdownAsync.21", (report.Metrics.WorkshopItemsVisited)));
        text.AppendLine(DisplayText.Format("Report.ExportMarkdownAsync.22", (report.Metrics.ArchiveEntriesVisited)));
        if (report.ResourceAudit is { } audit)
            foreach (string line in ScanResourcePresentation.Describe(audit)) text.AppendLine("- " + Escape(line));
        text.AppendLine();
        text.AppendLine(DisplayText.Get("Report.ExportMarkdownAsync.23"));
        if (report.ContentScanSettings is ScanOptions settings)
        {
            text.AppendLine();
            text.AppendLine(DisplayText.Format("Report.ExportMarkdownAsync.24", (settings.Mode), (settings.IncludeDownloadLocations), (settings.InspectArchives), (settings.UseAmsi)));
            string hashBudget = settings.MaximumContentBytes == long.MaxValue ? DisplayText.Get("Report.ExportMarkdownAsync.25") :
                DisplayText.Format("Report.ExportMarkdownAsync.26", (settings.MaximumContentBytes / 1024 / 1024), (settings.MaximumContentBytes));
            text.AppendLine(DisplayText.Format("Report.ExportMarkdownAsync.27", (hashBudget)) +
                (settings.Mode == ScanMode.Quick ? DisplayText.Format("Report.ExportMarkdownAsync.28", (settings.MaximumQuickPriorityFileBytes / 1048576m), (settings.MaximumQuickPriorityBytes / 1048576m)) : "") +
                DisplayText.Format("Report.ExportMarkdownAsync.29", (settings.MaximumEntryBytes / 1024 / 1024), (settings.MaximumArchiveDepth)));
            var configured = System.Text.Json.JsonSerializer.SerializeToNode(settings)!;
            text.AppendLine();
            text.AppendLine(DisplayText.Get("Report.ExportMarkdownAsync.30"));
            text.AppendLine();
            foreach (ScanLimitDefinition field in ScanLimitSettings.Fields)
            {
                string[] parts = field.Key.Split('.');
                var value = parts.Length == 1 ? configured[parts[0]] : configured[parts[0]]?[parts[1]];
                if (value is null) continue;
                decimal number = value.GetValue<decimal>();
                string display = field.Key == "MaximumContentBytes" && number == long.MaxValue ? DisplayText.Get("Report.ExportMarkdownAsync.31") : (number / field.Scale).ToString("0.########", DisplayText.Culture) + " " + field.Unit;
                text.AppendLine("- " + DisplayText.Format("Common.LabelValue", field.Label, display));
            }
        }
        if (report.WorkerDiagnostics is WorkerDiagnostics diagnostic)
        {
            text.AppendLine();
            text.AppendLine(DisplayText.Get("Report.ExportMarkdownAsync.32"));
            text.AppendLine();
            text.AppendLine(DisplayText.Get("Report.ExportMarkdownAsync.33") + Escape(diagnostic.StageText.Display + " / " + diagnostic.OperationText.Display));
            text.AppendLine(DisplayText.Get("Report.ExportMarkdownAsync.34") + Escape(diagnostic.LastPathText.Display));
            text.AppendLine(DisplayText.Format("Report.ExportMarkdownAsync.35", (diagnostic.PrivateBytes / 1024 / 1024), (diagnostic.PeakPrivateBytes / 1024 / 1024), (diagnostic.ManagedBytes / 1024 / 1024)));
            text.AppendLine(DisplayText.Get("Report.ExportMarkdownAsync.36") + Escape(diagnostic.LauncherIntegrity ?? DisplayText.Get("Report.ExportMarkdownAsync.37")));
            text.AppendLine(DisplayText.Format("Report.ExportMarkdownAsync.38", (diagnostic.CapturedAtUtc.ToLocalTime())));
            if (diagnostic.FailureType is not null) text.AppendLine(DisplayText.Get("Report.ExportMarkdownAsync.39") + Escape(diagnostic.FailureType));
            if (diagnostic.FailureStack is not null) text.AppendLine(DisplayText.Get("Report.ExportMarkdownAsync.40") + Escape(diagnostic.FailureStack));
            text.AppendLine(DisplayText.Get("Report.ExportMarkdownAsync.41"));
        }
        text.AppendLine();
        foreach (MessageText source in report.ContentSourceTexts.DistinctBy(text => text.OriginalText)) text.AppendLine("- " + Escape(source.Display));
        foreach (string source in report.CandidateRoots.Distinct()) text.AppendLine(DisplayText.Get("Report.ExportMarkdownAsync.42") + Escape(source));
        text.AppendLine();

        if (report.RootSummaries.Count > 0)
        {
            text.AppendLine(DisplayText.Get("Report.ExportMarkdownAsync.43"));
            text.AppendLine();
            text.AppendLine(DisplayText.Get("Report.ExportMarkdownAsync.44"));
            text.AppendLine("|---|---:|---:|---|");
            foreach (ScanRootSummary root in report.RootSummaries)
                text.AppendLine($"| {Escape(root.Path)} | {root.KnownThreats} | {root.ActionableFindings} | {CoverageLabel(root.Coverage)} |");
            text.AppendLine();
        }

        if (report.CoverageNotes.Count > 0 || report.CoverageNotices.Count > 0 || report.CoverageAggregates.Count > 0 || report.Findings.Any(f => f.Category == FindingCategory.Coverage))
        {
            text.AppendLine(DisplayText.Get("Report.ExportMarkdownAsync.45"));
            text.AppendLine();
            foreach (CoverageGroup group in CoveragePresentation.Groups(report))
            {
                text.AppendLine(DisplayText.Format("Report.ExportMarkdownAsync.46", (Escape(group.Kind)), (group.Count)));
                text.AppendLine();
                text.AppendLine(Escape(group.NextStep));
                text.AppendLine();
                foreach (CoverageEntry item in group.Entries) text.AppendLine("- " + DisplayText.Format("Common.LabelValue", Escape(item.TargetDisplay), Escape(item.Detail)));
                text.AppendLine();
            }
            text.AppendLine();
        }

        if (report.TrustProxyDiagnostics is { } trustProxy)
        {
            text.AppendLine(DisplayText.Get("Report.ExportMarkdownAsync.47"));
            text.AppendLine();
            text.AppendLine(DisplayText.Get("Report.ExportMarkdownAsync.48"));
            text.AppendLine();
            text.AppendLine("```text");
            text.AppendLine(TrustProxyReportPresentation.Describe(trustProxy).Replace("```", "｀｀｀", StringComparison.Ordinal));
            text.AppendLine("```");
            text.AppendLine();
        }
        if (report.RelatedComponentDiagnostics is { } relatedComponents)
        {
            text.AppendLine(DisplayText.Get("Report.ExportMarkdownAsync.49"));
            text.AppendLine();
            text.AppendLine(DisplayText.Get("Report.ExportMarkdownAsync.50"));
            text.AppendLine();
            text.AppendLine("```text");
            text.AppendLine(RelatedComponentReportPresentation.Describe(relatedComponents).Replace("```", "｀｀｀", StringComparison.Ordinal));
            text.AppendLine("```");
            text.AppendLine();
        }
        if (report.Containers is { } containers)
        {
            text.AppendLine(DisplayText.Get("Report.ExportMarkdownAsync.51"));
            text.AppendLine();
            text.AppendLine(DisplayText.Get("Report.ExportMarkdownAsync.52"));
            text.AppendLine();
            text.AppendLine("```text");
            text.AppendLine(ContainerReportPresentation.Describe(containers).Replace("```", "｀｀｀", StringComparison.Ordinal));
            text.AppendLine("```");
            text.AppendLine();
        }
        text.AppendLine(DisplayText.Get("Report.ExportMarkdownAsync.53"));
        text.AppendLine();
        text.AppendLine(DisplayText.Get("Report.ExportMarkdownAsync.54"));
        text.AppendLine("|---|---|---|---:|---|---|---|");
        foreach (Finding finding in report.Findings.Where(f => f.Category != FindingCategory.Coverage).OrderByDescending(f => f.Severity).ThenByDescending(f => f.Score))
        {
            text.AppendLine($"| {SeverityLabel(finding.Severity)} | `{Escape(finding.RuleId)}` | {CategoryLabel(finding.Category)} | {finding.Score} | {Escape(finding.TitleText.Display)} | `{Escape(finding.Sha256 ?? "—")}` | `{Escape(finding.TargetText.Display)}` |");
        }

        text.AppendLine();
        text.AppendLine(DisplayText.Get("Report.ExportMarkdownAsync.55"));
        text.AppendLine();
        foreach (Finding finding in report.Findings.Where(f => f.Category != FindingCategory.Coverage).OrderByDescending(f => f.Severity).ThenByDescending(f => f.Score))
        {
            text.AppendLine($"### {SeverityLabel(finding.Severity)} · {Escape(finding.TitleText.Display)}");
            text.AppendLine();
            text.AppendLine(DisplayText.Format("Report.ExportMarkdownAsync.56", (Escape(finding.RuleId))));
            text.AppendLine(DisplayText.Format("Report.ExportMarkdownAsync.57", (Escape(finding.DescriptionText.Display))));
            text.AppendLine(DisplayText.Format("Report.ExportMarkdownAsync.58", (Escape(finding.AppId ?? "—")), (Escape(finding.WorkshopId ?? "—")), (Escape(finding.SourceKind ?? "—"))));
            if (finding.RelatedFilePath is not null) text.AppendLine(DisplayText.Format("Report.ExportMarkdownAsync.59", (Escape(finding.RelatedFilePath)), (Escape(finding.RelatedFileSha256 ?? "—"))));
            text.AppendLine(DisplayText.Format("Report.ExportMarkdownAsync.60", (Escape(finding.TargetText.Display))));
            text.AppendLine("- " + DisplayText.Format("Common.LabelValue", "SHA-256", $"`{Escape(finding.Sha256 ?? DisplayText.Get("Report.ExportMarkdownAsync.61"))}`"));
            text.AppendLine(DisplayText.Format("Report.ExportMarkdownAsync.62", (Escape(finding.ContentPath ?? finding.Target))));
            text.AppendLine(DisplayText.Format("Report.ExportMarkdownAsync.63", (Escape(finding.TargetSha256 ?? DisplayText.Get("Report.ExportMarkdownAsync.64")))));
            text.AppendLine(DisplayText.Format("Report.ExportMarkdownAsync.65", (Escape(finding.EvidenceDisplay))));
            text.AppendLine(DisplayText.Format("Report.ExportMarkdownAsync.66", ((FindingHandlingPresentation.Get(finding).CanSelect ? DisplayText.Get("Report.ExportMarkdownAsync.67") : DisplayText.Get("Report.ExportMarkdownAsync.68")))));
            FindingHandlingInfo handling = FindingHandlingPresentation.Get(finding);
            text.AppendLine(DisplayText.Get("Report.ExportMarkdownAsync.69") + handling.Label + DisplayText.Get("Common.Semicolon") + Escape(handling.Reason));
            text.AppendLine(DisplayText.Get("Report.ExportMarkdownAsync.70") + Escape(handling.NextStep));
            if (!handling.CanSelect) text.AppendLine(DisplayText.Get("Report.ExportMarkdownAsync.71"));
            if (finding.DiagnosticObservationIds.Count > 0) text.AppendLine(DisplayText.Get("Report.ExportMarkdownAsync.72") + Escape(string.Join(", ", finding.DiagnosticObservationIds)));
            if (RelatedComponentReportPresentation.IsRelatedFinding(finding))
            {
                text.AppendLine(DisplayText.Get("Report.ExportMarkdownAsync.73") + RelatedComponentReportPresentation.EvidenceTierLabel(finding.AssociationEvidenceTier) + DisplayText.Get("Report.ExportMarkdownAsync.74"));
                text.AppendLine(DisplayText.Get("Report.ExportMarkdownAsync.75") + Escape(string.Join(", ", finding.AssociationObservationIds.Take(16))) +
                    (finding.AssociationObservationIds.Count > 16 ? DisplayText.Get("Report.ExportMarkdownAsync.76") : DisplayText.Get("Report.ExportMarkdownAsync.77")));
            }
            text.AppendLine();
        }

        text.AppendLine(DisplayText.Get("Report.ExportMarkdownAsync.78"));
        text.AppendLine();
        text.AppendLine(DisplayText.Get("Report.ExportMarkdownAsync.79"));

        await Utilities.AtomicFile.WriteAsync(path, async output =>
        {
            await using StreamWriter writer = new(output, new UTF8Encoding(encoderShouldEmitUTF8Identifier: true), leaveOpen: true);
            await writer.WriteAsync(text.ToString().AsMemory(), cancellationToken);
            await writer.FlushAsync(cancellationToken);
        }, cancellationToken);
    }

    private static string Escape(string value) => Inspection.ScriptSignals.RedactSecrets(value).Replace("|", "\\|").Replace("\r", " ").Replace("\n", " ");

    public static string CoverageLabel(ScanCoverage value) => value switch
    {
        ScanCoverage.Complete => DisplayText.Get("Report.CoverageLabel.Complete.01"),
        ScanCoverage.Partial => DisplayText.Get("Report.CoverageLabel.Partial.01"),
        ScanCoverage.Skipped => DisplayText.Get("Report.CoverageLabel.01"),
        _ => DisplayText.Get("Common.Unknown")
    };

    public static string CategoryLabel(FindingCategory value) => value switch
    {
        FindingCategory.File => DisplayText.Get("Report.CategoryLabel.File.01"),
        FindingCategory.Archive => DisplayText.Get("Report.CategoryLabel.Archive.01"),
        FindingCategory.Process => DisplayText.Get("Report.CategoryLabel.Process.01"),
        FindingCategory.Persistence => DisplayText.Get("Report.CategoryLabel.Persistence.01"),
        FindingCategory.Steam => DisplayText.Get("Report.CategoryLabel.Steam.01"),
        FindingCategory.WallpaperEngine => "Wallpaper Engine",
        FindingCategory.Network => DisplayText.Get("Report.CategoryLabel.Network.01"),
        FindingCategory.Certificate => DisplayText.Get("Report.CategoryLabel.Certificate.01"),
        FindingCategory.SecurityControl => DisplayText.Get("Report.CategoryLabel.SecurityControl.01"),
        FindingCategory.Coverage => DisplayText.Get("Report.CategoryLabel.Coverage.01"),
        _ => DisplayText.Get("Report.CategoryLabel.01")
    };

    public static string ActionLabel(RemediationActionType value) => value switch
    {
        RemediationActionType.StopProcess => DisplayText.Get("Report.ActionLabel.StopProcess.01"),
        RemediationActionType.StopHostProcess => DisplayText.Get("Report.ActionLabel.StopHostProcess.01"),
        RemediationActionType.DisableService => DisplayText.Get("Report.ActionLabel.DisableService.01"),
        RemediationActionType.RemoveRelatedDefenderExclusion => DisplayText.Get("Report.ActionLabel.RemoveRelatedDefenderExclusion.01"),
        RemediationActionType.DisableRelatedFirewallRule => DisplayText.Get("Report.ActionLabel.DisableRelatedFirewallRule.01"),
        RemediationActionType.RemoveBoundCertificate => DisplayText.Get("Report.ActionLabel.RemoveBoundCertificate.01"),
        RemediationActionType.RestoreBoundProxyConfiguration => DisplayText.Get("Report.ActionLabel.RestoreBoundProxyConfiguration.01"),
        RemediationActionType.RemoveRegistryValue => DisplayText.Get("Report.ActionLabel.RemoveRegistryValue.01"),
        RemediationActionType.RemoveScheduledTask => DisplayText.Get("Report.ActionLabel.RemoveScheduledTask.01"),
        RemediationActionType.RemoveDefenderExclusion => DisplayText.Get("Report.ActionLabel.RemoveDefenderExclusion.01"),
        RemediationActionType.QuarantineFile => DisplayText.Get("Report.ActionLabel.QuarantineFile.01"),
        RemediationActionType.QuarantineDirectory => DisplayText.Get("Report.ActionLabel.QuarantineDirectory.01"),
        RemediationActionType.AddProgramFirewallBlock => DisplayText.Get("Report.ActionLabel.AddProgramFirewallBlock.01"),
        RemediationActionType.BlockKnownDomains => DisplayText.Get("Report.ActionLabel.BlockKnownDomains.01"),
        RemediationActionType.RestoreSecurityControls => DisplayText.Get("Report.ActionLabel.RestoreSecurityControls.01"),
        RemediationActionType.RollbackIncident => DisplayText.Get("Report.ActionLabel.RollbackIncident.01"),
        RemediationActionType.DeleteIncident => DisplayText.Get("Report.ActionLabel.DeleteIncident.01"),
        _ => DisplayText.Get("Report.ActionLabel.01")
    };

    public static string SeverityLabel(FindingSeverity value) => value switch
    {
        FindingSeverity.Critical => DisplayText.Get("Report.SeverityLabel.Critical.01"),
        FindingSeverity.High => DisplayText.Get("Report.SeverityLabel.High.01"),
        FindingSeverity.Medium => DisplayText.Get("Report.SeverityLabel.Medium.01"),
        FindingSeverity.Low => DisplayText.Get("Report.SeverityLabel.Low.01"),
        FindingSeverity.Information => DisplayText.Get("Report.SeverityLabel.01"),
        _ => DisplayText.Get("Common.Unknown")
    };
}
