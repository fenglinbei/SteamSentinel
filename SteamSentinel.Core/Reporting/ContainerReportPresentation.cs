using System.Globalization;
using System.Text;
using SteamSentinel.Core.Inspection;
using SteamSentinel.Core.Models;

namespace SteamSentinel.Core.Reporting;

/// <summary>Metadata-only presentation shared by the read-only UI and report export.</summary>
public static class ContainerReportPresentation
{
    public static string Summary(ContainerScanReport? report, System.Globalization.CultureInfo culture)
    {
        using IDisposable scope = DisplayText.UseCulture(culture);
        return Summary(report);
    }

    public static string Describe(ContainerScanReport report, System.Globalization.CultureInfo culture)
    {
        using IDisposable scope = DisplayText.UseCulture(culture);
        return Describe(report);
    }

    public static string StatusLabel(ContainerStageStatus status, System.Globalization.CultureInfo culture)
    {
        using IDisposable scope = DisplayText.UseCulture(culture);
        return StatusLabel(status);
    }

    public static string SignatureLabel(ContentSignatureStatus status, System.Globalization.CultureInfo culture)
    {
        using IDisposable scope = DisplayText.UseCulture(culture);
        return SignatureLabel(status);
    }
    public static string Describe(ContainerScanReport report, Guid? selectedNodeId, CultureInfo culture)
    {
        using IDisposable scope = DisplayText.UseCulture(culture);
        return Describe(report, selectedNodeId);
    }

    public static string Summary(ContainerScanReport? report)
    {
        if (report is null) return DisplayText.Get("ContainerReport.Summary.01");
        int complete = report.Nodes.Count(NodeComplete);
        bool finished = report.Complete && report.Nodes.Count > 0 && complete == report.Nodes.Count;
        return DisplayText.Format("ContainerReport.Summary.02", (report.Nodes.Count), (complete), ((finished ? DisplayText.Get("ContainerReport.Summary.03") : DisplayText.Get("ContainerReport.Summary.04"))));
    }

    public static string Describe(ContainerScanReport report, Guid? selectedNodeId = null)
    {
        ArgumentNullException.ThrowIfNull(report);
        StringBuilder text = new();
        text.AppendLine(Summary(report));
        text.AppendLine(DisplayText.Get("ContainerReport.Describe.01"));
        text.AppendLine(DisplayText.Get("ContainerReport.Describe.02"));
        text.AppendLine();
        if (report.Runs.Count == 0) AppendResources(text, report.Resources, report.Limits, report.RecoveryOutputDirectory);
        else
        {
            text.AppendLine(DisplayText.Format("ContainerReport.Describe.03", (report.Runs.Count)));
            foreach (ContainerScanRunSummary run in report.Runs)
            {
                text.AppendLine(DisplayText.Format("ContainerReport.Describe.04", (run.ScanId), (run.Mode), ((run.Complete ? DisplayText.Get("ContainerReport.Describe.05") : DisplayText.Get("ContainerReport.Describe.06")))));
                text.AppendLine(DisplayText.Format("ContainerReport.Describe.07", (run.StartedAtUtc), (run.CompletedAtUtc?.ToString("O") ?? DisplayText.Get("ContainerReport.Describe.08")), (run.NodeIds.Count)));
                foreach (string root in run.Roots) text.AppendLine(DisplayText.Get("ContainerReport.Describe.09") + root);
                AppendResources(text, run.Resources, run.Limits, run.RecoveryOutputDirectory);
                text.AppendLine();
            }
        }
        foreach (MessageText check in report.CheckTexts) text.AppendLine(DisplayText.Get("ContainerReport.Describe.10") + check.Display);
        text.AppendLine();
        if (selectedNodeId.HasValue)
        {
            ContainerScanNode? selected = report.Nodes.FirstOrDefault(x => x.NodeId == selectedNodeId.Value);
            if (selected is null) text.AppendLine(DisplayText.Get("ContainerReport.Describe.11"));
            else
            {
                text.AppendLine(DisplayText.Get("ContainerReport.Describe.12"));
                foreach (ContainerScanNode node in Ancestors(report, selected))
                    text.AppendLine($"  {node.FormatText.Display} · {node.DisplayPath} [{StatusLabel(node.Overall)}]");
                text.AppendLine(); AppendNode(text, selected);
            }
        }
        else foreach (ContainerScanNode node in report.Nodes) { AppendNode(text, node); text.AppendLine(); }
        return ScriptSignals.RedactSecrets(text.ToString());
    }

    public static IReadOnlyList<ContainerScanNode> Ancestors(ContainerScanReport report, ContainerScanNode selected)
    {
        Dictionary<Guid, ContainerScanNode> byId = report.Nodes.GroupBy(x => x.NodeId).ToDictionary(x => x.Key, x => x.First());
        List<ContainerScanNode> chain = [];
        HashSet<Guid> visited = [];
        ContainerScanNode? node = selected;
        while (node is not null && visited.Add(node.NodeId) && chain.Count < 64)
        {
            chain.Add(node);
            node = node.ParentId is Guid parent && byId.TryGetValue(parent, out ContainerScanNode? value) ? value : null;
        }
        chain.Reverse(); return chain;
    }

    public static bool NodeComplete(ContainerScanNode node) => node.Overall == ContainerStageStatus.Complete &&
        new[] { node.Recognition, node.DirectoryRead, node.Decryption, node.Integrity, node.ContentCheck }
            .All(x => x is ContainerStageStatus.Complete or ContainerStageStatus.NotRequested);

    private static void AppendResources(StringBuilder text, ContainerResourceSnapshot usage, ContainerResourceLimits limits, string? recoveryOutputDirectory)
    {
        decimal work = (decimal)usage.ReadBytes + usage.DecodedBytes;
        text.AppendLine(DisplayText.Get("ContainerReport.AppendResources.01"));
        text.AppendLine(DisplayText.Format("ContainerReport.AppendResources.02", (Bytes(usage.ReadBytes)), (Bytes(usage.DecodedBytes)), (Bytes(work))));
        text.AppendLine(DisplayText.Format("ContainerReport.AppendResources.03", (Bytes(usage.NativeReservedReadBytes)), (Bytes(usage.NativeReservedDecodedBytes))));
        text.AppendLine(DisplayText.Format("ContainerReport.AppendResources.04", (Bytes(work + usage.NativeReservedReadBytes + usage.NativeReservedDecodedBytes)), (Bytes(limits.MaximumWorkBytes))));
        text.AppendLine(DisplayText.Format("ContainerReport.AppendResources.05", (Bytes(usage.AcceptedExpandedBytes)), (Bytes(limits.MaximumExpandedBytes)), (Bytes(limits.MaximumEntryBytes))));
        text.AppendLine(DisplayText.Format("ContainerReport.AppendResources.06", (Bytes(usage.RangeCopyBytes)), (Bytes(usage.CurrentTemporaryBytes)), (Bytes(usage.PeakTemporaryBytes)), (Bytes(limits.MaximumTemporaryBytes))));
        text.AppendLine(DisplayText.Format("ContainerReport.AppendResources.07", (Bytes(limits.ReservedDiskBytes)), (Bytes(usage.PeakPrivateMemoryBytes))));
        text.AppendLine(DisplayText.Format("ContainerReport.AppendResources.08", (usage.MetadataAttempts), (limits.MaximumMetadataAttempts), (usage.PasswordAttempts), (limits.MaximumPasswordAttempts)));
        text.AppendLine(DisplayText.Format("ContainerReport.AppendResources.09", (limits.MaximumDepth), (limits.MaximumEntries), (limits.MaximumVolumes), (limits.MaximumDirectoryCandidates), (limits.MaximumCompressionRatio.ToString("0.##", CultureInfo.InvariantCulture))));
        text.AppendLine(DisplayText.Format("ContainerReport.AppendResources.10", (Math.Max(0, usage.ElapsedMilliseconds) / 1000m), (limits.MaximumDurationSeconds)));
        text.AppendLine(DisplayText.Get("ContainerReport.AppendResources.11"));
        text.AppendLine(recoveryOutputDirectory is { Length: > 0 } output
            ? DisplayText.Format("Container.RecoveryDirectory", output)
            : DisplayText.Get("ContainerReport.AppendResources.14"));
    }

    private static void AppendNode(StringBuilder text, ContainerScanNode node)
    {
        text.AppendLine(DisplayText.Format("ContainerReport.AppendNode.01", (node.DisplayPath)));
        text.AppendLine(DisplayText.Format("ContainerReport.AppendNode.02", (node.NodeId), (node.ParentId?.ToString() ?? DisplayText.Get("ContainerReport.AppendNode.03")), (node.Revision)));
        text.AppendLine(DisplayText.Format("ContainerReport.AppendNode.04", (KindLabel(node.Kind)), ((string.IsNullOrWhiteSpace(node.Format) ? DisplayText.Get("ContainerReport.AppendNode.05") : node.FormatText.Display)), (node.Depth), (Bytes(node.Length))));
        if (node.ParentOffset.HasValue || node.ParentLength.HasValue)
            text.AppendLine(DisplayText.Format("ContainerReport.AppendNode.06", (node.ParentOffset?.ToString(CultureInfo.InvariantCulture) ?? DisplayText.Get("ContainerReport.AppendNode.07")), (node.ParentLength?.ToString(CultureInfo.InvariantCulture) ?? DisplayText.Get("ContainerReport.AppendNode.08"))));
        text.AppendLine(DisplayText.Format("ContainerReport.AppendNode.09", (node.OriginalTarget)));
        text.AppendLine(DisplayText.Format("ContainerReport.AppendNode.10", (node.OriginalTargetSha256 ?? DisplayText.Get("ContainerReport.AppendNode.11"))));
        text.AppendLine(DisplayText.Format("ContainerReport.AppendNode.12", (node.Sha256 ?? DisplayText.Get("ContainerReport.AppendNode.13"))));
        if (node.VolumeGroupSha256 is { } groupHash) text.AppendLine(DisplayText.Get("ContainerReport.AppendNode.14") + groupHash);
        if (node.VPetFamily is { } family)
        {
            text.AppendLine(DisplayText.Format("ContainerReport.AppendNode.15", (family.ReasonCode), (family.Role), (family.DecoderId)));
            if (family.DerivedSha256 is { } derived) text.AppendLine(DisplayText.Format("ContainerReport.AppendNode.16", (derived), (family.DerivedLength)));
            foreach (VPetDecodedRegion region in family.Regions)
                text.AppendLine(DisplayText.Format("ContainerReport.AppendNode.17", (region.Rva), (region.Offset), (region.Length)));
            if (family.RelatedNodeIds.Count > 0) text.AppendLine(DisplayText.Get("ContainerReport.AppendNode.18") + string.Join(", ", family.RelatedNodeIds));
            text.AppendLine(DisplayText.Get("ContainerReport.AppendNode.19") + string.Join(", ", family.Signals));
            text.AppendLine(DisplayText.Get("ContainerReport.AppendNode.20"));
        }
        if (node.ReusedNodeId is Guid reused) text.AppendLine(DisplayText.Format("Container.ReusedNode", reused));
        text.AppendLine(DisplayText.Format("Container.Stages", StatusLabel(node.Recognition), StatusLabel(node.DirectoryRead),
            StatusLabel(node.Decryption), StatusLabel(node.Integrity), StatusLabel(node.ContentCheck)));
        text.AppendLine(DisplayText.Get("ContainerReport.AppendNode.28") + StatusLabel(node.Overall) + (node.Overall == ContainerStageStatus.Complete && !NodeComplete(node) ? DisplayText.Get("ContainerReport.AppendNode.29") : string.Empty));
        text.AppendLine(DisplayText.Get("ContainerReport.AppendNode.30") + SignatureLabel(node.Signature) +
            (node.SignatureCheckedAtUtc is { } checkedAt ? DisplayText.Format("ContainerReport.AppendNode.31", (checkedAt)) : string.Empty));
        text.AppendLine(DisplayText.Get("ContainerReport.AppendNode.32"));
        text.AppendLine(DisplayText.Format("ContainerReport.AppendNode.33", (node.StartedAtUtc), (node.CompletedAtUtc?.ToString("O") ?? DisplayText.Get("ContainerReport.AppendNode.34"))));
        if (node.Volumes.Count > 0)
        {
            text.AppendLine(DisplayText.Get("ContainerReport.AppendNode.35"));
            foreach (ContainerVolumeIdentity volume in node.Volumes)
                text.AppendLine($"    {volume.DisplayName} · {volume.OriginalPath} · {Bytes(volume.Length)} · SHA-256 {volume.Sha256} · {(volume.IsTemporary ? DisplayText.Get("ContainerReport.AppendNode.36") : DisplayText.Get("ContainerReport.AppendNode.37"))}");
        }
        foreach (ContainerEngineObservation engine in node.Engines)
        {
            text.AppendLine(DisplayText.Format("ContainerReport.AppendNode.38", (engine.EngineText.Display), (StatusLabel(engine.Status)), (engine.Offset?.ToString(CultureInfo.InvariantCulture) ?? DisplayText.Get("ContainerReport.AppendNode.39")), (engine.Length?.ToString(CultureInfo.InvariantCulture) ?? DisplayText.Get("ContainerReport.AppendNode.40"))));
            if (engine.AmsiDiagnostics is { } amsi) text.AppendLine(AmsiPresentation.Describe(amsi));
            text.AppendLine("    " + (engine.DetailMessage is null ? DisplayText.Format("Common.RawDetail", engine.Detail) : engine.DetailText.Display));
        }
        foreach (MessageText detail in node.DetailTexts) text.AppendLine(DisplayText.Get("ContainerReport.AppendNode.41") + detail.Display);
        if (node.RecoveredContentAvailable || node.RecoveredContentName is not null)
            text.AppendLine(DisplayText.Format(node.RecoveredContentAvailable ? "Container.RecoveryAvailable" : "Container.RecoveryUnavailable",
                node.RecoveredContentName ?? DisplayText.Get("ContainerReport.AppendNode.43")));
    }

    public static string StatusLabel(ContainerStageStatus status) => status switch
    {
        ContainerStageStatus.NotRequested => DisplayText.Get("ContainerReport.StatusLabel.NotRequested.01"),
        ContainerStageStatus.Pending => DisplayText.Get("ContainerReport.StatusLabel.Pending.01"),
        ContainerStageStatus.Complete => DisplayText.Get("ContainerReport.StatusLabel.Complete.01"),
        ContainerStageStatus.Partial => DisplayText.Get("ContainerReport.StatusLabel.Partial.01"),
        ContainerStageStatus.PasswordRequired => DisplayText.Get("ContainerReport.StatusLabel.PasswordRequired.01"),
        ContainerStageStatus.PasswordFailed => DisplayText.Get("ContainerReport.StatusLabel.PasswordFailed.01"),
        ContainerStageStatus.Skipped => DisplayText.Get("ContainerReport.StatusLabel.Skipped.01"),
        ContainerStageStatus.MissingVolume => DisplayText.Get("ContainerReport.StatusLabel.MissingVolume.01"),
        ContainerStageStatus.MixedVolumes => DisplayText.Get("ContainerReport.StatusLabel.MixedVolumes.01"),
        ContainerStageStatus.DuplicateVolume => DisplayText.Get("ContainerReport.StatusLabel.DuplicateVolume.01"),
        ContainerStageStatus.Corrupt => DisplayText.Get("ContainerReport.StatusLabel.Corrupt.01"),
        ContainerStageStatus.Unsupported => DisplayText.Get("ContainerReport.StatusLabel.Unsupported.01"),
        ContainerStageStatus.UnsupportedIntegrity => DisplayText.Get("ContainerReport.StatusLabel.UnsupportedIntegrity.01"),
        ContainerStageStatus.LimitReached => DisplayText.Get("ContainerReport.StatusLabel.LimitReached.01"),
        ContainerStageStatus.AccessDenied => DisplayText.Get("ContainerReport.StatusLabel.AccessDenied.01"),
        ContainerStageStatus.SourceChanged => DisplayText.Get("ContainerReport.StatusLabel.SourceChanged.01"),
        ContainerStageStatus.Cancelled => DisplayText.Get("ContainerReport.StatusLabel.Cancelled.01"),
        ContainerStageStatus.Failed => DisplayText.Get("ContainerReport.StatusLabel.Failed.01"),
        _ => DisplayText.Get("ContainerReport.StatusLabel.01")
    };
    public static string SignatureLabel(ContentSignatureStatus status) => status switch
    {
        ContentSignatureStatus.NotChecked => DisplayText.Get("ContainerReport.SignatureLabel.NotChecked.01"),
        ContentSignatureStatus.Valid => DisplayText.Get("ContainerReport.SignatureLabel.Valid.01"),
        ContentSignatureStatus.NotSigned => DisplayText.Get("ContainerReport.SignatureLabel.NotSigned.01"),
        ContentSignatureStatus.HashMismatch => DisplayText.Get("ContainerReport.SignatureLabel.HashMismatch.01"),
        ContentSignatureStatus.Untrusted => DisplayText.Get("ContainerReport.SignatureLabel.Untrusted.01"),
        ContentSignatureStatus.Unavailable => DisplayText.Get("ContainerReport.SignatureLabel.Unavailable.01"),
        ContentSignatureStatus.Failed => DisplayText.Get("ContainerReport.SignatureLabel.Failed.01"),
        _ => DisplayText.Get("ContainerReport.SignatureLabel.01")
    };
    private static string KindLabel(ContainerNodeKind kind) => kind switch
    {
        ContainerNodeKind.File => DisplayText.Get("ContainerReport.KindLabel.File.01"),
        ContainerNodeKind.EmbeddedRange => DisplayText.Get("ContainerReport.KindLabel.EmbeddedRange.01"),
        ContainerNodeKind.ArchiveMember => DisplayText.Get("ContainerReport.KindLabel.ArchiveMember.01"),
        ContainerNodeKind.VolumeGroup => DisplayText.Get("ContainerReport.KindLabel.VolumeGroup.01"),
        ContainerNodeKind.UnknownRange => DisplayText.Get("ContainerReport.KindLabel.UnknownRange.01"),
        _ => DisplayText.Get("ContainerReport.KindLabel.01")
    };
    private static string Bytes(decimal bytes) => bytes >= 1024m * 1024 * 1024
        ? DisplayText.Format("ContainerReport.Bytes.01", (bytes / (1024m * 1024 * 1024)), (bytes))
        : bytes >= 1024m * 1024 ? DisplayText.Format("ContainerReport.Bytes.02", (bytes / (1024m * 1024)), (bytes)) : DisplayText.Format("ContainerReport.Bytes.03", (bytes));
}
