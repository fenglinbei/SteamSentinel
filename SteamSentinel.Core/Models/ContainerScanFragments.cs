using SteamSentinel.Core.Reporting;
using System.Text.Json.Serialization;
using System.Text.Json;
using SteamSentinel.Core.Scanning;
using SteamSentinel.Core.Utilities;

namespace SteamSentinel.Core.Models;

public sealed record ContainerScanMetadata(int TotalNodes, bool Complete, ContainerResourceLimits Limits,
    ContainerResourceSnapshot Resources, List<string> Checks, string? RecoveryOutputDirectory,
    List<ContainerScanRunSummary>? Runs = null)
{
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] public Dictionary<int, DisplayMessage>? CheckMessages { get => SteamSentinel.Core.Models.DisplayMessageMap.Bound(Checks, field); init => field = value; }
}
public sealed record ContainerScanFragment(ContainerScanMetadata Metadata, int Index, ContainerScanNode? Node, bool IsFinal);

internal static class ContainerScanFragments
{
    internal static ContainerScanMetadata Metadata(ContainerScanReport report) =>
        new(report.Nodes.Count, report.Complete, report.Limits, report.Resources, report.Checks, report.RecoveryOutputDirectory, report.Runs) { CheckMessages = report.CheckMessages };

    internal static void ValidateMetadata(ContainerScanMetadata value)
    {
        if (value is null || value.TotalNodes is < 0 or > ContainerScanReport.MaximumNodes || value.Resources is null || value.Limits is null || value.Checks is null ||
            value.Checks.Count > 512 || value.Checks.Any(s => s is null || s.Length > 2048) || value.RecoveryOutputDirectory?.Length > 32768)
            throw MessageExceptions.Create(MessageText.Create("Backend.Core.ContainerScanFragments.ValidateMetadata.01"), sourceText => new InvalidDataException(sourceText));
        ContainerResourceBudget.Validate(value.Limits);
        ContainerResourceSnapshot r = value.Resources;
        long workAllowance = value.Limits.MaximumWorkBytes + (value.Complete ? 0 : 128 * 1024);
        if (r.ReadBytes < 0 || r.DecodedBytes < 0 || r.NativeReservedReadBytes < 0 || r.NativeReservedReadBytes > value.Limits.MaximumWorkBytes ||
            r.NativeReservedDecodedBytes < 0 || r.NativeReservedDecodedBytes > value.Limits.MaximumWorkBytes || r.AcceptedExpandedBytes < 0 || r.CurrentTemporaryBytes < 0 || r.RangeCopyBytes < 0 ||
            r.PeakTemporaryBytes < r.CurrentTemporaryBytes || r.PeakPrivateMemoryBytes < 0 || r.MetadataAttempts < 0 ||
            r.PasswordAttempts < 0 || r.ElapsedMilliseconds < 0 || r.ReadBytes > workAllowance ||
            r.DecodedBytes > workAllowance - r.ReadBytes - r.NativeReservedReadBytes - r.NativeReservedDecodedBytes || r.AcceptedExpandedBytes > value.Limits.MaximumExpandedBytes ||
            r.PeakTemporaryBytes > value.Limits.MaximumTemporaryBytes || r.MetadataAttempts > value.Limits.MaximumMetadataAttempts + 1L ||
            r.PasswordAttempts > value.Limits.MaximumPasswordAttempts + 1L)
            throw MessageExceptions.Create(MessageText.Create("Backend.Core.ContainerScanFragments.ValidateMetadata.02"), sourceText => new InvalidDataException(sourceText));
        if (value.Runs is { } runs)
        {
            if (runs.Count > ContainerScanRunSummary.MaximumRuns || runs.Any(run => run is null) || runs.Select(run => run.ScanId).Distinct().Count() != runs.Count)
                throw MessageExceptions.Create(MessageText.Create("Backend.Core.ContainerScanFragments.ValidateMetadata.03"), sourceText => new InvalidDataException(sourceText));
            foreach (ContainerScanRunSummary run in runs)
            {
                if (run is null || run.ScanId == Guid.Empty || !Enum.IsDefined(run.Mode) || run.StartedAtUtc == default ||
                    run.CompletedAtUtc < run.StartedAtUtc || run.Roots is null || run.NodeIds is null ||
                    run.Roots.Count > ContainerScanRunSummary.MaximumRoots || run.NodeIds.Count > ContainerScanReport.MaximumNodes ||
                    run.Roots.Any(path => string.IsNullOrWhiteSpace(path) || path.Length > 32768) ||
                    run.NodeIds.Any(id => id == Guid.Empty) || run.NodeIds.Distinct().Count() != run.NodeIds.Count)
                    throw MessageExceptions.Create(MessageText.Create("Backend.Core.ContainerScanFragments.ValidateMetadata.04"), sourceText => new InvalidDataException(sourceText));
                ValidateMetadata(new(run.NodeIds.Count, run.Complete, run.Limits, run.Resources, [], run.RecoveryOutputDirectory));
            }
        }
        DisplayMessageMap.Validate(value.Checks, value.CheckMessages);
        if (JsonSerializer.SerializeToUtf8Bytes(value, JsonFile.Options).Length > 512 * 1024)
            throw MessageExceptions.Create(MessageText.Create("Backend.Core.ContainerScanFragments.ValidateMetadata.05"), sourceText => new InvalidDataException(sourceText));
    }

    internal static int ValidateNode(ContainerScanNode n)
    {
        if (n is null || n.NodeId == Guid.Empty || n.ParentId == n.NodeId || n.Revision is < 0 or > 1024 || !Enum.IsDefined(n.Kind) ||
            n.Depth is < 0 or >= int.MaxValue || n.Length < 0 || n.ParentOffset < 0 || n.ParentLength < 0 ||
            !Enum.IsDefined(n.Recognition) || !Enum.IsDefined(n.DirectoryRead) || !Enum.IsDefined(n.Decryption) ||
            !Enum.IsDefined(n.Integrity) || !Enum.IsDefined(n.ContentCheck) || !Enum.IsDefined(n.Overall) || !Enum.IsDefined(n.Signature) ||
            n.StartedAtUtc == default || n.CompletedAtUtc < n.StartedAtUtc || n.Volumes is null || n.Engines is null || n.Details is null ||
            n.Engines.Count > 16 || n.Details.Count > 32)
            throw MessageExceptions.Create(MessageText.Create("Backend.Core.ContainerScanFragments.ValidateNode.01"), sourceText => new InvalidDataException(sourceText));
        if (n.Overall == ContainerStageStatus.Complete &&
            new[] { n.Recognition, n.DirectoryRead, n.Decryption, n.Integrity, n.ContentCheck }
                .Any(stage => stage is not (ContainerStageStatus.Complete or ContainerStageStatus.NotRequested)))
            throw MessageExceptions.Create(MessageText.Create("Backend.Core.ContainerScanFragments.ValidateNode.02"), sourceText => new InvalidDataException(sourceText));
        int characters = 0;
        void Field(string? s, int maximum, bool required = false)
        {
            if (s is null) { if (required) throw MessageExceptions.Create(MessageText.Create("Backend.Core.ContainerScanFragments.ValidateNode.03"), sourceText => new InvalidDataException(sourceText)); return; }
            if (s.Length > maximum || required && string.IsNullOrWhiteSpace(s)) throw MessageExceptions.Create(MessageText.Create("Backend.Core.ContainerScanFragments.ValidateNode.04"), sourceText => new InvalidDataException(sourceText));
            characters = checked(characters + s.Length);
        }
        void Hash(string? hash) { if (hash is not null && !Validation.IsHexSha256(hash)) throw MessageExceptions.Create(MessageText.Create("Backend.Core.ContainerScanFragments.ValidateNode.05"), sourceText => new InvalidDataException(sourceText)); }
        Field(n.DisplayPath, 32768, true); Field(n.OriginalTarget, 32768, true); Field(n.Format, 128);
        Field(n.RecoveredContentName, 128); Hash(n.Sha256); Hash(n.OriginalTargetSha256); Hash(n.VolumeGroupSha256);
        if (n.VPetFamily is { } family)
        {
            if (!Enum.IsDefined(family.Status) || !Enum.IsDefined(family.Role) || family.FooterOffset < 0 || family.FooterLength < 0 ||
                family.FooterOffset > n.Length || family.FooterLength > n.Length - family.FooterOffset || family.DerivedLength is < 0 or > 8 * 1024 * 1024 ||
                family.Regions is null || family.Regions.Count > 2 || family.Signals is null || family.Signals.Count > 32 ||
                family.RelatedNames is null || family.RelatedNames.Count > 16 || family.RelatedNodeIds is null || family.RelatedNodeIds.Count > 16 ||
                family.SourceSha256 != n.Sha256 || !Validation.IsHexSha256(family.SourceSha256) ||
                family.Status == VPetFamilyStatus.Decoded && (family.DerivedSha256 is null || family.DerivedLength == 0 || !family.EnvelopeValidated))
                throw MessageExceptions.Create(MessageText.Create("Backend.Core.ContainerScanFragments.ValidateNode.06"), sourceText => new InvalidDataException(sourceText));
            Field(family.DecoderId, 64, true); Field(family.ReasonCode, 64, true); Field(family.ExportModule, 128);
            Hash(family.CodeSha256); Hash(family.DerivedSha256);
            foreach (VPetDecodedRegion region in family.Regions)
                if (region is null || region.Rva is < 0 or > uint.MaxValue || region.Offset < 0 || region.Length <= 0 || region.Offset > n.Length || region.Length > n.Length - region.Offset || region.Length > uint.MaxValue - region.Rva)
                    throw MessageExceptions.Create(MessageText.Create("Backend.Core.ContainerScanFragments.ValidateNode.07"), sourceText => new InvalidDataException(sourceText));
            if (family.Status == VPetFamilyStatus.Decoded && (family.Regions.Count != 2 || family.FooterLength != 108 ||
                family.DerivedLength != family.FooterOffset || family.FooterOffset + family.FooterLength != n.Length ||
                family.Role is not (VPetComponentRole.UiPayload or VPetComponentRole.CredentialPayload) ||
                family.Regions.Any(region => region.Offset >= family.DerivedLength || region.Length > family.DerivedLength - region.Offset) ||
                family.Regions[0].Offset + family.Regions[0].Length > family.Regions[1].Offset ||
                family.Regions[0].Rva + family.Regions[0].Length > family.Regions[1].Rva))
                throw MessageExceptions.Create(MessageText.Create("Backend.Core.ContainerScanFragments.ValidateNode.08"), sourceText => new InvalidDataException(sourceText));
            if (family.Status != VPetFamilyStatus.Decoded && (family.DerivedSha256 is not null || family.DerivedLength != 0))
                throw MessageExceptions.Create(MessageText.Create("Backend.Core.ContainerScanFragments.ValidateNode.09"), sourceText => new InvalidDataException(sourceText));
            foreach (string signal in family.Signals) Field(signal, 128, true);
            foreach (string name in family.RelatedNames) Field(name, 256, true);
            if (family.RelatedNodeIds.Any(id => id == Guid.Empty || id == n.NodeId) || family.RelatedNodeIds.Distinct().Count() != family.RelatedNodeIds.Count)
                throw MessageExceptions.Create(MessageText.Create("Backend.Core.ContainerScanFragments.ValidateNode.10"), sourceText => new InvalidDataException(sourceText));
        }
        foreach (string detail in n.Details) Field(detail, 2048, true);
        characters += checked((int)DisplayMessageMap.Validate(n.Details, n.DetailMessages));
        characters += checked((int)(n.FormatMessage?.Validate() ?? 0));
        foreach (ContainerVolumeIdentity v in n.Volumes)
        {
            if (v is null || v.Length < 0) throw MessageExceptions.Create(MessageText.Create("Backend.Core.ContainerScanFragments.ValidateNode.11"), sourceText => new InvalidDataException(sourceText));
            Field(v.OriginalPath, 32768, true); Field(v.DisplayName, 32768, true); Hash(v.Sha256);
        }
        foreach (ContainerEngineObservation e in n.Engines)
        {
            if (e is null || !Enum.IsDefined(e.Status) || e.Offset < 0 || e.Length < 0) throw MessageExceptions.Create(MessageText.Create("Backend.Core.ContainerScanFragments.ValidateNode.12"), sourceText => new InvalidDataException(sourceText));
            Field(e.Engine, 128, true); Field(e.Detail, 2048);
            characters += checked((int)((e.DetailMessage?.Validate() ?? 0) + (e.EngineMessage?.Validate() ?? 0)));
            if (e.AmsiDiagnostics is { } amsi)
            {
                if (e.Engine != "AMSI" || !Enum.IsDefined(amsi.Operation)) throw MessageExceptions.Create(MessageText.Create("Backend.Core.ContainerScanFragments.ValidateNode.13"), sourceText => new InvalidDataException(sourceText));
                Field(amsi.Code, 64, true); Field(amsi.Architecture, 32, true); Field(amsi.Integrity, 32, true);
            }
        }
        if (characters > 128 * 1024 || JsonSerializer.SerializeToUtf8Bytes(n, JsonFile.Options).Length > 512 * 1024)
            throw MessageExceptions.Create(MessageText.Create("Backend.Core.ContainerScanFragments.ValidateNode.14"), sourceText => new InvalidDataException(sourceText));
        return characters;
    }

    internal static void ValidateGraph(IReadOnlyList<ContainerScanNode> nodes)
    {
        Dictionary<Guid, ContainerScanNode> ids = nodes.ToDictionary(n => n.NodeId);
        foreach (ContainerScanNode n in nodes)
        {
            if (n.ParentId is { } parent && (!ids.TryGetValue(parent, out ContainerScanNode? p) || p.Depth >= n.Depth))
                throw MessageExceptions.Create(MessageText.Create("Backend.Core.ContainerScanFragments.ValidateGraph.01"), sourceText => new InvalidDataException(sourceText));
            if (n.ReusedNodeId is { } reused && (reused == n.NodeId || !ids.ContainsKey(reused) || ids[reused].ReusedNodeId.HasValue))
                throw MessageExceptions.Create(MessageText.Create("Backend.Core.ContainerScanFragments.ValidateGraph.02"), sourceText => new InvalidDataException(sourceText));
            if (n.VPetFamily?.RelatedNodeIds.Any(id => !ids.ContainsKey(id)) == true)
                throw MessageExceptions.Create(MessageText.Create("Backend.Core.ContainerScanFragments.ValidateGraph.03"), sourceText => new InvalidDataException(sourceText));
        }
    }
}

internal sealed class ContainerScanAssembly
{
    public ContainerScanReport Report { get; } = new();
    public bool IsComplete { get; private set; }
    private long _characters;
    internal PreparedContainerFragment Prepare(ContainerScanFragment f)
    {
        if (f is null || IsComplete) throw MessageExceptions.Create(MessageText.Create("Backend.Core.ContainerScanFragments.Prepare.01"), sourceText => new InvalidDataException(sourceText));
        ContainerScanFragments.ValidateMetadata(f.Metadata);
        if (f.Index < 0 || f.Index > Report.Nodes.Count || f.Index > f.Metadata.TotalNodes ||
            f.Node is not null && f.Index >= f.Metadata.TotalNodes || f.IsFinal && f.Node is not null)
            throw MessageExceptions.Create(MessageText.Create("Backend.Core.ContainerScanFragments.Prepare.02"), sourceText => new InvalidDataException(sourceText));
        int length = f.Node is null ? 0 : ContainerScanFragments.ValidateNode(f.Node);
        if (_characters + length > 64L * 1024 * 1024) throw MessageExceptions.Create(MessageText.Create("Backend.Core.ContainerScanFragments.Prepare.03"), sourceText => new InvalidDataException(sourceText));
        if (f.Node is { } n)
        {
            if (f.Index < Report.Nodes.Count)
            {
                ContainerScanNode old = Report.Nodes[f.Index];
                if (old.NodeId != n.NodeId || old.ParentId != n.ParentId || old.Kind != n.Kind || old.DisplayPath != n.DisplayPath ||
                    old.OriginalTarget != n.OriginalTarget || old.Depth != n.Depth || old.Revision >= n.Revision)
                    throw MessageExceptions.Create(MessageText.Create("Backend.Core.ContainerScanFragments.Prepare.04"), sourceText => new InvalidDataException(sourceText));
            }
            else if (Report.Nodes.Any(old => old.NodeId == n.NodeId)) throw MessageExceptions.Create(MessageText.Create("Backend.Core.ContainerScanFragments.Prepare.05"), sourceText => new InvalidDataException(sourceText));
        }
        if (f.IsFinal)
        {
            if (Report.Nodes.Count != f.Metadata.TotalNodes || f.Index != Report.Nodes.Count)
                throw MessageExceptions.Create(MessageText.Create("Backend.Core.ContainerScanFragments.Prepare.06"), sourceText => new InvalidDataException(sourceText));
            ContainerScanFragments.ValidateGraph(Report.Nodes);
            if (f.Metadata.Runs?.Any(run => run.NodeIds.Any(id => !Report.Nodes.Any(node => node.NodeId == id))) == true)
                throw MessageExceptions.Create(MessageText.Create("Backend.Core.ContainerScanFragments.Prepare.07"), sourceText => new InvalidDataException(sourceText));
            if (f.Metadata.Complete && Report.Nodes.Any(n => n.Overall is not (ContainerStageStatus.Complete or ContainerStageStatus.NotRequested)))
                throw MessageExceptions.Create(MessageText.Create("Backend.Core.ContainerScanFragments.Prepare.08"), sourceText => new InvalidDataException(sourceText));
        }
        else if (f.Node is null) throw MessageExceptions.Create(MessageText.Create("Backend.Core.ContainerScanFragments.Prepare.09"), sourceText => new InvalidDataException(sourceText));
        return new(f, length);
    }
    internal void Commit(PreparedContainerFragment prepared)
    {
        ContainerScanFragment f = prepared.Fragment;
        if (f.Node is not null)
        {
            if (f.Index == Report.Nodes.Count) Report.Nodes.Add(f.Node); else Report.Nodes[f.Index] = f.Node;
        }
        Report.Limits = f.Metadata.Limits; Report.Resources = f.Metadata.Resources;
        Report.Checks.Clear(); Report.Checks.AddRange(f.Metadata.Checks);
        Report.CheckMessages = f.Metadata.CheckMessages is null ? null : new(f.Metadata.CheckMessages);
        Report.Runs.Clear(); Report.Runs.AddRange(f.Metadata.Runs ?? []);
        Report.RecoveryOutputDirectory = f.Metadata.RecoveryOutputDirectory;
        Report.Complete = f.IsFinal && f.Metadata.Complete; IsComplete = f.IsFinal; _characters += prepared.Characters;
    }
}
internal sealed record PreparedContainerFragment(ContainerScanFragment Fragment, int Characters);
