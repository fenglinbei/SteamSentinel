using SteamSentinel.Core.Reporting;
using SteamSentinel.Core.Inspection;
using SteamSentinel.Core.Models;

namespace SteamSentinel.Core.Scanning;

public sealed partial class ContentScanner
{
    private void InspectContainerSignature(FileStream file, ArchiveVolumeCandidate source, ContainerContext context, ContainerScanNode node)
    {
        if (source.Offset != 0 || node.Length != file.Length)
        {
            node.Signature = ContentSignatureStatus.Unavailable;
            node.Engines.Add(new()
            {
                EngineText = MessageText.Create("Backend.Core.ContentScanner.Signatures.InspectContainerSignature.01"),
                Status = ContainerStageStatus.Unsupported,
                DetailText = MessageText.Create("Backend.Core.ContentScanner.Signatures.InspectContainerSignature.02")
            }); return;
        }
        context.Budget.Check();
        // Native WinTrust does not expose actual I/O. Account a distinct conservative full-file
        // reservation, keeping it out of measured scanner stream reads and decoded bytes.
        context.Budget.ReserveNativeRead(node.Length);
        RelatedArtifactReader.ValidatePath(file.SafeFileHandle, Path.GetFullPath(source.PhysicalPath));
        SignatureResult result = AuthenticodeVerifier.VerifyOffline(Path.GetFullPath(source.PhysicalPath), file.SafeFileHandle);
        context.Budget.Check();
        RelatedArtifactReader.ValidatePath(file.SafeFileHandle, Path.GetFullPath(source.PhysicalPath));
        node.Signature = result.Status switch
        {
            SignatureStatus.Valid => ContentSignatureStatus.Valid,
            SignatureStatus.Unsigned => ContentSignatureStatus.NotSigned,
            SignatureStatus.HashMismatch => ContentSignatureStatus.HashMismatch,
            SignatureStatus.Untrusted => ContentSignatureStatus.Untrusted,
            SignatureStatus.Unavailable => ContentSignatureStatus.Unavailable,
            _ => ContentSignatureStatus.Failed
        };
        node.SignatureCheckedAtUtc = DateTimeOffset.UtcNow;
        node.Engines.Add(new()
        {
            EngineText = MessageText.Create("Backend.Core.ContentScanner.Signatures.InspectContainerSignature.03"),
            Status = result.Status is SignatureStatus.Error or SignatureStatus.Unavailable
            ? ContainerStageStatus.Failed : ContainerStageStatus.Complete,
            Offset = 0,
            Length = node.Length,
            DetailText = result.DetailText + MessageText.Create("Backend.Core.ContentScanner.Signatures.InspectContainerSignature.04")
        });
        if (result.Status == SignatureStatus.HashMismatch) context.Report.Findings.Add(new()
        {
            RuleId = "CONTENT-SIGNATURE-HASH-MISMATCH",
            Category = FindingCategory.File,
            Severity = FindingSeverity.Medium,
            Score = 40,
            TitleText = MessageText.Create("Backend.Core.ContentScanner.Signatures.InspectContainerSignature.05"),
            DescriptionText = result.DetailText,
            Target = node.OriginalTarget,
            ContentPath = node.DisplayPath,
            Sha256 = node.Sha256,
            TargetSha256 = node.OriginalTargetSha256,
            EvidenceText = MessageText.Create("Backend.Core.ContentScanner.Signatures.InspectContainerSignature.06"),
            CanRemediate = false,
            SuggestedActions = [SuggestedActionKind.ReviewOnly]
        });
    }
}
