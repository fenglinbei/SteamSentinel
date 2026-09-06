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
                Engine = "离线 Authenticode",
                Status = ContainerStageStatus.Unsupported,
                Detail = "嵌入 PE 范围未生成独立文件，原生签名接口不能以外层句柄替代此内容身份。"
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
            Engine = "离线 Authenticode",
            Status = result.Status is SignatureStatus.Error or SignatureStatus.Unavailable
            ? ContainerStageStatus.Failed : ContainerStageStatus.Complete,
            Offset = 0,
            Length = node.Length,
            Detail = result.Detail + " 原生读取量不可测，另预留一份文件长度计入本轮工作预算。"
        });
        if (result.Status == SignatureStatus.HashMismatch) context.Report.Findings.Add(new()
        {
            RuleId = "CONTENT-SIGNATURE-HASH-MISMATCH",
            Category = FindingCategory.File,
            Severity = FindingSeverity.Medium,
            Score = 40,
            Title = "深层程序签名摘要不匹配",
            Description = result.Detail,
            Target = node.OriginalTarget,
            ContentPath = node.DisplayPath,
            Sha256 = node.Sha256,
            TargetSha256 = node.OriginalTargetSha256,
            Evidence = "同一只读文件身份的离线 Authenticode 结果；未执行文件。",
            CanRemediate = false,
            SuggestedActions = [SuggestedActionKind.ReviewOnly]
        });
    }
}
