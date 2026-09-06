using System.IO;
using System.IO.Compression;
using System.Reflection.PortableExecutable;
using SteamSentinel.App.Services;
using SteamSentinel.Core.Inspection;
using SteamSentinel.Core.Models;
using SteamSentinel.Core.Reporting;
using SteamSentinel.Core.Scanning;
using SteamSentinel.Core.Utilities;

namespace SteamSentinel.SelfTest;

internal static partial class Program
{
    // Explicit native validation utility. Reads a signed benign program, mutates only an owned
    // copy, and passes copies through the Low worker. No fixture program is ever executed.
    private static async Task<int> RunV020SignatureAsync(string signedSource, string outputDirectory, string? workerOverride = null)
    {
        string output = Path.GetFullPath(outputDirectory);
        Directory.CreateDirectory(output);
        string fixture = Path.Combine(output, "signature-fixture-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(fixture);
        string original = Path.Combine(fixture, "signed-original.exe"), changed = Path.Combine(fixture, "signed-modified.exe");
        using (FileStream input = RelatedArtifactReader.Open(Path.GetFullPath(signedSource)))
        {
            using FileStream copy = new(original, FileMode.CreateNew, FileAccess.Write, FileShare.None);
            await input.CopyToAsync(copy);
        }
        SignatureResult before;
        using (FileStream input = RelatedArtifactReader.Open(original))
            before = AuthenticodeVerifier.VerifyOffline(original, input.SafeFileHandle);
        Check("0.2本机签名原件只读离线验证通过", before.Status == SignatureStatus.Valid);
        if (before.Status != SignatureStatus.Valid)
            throw new InvalidDataException("签名夹具在当前本地缓存不能验证：" + before.Detail);
        File.Copy(original, changed);
        long mutation;
        using (FileStream input = File.OpenRead(changed))
        using (PEReader pe = new(input))
        {
            var section = pe.PEHeaders.SectionHeaders.First(value => value.SizeOfRawData > 32 && value.PointerToRawData > 0);
            mutation = section.PointerToRawData + 16;
        }
        using (FileStream copy = new(changed, FileMode.Open, FileAccess.ReadWrite, FileShare.None))
        {
            copy.Position = mutation; int value = copy.ReadByte();
            if (value < 0) throw new InvalidDataException("签名夹具节范围不存在。");
            copy.Position = mutation; copy.WriteByte((byte)(value ^ 1));
        }
        using (FileStream input = RelatedArtifactReader.Open(changed))
            Check("0.2本机签名代码节修改得到独立摘要不匹配状态",
                AuthenticodeVerifier.VerifyOffline(changed, input.SafeFileHandle).Status == SignatureStatus.HashMismatch);
        string zip = Path.Combine(fixture, "signature-pair.zip");
        using (ZipArchive archive = ZipFile.Open(zip, ZipArchiveMode.Create))
        {
            archive.CreateEntryFromFile(original, "unchanged.exe", CompressionLevel.NoCompression);
            archive.CreateEntryFromFile(changed, "changed.exe", CompressionLevel.NoCompression);
        }
        string outerHash = await Hashing.Sha256FileAsync(zip), innerHash = await Hashing.Sha256FileAsync(changed);
        string workerPath = workerOverride ?? DevelopmentWorkerPath();
        ScanReport report = await new ArchiveWorkerClient(workerPath).RunAsync(new()
        {
            Mode = ScanMode.Custom,
            IncludeSystem = false,
            IncludeSteam = false,
            IncludeWorkshop = false,
            IncludeRelatedContent = false,
            UseAmsi = false,
            InspectArchives = true,
            HashEveryFile = true,
            InspectDeepSignatures = true,
            CustomRoots = [zip],
            MaximumContentBytes = long.MaxValue
        }, (request, _) => Task.FromResult(new ArchivePasswordResponse(request.RequestId, true, null, false)), null, CancellationToken.None);
        ContainerScanNode[] nodes = report.Containers?.Nodes.ToArray() ?? [];
        Finding[] findings = report.Findings.Where(value => value.RuleId == "CONTENT-SIGNATURE-HASH-MISMATCH").ToArray();
        Check("0.2本机深层签名在Low Worker中区分完整与修改成员", nodes.Any(value => value.DisplayPath.EndsWith("!/unchanged.exe", StringComparison.Ordinal) && value.Signature == ContentSignatureStatus.Valid) &&
            nodes.Any(value => value.DisplayPath.EndsWith("!/changed.exe", StringComparison.Ordinal) && value.Signature == ContentSignatureStatus.HashMismatch));
        Check("0.2本机深层摘要异常同时绑定内层身份与外层目标", findings.Length == 1 && findings[0].Target == zip &&
            findings[0].Sha256 == innerHash && findings[0].TargetSha256 == outerHash && findings[0].ContentPath?.EndsWith("!/changed.exe", StringComparison.Ordinal) == true &&
            !findings[0].CanRemediate && !findings[0].IsKnownMalware);
        Check("0.2本机深层签名原生预算独立预留且没有执行成员", report.Containers?.Resources.NativeReservedReadBytes == new FileInfo(original).Length * 2 &&
            report.Metrics.ProcessesVisited == 0 && report.WorkerDiagnostics is not null);
        await JsonFile.WriteAtomicAsync(Path.Combine(output, "signature-report.json"), report, options: ReportPrivacy.ExportOptions);
        await JsonFile.WriteAtomicAsync(Path.Combine(output, "signature-results.json"), new
        {
            Passed = _passed,
            Failed = Failures.Count,
            Failures,
            BuildIdentity = ProductInfo.BuildIdentity,
            WorkerBuildIdentity = report.BuildIdentity,
            WorkerPath = workerPath,
            WorkerSha256 = await Hashing.Sha256FileAsync(workerPath),
            WorkerAssemblySha256 = await Hashing.Sha256FileAsync(Path.ChangeExtension(workerPath, ".dll")),
            CoreAssemblySha256 = await Hashing.Sha256FileAsync(Path.Combine(Path.GetDirectoryName(workerPath)!, "SteamSentinel.Core.dll")),
            SignedSource = signedSource,
            SourceSha256 = await Hashing.Sha256FileAsync(original),
            MutationOffset = mutation,
            ChangedSha256 = innerHash,
            CompletedAtUtc = DateTimeOffset.UtcNow,
            Safety = "Only owned copies were changed. Fixture programs were not executed; no trust store was changed."
        });
        Console.WriteLine($"V020_SIGNATURE_PASS={_passed};FAIL={Failures.Count}");
        return Failures.Count == 0 ? 0 : 1;
    }
}
