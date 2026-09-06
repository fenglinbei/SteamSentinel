using System.IO;
using SteamSentinel.App.Services;
using SteamSentinel.Core.Inspection;
using SteamSentinel.Core.Models;
using SteamSentinel.Core.Scanning;
using SteamSentinel.Core.Utilities;

namespace SteamSentinel.SelfTest;

internal static partial class Program
{
    // Only this test assembly and inert files are read. No sample, process or configuration is changed.
    private static async Task TestPhase2RelatedSignatureAsync(string root)
    {
        string directory = Path.Combine(root, "phase2-offline-signature");
        Directory.CreateDirectory(directory);
        string file = Path.Combine(directory, "inert-owned-test.dll");
        File.Copy(typeof(Program).Assembly.Location, file, overwrite: true);
        long length = new FileInfo(file).Length;
        string expectedHash = await Hashing.Sha256FileAsync(file);
        int calls = 0, checkpoints = 0;
        bool writeDenied = false, renameDenied = false, handleValid = false;
        RelatedSignatureProbe success = new((path, handle) =>
        {
            calls++;
            handleValid = !handle.IsClosed && !handle.IsInvalid && path == file;
            try { using FileStream write = new(path, FileMode.Open, FileAccess.Write, FileShare.ReadWrite); }
            catch (IOException) { writeDenied = true; }
            try { File.Move(path, path + ".moved"); File.Move(path + ".moved", path); }
            catch (IOException) { renameDenied = true; }
            return new(SignatureStatus.Valid, "无害测试签名结果；仅使用本地信任缓存。");
        });
        ScanReport exact = new(); exact.Metrics.BytesHashed = 7;
        await success.CollectAsync(exact, [file, file], length * 2, CancellationToken.None, _ => checkpoints++);
        Finding valid = exact.Findings.Single();
        Check("组件签名 固定同一只读句柄并拒绝写入和替换", handleValid && writeDenied && renameDenied && File.Exists(file));
        Check("组件签名 精确双份预算去重且固定哈希", calls == 1 && checkpoints > 0 &&
            exact.Metrics.BytesHashed == length * 2 + 7 && valid.Sha256 == expectedHash && valid.TargetSha256 == expectedHash &&
            valid.ConfigurationKind == "Valid" && exact.Coverage == ScanCoverage.Complete &&
            valid.Evidence.Contains("保守逻辑预算", StringComparison.Ordinal) && valid.Evidence.Contains("不代表原生调用实际 I/O", StringComparison.Ordinal));
        Check("组件签名 有效签名仅观察且不能执行处置", !valid.CanRemediate && !valid.IsKnownMalware &&
            valid.Score == 0 && valid.Severity == FindingSeverity.Information && valid.RuleId == RelatedSignatureProbe.RuleId &&
            valid.SourceKind == "related-components" && valid.AssociationEvidenceTier == RelatedEvidenceTier.Observation &&
            valid.SuggestedActions.SequenceEqual([SuggestedActionKind.None]) && valid.Description.Contains("未联网", StringComparison.Ordinal));

        foreach (long budget in new[] { 0L, length * 2 - 1, -1L })
        {
            ScanReport limited = new();
            await success.CollectAsync(limited, [file], budget, CancellationToken.None);
            Check($"组件签名 预算 {budget} 在正文读取前拒绝", calls == 1 && limited.Metrics.BytesHashed == 0 &&
                limited.Coverage == ScanCoverage.Partial && limited.Findings.Single().ConfigurationKind == "NotChecked" &&
                limited.Findings.Single().Sha256 is null);
        }

        string oversized = Path.Combine(directory, "inert-oversized.exe");
        using (FileStream sparse = new(oversized, FileMode.Create, FileAccess.Write)) sparse.SetLength(RelatedSignatureProbe.MaximumFileBytes + 1);
        ScanReport tooLarge = new();
        await success.CollectAsync(tooLarge, [oversized], long.MaxValue, CancellationToken.None);
        Check("组件签名 单文件16MiB上限在哈希前生效", calls == 1 && tooLarge.Metrics.BytesHashed == 0 &&
            tooLarge.Findings.Single().ConfigurationKind == "NotChecked");

        ScanReport pathLimit = new();
        await success.CollectAsync(pathLimit, Enumerable.Range(0, 33).Select(i => Path.Combine(directory, $"inert-{i}.exe")).ToArray(),
            0, CancellationToken.None);
        Check("组件签名 路径硬限32且留下未检查说明", pathLimit.Findings.Count == RelatedSignatureProbe.MaximumPaths &&
            pathLimit.CoverageNotes.Any(n => n.Contains("前 32", StringComparison.Ordinal)) && pathLimit.Metrics.BytesHashed == 0 && calls == 1);

        ScanReport unsupported = new();
        await success.CollectAsync(unsupported, [Path.Combine(directory, "inert.txt"), @"\\example.invalid\share\inert.exe"],
            long.MaxValue, CancellationToken.None);
        Check("组件签名 不读取非PE扩展名和网络路径", unsupported.Findings.Count == 2 &&
            unsupported.Findings.All(f => f.ConfigurationKind == "NotChecked") && unsupported.Metrics.BytesHashed == 0 && calls == 1);

        ScanReport occupied = new();
        using (FileStream locked = new(file, FileMode.Open, FileAccess.Read, FileShare.None))
            await success.CollectAsync(occupied, [file], length * 2, CancellationToken.None);
        Check("组件签名 占用失败不伪装为无签名或篡改", occupied.Findings.Single().ConfigurationKind == "Failed" &&
            occupied.Coverage == ScanCoverage.Partial && occupied.Metrics.BytesHashed == 0 && calls == 1);

        foreach (SignatureStatus input in new[] { SignatureStatus.Unsigned, SignatureStatus.Error, SignatureStatus.Invalid })
        {
            ScanReport result = new();
            await new RelatedSignatureProbe((_, _) => new(input, "无害测试：本地缓存或信任观察"))
                .CollectAsync(result, [file], length * 2, CancellationToken.None);
            Check($"组件签名 {input} 状态保守映射且保留对应宿主", result.Findings.Single().Target == file &&
                result.Findings.Single().ConfigurationKind == (input == SignatureStatus.Unsigned ? "Unsigned" : "Failed") &&
                !result.Findings.Single().CanRemediate && result.Metrics.BytesHashed == length * 2 &&
                result.Coverage == (input == SignatureStatus.Unsigned ? ScanCoverage.Complete : ScanCoverage.Partial));
        }
        ScanReport nativeFailure = new();
        await new RelatedSignatureProbe((_, _) => throw new IOException("无害测试：原生调用失败"))
            .CollectAsync(nativeFailure, [file], length * 2, CancellationToken.None);
        Check("组件签名 原生失败保留固定哈希与预算", nativeFailure.Findings.Single().ConfigurationKind == "Failed" &&
            nativeFailure.Findings.Single().Sha256 == expectedHash && nativeFailure.Metrics.BytesHashed == length * 2);

        using (CancellationTokenSource before = new())
        {
            before.Cancel(); ScanReport cancelled = new(); bool threw = false;
            try { await success.CollectAsync(cancelled, [file, oversized], long.MaxValue, before.Token); }
            catch (OperationCanceledException) { threw = true; }
            Check("组件签名 提前取消每个未检查宿主均留状态", threw && calls == 1 && cancelled.Metrics.BytesHashed == 0 &&
                cancelled.Coverage == ScanCoverage.Partial && cancelled.Findings.Count == 2 &&
                cancelled.Findings.All(f => f.ConfigurationKind == "NotChecked"));
        }
        using (CancellationTokenSource during = new())
        {
            ScanReport cancelled = new(); bool threw = false; int cancelledCheckpoints = 0;
            RelatedSignatureProbe cancelling = new((_, _) => { during.Cancel(); return new(SignatureStatus.Valid, "不应显示为已完成"); });
            try { await cancelling.CollectAsync(cancelled, [file], length * 2, during.Token, _ => cancelledCheckpoints++); }
            catch (OperationCanceledException) { threw = true; }
            Check("组件签名 原生返回后取消不提升成功且发出保留片段", threw && cancelledCheckpoints > 0 &&
                cancelled.Findings.Single().ConfigurationKind == "NotChecked" && cancelled.Findings.Single().Sha256 == expectedHash &&
                cancelled.Metrics.BytesHashed == length * 2 && cancelled.Coverage == ScanCoverage.Partial);
        }

        Check("组件签名 离线信任缓存策略不把失败当篡改", AuthenticodeVerifier.OfflineProviderFlags == (0x10U | 0x1000U) &&
            AuthenticodeVerifier.InterpretOfflineResult(0).Status == SignatureStatus.Valid &&
            AuthenticodeVerifier.InterpretOfflineResult(unchecked((int)0x800B0100)).Status == SignatureStatus.Unsigned &&
            AuthenticodeVerifier.InterpretOfflineResult(unchecked((int)0x800B0109)).Status == SignatureStatus.Untrusted &&
            AuthenticodeVerifier.InterpretOfflineResult(unchecked((int)0x800B010A)).Status == SignatureStatus.Unavailable &&
            AuthenticodeVerifier.InterpretOfflineResult(unchecked((int)0x80096010)).Status == SignatureStatus.HashMismatch);
        await using (FileStream locked = RelatedArtifactReader.Open(file))
        {
            SignatureResult native = AuthenticodeVerifier.VerifyOffline(file, locked.SafeFileHandle);
            Check("组件签名 原生只读调用可处理自有无害程序集并保留调用者句柄", native.Status is SignatureStatus.Unsigned or SignatureStatus.Error &&
                !locked.SafeFileHandle.IsClosed && locked.CanRead && native.Detail.Length > 0);
        }

        string text = Path.Combine(directory, "inert-worker-content.txt");
        await File.WriteAllTextAsync(text, "Harmless offline-signature worker integration fixture. No commands or payload.");
        using CancellationTokenSource workerTimeout = new(TimeSpan.FromSeconds(45));
        ScanReport wire = await new ArchiveWorkerClient(DevelopmentWorkerPath()).RunAsync(new ScanOptions
        {
            Mode = ScanMode.Custom,
            IncludeSystem = false,
            IncludeSteam = false,
            IncludeWorkshop = false,
            IncludeRelatedContent = false,
            IncludeDownloadLocations = false,
            IncludeExecutionHistory = false,
            UseAmsi = false,
            InspectArchives = false,
            HashEveryFile = true,
            CustomRoots = [text],
            RelatedSignaturePaths = [file],
            MaximumRelatedSignatureBytes = length * 2,
            MaximumContentBytes = length * 2 + 1024 * 1024
        }, (request, _) => Task.FromResult(new ArchivePasswordResponse(request.RequestId, true, null, false)), null, workerTimeout.Token);
        Finding? wireSignature = wire.Findings.SingleOrDefault(f => f.RuleId == RelatedSignatureProbe.RuleId);
        Check("组件签名 真实Low worker保留签名观察和惰性文本内容结果", wireSignature is not null &&
            wireSignature.Target == file && wireSignature.Sha256 == expectedHash &&
            (wireSignature.ConfigurationKind is "Unsigned" or "Failed") && !wireSignature.CanRemediate &&
            wire.Metrics.FilesVisited == 1 && wire.Metrics.BytesHashed == length * 2 + new FileInfo(text).Length &&
            wire.WorkerDiagnostics is not null &&
            wire.Findings.All(f => !f.CanRemediate && !f.IsKnownMalware));
    }
}
