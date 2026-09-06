using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using SteamSentinel.Core.Models;
using SteamSentinel.Core.Reporting;
using SteamSentinel.Core.Scanning;
using SteamSentinel.Core.Utilities;

namespace SteamSentinel.SelfTest;

internal static partial class Program
{
    /// <summary>
    /// Explicit, local read-only integration probe. It does not run SystemScanner,
    /// execute a sample, import a certificate, resolve a PAC, or apply a repair.
    /// Writes only the three uniquely named evidence files in outputDirectory.
    /// </summary>
    private static async Task<int> RunTrustProxyNativeSmokeAsync(string outputDirectory)
    {
        string directory = Path.GetFullPath(outputDirectory);
        Directory.CreateDirectory(directory);
        string prefix = $"native-trust-proxy-{DateTimeOffset.UtcNow:yyyyMMdd-HHmmssfff}-{Guid.NewGuid():N}";
        string reportName = prefix + ".report.json";
        string summaryName = prefix + ".summary.json";
        string markdownName = prefix + ".md";
        DiagnosticScanLimits limits = new();
        ScanReport report = new() { Mode = ScanMode.Custom };
        List<NativeSmokeCheck> checks = [];
        List<string> unexpectedExceptions = [];
        Stopwatch timer = Stopwatch.StartNew();
        using CancellationTokenSource deadline = new(TimeSpan.FromSeconds(60));
        try
        {
            new TrustProxyDiagnosticScanner().Collect(report, cancellationToken: deadline.Token, limits: limits);
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            unexpectedExceptions.Add(ex.ToString());
        }
        timer.Stop();
        report.CompletedAtUtc = DateTimeOffset.UtcNow;
        TrustProxyDiagnosticReport? diagnostic = report.TrustProxyDiagnostics;
        void Verify(string name, bool passed, string detail) => checks.Add(new(name, passed, detail));
        Verify("DiagnosticPresent", diagnostic is not null, "采集器应保存结构化诊断，包括无法读取的来源状态。");
        if (diagnostic is not null)
        {
            unexpectedExceptions.AddRange(diagnostic.Checks.Where(c =>
                (c.Name is "代理配置采集" or "证书存储采集") && c.Status == DiagnosticReadStatus.Failed)
                .Select(c => c.Name + ": " + c.Detail));
            Verify("TargetUserSidPresent", !string.IsNullOrWhiteSpace(diagnostic.TargetUserSid), "记录实际扫描用户 SID。");
            Verify("DiagnosticCompleted", diagnostic.CompletedAtUtc is not null, "记录诊断完成时间。");

            string[] expectedStores = ["CurrentUser/Root", "CurrentUser/CA", "LocalMachine/Root", "LocalMachine/CA"];
            string[] actualStores = diagnostic.CertificateStores.Select(s => s.Scope + "/" + s.StoreName).ToArray();
            Verify("FourPhysicalStores", actualStores.Length == expectedStores.Length &&
                actualStores.Order().SequenceEqual(expectedStores.Order()), string.Join(", ", actualStores));
            Verify("PhysicalProviderAndScope", diagnostic.CertificateStores.All(s =>
                s.Provider == CertificateStoreScanner.PhysicalProvider && (s.Scope == "CurrentUser"
                    ? s.UserSid == diagnostic.TargetUserSid : s.UserSid is null)),
                "CurrentUser 绑定目标 SID；LocalMachine 保留独立来源；提供程序为物理注册表存储。");

            string[] expectedProxies = [
                "WinINetRegistry/CurrentUser", "WinINetRegistry/LocalMachine",
                "WinINetPolicyRegistry/CurrentUser", "WinINetPolicyRegistry/LocalMachine",
                "InternetExplorerControlPanelPolicy/CurrentUser", "InternetExplorerControlPanelPolicy/LocalMachine",
                "WinHttpDefault/LocalMachine", "WinINetCurrentConnection/CurrentUser"];
            string[] actualProxies = diagnostic.Proxies.Select(p => p.Source + "/" + p.Scope).ToArray();
            Verify("EightProxySources", actualProxies.Length == expectedProxies.Length &&
                actualProxies.Order().SequenceEqual(expectedProxies.Order()), string.Join(", ", actualProxies));
            Verify("ProxyUserScope", diagnostic.Proxies.All(p => p.Scope == "CurrentUser"
                ? p.UserSid == diagnostic.TargetUserSid : p.UserSid is null), "每个用户配置来源绑定同一个实际用户 SID。");

            string[] observationIds = diagnostic.CertificateStores.Select(s => s.Id)
                .Concat(diagnostic.Certificates.Select(c => c.Id)).Concat(diagnostic.Proxies.Select(p => p.Id)).ToArray();
            HashSet<string> observationIdSet = observationIds.ToHashSet(StringComparer.Ordinal);
            HashSet<string> storeIds = diagnostic.CertificateStores.Select(s => s.Id).ToHashSet(StringComparer.Ordinal);
            Verify("UniqueObservationIds", observationIds.All(id => !string.IsNullOrWhiteSpace(id)) &&
                observationIdSet.Count == observationIds.Length, $"{observationIds.Length} 个观察对象具有唯一 ID。");
            Verify("CertificateSourceCounts", diagnostic.Certificates.All(c => storeIds.Contains(c.StoreObservationId)) &&
                diagnostic.CertificateStores.All(s => s.CertificatesRead == diagnostic.Certificates.Count(c => c.StoreObservationId == s.Id)),
                "每份公开证书可回溯到存在的物理来源，来源计数与记录数一致。");
            Verify("PerSourceChecks", diagnostic.CertificateStores.All(s => diagnostic.Checks.Any(c => c.ObservationId == s.Id && c.Status == s.Status)) &&
                diagnostic.Proxies.All(p => diagnostic.Checks.Any(c => c.ObservationId == p.Id && c.Status == p.Status)),
                "全部来源均保留独立检查状态。");

            List<string> invalidDer = [];
            long totalDerBytes = 0;
            foreach (CertificateObservation certificate in diagnostic.Certificates)
            {
                try
                {
                    byte[] der = Convert.FromBase64String(certificate.DerBase64);
                    totalDerBytes += der.Length;
                    if (der.Length == 0 || der.Length > limits.MaximumCertificateBytes ||
                        !Convert.ToHexString(SHA256.HashData(der)).Equals(certificate.DerSha256, StringComparison.OrdinalIgnoreCase) ||
                        !Convert.ToHexString(SHA1.HashData(der)).Equals(certificate.Sha1Thumbprint, StringComparison.OrdinalIgnoreCase))
                        invalidDer.Add(certificate.Id);
                }
                catch (FormatException) { invalidDer.Add(certificate.Id); }
            }
            Verify("PublicDerFingerprints", invalidDer.Count == 0,
                $"验证 {diagnostic.Certificates.Count} 份 DER 的 Base64、SHA-256、SHA-1；不一致 ID：{string.Join(", ", invalidDer)}。");
            Verify("CertificateBudgets", totalDerBytes <= limits.MaximumTotalCertificateBytes &&
                diagnostic.CertificateStores.All(s => s.CertificatesRead <= limits.MaximumCertificatesPerStore),
                $"已保存公开 DER 共 {totalDerBytes} 字节；每存储及总字节限额未超出。");
            Verify("UtcCertificateValidity", diagnostic.Certificates.All(c =>
                c.NotBeforeUtc.Offset == TimeSpan.Zero && c.NotAfterUtc.Offset == TimeSpan.Zero), "有效期按 UTC 导出；不推断安装时间。");
            Verify("NoSelfSignatureClaim", diagnostic.Certificates.All(c => c.SelfSignatureVerified is null),
                "未把主体与颁发者相同或离线链结果标记为单独完成自签名验证。");
            HashSet<string> hashes = diagnostic.Certificates.Select(c => c.DerSha256).ToHashSet(StringComparer.OrdinalIgnoreCase);
            Verify("OfflineSnapshotChainBoundary", diagnostic.Certificates.All(c =>
                c.ChainScope == CertificateStoreScanner.SnapshotChainScope && c.ChainCertificateSha256.All(hashes.Contains) &&
                (c.ChainStatus == DiagnosticReadStatus.Complete || c.ChainCertificateSha256.Count == 0)),
                "导出的链成员仅引用已采集公开 DER；未完成的链不保存有效链结论。");
            Verify("RelationsResolve", diagnostic.Relations.All(r => observationIdSet.Contains(r.FromId) && observationIdSet.Contains(r.ToId)),
                $"{diagnostic.Relations.Count} 条关系两端均指向存在的观察对象。");
            Verify("NoDiagnosticRepairOrMalwareVerdict", report.Findings.All(f =>
                !f.CanRemediate && !f.IsKnownMalware && f.Severity == FindingSeverity.Information &&
                f.SuggestedActions.All(a => a is SuggestedActionKind.None or SuggestedActionKind.ReviewOnly)),
                "本次只读诊断仅生成信息、复核或覆盖提示，未生成修复动作或恶意结论。");
            Verify("NoUnrelatedScan", report.Metrics.FilesVisited == 0 && report.Metrics.ProcessesVisited == 0 &&
                report.Metrics.PersistenceItemsVisited == 0 && report.Metrics.ArchiveEntriesVisited == 0,
                "未调用文件、进程、启动项或压缩包扫描。");
        }
        Verify("NoUnexpectedCollectorException", unexpectedExceptions.Count == 0, string.Join("\n", unexpectedExceptions));

        // Exercise the same privacy serializer as the application's JSON/ZIP exports, then
        // verify the persisted bytes rather than only the collector's in-memory objects.
        await using (FileStream stream = new(Path.Combine(directory, reportName), FileMode.CreateNew, FileAccess.Write, FileShare.Read))
            await JsonSerializer.SerializeAsync(stream, report, ReportPrivacy.ExportOptions);
        ScanReport persisted = await JsonFile.ReadAsync<ScanReport>(Path.Combine(directory, reportName));
        Verify("PersistedPublicDerUnchanged", diagnostic is not null && persisted.TrustProxyDiagnostics is { } saved &&
            saved.Certificates.Count == diagnostic.Certificates.Count && saved.Certificates.Zip(diagnostic.Certificates).All(pair =>
                pair.First.DerBase64 == pair.Second.DerBase64 &&
                Convert.ToHexString(SHA256.HashData(Convert.FromBase64String(pair.First.DerBase64))).Equals(pair.First.DerSha256, StringComparison.OrdinalIgnoreCase)),
            "按应用导出选项重新读取磁盘 JSON，公开 DER 保持原样并逐份复核 SHA-256。");

        try
        {
            ReportBatchReader received = new();
            int frames = 0;
            ReportBatchWriter writer = new(batch =>
            {
                string wire = JsonSerializer.Serialize(new WorkerMessage { Type = WorkerMessageTypes.Checkpoint, Batch = batch },
                    new JsonSerializerOptions(JsonFile.Options) { WriteIndented = false });
                if (wire.Length >= 1024 * 1024) throw new InvalidDataException("诊断帧超出消息长度上限。");
                received.Apply(JsonSerializer.Deserialize<WorkerMessage>(wire, JsonFile.Options)!.Batch!);
                frames++;
            });
            writer.Send(persisted, final: true);
            Verify("NativeDiagnosticBatchRoundTrip", received.Report?.TrustProxyDiagnostics is { } transported &&
                !received.HasIncompleteTrustProxyDiagnostics && diagnostic is not null &&
                transported.Certificates.Select(c => (c.Id, c.DerBase64)).SequenceEqual(diagnostic.Certificates.Select(c => (c.Id, c.DerBase64))) &&
                transported.Proxies.Count == diagnostic.Proxies.Count && transported.Checks.Count == diagnostic.Checks.Count &&
                transported.Relations.SequenceEqual(diagnostic.Relations), $"真实采集记录通过 {frames} 个有界消息帧往返，来源、检查及 DER 保持完整。");
        }
        catch (InvalidDataException ex) { Verify("NativeDiagnosticBatchRoundTrip", false, ex.Message); }

        int failed = checks.Count(c => !c.Passed);
        bool sourceReadCoverageComplete = diagnostic is not null && diagnostic.Proxies.Count == 8 &&
            diagnostic.CertificateStores.Count == 4 && diagnostic.Proxies.All(p => NativeSourceReadComplete(p.Status)) &&
            diagnostic.CertificateStores.All(s => NativeSourceReadComplete(s.Status));
        var summary = new
        {
            SchemaVersion = 1,
            Probe = "TrustProxyNativeReadOnly",
            report.ProductVersion,
            report.BuildIdentity,
            StartedAtUtc = report.StartedAtUtc,
            CompletedAtUtc = report.CompletedAtUtc,
            ElapsedMilliseconds = timer.ElapsedMilliseconds,
            OsDescription = RuntimeInformation.OSDescription,
            ProcessArchitecture = RuntimeInformation.ProcessArchitecture.ToString(),
            FrameworkDescription = RuntimeInformation.FrameworkDescription,
            TargetUserSid = diagnostic?.TargetUserSid,
            Limits = limits,
            ExitCode = failed == 0 ? 0 : 1,
            Passed = checks.Count(c => c.Passed),
            Failed = failed,
            SourceReadCoverageComplete = sourceReadCoverageComplete,
            Scope = "固定读取本机 8 个代理来源和 4 个物理 Root/CA 存储；不执行样本、联网、导入证书或修改代理。",
            Interpretation = "退出码验证原生路径与输出一致性；权限不足、来源不存在、读取失败、预算不足等原始状态单独保留。通过不表示配置安全或所有链均已完成。",
            CertificateRecords = diagnostic?.Certificates.Count ?? 0,
            UniqueCertificateDer = diagnostic?.Certificates.Select(c => c.DerSha256).Distinct(StringComparer.OrdinalIgnoreCase).Count() ?? 0,
            ProxySources = diagnostic?.Proxies.Select(p => new { p.Id, p.Source, p.Scope, p.Status, p.Detail }).ToArray(),
            CertificateStores = diagnostic?.CertificateStores.Select(s => new { s.Id, s.Scope, s.StoreName, s.Provider, s.Status, s.CertificatesRead, s.Detail }).ToArray(),
            ChainStatusCounts = diagnostic?.Certificates.GroupBy(c => c.ChainStatus.ToString()).ToDictionary(g => g.Key, g => g.Count()),
            Findings = report.Findings.Select(f => new { f.RuleId, f.Title, f.Severity, f.HandlingReason, f.CanRemediate, f.DiagnosticObservationIds }).ToArray(),
            Checks = checks,
            UnexpectedExceptions = unexpectedExceptions,
            ReportFile = reportName,
            MarkdownFile = markdownName
        };
        await JsonFile.WriteNewAsync(Path.Combine(directory, summaryName), summary);
        StringBuilder markdown = new();
        markdown.AppendLine("# 本机证书与代理只读集成验证").AppendLine();
        markdown.AppendLine($"采集时间：{report.StartedAtUtc:O} 至 {report.CompletedAtUtc:O}；耗时 {timer.ElapsedMilliseconds} ms。");
        markdown.AppendLine($"版本：{report.ProductVersion}；构建：{report.BuildIdentity}；架构：{RuntimeInformation.ProcessArchitecture}。").AppendLine();
        markdown.AppendLine($"结构与约束验证：通过 {checks.Count(c => c.Passed)} 项，失败 {failed} 项；全部来源读取完成或不存在：{sourceReadCoverageComplete}。");
        markdown.AppendLine("此验证直接调用本机代理 API、只读注册表与物理证书存储。只验证记录内容和采集状态，不代表配置安全、诊断覆盖完整或恶意软件已清除。");
        markdown.AppendLine("公开 DER 只保存在 JSON；未读取私钥，不下载证书、不执行 PAC、不修改证书或代理配置。时间预算在同步本机 API 调用前后协作检查，不能强制中断单次原生调用。").AppendLine();
        markdown.AppendLine($"[完整诊断 JSON]({reportName}) · [验证摘要 JSON]({summaryName})").AppendLine();
        markdown.AppendLine("| 验证 | 结果 | 说明 |").AppendLine("| --- | --- | --- |");
        foreach (NativeSmokeCheck check in checks)
            markdown.AppendLine($"| {NativeSmokeCell(check.Name)} | {(check.Passed ? "通过" : "失败")} | {NativeSmokeCell(check.Detail)} |");
        markdown.AppendLine();
        if (diagnostic is not null)
        {
            markdown.AppendLine("## 原生读取结果").AppendLine();
            markdown.AppendLine("| 类型 | 来源 | 状态 | 证书记录数 |").AppendLine("| --- | --- | --- | ---: |");
            foreach (ProxyConfigurationObservation proxy in diagnostic.Proxies)
                markdown.AppendLine($"| 代理 | {NativeSmokeCell(proxy.Source + "/" + proxy.Scope)} | {TrustProxyReportPresentation.StatusLabel(proxy.Status)} | — |");
            foreach (CertificateStoreObservation store in diagnostic.CertificateStores)
                markdown.AppendLine($"| 证书 | {NativeSmokeCell(store.Scope + "/" + store.StoreName)} | {TrustProxyReportPresentation.StatusLabel(store.Status)} | {store.CertificatesRead} |");
            markdown.AppendLine().AppendLine("## 观察详情").AppendLine();
            // Indented text remains inert even if a local proxy value or certificate name contains Markdown fences.
            foreach (string line in TrustProxyReportPresentation.Describe(diagnostic).Replace("\r\n", "\n").Split('\n'))
                markdown.Append("    ").AppendLine(line);
        }
        if (unexpectedExceptions.Count != 0)
        {
            markdown.AppendLine().AppendLine("## 未预期异常").AppendLine();
            foreach (string line in string.Join("\n", unexpectedExceptions).Replace("\r\n", "\n").Split('\n'))
                markdown.Append("    ").AppendLine(line);
        }
        await using (FileStream stream = new(Path.Combine(directory, markdownName), FileMode.CreateNew, FileAccess.Write, FileShare.Read))
        await using (StreamWriter writer = new(stream, new UTF8Encoding(false)))
            await writer.WriteAsync(markdown.ToString());
        Console.WriteLine($"NATIVE_TRUST_PROXY_PASS={checks.Count(c => c.Passed)};FAIL={failed};SOURCE_READ_COMPLETE={sourceReadCoverageComplete};ELAPSED_MS={timer.ElapsedMilliseconds}");
        Console.WriteLine("SUMMARY=" + Path.Combine(directory, summaryName));
        Console.WriteLine("REPORT=" + Path.Combine(directory, reportName));
        Console.WriteLine("MARKDOWN=" + Path.Combine(directory, markdownName));
        return failed == 0 ? 0 : 1;
    }

    private static bool NativeSourceReadComplete(DiagnosticReadStatus status) =>
        status is DiagnosticReadStatus.Complete or DiagnosticReadStatus.NotPresent;

    private static string NativeSmokeCell(string value) => value.Replace("&", "&amp;", StringComparison.Ordinal)
        .Replace("<", "&lt;", StringComparison.Ordinal).Replace(">", "&gt;", StringComparison.Ordinal)
        .Replace("|", "\\|", StringComparison.Ordinal).Replace("\r", " ", StringComparison.Ordinal)
        .Replace("\n", "<br>", StringComparison.Ordinal);

    private sealed record NativeSmokeCheck(string Name, bool Passed, string Detail);
}
