using System.Diagnostics;
using System.IO;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using SteamSentinel.App.Services;
using SteamSentinel.Core.Models;
using SteamSentinel.Core.Remediation;
using SteamSentinel.Core.Reporting;
using SteamSentinel.Core.Utilities;

namespace SteamSentinel.SelfTest;

internal static partial class Program
{
    // Explicit release acceptance: real harmless files through the restricted worker,
    // followed by case persistence. No Broker or remediation operations are invoked.
    private static async Task<int> RunV031LargeScanAsync(string output, int fileCount, string? workerPath,
        string? sourceCommit, string? sourceTree)
    {
        if (fileCount is < 256 or > 200_000 || Directory.Exists(output) || File.Exists(output) ||
            Validation.ContainsReparsePoint(output))
            throw new ArgumentException("Use a new non-reparse evidence directory and 256 to 200000 inert files.");
        if ((sourceCommit is null) != (sourceTree is null) || sourceCommit is not null &&
            (sourceCommit.Length != 40 || sourceTree!.Length != 40 ||
                !sourceCommit.All(Uri.IsHexDigit) || !sourceTree.All(Uri.IsHexDigit) ||
                ProductInfo.BuildIdentity != $"{ProductInfo.Version}+{sourceCommit}.preview"))
            throw new ArgumentException("Release acceptance requires the exact preview source identity.");
        Directory.CreateDirectory(output);
        using IDisposable culture = DisplayText.UseCulture(DisplayText.Chinese);
        List<object> tests = [];
        int passed = 0, failed = 0;
        void Assert(string name, bool success)
        {
            tests.Add(new { name, passed = success });
            if (success) passed++; else failed++;
            Console.WriteLine($"{(success ? "PASS" : "FAIL")}: {name}");
        }
        Stopwatch elapsed = Stopwatch.StartNew();
        ScanReport? report = null;
        long reportBytes = 0, caseBytes = 0;
        bool saved = false, loaded = false, updated = false, exported = false;
        string? originalReportSha256 = null, loadedReportSha256 = null, updatedReportSha256 = null;
        string? expectedExportedScanSha256 = null, exportedScanSha256 = null, expectedExportedCaseSha256 = null, exportedCaseSha256 = null;
        string? error = null;
        string worker = workerPath ?? DevelopmentWorkerPath();
        List<string> approvals = [];
        try
        {
            string corpus = Path.Combine(output, "inert-files");
            Directory.CreateDirectory(corpus);
            byte[] content = Encoding.UTF8.GetBytes("Ordinary harmless text for the SteamSentinel large scan regression.\n");
            string expectedHash = Convert.ToHexString(SHA256.HashData(content));
            for (int i = 0; i < fileCount; i++)
            {
                string group = Path.Combine(corpus, $"group-{i / 1000:D3}");
                if (i % 1000 == 0) Directory.CreateDirectory(group);
                await File.WriteAllBytesAsync(Path.Combine(group, $"ordinary-{i:D6}.txt"), content);
                if ((i + 1) % 10000 == 0) Console.WriteLine($"GENERATED={i + 1}");
            }
            ScanLimitSettings settings = new() { PerformanceMode = ScanPerformanceMode.HighThroughput };
            settings.Full["MaximumFiles"] = 1000;
            settings.Full["MaximumReportRecords"] = 16;
            settings.Full["MaximumReportTextCharacters"] = 128;
            settings.Full["ContainerLimits.MaximumNodes"] = 1000;
            ScanOptions options = settings.Apply(new()
            {
                Mode = ScanMode.Custom,
                IncludeSystem = false,
                IncludeSteam = false,
                IncludeWorkshop = false,
                UseAmsi = false,
                HashEveryFile = true,
                CustomRoots = [corpus]
            });
            Console.WriteLine($"SCAN_START files={fileCount}");
            using CancellationTokenSource timeout = new(TimeSpan.FromMinutes(35));
            report = await new ArchiveWorkerClient(worker).RunAsync(options,
                (request, _) => Task.FromResult(new ArchivePasswordResponse(request.RequestId, true, null, false)),
                null, timeout.Token, (proposal, _) =>
                {
                    if (proposal.Assessment != ResourceAssessmentKind.EstimatedAvailable)
                        throw new InvalidOperationException("Inert acceptance corpus cannot be granted the proposed resources: " + proposal.ReasonCode);
                    approvals.Add(proposal.Request.LimitKey);
                    Console.WriteLine($"APPROVED={proposal.Request.LimitKey}:{proposal.Request.CurrentLimit}->{proposal.Changes.First(c => c.LimitKey == proposal.Request.LimitKey).After}");
                    return Task.FromResult(new ScanLimitResponse(proposal.Request.RequestId, ResourceDecisionKind.Approve, proposal.Changes));
                });
            Assert("restricted_worker_completed_full_corpus", report.ExecutionState == ScanExecutionState.Completed &&
                report.Coverage == ScanCoverage.Complete && report.Containers?.Complete == true && report.Metrics.FilesVisited == fileCount);
            Assert("all_file_nodes_and_exact_hashes_retained", report.Containers?.Nodes.Count == fileCount &&
                report.Containers.Nodes.All(n => n.Sha256 == expectedHash && n.Length == content.Length) &&
                report.Containers.Nodes.Select(n => n.NodeId).Distinct().Count() == fileCount);
            Assert("benign_corpus_has_no_risk_findings", report.RiskFindingCount == 0);
            Assert("real_worker_approved_text_budget", approvals.Contains("MaximumReportTextCharacters") &&
                report.ResourceAudit?.Decisions.Any(d => d.Request.LimitKey == "MaximumReportTextCharacters" && d.Decision == ResourceDecisionKind.Approve) == true &&
                report.ContentScanSettings!.MaximumReportTextCharacters > options.MaximumReportTextCharacters);
            Assert("approved_file_and_node_budgets", fileCount <= 1000 || approvals.Contains("MaximumFiles") && approvals.Contains("ContainerLimits.MaximumNodes"));
            Assert("callers_defaults_unchanged", options.MaximumFiles == 1000 && options.MaximumReportTextCharacters == 128 && options.ContainerLimits!.MaximumNodes == 1000);
            Assert("worker_and_test_build_identity_match", report.BuildIdentity == ProductInfo.BuildIdentity);
            Assert("fixture_files_preserved", Directory.EnumerateFiles(corpus, "*.txt", SearchOption.AllDirectories).Count() == fileCount);

            Console.WriteLine("CASE_SAVE_START");
            string reportPath = Path.Combine(output, "scan.json");
            await JsonFile.WriteAtomicAsync(reportPath, report);
            reportBytes = new FileInfo(reportPath).Length;
            await using (FileStream originalJson = File.OpenRead(reportPath))
                originalReportSha256 = Convert.ToHexString(await SHA256.HashDataAsync(originalJson));
            using WindowsIdentity identity = WindowsIdentity.GetCurrent();
            var store = new RemediationCaseStore(Path.Combine(output, "cases"));
            var record = new RemediationCaseRecord { UserSid = identity.User!.Value, OriginalScan = report, OriginalContentSettings = report.ContentScanSettings };
            await store.SaveAsync(record);
            saved = record.Revision == 1;
            RemediationCaseRecord? read = await store.LoadAsync(record.CaseId);
            if (read?.OriginalScan is { } loadedScan)
                loadedReportSha256 = await V031SerializationSha256Async(loadedScan, JsonFile.Options);
            loaded = read?.OriginalScan?.Containers?.Nodes.Count == fileCount &&
                read.OriginalScan.Metrics.FilesVisited == fileCount && read.OriginalScan.Containers.Nodes.All(n => n.Sha256 == expectedHash) &&
                loadedReportSha256 == originalReportSha256;
            Assert("case_save_load_preserves_full_scan", saved && loaded);
            Assert("case_loaded_report_matches_original_json_sha256", loadedReportSha256 == originalReportSha256);
            record.Notes.Add("Inert regression update after the first durable save.");
            await store.SaveAsync(record);
            RemediationCaseRecord? reread = await store.LoadAsync(record.CaseId);
            if (reread?.OriginalScan is { } updatedScan)
                updatedReportSha256 = await V031SerializationSha256Async(updatedScan, JsonFile.Options);
            updated = reread?.Revision == 2 && reread.Notes.SequenceEqual(record.Notes) && reread.OriginalScan?.Containers?.Nodes.Count == fileCount &&
                updatedReportSha256 == originalReportSha256;
            Assert("case_revision_update_preserves_scan", updated);
            Assert("case_updated_report_matches_original_json_sha256", updatedReportSha256 == originalReportSha256);
            Assert("case_summary_lists_completed_save", (await store.ListAsync()).Any(s => s.CaseId == record.CaseId && s.Revision == 2 && s.ReadStatus == DiagnosticReadStatus.Complete));
            caseBytes = Directory.EnumerateFiles(store.RootDirectory, "*", SearchOption.AllDirectories).Sum(p => new FileInfo(p).Length);
            if (fileCount >= 60000) Assert("case_exceeds_legacy_64mib_limit", reportBytes > RemediationCaseStore.MaximumCaseBytes);
            Console.WriteLine($"CASE_EXPORT_START reportBytes={reportBytes}");
            string exportPath = Path.Combine(output, "case-export.zip");
            // Export intentionally redacts recognized credentials. Compare against the complete
            // expected export representation, not against the unredacted local case bytes.
            expectedExportedScanSha256 = await V031SerializationSha256Async(report, ReportPrivacy.ExportOptions);
            if (reread is not null)
                expectedExportedCaseSha256 = await V031SerializationSha256Async(reread, ReportPrivacy.ExportOptions);
            await CaseBundleExporter.ExportAsync(exportPath, report, null, null, null, persistedCase: reread, culture: DisplayText.Chinese);
            using (var zip = System.IO.Compression.ZipFile.OpenRead(exportPath))
            {
                exportedScanSha256 = await V031ZipEntrySha256Async(zip, "scan.json");
                exportedCaseSha256 = await V031ZipEntrySha256Async(zip, "remediation-case.json");
                exported = exportedScanSha256 == expectedExportedScanSha256 && expectedExportedCaseSha256 is not null &&
                    exportedCaseSha256 == expectedExportedCaseSha256;
            }
            Assert("large_case_export_contains_scan_and_case", exported);
            Assert("large_case_export_full_scan_exact_after_privacy", exportedScanSha256 == expectedExportedScanSha256);
            Assert("large_case_export_full_case_exact_after_privacy", expectedExportedCaseSha256 is not null && exportedCaseSha256 == expectedExportedCaseSha256);
        }
        catch (Exception ex)
        {
            error = ex.ToString();
            Assert("acceptance_completed_without_exception", false);
            Console.Error.WriteLine(ex);
        }
        finally
        {
            await JsonFile.WriteAtomicAsync(Path.Combine(output, "LARGE-SCAN-RESULTS.json"), new
            {
                schema = "SteamSentinel.LargeScanAcceptance/1",
                version = ProductInfo.Version,
                buildIdentity = ProductInfo.BuildIdentity,
                sourceCommit,
                sourceTree,
                passed,
                failed,
                skipped = 0,
                elapsedMs = elapsed.ElapsedMilliseconds,
                filesScanned = report?.Metrics.FilesVisited ?? 0,
                requestedFiles = fileCount,
                actualBenignFiles = true,
                scanCompleted = report?.ExecutionState == ScanExecutionState.Completed && report?.Coverage == ScanCoverage.Complete,
                budgetIncreaseVerified = approvals.Contains("MaximumReportTextCharacters") && (fileCount <= 1000 || approvals.Contains("MaximumFiles") && approvals.Contains("ContainerLimits.MaximumNodes")),
                caseSaveLoadVerified = saved && loaded && updated && exported,
                reportBytes,
                caseBytes,
                originalReportSha256,
                loadedReportSha256,
                updatedReportSha256,
                expectedExportedScanSha256,
                exportedScanSha256,
                expectedExportedCaseSha256,
                exportedCaseSha256,
                approvalCount = approvals.Count,
                approvedLimitKeys = approvals.Distinct().Order().ToArray(),
                workerFile = Path.GetFileName(worker),
                workerSha256 = File.Exists(worker) ? Convert.ToHexString(SHA256.HashData(await File.ReadAllBytesAsync(worker))) : null,
                tests,
                error,
                completedAtUtc = DateTimeOffset.UtcNow
            });
        }
        return failed == 0 ? 0 : 1;
    }

    private static async Task<string> V031SerializationSha256Async<T>(T value, JsonSerializerOptions options)
    {
        using SHA256 hash = SHA256.Create();
        await using CryptoStream output = new(Stream.Null, hash, CryptoStreamMode.Write, leaveOpen: true);
        await JsonSerializer.SerializeAsync(output, value, options);
        await output.FlushFinalBlockAsync();
        return Convert.ToHexString(hash.Hash!);
    }

    private static async Task<string?> V031ZipEntrySha256Async(System.IO.Compression.ZipArchive zip, string name)
    {
        System.IO.Compression.ZipArchiveEntry[] entries = zip.Entries.Where(entry => entry.FullName == name).ToArray();
        if (entries.Length != 1 || entries[0].Length == 0) return null;
        await using Stream input = entries[0].Open();
        return Convert.ToHexString(await SHA256.HashDataAsync(input));
    }
}
