using System.IO.Compression;
using System.Text;
using System.Text.Json;
using SteamSentinel.Core.Models;

namespace SteamSentinel.Core.Reporting;

/// <summary>Metadata only. Never copies a scanned file or quarantine payload into the export.</summary>
public static class CaseBundleExporter
{
    public static async Task ExportAsync(string destination, ScanReport scan, RemediationPlan? plan,
        RemediationRunResult? result, ScanReport? followUp, CancellationToken token = default,
        RemediationBatchSession? batches = null, ScanReport? contentFollowUp = null,
        TrustProxyDiagnosticReport? latestDiagnostics = null,
        RelatedComponentDiagnosticReport? latestRelatedDiagnostics = null,
        RemediationCaseRecord? persistedCase = null,
        System.Globalization.CultureInfo? culture = null)
    {
        using IDisposable scope = DisplayText.UseCulture(culture);
        await Utilities.AtomicFile.WriteAsync(destination, async output =>
        {
            using ZipArchive zip = new(output, ZipArchiveMode.Create, leaveOpen: true);
            await WriteAsync(zip, "scan.json", scan, token);
            if (plan is not null) await WriteAsync(zip, "plan.json", plan, token);
            if (result is not null) await WriteAsync(zip, "result.json", result, token);
            if (followUp is not null) await WriteAsync(zip, "follow-up.json", followUp, token);
            if (batches is not null)
            {
                await WriteAsync(zip, "batches.json", batches, token);
                for (int i = 0; i < batches.Plans.Count; i++)
                {
                    await WriteAsync(zip, $"batches/{i + 1:D3}/plan.json", batches.Plans[i], token);
                    RemediationRunResult? batchResult = batches.Results.FirstOrDefault(r => r.PlanId == batches.Plans[i].PlanId);
                    if (batchResult is not null) await WriteAsync(zip, $"batches/{i + 1:D3}/result.json", batchResult, token);
                }
            }
            if (contentFollowUp is not null) await WriteAsync(zip, "content-follow-up.json", contentFollowUp, token);
            if (latestDiagnostics is not null) await WriteAsync(zip, "trust-proxy-diagnostics.json", latestDiagnostics, token);
            RelatedComponentDiagnosticReport? relatedDiagnostics = latestRelatedDiagnostics ?? scan.RelatedComponentDiagnostics;
            if (relatedDiagnostics is not null) await WriteAsync(zip, "related-components.json", relatedDiagnostics, token);
            if (persistedCase is not null) await WriteAsync(zip, "remediation-case.json", persistedCase, token);
            await using Stream stream = zip.CreateEntry("说明.txt").Open();
            await using StreamWriter writer = new(stream, new UTF8Encoding(false));
            await writer.WriteAsync(DisplayText.Format("CaseBundle.Readme", ProductInfo.Version).AsMemory(), token);
            await writer.WriteAsync(("\n\n" + DisplayText.Get("Report.OriginalTextNotice")).AsMemory(), token);
        }, token);
    }

    private static async Task WriteAsync<T>(ZipArchive zip, string name, T value, CancellationToken token)
    {
        await using Stream entry = zip.CreateEntry(name, CompressionLevel.Optimal).Open();
        await JsonSerializer.SerializeAsync(entry, value, ReportPrivacy.ExportOptions, token);
    }
}
