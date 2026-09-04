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
        RemediationBatchSession? batches = null, ScanReport? contentFollowUp = null)
    {
        await using FileStream output = new(destination, FileMode.Create, FileAccess.Write, FileShare.None);
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
        await using Stream stream = zip.CreateEntry("说明.txt").Open();
        await using StreamWriter writer = new(stream, new UTF8Encoding(false));
        await writer.WriteAsync(("SteamSentinel " + ProductInfo.Version + "\n" +
            "此包只包含记录，不包含被扫描文件、隔离样本或压缩包密码，也不会自动上传。\n" +
            "scan.json 为处置前扫描，plan.json 为用户确认的动作，result.json 为实际执行及复查结果。\n" +
            "follow-up.json 如存在，是后续定向复查，不代表全盘扫描。\n" +
            "batches.json 如存在，包含原始选择、未纳入目标和所有批次结果，batches/ 下保留每批独立计划及执行记录。\n" +
            "content-follow-up.json 是原扫描范围复查，follow-up.json 是单独的系统与 Steam 复查，两者不能互相替代。\n" +
            "缺少某个文件表示没有相应记录，不表示检查通过。动作成功不等于所有威胁已清除。\n" +
            "记录已过滤已识别的凭据字段，但仍可能包含用户名、路径和命令参数，转发前请核对。\n").AsMemory(), token);
    }

    private static async Task WriteAsync<T>(ZipArchive zip, string name, T value, CancellationToken token)
    {
        await using Stream entry = zip.CreateEntry(name, CompressionLevel.Optimal).Open();
        await JsonSerializer.SerializeAsync(entry, value, ReportPrivacy.ExportOptions, token);
    }
}
