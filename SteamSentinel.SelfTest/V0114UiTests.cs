using System.IO;
using System.IO.Compression;
using System.Text.Json;
using SteamSentinel.App.Services;
using SteamSentinel.Core.Models;
using SteamSentinel.Core.Remediation;
using SteamSentinel.Core.Reporting;

namespace SteamSentinel.SelfTest;

internal static partial class Program
{
    private static async Task TestV0114UiAsync(string root)
    {
        string path = Path.Combine(root, "v0114-evidence-only.dat");
        await File.WriteAllTextAsync(path, "inert fixture, do not execute");
        Finding item = new() { Category = FindingCategory.Persistence, Target = "\"" + path + "\"", RelatedFilePath = path };
        Check("进一步检查能定位精确关联文件", FindingReviewTargets.Get(item).SequenceEqual([path]));
        Check("进一步检查不接受网络命令或 URL", FindingReviewTargets.Get(new() { Target = "https://example.invalid/a.exe" }).Count == 0);
        ScanReport before = new() { Coverage = ScanCoverage.Partial };
        before.Findings.Add(new() { Target = path, Evidence = "token=sample-secret" });
        RemediationPlan plan = new();
        RemediationRunResult result = new() { PlanId = plan.PlanId, Success = false };
        ScanReport after = new() { Coverage = ScanCoverage.Partial };
        string zipPath = Path.Combine(root, "v0114-case.zip");
        await CaseBundleExporter.ExportAsync(zipPath, before, plan, result, after);
        using ZipArchive zip = ZipFile.OpenRead(zipPath);
        Check("完整记录包包含前后扫描和实际计划结果", zip.Entries.Select(e => e.FullName).Order().SequenceEqual(new[]
            { "scan.json", "plan.json", "result.json", "follow-up.json", "说明.txt" }.Order()));
        using StreamReader reader = new(zip.GetEntry("scan.json")!.Open());
        string json = await reader.ReadToEndAsync();
        Check("记录包不复制目标内容并过滤已识别凭据", !json.Contains("sample-secret") && !json.Contains("inert fixture"));
        using StreamReader planReader = new(zip.GetEntry("plan.json")!.Open());
        using JsonDocument doc = JsonDocument.Parse(await planReader.ReadToEndAsync());
        Check("导出计划保留真实计划 ID", doc.RootElement.GetProperty("PlanId").GetGuid() == plan.PlanId);
        WorkerFailureException resource = new(WorkerStage.Scanning, 1, "ScanResourceLimitException: 文件数达到上限");
        WorkerFailureException oom = new(WorkerStage.Scanning, 1, "OutOfMemoryException");
        Check("安全上限和真正内存分配失败使用不同提示", resource.Message.Contains("不等于系统内存不足") && oom.Message.Contains("内存分配失败"));
    }
}
