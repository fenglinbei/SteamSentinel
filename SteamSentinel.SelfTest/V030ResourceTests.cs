using System.Collections;
using System.Globalization;
using System.IO;
using System.IO.Compression;
using System.Resources;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using SteamSentinel.App.Services;
using SteamSentinel.Core.Inspection;
using SteamSentinel.Core.Models;
using SteamSentinel.Core.Remediation;
using SteamSentinel.Core.Reporting;
using SteamSentinel.Core.Scanning;
using SteamSentinel.Core.Utilities;

namespace SteamSentinel.SelfTest;

internal static partial class Program
{
    private static async Task TestV030ResourcesAsync(string root)
    {
        CultureInfo zh = DisplayText.Chinese, en = DisplayText.English;
        bool HasHan(string text) => Regex.IsMatch(text, "[\\p{IsCJKUnifiedIdeographs}]");
        int pairs = 0;
        foreach (string catalog in new[] { "PresentationMessages", "StatusMessages" })
        {
            ResourceManager manager = new("SteamSentinel.Core.Reporting." + catalog, typeof(DisplayText).Assembly);
            Dictionary<string, string> Read(CultureInfo culture) => manager.GetResourceSet(culture, true, false)!
                .Cast<DictionaryEntry>().ToDictionary(e => (string)e.Key, e => (string)e.Value!, StringComparer.Ordinal);
            Dictionary<string, string> english = Read(CultureInfo.InvariantCulture), chinese = Read(zh);
            Check("资源 中英文键完整对应 " + catalog, english.Count > 0 && english.Keys.ToHashSet().SetEquals(chinese.Keys));
            List<string> problems = [];
            foreach ((string key, string value) in english)
            {
                if (string.IsNullOrWhiteSpace(value) || HasHan(value) || !chinese.TryGetValue(key, out string? other))
                { problems.Add(key); continue; }
                try
                {
                    CompositeFormat a = CompositeFormat.Parse(value), b = CompositeFormat.Parse(other);
                    string[] Placeholders(string template) => Regex.Matches(template, @"\{\d+(?:,[^}:]+)?(?::[^}]+)?\}")
                        .Select(m => m.Value).Order(StringComparer.Ordinal).ToArray();
                    if (a.MinimumArgumentCount != b.MinimumArgumentCount || !Placeholders(value).SequenceEqual(Placeholders(other))) problems.Add(key);
                    object[] arguments = Enumerable.Range(0, a.MinimumArgumentCount).Select(i => (object)new ResourceFormatProbe(i)).ToArray();
                    string renderedEn = string.Format(en, a, arguments), renderedZh = string.Format(zh, b, arguments);
                    if (Enumerable.Range(0, a.MinimumArgumentCount).Any(i => !renderedEn.Contains("ARG" + i) || !renderedZh.Contains("ARG" + i))) problems.Add(key);
                }
                catch (FormatException) { problems.Add(key); }
            }
            Check("资源 模板有效占位符格式与参数均保留 " + catalog + " " + string.Join(",", problems.Take(5)), problems.Count == 0);
            pairs += english.Count;
        }
        await JsonFile.WriteNewAsync(Path.Combine(root, "resource-catalog.json"), new { pairs, cultures = new[] { "en-US", "zh-Hans" } });

        Check("资源 默认仍为中文", HasHan(ReportExporter.SeverityLabel(FindingSeverity.Critical)));
        CultureInfo threadCulture = CultureInfo.CurrentCulture, threadUiCulture = CultureInfo.CurrentUICulture;
        async Task<string> ParallelRender(CultureInfo culture)
        {
            using IDisposable scope = DisplayText.UseCulture(culture);
            await Task.Yield();
            string first = ReportExporter.ActionLabel(RemediationActionType.QuarantineFile);
            using (DisplayText.UseCulture(culture == en ? zh : en)) { await Task.Yield(); }
            return first + "/" + ReportExporter.ActionLabel(RemediationActionType.QuarantineFile);
        }
        string[] parallel = await Task.WhenAll(ParallelRender(en), ParallelRender(zh));
        Check("资源 并行及嵌套渲染语言独立", parallel[0] == "Quarantine file/Quarantine file" && parallel[1] == "隔离文件/隔离文件" && DisplayText.Culture == zh);
        try { using IDisposable scope = DisplayText.UseCulture(en); throw new IOException("inert"); }
        catch (IOException) { }
        Check("资源 异常后恢复且不更改线程与系统区域设置", DisplayText.Culture == zh && CultureInfo.CurrentCulture == threadCulture && CultureInfo.CurrentUICulture == threadUiCulture);
        using (DisplayText.UseCulture(CultureInfo.GetCultureInfo("fr-FR")))
        {
            Check("资源 未支持语言回退英文", ReportExporter.SeverityLabel(FindingSeverity.Critical) == "Critical");
            Check("资源 未知键花括号不再作为模板解释", DisplayText.Format("future.{0}", "do-not-substitute") == "Unrecognized display resource: future.{0}");
            Check("资源 参数中的格式文本只显示一次", DisplayText.Format("Common.RawDetail", "{0:X8} C:\\AMSI\\已完成") == "Original record: {0:X8} C:\\AMSI\\已完成");
            Check("资源 缺参数回退为可读代码", DisplayText.Format("Container.Stages", "incomplete").Contains("Unrecognized display resource: Container.Stages"));
        }
        Check("资源 中文区域变体使用简体资源", ReportExporter.SeverityLabel(FindingSeverity.Critical, CultureInfo.GetCultureInfo("zh-TW")) == "严重");

        void Labels<T>(Func<T, CultureInfo, string> label) where T : struct, Enum => Check("资源 枚举显示覆盖 " + typeof(T).Name,
            Enum.GetValues<T>().All(v => !string.IsNullOrWhiteSpace(label(v, en)) && !HasHan(label(v, en)) && !label(v, en).Contains("Unrecognized display")));
        Labels<FindingSeverity>(ReportExporter.SeverityLabel);
        Labels<FindingCategory>(ReportExporter.CategoryLabel);
        Labels<RemediationActionType>(ReportExporter.ActionLabel);
        Labels<ScanCoverage>(ReportExporter.CoverageLabel);
        Labels<ContainerStageStatus>(ContainerReportPresentation.StatusLabel);
        Labels<ContentSignatureStatus>(ContainerReportPresentation.SignatureLabel);
        Labels<RemediationVerificationStatus>(RemediationVerification.Label);
        Labels<RemediationExecutionStatus>(RemediationResultPresentation.ExecutionLabel);
        Labels<RemediationRunDisposition>(RemediationResultPresentation.RunLabel);
        Labels<CaseReverificationState>(RemediationCasePresentation.Label);
        Labels<CaseSessionTransition>(RemediationResultPresentation.SessionLabel);
        Labels<AmsiVerdict>(AmsiPresentation.VerdictLabel);
        Check("资源 未知值不伪装信息完成或未执行", ReportExporter.CoverageLabel((ScanCoverage)999, en) == "Unknown state" &&
            ReportExporter.SeverityLabel((FindingSeverity)999, en) == "Unknown state" &&
            RemediationCasePresentation.Label((CaseReverificationState)999, en) == "Unknown state");

        Finding[] findings =
        [
            new() { RuleId = "inert.known", Title = "inert", Target = @"C:\fixture\a.bin", IsKnownMalware = true, CanRemediate = true },
            new() { RuleId = "inert.container", CanRemediate = true, ContentPath = "archive!/inner.bin", Target = "archive" },
            new() { RuleId = "inert.unsupported", HandlingReason = FindingHandlingReason.UnsupportedAction, HandlingDetails = "已完成 / failed" },
            new() { RuleId = "inert.blocked", HandlingReason = FindingHandlingReason.PrerequisiteNotMet },
            new() { RuleId = "NETWORK-PROXY-PRESENT" },
            new() { RuleId = "inert.info" }
        ];
        string before = JsonSerializer.Serialize(findings, JsonFile.Options);
        Check("资源 风险与资格跨语言相同且不解析原文", findings.All(f =>
        {
            FindingHandlingInfo a = FindingHandlingPresentation.Get(f, zh), b = FindingHandlingPresentation.Get(f, en);
            return a.Disposition == b.Disposition && a.CanSelect == b.CanSelect && a.Label != b.Label;
        }) && before == JsonSerializer.Serialize(findings, JsonFile.Options));
        Check("资源 原始处理说明单独标识并保留", FindingHandlingPresentation.Get(findings[2], en).Reason.Contains("Original record: 已完成 / failed") &&
            FindingHandlingPresentation.Get(findings[2], en).Disposition == FindingDisposition.Unsupported);

        ScanLimitSettings limits = new();
        foreach (ScanMode mode in new[] { ScanMode.Quick, ScanMode.Full })
            for (int index = 0; index < 5; index++)
            {
                string zhValues, enValues;
                using (DisplayText.UseCulture(zh)) { limits.UsePreset(mode, index); zhValues = JsonSerializer.Serialize(limits.Apply(new() { Mode = mode }), JsonFile.Options); }
                using (DisplayText.UseCulture(en)) { limits.UsePreset(mode, index); enValues = JsonSerializer.Serialize(limits.Apply(new() { Mode = mode }), JsonFile.Options); }
                Check($"资源 预算值与范围不随语言变化 {mode}/{index}", zhValues == enValues);
            }
        using (DisplayText.UseCulture(en))
            Check("资源 预算元数据不被首次中文访问固定", ScanLimitSettings.Presets[2] == "Medium" &&
                ScanLimitSettings.Fields.All(f => !HasHan(f.Label + f.Consequence + f.Unit)));
        Check("资源 预算元数据恢复中文", HasHan(ScanLimitSettings.Fields[0].Label));

        AmsiDiagnosticInfo diagnostic = new("AMSI-INITIALIZE-FAILED", AmsiOperation.Initialize,
            unchecked((int)0x80070103), unchecked((int)0x80070103), null, "X64", "Low");
        string diagBefore = JsonSerializer.Serialize(diagnostic);
        string diagEn = AmsiPresentation.Describe(diagnostic, en), diagZh = AmsiPresentation.Describe(diagnostic, zh);
        Check("资源 AMSI 保留阶段HRESULT架构权限与原因码", diagEn.Contains("0x80070103") && diagZh.Contains("0x80070103") &&
            diagEn.Contains("AMSI-INITIALIZE-FAILED") && diagEn.Contains("X64") && diagEn.Contains("Low") && !HasHan(diagEn) && diagBefore == JsonSerializer.Serialize(diagnostic));
        Check("资源 AMSI 未知代码不猜判定", AmsiPresentation.Describe(diagnostic with { Code = "future.unknown" }, en).Contains("no engine verdict is inferred"));
        using (DisplayText.UseCulture(en))
        using (AmsiScanner scanner = new(new V030AmsiApi { ScanResult = unchecked((int)0x80004005), Verdict = 32768 }))
        {
            AmsiScanResult result = scanner.Scan("inert"u8, "inert");
            string rendered = AmsiPresentation.Describe(result);
            Check("资源 AMSI 失败原始威胁值不能形成显示判定", result.Verdict == AmsiVerdict.Error && !rendered.Contains("Threat detected") && rendered.Contains("0x80004005"));
        }

        RemediationActionResult action = new()
        {
            Type = RemediationActionType.QuarantineFile,
            Target = @"C:\fixture\{0}.bin",
            Success = true,
            ExecutionStatus = RemediationExecutionStatus.Succeeded,
            VerificationStatus = RemediationVerificationStatus.PendingReboot,
            Message = "已完成",
            VerificationSummary = "verified / 已清除"
        };
        string actionJson = JsonSerializer.Serialize(action, JsonFile.Options);
        string actionEn = RemediationResultPresentation.Describe(action, en);
        Check("资源 逐动作执行成功与待重启验证保持独立", actionEn.Contains("Action executed successfully") && actionEn.Contains("Restart and reverify") &&
            actionEn.Contains("Original verification note: verified / 已清除") && actionJson == JsonSerializer.Serialize(action, JsonFile.Options));
        action.ExecutionStatus = RemediationExecutionStatus.ExecutionUnknown;
        Check("资源 未知执行结果不被成功布尔或说明改写", RemediationResultPresentation.Describe(action, en).Contains("Execution outcome unconfirmed"));
        DateTimeOffset started = DateTimeOffset.UtcNow;
        RemediationVerificationStatus[] Probe(CultureInfo culture)
        {
            using IDisposable scope = DisplayText.UseCulture(culture);
            return [WindowsRemediationStateProbe.AssessProcessIdentity(started, started.AddSeconds(1), true).Status,
                WindowsRemediationStateProbe.AssessHosts("# 0.0.0.0 inert.invalid\n:: inert.invalid", ["inert.invalid"]).Status];
        }
        Check("资源 实际观察的状态不随说明语言变化", Probe(zh).SequenceEqual(Probe(en)) && Probe(en).SequenceEqual([RemediationVerificationStatus.NoResidual, RemediationVerificationStatus.ResidualDetected]));
        WorkerFailureException worker;
        using (DisplayText.UseCulture(en)) worker = new(WorkerStage.Scanning, null, "OutOfMemoryException 已完成", reasonCode: ReasonCodes.ResourceLimit);
        using (DisplayText.UseCulture(en))
            Check("资源 Worker 建议按原因码生成英文而不解析错误原文", worker.ReasonCode == ReasonCodes.ResourceLimit &&
                MessageExceptions.Display(worker).Contains("safety limit") && !MessageExceptions.Display(worker).Contains("failed to allocate") &&
                worker.Message.Contains("OutOfMemoryException 已完成", StringComparison.Ordinal));

        ContainerScanReport container = new()
        {
            Complete = true,
            Nodes = [new() { DisplayPath = "inert.bin", OriginalTarget = "inert.bin", Format = "BIN", Overall = ContainerStageStatus.Complete,
                Recognition = ContainerStageStatus.Complete, Integrity = ContainerStageStatus.UnsupportedIntegrity, ContentCheck = ContainerStageStatus.Complete,
                Engines = [new() { Engine = "AMSI", Status = ContainerStageStatus.Failed, AmsiDiagnostics = diagnostic }] }]
        };
        string containerJson = JsonSerializer.Serialize(container, JsonFile.Options);
        string containerEn = ContainerReportPresentation.Describe(container, en);
        Check("资源 容器总体完成不能遮盖阶段缺口", containerEn.Contains("Integrity algorithm not supported") &&
            containerEn.Contains("Some content remains incomplete or unknown") && !ContainerReportPresentation.NodeComplete(container.Nodes[0]));
        Check("资源 容器英文说明及AMSI结构化诊断不改原证据", !HasHan(containerEn) && containerJson == JsonSerializer.Serialize(container, JsonFile.Options));
        await File.WriteAllTextAsync(Path.Combine(root, "container.en.txt"), containerEn);

        ScanReport report = new()
        {
            StatusSchemaVersion = ScanExecution.SchemaVersion,
            ExecutionState = ScanExecutionState.Completed,
            Coverage = ScanCoverage.Partial,
            CompletedAtUtc = DateTimeOffset.UtcNow,
            Containers = container,
            ContentScanSettings = new()
        };
        report.CoverageNotices.Add(new(ReasonCodes.AmsiUnavailable, "inert raw note"));
        report.TrustProxyDiagnostics = new(); report.RelatedComponentDiagnostics = new();
        string reportJson = JsonSerializer.Serialize(report, JsonFile.Options);
        string englishPath = Path.Combine(root, "report.en.md"), chinesePath = Path.Combine(root, "report.zh.md");
        await Task.WhenAll(ReportExporter.ExportMarkdownAsync(report, englishPath, en), ReportExporter.ExportMarkdownAsync(report, chinesePath, zh));
        string enReport = await File.ReadAllTextAsync(englishPath), zhReport = await File.ReadAllTextAsync(chinesePath);
        Check("资源 同一报告完整公共显示中英独立渲染", !HasHan(enReport) && !Regex.IsMatch(enReport, "[：；，。（）]") && enReport.Contains("some content was not checked") && zhReport.Contains("检查完整性") &&
            enReport.Contains("Total file hash budget") && enReport.Contains("Certificate and proxy diagnostics") && enReport.Contains("Component association inspection"));
        string enJson = Path.Combine(root, "report.en.json"), zhJson = Path.Combine(root, "report.zh.json");
        using (DisplayText.UseCulture(en)) await ReportExporter.ExportJsonAsync(report, enJson);
        using (DisplayText.UseCulture(zh)) await ReportExporter.ExportJsonAsync(report, zhJson);
        byte[] englishJsonBytes = await File.ReadAllBytesAsync(enJson), chineseJsonBytes = await File.ReadAllBytesAsync(zhJson);
        Check("资源 JSON逐字节不随渲染语言变化", englishJsonBytes.SequenceEqual(chineseJsonBytes) && reportJson == JsonSerializer.Serialize(report, JsonFile.Options));
        report.LegacyExecutionStatus = "旧版未完整检查";
        report.Findings.Add(new() { RuleId = "legacy", Title = "原始标题", Description = "原始记录说明", Evidence = "raw {0}", Target = "example" });
        string legacyPath = Path.Combine(root, "legacy.en.md");
        await ReportExporter.ExportMarkdownAsync(report, legacyPath, en);
        string legacyText = await File.ReadAllTextAsync(legacyPath);
        Check("资源 英文导出保留旧记录原文而不据此改状态", legacyText.Contains("Original status text (reference only): 旧版未完整检查") &&
            legacyText.Contains("原始标题") && report.ExecutionState == ScanExecutionState.Completed);
        Check("资源 病例解释不依赖中文计算字段", !HasHan(RemediationCasePresentation.Render(new RemediationCaseRecord(), en)));
        string bundlePath = Path.Combine(root, "bundle.en.zip");
        await CaseBundleExporter.ExportAsync(bundlePath, report, null, null, null, culture: en);
        using (ZipArchive zip = ZipFile.OpenRead(bundlePath))
        using (StreamReader reader = new(zip.GetEntry("说明.txt")!.Open()))
        {
            string readme = await reader.ReadToEndAsync();
            Check("资源 记录包说明可翻译且数据条目名不变", !HasHan(readme) && readme.Contains("not administrator authorization") &&
                zip.Entries.Select(e => e.FullName).Order().SequenceEqual(new[] { "scan.json", "说明.txt", "related-components.json" }.Order()));
        }
        await File.WriteAllTextAsync(Path.Combine(root, "action.en.txt"), actionEn);

        string file = Path.Combine(root, "locale-inert.bin");
        await File.WriteAllTextAsync(file, "A harmless localization scan fixture.");
        RuleSet rules = new() { KnownHashes = [new() { Id = "LOCALE-INERT", Sha256 = await Hashing.Sha256FileAsync(file), Label = "inert", Malware = true, Remediable = true }] };
        async Task<ScanReport> Inspect(CultureInfo culture)
        {
            using IDisposable scope = DisplayText.UseCulture(culture);
            using ContentScanner scanner = new(rules);
            ScanReport scanned = new();
            await scanner.ScanRootAsync(file, scanned, new() { Mode = ScanMode.Full, UseAmsi = false, InspectArchives = false, InspectDeepSignatures = false }, new NullPasswordProvider());
            return scanned;
        }
        ScanReport zhScan = await Inspect(zh), enScan = await Inspect(en);
        string Decision(ScanReport value) => JsonSerializer.Serialize(new
        {
            value.Coverage,
            Findings = value.Findings.Select(f => new
            { f.RuleId, f.Sha256, f.TargetSha256, f.Target, f.Severity, f.Score, f.IsKnownMalware, f.CanRemediate, f.HandlingReason, f.ReasonCode, f.SuggestedActions })
        });
        Check("资源 无害哈希夹具的规则命中身份严重度与动作集合相同", zhScan.Findings.Any(f => f.RuleId == "LOCALE-INERT") && Decision(zhScan) == Decision(enScan));
    }

    private sealed record ResourceFormatProbe(int Index) : IFormattable
    {
        public string ToString(string? format, IFormatProvider? formatProvider) => "ARG" + Index;
        public override string ToString() => "ARG" + Index;
    }

    private static async Task<int> RunV030ResourcesAsync(string root)
    {
        if (Directory.Exists(root) || File.Exists(root)) throw new IOException("A new inert resource-test directory is required.");
        Directory.CreateDirectory(root);
        try
        {
            await TestV030ResourcesAsync(root);
            await TestV030StatusAsync(root);
            await TestV030AmsiDiagnosticsAsync(root);
            TestV0119Copy();
            await TestV0114BrokerAsync(root);
            await TestV0114UiAsync(root);
            await TestV0117UiAsync(root);
            await TestScanLimitSettingsAsync(root);
            await TestV020ContainerExportAsync(root);
            await TestPhase2RelatedPresentationAsync(root);
            await TestPhase3DependenciesAsync(root);
            await TestPhase3CasesAsync(root);
            await TestPhase3CaseExportAsync(root);
        }
        catch (Exception ex) { Failures.Add(ex.ToString()); Console.Error.WriteLine(ex); }
        await JsonFile.WriteNewAsync(Path.Combine(root, "results.json"), new
        { passed = _passed, failed = Failures.Count, skipped = _skipped, failures = Failures, completedAtUtc = DateTimeOffset.UtcNow });
        Console.WriteLine($"RESOURCES_PASS={_passed};FAIL={Failures.Count};SKIP={_skipped}");
        return Failures.Count == 0 ? 0 : 1;
    }
}
