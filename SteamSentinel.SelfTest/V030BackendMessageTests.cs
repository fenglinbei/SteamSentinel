using System.IO;
using System.Text.Json;
using SteamSentinel.App.ViewModels;
using SteamSentinel.Core.Models;
using SteamSentinel.Core.Reporting;
using SteamSentinel.Core.Remediation;
using SteamSentinel.Core.Scanning;
using SteamSentinel.Core.Utilities;

namespace SteamSentinel.SelfTest;

internal static partial class Program
{
    private static async Task TestV030BackendMessagesAsync(string root)
    {
        MessageText produced;
        using (DisplayText.UseCulture(DisplayText.English)) produced = MessageText.Create("Ui.Language.Saved");
        string original = produced.OriginalText;
        Check("后台消息 来源原文不随生产线程语言变化", original.Contains("下次启动", StringComparison.Ordinal));
        using (DisplayText.UseCulture(DisplayText.English))
        {
            Finding labelTarget = new() { Category = FindingCategory.Coverage, TargetText = produced };
            var display = new FindingItemViewModel(labelTarget);
            CoverageEntry coverage = CoveragePresentation.Groups(new() { Findings = [labelTarget] }).Single().Entries.Single();
            Check("后台消息 目标说明显示英语但操作路径保留原值", display.TargetDisplay == DisplayText.Get("Ui.Language.Saved") &&
                display.Target == original && coverage.Target == original && coverage.TargetDisplay == display.TargetDisplay);
            Finding badTarget = new() { Target = "raw path", TargetMessage = new("bad id", []) };
            Check("后台消息 目标说明仍受消息边界校验", V020Throws<InvalidDataException>(() => badTarget.ValidateDisplayMessages()));
            RemediationCaseRecord noteCase = new();
            noteCase.AddNote(produced);
            Check("后台消息 病例备注按显示语言渲染", RemediationCasePresentation.Render(noteCase).Contains(DisplayText.Get("Ui.Language.Saved"), StringComparison.Ordinal) && noteCase.Notes.Single() == original);
        }
        Finding finding = new()
        {
            RuleId = "INERT",
            Severity = FindingSeverity.High,
            TitleText = produced,
            DescriptionText = MessageText.Create("Common.LabelValue", produced, "source {0} 密码=raw"),
            Evidence = "untouched evidence",
            CanRemediate = false,
            SuggestedActions = [SuggestedActionKind.ReviewOnly]
        };
        string source = JsonSerializer.Serialize(finding, JsonFile.Options);
        Finding received = JsonSerializer.Deserialize<Finding>(source, JsonFile.Options)!;
        Check("后台消息 原字段与可选描述均可往返", received.Title == original && received.TitleMessage?.MessageId == "Ui.Language.Saved");
        foreach (var culture in new[] { DisplayText.Chinese, DisplayText.English })
        {
            using IDisposable scope = DisplayText.UseCulture(culture);
            FindingItemViewModel item = new(received);
            Check("后台消息 真实视图按选择语言显示 " + culture.Name, item.Title == DisplayText.Get("Ui.Language.Saved") &&
                item.Description.Contains(item.Title, StringComparison.Ordinal) && item.Description.Contains("source {0}", StringComparison.Ordinal) && !item.CanSelect);
            Check("后台消息 显示不改动JSON与动作 " + culture.Name, source == JsonSerializer.Serialize(received, JsonFile.Options) &&
                received.Severity == FindingSeverity.High && received.SuggestedActions.SequenceEqual([SuggestedActionKind.ReviewOnly]));
        }
        Finding old = JsonSerializer.Deserialize<Finding>("{\"Title\":\"原记录\",\"Description\":\"completed\"}", JsonFile.Options)!;
        Check("后台消息 旧记录不增加空消息字段或推断资格", !JsonSerializer.Serialize(old, JsonFile.Options).Contains("TitleMessage", StringComparison.Ordinal) &&
            old.TitleText.Display == "原记录" && !new FindingItemViewModel(old).CanSelect);
        Check("后台消息 未知ID保留原文而不推断含义", MessageText.Render(new("future.message", []), "original completed") == "original completed");
        Check("后台消息 格式参数缺失保留原文", MessageText.Render(new("Common.LabelValue", []), "raw format") == "raw format");
        List<DisplayArgument> cyclicArguments = [];
        DisplayMessage cyclic = new("cycle", cyclicArguments);
        cyclicArguments.Add(new("raw", cyclic));
        DisplayMessage deep = new("level", []);
        for (int i = 0; i < DisplayMessage.MaximumDepth; i++) deep = new("level", [new("raw", deep)]);
        DisplayMessage wide = new("wide", Enumerable.Range(0, 8).Select(_ => new DisplayArgument("raw",
            new("branch", Enumerable.Range(0, 8).Select(_ => new DisplayArgument("raw", new("leaf", []))).ToArray()))).ToArray());
        DisplayMessage[] invalid = [new("", []), new(new string('x', 97), []), new("bad id", []),
            new("null", null!), new("nine", Enumerable.Repeat(new DisplayArgument("x"), 9).ToArray()),
            new("null.argument", [null!]), new("null.text", [new(null!)]), new("long", [new(new string('x', 4097))]),
            new("total", Enumerable.Repeat(new DisplayArgument(new string('x', 4096)), 4).ToArray()), cyclic, deep, wide];
        for (int i = 0; i < invalid.Length; i++)
        {
            Check("后台消息 越界描述拒绝 " + i, V020Throws<InvalidDataException>(() => invalid[i].Validate()));
            Check("后台消息 无效显示数据不覆盖原文 " + i, MessageText.Render(invalid[i], "untouched") == "untouched");
        }
        string oversized = new('x', 4097);
        MessageText fallback = MessageText.Create("Common.LabelValue", "label", oversized);
        Check("后台消息 超限参数仅省略显示描述且保留全部原文", fallback.Message is null && fallback.OriginalText.Contains(oversized, StringComparison.Ordinal));
        IOException exception = MessageExceptions.Create(produced, text => new IOException(text));
        using (DisplayText.UseCulture(DisplayText.English))
            Check("后台消息 本地异常保留原类型与原文", exception.GetType() == typeof(IOException) && exception.Message == original &&
                MessageExceptions.Display(exception) == DisplayText.Get("Ui.Language.Saved"));
        ScanProgress progress = new(produced, "inert", 3, 4, produced);
        ScanProgress progressReceived = JsonSerializer.Deserialize<ScanProgress>(JsonSerializer.Serialize(progress, JsonFile.Options), JsonFile.Options)!;
        using (DisplayText.UseCulture(DisplayText.English))
            Check("后台消息 进度经过序列化后显示英语而阶段原值不变", progressReceived.Stage == original &&
                progressReceived.DisplayStage == DisplayText.Get("Ui.Language.Saved") && progressReceived.Completed == 3);
        ScanReport report = new() { ExecutionState = ScanExecutionState.Completed, Coverage = ScanCoverage.Partial, Findings = [received] };
        List<ReportBatch> frames = [];
        new ReportBatchWriter(frames.Add).Send(report, true);
        ReportBatchReader reader = new();
        foreach (ReportBatch frame in frames) reader.Apply(JsonSerializer.Deserialize<ReportBatch>(JsonSerializer.Serialize(frame, JsonFile.Options), JsonFile.Options)!);
        Check("后台消息 Worker分片保留显示描述", reader.Report!.Findings.Single().TitleMessage?.MessageId == "Ui.Language.Saved");
        ScanReport invalidReport = new() { Findings = [new() { Title = "valid" }, new() { TitleMessage = invalid[0] }] };
        ReportBatchReader rejected = new();
        ReportBatch bad = new(0, new(0, 0, 0, 0, 0, 0, 0), invalidReport);
        Check("后台消息 坏分片在提交任何发现之前拒绝", V020Throws<InvalidDataException>(() => rejected.Apply(bad)) && rejected.Report is null && rejected.Count == 0);
        RemediationPlan plan = new();
        RemediationRunResult result = new()
        {
            PlanId = plan.PlanId,
            PlanIdentitySha256 = RemediationPlanIdentity.Fingerprint(plan),
            Disposition = RemediationRunDisposition.NotStarted,
            CompletedAtUtc = DateTimeOffset.UtcNow,
            Errors = ["raw refusal"],
            ErrorMessages = [invalid[0]]
        };
        Check("后台消息 受保护结果拒绝非法描述", V020Throws<InvalidDataException>(() => ProtectedRemediationResultReader.Validate(plan, result)));
        result.Errors[0] = produced.OriginalText;
        result.ErrorMessages = [produced.Message];
        ProtectedRemediationResultReader.Validate(plan, result);
        Check("后台消息 翻译不能把拒绝结果变为成功", !result.Success && result.Disposition == RemediationRunDisposition.NotStarted && result.Actions.Count == 0);
        result.ErrorMessages.Add(null);
        Check("后台消息 错误描述与原文必须一一对应", V020Throws<InvalidDataException>(() => ProtectedRemediationResultReader.Validate(plan, result)));
        string? previousJson = null;
        foreach (var culture in new[] { DisplayText.Chinese, DisplayText.English })
        {
            using IDisposable scope = DisplayText.UseCulture(culture);
            string jsonPath = Path.Combine(root, "backend-" + culture.Name + ".json");
            string markdownPath = Path.Combine(root, "backend-" + culture.Name + ".md");
            await ReportExporter.ExportJsonAsync(report, jsonPath);
            await ReportExporter.ExportMarkdownAsync(report, markdownPath, culture);
            string json = await File.ReadAllTextAsync(jsonPath);
            previousJson ??= json;
            Check("后台消息 双语导出JSON一致且Markdown使用资源 " + culture.Name, json == previousJson &&
                (await File.ReadAllTextAsync(markdownPath)).Contains(DisplayText.Get("Ui.Language.Saved"), StringComparison.Ordinal));
        }
        MessageText secret = MessageText.Create("Common.LabelValue", "data", "password=INERT-SECRET");
        string redacted = JsonSerializer.Serialize(new Finding { DescriptionText = secret }, ReportPrivacy.ExportOptions);
        Check("后台消息 参数中的敏感字符串沿用导出脱敏", !redacted.Contains("INERT-SECRET", StringComparison.Ordinal));
        await TestV030BackendFlowsAsync();
        TestV030ReportMessageMaps();
        await TestV030ProducerLocalizationAsync(root);
        TestV030ArchiveMessageFlows();
        TestV030RelatedMessageFlows();
        TestV030TrustMessages();
    }

    private static async Task TestV030BackendFlowsAsync()
    {
        var previous = DisplayText.ApplicationCulture;
        try
        {
            Check("后台消息 Broker拒绝语言参数注入", !SteamSentinel.Broker.Program.TryInitializeDisplayLanguage(["plan", "hash", "--ui-language", "en --other"]));
            Check("后台消息 Broker接受明确当前英语", SteamSentinel.Broker.Program.TryInitializeDisplayLanguage(["plan", "hash", "--ui-language", "en"]) && DisplayText.ApplicationCulture == DisplayText.English);
            using (DisplayText.UseCulture(DisplayText.English))
            {
                string deletion = SteamSentinel.Broker.Program.BuildConfirmationMessage(new() { Actions = [new() { Type = RemediationActionType.DeleteIncident, Target = "inert" }] });
                string rollback = SteamSentinel.Broker.Program.BuildConfirmationMessage(new() { Actions = [new() { Type = RemediationActionType.RollbackIncident, Target = "inert" }] });
                Check("后台消息 英语管理员确认保留不可撤销和重新启用提示", deletion.Contains("cannot be undone", StringComparison.Ordinal) && deletion.Contains("Do not restore suspicious samples", StringComparison.Ordinal) && rollback.Contains("reactivate", StringComparison.Ordinal) && rollback.Contains("whole-directory", StringComparison.Ordinal));
            }
            MessageText detail = MessageText.Create("Backend.Worker.Program.Main.01");
            SteamSentinel.App.Services.WorkerFailureException worker = new(SteamSentinel.App.Services.WorkerStage.Handshake,
                unchecked((int)0xC0000142), detail, reasonCode: ReasonCodes.WorkerStartFailed);
            string workerOriginal = worker.Message;
            using (DisplayText.UseCulture(DisplayText.English))
            {
                string displayed = MessageExceptions.Display(worker);
                Check("后台消息 Worker失败保留原文与十六进制退出码", workerOriginal.Contains("工作进程", StringComparison.Ordinal) && displayed.Contains("valid start request", StringComparison.Ordinal) && displayed.Contains("C0000142", StringComparison.Ordinal) && worker.ReasonCode == ReasonCodes.WorkerStartFailed && worker.BeforeScan);
            }
            RemediationPlan plan = new()
            {
                Actions = [new() { Type = RemediationActionType.BlockKnownDomains, Target = "inert-a" },
                new() { Type = RemediationActionType.BlockKnownDomains, Target = "inert-b" }]
            };
            string typedIdentity = RemediationPlanIdentity.Fingerprint(plan);
            var edited = System.Text.Json.Nodes.JsonNode.Parse(JsonSerializer.Serialize(plan, JsonFile.Options))!;
            edited["Actions"]![0]!["DisplayNameMessage"] = JsonSerializer.SerializeToNode(detail.Message, JsonFile.Options);
            Check("后台消息 显示描述不改变类型化计划身份", RemediationPlanIdentity.Fingerprint(edited.Deserialize<RemediationPlan>(JsonFile.Options)!) == typedIdentity);
            edited["Actions"]![0]!["Target"] = "inert-other";
            Check("后台消息 目标变化仍改变类型化计划身份", RemediationPlanIdentity.Fingerprint(edited.Deserialize<RemediationPlan>(JsonFile.Options)!) != typedIdentity);
            RemediationRunResult run = new();
            int executed = 0;
            await SteamSentinel.Broker.BrokerActionSequencer.RunLocalizedAsync(plan, run, new Dictionary<Guid, MessageText>(),
                (action, _) =>
                {
                    executed++;
                    if (action == plan.Actions[1]) throw MessageExceptions.Win32(5, detail);
                    return Task.FromResult(MessageText.Create("Backend.Broker.BrokerBoundActions.StopHostAsync.03"));
                }, (_, _, _) => Task.CompletedTask, _ => Task.CompletedTask);
            RemediationRunResult roundTrip = JsonSerializer.Deserialize<RemediationRunResult>(JsonSerializer.Serialize(run, JsonFile.Options), JsonFile.Options)!;
            using (DisplayText.UseCulture(DisplayText.English))
            {
                Check("后台消息 生产Broker循环传递成功与失败描述", executed == 2 && roundTrip.Actions[0].Success && roundTrip.Actions[0].ExecutionStatus == RemediationExecutionStatus.Succeeded && !roundTrip.Actions[1].Success && roundTrip.Actions[1].ExecutionStatus == RemediationExecutionStatus.Failed && roundTrip.Actions[0].MessageText.Display.Contains("host process", StringComparison.Ordinal) && roundTrip.Actions[1].MessageText.Display.Contains("valid start request", StringComparison.Ordinal) && roundTrip.DisplayErrors.Single().Contains("valid start request", StringComparison.Ordinal));
            }
            RemediationVerification verification = new(new V030MessageProbe());
            RemediationActionResult actionResult = new() { Success = true, ExecutionStatus = RemediationExecutionStatus.Succeeded };
            await verification.ObserveAsync(plan.Actions[0], actionResult, 1);
            await verification.ObserveAsync(plan.Actions[0], actionResult, 2);
            using (DisplayText.UseCulture(DisplayText.English))
                Check("后台消息 复验重新出现状态独立于译文且保留描述", actionResult.VerificationStatus == RemediationVerificationStatus.Reappeared && actionResult.Verifications.Count == 2 && actionResult.VerificationSummaryMessage is not null && actionResult.VerificationSummaryText.Display.Contains("valid start request", StringComparison.Ordinal) && actionResult.Message == "");
        }
        finally { DisplayText.InitializeApplicationCulture(previous); }
    }

    private sealed class V030MessageProbe : IRemediationStateProbe
    {
        private int _pass;
        public Task<RemediationVerificationObservation> ObserveAsync(RemediationAction action, CancellationToken cancellationToken) =>
            Task.FromResult(new RemediationVerificationObservation
            {
                Status = ++_pass == 1 ? RemediationVerificationStatus.NoResidual : RemediationVerificationStatus.ResidualDetected,
                MessageText = MessageText.Create("Backend.Worker.Program.Main.01")
            });
    }

    private static void TestV030ReportMessageMaps()
    {
        ScanReport report = new();
        for (int i = 0; i < 70; i++)
        {
            report.AddCoverageNote(MessageText.Create("Backend.Core.ScanCoordinator.RunAsync.23", "inert-" + i));
            report.AddScopeNote(MessageText.Create("Backend.Core.ScanCoordinator.RunAsync.30", "inert-" + i));
            report.AddContentSource(MessageText.Create("Backend.Core.ScanCoordinator.RunAsync.29", "inert-" + i));
        }
        List<ReportBatch> frames = [];
        ReportBatchWriter writer = new(frames.Add);
        writer.Send(report);
        ReportBatchReader reader = new();
        foreach (ReportBatch frame in frames) reader.Apply(JsonSerializer.Deserialize<ReportBatch>(JsonSerializer.Serialize(frame, JsonFile.Options), JsonFile.Options)!);
        using (DisplayText.UseCulture(DisplayText.English))
            Check("后台消息 多批次索引对齐并保留三类说明", reader.Count == 2 && reader.Report!.CoverageTexts.Last().Display.Contains("inert-69", StringComparison.Ordinal) && reader.Report.CoverageTexts.Last().Display.Contains("safely", StringComparison.Ordinal) && reader.Report.ScopeNoteMessages?.Count == 70 && reader.Report.ContentSourceMessages?.Count == 70);
        int before = reader.Count;
        ScanReport malformed = new() { ScanId = report.ScanId, CoverageNotes = ["raw"], CoverageNoteMessages = new() { [-1] = new("Backend.List.1", [new("bad")]) } };
        Check("后台消息 非法说明索引在分片提交前拒绝", V020Throws<InvalidDataException>(() => reader.Apply(new(before, new(0, 0, 0, 0, 0, 0, 0), malformed))) && reader.Count == before && reader.Report!.CoverageNotes[0] == report.CoverageNotes[0]);
        report.CoverageNotes[0] = "legacy source replacement";
        Check("后台消息 旧调用方直接改写列表原文自动丢弃旧描述", report.CoverageNoteMessages?.ContainsKey(0) == false);
        frames.Clear(); writer.Send(report, true);
        foreach (ReportBatch frame in frames) reader.Apply(frame);
        Check("后台消息 完成帧重放删除被替换原文的旧描述", !reader.Report!.CoverageNoteMessages!.ContainsKey(0) && reader.Report.CoverageTexts.First().Display == "legacy source replacement" && reader.Report.CoverageNoteMessages.Count == 69);
        ScanReport merged = ScanReportMerger.Merge(new(), reader.Report);
        Check("后台消息 合并保留说明描述而旧JSON不增加空字段", merged.ScopeNoteMessages?.Count == 70 && !JsonSerializer.Serialize(new ScanReport(), JsonFile.Options).Contains("ScopeNoteMessages", StringComparison.Ordinal));
        using (DisplayText.UseCulture(DisplayText.English))
        {
            for (int count = 1; count <= 8; count++)
            {
                MessageText list = MessageText.List(Enumerable.Range(0, count).Select(i => (MessageText)("item" + i)));
                Check("后台消息 有界列表组合 " + count, list.Message is not null && list.Display == string.Join("; ", Enumerable.Range(0, count).Select(i => "item" + i)));
            }
            MessageText redacted = MessageText.Create("Common.LabelValue", "source", "password=INERT-INTERNAL-SECRET").RedactSecrets();
            Check("后台消息 内部脱敏同时处理原文和显示参数", redacted.Message is not null && !redacted.Display.Contains("INERT-INTERNAL-SECRET", StringComparison.Ordinal) && !JsonSerializer.Serialize(redacted, JsonFile.Options).Contains("INERT-INTERNAL-SECRET", StringComparison.Ordinal));
            MessageText numeric = MessageText.Create("Backend.Core.ProxyConfigurationScanner.NativeFailure.01") + 123;
            Check("后台消息 数字拼接仍保留翻译描述", numeric.Message is not null && !numeric.Display.Any(c => c is >= '\u4e00' and <= '\u9fff'));
            MessageText status = MessageText.Status(ReasonCodes.PlanExpired);
            Check("后台消息 状态资源复用且原文固定为中文", status.Message is not null && status.Display == StatusPresentation.Text(ReasonCodes.PlanExpired) &&
                status.OriginalText == StatusPresentation.Text(ReasonCodes.PlanExpired, DisplayText.Chinese));
        }
        MessageText label = MessageText.Create("Ui.Language.Saved");
        string descriptorFirst = "{\"TitleMessage\":" + JsonSerializer.Serialize(label.Message, JsonFile.Options) +
            ",\"Title\":" + JsonSerializer.Serialize(label.OriginalText) + "}";
        Finding reordered = JsonSerializer.Deserialize<Finding>(descriptorFirst, JsonFile.Options)!;
        Check("后台消息 描述先于原文字段仍正确往返", reordered.TitleMessage?.MessageId == label.Message?.MessageId);
        RemediationRunResult errors = new(); errors.AddError(label); errors.Errors[0] = "legacy replacement";
        Check("后台消息 旧调用方改写错误原文不保留旧描述", errors.ErrorMessages is null && errors.DisplayErrors.Single() == "legacy replacement");
        TestV030ConfigurationMessageIdentity();
    }

    private static void TestV030ConfigurationMessageIdentity()
    {
        MessageText detail = MessageText.Create("Backend.Core.WindowsBoundProxySettings.ReadPolicyGuard.Unmanaged.01");
        BoundProxyPolicyGuard Guard(bool described) => new()
        { Status = BoundProxyPolicyStatus.Unmanaged, Fingerprint = new string('A', 64), Detail = detail.OriginalText, DetailMessage = described ? detail.Message : null };
        RemediationAction Action(bool described) => new()
        {
            Type = RemediationActionType.RestoreBoundProxyConfiguration,
            Target = "inert",
            BoundProxy = new()
            {
                TargetUserSid = "S-1-5-21-100-200-300-1001",
                ChangedFields = [BoundProxyField.Flags],
                Before = new() { Flags = 1, PolicyGuard = Guard(described) },
                Desired = new() { Flags = 3, PolicyGuard = Guard(described) }
            }
        };
        RemediationAction plain = Action(false);
        RemediationPlan plan = new() { Actions = [plain] };
        string fingerprint = RemediationPlanIdentity.Fingerprint(plan), ruleIdentity = BoundConfigurationEvidenceCatalog.IdentityFingerprint(plain);
        var node = System.Text.Json.Nodes.JsonNode.Parse(JsonSerializer.Serialize(plan, JsonFile.Options))!;
        foreach (string snapshot in new[] { "Before", "Desired" })
            node["Actions"]![0]!["BoundProxy"]![snapshot]!["PolicyGuard"]!["DetailMessage"] = JsonSerializer.SerializeToNode(detail.Message, JsonFile.Options);
        RemediationPlan described = node.Deserialize<RemediationPlan>(JsonFile.Options)!;
        Check("后台消息 代理策略说明不改变计划和精确规则身份", fingerprint == RemediationPlanIdentity.Fingerprint(described) &&
            ruleIdentity == BoundConfigurationEvidenceCatalog.IdentityFingerprint(described.Actions[0]));
        node["Actions"]![0]!["BoundProxy"]!["Desired"]!["Flags"] = 5;
        RemediationPlan changed = node.Deserialize<RemediationPlan>(JsonFile.Options)!;
        Check("后台消息 代理实际期望值改变仍改变两种身份", fingerprint != RemediationPlanIdentity.Fingerprint(changed) &&
            ruleIdentity != BoundConfigurationEvidenceCatalog.IdentityFingerprint(changed.Actions[0]));
    }

    private static async Task TestV030ProducerLocalizationAsync(string root)
    {
        string directory = Path.Combine(root, "message-producers");
        Directory.CreateDirectory(directory);
        string file = Path.Combine(directory, "inert-markers.txt");
        await File.WriteAllTextAsync(file, "steam_save_mafile steam_outbox_list /api/v1/plugin/beacon password");
        var embedded = SteamSentinel.Core.Rules.RuleLoader.LoadEmbedded();
        HashRule sourceRule = embedded.KnownHashes.First();
        RuleSet rules = new()
        {
            KnownHashes = [new() { Id = "INERT-MESSAGE-HASH", Sha256 = await Hashing.Sha256FileAsync(file),
            Label = sourceRule.Label, LabelMessage = sourceRule.LabelMessage, Evidence = sourceRule.Evidence, EvidenceMessage = sourceRule.EvidenceMessage }]
        };
        string? previous = null;
        foreach (var culture in new[] { DisplayText.Chinese, DisplayText.English })
        {
            using IDisposable scope = DisplayText.UseCulture(culture);
            ScanReport report = new();
            using ContentScanner scanner = new(rules);
            await scanner.ScanRootAsync(file, report, ContentOptions(), new NullPasswordProvider(), null, CancellationToken.None);
            Finding known = report.Findings.Single(finding => finding.RuleId == "INERT-MESSAGE-HASH");
            string decisions = JsonSerializer.Serialize(report.Findings.OrderBy(finding => finding.RuleId).Select(finding =>
                new { finding.RuleId, finding.Sha256, finding.IsKnownMalware, finding.CanRemediate, finding.Severity, finding.SuggestedActions }), JsonFile.Options);
            previous ??= decisions;
            Check("后台消息 真实扫描规则说明保留描述且判定跨语言一致 " + culture.Name,
                known.TitleMessage is not null && known.DescriptionMessage is not null && known.EvidenceMessage is not null && decisions == previous &&
                known.TitleText.Display == MessageText.Render(sourceRule.LabelMessage, sourceRule.Label));
        }
        using (DisplayText.UseCulture(DisplayText.English))
        {
            Check("后台消息 内置规则全部可显示英语且匹配数据完整", embedded.KnownHashes.All(rule => rule.LabelMessage is not null && rule.LabelText.Display.Length > 0 && !V030HasHan(rule.LabelText.Display)) &&
                embedded.KnownHashes.Where(rule => rule.Evidence is not null).All(rule => rule.EvidenceMessage is not null && !V030HasHan(rule.EvidenceText!.Display)) &&
                embedded.SuspiciousStrings.All(rule => rule.LabelMessage is not null && !V030HasHan(rule.LabelText.Display)));
            List<MessageText> signals = SteamSecurityScanner.AnalyzeSteamUiMessages("function BHasActiveSupportAlerts(){return true;}");
            Check("后台消息 Steam语义说明沿稳定资源显示", signals.Count == 1 && signals[0].Message is not null && signals[0].Display.Contains("Support alert state", StringComparison.Ordinal) && !V030HasHan(signals[0].Display));
            ScanProgress progress = new(MessageText.Create("Backend.Core.SystemScanner.ScanAsync.01"), MessageText.Create("Backend.Core.SystemScanner.ScanAsync.02"), 0, null, MessageText.Create("Backend.Core.SystemScanner.ScanAsync.03"));
            ScanProgress roundTrip = JsonSerializer.Deserialize<ScanProgress>(JsonSerializer.Serialize(progress, JsonFile.Options), JsonFile.Options)!;
            Check("后台消息 系统进度项目名称跨进程保留描述", roundTrip.CurrentItemMessage is not null && roundTrip.DisplayCurrentItem == "Active processes" && roundTrip.CurrentItem == "活动进程");
        }
    }

    private static bool V030HasHan(string text) => text.Any(character => character is >= '\u4e00' and <= '\u9fff');

    private static async Task<int> RunV030BackendMessagesAsync(string root)
    {
        if (Directory.Exists(root) || File.Exists(root)) throw new IOException("Use a new backend-message test directory.");
        Directory.CreateDirectory(root);
        try
        {
            await TestV030BackendMessagesAsync(root);
            await TestPhase3ConfigurationBrokerAsync();
            await TestPhase2MsiAsync(root, Core.Rules.RuleLoader.LoadEmbedded());
            TestPhase2Discovery(); TestPhase2SourceBounds(); TestPhase2RelatedBatch();
            await TestPhase2PipelineAsync(root); await TestPhase2RelatedSignatureAsync(root);
            await TestPhase2RelatedPresentationAsync(root);
            TestTrustProxyProxy(); TestTrustProxyCertificates(); TestTrustProxyBatch();
            await TestTrustProxyDiagnosticsAsync(root);
            await TestPhase3CasesAsync(root); await TestPhase3CaseExportAsync(root);
        }
        catch (Exception ex) { Failures.Add(ex.ToString()); }
        await JsonFile.WriteNewAsync(Path.Combine(root, "results.json"), new
        { passed = _passed, failed = Failures.Count, failures = Failures, completedAtUtc = DateTimeOffset.UtcNow });
        Console.WriteLine($"BACKEND_MESSAGES_PASS={_passed};FAIL={Failures.Count}");
        foreach (string failure in Failures) Console.Error.WriteLine(failure);
        return Failures.Count == 0 ? 0 : 1;
    }
}
