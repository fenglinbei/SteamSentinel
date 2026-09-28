using System.IO;
using System.IO.Compression;
using System.Text.Json;
using System.Windows;
using System.Windows.Controls;
using SteamSentinel.App;
using SteamSentinel.App.Dialogs;
using SteamSentinel.Core.Models;
using SteamSentinel.Core.Reporting;
using SteamSentinel.Core.Utilities;

namespace SteamSentinel.SelfTest;

internal static partial class Program
{
    private const string Phase3CasePresentationSecret = "phase3-inert-case-secret-do-not-display";

    // Hidden STA layout only: no Loaded handler, persisted case read, Broker, or native session probe.
    private static void TestPhase3CaseUi(string? output)
    {
        foreach ((int width, int height) in new[] { (1148, 780), (784, 460) })
        {
            MainWindow window = new();
            try
            {
                using UiLayoutHarness layout = new(window, width, height);
                string viewport = $"{width}x{height}";
                SetTrustProxyUiReport(window, new() { CompletedAtUtc = DateTimeOffset.UtcNow });
                TabControl tabs = (TabControl)window.FindName("ResultTabs");
                tabs.SelectedIndex = 5;
                RemediationCaseRecord record = Phase3CaseUiFixture(CaseReverificationState.SessionUnknown);
                DisplayPhase3CaseUiFixture(window, record);
                layout.Refresh();
                TextBox details = (TextBox)window.FindName("CaseDetailsText");
                string[] buttons = ["CaseRefreshButton", "CaseRecheckButton", "CaseExportButton"];
                Check($"第三批病例UI {viewport} 已载入病例处于空闲状态且不残留初始化忙碌横幅",
                    typeof(MainWindow).GetField("_busy", TrustProxyUiPrivate)!.GetValue(window) is false &&
                    ((FrameworkElement)window.FindName("ActivityPanel")).Visibility == Visibility.Collapsed &&
                    buttons.All(name => ((Button)window.FindName(name)).IsEnabled));
                Check($"第三批病例UI {viewport} 第六页保留原标签次序且读取复验导出均可见",
                    tabs.Items.Count == 7 && tabs.Items[2] == window.FindName("BatchResultsTab") &&
                    tabs.Items[3] == window.FindName("TrustProxyTab") && tabs.Items[4] == window.FindName("RelatedComponentsTab") &&
                    tabs.Items[5] == window.FindName("CasesTab") && buttons.All(name => layout.IsFullyVisible((FrameworkElement)window.FindName(name))) &&
                    layout.IsFullyVisible((FrameworkElement)window.FindName("CaseListComboBox")));
                Check($"第三批病例UI {viewport} 长记录只读可复制换行且有可滚动阅读区域",
                    details.IsReadOnly && details.TextWrapping == TextWrapping.Wrap && details.AcceptsReturn &&
                    details.HorizontalScrollBarVisibility == ScrollBarVisibility.Disabled && details.ActualHeight >= 70 &&
                    layout.IsFullyVisible(details) && UiLayoutHarness.Descendants<ScrollViewer>(details).All(v => v.ScrollableWidth <= 1));
                FrameworkElement casePage = (FrameworkElement)((TabItem)window.FindName("CasesTab")).Content;
                Button[] caseButtons = UiLayoutHarness.Descendants<Button>(casePage).ToArray();
                Check($"第三批病例UI {viewport} 病例页没有旧计划执行按钮且不提供处理入口",
                    caseButtons.Length == 3 && caseButtons.Select(button => button.Content?.ToString()).OrderBy(s => s)
                        .SequenceEqual(new[] { UiExpected("读取病例", "Load cases"), UiExpected("复验所选病例", "Verify selected case"), UiExpected("导出病例", "Export case") }.OrderBy(s => s)) &&
                    TrustProxyUiButton(window, "RemediateButton").Visibility == Visibility.Collapsed &&
                    details.Text.Contains(UiExpected("旧计划不会重放", "Old plans are not replayed"), StringComparison.Ordinal) && details.Text.Contains(UiExpected("不是管理员处置授权", "does not authorize administrator actions"), StringComparison.Ordinal));
                Check($"第三批病例UI {viewport} 会话Unknown不显示为通过且来源仍未知",
                    details.Text.Contains(UiExpected("状态：会话身份未确认", "State: Session identity unconfirmed"), StringComparison.Ordinal) &&
                    details.Text.Contains(UiExpected("写入来源尚未证实", "The source of the writes remains unconfirmed"), StringComparison.Ordinal) &&
                    !details.Text.Contains(UiExpected("状态：所选目标跨会话复验通过", "State: Selected targets passed verification across sessions"), StringComparison.Ordinal) &&
                    !details.Text.Contains(Phase3CasePresentationSecret, StringComparison.Ordinal));
                if (output is not null) layout.Save("phase3-case-unknown-" + viewport, output);

                record = Phase3CaseUiFixture(CaseReverificationState.SelectedTargetsVerified);
                string originalResults = JsonSerializer.Serialize(record.ExecutionResults, JsonFile.Options);
                DisplayPhase3CaseUiFixture(window, record);
                layout.Refresh();
                Check($"第三批病例UI {viewport} 跨会话通过限定所选目标且不会改写原即时结果",
                    details.Text.Contains(UiExpected("状态：所选目标跨会话复验通过", "State: Selected targets passed verification across sessions"), StringComparison.Ordinal) &&
                    details.Text.Contains(UiExpected("写入来源尚未证实", "The source of the writes remains unconfirmed"), StringComparison.Ordinal) &&
                    !record.IsWholeMachineClear && !record.WriterIdentified && !record.MayReplaySavedPlans &&
                    originalResults == JsonSerializer.Serialize(record.ExecutionResults, JsonFile.Options));
                if (output is not null) layout.Save("phase3-case-verified-" + viewport, output);

                record.PendingPlanIds.Add(record.Plans[0].PlanId);
                DisplayPhase3CaseUiFixture(window, record);
                Check($"第三批病例UI {viewport} 新未决执行优先于历史通过episode",
                    details.Text.Contains(UiExpected("状态：执行结果未确定", "State: Execution outcome uncertain"), StringComparison.Ordinal) &&
                    !details.Text.Contains(UiExpected("状态：所选目标跨会话复验通过", "State: Selected targets passed verification across sessions"), StringComparison.Ordinal) &&
                    record.Episodes.Single().State == CaseReverificationState.SelectedTargetsVerified);

                record = Phase3CaseUiFixture(CaseReverificationState.Incomplete);
                record.Episodes[0].Targets.Add(new()
                {
                    PlanId = record.Plans[0].PlanId,
                    ActionId = Guid.NewGuid(),
                    Type = RemediationActionType.StopHostProcess,
                    Target = "PID 4242 / inert original start identity",
                    ExecutionSucceeded = true,
                    Status = RemediationVerificationStatus.NoResidual,
                    Message = "原 PID 已不存在；这里只核对原 PID 和启动时间，不排除新的进程实例、磁盘组件或重新写入来源。"
                });
                DisplayPhase3CaseUiFixture(window, record);
                layout.Refresh();
                Check($"第三批病例UI {viewport} 原PID消失仍展示新实例磁盘组件与写入来源限制",
                    details.Text.Contains(UiExpected("状态：复验不完整", "State: Reverification incomplete"), StringComparison.Ordinal) &&
                    details.Text.Contains("不排除新的进程实例、磁盘组件或重新写入来源", StringComparison.Ordinal) &&
                    record.Episodes[0].Targets.Last().IsOriginalProcessIdentityOnly);
                if (output is not null) layout.Save("phase3-case-old-pid-" + viewport, output);
            }
            finally { CloseSummaryFixture(window); }
        }

        RemediationPlan plan = Phase3CaseUiFixture(CaseReverificationState.NotChecked).Plans[0];
        foreach (bool batch in new[] { false, true })
        {
            RemediationPreviewWindow preview = batch ? new(new RemediationBatchSession { Plans = [plan] }) : new(plan);
            try
            {
                using UiLayoutHarness layout = new(preview, 600, 420);
                DataGrid grid = (DataGrid)preview.FindName("PreviewActionsGrid");
                grid.SelectedIndex = 1;
                layout.Refresh();
                RemediationActionDisplayItem dependent = preview.Actions[1];
                string dependency = plan.Actions[0].ActionId.ToString();
                Check("第三批病例UI " + (batch ? "批次" : "单计划") + "预览保留精确前置动作及顺序而不会提前启用执行",
                    dependent.ExpectedIdentity.Contains(UiExpected("仅在这些前置动作成功后执行", "Execute only after these prerequisite actions succeed"), StringComparison.Ordinal) &&
                    dependent.ExpectedIdentity.Contains(dependency, StringComparison.Ordinal) &&
                    dependent.ExpectedIdentity.Contains(new string('A', 64), StringComparison.Ordinal) &&
                    preview.Actions[0].Target == plan.Actions[0].Target && preview.Actions[1].Target == plan.Actions[1].Target &&
                    !((Button)preview.FindName("ExecuteButton")).IsEnabled &&
                    layout.IsFullyVisible((FrameworkElement)preview.FindName("ConfirmCheckBox")) &&
                    layout.IsFullyVisible((FrameworkElement)preview.FindName("ExecuteButton")));
                Check("第三批病例UI " + (batch ? "批次" : "单计划") + "选中行真实显示依赖说明且敏感原值不显示",
                    UiLayoutHarness.Descendants<TextBlock>(grid).Any(text => text.Text.Contains(UiExpected("仅在这些前置动作成功后执行", "Execute only after these prerequisite actions succeed"), StringComparison.Ordinal)) &&
                    !dependent.ExpectedIdentity.Contains(Phase3CasePresentationSecret, StringComparison.Ordinal));
                if (output is not null) layout.Save("phase3-case-preview-" + (batch ? "batch" : "single"), output);
            }
            finally { preview.Close(); }
        }
    }

    private static void DisplayPhase3CaseUiFixture(MainWindow window, RemediationCaseRecord record)
    {
        // Match the completed read/recheck display path without reading the real case store.
        Type listItemType = typeof(MainWindow).GetNestedType("CaseListItem", System.Reflection.BindingFlags.NonPublic)!;
        object selected = Activator.CreateInstance(listItemType, new RemediationCaseSummary
        {
            CaseId = record.CaseId,
            UserSid = record.UserSid,
            UpdatedAtUtc = record.UpdatedAtUtc,
            EpisodeCount = record.Episodes.Count,
            PendingExecutionCount = record.PendingPlanIds.Count,
            State = record.PendingPlanIds.Count > 0 ? CaseReverificationState.ExecutionUncertain : record.Episodes.LastOrDefault()?.State ?? CaseReverificationState.NotChecked
        })!;
        ComboBox list = (ComboBox)window.FindName("CaseListComboBox");
        list.ItemsSource = new[] { selected };
        list.SelectedItem = selected;
        window.DisplayCaseRecord(record);
        UiPreview.ApplyAccessState(window, InstallationSecurityStatus.Protected, new(false, true));
    }

    private static async Task TestPhase3CaseExportAsync(string root)
    {
        string directory = Path.Combine(root, "phase3-case-export");
        Directory.CreateDirectory(directory);
        string payloadPath = Path.Combine(directory, "inert-payload-never-executed.bin");
        string payloadMarker = "INERT-CASE-PAYLOAD-MUST-NOT-BE-BUNDLED-" + Guid.NewGuid().ToString("N");
        await File.WriteAllTextAsync(payloadPath, payloadMarker);
        RemediationCaseRecord record = Phase3CaseUiFixture(CaseReverificationState.SelectedTargetsVerified, payloadPath);
        record.Notes.Add("source=https://inert.invalid/case?token=" + Phase3CasePresentationSecret);
        record.OriginalScan = new()
        {
            CompletedAtUtc = DateTimeOffset.UtcNow,
            ContentScanSettings = record.OriginalContentSettings,
            Findings = [new() { Id = "phase3-original-finding", RuleId = "INERT-CASE-METADATA", Target = payloadPath,
                Description = "token=" + Phase3CasePresentationSecret }]
        };
        string before = JsonSerializer.Serialize(record, JsonFile.Options);
        string zipPath = Path.Combine(directory, "case-metadata.zip");
        await CaseBundleExporter.ExportAsync(zipPath, record.OriginalScan, record.Plans[0], record.ExecutionResults[0], null, persistedCase: record);
        using ZipArchive zip = ZipFile.OpenRead(zipPath);
        Dictionary<string, string> entries = [];
        foreach (ZipArchiveEntry entry in zip.Entries)
        {
            using StreamReader reader = new(entry.Open());
            entries.Add(entry.FullName, await reader.ReadToEndAsync());
        }
        RemediationCaseRecord? restored = JsonSerializer.Deserialize<RemediationCaseRecord>(entries["remediation-case.json"], JsonFile.Options);
        Check("第三批病例导出完整保存独立episode原范围与原执行结果并保持用户记录权限",
            restored?.CaseId == record.CaseId && restored.Plans[0].PlanId == record.Plans[0].PlanId &&
            restored.Episodes.Single().State == CaseReverificationState.SelectedTargetsVerified &&
            restored.ExecutionResults[0].Actions.Count == record.ExecutionResults[0].Actions.Count &&
            restored.OriginalScan?.Findings.Single().Id == "phase3-original-finding" &&
            JsonSerializer.Serialize(restored.OriginalContentSettings, JsonFile.Options) == JsonSerializer.Serialize(record.OriginalContentSettings, JsonFile.Options) &&
            !restored.IsWholeMachineClear && !restored.WriterIdentified && !restored.MayReplaySavedPlans &&
            restored.Authority == "UserOwnedReadOnlyRecordNotBrokerAuthorization");
        Check("第三批病例导出仅含记录且不打开或附带目标备份载荷",
            entries.Keys.OrderBy(s => s).SequenceEqual(new[] { "scan.json", "plan.json", "result.json", "remediation-case.json", "说明.txt" }.OrderBy(s => s)) &&
            entries.Values.All(value => !value.Contains(payloadMarker, StringComparison.Ordinal)) &&
            await File.ReadAllTextAsync(payloadPath) == payloadMarker &&
            entries["说明.txt"].Contains("不包含被扫描文件、隔离样本", StringComparison.Ordinal) &&
            entries["说明.txt"].Contains("不能重放其中计划", StringComparison.Ordinal));
        Check("第三批病例所有导出记录隐藏已识别凭据而不改写本地原记录",
            entries.Values.All(value => !value.Contains(Phase3CasePresentationSecret, StringComparison.Ordinal)) &&
            JsonSerializer.Serialize(record, JsonFile.Options) == before);
    }

    private static RemediationCaseRecord Phase3CaseUiFixture(CaseReverificationState state, string? file = null)
    {
        const string sid = "S-1-5-21-123-456-789-1001";
        DateTimeOffset time = new(2026, 9, 6, 0, 0, 0, TimeSpan.Zero);
        RemediationAction source = new()
        {
            Type = RemediationActionType.RemoveRegistryValue,
            Target = @"HKCU\Software\InertCaseFixture\Run\NeverExecuted",
            DisplayName = "无害前置来源定位",
            ExpectedValueData = "inert.exe token=" + Phase3CasePresentationSecret
        };
        RemediationAction component = new()
        {
            Type = RemediationActionType.QuarantineFile,
            Target = file ?? @"C:\InertCaseFixture\never-executed.dll",
            DisplayName = "无害关联文件定位",
            ExpectedSha256 = new string('A', 64),
            DependsOnActionIds = [source.ActionId]
        };
        RemediationPlan plan = new() { RequestedBySid = sid, CreatedAtUtc = time, ExpiresAtUtc = time.AddMinutes(15), Actions = [source, component] };
        RemediationRunResult run = new()
        {
            PlanId = plan.PlanId,
            StartedAtUtc = time.AddSeconds(1),
            CompletedAtUtc = time.AddMinutes(1),
            Success = true,
            Disposition = RemediationRunDisposition.Completed,
            Actions = plan.Actions.Select(action => new RemediationActionResult
            {
                ActionId = action.ActionId,
                Type = action.Type,
                Target = action.Target,
                Success = true,
                ExecutionStatus = RemediationExecutionStatus.Succeeded,
                VerificationStatus = RemediationVerificationStatus.NoResidual
            }).ToList()
        };
        return new()
        {
            UserSid = sid,
            CreatedAtUtc = time,
            UpdatedAtUtc = time.AddHours(2),
            Plans = [plan],
            ExecutionResults = [run],
            OriginalContentSettings = new()
            {
                Mode = ScanMode.Custom,
                IncludeSystem = false,
                IncludeSteam = false,
                IncludeWorkshop = false,
                CustomRoots = [@"C:\InertCaseFixture"],
                UseAmsi = false,
                HashEveryFile = true,
                InspectArchives = false
            },
            BaselineSession = new()
            {
                UserSid = sid,
                CapturedAtUtc = time,
                MachineName = "INERT-UI-CASE",
                BootStatus = DiagnosticReadStatus.Complete,
                LogonStatus = DiagnosticReadStatus.Complete,
                BootIdentity = "inert-boot-A",
                InteractiveLogonId = "inert-logon-A"
            },
            Episodes = [new()
            {
                StartedAtUtc = time.AddHours(2), CompletedAtUtc = time.AddHours(2).AddMinutes(1), State = state,
                Transition = state == CaseReverificationState.SelectedTargetsVerified ? CaseSessionTransition.NewBoot : CaseSessionTransition.Unknown,
                SelectedActionCount = 2, Summary = "无害 UI 记录：目标、完整范围与会话观察独立保留；写入来源尚未证实。",
                Checks = [new() { Name = "无害会话读取", Status = state == CaseReverificationState.SessionUnknown ? DiagnosticReadStatus.AccessDenied : DiagnosticReadStatus.Complete,
                    Detail = "仅为注入的显示记录，没有读取或更改系统配置。" }],
                Targets = [new() { PlanId = plan.PlanId, ActionId = component.ActionId, Type = component.Type, Target = component.Target,
                    ExecutionSucceeded = true, Status = RemediationVerificationStatus.NoResidual, Message = "无害精确目标观察，不构成整机安全结论。" }]
            }],
            Notes = ["token=" + Phase3CasePresentationSecret]
        };
    }
}
