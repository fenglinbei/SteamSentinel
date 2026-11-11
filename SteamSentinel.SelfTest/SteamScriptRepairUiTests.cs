using System.Text.Json;
using System.Windows;
using System.Windows.Controls;
using SteamSentinel.App;
using SteamSentinel.App.Dialogs;
using SteamSentinel.Broker;
using SteamSentinel.Core.Models;
using SteamSentinel.Core.Remediation;
using SteamSentinel.Core.Reporting;
using SteamSentinel.Core.Utilities;

namespace SteamSentinel.SelfTest;

internal static partial class Program
{
    // Inert plans and hidden controls only. This fixture never starts the Broker or changes Steam.
    private static void TestSteamScriptRepairUi(string? output)
    {
        string originalHash = new('A', 64), repairedHash = new('B', 64);
        foreach (var culture in new[] { DisplayText.Chinese, DisplayText.English })
        {
            using IDisposable language = DisplayText.UseCulture(culture);
            RemediationAction source = new()
            {
                Type = RemediationActionType.QuarantineFile,
                Target = @"C:\Lab\SteamScriptUi\PWLoader.dll",
                DisplayName = "Inert downloader",
                ExpectedSha256 = new string('C', 64),
                IsKnownMalware = true
            };
            RemediationAction repair = new()
            {
                Type = RemediationActionType.RepairSteamScript,
                Target = @"C:\Lab\SteamScriptUi\steamui\sp.js",
                DisplayNameText = MessageText.Create("SteamScript.ActionName"),
                ExpectedSha256 = originalHash,
                RepairedSha256 = repairedHash,
                ExpectedFileIdentity = "inert-script-file",
                ExpectedParentIdentity = "inert-script-parent",
                DependsOnActionIds = [source.ActionId]
            };
            RemediationPlan plan = new() { Actions = [source, repair] };
            RemediationBatchSession batch = new() { Plans = [plan] };
            string unchanged = JsonSerializer.Serialize(batch, JsonFile.Options);
            foreach ((int width, int height) in new[] { (1148, 780), (784, 460) })
            {
                RemediationPreviewWindow preview = new(batch);
                try
                {
                    using UiLayoutHarness layout = new(preview, width, height);
                    CheckBox confirm = (CheckBox)preview.FindName("ConfirmCheckBox");
                    Button execute = (Button)preview.FindName("ExecuteButton");
                    DataGrid grid = (DataGrid)preview.FindName("PreviewActionsGrid");
                    grid.SelectedIndex = 1;
                    layout.Refresh();
                    RemediationActionDisplayItem shown = preview.Actions[1];
                    Check($"Steam script UI {culture.Name}/{width} repair follows component cleanup and retains both identities",
                        preview.Actions.Count == 2 && grid.Items.Count == 2 &&
                        shown.Type == DisplayText.Get("SteamScript.ActionName") &&
                        shown.Target == repair.Target && shown.Confidence == DisplayText.Get("SteamScript.PreviewEvidence") &&
                        shown.ExpectedIdentity.Contains(originalHash) && shown.ExpectedIdentity.Contains(repairedHash) &&
                        UiLayoutHarness.Descendants<TextBlock>(grid).Any(text =>
                            text.Text.Contains(originalHash) && text.Text.Contains(repairedHash)) &&
                        preview.NoticeText.Contains(DisplayText.Get("SteamScript.PreviewNotice")));
                    Check($"Steam script UI {culture.Name}/{width} repair uses the existing visible confirmation",
                        layout.IsFullyVisible(confirm) && layout.IsFullyVisible(execute) && !execute.IsEnabled &&
                        UiLayoutHarness.Descendants<CheckBox>(layout.Root).Count() == 1);
                    confirm.IsChecked = true;
                    layout.Refresh();
                    Check($"Steam script UI {culture.Name}/{width} confirmation preserves the plan and repair hash",
                        execute.IsEnabled && JsonSerializer.Serialize(batch, JsonFile.Options) == unchanged);
                    if (output is not null) layout.Save($"steam-script-preview-{culture.Name}-{width}x{height}", output);
                }
                finally { preview.Close(); }
            }

            BrokerConfirmationRow[] rows = BrokerConfirmationWindow.BuildRows(plan, null);
            Check($"Steam script UI {culture.Name} administrator confirmation includes target and both hashes",
                rows.Length == 2 && rows[1].Action == DisplayText.Get("SteamScript.ActionName") &&
                rows[1].Target == repair.Target && rows[1].Sha256.Contains(originalHash) &&
                rows[1].Sha256.Contains(repairedHash) && rows[1].Verification == DisplayText.Get("SteamScript.Confirmation"));
            using (BrokerConfirmationWindow confirmation = new(plan, null))
            {
                var panel = confirmation.Controls.OfType<System.Windows.Forms.TableLayoutPanel>().Single();
                var grid = panel.Controls.OfType<System.Windows.Forms.DataGridView>().Single();
                var detail = panel.Controls.OfType<System.Windows.Forms.RichTextBox>().Single();
                grid.CurrentCell = grid.Rows[1].Cells[0];
                Check($"Steam script UI {culture.Name} administrator details expose the full repair operation",
                    detail.Text.Contains(DisplayText.Get("SteamScript.Confirmation")) &&
                    detail.Text.Contains(originalHash) && detail.Text.Contains(repairedHash));
            }

            RemediationActionResult completed = new()
            {
                ActionId = repair.ActionId, Type = repair.Type, Target = repair.Target,
                Success = true, ExecutionStatus = RemediationExecutionStatus.Succeeded,
                VerificationStatus = RemediationVerificationStatus.Verified,
                MessageText = MessageText.Create("SteamScript.Repaired"),
                VerificationSummaryText = MessageText.Create("SteamScript.Verified")
            };
            RemediationActionResult incomplete = new()
            {
                ActionId = repair.ActionId, Type = repair.Type, Target = repair.Target,
                ExecutionStatus = RemediationExecutionStatus.SkippedDependency,
                VerificationStatus = RemediationVerificationStatus.Unknown,
                MessageText = MessageText.Create("SteamScript.RepairFailed"),
                VerificationSummaryText = MessageText.Create("SteamScript.VerificationUnavailable")
            };
            string completedText = RemediationResultPresentation.Describe(completed);
            string incompleteText = RemediationResultPresentation.Describe(incomplete);
            Check($"Steam script UI {culture.Name} results distinguish verified repair and skipped repair",
                completedText.Contains(DisplayText.Get("SteamScript.Repaired")) &&
                completedText.Contains(DisplayText.Get("SteamScript.Verified")) &&
                incompleteText.Contains(RemediationResultPresentation.ExecutionLabel(RemediationExecutionStatus.SkippedDependency)) &&
                incompleteText.Contains(DisplayText.Get("SteamScript.VerificationUnavailable")));
            batch.Results.Add(new() { PlanId = plan.PlanId, Actions = [completed] });
            batch.ExecutionFinished = true;
            Check($"Steam script UI {culture.Name} completion summary counts only verified repairs",
                MainWindow.SteamScriptRepairSummary(batch) == DisplayText.Format("SteamScript.ResultSummary", 1, 0));
            batch.Results[0].Actions.Clear();
            batch.Results[0].Actions.Add(incomplete);
            Check($"Steam script UI {culture.Name} skipped repairs remain incomplete in the summary",
                MainWindow.SteamScriptRepairSummary(batch) == DisplayText.Format("SteamScript.ResultSummary", 0, 1));

            ScanReport followUp = new()
            {
                Coverage = ScanCoverage.Complete,
                Findings =
                [
                    new() { RuleId = "STEAMALERT-UI-INJECTION", Category = FindingCategory.Steam },
                    new() { RuleId = "STEAM-UI-LOOPBACK-SCRIPT", Category = FindingCategory.Steam }
                ]
            };
            string summary = MainWindow.SystemFollowUpSummary(followUp);
            Check($"Steam script UI {culture.Name} follow-up retains confirmed and review-only script findings",
                summary.Contains(DisplayText.Get("Remediation.SystemFollowUpSummary.02")) &&
                summary.Contains(DisplayText.Get("SteamScript.FollowUpResidual")) &&
                summary.Contains(DisplayText.Get("SteamScript.FollowUpReview")));
        }
    }
}
