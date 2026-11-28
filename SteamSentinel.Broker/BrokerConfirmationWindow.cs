using System.Globalization;
using System.Text;
using SteamSentinel.Core.Inspection;
using SteamSentinel.Core.Models;
using SteamSentinel.Core.Remediation;
using SteamSentinel.Core.Reporting;

namespace SteamSentinel.Broker;

internal sealed record BrokerConfirmationRow(string Action, string Target, string Verification, string Identity);

/// <summary>The ordinary final Broker confirmation, with every action available for review.</summary>
internal sealed class BrokerConfirmationWindow : Form
{
    internal BrokerConfirmationWindow(RemediationPlan plan, BrokerFileScopeAuthorization? prepared)
    {
        Text = DisplayText.Get("Scope.ConfirmationTitle");
        StartPosition = FormStartPosition.CenterScreen;
        AutoScaleMode = AutoScaleMode.Dpi;
        Font = new Font("Segoe UI", 10);
        MinimumSize = new Size(760, 500);
        Size = new Size(1080, 720);
        MinimizeBox = false;
        ShowInTaskbar = true;

        TableLayoutPanel layout = new() { Dock = DockStyle.Fill, ColumnCount = 1, RowCount = 5, Padding = new Padding(16) };
        layout.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        layout.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        layout.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 110));
        layout.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 48));
        bool hasSteamRepair = plan.Actions.Any(action => action.Type == RemediationActionType.RepairSteamConfiguration);
        string introText = RemediationModePresentation.Summary(plan) + Environment.NewLine +
            (plan.Mode == RemediationMode.Aggressive
                ? DisplayText.Get("RemediationMode.AggressiveNotice") + Environment.NewLine + DisplayText.Get("RemediationMode.ExactTargetsNotice")
                : DisplayText.Get("Scope.ConfirmationIntro") + " " + DisplayText.Get("Scope.Ui.PreviewNotice"));
        if (hasSteamRepair)
            introText += Environment.NewLine + DisplayText.Get("SteamConfig.AutoCloseSteamNotice");

        Label introduction = new()
        {
            Text = introText,
            ForeColor = plan.Mode == RemediationMode.Aggressive ? Color.FromArgb(154, 52, 18) : SystemColors.ControlText,
            AutoSize = true,
            Dock = DockStyle.Fill,
            Margin = new Padding(0, 0, 0, 12)
        };
        DataGridView grid = new()
        {
            Dock = DockStyle.Fill,
            ReadOnly = true,
            AllowUserToAddRows = false,
            AllowUserToDeleteRows = false,
            AllowUserToOrderColumns = false,
            AutoSizeColumnsMode = DataGridViewAutoSizeColumnsMode.Fill,
            RowHeadersVisible = false,
            SelectionMode = DataGridViewSelectionMode.FullRowSelect,
            MultiSelect = false,
            BackgroundColor = SystemColors.Window,
            BorderStyle = BorderStyle.FixedSingle,
            AccessibleName = DisplayText.Get("Scope.ConfirmationIntro")
        };
        grid.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = DisplayText.Get("Scope.ActionColumn"), FillWeight = 25, MinimumWidth = 130 });
        grid.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = DisplayText.Get("Scope.TargetColumn"), FillWeight = 50, MinimumWidth = 240 });
        grid.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = DisplayText.Get("Scope.VerificationColumn"), FillWeight = 25, MinimumWidth = 150 });
        RichTextBox detail = new() { Dock = DockStyle.Fill, ReadOnly = true, DetectUrls = false, WordWrap = true, Margin = new Padding(0, 8, 0, 8) };
        BrokerConfirmationRow[] rows = BuildRows(plan, prepared);
        foreach (BrokerConfirmationRow row in rows)
        {
            int index = grid.Rows.Add(row.Action, row.Target, row.Verification);
            grid.Rows[index].Cells[1].ToolTipText = row.Target;
            grid.Rows[index].Cells[2].ToolTipText = row.Verification;
        }
        void ShowSelection()
        {
            int index = grid.CurrentRow?.Index ?? -1;
            if (index >= 0 && index < rows.Length)
            {
                BrokerConfirmationRow row = rows[index];
                detail.Text = row.Action + Environment.NewLine + row.Target + Environment.NewLine + row.Verification +
                    (row.Identity.Length == 0 ? string.Empty : Environment.NewLine + row.Identity);
            }
        }
        grid.CurrentCellChanged += (_, _) => ShowSelection();
        string[] legacyTargets = plan.Actions.Where(action => action.Type is RemediationActionType.QuarantineFile or RemediationActionType.AddProgramFirewallBlock)
            .Select(action => Path.GetFullPath(action.Target)).Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
        int exactCount = prepared?.Targets.DistinctBy(target => target.FileIdentity, StringComparer.OrdinalIgnoreCase).Count() ?? legacyTargets.Length;
        int sensitiveCount = prepared?.Targets.Where(target => target.Sensitive)
            .DistinctBy(target => target.FileIdentity, StringComparer.OrdinalIgnoreCase).Count() ??
            legacyTargets.Count(path => FileScopeSafety.EvaluatePath(path).Sensitive);
        Label scope = new()
        {
            Text = DisplayText.Format("Scope.ConfirmationScope", exactCount, sensitiveCount),
            AutoSize = true,
            Dock = DockStyle.Fill,
            Margin = new Padding(0, 4, 0, 8)
        };
        FlowLayoutPanel buttons = new() { Dock = DockStyle.Fill, FlowDirection = FlowDirection.RightToLeft };
        Button cancel = new() { Text = DisplayText.Get("Scope.Cancel"), DialogResult = DialogResult.Cancel, AutoSize = true, MinimumSize = new Size(110, 34) };
        Button confirm = new() { Text = DisplayText.Get("Scope.Confirm"), DialogResult = DialogResult.OK, AutoSize = true, MinimumSize = new Size(110, 34) };
        buttons.Controls.Add(cancel);
        buttons.Controls.Add(confirm);
        CancelButton = cancel;
        // 禁止将 Cancel 设为 AcceptButton，防止用户按回车阅读表格时误取消高危确认。
        AcceptButton = null;
        layout.Controls.Add(introduction, 0, 0);
        layout.Controls.Add(grid, 0, 1);
        layout.Controls.Add(detail, 0, 2);
        layout.Controls.Add(scope, 0, 3);
        layout.Controls.Add(buttons, 0, 4);
        Controls.Add(layout);
        ConstrainToWorkingArea(Screen.FromPoint(Cursor.Position).WorkingArea);
        Shown += (_, _) =>
        {
            ConstrainToWorkingArea(Screen.FromControl(this).WorkingArea);
            ShowSelection();
            grid.Focus();
        };
        DpiChanged += (_, _) => ConstrainToWorkingArea(Screen.FromControl(this).WorkingArea);
    }

    internal void ConstrainToWorkingArea(Rectangle area)
    {
        if (area.Width <= 0 || area.Height <= 0) return;
        MinimumSize = Size.Empty;
        MaximumSize = area.Size;
        Size = new Size(Math.Min(Width, area.Width), Math.Min(Height, area.Height));
        MinimumSize = new Size(Math.Min(760, area.Width), Math.Min(500, area.Height));
        if (Controls.OfType<TableLayoutPanel>().FirstOrDefault() is { RowStyles.Count: > 2 } layout)
            layout.RowStyles[2].Height = Height < 600 ? 70 : 110;
        Location = new Point(Math.Clamp(Left, area.Left, Math.Max(area.Left, area.Right - Width)),
            Math.Clamp(Top, area.Top, Math.Max(area.Top, area.Bottom - Height)));
        PerformLayout();
    }

    internal static BrokerConfirmationRow[] BuildRows(RemediationPlan plan, BrokerFileScopeAuthorization? prepared)
    {
        Dictionary<Guid, VerifiedBrokerFileTarget> verified = prepared?.Targets.ToDictionary(target => target.ActionId) ?? [];
        return plan.Actions.Select(action =>
        {
            verified.TryGetValue(action.ActionId, out VerifiedBrokerFileTarget? file);
            // IsKnownMalware, display strings and confidence supplied by a client never become Broker proof.
            string verification = DisplayText.Get(file is null ? "Scope.ExistingAction" :
                file.Sensitive ? "Scope.VerifiedSensitiveFile" : "Scope.VerifiedFile");
            if (action.UserSelectedRisk)
                verification = DisplayText.Get("RemediationMode.BrokerRisk") + Environment.NewLine + verification;
            if (action.Type == RemediationActionType.RepairSteamConfiguration)
            {
                string description = action.ConfigurationKind switch
                {
                    SteamConfigurationRepair.Cfg => "SteamConfig.CfgDescription",
                    SteamConfigurationRepair.Marker => "SteamConfig.MarkerDescription",
                    SteamConfigurationRepair.UiFile => "SteamConfig.UiFileDescription",
                    SteamConfigurationRepair.PackageRestore => "SteamConfig.PackageRestoreDescription",
                    SteamConfigurationRepair.Run or SteamConfigurationRepair.Shortcut => "SteamConfig.ArgumentsDescription",
                    _ => "SteamConfig.InvalidTarget"
                };
                string repairVerification = DisplayText.Format("SteamConfig.PreviewIntent", DisplayText.Get(description));
                if (action.ConfigurationKind == SteamConfigurationRepair.PackageRestore)
                    repairVerification += Environment.NewLine + DisplayText.Get("SteamConfig.AutoCloseSteamNotice");
                return new BrokerConfirmationRow(ReportExporter.ActionLabel(action.Type), Sanitize(action.Target),
                    repairVerification,
                    Sanitize(RemediationCasePresentation.ActionIdentity(action)));
            }
            return new BrokerConfirmationRow(ReportExporter.ActionLabel(action.Type), Sanitize(action.Target), verification,
                file is null ? string.Empty : "SHA-256: " + file.Sha256);
        }).ToArray();
    }

    private static string Sanitize(string text)
    {
        StringBuilder output = new(text.Length);
        foreach (char value in text)
        {
            if (char.IsControl(value) || char.GetUnicodeCategory(value) == UnicodeCategory.Format)
                output.Append("\\u").Append(((int)value).ToString("X4", CultureInfo.InvariantCulture));
            else output.Append(value);
        }
        return output.ToString();
    }
}
