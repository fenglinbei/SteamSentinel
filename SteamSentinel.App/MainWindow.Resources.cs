using System.Windows;
using System.Text.Json;
using SteamSentinel.App.Dialogs;
using SteamSentinel.App.Services;
using SteamSentinel.Core.Models;
using SteamSentinel.Core.Scanning;

namespace SteamSentinel.App;

public partial class MainWindow
{
    private Task<ScanLimitResponse> RequestResourcesAsync(ScanResourceProposal proposal, CancellationToken token) =>
        Dispatcher.InvokeAsync(() =>
        {
            token.ThrowIfCancellationRequested();
            ScanResourceDialog dialog = new(proposal) { Owner = this };
            using CancellationTokenRegistration registration = token.Register(() => Dispatcher.BeginInvoke(new Action(() => { if (dialog.IsVisible) dialog.Close(); })));
            dialog.ShowDialog();
            token.ThrowIfCancellationRequested();
            if (dialog.SaveForFuture) _resourceSaveChoices.Add(proposal.Request.RequestId);
            return new ScanLimitResponse(proposal.Request.RequestId, dialog.Decision,
                dialog.Decision == ResourceDecisionKind.Approve ? [.. proposal.Changes] : []);
        }).Task;
    private ScanMode _resourceScanMode;
    private readonly HashSet<string> _resourceSaveChoices = [];
    private void SaveResourceChoices(ScanReport? report)
    {
        if (report?.ResourceAudit is not { } audit || _resourceSaveChoices.Count == 0) return;
        ScanLimitSettings saved = JsonSerializer.Deserialize<ScanLimitSettings>(JsonSerializer.Serialize(_scanLimits))!;
        bool changed = false;
        foreach (ScanResourceDecision decision in audit.Decisions.Where(d => d.Decision == ResourceDecisionKind.Approve && _resourceSaveChoices.Contains(d.Request.RequestId)))
            foreach (ScanLimitChange change in decision.Changes)
            {
                ScanLimitDefinition field = ScanLimitAccess.Definition(change.LimitKey);
                saved.For(_resourceScanMode)[change.LimitKey] = change.After / field.Scale; changed = true;
            }
        if (!changed) return;
        try { ScanSettingsStore.Save(ScanSettingsStore.DefaultPath, saved); _scanLimits = saved; }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or InvalidDataException)
        {
            AppErrorLog.Write("SaveResourceGrant", exception);
            if (!_closeWhenIdle) MessageBox.Show(this, Core.Reporting.DisplayText.Get("Resource.SaveFailed"), Core.Reporting.DisplayText.Get("Resource.Title"), MessageBoxButton.OK, MessageBoxImage.Warning);
        }
    }
}
