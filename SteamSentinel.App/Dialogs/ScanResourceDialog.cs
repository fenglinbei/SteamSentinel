using System.Globalization;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using SteamSentinel.Core.Models;
using SteamSentinel.Core.Reporting;
using SteamSentinel.Core.Scanning;

namespace SteamSentinel.App.Dialogs;

internal sealed class ScanResourceDialog : Window
{
    private ScanResourceProposal _proposal;
    private readonly TextBlock _capacity = new() { TextWrapping = TextWrapping.Wrap, Margin = new(0, 12, 0, 12) };
    private readonly Button _approve = new() { Name = "ApproveResourcesButton", Padding = new(12, 7, 12, 7), Margin = new(4) };
    private readonly CheckBox _save = new() { Name = "SaveResourceGrantCheckBox", Margin = new(0, 12, 0, 12) };
    internal ResourceDecisionKind Decision { get; private set; } = ResourceDecisionKind.Skip;
    internal bool SaveForFuture => Decision == ResourceDecisionKind.Approve && _save.IsChecked == true;

    internal ScanResourceDialog(ScanResourceProposal proposal)
    {
        _proposal = proposal;
        Title = DisplayText.Get("Resource.Title"); Width = 720; Height = 610; MinWidth = 440; MinHeight = 350;
        MaxWidth = SystemParameters.WorkArea.Width; MaxHeight = SystemParameters.WorkArea.Height;
        WindowStartupLocation = WindowStartupLocation.CenterOwner; Background = Brushes.White;
        FontFamily = new("Microsoft YaHei UI"); FontSize = 13; UseLayoutRounding = true;
        DockPanel outer = new() { Margin = new(18) }; Content = outer;
        WrapPanel actions = new() { HorizontalAlignment = HorizontalAlignment.Right };
        DockPanel.SetDock(actions, Dock.Bottom); outer.Children.Add(actions);
        Button skip = new() { Name = "SkipResourcesButton", Content = DisplayText.Get("Resource.Skip"), Padding = new(12, 7, 12, 7), Margin = new(4), IsCancel = true };
        skip.Click += (_, _) => { Decision = ResourceDecisionKind.Skip; DialogResult = false; };
        actions.Children.Add(skip);
        Button stop = new() { Content = DisplayText.Get("Resource.Stop"), Padding = new(12, 7, 12, 7), Margin = new(4) };
        stop.Click += (_, _) => { Decision = ResourceDecisionKind.Stop; DialogResult = false; };
        actions.Children.Add(stop);
        _approve.Content = DisplayText.Get("Resource.Approve");
        _approve.Click += (_, _) =>
        {
            RefreshCapacity();
            if (!_approve.IsEnabled) return;
            Decision = ResourceDecisionKind.Approve; DialogResult = true;
        };
        actions.Children.Add(_approve);
        StackPanel text = new();
        outer.Children.Add(new ScrollViewer { Content = text, VerticalScrollBarVisibility = ScrollBarVisibility.Auto, Margin = new(0, 0, 0, 12) });
        void Paragraph(string value) => text.Children.Add(new TextBlock { Text = value, TextWrapping = TextWrapping.Wrap, Margin = new(0, 5, 0, 7) });
        Paragraph(DisplayText.Get("Resource.Intro"));
        Paragraph(proposal.Request.Target);
        Paragraph(DisplayText.Get(proposal.Request.DemandKnown ? "Resource.DemandKnown" : "Resource.DemandUnknown"));
        Paragraph(DisplayText.Get("Resource.Changes"));
        foreach (ScanLimitChange change in proposal.Changes)
        {
            ScanLimitDefinition field = ScanLimitAccess.Definition(change.LimitKey);
            Paragraph(DisplayText.Format("Resource.Change", field.Label,
                (change.Before / field.Scale).ToString("0.########", DisplayText.Culture),
                (change.After / field.Scale).ToString("0.########", DisplayText.Culture), field.Unit));
        }
        text.Children.Add(_capacity);
        Button refresh = new() { Content = DisplayText.Get("Resource.Refresh"), HorizontalAlignment = HorizontalAlignment.Left, Padding = new(12, 7, 12, 7) };
        refresh.Click += (_, _) => RefreshCapacity(); text.Children.Add(refresh);
        Paragraph(DisplayText.Get("Resource.Risks"));
        _save.Content = new TextBlock { Text = DisplayText.Get("Resource.SaveFuture"), TextWrapping = TextWrapping.Wrap };
        text.Children.Add(_save);
        RenderCapacity();
    }
    private void RefreshCapacity() { _proposal = ScanResourcePlanner.Refresh(_proposal); RenderCapacity(); }
    private void RenderCapacity()
    {
        static string Size(long value)
        {
            if (value < 0) return "?";
            (decimal scale, string unit) = value >= 1073741824 ? (1073741824m, "GiB") :
                value >= 1048576 ? (1048576m, "MiB") : value >= 1024 ? (1024m, "KiB") : (1m, "B");
            return (value / scale).ToString("0.##", DisplayText.Culture) + " " + unit;
        }
        _capacity.Text = DisplayText.Format("Resource.Machine", Size(_proposal.Machine.AvailableMemoryBytes),
            Size(_proposal.Machine.TemporaryFreeBytes), Size(_proposal.AdditionalTemporaryBytes)) + "\n" +
            DisplayText.Format("Resource.Headroom", Size(_proposal.Machine.CommitHeadroomBytes), Size(_proposal.EstimatedPrivateBytes), Size(_proposal.ReservedDiskBytes)) + "\n" +
            DisplayText.Get("Resource.Assessment." + _proposal.Assessment);
        _approve.IsEnabled = _proposal.Assessment == ResourceAssessmentKind.EstimatedAvailable;
    }
}
