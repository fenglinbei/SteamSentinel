using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using SteamSentinel.App;

namespace SteamSentinel.SelfTest;

internal static partial class Program
{
    private static void TestV030DpiLayout(string? output)
    {
        MainWindow window = new();
        using (UiLayoutHarness layout = new(window, 784, 460))
        {
            UiLayoutFixtures.PopulateInformationWindow(window);
            layout.Refresh();
            DpiScale dpi = VisualTreeHelper.GetDpi(layout.Root);
            DataGrid grid = (DataGrid)window.FindName("FindingsGrid");
            Check("DPI 布局使用请求的缩放且原生客户区按物理像素分配", layout.HasCorrectPixelSize() &&
                (UiLayoutHarness.RequestedDpi is not { } requested || requested.Equals(dpi)) &&
                UiLayoutHarness.Descendants<Control>(layout.Root).All(control => VisualTreeHelper.GetDpi(control).Equals(dpi)));

            DataGridCell cell = UiLayoutHarness.Descendants<DataGridCell>(grid).First();
            Thickness padding = cell.Padding;
            cell.Padding = new Thickness(0);
            layout.Refresh();
            Check("DPI 留白检查仍拒绝真实的零留白", !layout.CellsHaveRealPadding(grid));
            cell.Padding = padding;
            layout.Refresh();
            Check("DPI 留白恢复后通过物理像素检查", layout.CellsHaveRealPadding(grid));

            DataGridCell handling = UiLayoutHarness.Descendants<DataGridCell>(grid).First(candidate => candidate.Column.DisplayIndex == 6);
            ContentPresenter presenter = (ContentPresenter)handling.Template.FindName("CellContent", handling);
            Rect initialContent = presenter.TransformToAncestor(handling).TransformBounds(new Rect(presenter.RenderSize));
            presenter.RenderTransform = new TranslateTransform(0, 3 - 2 / dpi.DpiScaleY - initialContent.Top);
            layout.Refresh();
            Check("DPI 留白检查拒绝额外丢失两物理像素", !layout.CellsHaveRealPadding(grid));
            presenter.ClearValue(UIElement.RenderTransformProperty);
            layout.Refresh();
            Check("DPI 双行留白恢复后通过", layout.CellsHaveRealPadding(grid));

            TextBlock centered = (TextBlock)grid.Columns[1].GetCellContent(grid.Items[0]);
            centered.RenderTransform = new TranslateTransform(4 / dpi.DpiScaleX, 0);
            layout.Refresh();
            Check("DPI 居中检查仍拒绝四物理像素错位", !layout.CellTextIsCentered(grid, 0, 1));
            centered.ClearValue(UIElement.RenderTransformProperty);
            layout.Refresh();
            Check("DPI 文字恢复后按去除分隔线的内容区域居中", layout.CellTextIsCentered(grid, 0, 1));

            Expander options = (Expander)window.FindName("ScanOptionsExpander");
            Expander details = (Expander)window.FindName("FindingDetailCard");
            ScrollViewer optionsScroll = (ScrollViewer)window.FindName("ScanOptionsScroll");
            ScrollViewer detailsScroll = (ScrollViewer)window.FindName("FindingDetailScroll");
            options.IsExpanded = true;
            layout.Refresh();
            Check("DPI 短窗口展开选项时让出品牌区域", ((FrameworkElement)window.FindName("HeaderCard")).Visibility == Visibility.Collapsed);
            double stableHeight = optionsScroll.ActualHeight;
            for (int pass = 0; pass < 4; pass++) layout.Refresh();
            Check("DPI 展开面板布局稳定且保留完整第一行", Math.Abs(optionsScroll.ActualHeight - stableHeight) < 0.01 &&
                grid.ItemContainerGenerator.ContainerFromIndex(0) is FrameworkElement first && layout.IsFullyVisible(first));
            foreach (string name in new[] { "WorkshopScopeComboBox", "DownloadLocationsCheckBox", "DomainBlockCheckBox" })
            {
                FrameworkElement control = (FrameworkElement)window.FindName(name);
                control.BringIntoView();
                layout.Refresh();
                // BringIntoView can round the scroll offset to a neighboring pixel.
                // Verify the user can reach the entire control with a pixel scroll;
                // an oversized control or a clipped end-of-content still fails.
                for (int step = 0; step < 2 && !layout.IsFullyVisible(control); step++)
                {
                    optionsScroll.ScrollToVerticalOffset(optionsScroll.VerticalOffset + 1 / dpi.DpiScaleY);
                    layout.Refresh();
                }
                Check($"DPI 选项内部滚动后 {name} 完整可见 {layout.VisibilityIssue(control)}".TrimEnd(), layout.IsFullyVisible(control));
            }
            // Different Windows themes/fonts can make the same controls taller.
            // Exercise that real measurement change rather than relaxing clipping.
            Control workshop = (Control)window.FindName("WorkshopScopeComboBox");
            Control downloads = (Control)window.FindName("DownloadLocationsCheckBox");
            workshop.MinHeight = 40;
            downloads.MinHeight = 40;
            layout.Refresh();
            foreach (FrameworkElement control in new[] { workshop, downloads })
            {
                control.BringIntoView();
                layout.Refresh();
                Check($"DPI 较高选项控件 {control.Name} 有完整滚动视口", layout.IsFullyVisible(control));
            }
            Check("DPI 较高选项控件仍保留结果首行及操作栏",
                grid.ItemContainerGenerator.ContainerFromIndex(0) is FrameworkElement tallFirst && layout.IsFullyVisible(tallFirst) &&
                UiLayoutFixtures.ScanButtons.Concat(UiLayoutFixtures.ResultButtons).All(name =>
                    layout.IsFullyVisible((FrameworkElement)window.FindName(name))));
            workshop.ClearValue(FrameworkElement.MinHeightProperty);
            downloads.ClearValue(FrameworkElement.MinHeightProperty);
            layout.Refresh();
            if (output is not null) layout.Save("dpi-options-scrolled-784x460", output);

            // Exercise the same live visual tree at each scale, in both directions.
            // This delivers WM_DPICHANGED to our own hidden HWND, not an OS monitor move.
            int layoutPasses = 0;
            EventHandler rejectOscillation = (_, _) =>
            {
                if (++layoutPasses > 128) throw new InvalidOperationException("DPI fixture exceeded 128 layout notifications without settling.");
            };
            layout.Root.LayoutUpdated += rejectOscillation;
            try
            {
                foreach (int percent in new[] { 100, 125, 150, 175, 200, 150, 100 })
                {
                    layoutPasses = 0;
                    layout.SetDpi(new DpiScale(percent / 100d, percent / 100d));
                    details.IsExpanded = true;
                    layout.Refresh();
                    Check($"DPI 同一窗口切换到 {percent}% 后证据与结果仍完整且无布局振荡", layout.HasCorrectPixelSize() &&
                        VisualTreeHelper.GetDpi(grid).DpiScaleX == percent / 100d &&
                        grid.ItemContainerGenerator.ContainerFromIndex(0) is FrameworkElement firstRow && layout.IsFullyVisible(firstRow) &&
                        UiLayoutFixtures.ResultButtons.All(name => layout.IsFullyVisible((FrameworkElement)window.FindName(name))));
                    double detailHeight = detailsScroll.Height;
                    layout.Refresh();
                    Check($"DPI {percent}% 后续布局保持稳定", Math.Abs(detailsScroll.Height - detailHeight) < 0.01);
                }
            }
            finally { layout.Root.LayoutUpdated -= rejectOscillation; }
            details.IsExpanded = false;
            layout.Refresh();
            Check("DPI 关闭可选面板后恢复品牌区域", ((FrameworkElement)window.FindName("HeaderCard")).Visibility == Visibility.Visible);
            layout.SetDpi(dpi);
            layout.Refresh();
        }
        window.Close();

        // A deliberately clipped child must fail even at 200%, where two physical
        // pixels used to fit inside the old one-DIP visibility tolerance.
        Border child = new() { Height = 60, Background = Brushes.White, VerticalAlignment = VerticalAlignment.Top };
        Window clipped = new() { Content = new Border { Height = 60, ClipToBounds = true, Child = child, VerticalAlignment = VerticalAlignment.Top } };
        using (UiLayoutHarness layout = new(clipped, 200, 100))
        {
            DpiScale dpi = VisualTreeHelper.GetDpi(layout.Root);
            Check("DPI 可视检查接受完整内容", layout.IsFullyVisible(child));
            child.RenderTransform = new TranslateTransform(0, 2 / dpi.DpiScaleY);
            layout.Refresh();
            Check("DPI 可视检查拒绝两物理像素裁切", !layout.IsFullyVisible(child));
        }
        clipped.Close();
    }
}
