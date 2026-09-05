using System.Runtime.InteropServices;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;

namespace SteamSentinel.App.Dialogs;

/// <summary>A read-only, bounded alternative to message boxes for long diagnostic text.</summary>
internal sealed class TextDetailsWindow : Window
{
    internal TextDetailsWindow(string title, string text)
    {
        Title = title;
        Width = 760;
        Height = 520;
        MinWidth = 436;
        MinHeight = 380;
        FontFamily = new FontFamily("Microsoft YaHei UI, Segoe UI");
        FontSize = 12;
        UseLayoutRounding = true;
        ResizeMode = ResizeMode.CanResize;
        WindowStartupLocation = WindowStartupLocation.CenterOwner;
        ShowInTaskbar = false;
        PreviewKeyDown += (_, e) =>
        {
            // Let focused buttons handle Enter normally (notably "Copy all").
            // Enter from the read-only text area still invokes this viewer's close action.
            if (e.Key != Key.Escape && (e.Key != Key.Enter || Keyboard.FocusedElement is Button)) return;
            e.Handled = true;
            Close();
        };
        NameScope.SetNameScope(this, new NameScope());

        Grid layout = new() { Name = "TextDetailsLayout", Margin = new Thickness(12) };
        layout.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
        layout.RowDefinitions.Add(new RowDefinition { Height = new GridLength(1, GridUnitType.Star) });
        layout.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
        TextBlock heading = new()
        {
            Text = title,
            FontSize = 18,
            FontWeight = FontWeights.SemiBold,
            TextWrapping = TextWrapping.Wrap,
            Margin = new Thickness(0, 0, 0, 8)
        };
        layout.Children.Add(heading);

        TextBox details = new()
        {
            Name = "DetailsTextBox",
            Text = text,
            IsReadOnly = true,
            IsUndoEnabled = false,
            AcceptsReturn = true,
            TextWrapping = TextWrapping.Wrap,
            VerticalScrollBarVisibility = ScrollBarVisibility.Auto,
            HorizontalScrollBarVisibility = ScrollBarVisibility.Disabled,
            Padding = new Thickness(8),
            BorderBrush = new SolidColorBrush(Color.FromRgb(208, 213, 221)),
            BorderThickness = new Thickness(1)
        };
        System.Windows.Automation.AutomationProperties.SetName(details, title + "，只读完整内容");
        Grid.SetRow(details, 1);
        layout.Children.Add(details);

        Grid actions = new() { Name = "DetailsActionsBar", Margin = new Thickness(0, 10, 0, 0) };
        actions.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
        actions.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
        TextBlock copyStatus = new()
        {
            Text = "可选择文本并按 Ctrl+C 复制。",
            Foreground = new SolidColorBrush(Color.FromRgb(102, 112, 133)),
            VerticalAlignment = VerticalAlignment.Center,
            TextWrapping = TextWrapping.Wrap,
            Margin = new Thickness(0, 0, 8, 0)
        };
        actions.Children.Add(copyStatus);
        WrapPanel buttons = new() { HorizontalAlignment = HorizontalAlignment.Right };
        Button copy = new() { Name = "CopyDetailsButton", Content = "复制全部", IsEnabled = text.Length > 0 };
        copy.Click += (_, _) =>
        {
            try
            {
                Clipboard.SetText(details.Text);
                copyStatus.Text = "已复制完整内容。";
            }
            catch (ExternalException)
            {
                copyStatus.Text = "剪贴板暂不可用，请选择文本后重试。";
            }
        };
        Button close = new()
        {
            Name = "CloseDetailsButton",
            Content = "关闭",
            IsCancel = true,
            IsDefault = true,
            Margin = new Thickness(0)
        };
        close.Click += (_, _) => Close();
        buttons.Children.Add(copy);
        buttons.Children.Add(close);
        Grid.SetColumn(buttons, 1);
        actions.Children.Add(buttons);
        Grid.SetRow(actions, 2);
        layout.Children.Add(actions);
        Content = layout;

        foreach (FrameworkElement named in new FrameworkElement[] { layout, details, actions, copy, close })
            RegisterName(named.Name, named);
        DialogLayout.ConstrainToWorkArea(this);
    }
}
