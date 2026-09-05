using System.Windows;
using System.Windows.Automation;
using System.Windows.Controls;
using SteamSentinel.App.Dialogs;
using SteamSentinel.Core.Models;

namespace SteamSentinel.SelfTest;

internal static partial class Program
{
    // Called on the existing WPF STA; no dialog is shown and no archive is opened.
    private static void TestV0119PasswordUi(string? output)
    {
        static PasswordDialog Create() => new(new("inert-v0119-ui", UiLayoutFixtures.LongPath,
            new string('A', 64), "ZIP 无害示例", 1, null, "仅验证密码交互，不读取任何文件。"));
        static T Control<T>(PasswordDialog dialog, string name) where T : FrameworkElement => (T)dialog.FindName(name);
        static void Multiple(PasswordDialog dialog) => Control<CheckBox>(dialog, "PasswordMultipleCheckBox").IsChecked = true;
        foreach ((int width, int height) in new[] { (596, 554), (420, 340) })
        {
            PasswordDialog dialog = Create();
            using (UiLayoutHarness layout = new(dialog, width, height))
            {
                string[] actions = ["SkipAllEncryptedButton", "SkipPasswordButton", "ContinuePasswordButton"];
                Check($"0.1.19 密码窗口{width}x{height}默认输入作用域与三个操作入口可见", actions.Concat(["PasswordInput", "CurrentOnlyRadio", "ArchiveTreeRadio", "SessionRadio"])
                    .All(name => layout.IsFullyVisible(Control<FrameworkElement>(dialog, name))));
                if (output is not null) layout.Save($"password-v0119-single-{width}x{height}", output);
                Multiple(dialog);
                dialog.TryAddCandidatePassword("inert-ui-first");
                dialog.TryAddCandidatePassword(" inert-ui-second ");
                dialog.TryAddCandidatePassword("inert-ui-third,not-split");
                layout.Refresh();
                Check($"0.1.19 密码窗口{width}x{height}多候选模式核心操作仍固定可见", actions.Concat(["PasswordInput", "AddPasswordButton"])
                    .All(name => layout.IsFullyVisible(Control<FrameworkElement>(dialog, name))) && dialog.CandidatePasswordCount == 3);
                ListBox list = Control<ListBox>(dialog, "PasswordCandidatesList");
                string publicText = string.Join("\n", UiLayoutHarness.Descendants<TextBlock>(layout.Root).Select(text => text.Text)
                    .Concat(UiLayoutHarness.Descendants<FrameworkElement>(layout.Root).Select(AutomationProperties.GetName))
                    .Concat(list.Items.Cast<object>().Select(item => item.ToString())));
                Check($"0.1.19 密码窗口{width}x{height}候选只显示序号与固定掩码", list.Items.Cast<object>().Select(item => item.ToString()).SequenceEqual(["1. ••••••••", "2. ••••••••", "3. ••••••••"]) &&
                    !publicText.Contains("inert-ui-first") && !publicText.Contains("inert-ui-second") && !publicText.Contains("inert-ui-third"));
                if (output is not null) layout.Save($"password-v0119-multiple-{width}x{height}", output);
                list.BringIntoView();
                layout.Refresh();
                Check($"0.1.19 密码窗口{width}x{height}候选列表可局部滚动查看且底栏不遮挡", layout.IsFullyVisible(list) && actions.All(name => layout.IsFullyVisible(Control<FrameworkElement>(dialog, name))));
                if (output is not null) layout.Save($"password-v0119-list-{width}x{height}", output);
            }
            dialog.Close();
        }
        foreach (ArchivePasswordReuseScope scope in Enum.GetValues<ArchivePasswordReuseScope>())
        {
            PasswordDialog dialog = Create();
            Multiple(dialog);
            string radio = scope == ArchivePasswordReuseScope.CurrentOnly ? "CurrentOnlyRadio" : scope == ArchivePasswordReuseScope.ArchiveTree ? "ArchiveTreeRadio" : "SessionRadio";
            Control<RadioButton>(dialog, radio).IsChecked = true;
            dialog.TryAddCandidatePassword("first");
            Control<PasswordBox>(dialog, "PasswordInput").Password = " second ";
            bool accepted = dialog.TryAcceptPassword();
            Check($"0.1.19 多候选提交保留输入末尾顺序及{scope}作用域", accepted && dialog.EnteredPassword is null &&
                dialog.EnteredPasswords?.SequenceEqual(["first", " second "]) == true && dialog.ReuseScope == scope && !dialog.SkipAllEncrypted);
            Check($"0.1.19 {scope}提交后清空可见输入和队列但保留返回快照", dialog.CandidatePasswordCount == 0 &&
                Control<PasswordBox>(dialog, "PasswordInput").Password.Length == 0 && dialog.EnteredPasswords?.Count == 2);
            dialog.ClearReturnedPasswords();
            dialog.Close();
        }
        PasswordDialog empty = Create();
        Multiple(empty);
        Check("0.1.19 空候选不能误提交为成功解密", !empty.TryAcceptPassword() && empty.EnteredPasswords is null &&
            Control<TextBlock>(empty, "PasswordValidationText").Visibility == Visibility.Visible);
        empty.Close();

        PasswordDialog longInput = Create();
        PasswordBox longPasswordBox = Control<PasswordBox>(longInput, "PasswordInput");
        longPasswordBox.Password = new string('x', 1025);
        Check("0.1.19 超长密码保留原输入并拒绝提交而非静默截断", longPasswordBox.Password.Length == 1025 && !longInput.TryAcceptPassword() &&
            longInput.EnteredPassword is null && Control<TextBlock>(longInput, "PasswordValidationText").Visibility == Visibility.Visible);
        longPasswordBox.Password = "existing-inert-password";
        DataObject pasteData = new(DataFormats.UnicodeText, new string('y', 1025));
        DataObjectPastingEventArgs paste = new(pasteData, false, DataFormats.UnicodeText) { RoutedEvent = DataObject.PastingEvent };
        longPasswordBox.RaiseEvent(paste);
        Check("0.1.19 超长粘贴整体拒绝且不覆盖已有输入", paste.CommandCancelled && longPasswordBox.Password == "existing-inert-password" &&
            Control<TextBlock>(longInput, "PasswordValidationText").Visibility == Visibility.Visible);
        longInput.Close();

        PasswordDialog edit = Create();
        Multiple(edit);
        foreach (string password in new[] { "first", "middle", "last" }) edit.TryAddCandidatePassword(password);
        Control<ListBox>(edit, "PasswordCandidatesList").SelectedIndex = 1;
        Control<Button>(edit, "RemovePasswordButton").RaiseEvent(new RoutedEventArgs(Button.ClickEvent));
        Check("0.1.19 移除选中候选保留剩余密码原顺序", edit.TryAcceptPassword() && edit.EnteredPasswords?.SequenceEqual(["first", "last"]) == true);
        edit.ClearReturnedPasswords();
        edit.TryAddCandidatePassword("never-display-this");
        Control<Button>(edit, "ClearPasswordsButton").RaiseEvent(new RoutedEventArgs(Button.ClickEvent));
        Check("0.1.19 清空候选按钮同步清空内部队列与掩码列表", edit.CandidatePasswordCount == 0 && Control<ListBox>(edit, "PasswordCandidatesList").Items.Count == 0);
        edit.Close();

        PasswordDialog single = Create();
        Control<PasswordBox>(single, "PasswordInput").Password = " single password ";
        Check("0.1.19 默认单密码路径保留空格且不转为多候选", single.TryAcceptPassword() && single.EnteredPassword == " single password " &&
            single.EnteredPasswords is null && single.ReuseScope == ArchivePasswordReuseScope.ArchiveTree);
        single.ClearReturnedPasswords();
        single.Close();

        PasswordDialog skip = Create();
        Multiple(skip);
        skip.TryAddCandidatePassword("unsubmitted-candidate");
        Control<PasswordBox>(skip, "PasswordInput").Password = "unsubmitted-input";
        skip.PrepareSkip(true);
        Check("0.1.19 全部跳过只返回明确标记并清空未提交秘密", skip.SkipAllEncrypted && skip.EnteredPassword is null && skip.EnteredPasswords is null &&
            skip.CandidatePasswordCount == 0 && Control<PasswordBox>(skip, "PasswordInput").Password.Length == 0);
        skip.PrepareSkip(false);
        Check("0.1.19 单层跳过不扩大为全部跳过", !skip.SkipAllEncrypted && skip.EnteredPassword is null && skip.EnteredPasswords is null);
        skip.Close();

        PasswordDialog closed = Create();
        closed.TryAddCandidatePassword("close-candidate");
        Control<PasswordBox>(closed, "PasswordInput").Password = "close-input";
        closed.Close();
        Check("0.1.19 直接关闭窗口不启用全部跳过且清空输入候选", !closed.SkipAllEncrypted && closed.EnteredPasswords is null && closed.EnteredPassword is null &&
            closed.CandidatePasswordCount == 0 && Control<PasswordBox>(closed, "PasswordInput").Password.Length == 0);
        TestV0119PasswordRevealUi(output);
    }

    private static void TestV0119PasswordRevealUi(string? output)
    {
        static PasswordDialog Create() => new(new("inert-v0119-reveal", UiLayoutFixtures.LongPath,
            new string('B', 64), "ZIP 无害示例", 1, null, "当前显示的“示例密码”仅用于界面测试。"));
        static T Control<T>(PasswordDialog dialog, string name) where T : FrameworkElement => (T)dialog.FindName(name);
        foreach ((int width, int height) in new[] { (596, 554), (420, 340) })
        {
            PasswordDialog dialog = Create();
            using (UiLayoutHarness layout = new(dialog, width, height))
            {
                PasswordBox masked = Control<PasswordBox>(dialog, "PasswordInput");
                TextBox visible = Control<TextBox>(dialog, "PasswordVisibleInput");
                Button eye = Control<Button>(dialog, "PasswordVisibilityButton");
                string[] actions = ["SkipAllEncryptedButton", "SkipPasswordButton", "ContinuePasswordButton"];
                Rect maskedBounds = layout.Bounds(masked), eyeBounds = layout.Bounds(eye);
                Check($"0.1.19 密码眼睛{width}x{height}默认遮蔽且位于输入右侧不遮挡操作", !dialog.IsPasswordVisible &&
                    visible.Visibility == Visibility.Collapsed && visible.Text.Length == 0 && layout.IsFullyVisible(masked) && layout.IsFullyVisible(eye) &&
                    masked.ActualWidth >= 180 && eyeBounds.Left >= maskedBounds.Right - 1 && Math.Abs(eyeBounds.Top - maskedBounds.Top) <= 1 &&
                    actions.All(name => layout.IsFullyVisible(Control<Button>(dialog, name))));
                masked.Password = " 示例密码 ";
                eye.RaiseEvent(new RoutedEventArgs(Button.ClickEvent));
                layout.Refresh();
                Check($"0.1.19 密码眼睛{width}x{height}真实按钮可显示当前密码且输入边界不变", dialog.IsPasswordVisible &&
                    masked.Visibility == Visibility.Collapsed && visible.Text == " 示例密码 " && layout.IsFullyVisible(visible) &&
                    layout.Bounds(visible) == maskedBounds && layout.IsFullyVisible(eye));
                if (output is not null) layout.Save($"password-v0119-eye-visible-{width}x{height}", output);
                visible.Text = "  示例密码  ";
                bool fromVisible = masked.Password == "  示例密码  ";
                masked.Password = " 示例密码 ";
                bool fromMasked = visible.Text == " 示例密码 ";
                eye.RaiseEvent(new RoutedEventArgs(Button.ClickEvent));
                layout.Refresh();
                Check($"0.1.19 密码眼睛{width}x{height}双向编辑和隐藏保留空格且清空明文框", fromVisible && fromMasked &&
                    !dialog.IsPasswordVisible && masked.Password == " 示例密码 " && visible.Visibility == Visibility.Collapsed && visible.Text.Length == 0);
                if (output is not null) layout.Save($"password-v0119-eye-hidden-{width}x{height}", output);
                Control<CheckBox>(dialog, "PasswordMultipleCheckBox").IsChecked = true;
                dialog.TryAddCandidatePassword("仅用于测试的候选一");
                dialog.TryAddCandidatePassword("仅用于测试的候选二");
                eye.RaiseEvent(new RoutedEventArgs(Button.ClickEvent));
                layout.Refresh();
                ListBox candidates = Control<ListBox>(dialog, "PasswordCandidatesList");
                Check($"0.1.19 密码眼睛{width}x{height}仅显示当前输入不暴露候选列表", dialog.IsPasswordVisible && visible.Text == " 示例密码 " &&
                    candidates.Items.Cast<object>().Select(item => item.ToString()).SequenceEqual(["1. ••••••••", "2. ••••••••"]) &&
                    visible.ActualWidth >= 150 && layout.IsFullyVisible(visible) && layout.IsFullyVisible(eye) &&
                    layout.DoNotOverlap(new FrameworkElement[] { visible, eye, Control<Button>(dialog, "AddPasswordButton") }) &&
                    actions.All(name => layout.IsFullyVisible(Control<Button>(dialog, name))));
                if (output is not null) layout.Save($"password-v0119-eye-candidates-{width}x{height}", output);
            }
            dialog.Close();
        }

        foreach (string action in new[] { "提交", "跳过全部", "关闭", "清空列表" })
        {
            PasswordDialog dialog = Create();
            Control<CheckBox>(dialog, "PasswordMultipleCheckBox").IsChecked = true;
            dialog.TryAddCandidatePassword("inert-existing-candidate");
            PasswordBox masked = Control<PasswordBox>(dialog, "PasswordInput");
            TextBox visible = Control<TextBox>(dialog, "PasswordVisibleInput");
            masked.Password = " 示例密码 ";
            dialog.SetPasswordVisible(true);
            bool performed = true;
            switch (action)
            {
                case "提交": performed = dialog.TryAcceptPassword(); break;
                case "跳过全部": dialog.PrepareSkip(true); break;
                case "关闭": dialog.Close(); break;
                default: Control<Button>(dialog, "ClearPasswordsButton").RaiseEvent(new RoutedEventArgs(Button.ClickEvent)); break;
            }
            Check($"0.1.19 显示密码后{action}恢复隐藏并清理两输入框", performed && !dialog.IsPasswordVisible &&
                masked.Password.Length == 0 && visible.Text.Length == 0 && visible.Visibility == Visibility.Collapsed && dialog.CandidatePasswordCount == 0);
            dialog.ClearReturnedPasswords();
            if (action != "关闭") dialog.Close();
        }

        PasswordDialog longVisible = Create();
        PasswordBox maskedLong = Control<PasswordBox>(longVisible, "PasswordInput");
        TextBox visibleLong = Control<TextBox>(longVisible, "PasswordVisibleInput");
        longVisible.SetPasswordVisible(true);
        visibleLong.Text = new string('z', 1025);
        Check("0.1.19 明文超长输入不截断并拒绝提交", visibleLong.Text.Length == 1025 && maskedLong.Password.Length == 1025 &&
            !longVisible.TryAcceptPassword() && longVisible.EnteredPassword is null);
        visibleLong.Text = "原有示例密码";
        DataObject data = new(DataFormats.UnicodeText, new string('q', 1025));
        DataObjectPastingEventArgs paste = new(data, false, DataFormats.UnicodeText) { RoutedEvent = DataObject.PastingEvent };
        visibleLong.RaiseEvent(paste);
        Check("0.1.19 明文框超长粘贴整体拒绝且不覆盖已有密码", paste.CommandCancelled && visibleLong.Text == "原有示例密码" &&
            maskedLong.Password == "原有示例密码" && Control<TextBlock>(longVisible, "PasswordValidationText").Visibility == Visibility.Visible);
        longVisible.Close();
    }
}
