using System.Windows;
using SteamSentinel.Core.Models;

namespace SteamSentinel.App.Dialogs;

public partial class PasswordDialog : Window
{
    public PasswordDialog(ArchivePasswordRequest request)
    {
        InitializeComponent();
        Request = request;
        ReuseScope = request.PreferredReuseScope;
        CurrentOnlyRadio.IsChecked = ReuseScope == ArchivePasswordReuseScope.CurrentOnly;
        ArchiveTreeRadio.IsChecked = ReuseScope == ArchivePasswordReuseScope.ArchiveTree;
        SessionRadio.IsChecked = ReuseScope == ArchivePasswordReuseScope.Session;
        DataContext = this;
        Loaded += (_, _) => PasswordInput.Focus();
    }

    public ArchivePasswordRequest Request { get; }
    public string PromptTitle => Request.PromptKind switch
    {
        ArchivePasswordPromptKind.CachedPasswordFailed => "已保存的密码未能解开这一层",
        ArchivePasswordPromptKind.EnteredPasswordFailed => "刚输入的密码未能解开这一层",
        ArchivePasswordPromptKind.RepeatedPassword => "这个密码已经尝试过",
        _ => "这一层内容需要密码"
    };
    public string? EnteredPassword { get; private set; }
    public ArchivePasswordReuseScope ReuseScope { get; private set; }

    private void Continue_Click(object sender, RoutedEventArgs e)
    {
        if (PasswordInput.Password.Length == 0)
        {
            MessageBox.Show(this, "请输入密码，或选择跳过。", "SteamSentinel", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }
        EnteredPassword = PasswordInput.Password;
        ReuseScope = SelectedScope();
        PasswordInput.Clear();
        DialogResult = true;
    }

    private void Skip_Click(object sender, RoutedEventArgs e)
    {
        EnteredPassword = null;
        ReuseScope = SelectedScope();
        PasswordInput.Clear();
        DialogResult = false;
    }

    private ArchivePasswordReuseScope SelectedScope() => SessionRadio.IsChecked == true ? ArchivePasswordReuseScope.Session :
        ArchiveTreeRadio.IsChecked == true ? ArchivePasswordReuseScope.ArchiveTree : ArchivePasswordReuseScope.CurrentOnly;
}
