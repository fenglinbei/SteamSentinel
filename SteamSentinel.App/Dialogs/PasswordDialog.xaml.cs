using System.Windows;
using SteamSentinel.Core.Models;

namespace SteamSentinel.App.Dialogs;

public partial class PasswordDialog : Window
{
    public PasswordDialog(ArchivePasswordRequest request)
    {
        InitializeComponent();
        Request = request;
        DataContext = this;
        Loaded += (_, _) => PasswordInput.Focus();
    }

    public ArchivePasswordRequest Request { get; }
    public string? EnteredPassword { get; private set; }
    public bool ReuseForSession { get; private set; }

    private void Continue_Click(object sender, RoutedEventArgs e)
    {
        if (PasswordInput.Password.Length == 0)
        {
            MessageBox.Show(this, "请输入密码，或选择跳过。", "SteamSentinel", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }
        EnteredPassword = PasswordInput.Password;
        ReuseForSession = ReuseCheckBox.IsChecked == true;
        PasswordInput.Clear();
        DialogResult = true;
    }

    private void Skip_Click(object sender, RoutedEventArgs e)
    {
        EnteredPassword = null;
        ReuseForSession = false;
        PasswordInput.Clear();
        DialogResult = false;
    }
}
