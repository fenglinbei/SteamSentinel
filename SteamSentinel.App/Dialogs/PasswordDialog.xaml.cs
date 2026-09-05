using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using SteamSentinel.Core.Models;

namespace SteamSentinel.App.Dialogs;

public partial class PasswordDialog : Window
{
    internal const int MaximumCandidatePasswords = ArchivePasswordInput.MaximumPasswords;
    internal const int MaximumPasswordLength = ArchivePasswordInput.MaximumPasswordCharacters;
    private readonly List<string> _candidatePasswords = [];
    private bool _passwordVisible;
    private bool _synchronizingPasswordInputs;

    public PasswordDialog(ArchivePasswordRequest request)
    {
        InitializeComponent();
        DialogLayout.ConstrainToWorkArea(this);
        Request = request;
        ReuseScope = request.PreferredReuseScope;
        CurrentOnlyRadio.IsChecked = ReuseScope == ArchivePasswordReuseScope.CurrentOnly;
        ArchiveTreeRadio.IsChecked = ReuseScope == ArchivePasswordReuseScope.ArchiveTree;
        SessionRadio.IsChecked = ReuseScope == ArchivePasswordReuseScope.Session;
        DataContext = this;
        Loaded += (_, _) => PasswordInput.Focus();
        Closed += (_, _) => ClearTransientInput();
    }

    public ArchivePasswordRequest Request { get; }
    public string PromptTitle => Request.PromptKind switch
    {
        ArchivePasswordPromptKind.CachedPasswordFailed => "本次暂存的密码未能解开这一层",
        ArchivePasswordPromptKind.EnteredPasswordFailed => "刚输入的密码未能解开这一层",
        ArchivePasswordPromptKind.RepeatedPassword => "这个密码已经尝试过",
        _ => "这一层内容需要密码"
    };
    public string? EnteredPassword { get; private set; }
    public IReadOnlyList<string>? EnteredPasswords { get; private set; }
    public bool SkipAllEncrypted { get; private set; }
    public ArchivePasswordReuseScope ReuseScope { get; private set; }
    internal int CandidatePasswordCount => _candidatePasswords.Count;
    internal bool IsPasswordVisible => _passwordVisible;

    private void Continue_Click(object sender, RoutedEventArgs e)
    {
        if (TryAcceptPassword()) DialogResult = true;
    }

    internal bool TryAcceptPassword()
    {
        if (PasswordMultipleCheckBox.IsChecked == true)
        {
            // Treat the current input as the final candidate, never silently drop it.
            if (PasswordInput.Password.Length > 0 && !TryAddCandidatePassword(PasswordInput.Password)) return false;
            if (_candidatePasswords.Count == 0)
            {
                ShowValidation("请至少加入一个候选密码，或选择跳过。");
                return false;
            }
            EnteredPassword = null;
            EnteredPasswords = ArchivePasswordInput.ValidateAndGetPasswords(new ArchivePasswordResponse(
                Request.RequestId, false, null, false, SelectedScope(), Passwords: _candidatePasswords.ToArray())).ToArray();
        }
        else
        {
            string password = PasswordInput.Password;
            if (password.Length is < 1 or > MaximumPasswordLength)
            {
                ShowValidation("请输入 1–1024 字符的密码，或选择跳过；密码中的空格会保留。");
                return false;
            }
            EnteredPassword = ArchivePasswordInput.ValidateAndGetPasswords(new ArchivePasswordResponse(
                Request.RequestId, false, password, false, SelectedScope())).Single();
            EnteredPasswords = null;
        }
        ReuseScope = SelectedScope();
        SkipAllEncrypted = false;
        ClearTransientInput();
        return true;
    }

    private void Skip_Click(object sender, RoutedEventArgs e)
    {
        PrepareSkip(allEncrypted: false);
        DialogResult = false;
    }

    private void SkipAllEncrypted_Click(object sender, RoutedEventArgs e)
    {
        if (MessageBox.Show(this,
            "仅对本次扫描生效：仍先尝试已提交且适用的密码，未解开的加密压缩包不再询问，并标记为未检查。扫描结束后可重试。\n\n本窗口尚未提交的密码不会使用。继续吗？",
            "跳过所有未能解密的加密压缩包", MessageBoxButton.OKCancel, MessageBoxImage.Information) != MessageBoxResult.OK) return;
        PrepareSkip(allEncrypted: true);
        DialogResult = false;
    }

    internal void PrepareSkip(bool allEncrypted)
    {
        EnteredPassword = null;
        EnteredPasswords = null;
        ReuseScope = SelectedScope();
        SkipAllEncrypted = allEncrypted;
        ClearTransientInput();
    }

    internal bool TryAddCandidatePassword(string? password)
    {
        if (password is null || password.Length is < 1 or > MaximumPasswordLength)
        {
            ShowValidation("每个候选密码需为 1–1024 字符，空格会保留；不会按逗号拆分。");
            return false;
        }
        int duplicateIndex = _candidatePasswords.FindIndex(item => string.Equals(item, password, StringComparison.Ordinal));
        if (duplicateIndex >= 0)
        {
            PasswordCandidatesList.SelectedIndex = duplicateIndex;
            ShowValidation("该密码已在候选列表中，未重复加入。", isError: false);
            return true;
        }
        if (_candidatePasswords.Count >= MaximumCandidatePasswords)
        {
            ShowValidation("最多可提供 16 个候选密码，请先移除不需要的候选。");
            return false;
        }
        _candidatePasswords.Add(password);
        UpdateCandidateList();
        PasswordValidationText.Visibility = Visibility.Collapsed;
        return true;
    }

    private void AddPassword_Click(object sender, RoutedEventArgs e)
    {
        if (TryAddCandidatePassword(PasswordInput.Password)) ClearCurrentPasswordInput();
        FocusCurrentPasswordInput();
    }

    private void PasswordVisibility_Click(object sender, RoutedEventArgs e) => SetPasswordVisible(!_passwordVisible);

    internal void SetPasswordVisible(bool visible)
    {
        SetPasswordVisible(visible, focusInput: true);
    }

    private void SetPasswordVisible(bool visible, bool focusInput)
    {
        _synchronizingPasswordInputs = true;
        try
        {
            // The collapsed plain-text control must never retain a hidden password.
            PasswordVisibleInput.Text = visible ? PasswordInput.Password : string.Empty;
            _passwordVisible = visible;
            PasswordInput.Visibility = visible ? Visibility.Collapsed : Visibility.Visible;
            PasswordVisibleInput.Visibility = visible ? Visibility.Visible : Visibility.Collapsed;
            PasswordVisibilitySlash.Visibility = visible ? Visibility.Visible : Visibility.Collapsed;
            PasswordVisibilityButton.ToolTip = visible ? "隐藏当前输入的密码" : "显示当前输入的密码";
            System.Windows.Automation.AutomationProperties.SetName(PasswordVisibilityButton, visible ? "隐藏密码" : "显示密码");
        }
        finally { _synchronizingPasswordInputs = false; }
        if (focusInput) FocusCurrentPasswordInput();
    }

    private void FocusCurrentPasswordInput()
    {
        if (_passwordVisible)
        {
            PasswordVisibleInput.Focus();
            PasswordVisibleInput.CaretIndex = PasswordVisibleInput.Text.Length;
        }
        else PasswordInput.Focus();
    }

    private void PasswordInput_PreviewKeyDown(object sender, KeyEventArgs e)
    {
        if (e.Key == Key.Enter && PasswordMultipleCheckBox.IsChecked == true)
        {
            e.Handled = true;
            AddPassword_Click(sender, e);
        }
    }

    private void PasswordInput_Pasting(object sender, DataObjectPastingEventArgs e)
    {
        string? pasted = e.DataObject.GetData(DataFormats.UnicodeText, autoConvert: true) as string ??
            e.DataObject.GetData(DataFormats.Text, autoConvert: true) as string;
        if (pasted is not { Length: > MaximumPasswordLength }) return;
        // Reject the paste as a whole. Never silently accept a truncated password.
        e.CancelCommand();
        ShowValidation("粘贴未完成：单个密码不能超过 1024 字符，请核对后重新输入。");
    }

    private void PasswordInput_PasswordChanged(object sender, RoutedEventArgs e)
    {
        if (_synchronizingPasswordInputs || PasswordValidationText is null) return;
        if (_passwordVisible)
        {
            _synchronizingPasswordInputs = true;
            try { PasswordVisibleInput.Text = PasswordInput.Password; }
            finally { _synchronizingPasswordInputs = false; }
        }
        ValidateCurrentPasswordLength();
    }

    private void PasswordVisibleInput_TextChanged(object sender, TextChangedEventArgs e)
    {
        if (_synchronizingPasswordInputs) return;
        _synchronizingPasswordInputs = true;
        try
        {
            if (_passwordVisible) PasswordInput.Password = PasswordVisibleInput.Text;
            else PasswordVisibleInput.Clear();
        }
        finally { _synchronizingPasswordInputs = false; }
        ValidateCurrentPasswordLength();
    }

    private void ValidateCurrentPasswordLength()
    {
        if (PasswordValidationText is null) return;
        // PasswordBox has no public selection length. Validate the resulting value
        // so replacing a selected password remains possible without guessing selection.
        using var password = PasswordInput.SecurePassword;
        if (password.Length > MaximumPasswordLength)
            ShowValidation("密码超过 1024 字符，不能提交；请修改密码，内容不会被自动截断。");
        else PasswordValidationText.Visibility = Visibility.Collapsed;
    }

    private void PasswordMode_Changed(object sender, RoutedEventArgs e)
    {
        if (PasswordCandidatesPanel is null || PasswordScopeTitleText is null) return;
        bool multiple = PasswordMultipleCheckBox.IsChecked == true;
        AddPasswordButton.Visibility = multiple ? Visibility.Visible : Visibility.Collapsed;
        PasswordCandidatesPanel.Visibility = multiple ? Visibility.Visible : Visibility.Collapsed;
        PasswordScopeTitleText.Text = multiple ? "候选密码的尝试范围（按加入顺序）" : "成功解密后的密码复用范围";
        ContinuePasswordButton.Content = multiple ? "按顺序尝试" : "使用密码继续";
        PasswordValidationText.Visibility = Visibility.Collapsed;
    }

    private void PasswordCandidates_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (RemovePasswordButton is not null) RemovePasswordButton.IsEnabled = PasswordCandidatesList.SelectedIndex >= 0;
    }

    private void RemovePassword_Click(object sender, RoutedEventArgs e)
    {
        int index = PasswordCandidatesList.SelectedIndex;
        if (index < 0 || index >= _candidatePasswords.Count) return;
        _candidatePasswords.RemoveAt(index);
        UpdateCandidateList();
        PasswordValidationText.Visibility = Visibility.Collapsed;
    }

    private void ClearPasswords_Click(object sender, RoutedEventArgs e)
    {
        ClearTransientInput();
        PasswordValidationText.Visibility = Visibility.Collapsed;
        PasswordInput.Focus();
    }

    private void UpdateCandidateList()
    {
        PasswordCandidatesList.Items.Clear();
        for (int index = 0; index < _candidatePasswords.Count; index++)
            PasswordCandidatesList.Items.Add($"{index + 1}. ••••••••");
        // Keep secrets out of text bindings, item models, tooltips and accessibility labels.
        PasswordCandidateStatusText.Text = $"{_candidatePasswords.Count} / {MaximumCandidatePasswords} 个候选";
        ClearPasswordsButton.IsEnabled = _candidatePasswords.Count > 0;
        RemovePasswordButton.IsEnabled = false;
    }

    private void ShowValidation(string message, bool isError = true)
    {
        PasswordValidationText.Text = message;
        PasswordValidationText.Foreground = new SolidColorBrush(isError ? Color.FromRgb(180, 35, 24) : Color.FromRgb(71, 84, 103));
        PasswordValidationText.Visibility = Visibility.Visible;
        PasswordValidationText.BringIntoView();
    }

    private void ClearTransientInput()
    {
        ClearCurrentPasswordInput();
        _candidatePasswords.Clear();
        UpdateCandidateList();
    }

    private void ClearCurrentPasswordInput()
    {
        _synchronizingPasswordInputs = true;
        try
        {
            PasswordInput.Clear();
            PasswordVisibleInput.Clear();
        }
        finally { _synchronizingPasswordInputs = false; }
        SetPasswordVisible(false, focusInput: false);
        PasswordValidationText.Visibility = Visibility.Collapsed;
    }

    internal void ClearReturnedPasswords()
    {
        EnteredPassword = null;
        EnteredPasswords = null;
        ClearTransientInput();
    }

    private ArchivePasswordReuseScope SelectedScope() => SessionRadio.IsChecked == true ? ArchivePasswordReuseScope.Session :
        ArchiveTreeRadio.IsChecked == true ? ArchivePasswordReuseScope.ArchiveTree : ArchivePasswordReuseScope.CurrentOnly;
}
