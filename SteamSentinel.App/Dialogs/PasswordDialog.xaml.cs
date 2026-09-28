using SteamSentinel.Core.Reporting;
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
        ArchivePasswordPromptKind.CachedPasswordFailed => DisplayText.Get("Ui.PasswordDialog.xaml.PromptTitle.CachedPasswordFailed.01"),
        ArchivePasswordPromptKind.EnteredPasswordFailed => DisplayText.Get("Ui.PasswordDialog.xaml.PromptTitle.EnteredPasswordFailed.01"),
        ArchivePasswordPromptKind.RepeatedPassword => DisplayText.Get("Ui.PasswordDialog.xaml.PromptTitle.RepeatedPassword.01"),
        _ => DisplayText.Get("Ui.PasswordDialog.xaml.PromptTitle.01")
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
                ShowValidation(DisplayText.Get("Ui.PasswordDialog.xaml.TryAcceptPassword.01"));
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
                ShowValidation(DisplayText.Get("Ui.PasswordDialog.xaml.TryAcceptPassword.02"));
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
            DisplayText.Get("Ui.PasswordDialog.xaml.SkipAllEncrypted_Click.01"),
            DisplayText.Get("Ui.PasswordDialog.xaml.SkipAllEncrypted_Click.02"), MessageBoxButton.OKCancel, MessageBoxImage.Information) != MessageBoxResult.OK) return;
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
            ShowValidation(DisplayText.Get("Ui.PasswordDialog.xaml.TryAddCandidatePassword.01"));
            return false;
        }
        int duplicateIndex = _candidatePasswords.FindIndex(item => string.Equals(item, password, StringComparison.Ordinal));
        if (duplicateIndex >= 0)
        {
            PasswordCandidatesList.SelectedIndex = duplicateIndex;
            ShowValidation(DisplayText.Get("Ui.PasswordDialog.xaml.TryAddCandidatePassword.02"), isError: false);
            return true;
        }
        if (_candidatePasswords.Count >= MaximumCandidatePasswords)
        {
            ShowValidation(DisplayText.Get("Ui.PasswordDialog.xaml.TryAddCandidatePassword.03"));
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
            PasswordVisibilityButton.ToolTip = visible ? DisplayText.Get("Ui.PasswordDialog.xaml.SetPasswordVisible.01") : DisplayText.Get("Ui.PasswordDialog.xaml.SetPasswordVisible.02");
            System.Windows.Automation.AutomationProperties.SetName(PasswordVisibilityButton, visible ? DisplayText.Get("Ui.PasswordDialog.xaml.SetPasswordVisible.03") : DisplayText.Get("Ui.PasswordDialog.xaml.SetPasswordVisible.04"));
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
        ShowValidation(DisplayText.Get("Ui.PasswordDialog.xaml.PasswordInput_Pasting.01"));
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
            ShowValidation(DisplayText.Get("Ui.PasswordDialog.xaml.ValidateCurrentPasswordLength.01"));
        else PasswordValidationText.Visibility = Visibility.Collapsed;
    }

    private void PasswordMode_Changed(object sender, RoutedEventArgs e)
    {
        if (PasswordCandidatesPanel is null || PasswordScopeTitleText is null) return;
        bool multiple = PasswordMultipleCheckBox.IsChecked == true;
        AddPasswordButton.Visibility = multiple ? Visibility.Visible : Visibility.Collapsed;
        PasswordCandidatesPanel.Visibility = multiple ? Visibility.Visible : Visibility.Collapsed;
        PasswordScopeTitleText.Text = multiple ? DisplayText.Get("Ui.PasswordDialog.xaml.PasswordMode_Changed.01") : DisplayText.Get("Ui.PasswordDialog.xaml.PasswordMode_Changed.02");
        ContinuePasswordButton.Content = multiple ? DisplayText.Get("Ui.PasswordDialog.xaml.PasswordMode_Changed.03") : DisplayText.Get("Ui.PasswordDialog.xaml.PasswordMode_Changed.04");
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
        PasswordCandidateStatusText.Text = DisplayText.Format("Ui.PasswordDialog.xaml.UpdateCandidateList.01", (_candidatePasswords.Count), (MaximumCandidatePasswords));
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
