using System.Globalization;
using SteamSentinel.App.Dialogs;
using SteamSentinel.App.Localization;
using SteamSentinel.Core.Reporting;

namespace SteamSentinel.App;

public partial class MainWindow
{
    private CultureInfo? ChooseExportLanguage()
    {
        ExportLanguageDialog dialog = new(DisplayText.Culture) { Owner = this };
        return dialog.ShowDialog() == true ? dialog.SelectedCulture : null;
    }

    private void ShowStartupLanguageNotice()
    {
        if (System.Windows.Application.Current is not App { LanguageStartup: { } startup }) return;
        if (startup.SettingsError != LanguageSettingsError.None)
            FooterText.Text += " " + LanguageSettings.ErrorText(startup.SettingsError);
        if (startup.IgnoredArguments) FooterText.Text += " " + DisplayText.Get("Ui.Language.ArgumentsIgnored");
    }
}
