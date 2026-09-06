using System.ComponentModel;
using System.Runtime.CompilerServices;
using SteamSentinel.Core.Models;
using SteamSentinel.Core.Reporting;

namespace SteamSentinel.App.ViewModels;

public sealed class FindingItemViewModel : INotifyPropertyChanged
{
    private bool _isSelected;

    public FindingItemViewModel(Finding finding)
    {
        Finding = finding;
        _isSelected = finding.IsKnownMalware && CanSelect;
    }

    public Finding Finding { get; }
    public bool IsSelected
    {
        get => _isSelected;
        set
        {
            if (_isSelected == value) return;
            _isSelected = value;
            OnPropertyChanged();
        }
    }
    public FindingHandlingInfo Handling => FindingHandlingPresentation.Get(Finding);
    public bool CanSelect => Handling.CanSelect;
    public string HandlingLabel => Handling.Label;
    public string HandlingReason => Handling.Reason;
    public string HandlingNextStep => Handling.NextStep;
    public string HandlingDetails => Handling.Label + "：" + Handling.Reason + "\n" + Handling.NextStep;
    public bool IsTrustProxyFinding => FindingHandlingPresentation.IsTrustProxyFinding(Finding);
    public string Severity => ReportExporter.SeverityLabel(Finding.Severity);
    public string Category => ReportExporter.CategoryLabel(Finding.Category);
    public int Score => Finding.Score;
    public string Title => Finding.Title;
    public string Target => Finding.Target;
    public string Evidence => Finding.Evidence;
    public string Description => Finding.Description;
    public string Sha256 => Finding.Sha256 ?? string.Empty;
    public string WorkshopId => Finding.AppId is { Length: > 0 } ? $"{Finding.AppId} / {Finding.WorkshopId ?? "—"}" : Finding.WorkshopId ?? string.Empty;

    public event PropertyChangedEventHandler? PropertyChanged;
    private void OnPropertyChanged([CallerMemberName] string? name = null) =>
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
}
