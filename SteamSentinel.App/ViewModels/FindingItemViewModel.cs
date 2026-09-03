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
        _isSelected = finding.IsKnownMalware && finding.CanRemediate;
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
    public bool CanSelect => Finding.CanRemediate;
    public string Severity => ReportExporter.SeverityLabel(Finding.Severity);
    public string Category => ReportExporter.CategoryLabel(Finding.Category);
    public int Score => Finding.Score;
    public string Title => Finding.Title;
    public string Target => Finding.Target;
    public string Evidence => Finding.Evidence;
    public string Description => Finding.Description;
    public string Sha256 => Finding.Sha256 ?? string.Empty;
    public string WorkshopId => Finding.WorkshopId ?? string.Empty;

    public event PropertyChangedEventHandler? PropertyChanged;
    private void OnPropertyChanged([CallerMemberName] string? name = null) =>
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
}
