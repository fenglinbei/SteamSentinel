using System.ComponentModel;
using System.Runtime.CompilerServices;
using SteamSentinel.Core.Models;
using SteamSentinel.Core.Remediation;
using SteamSentinel.Core.Reporting;
using SteamSentinel.Core.Steam;

namespace SteamSentinel.App.ViewModels;

public sealed class FindingItemViewModel : INotifyPropertyChanged
{
    private bool _isSelected;
    private readonly FileScopeAssessment? _scope;
    private readonly RemediationMode _mode;

    public FindingItemViewModel(Finding finding, RuleSet? rules = null, SteamLayout? layout = null,
        RemediationMode mode = RemediationMode.Conservative, bool isReference = false)
    {
        Finding = finding;
        IsReference = isReference;
        _mode = mode;
        UserSelectedRisk = mode == RemediationMode.Aggressive && RemediationModePolicy.ProjectFinding(finding, mode).UserSelectedRisk;
        _scope = rules is not null && layout is not null ? FindingHandlingPresentation.AssessFileScope(finding, rules, layout, mode) : null;
        // Mode and scope are fixed for this row; changing mode rebuilds the view models.
        // Bindings must not repeat policy projection or filesystem checks while scrolling.
        Handling = FindingHandlingPresentation.Get(finding, _scope, _mode);
        _isSelected = !UserSelectedRisk && finding.IsKnownMalware && CanSelect && _scope?.Status is null or FileScopeStatus.Automatic;
    }

    public Finding Finding { get; }
    public bool IsReference { get; }
    public bool IsSelected
    {
        get => _isSelected;
        set
        {
            if (value && !CanSelect) return;
            if (_isSelected == value) return;
            _isSelected = value;
            OnPropertyChanged();
        }
    }
    public bool UserSelectedRisk { get; }
    public FindingHandlingInfo Handling { get; private set; }
    public bool CanSelect => Handling.CanSelect;
    public string HandlingLabel => Handling.Label;
    public string HandlingReason => Handling.Reason;

    /// <summary>按当前显示语言重算文本描述并通知列表绑定刷新，保留选中与勾选状态。</summary>
    internal void RefreshLocalizedText()
    {
        Handling = FindingHandlingPresentation.Get(Finding, _scope, _mode);
        OnPropertyChanged(string.Empty);
    }

    /// <summary>供表格紧凑展示的处理原因首行摘要，避免截断露出原始记录前缀。</summary>
    public string HandlingReasonSummary
    {
        get
        {
            int nl = Handling.Reason.IndexOfAny(['\r', '\n']);
            return nl >= 0 ? Handling.Reason[..nl].Trim() : Handling.Reason;
        }
    }

    public string HandlingNextStep => Handling.NextStep;
    public string HandlingDetails => DisplayText.Format("Common.LabelValue", Handling.Label, Handling.Reason) + "\n" + Handling.NextStep;
    public bool IsTrustProxyFinding => FindingHandlingPresentation.IsTrustProxyFinding(Finding);
    public string Severity => ReportExporter.SeverityLabel(Finding.Severity);
    public string Category => ReportExporter.CategoryLabel(Finding.Category);
    public int Score => Finding.Score;
    // 仅纯格式不符折叠项采用简化标题“文件格式提示”，其他归入「信息与参考」的规则保留各自明确标题。
    public string Title => IsReference && Finding.RuleId == "CONTENT-EXTENSION-MISMATCH"
        ? DisplayText.Get("FindingPriority.FormatHint")
        : Finding.TitleText.Display;
    public string Target => Finding.Target;
    public string TargetDisplay => Finding.TargetText.Display;
    public string Evidence => Finding.EvidenceDisplay;
    public string Description => Finding.DescriptionText.Display;
    public string Sha256 => Finding.Sha256 ?? string.Empty;
    public string WorkshopId => Finding.AppId is { Length: > 0 } ? $"{Finding.AppId} / {Finding.WorkshopId ?? "—"}" : Finding.WorkshopId ?? string.Empty;

    public event PropertyChangedEventHandler? PropertyChanged;
    private void OnPropertyChanged([CallerMemberName] string? name = null) =>
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
}
