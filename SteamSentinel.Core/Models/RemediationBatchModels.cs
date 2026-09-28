using System.Text.Json.Serialization;
using SteamSentinel.Core.Reporting;

namespace SteamSentinel.Core.Models;

public sealed class RemediationBatchSession
{
    public Guid SessionId { get; init; } = Guid.NewGuid();
    public int SelectedFindingCount { get; init; }
    public List<RemediationTargetOutcome> Targets { get; init; } = [];
    public List<RemediationPlan> Plans { get; init; } = [];
    public List<RemediationRunResult> Results { get; init; } = [];
    public List<string> Notes { get; init; } = [];
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] public Dictionary<int, DisplayMessage>? NoteMessages { get => SteamSentinel.Core.Models.DisplayMessageMap.Bound(Notes, field); set => field = value; }
    [JsonIgnore] public IEnumerable<MessageText> NoteTexts => DisplayMessageMap.Read(Notes, NoteMessages);
    public void AddNote(MessageText text) => NoteMessages = DisplayMessageMap.Add(Notes, NoteMessages, text);
    public List<RemediationPreparationNote> PreparationNotes { get; init; } = [];
    public string? Interruption { get; set; }
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public DisplayMessage? InterruptionMessage { get => SteamSentinel.Core.Reporting.MessageText.BoundDescriptor(field, Interruption); set => field = value; }
    [JsonIgnore] public MessageText InterruptionText { get => new(Interruption ?? string.Empty, InterruptionMessage); set { Interruption = value.OriginalText; InterruptionMessage = value.Message; } }
    public string? InterruptionReasonCode { get; set; }
    public bool ExecutionStarted { get; set; }
    public bool ExecutionFinished { get; set; }
    public ScanOptions? OriginalContentSettings { get; init; }
    public int PlannedCount => Targets.Count(t => t.ActionIds.Count > 0);
    public int SelectedTargetCount => Targets.Count(t => !t.AddedByAssociation);
    public int CompletedCount => Targets.Count(t => t.State == RemediationTargetState.Completed);
    public int ReviewRequiredCount => Targets.Count(t => t.State == RemediationTargetState.ReviewRequired);
    public int FailedCount => Targets.Count(t => t.State == RemediationTargetState.Failed);
    public int UnfinishedCount => Targets.Count - CompletedCount - ReviewRequiredCount - FailedCount;
    [JsonIgnore] public string Summary => StatusPresentation.Batch(this);
}
[method: System.Text.Json.Serialization.JsonConstructor]
public sealed record RemediationPreparationNote(string Target, string ReasonCode, string Detail)
{
    [System.Text.Json.Serialization.JsonIgnore(Condition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull)]
    public SteamSentinel.Core.Models.DisplayMessage? DetailMessage { get => SteamSentinel.Core.Reporting.MessageText.BoundDescriptor(field, Detail); init => field = value; }

    [System.Text.Json.Serialization.JsonIgnore]
    public SteamSentinel.Core.Reporting.MessageText DetailText
    {
        get => new(Detail ?? string.Empty, DetailMessage);
        init
        {
            Detail = value.OriginalText;
            DetailMessage = value.Message;
        }
    }

    public RemediationPreparationNote(string Target, string ReasonCode, SteamSentinel.Core.Reporting.MessageText Detail) : this(Target, ReasonCode, Detail.OriginalText)
    {
        DetailMessage = Detail.Message;
    }
}

public sealed class RemediationTargetOutcome
{
    public string Key { get; init; } = string.Empty;
    public string Target { get; init; } = string.Empty;
    public bool AddedByAssociation { get; init; }
    public List<string> FindingIds { get; init; } = [];
    public List<string> RequiredActions { get; init; } = [];
    public List<string> MissingActions { get; init; } = [];
    public List<Guid> ActionIds { get; init; } = [];
    public List<int> Batches { get; init; } = [];
    public RemediationTargetState State { get; set; }
    public string? ReasonCode { get; set; }
    public StatusMessage? ReasonMessage { get; set; }
    public string? ReasonDetails { get; set; }
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public DisplayMessage? ReasonDetailsMessage { get => SteamSentinel.Core.Reporting.MessageText.BoundDescriptor(field, ReasonDetails); set => field = value; }
    [JsonIgnore] public MessageText ReasonDetailsText => new(ReasonDetails ?? string.Empty, ReasonDetailsMessage);
    [JsonPropertyName("Status")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? LegacyStatus { get; set; }
    [JsonPropertyName("Reason")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? LegacyReason { get; set; }
    [JsonIgnore]
    public string Status => StatusPresentation.Target(State);
    [JsonIgnore]
    public string Reason
    {
        get => string.Join("\n", new[] { ReasonMessage is null ? LegacyReason : StatusPresentation.Format(ReasonMessage), ReasonDetailsText.Display }
            .Where(s => !string.IsNullOrWhiteSpace(s)));
    }

    public void SetState(RemediationTargetState state, string reason, MessageText? details = null)
    {
        if (!Enum.IsDefined(state) || !ReasonCodes.IsValid(reason)) throw new ArgumentException("Invalid target state or reason.");
        State = state;
        ReasonCode = reason;
        ReasonMessage = StatusMessage.Create(reason);
        ReasonDetails = details?.OriginalText;
        ReasonDetailsMessage = details?.Message;
    }
}
