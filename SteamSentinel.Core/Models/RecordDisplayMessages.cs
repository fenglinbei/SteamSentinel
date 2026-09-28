using System.Text.Json.Serialization;
using SteamSentinel.Core.Reporting;

namespace SteamSentinel.Core.Models;

public sealed partial class Finding
{
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public DisplayMessage? TitleMessage { get => SteamSentinel.Core.Reporting.MessageText.BoundDescriptor(field, Title); init => field = value; }
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public DisplayMessage? TargetMessage { get => SteamSentinel.Core.Reporting.MessageText.BoundDescriptor(field, Target); init => field = value; }
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public DisplayMessage? DescriptionMessage { get => SteamSentinel.Core.Reporting.MessageText.BoundDescriptor(field, Description); init => field = value; }
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public DisplayMessage? EvidenceMessage { get => SteamSentinel.Core.Reporting.MessageText.BoundDescriptor(field, Evidence); init => field = value; }
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public DisplayMessage? HandlingDetailsMessage { get => SteamSentinel.Core.Reporting.MessageText.BoundDescriptor(field, HandlingDetails); init => field = value; }
    [JsonIgnore] public MessageText TitleText { get => new(Title, TitleMessage); init { Title = value.OriginalText; TitleMessage = value.Message; } }
    [JsonIgnore] public MessageText TargetText { get => new(Target, TargetMessage); init { Target = value.OriginalText; TargetMessage = value.Message; } }
    [JsonIgnore] public MessageText DescriptionText { get => new(Description, DescriptionMessage); init { Description = value.OriginalText; DescriptionMessage = value.Message; } }
    [JsonIgnore] public MessageText EvidenceText { get => new(Evidence, EvidenceMessage); init { Evidence = value.OriginalText; EvidenceMessage = value.Message; EvidenceLineMessages = null; } }
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] public Dictionary<int, DisplayMessage>? EvidenceLineMessages { get => SteamSentinel.Core.Models.DisplayMessageMap.Bound((Evidence ?? string.Empty).Split('\n'), field); init => field = value; }
    [JsonIgnore]
    public IEnumerable<MessageText> EvidenceLines
    {
        get => DisplayMessageMap.Read((Evidence ?? string.Empty).Split('\n'), EvidenceLineMessages);
        init
        {
            List<string> lines = [];
            Dictionary<int, DisplayMessage>? messages = null;
            foreach (MessageText line in value)
            {
                // A multi-line source has no single-line binding; retain it without guessing.
                if (line.OriginalText.Contains('\n')) lines.AddRange(line.OriginalText.Split('\n'));
                else messages = DisplayMessageMap.Add(lines, messages, line);
            }
            Evidence = string.Join("\n", lines); EvidenceMessage = null; EvidenceLineMessages = messages;
        }
    }
    [JsonIgnore] public string EvidenceDisplay => EvidenceLineMessages is null ? EvidenceText.Display : string.Join("\n", EvidenceLines.Select(line => line.Display));
    [JsonIgnore] public MessageText HandlingDetailsText { get => new(HandlingDetails ?? string.Empty, HandlingDetailsMessage); init { HandlingDetails = value.OriginalText; HandlingDetailsMessage = value.Message; } }
    public long ValidateDisplayMessages() => (TitleMessage?.Validate() ?? 0) + (TargetMessage?.Validate() ?? 0) + (DescriptionMessage?.Validate() ?? 0) +
        (EvidenceMessage?.Validate() ?? 0) + (HandlingDetailsMessage?.Validate() ?? 0) +
        DisplayMessageMap.Validate((Evidence ?? string.Empty).Split('\n'), EvidenceLineMessages);
}

public sealed partial class RemediationAction
{
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public DisplayMessage? DisplayNameMessage { get => SteamSentinel.Core.Reporting.MessageText.BoundDescriptor(field, DisplayName); init => field = value; }
    [JsonIgnore] public MessageText DisplayNameText { get => new(DisplayName, DisplayNameMessage); init { DisplayName = value.OriginalText; DisplayNameMessage = value.Message; } }
}

public sealed partial class RemediationActionResult
{
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public DisplayMessage? ResultMessage { get => SteamSentinel.Core.Reporting.MessageText.BoundDescriptor(field, Message); set => field = value; }
    [JsonIgnore] public MessageText MessageText { get => new(Message, ResultMessage); set { Message = value.OriginalText; ResultMessage = value.Message; } }
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public DisplayMessage? VerificationSummaryMessage { get => SteamSentinel.Core.Reporting.MessageText.BoundDescriptor(field, VerificationSummary); set => field = value; }
    [JsonIgnore] public MessageText VerificationSummaryText { get => new(VerificationSummary, VerificationSummaryMessage); set { VerificationSummary = value.OriginalText; VerificationSummaryMessage = value.Message; } }
}

public sealed partial class RemediationVerificationObservation
{
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public DisplayMessage? ResultMessage { get => SteamSentinel.Core.Reporting.MessageText.BoundDescriptor(field, Message); init => field = value; }
    [JsonIgnore] public MessageText MessageText { get => new(Message, ResultMessage); init { Message = value.OriginalText; ResultMessage = value.Message; } }
}

public sealed partial class RemediationRunResult
{
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public DisplayMessage? VerificationSummaryMessage { get => SteamSentinel.Core.Reporting.MessageText.BoundDescriptor(field, VerificationSummary); set => field = value; }
    [JsonIgnore] public MessageText VerificationSummaryText { get => new(VerificationSummary, VerificationSummaryMessage); set { VerificationSummary = value.OriginalText; VerificationSummaryMessage = value.Message; } }
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] public List<DisplayMessage?>? ErrorMessages { get => DisplayMessageMap.BoundErrors(Errors, field); set => field = value; }
    public void AddError(MessageText text)
    {
        ErrorMessages ??= Enumerable.Repeat<DisplayMessage?>(null, Errors.Count).ToList();
        while (ErrorMessages.Count < Errors.Count) ErrorMessages.Add(null);
        Errors.Add(text.OriginalText);
        ErrorMessages.Add(text.Message);
    }
    [JsonIgnore]
    public IEnumerable<string> DisplayErrors => Errors.Select((text, index) =>
        MessageText.Render(ErrorMessages is not null && index < ErrorMessages.Count ? ErrorMessages[index] : null, text));
}

public sealed partial class WorkerMessage
{
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public DisplayMessage? ErrorMessage { get => SteamSentinel.Core.Reporting.MessageText.BoundDescriptor(field, Error); init => field = value; }
    [JsonIgnore] public MessageText ErrorText { get => new(Error ?? string.Empty, ErrorMessage); init { Error = value.OriginalText; ErrorMessage = value.Message; } }
}
