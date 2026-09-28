using System.Text.Json.Serialization;
using SteamSentinel.Core.Reporting;

namespace SteamSentinel.Core.Models;

public sealed partial class HashRule
{
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public DisplayMessage? LabelMessage { get => SteamSentinel.Core.Reporting.MessageText.BoundDescriptor(field, Label); init => field = value; }
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public DisplayMessage? EvidenceMessage { get => SteamSentinel.Core.Reporting.MessageText.BoundDescriptor(field, Evidence); init => field = value; }
    [JsonIgnore] public MessageText LabelText => new(Label, LabelMessage);
    [JsonIgnore] public MessageText? EvidenceText => Evidence is null ? null : new(Evidence, EvidenceMessage);
}

public sealed partial class StringRule
{
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public DisplayMessage? LabelMessage { get => SteamSentinel.Core.Reporting.MessageText.BoundDescriptor(field, Label); init => field = value; }
    [JsonIgnore] public MessageText LabelText => new(Label, LabelMessage);
}
