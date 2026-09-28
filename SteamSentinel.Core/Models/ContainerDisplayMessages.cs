using System.Text.Json.Serialization;
using SteamSentinel.Core.Reporting;

namespace SteamSentinel.Core.Models;

public sealed partial class ContainerEngineObservation
{
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public DisplayMessage? EngineMessage { get => SteamSentinel.Core.Reporting.MessageText.BoundDescriptor(field, Engine); set => field = value; }
    [JsonIgnore] public MessageText EngineText { get => new(Engine, EngineMessage); init { Engine = value.OriginalText; EngineMessage = value.Message; } }
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public DisplayMessage? DetailMessage { get => SteamSentinel.Core.Reporting.MessageText.BoundDescriptor(field, Detail); set => field = value; }
    [JsonIgnore] public MessageText DetailText { get => new(Detail, DetailMessage); set { Detail = value.OriginalText; DetailMessage = value.Message; } }
}

public sealed partial class ContainerScanNode
{
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public DisplayMessage? FormatMessage { get => SteamSentinel.Core.Reporting.MessageText.BoundDescriptor(field, Format); set => field = value; }
    [JsonIgnore] public MessageText FormatText { get => new(Format, FormatMessage); set { Format = value.OriginalText; FormatMessage = value.Message; } }
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] public Dictionary<int, DisplayMessage>? DetailMessages { get => SteamSentinel.Core.Models.DisplayMessageMap.Bound(Details, field); set => field = value; }
    [JsonIgnore] public IEnumerable<MessageText> DetailTexts => DisplayMessageMap.Read(Details, DetailMessages);
    public void AddDetail(MessageText text) => DetailMessages = DisplayMessageMap.Add(Details, DetailMessages, text);
}

public sealed partial class ContainerScanReport
{
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] public Dictionary<int, DisplayMessage>? CheckMessages { get => SteamSentinel.Core.Models.DisplayMessageMap.Bound(Checks, field); set => field = value; }
    [JsonIgnore] public IEnumerable<MessageText> CheckTexts => DisplayMessageMap.Read(Checks, CheckMessages);
    public void AddCheck(MessageText text) => CheckMessages = DisplayMessageMap.Add(Checks, CheckMessages, text);
}
