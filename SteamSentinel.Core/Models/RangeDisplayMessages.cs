using System.Text.Json.Serialization;
using SteamSentinel.Core.Reporting;

namespace SteamSentinel.Core.Models;

public sealed partial class ContainerRange
{
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public DisplayMessage? DetailMessage { get => SteamSentinel.Core.Reporting.MessageText.BoundDescriptor(field, Detail); init => field = value; }
    [JsonIgnore] public MessageText DetailText { get => new(Detail ?? string.Empty, DetailMessage); init { Detail = value.OriginalText; DetailMessage = value.Message; } }
    public long ValidateDisplayMessages() => (DetailMessage?.Validate() ?? 0);
}

public sealed partial class ContainerRangeInspection
{
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public DisplayMessage? DetailMessage { get => SteamSentinel.Core.Reporting.MessageText.BoundDescriptor(field, Detail); set => field = value; }
    [JsonIgnore] public MessageText DetailText { get => new(Detail ?? string.Empty, DetailMessage); set { Detail = value.OriginalText; DetailMessage = value.Message; } }
    public long ValidateDisplayMessages() => (DetailMessage?.Validate() ?? 0);
}

public sealed partial class ContainerRangeCheck
{
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public DisplayMessage? DetailMessage { get => SteamSentinel.Core.Reporting.MessageText.BoundDescriptor(field, Detail); init => field = value; }
    [JsonIgnore] public MessageText DetailText { get => new(Detail ?? string.Empty, DetailMessage); init { Detail = value.OriginalText; DetailMessage = value.Message; } }
    public long ValidateDisplayMessages() => (DetailMessage?.Validate() ?? 0);
}

public sealed partial class ContainerRangeRarInspection
{
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public DisplayMessage? DetailMessage { get => SteamSentinel.Core.Reporting.MessageText.BoundDescriptor(field, Detail); set => field = value; }
    [JsonIgnore] public MessageText DetailText { get => new(Detail ?? string.Empty, DetailMessage); set { Detail = value.OriginalText; DetailMessage = value.Message; } }
    public long ValidateDisplayMessages() => (DetailMessage?.Validate() ?? 0);
}

public sealed partial class ContainerRangeSfxDirective
{
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public DisplayMessage? SourceMessage { get => SteamSentinel.Core.Reporting.MessageText.BoundDescriptor(field, Source); init => field = value; }
    [JsonIgnore] public MessageText SourceText { get => new(Source ?? string.Empty, SourceMessage); init { Source = value.OriginalText; SourceMessage = value.Message; } }
    public long ValidateDisplayMessages() => (SourceMessage?.Validate() ?? 0);
}
