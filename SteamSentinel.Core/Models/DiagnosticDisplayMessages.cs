using System.Text.Json.Serialization;
using SteamSentinel.Core.Reporting;

namespace SteamSentinel.Core.Models;

public sealed partial class RelatedSourceObservation
{
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public DisplayMessage? DetailMessage { get => SteamSentinel.Core.Reporting.MessageText.BoundDescriptor(field, Detail); set => field = value; }
    [JsonIgnore] public MessageText DetailText { get => new(Detail ?? string.Empty, DetailMessage); set { Detail = value.OriginalText; DetailMessage = value.Message; } }
    public long ValidateDisplayMessages() => (DetailMessage?.Validate() ?? 0);
}

public sealed partial class RelatedHostObservation
{
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public DisplayMessage? DetailMessage { get => SteamSentinel.Core.Reporting.MessageText.BoundDescriptor(field, Detail); set => field = value; }
    [JsonIgnore] public MessageText DetailText { get => new(Detail ?? string.Empty, DetailMessage); set { Detail = value.OriginalText; DetailMessage = value.Message; } }
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public DisplayMessage? SignatureDetailMessage { get => SteamSentinel.Core.Reporting.MessageText.BoundDescriptor(field, SignatureDetail); set => field = value; }
    [JsonIgnore] public MessageText SignatureDetailText { get => new(SignatureDetail ?? string.Empty, SignatureDetailMessage); set { SignatureDetail = value.OriginalText; SignatureDetailMessage = value.Message; } }
    public long ValidateDisplayMessages() => (DetailMessage?.Validate() ?? 0) + (SignatureDetailMessage?.Validate() ?? 0);
}

public sealed partial class RelatedComponentCandidate
{
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public DisplayMessage? ReasonMessage { get => SteamSentinel.Core.Reporting.MessageText.BoundDescriptor(field, Reason); set => field = value; }
    [JsonIgnore] public MessageText ReasonText { get => new(Reason ?? string.Empty, ReasonMessage); set { Reason = value.OriginalText; ReasonMessage = value.Message; } }
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public DisplayMessage? DetailMessage { get => SteamSentinel.Core.Reporting.MessageText.BoundDescriptor(field, Detail); set => field = value; }
    [JsonIgnore] public MessageText DetailText { get => new(Detail ?? string.Empty, DetailMessage); set { Detail = value.OriginalText; DetailMessage = value.Message; } }
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public DisplayMessage? ContentDetailMessage { get => SteamSentinel.Core.Reporting.MessageText.BoundDescriptor(field, ContentDetail); set => field = value; }
    [JsonIgnore] public MessageText ContentDetailText { get => new(ContentDetail ?? string.Empty, ContentDetailMessage); set { ContentDetail = value.OriginalText; ContentDetailMessage = value.Message; } }
    public long ValidateDisplayMessages() => (ReasonMessage?.Validate() ?? 0) + (DetailMessage?.Validate() ?? 0) + (ContentDetailMessage?.Validate() ?? 0);
}

public sealed partial class RelatedScanRound
{
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public DisplayMessage? DetailMessage { get => SteamSentinel.Core.Reporting.MessageText.BoundDescriptor(field, Detail); set => field = value; }
    [JsonIgnore] public MessageText DetailText { get => new(Detail ?? string.Empty, DetailMessage); set { Detail = value.OriginalText; DetailMessage = value.Message; } }
    public long ValidateDisplayMessages() => (DetailMessage?.Validate() ?? 0);
}

public sealed partial class DiagnosticCheck
{
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public DisplayMessage? NameMessage { get => SteamSentinel.Core.Reporting.MessageText.BoundDescriptor(field, Name); init => field = value; }
    [JsonIgnore] public MessageText NameText { get => new(Name ?? string.Empty, NameMessage); init { Name = value.OriginalText; NameMessage = value.Message; } }
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public DisplayMessage? DetailMessage { get => SteamSentinel.Core.Reporting.MessageText.BoundDescriptor(field, Detail); init => field = value; }
    [JsonIgnore] public MessageText DetailText { get => new(Detail ?? string.Empty, DetailMessage); init { Detail = value.OriginalText; DetailMessage = value.Message; } }
    public long ValidateDisplayMessages() => (NameMessage?.Validate() ?? 0) + (DetailMessage?.Validate() ?? 0);
}

public sealed partial class ProxyConfigurationObservation
{
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public DisplayMessage? DetailMessage { get => SteamSentinel.Core.Reporting.MessageText.BoundDescriptor(field, Detail); init => field = value; }
    [JsonIgnore] public MessageText DetailText { get => new(Detail ?? string.Empty, DetailMessage); init { Detail = value.OriginalText; DetailMessage = value.Message; } }
    public long ValidateDisplayMessages() => (DetailMessage?.Validate() ?? 0) +
        (ProxyServerMessage?.Validate() ?? 0) + (ProxyBypassMessage?.Validate() ?? 0) + (AutoConfigUrlMessage?.Validate() ?? 0);
}

public sealed partial class CertificateStoreObservation
{
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public DisplayMessage? DetailMessage { get => SteamSentinel.Core.Reporting.MessageText.BoundDescriptor(field, Detail); set => field = value; }
    [JsonIgnore] public MessageText DetailText { get => new(Detail ?? string.Empty, DetailMessage); set { Detail = value.OriginalText; DetailMessage = value.Message; } }
    public long ValidateDisplayMessages() => (DetailMessage?.Validate() ?? 0);
}

public sealed partial class CertificateObservation
{
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public DisplayMessage? ChainDetailMessage { get => SteamSentinel.Core.Reporting.MessageText.BoundDescriptor(field, ChainDetail); set => field = value; }
    [JsonIgnore] public MessageText ChainDetailText { get => new(ChainDetail ?? string.Empty, ChainDetailMessage); set { ChainDetail = value.OriginalText; ChainDetailMessage = value.Message; } }
    public long ValidateDisplayMessages() => (ChainDetailMessage?.Validate() ?? 0);
}

public sealed partial class CaseSessionObservation
{
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public DisplayMessage? DetailMessage { get => SteamSentinel.Core.Reporting.MessageText.BoundDescriptor(field, Detail); init => field = value; }
    [JsonIgnore] public MessageText DetailText { get => new(Detail ?? string.Empty, DetailMessage); init { Detail = value.OriginalText; DetailMessage = value.Message; } }
    public long ValidateDisplayMessages() => (DetailMessage?.Validate() ?? 0);
}

public sealed partial class CaseVerificationEpisode
{
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public DisplayMessage? SummaryMessage { get => SteamSentinel.Core.Reporting.MessageText.BoundDescriptor(field, Summary); set => field = value; }
    [JsonIgnore] public MessageText SummaryText { get => new(Summary ?? string.Empty, SummaryMessage); set { Summary = value.OriginalText; SummaryMessage = value.Message; } }
    public long ValidateDisplayMessages() => (SummaryMessage?.Validate() ?? 0);
}

public sealed partial class CaseActionVerification
{
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public DisplayMessage? MessageMessage { get => SteamSentinel.Core.Reporting.MessageText.BoundDescriptor(field, Message); init => field = value; }
    [JsonIgnore] public MessageText MessageText { get => new(Message ?? string.Empty, MessageMessage); init { Message = value.OriginalText; MessageMessage = value.Message; } }
    public long ValidateDisplayMessages() => (MessageMessage?.Validate() ?? 0);
}

public sealed partial class CaseFollowUpResult
{
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public DisplayMessage? DetailMessage { get => SteamSentinel.Core.Reporting.MessageText.BoundDescriptor(field, Detail); init => field = value; }
    [JsonIgnore] public MessageText DetailText { get => new(Detail ?? string.Empty, DetailMessage); init { Detail = value.OriginalText; DetailMessage = value.Message; } }
    public long ValidateDisplayMessages() => (DetailMessage?.Validate() ?? 0);
}

public sealed partial class RemediationCaseSummary
{
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public DisplayMessage? DetailMessage { get => SteamSentinel.Core.Reporting.MessageText.BoundDescriptor(field, Detail); init => field = value; }
    [JsonIgnore] public MessageText DetailText { get => new(Detail ?? string.Empty, DetailMessage); init { Detail = value.OriginalText; DetailMessage = value.Message; } }
    public long ValidateDisplayMessages() => (DetailMessage?.Validate() ?? 0);
}
