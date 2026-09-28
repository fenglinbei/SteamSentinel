using System.Text.Json.Serialization;
using SteamSentinel.Core.Reporting;

namespace SteamSentinel.Core.Models;

public sealed partial class FileOccupancyResult
{
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public DisplayMessage? DiagnosticMessage { get => SteamSentinel.Core.Reporting.MessageText.BoundDescriptor(field, Diagnostic); init => field = value; }
    [JsonIgnore] public MessageText DiagnosticText { get => new(Diagnostic, DiagnosticMessage); init { Diagnostic = value.OriginalText; DiagnosticMessage = value.Message; } }
}
