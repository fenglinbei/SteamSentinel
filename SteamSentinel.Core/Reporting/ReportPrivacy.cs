using System.Text.Json.Nodes;
using System.Text.Json;
using System.Text.Json.Serialization;
using SteamSentinel.Core.Utilities;
using SteamSentinel.Core.Inspection;

namespace SteamSentinel.Core.Reporting;

public static class ReportPrivacy
{
    public static JsonSerializerOptions ExportOptions { get; } = CreateOptions();
    private static JsonSerializerOptions CreateOptions()
    {
        JsonSerializerOptions options = new(JsonFile.Options);
        options.Converters.Add(new RedactedStringConverter());
        return options;
    }
    private sealed class RedactedStringConverter : JsonConverter<string>
    {
        public override string? Read(ref Utf8JsonReader reader, Type type, JsonSerializerOptions options) => reader.GetString();
        public override void Write(Utf8JsonWriter writer, string value, JsonSerializerOptions options) =>
            writer.WriteStringValue(ScriptSignals.RedactSecrets(value));
    }
    public static JsonNode? Scrub(JsonNode? node)
    {
        if (node is JsonObject obj)
            foreach (string key in obj.Select(pair => pair.Key).ToArray())
            {
                if (obj[key] is JsonValue value && value.TryGetValue(out string? text)) obj[key] = ScriptSignals.RedactSecrets(text ?? "");
                else Scrub(obj[key]);
            }
        else if (node is JsonArray array)
            for (int i = 0; i < array.Count; i++)
                if (array[i] is JsonValue value && value.TryGetValue(out string? text)) array[i] = ScriptSignals.RedactSecrets(text ?? "");
                else Scrub(array[i]);
        return node;
    }
}
