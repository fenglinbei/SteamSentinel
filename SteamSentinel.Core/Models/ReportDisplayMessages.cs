using System.Text.Json.Serialization;
using SteamSentinel.Core.Reporting;

namespace SteamSentinel.Core.Models;

public sealed partial class ScanReport
{
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] public Dictionary<int, DisplayMessage>? CoverageNoteMessages { get => SteamSentinel.Core.Models.DisplayMessageMap.Bound(CoverageNotes, field); set => field = value; }
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] public Dictionary<int, DisplayMessage>? ScopeNoteMessages { get => SteamSentinel.Core.Models.DisplayMessageMap.Bound(ScopeNotes, field); set => field = value; }
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] public Dictionary<int, DisplayMessage>? ContentSourceMessages { get => SteamSentinel.Core.Models.DisplayMessageMap.Bound(ContentSources, field); set => field = value; }
    [JsonIgnore] public IEnumerable<MessageText> CoverageTexts => DisplayMessageMap.Read(CoverageNotes, CoverageNoteMessages);
    [JsonIgnore] public IEnumerable<MessageText> ScopeTexts => DisplayMessageMap.Read(ScopeNotes, ScopeNoteMessages);
    [JsonIgnore] public IEnumerable<MessageText> ContentSourceTexts => DisplayMessageMap.Read(ContentSources, ContentSourceMessages);
    public void AddCoverageNote(MessageText text) => CoverageNoteMessages = DisplayMessageMap.Add(CoverageNotes, CoverageNoteMessages, text);
    public void AddScopeNote(MessageText text) => ScopeNoteMessages = DisplayMessageMap.Add(ScopeNotes, ScopeNoteMessages, text);
    public void AddContentSource(MessageText text) => ContentSourceMessages = DisplayMessageMap.Add(ContentSources, ContentSourceMessages, text);
    public long ValidateTextMessages() => DisplayMessageMap.Validate(CoverageNotes, CoverageNoteMessages) +
        DisplayMessageMap.Validate(ScopeNotes, ScopeNoteMessages) + DisplayMessageMap.Validate(ContentSources, ContentSourceMessages);
}

/// <summary>Optional display metadata indexed within an unchanged original string list.</summary>
public static class DisplayMessageMap
{
    public static Dictionary<int, DisplayMessage>? Bound(IReadOnlyList<string>? originals, Dictionary<int, DisplayMessage>? messages)
    {
        if (messages is null || originals is null) return messages;
        Dictionary<int, DisplayMessage>? filtered = null;
        foreach ((int index, DisplayMessage message) in messages)
        {
            // Keep malformed entries so the receiving boundary can reject them.
            if (index < 0 || index >= originals.Count || message is null || MessageText.BoundDescriptor(message, originals[index]) is not null) continue;
            filtered ??= new(messages);
            filtered.Remove(index);
        }
        return filtered is null ? messages : filtered.Count == 0 ? null : filtered;
    }

    public static List<DisplayMessage?>? BoundErrors(IReadOnlyList<string>? originals, List<DisplayMessage?>? messages)
    {
        if (messages is null || originals is null || messages.Count != originals.Count) return messages;
        List<DisplayMessage?>? filtered = null;
        for (int index = 0; index < messages.Count; index++)
            if (messages[index] is { } message && MessageText.BoundDescriptor(message, originals[index]) is null)
            {
                filtered ??= [.. messages];
                filtered[index] = null;
            }
        return filtered is null ? messages : filtered.All(message => message is null) ? null : filtered;
    }
    public static Dictionary<int, DisplayMessage>? FromTexts(IEnumerable<MessageText> texts)
    {
        Dictionary<int, DisplayMessage>? messages = null;
        int index = 0;
        foreach (MessageText text in texts)
        {
            if (text.Message is not null) (messages ??= [])[index] = text.Message;
            index++;
        }
        return messages;
    }
    public static IEnumerable<MessageText> Read(IReadOnlyList<string> originals, IReadOnlyDictionary<int, DisplayMessage>? messages)
    {
        for (int i = 0; i < originals.Count; i++)
            yield return new(originals[i], messages is not null && messages.TryGetValue(i, out var message) ? message : null);
    }

    public static Dictionary<int, DisplayMessage>? Add(List<string> originals, Dictionary<int, DisplayMessage>? messages, MessageText text)
    {
        if (text.Message is not null) (messages ??= [])[originals.Count] = text.Message;
        originals.Add(text.OriginalText);
        return messages;
    }

    public static long Validate(IReadOnlyList<string> originals, IReadOnlyDictionary<int, DisplayMessage>? messages)
    {
        if (messages is null) return 0;
        if (messages.Count > originals.Count) throw new InvalidDataException("Display message index count exceeds its source list.");
        long characters = 0;
        foreach ((int index, DisplayMessage message) in messages)
        {
            if (index < 0 || index >= originals.Count || message is null) throw new InvalidDataException("Invalid display message index.");
            characters += message.Validate();
        }
        return characters;
    }

    public static Dictionary<int, DisplayMessage>? Slice(IReadOnlyDictionary<int, DisplayMessage>? messages, int offset, int count)
    {
        if (messages is null) return null;
        Dictionary<int, DisplayMessage> result = [];
        foreach ((int index, DisplayMessage message) in messages)
            if (index >= offset && index - offset < count) result.Add(index - offset, message);
        return result.Count == 0 ? null : result;
    }

    public static long RangeCharacters(IReadOnlyDictionary<int, DisplayMessage>? messages, int offset, int count) =>
        messages?.Where(pair => pair.Key >= offset && pair.Key - offset < count).Sum(pair => pair.Value.Validate()) ?? 0;

    public static Dictionary<int, DisplayMessage>? Put(Dictionary<int, DisplayMessage>? target,
        IReadOnlyDictionary<int, DisplayMessage>? values, int offset, int count)
    {
        if (target is not null)
            foreach (int index in target.Keys.Where(index => index >= offset && index - offset < count).ToArray()) target.Remove(index);
        if (values is not null)
            foreach ((int index, DisplayMessage message) in values) (target ??= [])[offset + index] = message;
        return target is { Count: > 0 } ? target : null;
    }
}
