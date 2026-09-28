using SteamSentinel.Core.Models;

namespace SteamSentinel.Core.Reporting;

// Internal analysis lists retain their existing source-string API. Only explicit AddText
// calls attach display metadata; comparison and detection continue to use original text.
internal sealed class MessageTextCollection : List<string>
{
    private Dictionary<int, DisplayMessage>? _messages;
    public IEnumerable<MessageText> Texts => DisplayMessageMap.Read(this, _messages);
    public void AddText(MessageText text) => _messages = DisplayMessageMap.Add(this, _messages, text);
    public Dictionary<int, DisplayMessage>? CopyMessages() => _messages is null ? null : new(_messages);
}
