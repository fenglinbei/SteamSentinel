using System.Globalization;
using SteamSentinel.Core.Models;

namespace SteamSentinel.Core.Reporting;

/// <summary>Producer text and its optional descriptor travel together until assigned to a record.</summary>
public sealed record MessageText(string OriginalText, DisplayMessage? Message = null)
{
    public string Display => Render(Message, OriginalText);
    public static MessageText Status(string id, params string[] arguments) => Create("Status." + id, arguments.Cast<object?>().ToArray());

    public static MessageText Create(string id, params object?[] arguments)
    {
        DisplayArgument[] values = arguments.Select(value => value is MessageText text
            ? new DisplayArgument(text.OriginalText, text.Message)
            : new DisplayArgument(Convert.ToString(value, CultureInfo.InvariantCulture) ?? string.Empty)).ToArray();
        DisplayMessage descriptor = new(id, values);
        string original;
        using (DisplayText.UseCulture(DisplayText.Chinese))
            original = DisplayText.Format(id, values.Select(value => (object?)value.OriginalText).ToArray());
        try { descriptor.Validate(); }
        catch (InvalidDataException) { return new(original); } // Preserve all source text if display metadata would exceed its budget.
        return new(original, descriptor);
    }

    public static string Render(DisplayMessage? message, string? original)
    {
        string fallback = original ?? string.Empty;
        if (message is null) return fallback;
        try { message.Validate(); }
        catch (InvalidDataException) { return fallback; }
        return RenderValidated(message, fallback);
    }

    // Legacy callers can still write an original field directly. Never display or save
    // a known descriptor whose source text no longer belongs to that field. Unknown IDs
    // remain intact for forward compatibility; invalid metadata remains visible to validators.
    public static DisplayMessage? BoundDescriptor(DisplayMessage? message, string? original)
    {
        if (message is null) return null;
        try { message.Validate(); }
        catch (InvalidDataException) { return message; }
        using (DisplayText.UseCulture(DisplayText.Chinese))
            return DisplayText.TryFormat(message.MessageId, message.Arguments.Select(argument => (object?)argument.OriginalText).ToArray(), out string expected) &&
                !string.Equals(expected, original ?? string.Empty, StringComparison.Ordinal) ? null : message;
    }

    private static string RenderValidated(DisplayMessage message, string fallback)
    {
        if (BoundDescriptor(message, fallback) is null) return fallback;
        object?[] arguments = message.Arguments.Select(value => (object?)(value.Message is null
            ? value.OriginalText : RenderValidated(value.Message, value.OriginalText))).ToArray();
        return DisplayText.TryFormat(message.MessageId, arguments, out string text) ? text : fallback;
    }

    public static implicit operator MessageText(string? value) => new(value ?? string.Empty);
    public static MessageText List(IEnumerable<MessageText> items)
    {
        MessageText[] values = items.ToArray();
        if (values.Length == 0) return string.Empty;
        if (values.Length > MaximumListItems) return string.Join(Create("Common.ListSeparator").OriginalText, values.Select(item => item.OriginalText));
        return Create("Backend.List." + values.Length, values.Cast<object?>().ToArray());
    }
    private const int MaximumListItems = 8;
    public static MessageText Join(string separator, IEnumerable<MessageText> items) => Join(new MessageText(separator), items);
    public static MessageText Join(MessageText separator, IEnumerable<MessageText> items)
    {
        MessageText[] values = items.ToArray();
        if (values.Length == 0) return string.Empty;
        // Group modest lists without increasing the descriptor's fixed depth/node budget.
        // Create drops metadata if the combined tree exceeds that budget.
        if (values.Length > 49) return string.Join(separator.OriginalText, values.Select(item => item.OriginalText));
        if (values.Length > 7) return Join(separator, values.Chunk(7).Select(group => Join(separator, group)));
        return Create("Backend.Join." + values.Length, values.Cast<object?>().Append(separator).ToArray());
    }
    // Ordinary string consumers see the immutable source text. Presentation must opt in explicitly.
    public static implicit operator string(MessageText value) => value.OriginalText;
    public static MessageText operator +(MessageText left, MessageText right) => Create("Backend.Concat", left, right);
    public static MessageText operator +(MessageText left, string? right) => left + (MessageText)right;
    public static MessageText operator +(string? left, MessageText right) => (MessageText)left + right;
    public static MessageText operator +(MessageText left, int right) => Create("Backend.Concat", left, right);
    public static MessageText operator +(int left, MessageText right) => Create("Backend.Concat", left, right);
    public static MessageText operator +(MessageText left, long right) => Create("Backend.Concat", left, right);
    public static MessageText operator +(MessageText left, uint right) => Create("Backend.Concat", left, right);
    public static MessageText operator +(MessageText left, Guid right) => Create("Backend.Concat", left, right);
    public MessageText Limit(int maximumCharacters) => OriginalText.Length <= maximumCharacters ? this : new(OriginalText[..maximumCharacters]);
    public MessageText RedactSecrets()
    {
        string original = Inspection.ScriptSignals.RedactSecrets(OriginalText);
        if (Message is null) return new(original);
        try { Message.Validate(); }
        catch (InvalidDataException) { return new(original); }
        return new(original, RedactDescriptor(Message));
    }
    private static DisplayMessage RedactDescriptor(DisplayMessage message) => new(message.MessageId,
        message.Arguments.Select(argument => new DisplayArgument(Inspection.ScriptSignals.RedactSecrets(argument.OriginalText),
            argument.Message is null ? null : RedactDescriptor(argument.Message))).ToArray());
    public override string ToString() => OriginalText;
}

public static class MessageExceptions
{
    private const string DataKey = "SteamSentinel.DisplayMessage";

    public static T Create<T>(MessageText text, Func<string, T> factory) where T : Exception
    {
        T exception = factory(text.OriginalText);
        Attach(exception, text);
        return exception;
    }

    public static void Attach(Exception exception, MessageText text)
    {
        if (text.Message is not null) exception.Data[DataKey] = text.Message;
    }

    public static MessageText Describe(Exception exception) =>
        new(exception.Message, exception.Data[DataKey] as DisplayMessage);

    public static string Display(Exception exception) => Describe(exception).Display;

    public static System.ComponentModel.Win32Exception Win32(int error, MessageText text) =>
        Create(text, source => new System.ComponentModel.Win32Exception(error, source));
}
