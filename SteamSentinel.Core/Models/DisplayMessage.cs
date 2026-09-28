namespace SteamSentinel.Core.Models;

/// <summary>Optional display data. It never supplies a status, reason, target or permission.</summary>
public sealed record DisplayMessage(string MessageId, IReadOnlyList<DisplayArgument> Arguments)
{
    public const int MaximumArguments = 8;
    public const int MaximumDepth = 4;
    public const int MaximumNodes = 32;
    public const int MaximumCharacters = 16384;

    public long Validate()
    {
        int nodes = 0;
        long characters = 0;
        Visit(this, 1, ref nodes, ref characters);
        return characters;
    }

    private static void Visit(DisplayMessage value, int depth, ref int nodes, ref long characters)
    {
        if (depth > MaximumDepth || ++nodes > MaximumNodes || !ReasonCodes.IsValid(value.MessageId) ||
            value.Arguments is null || value.Arguments.Count > MaximumArguments)
            throw new InvalidDataException("Invalid display message descriptor.");
        characters += value.MessageId.Length;
        foreach (DisplayArgument argument in value.Arguments)
        {
            if (argument is null || argument.OriginalText is null || argument.OriginalText.Length > 4096)
                throw new InvalidDataException("Invalid display message argument.");
            characters += argument.OriginalText.Length;
            if (characters > MaximumCharacters) throw new InvalidDataException("Display message text limit exceeded.");
            if (argument.Message is not null) Visit(argument.Message, depth + 1, ref nodes, ref characters);
        }
        if (characters > MaximumCharacters) throw new InvalidDataException("Display message text limit exceeded.");
    }
}

public sealed record DisplayArgument(string OriginalText, DisplayMessage? Message = null);
