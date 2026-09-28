using SteamSentinel.Core.Reporting;
using System.Buffers.Binary;
using System.Text;

namespace SteamSentinel.Core.Inspection;

[method: System.Text.Json.Serialization.JsonConstructor]
public sealed record ShortcutInspection(string? Target, string? Arguments, string? WorkingDirectory, bool Complete, string Detail)
{
    [System.Text.Json.Serialization.JsonIgnore(Condition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull)]
    public SteamSentinel.Core.Models.DisplayMessage? DetailMessage { get => SteamSentinel.Core.Reporting.MessageText.BoundDescriptor(field, Detail); init => field = value; }

    [System.Text.Json.Serialization.JsonIgnore]
    public SteamSentinel.Core.Reporting.MessageText DetailText
    {
        get => new(Detail ?? string.Empty, DetailMessage);
        init
        {
            Detail = value.OriginalText;
            DetailMessage = value.Message;
        }
    }

    public ShortcutInspection(string? Target, string? Arguments, string? WorkingDirectory, bool Complete, SteamSentinel.Core.Reporting.MessageText Detail) : this(Target, Arguments, WorkingDirectory, Complete, Detail.OriginalText)
    {
        DetailMessage = Detail.Message;
    }
}

/// <summary>MS-SHLLINK bytes only. No Shell COM resolution, icon lookup or network access.</summary>
public static class ShortcutInspector
{
    public static ShortcutInspection Inspect(ReadOnlySpan<byte> data)
    {
        try
        {
            if (data.Length < 76 || data.Length > 1024 * 1024 || U32(data, 0) != 76 ||
                !data.Slice(4, 16).SequenceEqual(new Guid("00021401-0000-0000-c000-000000000046").ToByteArray()))
                throw MessageExceptions.Create(MessageText.Create("Backend.Core.ShortcutInspector.Inspect.01"), sourceText => new InvalidDataException(sourceText));
            uint flags = U32(data, 20);
            int position = 76;
            bool complete = (flags & 1) == 0;
            if ((flags & 1) != 0) position = checked(position + 2 + U16(data, position));
            string? target = null;
            if ((flags & 2) != 0)
            {
                int size = checked((int)U32(data, position));
                ReadOnlySpan<byte> info = data.Slice(position, size);
                int header = checked((int)U32(info, 4));
                if (header < 28 || header > size) throw MessageExceptions.Create(MessageText.Create("Backend.Core.ShortcutInspector.Inspect.02"), sourceText => new InvalidDataException(sourceText));
                uint infoFlags = U32(info, 8);
                if ((infoFlags & 1) != 0)
                {
                    int unicodeOffset = header >= 36 ? checked((int)U32(info, 28)) : 0;
                    int baseOffset = unicodeOffset > 0 ? unicodeOffset : checked((int)U32(info, 16));
                    target = ZString(info, baseOffset, unicodeOffset > 0);
                    int suffixUnicode = header >= 36 ? checked((int)U32(info, 32)) : 0;
                    string suffix = ZString(info, suffixUnicode > 0 ? suffixUnicode : checked((int)U32(info, 24)), suffixUnicode > 0);
                    if (!string.IsNullOrEmpty(suffix) && !target.EndsWith(suffix, StringComparison.OrdinalIgnoreCase))
                        target = target.TrimEnd('\\') + "\\" + suffix.TrimStart('\\');
                    complete = true;
                }
                if ((infoFlags & 2) != 0) complete = false;
                position = checked(position + size);
            }
            bool unicode = (flags & 128) != 0;
            string? relative = null, working = null, arguments = null;
            foreach (uint flag in new uint[] { 4, 8, 16, 32, 64 })
            {
                if ((flags & flag) == 0) continue;
                int count = U16(data, position); position += 2;
                int bytes = checked(count * (unicode ? 2 : 1));
                string value = (unicode ? Encoding.Unicode : Encoding.Latin1).GetString(data.Slice(position, bytes));
                position += bytes;
                if (flag == 8) relative = value;
                if (flag == 16) working = value;
                if (flag == 32) arguments = value;
            }
            target ??= relative;
            if ((flags & 0x02000000) != 0 || position + 4 < data.Length && U32(data, position) != 0) complete = false;
            if (string.IsNullOrWhiteSpace(target) || target.StartsWith("\\\\", StringComparison.Ordinal)) complete = false;
            return new(target, arguments, working, complete,
                complete ? MessageText.Create("Backend.Core.ShortcutInspector.Inspect.03") : MessageText.Create("Backend.Core.ShortcutInspector.Inspect.04"));
        }
        catch (Exception ex) when (ex is ArgumentOutOfRangeException or OverflowException or InvalidDataException)
        { return new(null, null, null, false, MessageExceptions.Describe(ex)); }
    }

    private static uint U32(ReadOnlySpan<byte> data, int offset) => BinaryPrimitives.ReadUInt32LittleEndian(data.Slice(offset, 4));
    private static ushort U16(ReadOnlySpan<byte> data, int offset) => BinaryPrimitives.ReadUInt16LittleEndian(data.Slice(offset, 2));
    private static string ZString(ReadOnlySpan<byte> data, int offset, bool unicode)
    {
        if (offset == 0) return "";
        int end = offset, stride = unicode ? 2 : 1;
        while (end + stride <= data.Length && (data[end] != 0 || unicode && data[end + 1] != 0)) end += stride;
        if (end + stride > data.Length) throw MessageExceptions.Create(MessageText.Create("Backend.Core.ShortcutInspector.ZString.01"), sourceText => new InvalidDataException(sourceText));
        return (unicode ? Encoding.Unicode : Encoding.Latin1).GetString(data.Slice(offset, end - offset));
    }
}
