using System.Buffers.Binary;
using System.Text;

namespace SteamSentinel.Core.Inspection;

public sealed record ShortcutInspection(string? Target, string? Arguments, string? WorkingDirectory, bool Complete, string Detail);

/// <summary>MS-SHLLINK bytes only. No Shell COM resolution, icon lookup or network access.</summary>
public static class ShortcutInspector
{
    public static ShortcutInspection Inspect(ReadOnlySpan<byte> data)
    {
        try
        {
            if (data.Length < 76 || data.Length > 1024 * 1024 || U32(data, 0) != 76 ||
                !data.Slice(4, 16).SequenceEqual(new Guid("00021401-0000-0000-c000-000000000046").ToByteArray()))
                throw new InvalidDataException("快捷方式头无效或超过上限");
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
                if (header < 28 || header > size) throw new InvalidDataException("LinkInfo 头无效");
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
                complete ? "已读取目标、参数和工作目录，未启动或解析目标" : "已读取可用字段，网络、IDList 或扩展块未解析，未访问目标");
        }
        catch (Exception ex) when (ex is ArgumentOutOfRangeException or OverflowException or InvalidDataException)
        { return new(null, null, null, false, ex.Message); }
    }

    private static uint U32(ReadOnlySpan<byte> data, int offset) => BinaryPrimitives.ReadUInt32LittleEndian(data.Slice(offset, 4));
    private static ushort U16(ReadOnlySpan<byte> data, int offset) => BinaryPrimitives.ReadUInt16LittleEndian(data.Slice(offset, 2));
    private static string ZString(ReadOnlySpan<byte> data, int offset, bool unicode)
    {
        if (offset == 0) return "";
        int end = offset, stride = unicode ? 2 : 1;
        while (end + stride <= data.Length && (data[end] != 0 || unicode && data[end + 1] != 0)) end += stride;
        if (end + stride > data.Length) throw new InvalidDataException("快捷方式字符串未终止");
        return (unicode ? Encoding.Unicode : Encoding.Latin1).GetString(data.Slice(offset, end - offset));
    }
}
