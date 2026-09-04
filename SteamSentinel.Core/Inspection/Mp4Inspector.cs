using System.Buffers.Binary;
using System.Text;

namespace SteamSentinel.Core.Inspection;

public sealed record Mp4InspectionResult(
    bool IsStructurallyValid,
    long LastValidOffset,
    long FileLength,
    long TrailingBytes,
    string? EmbeddedType,
    string Detail);

public static class Mp4Inspector
{
    private const int MaximumBoxes = 100_000;

    public static async Task<Mp4InspectionResult> InspectAsync(string path, CancellationToken cancellationToken = default)
    {
        await using FileStream stream = new(
            path,
            FileMode.Open,
            FileAccess.Read,
            FileShare.ReadWrite | FileShare.Delete,
            64 * 1024,
            FileOptions.Asynchronous | FileOptions.RandomAccess);
        return await InspectAsync(stream, cancellationToken);
    }

    public static async Task<Mp4InspectionResult> InspectAsync(Stream stream, CancellationToken cancellationToken = default)
    {
        if (!stream.CanSeek)
        {
            throw new ArgumentException("MP4 检查需要可定位流。", nameof(stream));
        }

        long length = stream.Length;
        long position = 0;
        long lastValid = 0;
        int boxes = 0;
        bool sawFtyp = false;
        byte[] header = new byte[16];

        while (position + 8 <= length && boxes++ < MaximumBoxes)
        {
            cancellationToken.ThrowIfCancellationRequested();
            stream.Position = position;
            int read = await ReadExactlyAtMostAsync(stream, header.AsMemory(0, 8), cancellationToken);
            if (read < 8) break;

            uint size32 = BinaryPrimitives.ReadUInt32BigEndian(header.AsSpan(0, 4));
            string type = Encoding.ASCII.GetString(header, 4, 4);
            long headerSize = 8;
            long boxSize;

            if (size32 == 1)
            {
                read = await ReadExactlyAtMostAsync(stream, header.AsMemory(8, 8), cancellationToken);
                if (read < 8) break;
                ulong extendedSize = BinaryPrimitives.ReadUInt64BigEndian(header.AsSpan(8, 8));
                if (extendedSize > long.MaxValue) break;
                boxSize = (long)extendedSize;
                headerSize = 16;
            }
            else if (size32 == 0)
            {
                boxSize = length - position;
            }
            else
            {
                boxSize = size32;
            }

            if (!IsPlausibleType(type) || boxSize < headerSize || boxSize > length - position)
            {
                break;
            }

            if (type == "ftyp") sawFtyp = true;
            lastValid = position + boxSize;
            position = lastValid;
            if (size32 == 0) break;
        }

        long trailing = Math.Max(0, length - lastValid);
        string? embedded = trailing > 0
            ? await DetectOverlayAsync(stream, lastValid, cancellationToken)
            : null;
        bool valid = sawFtyp && lastValid > 0 && trailing == 0;
        string detail = trailing == 0
            ? $"MP4 顶层结构完整，共检查 {boxes} 个 box。"
            : $"最后一个合法 MP4 box 在偏移 {lastValid} 结束，后方还有 {trailing} 字节。";

        return new Mp4InspectionResult(valid, lastValid, length, trailing, embedded, detail);
    }

    private static async Task<string?> DetectOverlayAsync(Stream stream, long offset, CancellationToken cancellationToken)
    {
        if (offset < 0 || offset >= stream.Length) return null;
        stream.Position = offset;
        byte[] buffer = new byte[64];
        int read = await stream.ReadAsync(buffer, cancellationToken);
        FileTypeResult type = FileTypeDetector.Detect(buffer.AsSpan(0, read), string.Empty);
        return type.Type == DetectedFileType.Unknown ? null : type.Label;
    }

    private static bool IsPlausibleType(string value) =>
        value.Length == 4 && value.All(c => c is >= ' ' and <= '~');

    private static async Task<int> ReadExactlyAtMostAsync(Stream stream, Memory<byte> buffer, CancellationToken cancellationToken)
    {
        int total = 0;
        while (total < buffer.Length)
        {
            int read = await stream.ReadAsync(buffer[total..], cancellationToken);
            if (read == 0) break;
            total += read;
        }

        return total;
    }
}
