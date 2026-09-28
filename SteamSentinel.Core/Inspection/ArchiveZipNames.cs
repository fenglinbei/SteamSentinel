using SteamSentinel.Core.Reporting;
using System.Buffers.Binary;
using System.Text;
using SharpCompress.Common;

namespace SteamSentinel.Core.Inspection;

/// <summary>One culture-independent ZIP name policy for the verifier and locked decoder.</summary>
internal static class ArchiveZipNames
{
    private static readonly Encoding StrictUtf8 = new UTF8Encoding(false, true);
    private static readonly Encoding Legacy = CreateLegacyEncoding();

    internal static IArchiveEncoding DecoderEncoding() => new ArchiveEncoding
    {
        Default = Legacy,
        UTF8 = StrictUtf8
    };

    internal static string Decode(ReadOnlySpan<byte> rawName, ushort flags,
        ReadOnlySpan<byte> centralExtra, ReadOnlySpan<byte> localExtra)
    {
        string? unicode = UnicodePath(rawName, centralExtra);
        string? localUnicode = UnicodePath(rawName, localExtra);
        string name = (flags & 0x0800) != 0 ? Utf8(rawName) : unicode ?? Legacy.GetString(rawName);
        if (unicode is not null && !string.Equals(unicode, name, StringComparison.Ordinal))
            Fail(MessageText.Create("Backend.Core.ArchiveZipNames.Decode.01"));
        if (localUnicode is not null && !string.Equals(localUnicode, name, StringComparison.Ordinal))
            Fail(MessageText.Create("Backend.Core.ArchiveZipNames.Decode.02"));
        if (name.Length == 0 || name[0] == '\uFEFF' || name.Any(char.IsControl))
            Fail(MessageText.Create("Backend.Core.ArchiveZipNames.Decode.03"));
        return name;
    }

    private static string? UnicodePath(ReadOnlySpan<byte> rawName, ReadOnlySpan<byte> extra)
    {
        string? name = null;
        bool found = false;
        for (int cursor = 0; cursor < extra.Length;)
        {
            if (extra.Length - cursor < 4) Fail(MessageText.Create("Backend.Core.ArchiveZipNames.UnicodePath.01"));
            ushort id = BinaryPrimitives.ReadUInt16LittleEndian(extra[cursor..]);
            int length = BinaryPrimitives.ReadUInt16LittleEndian(extra[(cursor + 2)..]);
            cursor += 4;
            if (length > extra.Length - cursor) Fail(MessageText.Create("Backend.Core.ArchiveZipNames.UnicodePath.02"));
            ReadOnlySpan<byte> value = extra.Slice(cursor, length);
            cursor += length;
            if (id != 0x7075) continue;
            if (found) Fail(MessageText.Create("Backend.Core.ArchiveZipNames.UnicodePath.03"));
            found = true;
            // APPNOTE 4.6.9 permits ignoring stale/unknown extensions. This scanner
            // conservatively reports a gap instead of accepting a decoder-dependent name.
            if (length <= 5 || value[0] != 1) Fail(MessageText.Create("Backend.Core.ArchiveZipNames.UnicodePath.04"));
            if (BinaryPrimitives.ReadUInt32LittleEndian(value[1..]) != ArchiveIntegrity.Crc32(rawName))
                Fail(MessageText.Create("Backend.Core.ArchiveZipNames.UnicodePath.05"));
            name = Utf8(value[5..]);
            if (name[0] == '\uFEFF' || name.Any(char.IsControl))
                Fail(MessageText.Create("Backend.Core.ArchiveZipNames.UnicodePath.06"));
        }
        return name;
    }

    private static string Utf8(ReadOnlySpan<byte> bytes)
    {
        try { return StrictUtf8.GetString(bytes); }
        catch (DecoderFallbackException exception)
        {
            throw new ArchiveVolumeException(ArchiveVolumeStatus.InvalidMetadata,
                MessageText.Create("Backend.Core.ArchiveZipNames.Utf8.01"), exception);
        }
    }

    private static Encoding CreateLegacyEncoding()
    {
        Encoding.RegisterProvider(CodePagesEncodingProvider.Instance);
        return Encoding.GetEncoding(437, EncoderFallback.ExceptionFallback, DecoderFallback.ExceptionFallback);
    }

    private static void Fail(MessageText detail) => throw new ArchiveVolumeException(ArchiveVolumeStatus.InvalidMetadata, detail);
}
