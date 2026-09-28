using System.Buffers.Binary;
using System.Text;
using SteamSentinel.Core.Scanning;

namespace SteamSentinel.Core.Inspection;

internal sealed record PeDataSection(string Name, long Rva, long VirtualSize, long Offset, long Length, uint Characteristics);

/// <summary>File-layout PE view. Never maps an image, resolves imports, or calls an entry point.</summary>
internal sealed class BoundedPeImage
{
    internal required PeDataSection[] Sections { get; init; }
    internal long RawEnd { get; init; }
    internal long ExportRva { get; init; }
    internal long ExportLength { get; init; }
    internal long ClrRva { get; init; }
    internal bool NativeX64Dll { get; init; }

    internal static BoundedPeImage Read(Stream input, CancellationToken token, ContainerResourceBudget? budget = null)
    {
        token.ThrowIfCancellationRequested(); budget?.ChargeMetadata();
        byte[] dos = ReadAt(input, 0, 64);
        if (dos[0] != 'M' || dos[1] != 'Z') throw new InvalidDataException("PE-DOS");
        long pe = U32(dos, 60);
        if (pe is < 64 or > 1024 * 1024) throw new InvalidDataException("PE-HEADER-OFFSET");
        byte[] coff = ReadAt(input, pe, 24);
        if (U32(coff, 0) != 0x4550) throw new InvalidDataException("PE-SIGNATURE");
        int count = U16(coff, 6), optionalSize = U16(coff, 20);
        if (count is < 1 or > 96 || optionalSize is < 96 or > 4096) throw new InvalidDataException("PE-HEADER-LIMIT");
        byte[] optional = ReadAt(input, pe + 24, optionalSize);
        ushort magic = U16(optional, 0);
        int directories = magic switch { 0x20b => 112, 0x10b => 96, _ => throw new InvalidDataException("PE-OPTIONAL-MAGIC") };
        if (optionalSize < directories) throw new InvalidDataException("PE-OPTIONAL-SIZE");
        long directoryCount = U32(optional, directories - 4);
        if (directoryCount > 16 || directories + directoryCount * 8 > optionalSize) throw new InvalidDataException("PE-DIRECTORIES");
        long headers = U32(optional, 60), imageSize = U32(optional, 56);
        long table = pe + 24 + optionalSize;
        if (headers < table + count * 40L || headers > input.Length || headers > 1024 * 1024) throw new InvalidDataException("PE-HEADERS-SIZE");
        byte[] entries = ReadAt(input, table, count * 40);
        List<PeDataSection> sections = [];
        HashSet<string> names = new(StringComparer.Ordinal);
        for (int i = 0; i < count; i++)
        {
            token.ThrowIfCancellationRequested(); budget?.ChargeMetadata();
            int p = i * 40;
            string name = Encoding.ASCII.GetString(entries, p, 8).TrimEnd('\0');
            if (name.Length == 0 || name.Any(c => c < 32 || c > 126) || !names.Add(name)) throw new InvalidDataException("PE-SECTION-NAME");
            long virtualSize = U32(entries, p + 8), rva = U32(entries, p + 12), length = U32(entries, p + 16), offset = U32(entries, p + 20);
            if (rva < headers || rva + Math.Max(virtualSize, length) > imageSize ||
                length > 0 && (offset < headers || offset > input.Length || length > input.Length - offset))
                throw new InvalidDataException("PE-SECTION-BOUNDS");
            sections.Add(new(name, rva, virtualSize, offset, length, U32(entries, p + 36)));
        }
        PeDataSection[] raw = sections.Where(s => s.Length > 0).OrderBy(s => s.Offset).ToArray();
        PeDataSection[] virtualOrder = sections.OrderBy(s => s.Rva).ToArray();
        for (int i = 1; i < raw.Length; i++)
            if (raw[i].Offset < raw[i - 1].Offset + raw[i - 1].Length) throw new InvalidDataException("PE-RAW-OVERLAP");
        for (int i = 1; i < virtualOrder.Length; i++)
            if (virtualOrder[i].Rva < virtualOrder[i - 1].Rva + Math.Max(virtualOrder[i - 1].VirtualSize, virtualOrder[i - 1].Length))
                throw new InvalidDataException("PE-RVA-OVERLAP");
        return new()
        {
            Sections = sections.ToArray(),
            RawEnd = Math.Max(headers, raw.Length == 0 ? 0 : raw.Max(s => s.Offset + s.Length)),
            ExportRva = directoryCount == 0 ? 0 : U32(optional, directories),
            ExportLength = directoryCount == 0 ? 0 : U32(optional, directories + 4),
            ClrRva = directoryCount <= 14 ? 0 : U32(optional, directories + 14 * 8),
            NativeX64Dll = magic == 0x20b && U16(coff, 4) == 0x8664 && (U16(coff, 22) & 0x2000) != 0
        };
    }

    internal PeDataSection Section(string name) => Sections.SingleOrDefault(s => s.Name == name)
        ?? throw new InvalidDataException("PE-SECTION-MISSING");

    internal long Map(long rva, long length)
    {
        if (rva < 0 || length <= 0) throw new InvalidDataException("PE-RVA-RANGE");
        PeDataSection? section = Sections.SingleOrDefault(s => rva >= s.Rva && rva - s.Rva <= s.Length && length <= s.Length - (rva - s.Rva));
        return section is null ? throw new InvalidDataException("PE-RVA-UNMAPPED") : section.Offset + rva - section.Rva;
    }

    internal string OrdinalOneModule(Stream input)
    {
        if (ExportLength is < 40 or > 65536) throw new InvalidDataException("PE-EXPORT-SIZE");
        long export = Map(ExportRva, ExportLength);
        byte[] table = ReadAt(input, export, 40);
        if (U32(table, 16) != 1 || U32(table, 20) != 1 || U32(table, 24) != 0) throw new InvalidDataException("PE-EXPORT-SHAPE");
        long function = U32(ReadAt(input, Map(U32(table, 28), 4), 4), 0);
        PeDataSection code = Section(".text");
        if ((code.Characteristics & 0x20000000) == 0 || function < code.Rva || function - code.Rva >= code.Length ||
            function >= ExportRva && function - ExportRva < ExportLength) throw new InvalidDataException("PE-EXPORT-TARGET");
        long nameRva = U32(table, 12);
        List<byte> name = [];
        for (int i = 0; i < 128; i++)
        {
            byte value = ReadAt(input, Map(nameRva + i, 1), 1)[0];
            if (value == 0) return name.Count > 0 ? Encoding.ASCII.GetString(name.ToArray()) : throw new InvalidDataException("PE-EXPORT-NAME");
            if (value is < 32 or > 126) throw new InvalidDataException("PE-EXPORT-NAME");
            name.Add(value);
        }
        throw new InvalidDataException("PE-EXPORT-NAME-LIMIT");
    }

    internal static byte[] ReadAt(Stream input, long offset, int length)
    {
        if (offset < 0 || length < 0 || offset > input.Length || length > input.Length - offset) throw new InvalidDataException("PE-FILE-BOUNDS");
        input.Position = offset; byte[] bytes = new byte[length]; input.ReadExactly(bytes); return bytes;
    }
    internal static ushort U16(ReadOnlySpan<byte> value, int offset) => BinaryPrimitives.ReadUInt16LittleEndian(value[offset..]);
    internal static uint U32(ReadOnlySpan<byte> value, int offset) => BinaryPrimitives.ReadUInt32LittleEndian(value[offset..]);
}
