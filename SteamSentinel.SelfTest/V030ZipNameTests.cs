using System.Buffers.Binary;
using System.Globalization;
using System.IO;
using System.Text;
using SharpCompress.Readers;
using SteamSentinel.Core.Inspection;
using SteamSentinel.Core.Models;
using SteamSentinel.Core.Scanning;
using SteamSentinel.Core.Utilities;

namespace SteamSentinel.SelfTest;

internal static partial class Program
{
    private sealed record V030ZipItem(byte[] Name, byte[] Payload, ushort Flags = 0,
        byte[]? Extra = null, byte[]? LocalExtra = null, byte[]? LocalName = null);

    private static async Task TestV030ZipNamesAsync(string root)
    {
        string directory = Path.Combine(root, "v030-zip-names"); Directory.CreateDirectory(directory);
        Encoding.RegisterProvider(CodePagesEncodingProvider.Instance);
        byte[] payload = "SteamSentinel inert name-binding fixture."u8.ToArray();
        byte[] gbk = Encoding.GetEncoding(936).GetBytes("介绍.txt");
        byte[] utf8 = Encoding.UTF8.GetBytes("介绍.txt");
        byte[] unicode = V030UnicodePath(gbk, utf8);
        CultureInfo culture = CultureInfo.CurrentCulture, uiCulture = CultureInfo.CurrentUICulture;
        try
        {
            foreach (string language in new[] { "zh-CN", "en-US" })
            {
                CultureInfo.CurrentCulture = CultureInfo.GetCultureInfo(language);
                CultureInfo.CurrentUICulture = CultureInfo.GetCultureInfo(language);
                (string Label, V030ZipItem Item, string Name)[] positives =
                [
                    ("utf8", new(utf8, payload, 0x0800), "介绍.txt"),
                    ("gbk-unicode", new(gbk, payload, Extra: unicode), "介绍.txt"),
                    ("central-unicode", new(gbk, payload, Extra: unicode, LocalExtra: []), "介绍.txt"),
                    ("utf8-consistent-extra", new(utf8, payload, 0x0800, V030UnicodePath(utf8, utf8)), "介绍.txt"),
                    ("cp437", new([0x63, 0x61, 0x66, 0x82, 0x2e, 0x74, 0x78, 0x74], payload), "café.txt")
                ];
                foreach (var item in positives)
                {
                    string path = Path.Combine(directory, language + "-" + item.Label + ".zip");
                    await File.WriteAllBytesAsync(path, V030StoredZip(item.Item));
                    using ArchiveVolumeSession session = await ArchiveVolumeSession.OpenAsync(
                        ArchiveVolumeResolver.Single(new(path, Path.GetFileName(path)), ArchiveVolumeFormat.Zip));
                    Check($"0.3 ZIP {language}/{item.Label} 保留原始名称和头位置",
                        session.ZipMembers.Single().RawName.Span.SequenceEqual(item.Item.Name) &&
                        session.ZipMembers.Single().CentralDirectoryOffset > session.ZipMembers.Single().LocalHeaderOffset);
                    using IReader reader = session.OpenReader();
                    bool next = reader.MoveToNextEntry();
                    Check($"0.3 ZIP {language}/{item.Label} 解码器名称与校验器一致", next && reader.Entry.Key == item.Name);
                    using ArchiveIntegrityEntryVerifier verifier = ArchiveIntegrity.Begin(session, reader.Entry);
                    using Stream input = reader.OpenEntryStream();
                    using MemoryStream output = new();
                    await input.CopyToAsync(output);
                    verifier.Complete(input, output.Length, ArchiveIntegrity.Crc32(output.ToArray()));
                    Check($"0.3 ZIP {language}/{item.Label} 实际内容经过 CRC 与 EOF", output.ToArray().SequenceEqual(payload) && !reader.MoveToNextEntry());
                    session.VerifyTraversalCompleted();
                }

                byte[] badCrc = unicode.ToArray(); badCrc[5] ^= 1;
                byte[] wrongVersion = unicode.ToArray(); wrongVersion[4] = 2;
                byte[] badLength = unicode.ToArray(); BinaryPrimitives.WriteUInt16LittleEndian(badLength.AsSpan(2), ushort.MaxValue);
                (string Label, V030ZipItem[] Items)[] rejected =
                [
                    ("stale-crc", [new(gbk, payload, Extra: badCrc)]),
                    ("unknown-version", [new(gbk, payload, Extra: wrongVersion)]),
                    ("truncated-field", [new(gbk, payload, Extra: badLength)]),
                    ("duplicate-field", [new(gbk, payload, Extra: unicode.Concat(unicode).ToArray())]),
                    ("invalid-extra-utf8", [new(gbk, payload, Extra: V030UnicodePath(gbk, [0xc3, 0x28]))]),
                    ("invalid-flag-utf8", [new([0xc3, 0x28], payload, 0x0800)]),
                    ("flag-extra-conflict", [new(utf8, payload, 0x0800, V030UnicodePath(utf8, "other.txt"u8.ToArray()))]),
                    ("local-extra-conflict", [new(gbk, payload, Extra: unicode, LocalExtra: V030UnicodePath(gbk, "other.txt"u8.ToArray()))]),
                    ("local-extra-invalid", [new(gbk, payload, Extra: unicode, LocalExtra: badCrc)]),
                    ("local-raw-conflict", [new("a.txt"u8.ToArray(), payload, LocalName: "b.txt"u8.ToArray())]),
                    ("nul-name", [new("a\0.txt"u8.ToArray(), payload)]),
                    ("empty-unicode", [new(gbk, payload, Extra: V030UnicodePath(gbk, []))]),
                    ("duplicate-name", [new("a.txt"u8.ToArray(), payload), new("a.txt"u8.ToArray(), "different"u8.ToArray())]),
                    ("case-conflict", [new("a.txt"u8.ToArray(), payload), new("A.TXT"u8.ToArray(), payload)]),
                    ("slash-conflict", [new("a/b.txt"u8.ToArray(), payload), new("a\\b.txt"u8.ToArray(), payload)]),
                    ("unicode-normalization", [new(Encoding.UTF8.GetBytes("café.txt"), payload, 0x0800), new(Encoding.UTF8.GetBytes("cafe\u0301.txt"), payload, 0x0800)])
                ];
                foreach (var item in rejected)
                {
                    string path = Path.Combine(directory, language + "-" + item.Label + ".zip");
                    await File.WriteAllBytesAsync(path, V030StoredZip(item.Items));
                    Check($"0.3 ZIP {language}/{item.Label} 拒绝歧义或损坏元数据",
                        await V020Rejects(ArchiveVolumeResolver.Single(new(path, Path.GetFileName(path)), ArchiveVolumeFormat.Zip), ArchiveVolumeStatus.InvalidMetadata));
                }
            }
        }
        finally { CultureInfo.CurrentCulture = culture; CultureInfo.CurrentUICulture = uiCulture; }

        string traversal = Path.Combine(directory, "unicode-path-traversal.zip");
        byte[] ascii = "visible.txt"u8.ToArray();
        await File.WriteAllBytesAsync(traversal, V030StoredZip(new V030ZipItem(ascii, payload, Extra: V030UnicodePath(ascii, "../v030-escape.txt"u8.ToArray()))));
        ScanReport report = await new ScanCoordinator(new RuleSet()).RunAsync(V030ContentOptions(traversal));
        await JsonFile.WriteAtomicAsync(Path.Combine(directory, "unicode-path-traversal-report.json"), report);
        Check("0.3 Unicode Path 仍进入既有路径穿越检查", report.Findings.Any(f => f.RuleId == "ARCHIVE-PATH-TRAVERSAL") &&
            !File.Exists(Path.Combine(root, "v030-escape.txt")) && !File.Exists(Path.Combine(directory, "v030-escape.txt")));

        string corrupt = Path.Combine(directory, "content-crc-damaged.zip");
        byte[] damaged = V030StoredZip(new V030ZipItem(gbk, payload, Extra: unicode)); damaged[30 + gbk.Length + unicode.Length] ^= 1;
        await File.WriteAllBytesAsync(corrupt, damaged);
        Check("0.3 Unicode 名称成功不跳过内容 CRC 校验", await V020Rejects(
            ArchiveVolumeResolver.Single(new(corrupt, Path.GetFileName(corrupt)), ArchiveVolumeFormat.Zip), ArchiveVolumeStatus.InvalidMetadata, decode: true));
    }

    private static byte[] V030UnicodePath(byte[] raw, byte[] unicode)
    {
        using MemoryStream stream = new(); using BinaryWriter writer = new(stream);
        writer.Write((ushort)0x7075); writer.Write(checked((ushort)(5 + unicode.Length)));
        writer.Write((byte)1); writer.Write(ArchiveIntegrity.Crc32(raw)); writer.Write(unicode);
        return stream.ToArray();
    }

    private static byte[] V030StoredZip(params V030ZipItem[] items)
    {
        using MemoryStream stream = new(); using BinaryWriter writer = new(stream);
        List<uint> offsets = [];
        foreach (V030ZipItem item in items)
        {
            offsets.Add(checked((uint)stream.Position));
            byte[] extra = item.LocalExtra ?? item.Extra ?? [], name = item.LocalName ?? item.Name;
            writer.Write(0x04034b50u); writer.Write((ushort)20); writer.Write(item.Flags); writer.Write((ushort)0); writer.Write(0u);
            writer.Write(ArchiveIntegrity.Crc32(item.Payload)); writer.Write((uint)item.Payload.Length); writer.Write((uint)item.Payload.Length);
            writer.Write((ushort)name.Length); writer.Write((ushort)extra.Length); writer.Write(name); writer.Write(extra); writer.Write(item.Payload);
        }
        uint central = checked((uint)stream.Position);
        for (int i = 0; i < items.Length; i++)
        {
            V030ZipItem item = items[i]; byte[] extra = item.Extra ?? [];
            writer.Write(0x02014b50u); writer.Write((ushort)20); writer.Write((ushort)20); writer.Write(item.Flags); writer.Write((ushort)0); writer.Write(0u);
            writer.Write(ArchiveIntegrity.Crc32(item.Payload)); writer.Write((uint)item.Payload.Length); writer.Write((uint)item.Payload.Length);
            writer.Write((ushort)item.Name.Length); writer.Write((ushort)extra.Length); writer.Write((ushort)0);
            writer.Write((ushort)0); writer.Write((ushort)0); writer.Write(0u); writer.Write(offsets[i]); writer.Write(item.Name); writer.Write(extra);
        }
        uint length = checked((uint)stream.Position - central);
        writer.Write(0x06054b50u); writer.Write((ushort)0); writer.Write((ushort)0); writer.Write((ushort)items.Length); writer.Write((ushort)items.Length);
        writer.Write(length); writer.Write(central); writer.Write((ushort)0);
        return stream.ToArray();
    }

    private static ScanOptions V030ContentOptions(string path, bool amsi = false) => new()
    {
        Mode = ScanMode.Custom,
        IncludeSystem = false,
        IncludeSteam = false,
        IncludeWorkshop = false,
        IncludeRelatedContent = false,
        UseAmsi = amsi,
        InspectArchives = true,
        HashEveryFile = true,
        CustomRoots = [path]
    };
}
