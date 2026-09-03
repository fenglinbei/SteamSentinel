using System.Buffers.Binary;
using System.Text;

namespace SteamSentinel.Core.Inspection;

public enum DetectedFileType
{
    Unknown,
    Empty,
    PortableExecutable,
    Zip,
    Rar,
    SevenZip,
    GZip,
    BZip2,
    Xz,
    Zstandard,
    Tar,
    Mp4,
    Json,
    Xml,
    Html,
    PowerShell,
    Batch,
    JavaScript,
    Shortcut,
    Pdf,
    Png,
    Jpeg,
    Gif
}

public sealed record FileTypeResult(
    DetectedFileType Type,
    string Label,
    bool ExtensionMismatch,
    string? ExpectedExtension,
    bool IsArchive,
    bool IsExecutableOrScript);

public static class FileTypeDetector
{
    public static async Task<FileTypeResult> DetectAsync(string path, CancellationToken cancellationToken = default)
    {
        byte[] head = new byte[64 * 1024];
        int read;
        await using (FileStream stream = new(
            path,
            FileMode.Open,
            FileAccess.Read,
            FileShare.ReadWrite | FileShare.Delete,
            head.Length,
            FileOptions.Asynchronous | FileOptions.SequentialScan))
        {
            read = await stream.ReadAsync(head, cancellationToken);
        }

        return Detect(head.AsSpan(0, read), Path.GetExtension(path));
    }

    public static FileTypeResult Detect(ReadOnlySpan<byte> head, string? extension)
    {
        extension = extension?.ToLowerInvariant() ?? string.Empty;
        DetectedFileType type = DetectCore(head, extension);
        string? expected = ExpectedExtension(type);
        bool mismatch = IsMeaningfulMismatch(type, extension);
        bool archive = type is DetectedFileType.Zip or DetectedFileType.Rar or
            DetectedFileType.SevenZip or DetectedFileType.GZip or DetectedFileType.BZip2 or
            DetectedFileType.Xz or DetectedFileType.Zstandard or DetectedFileType.Tar;
        bool executable = type is DetectedFileType.PortableExecutable or DetectedFileType.PowerShell or
            DetectedFileType.Batch or DetectedFileType.JavaScript or DetectedFileType.Shortcut;
        return new FileTypeResult(type, Label(type), mismatch, expected, archive, executable);
    }

    private static DetectedFileType DetectCore(ReadOnlySpan<byte> data, string extension)
    {
        if (data.IsEmpty)
        {
            return DetectedFileType.Empty;
        }

        if (StartsWith(data, "MZ"u8)) return DetectedFileType.PortableExecutable;
        if (StartsWith(data, [0x50, 0x4B, 0x03, 0x04]) ||
            StartsWith(data, [0x50, 0x4B, 0x05, 0x06]) ||
            StartsWith(data, [0x50, 0x4B, 0x07, 0x08])) return DetectedFileType.Zip;
        if (StartsWith(data, [0x52, 0x61, 0x72, 0x21, 0x1A, 0x07])) return DetectedFileType.Rar;
        if (StartsWith(data, [0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C])) return DetectedFileType.SevenZip;
        if (StartsWith(data, [0x1F, 0x8B])) return DetectedFileType.GZip;
        if (StartsWith(data, "BZh"u8)) return DetectedFileType.BZip2;
        if (StartsWith(data, [0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00])) return DetectedFileType.Xz;
        if (StartsWith(data, [0x28, 0xB5, 0x2F, 0xFD])) return DetectedFileType.Zstandard;
        if (data.Length > 262 && data.Slice(257, 5).SequenceEqual("ustar"u8)) return DetectedFileType.Tar;
        if (data.Length >= 12 && data.Slice(4, 4).SequenceEqual("ftyp"u8)) return DetectedFileType.Mp4;
        if (StartsWith(data, "%PDF"u8)) return DetectedFileType.Pdf;
        if (StartsWith(data, [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A])) return DetectedFileType.Png;
        if (StartsWith(data, [0xFF, 0xD8, 0xFF])) return DetectedFileType.Jpeg;
        if (StartsWith(data, "GIF87a"u8) || StartsWith(data, "GIF89a"u8)) return DetectedFileType.Gif;
        if (StartsWith(data, [0x4C, 0x00, 0x00, 0x00, 0x01, 0x14, 0x02, 0x00])) return DetectedFileType.Shortcut;

        ReadOnlySpan<byte> text = TrimBomAndWhitespace(data);
        if (extension == ".ps1" || StartsWithIgnoreCase(text, "#requires")) return DetectedFileType.PowerShell;
        if (extension is ".bat" or ".cmd" || StartsWithIgnoreCase(text, "@echo off")) return DetectedFileType.Batch;
        if (extension is ".js" or ".jse") return DetectedFileType.JavaScript;
        if (extension is ".html" or ".htm" || StartsWithIgnoreCase(text, "<!doctype html") || StartsWithIgnoreCase(text, "<html")) return DetectedFileType.Html;
        if (extension == ".json" || StartsWith(text, "{"u8) || StartsWith(text, "["u8)) return DetectedFileType.Json;
        if (extension == ".xml" || StartsWith(text, "<?xml"u8)) return DetectedFileType.Xml;
        return DetectedFileType.Unknown;
    }

    private static bool StartsWith(ReadOnlySpan<byte> data, ReadOnlySpan<byte> prefix) =>
        data.Length >= prefix.Length && data[..prefix.Length].SequenceEqual(prefix);

    private static bool StartsWithIgnoreCase(ReadOnlySpan<byte> data, string text)
    {
        if (data.Length < text.Length) return false;
        string actual = Encoding.UTF8.GetString(data[..text.Length]);
        return actual.Equals(text, StringComparison.OrdinalIgnoreCase);
    }

    private static ReadOnlySpan<byte> TrimBomAndWhitespace(ReadOnlySpan<byte> data)
    {
        if (data.Length >= 3 && data[0] == 0xEF && data[1] == 0xBB && data[2] == 0xBF) data = data[3..];
        int index = 0;
        while (index < data.Length && data[index] is (byte)' ' or (byte)'\r' or (byte)'\n' or (byte)'\t') index++;
        return data[index..];
    }

    private static bool IsMeaningfulMismatch(DetectedFileType type, string extension)
    {
        if (string.IsNullOrEmpty(extension)) return false;
        return type switch
        {
            DetectedFileType.PortableExecutable => extension is not (".exe" or ".dll" or ".scr" or ".com" or ".cpl" or ".sys" or ".msi"),
            DetectedFileType.Zip => extension is not (".zip" or ".zipx" or ".jar" or ".docx" or ".xlsx" or ".pptx" or ".nupkg"),
            DetectedFileType.Rar => extension != ".rar",
            DetectedFileType.SevenZip => extension != ".7z",
            DetectedFileType.GZip => extension is not (".gz" or ".gzip" or ".tgz"),
            DetectedFileType.Mp4 => extension is not (".mp4" or ".m4v" or ".mov"),
            DetectedFileType.Shortcut => extension != ".lnk",
            _ => false
        };
    }

    private static string? ExpectedExtension(DetectedFileType type) => type switch
    {
        DetectedFileType.PortableExecutable => ".exe/.dll",
        DetectedFileType.Zip => ".zip",
        DetectedFileType.Rar => ".rar",
        DetectedFileType.SevenZip => ".7z",
        DetectedFileType.GZip => ".gz",
        DetectedFileType.BZip2 => ".bz2",
        DetectedFileType.Xz => ".xz",
        DetectedFileType.Zstandard => ".zst",
        DetectedFileType.Tar => ".tar",
        DetectedFileType.Mp4 => ".mp4",
        DetectedFileType.Shortcut => ".lnk",
        _ => null
    };

    private static string Label(DetectedFileType type) => type switch
    {
        DetectedFileType.PortableExecutable => "Windows PE 可执行文件",
        DetectedFileType.Zip => "ZIP 压缩包",
        DetectedFileType.Rar => "RAR 压缩包",
        DetectedFileType.SevenZip => "7z 压缩包",
        DetectedFileType.GZip => "GZip 数据",
        DetectedFileType.BZip2 => "BZip2 数据",
        DetectedFileType.Xz => "XZ 数据",
        DetectedFileType.Zstandard => "Zstandard 数据",
        DetectedFileType.Tar => "TAR 归档",
        DetectedFileType.Mp4 => "MP4/ISO BMFF 媒体",
        DetectedFileType.Shortcut => "Windows 快捷方式",
        DetectedFileType.PowerShell => "PowerShell 脚本",
        DetectedFileType.Batch => "批处理脚本",
        DetectedFileType.JavaScript => "JavaScript",
        DetectedFileType.Empty => "空文件",
        _ => type.ToString()
    };
}
