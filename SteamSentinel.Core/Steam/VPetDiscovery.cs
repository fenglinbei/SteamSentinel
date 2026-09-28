using System.ComponentModel;
using System.Text;
using SteamSentinel.Core.Scanning;

namespace SteamSentinel.Core.Steam;

public enum VPetMetadataStatus { Available, Missing, Invalid, TooLarge, UnsafePath, Unavailable }
public sealed record VPetModMetadata(string Directory, VPetMetadataStatus Status,
    string? Name = null, string? DeclaredWorkshopId = null)
{
    public string ReasonCode => "VPET-METADATA-" + Status.ToString().ToUpperInvariant();
}

/// <summary>Reads display metadata only. No declared path, code or subscription identity is trusted.</summary>
public static class VPetDiscovery
{
    public const string AppId = "1920960";
    public const string ModDirectoryName = "mod";
    public const int MaximumMetadataBytes = 64 * 1024;
    private static readonly Encoding Utf8 = new UTF8Encoding(false, true);

    public static VPetModMetadata ReadMetadata(string directory, CancellationToken token = default)
    {
        token.ThrowIfCancellationRequested();
        if (!ContentDiscovery.IsLocalSafePath(directory)) return new(directory, VPetMetadataStatus.UnsafePath);
        string path = Path.Combine(directory, "info.lps");
        if (!ContentDiscovery.IsLocalSafePath(path)) return new(directory, VPetMetadataStatus.UnsafePath);
        try
        {
            // Reuse the deny-write/delete, final-path-verified artifact handle.
            using FileStream input = RelatedArtifactReader.Open(path);
            if (input.Length > MaximumMetadataBytes) return new(directory, VPetMetadataStatus.TooLarge);
            byte[] bytes = new byte[checked((int)input.Length)];
            input.ReadExactly(bytes);
            token.ThrowIfCancellationRequested();
            ReadOnlySpan<byte> content = bytes;
            if (content.StartsWith(new byte[] { 0xef, 0xbb, 0xbf })) content = content[3..];
            return Parse(directory, Utf8.GetString(content));
        }
        catch (Exception exception) when (exception is FileNotFoundException or DirectoryNotFoundException)
        { return new(directory, VPetMetadataStatus.Missing); }
        catch (Win32Exception exception) when (exception.NativeErrorCode is 2 or 3)
        { return new(directory, VPetMetadataStatus.Missing); }
        catch (Exception exception) when (exception is DecoderFallbackException or InvalidDataException)
        { return new(directory, VPetMetadataStatus.Invalid); }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or Win32Exception)
        { return new(directory, VPetMetadataStatus.Unavailable); }
    }

    private static VPetModMetadata Parse(string directory, string text)
    {
        string? name = null, itemId = null;
        bool sawItem = false;
        string[] lines = text.Split('\n');
        if (lines.Length > 256) return new(directory, VPetMetadataStatus.TooLarge);
        foreach (string raw in lines)
        {
            string line = raw.Trim();
            // Only the two top-level fields are needed. LPS paths, language maps,
            // author IDs and load settings never drive discovery or remediation.
            bool isName = line.StartsWith("vupmod#", StringComparison.OrdinalIgnoreCase);
            bool isItem = line.StartsWith("itemid#", StringComparison.OrdinalIgnoreCase);
            if (!isName && !isItem) continue;
            int end = line.IndexOf(":|", StringComparison.Ordinal);
            if (end < 7) return new(directory, VPetMetadataStatus.Invalid);
            string value = line[7..end].Trim();
            if (value.Length is 0 or > 256 || value.Any(char.IsControl)) return new(directory, VPetMetadataStatus.Invalid);
            if (isName)
            {
                if (name is not null) return new(directory, VPetMetadataStatus.Invalid);
                name = value;
            }
            else
            {
                if (sawItem || !ContentDiscovery.IsNumericId(value)) return new(directory, VPetMetadataStatus.Invalid);
                sawItem = true;
                itemId = value == "0" ? null : value;
            }
        }
        return name is null ? new(directory, VPetMetadataStatus.Invalid) : new(directory, VPetMetadataStatus.Available, name, itemId);
    }
}
