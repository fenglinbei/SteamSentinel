using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;
using SteamSentinel.Core.Steam;

namespace SteamSentinel.Core.Inspection;

/// <summary>Pure, bounded byte transformations. Never invokes Steam, a shortcut, or a command.</summary>
public static class SteamConfigurationRepair
{
    public const int MaximumBytes = 1024 * 1024;
    public const string RuleId = "STEAM-CONFIGURATION-REPAIR";
    public const string Cfg = "SteamCfg";
    public const string Marker = "SteamDebugMarker";
    public const string Run = "SteamRunDebugArguments";
    public const string Shortcut = "SteamShortcutDebugArguments";
    public const string ShortcutReviewRule = "STEAM-SHORTCUT-DEBUG-UNVERIFIED";
    public const string DebugArgument = "-cef-enable-debugging";
    private static readonly Regex Setting = new(@"^(?<prefix>\s*)(?<key>BootStrapperInhibitAll|BootStrapperInhibitV3|BootStrapperForceSelfUpdate|ForceOfflineMode)\s*=\s*(?<value>[A-Za-z0-9]+)\s*(?:(?:;|#|//).*)?$",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant, TimeSpan.FromMilliseconds(100));

    public static string Hash(ReadOnlySpan<byte> bytes) => Convert.ToHexString(SHA256.HashData(bytes));

    public static bool IsSteamExecutable(string? path, SteamLayout layout) => !string.IsNullOrWhiteSpace(path) &&
        ContentDiscovery.IsLocalSafePath(path) && layout.SteamRoots.Any(root =>
            Path.GetFullPath(path).Equals(Path.GetFullPath(Path.Combine(root, "steam.exe")), StringComparison.OrdinalIgnoreCase));

    public static bool TryRepairCfg(ReadOnlySpan<byte> original, out byte[] repaired, out bool paired)
    {
        repaired = []; paired = false;
        if (original.Length is <= 0 or > MaximumBytes) return false;
        try
        {
            Encoding encoding; int bom;
            if (original.StartsWith(new byte[] { 0xff, 0xfe })) { encoding = new UnicodeEncoding(false, false, true); bom = 2; }
            else if (original.StartsWith(new byte[] { 0xfe, 0xff })) { encoding = new UnicodeEncoding(true, false, true); bom = 2; }
            else { encoding = new UTF8Encoding(false, true); bom = original.StartsWith(new byte[] { 0xef, 0xbb, 0xbf }) ? 3 : 0; }
            string text = encoding.GetString(original[bom..]);
            if (text.Contains('\0') || !encoding.GetBytes(text).AsSpan().SequenceEqual(original[bom..])) return false;
            char[] changed = text.ToCharArray(); bool any = false, inhibit = false, second = false;
            int start = 0;
            while (start < text.Length)
            {
                int end = start;
                while (end < text.Length && text[end] is not ('\r' or '\n')) end++;
                Match match = Setting.Match(text[start..end]);
                if (match.Success)
                {
                    string key = match.Groups["key"].Value, value = match.Groups["value"].Value.ToLowerInvariant();
                    bool suppress = key.Equals("BootStrapperForceSelfUpdate", StringComparison.OrdinalIgnoreCase)
                        ? value is "0" or "false" or "disable" or "disabled"
                        : value is "1" or "true" or "enable" or "enabled";
                    if (suppress)
                    {
                        inhibit |= key.Equals("BootStrapperInhibitAll", StringComparison.OrdinalIgnoreCase);
                        second |= key.Equals("BootStrapperInhibitV3", StringComparison.OrdinalIgnoreCase) || key.Equals("BootStrapperForceSelfUpdate", StringComparison.OrdinalIgnoreCase);
                        // Blank only the setting through its value; retain any trailing comment verbatim.
                        int first = start + match.Groups["key"].Index;
                        int last = start + match.Groups["value"].Index + match.Groups["value"].Length;
                        Array.Fill(changed, ' ', first, last - first); any = true;
                    }
                }
                start = end;
                while (start < text.Length && text[start] is '\r' or '\n') start++;
            }
            if (!any) return false;
            byte[] body = encoding.GetBytes(changed);
            if (body.Length != original.Length - bom) return false;
            repaired = original.ToArray(); body.CopyTo(repaired, bom); paired = inhibit && second; return true;
        }
        catch (Exception ex) when (ex is DecoderFallbackException or EncoderFallbackException or RegexMatchTimeoutException) { return false; }
    }

    public static bool TryRepairCommand(string command, SteamLayout layout, out string repaired, out string steamExecutable)
    {
        repaired = command; steamExecutable = "";
        if (command.Length is 0 or > 32768 || command.Any(ch => ch is '\r' or '\n' or '\0')) return false;
        if (!TryTokens(command, out List<(int Start, int End, string Value)> tokens) || tokens.Count < 2) return false;
        string executable = Environment.ExpandEnvironmentVariables(tokens[0].Value);
        if (!IsSteamExecutable(executable, layout)) return false;
        if (!TryRemoveDebugArgument(command, tokens.Skip(1), out repaired)) return false;
        steamExecutable = Path.GetFullPath(executable); return true;
    }

    public static bool TryRepairShortcut(ReadOnlySpan<byte> original, SteamLayout layout, out byte[] repaired, out string steamExecutable)
    {
        repaired = []; steamExecutable = "";
        if (original.Length is < 76 or > MaximumBytes) return false;
        try
        {
            if (BinaryPrimitives.ReadUInt32LittleEndian(original[..4]) != 76 ||
                !original.Slice(4, 16).SequenceEqual(new Guid("00021401-0000-0000-c000-000000000046").ToByteArray())) return false;
            uint flags = BinaryPrimitives.ReadUInt32LittleEndian(original.Slice(20, 4));
            // Require an absolute local LinkInfo or filesystem PIDL; reject environment and Darwin targets.
            if ((flags & 3) == 0 || (flags & (0x200u | 0x1000u | 0x02000000u | 0x04000000u)) != 0) return false;
            int position = 76;
            string? idTarget = null; byte[]? idList = null;
            if ((flags & 1) != 0)
            {
                int idSize = BinaryPrimitives.ReadUInt16LittleEndian(original.Slice(position, 2));
                idList = original.Slice(position + 2, idSize).ToArray();
                if (!TryReadLocalIdList(idList, out idTarget) || !IsSteamExecutable(idTarget, layout)) return false;
                position = checked(position + 2 + idSize);
            }
            string? linkTarget = null;
            if ((flags & 2) != 0)
            {
                int linkBytes = checked((int)BinaryPrimitives.ReadUInt32LittleEndian(original.Slice(position, 4)));
                if (!TryReadLocalLinkInfo(original.Slice(position, linkBytes), out linkTarget) || !IsSteamExecutable(linkTarget, layout)) return false;
                position = checked(position + linkBytes);
            }
            bool unicode = (flags & 128) != 0; int argumentOffset = 0, argumentBytes = 0;
            foreach (uint flag in new uint[] { 4, 8, 16, 32, 64 })
            {
                if ((flags & flag) == 0) continue;
                int count = BinaryPrimitives.ReadUInt16LittleEndian(original.Slice(position, 2)); position += 2;
                int bytes = checked(count * (unicode ? 2 : 1));
                _ = original.Slice(position, bytes);
                if (flag == 32) { argumentOffset = position; argumentBytes = bytes; }
                position += bytes;
            }
            if (argumentBytes == 0) return false;
            // Keep inert metadata. Known-folder relocation is accepted only when its current
            // local prefix exactly matches the filesystem PIDL; unknown target changes fail closed.
            while (position + 4 <= original.Length)
            {
                uint size = BinaryPrimitives.ReadUInt32LittleEndian(original.Slice(position, 4));
                if (size == 0) { if (position + 4 != original.Length) return false; break; }
                if (size < 8 || size > original.Length - position) return false;
                uint signature = BinaryPrimitives.ReadUInt32LittleEndian(original.Slice(position + 4, 4));
                if (signature is 0xA0000005u or 0xA000000Bu)
                {
                    if (idList is null || !KnownFolderMatches(original.Slice(position, checked((int)size)), idList)) return false;
                }
                else if (signature is not (0xA0000003u or 0xA0000009u)) return false;
                position += checked((int)size);
            }
            if (position + 4 != original.Length) return false;
            string? target = idTarget;
            if ((flags & 2) != 0)
            {
                if (idTarget is not null && !idTarget.Equals(linkTarget, StringComparison.OrdinalIgnoreCase)) return false;
                target = linkTarget;
            }
            else if (target is null) return false;
            Encoding encoding = unicode ? new UnicodeEncoding(false, false, true) : Encoding.Latin1;
            string arguments = encoding.GetString(original.Slice(argumentOffset, argumentBytes));
            if (!TryTokens(arguments, out var tokens) || !TryRemoveDebugArgument(arguments, tokens, out string changed)) return false;
            byte[] changedBytes = encoding.GetBytes(changed);
            if (changedBytes.Length != argumentBytes) return false;
            repaired = original.ToArray(); changedBytes.CopyTo(repaired, argumentOffset);
            steamExecutable = Path.GetFullPath(target!); return true;
        }
        catch (Exception ex) when (ex is ArgumentException or OverflowException or DecoderFallbackException) { return false; }
    }

    /// <summary>Review-only observation from the bounded Shell Link arguments structure, without resolving its target.</summary>
    public static bool HasDebugShortcutArguments(ReadOnlySpan<byte> bytes)
    {
        if (bytes.Length is < 76 or > MaximumBytes) return false;
        try
        {
            if (BinaryPrimitives.ReadUInt32LittleEndian(bytes[..4]) != 76 ||
                !bytes.Slice(4, 16).SequenceEqual(new Guid("00021401-0000-0000-c000-000000000046").ToByteArray())) return false;
            uint flags = BinaryPrimitives.ReadUInt32LittleEndian(bytes.Slice(20, 4));
            if ((flags & 32) == 0) return false;
            int position = 76;
            if ((flags & 1) != 0)
            {
                int length = BinaryPrimitives.ReadUInt16LittleEndian(bytes.Slice(position, 2));
                if (length < 2 || BinaryPrimitives.ReadUInt16LittleEndian(bytes.Slice(position + length, 2)) != 0) return false;
                position = checked(position + 2 + length);
            }
            if ((flags & 2) != 0)
            {
                int size = checked((int)BinaryPrimitives.ReadUInt32LittleEndian(bytes.Slice(position, 4)));
                ReadOnlySpan<byte> info = bytes.Slice(position, size);
                if (size < 28) return false;
                int header = checked((int)BinaryPrimitives.ReadUInt32LittleEndian(info.Slice(4, 4)));
                if (header is not (28 or >= 36) || header > size) return false;
                position = checked(position + size);
            }
            bool unicode = (flags & 128) != 0, found = false;
            foreach (uint flag in new uint[] { 4, 8, 16, 32, 64 })
            {
                if ((flags & flag) == 0) continue;
                int count = BinaryPrimitives.ReadUInt16LittleEndian(bytes.Slice(position, 2)); position += 2;
                int size = checked(count * (unicode ? 2 : 1));
                ReadOnlySpan<byte> text = bytes.Slice(position, size);
                if (flag == 32)
                {
                    string arguments = (unicode ? new UnicodeEncoding(false, false, true) : Encoding.Latin1).GetString(text);
                    found = TryTokens(arguments, out var tokens) && tokens.Any(token => token.Value.Equals(DebugArgument, StringComparison.OrdinalIgnoreCase));
                }
                position += size;
            }
            while (position + 4 <= bytes.Length)
            {
                uint size = BinaryPrimitives.ReadUInt32LittleEndian(bytes.Slice(position, 4));
                if (size == 0) return found && position + 4 == bytes.Length;
                if (size < 8 || size > bytes.Length - position) return false;
                position += checked((int)size);
            }
            return false;
        }
        catch (Exception ex) when (ex is ArgumentException or OverflowException) { return false; }
    }

    private static bool TryReadLocalLinkInfo(ReadOnlySpan<byte> info, out string target)
    {
        target = "";
        if (info.Length < 28) return false;
        int header = checked((int)BinaryPrimitives.ReadUInt32LittleEndian(info.Slice(4, 4)));
        uint flags = BinaryPrimitives.ReadUInt32LittleEndian(info.Slice(8, 4));
        if (header is not (28 or >= 36) || header > info.Length || flags is not (1 or 3)) return false;
        int localUnicode = header >= 36 ? checked((int)BinaryPrimitives.ReadUInt32LittleEndian(info.Slice(28, 4))) : 0;
        int suffixUnicode = header >= 36 ? checked((int)BinaryPrimitives.ReadUInt32LittleEndian(info.Slice(32, 4))) : 0;
        int local = localUnicode > 0 ? localUnicode : checked((int)BinaryPrimitives.ReadUInt32LittleEndian(info.Slice(16, 4)));
        int suffix = suffixUnicode > 0 ? suffixUnicode : checked((int)BinaryPrimitives.ReadUInt32LittleEndian(info.Slice(24, 4)));
        if (local < header || suffix < header) return false;
        string basePath = LinkString(info, local, localUnicode > 0), tail = LinkString(info, suffix, suffixUnicode > 0);
        if (basePath.Length == 0) return false;
        target = tail.Length == 0 || basePath.EndsWith(tail, StringComparison.OrdinalIgnoreCase)
            ? basePath : basePath.TrimEnd('\\') + "\\" + tail.TrimStart('\\');
        if (!ContentDiscovery.IsLocalSafePath(target)) return false;
        return flags == 1 || LocalShareMatches(info, tail, target);
    }

    private static bool LocalShareMatches(ReadOnlySpan<byte> info, string suffix, string localTarget)
    {
        int offset = checked((int)BinaryPrimitives.ReadUInt32LittleEndian(info.Slice(20, 4)));
        if (offset < 28 || offset > info.Length - 20) return false;
        int size = checked((int)BinaryPrimitives.ReadUInt32LittleEndian(info.Slice(offset, 4)));
        ReadOnlySpan<byte> network = info.Slice(offset, size);
        uint flags = BinaryPrimitives.ReadUInt32LittleEndian(network.Slice(4, 4));
        int nameOffset = checked((int)BinaryPrimitives.ReadUInt32LittleEndian(network.Slice(8, 4)));
        if ((flags & ~2u) != 0 || nameOffset < 20) return false;
        int unicode = nameOffset > 20 ? checked((int)BinaryPrimitives.ReadUInt32LittleEndian(network.Slice(20, 4))) : 0;
        if (unicode != 0 && unicode < 28) return false;
        string networkName = LinkString(network, unicode > 0 ? unicode : nameOffset, unicode > 0);
        if (networkName.Length is < 5 or > 1024 || !networkName.StartsWith("\\\\", StringComparison.Ordinal)) return false;
        string[] parts = networkName[2..].Split('\\');
        if (parts.Length != 2 || !parts[0].Equals(Environment.MachineName, StringComparison.OrdinalIgnoreCase) ||
            parts[1].Length is 0 or > 80 || parts[1] is "." or ".." || parts[1].Any(ch => char.IsControl(ch) || ch is '/' or ':' or '*' or '?' or '"' or '<' or '>' or '|') ||
            suffix.IndexOf(':') >= 0 || suffix.StartsWith('\\') || suffix.StartsWith('/') ||
            suffix.Replace('/', '\\').Split('\\').Any(part => part is "." or "..")) return false;
        // NULL means the local share service. Never connect to or resolve the UNC name.
        uint result = NetShareGetInfo(null, parts[1], 2, out IntPtr data);
        try
        {
            if (result != 0 || data == IntPtr.Zero) return false;
            ShareInfo2 share = Marshal.PtrToStructure<ShareInfo2>(data);
            string? sharePath = Marshal.PtrToStringUni(share.Path), name = Marshal.PtrToStringUni(share.Name);
            if ((share.Type & 0xff) != 0 || !string.Equals(name, parts[1], StringComparison.OrdinalIgnoreCase) ||
                sharePath is null || !ContentDiscovery.IsLocalSafePath(sharePath)) return false;
            string mapped = Path.GetFullPath(Path.Combine(sharePath, suffix.TrimStart('\\')));
            return mapped.Equals(Path.GetFullPath(localTarget), StringComparison.OrdinalIgnoreCase);
        }
        finally { if (data != IntPtr.Zero) _ = NetApiBufferFree(data); }
    }

    private static string LinkString(ReadOnlySpan<byte> data, int start, bool unicode)
    {
        int end = start, stride = unicode ? 2 : 1;
        while (end + stride <= data.Length && (data[end] != 0 || unicode && data[end + 1] != 0)) end += stride;
        if (end + stride > data.Length) throw new ArgumentException();
        if (unicode) return new UnicodeEncoding(false, false, true).GetString(data.Slice(start, end - start));
        byte[] bytes = data.Slice(start, end - start).ToArray();
        if (bytes.Length == 0) return "";
        // MS-SHLLINK ANSI strings use the Windows ANSI code page, not Latin-1 or .NET's UTF-8 default.
        int chars = MultiByteToWideChar(0, 8, bytes, bytes.Length, null, 0);
        if (chars <= 0) throw new ArgumentException();
        char[] output = new char[chars];
        if (MultiByteToWideChar(0, 8, bytes, bytes.Length, output, output.Length) != chars) throw new ArgumentException();
        return new(output);
    }

    // Only ordinary Computer -> local drive -> filesystem item PIDLs reach the Windows path reader.
    // No ShellLink Resolve, icon lookup, custom namespace item, or executable is invoked.
    private static bool TryReadLocalIdList(ReadOnlySpan<byte> list, out string path, int minimumItems = 3)
    {
        path = "";
        int position = 0, count = 0;
        while (position + 2 <= list.Length)
        {
            int itemSize = BinaryPrimitives.ReadUInt16LittleEndian(list.Slice(position, 2));
            if (itemSize == 0) { if (position + 2 != list.Length || count < minimumItems) return false; break; }
            if (itemSize < 3 || itemSize > list.Length - position || count >= 128) return false;
            ReadOnlySpan<byte> item = list.Slice(position, itemSize);
            if (count == 0)
            {
                if (itemSize != 20 || item[2] != 0x1f || !item.Slice(4, 16).SequenceEqual(new Guid("20d04fe0-3aea-1069-a2d8-08002b30309d").ToByteArray())) return false;
            }
            else if (count == 1)
            {
                if (itemSize < 7 || item[2] != 0x2f || !char.IsAsciiLetter((char)item[3]) || item[4] != ':' || item[5] != '\\' || item[6] != 0 ||
                    new DriveInfo(((char)item[3]) + ":\\").DriveType == DriveType.Network) return false;
            }
            else if ((item[2] & 0x70) != 0x30 || itemSize < 14) return false;
            position += itemSize; count++;
        }
        if (position + 2 != list.Length) return false;
        IntPtr pidl = Marshal.AllocCoTaskMem(list.Length);
        try
        {
            Marshal.Copy(list.ToArray(), 0, pidl, list.Length);
            StringBuilder buffer = new(32768);
            if (!SHGetPathFromIDListEx(pidl, buffer, (uint)buffer.Capacity, 0) || !ContentDiscovery.IsLocalSafePath(buffer.ToString())) return false;
            path = Path.GetFullPath(buffer.ToString()); return true;
        }
        finally { Marshal.FreeCoTaskMem(pidl); }
    }

    private static bool KnownFolderMatches(ReadOnlySpan<byte> block, byte[] idList)
    {
        uint signature = BinaryPrimitives.ReadUInt32LittleEndian(block.Slice(4, 4));
        int offset; string folder;
        if (signature == 0xA0000005u)
        {
            if (block.Length != 16) return false;
            uint folderId = BinaryPrimitives.ReadUInt32LittleEndian(block.Slice(8, 4));
            if (folderId > 0x3f) return false;
            StringBuilder buffer = new(32768);
            if (SHGetFolderPath(IntPtr.Zero, (int)folderId | 0x4000, IntPtr.Zero, 0, buffer) != 0) return false;
            folder = buffer.ToString(); offset = checked((int)BinaryPrimitives.ReadUInt32LittleEndian(block.Slice(12, 4)));
        }
        else
        {
            if (block.Length != 28) return false;
            Guid folderId = new(block.Slice(8, 16));
            int result = SHGetKnownFolderPath(ref folderId, 0x4000, IntPtr.Zero, out IntPtr buffer);
            try { if (result != 0) return false; folder = Marshal.PtrToStringUni(buffer) ?? ""; }
            finally { if (buffer != IntPtr.Zero) Marshal.FreeCoTaskMem(buffer); }
            offset = checked((int)BinaryPrimitives.ReadUInt32LittleEndian(block.Slice(24, 4)));
        }
        if (offset <= 0 || offset > idList.Length - 2 || !ContentDiscovery.IsLocalSafePath(folder)) return false;
        byte[] prefix = [.. idList.AsSpan(0, offset), 0, 0];
        return TryReadLocalIdList(prefix, out string originalFolder, minimumItems: 2) &&
            Path.TrimEndingDirectorySeparator(originalFolder).Equals(Path.TrimEndingDirectorySeparator(Path.GetFullPath(folder)), StringComparison.OrdinalIgnoreCase);
    }

    [DllImport("shell32.dll", CharSet = CharSet.Unicode)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SHGetPathFromIDListEx(IntPtr pidl, StringBuilder path, uint characters, uint flags);
    [DllImport("shell32.dll", CharSet = CharSet.Unicode, EntryPoint = "SHGetFolderPathW")]
    private static extern int SHGetFolderPath(IntPtr window, int folder, IntPtr token, uint flags, StringBuilder path);
    [DllImport("shell32.dll")]
    private static extern int SHGetKnownFolderPath(ref Guid folder, uint flags, IntPtr token, out IntPtr path);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, ExactSpelling = true, SetLastError = true)]
    private static extern int MultiByteToWideChar(uint codePage, uint flags, byte[] bytes, int byteCount,
        [Out, MarshalAs(UnmanagedType.LPArray, ArraySubType = UnmanagedType.U2)] char[]? characters, int characterCount);
    [StructLayout(LayoutKind.Sequential)]
    private struct ShareInfo2
    {
        public IntPtr Name;
        public uint Type;
        public IntPtr Remark;
        public uint Permissions;
        public uint MaximumUses;
        public uint CurrentUses;
        public IntPtr Path;
        public IntPtr Password;
    }
    [DllImport("netapi32.dll", CharSet = CharSet.Unicode)]
    private static extern uint NetShareGetInfo(string? server, string share, uint level, out IntPtr data);
    [DllImport("netapi32.dll")]
    private static extern uint NetApiBufferFree(IntPtr data);

    private static bool TryRemoveDebugArgument(string input, IEnumerable<(int Start, int End, string Value)> tokens, out string repaired)
    {
        char[] chars = input.ToCharArray(); bool changed = false;
        foreach (var token in tokens)
            if (token.Value.Equals(DebugArgument, StringComparison.OrdinalIgnoreCase))
            { Array.Fill(chars, ' ', token.Start, token.End - token.Start); changed = true; }
        repaired = new(chars); return changed;
    }

    private static bool TryTokens(string value, out List<(int Start, int End, string Value)> tokens)
    {
        tokens = [];
        if (value.Any(ch => ch is '\r' or '\n' or '\0')) return false;
        for (int i = 0; i < value.Length;)
        {
            while (i < value.Length && value[i] is ' ' or '\t') i++;
            if (i == value.Length) break;
            int start = i; bool quoted = false; StringBuilder token = new();
            while (i < value.Length && (quoted || value[i] is not (' ' or '\t')))
            {
                if (value[i] == '"')
                {
                    // Reject escaped quotes, whose interpretation depends on the argument parser.
                    if (i > start && value[i - 1] == '\\') return false;
                    quoted = !quoted; i++; continue;
                }
                token.Append(value[i++]);
            }
            if (quoted) return false;
            tokens.Add((start, i, token.ToString()));
        }
        return true;
    }
}
