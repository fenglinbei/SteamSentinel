using System.Text.RegularExpressions;

namespace SteamSentinel.Core.Utilities;

public static partial class Validation
{
    [GeneratedRegex("^(?=.{1,253}$)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\\.)+[a-zA-Z]{2,63}$", RegexOptions.CultureInvariant)]
    private static partial Regex DomainRegex();

    public static bool IsSafeDomain(string value) => DomainRegex().IsMatch(value);

    public static bool IsHexSha256(string? value) =>
        value is { Length: 64 } && value.All(Uri.IsHexDigit);

    public static bool TryNormalizeScheduledTaskName(string? value, out string normalized)
    {
        normalized = string.Empty;
        if (string.IsNullOrWhiteSpace(value) || value.Length > 512 || value.Any(char.IsControl))
        {
            return false;
        }

        string[] parts = value.Replace('/', '\\').Trim('\\')
            .Split('\\', StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length == 0 || parts.Any(part => part is "." or ".." || part.Contains(':')))
        {
            return false;
        }

        normalized = "\\" + string.Join('\\', parts);
        return true;
    }

    public static bool IsSafeExactTarget(string path)
    {
        if (string.IsNullOrWhiteSpace(path) || !Path.IsPathFullyQualified(path))
        {
            return false;
        }

        string fullPath;
        try
        {
            fullPath = Path.TrimEndingDirectorySeparator(Path.GetFullPath(path));
        }
        catch
        {
            return false;
        }

        string? root = Path.GetPathRoot(fullPath);
        if (string.IsNullOrWhiteSpace(root) ||
            string.Equals(Path.TrimEndingDirectorySeparator(root), fullPath, StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        string windows = Path.TrimEndingDirectorySeparator(Environment.GetFolderPath(Environment.SpecialFolder.Windows));
        string programFiles = Path.TrimEndingDirectorySeparator(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles));
        string programFilesX86 = Path.TrimEndingDirectorySeparator(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86));
        string userProfile = Path.TrimEndingDirectorySeparator(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile));

        return !string.Equals(fullPath, windows, StringComparison.OrdinalIgnoreCase) &&
               !string.Equals(fullPath, programFiles, StringComparison.OrdinalIgnoreCase) &&
               !string.Equals(fullPath, programFilesX86, StringComparison.OrdinalIgnoreCase) &&
               !string.Equals(fullPath, userProfile, StringComparison.OrdinalIgnoreCase);
    }

    public static bool IsRedirectingReparseTag(uint reparseTag) =>
        (reparseTag & 0x20000000u) != 0 || reparseTag == 0x8000001Bu;

    public static bool IsRedirectingReparsePoint(string path)
    {
        FileAttributes attributes;
        try { attributes = File.GetAttributes(path); }
        catch (Exception ex) when (ex is FileNotFoundException or DirectoryNotFoundException) { return false; }
        catch { return true; }
        if ((attributes & FileAttributes.ReparsePoint) == 0) return false;
        try
        {
            string full = LocalNativePath.Encode(Path.TrimEndingDirectorySeparator(Path.GetFullPath(path)));
            using SafeFindHandle find = FindFirstFileW(full, out Win32FindData data);
            if (!find.IsInvalid) return (data.dwFileAttributes & (uint)FileAttributes.ReparsePoint) != 0 && IsRedirectingReparseTag(data.dwReserved0);
            using Microsoft.Win32.SafeHandles.SafeFileHandle handle = CreateFileW(
                LocalNativePath.Encode(Path.GetFullPath(path)), 0x80, 7, IntPtr.Zero, 3, 0x02200000, IntPtr.Zero);
            if (handle.IsInvalid)
            {
                int error = System.Runtime.InteropServices.Marshal.GetLastWin32Error();
                return error is not (2 or 3);
            }
            return IsRedirectingReparseHandle(handle);
        }
        catch { return true; }
    }

    internal static bool IsRedirectingReparseHandle(Microsoft.Win32.SafeHandles.SafeFileHandle handle)
    {
        if (!GetFileInformationByHandleEx(handle, 9, out FileAttributeTagInfo info, 8)) return true;
        return (info.FileAttributes & (uint)FileAttributes.ReparsePoint) != 0 && IsRedirectingReparseTag(info.ReparseTag);
    }

    public static bool ContainsReparsePoint(string path)
    {
        string full = Path.GetFullPath(path);
        string? root = Path.GetPathRoot(full);
        if (root is null)
        {
            return true;
        }

        string current = root;
        foreach (string part in full[root.Length..].Split(Path.DirectorySeparatorChar, StringSplitOptions.RemoveEmptyEntries))
        {
            current = Path.Combine(current, part);
            if (!File.Exists(current) && !Directory.Exists(current))
            {
                continue;
            }

            FileAttributes attributes = File.GetAttributes(current);
            if ((attributes & FileAttributes.ReparsePoint) != 0 && IsRedirectingReparsePoint(current))
            {
                return true;
            }
        }

        return false;
    }

    private sealed class SafeFindHandle : Microsoft.Win32.SafeHandles.SafeHandleZeroOrMinusOneIsInvalid
    {
        private SafeFindHandle() : base(true) { }
        protected override bool ReleaseHandle() => FindClose(handle);
    }

    [System.Runtime.InteropServices.StructLayout(System.Runtime.InteropServices.LayoutKind.Sequential, CharSet = System.Runtime.InteropServices.CharSet.Unicode)]
    private struct Win32FindData
    {
        public uint dwFileAttributes;
        public System.Runtime.InteropServices.ComTypes.FILETIME ftCreationTime, ftLastAccessTime, ftLastWriteTime;
        public uint nFileSizeHigh, nFileSizeLow, dwReserved0, dwReserved1;
        [System.Runtime.InteropServices.MarshalAs(System.Runtime.InteropServices.UnmanagedType.ByValTStr, SizeConst = 260)]
        public string cFileName;
        [System.Runtime.InteropServices.MarshalAs(System.Runtime.InteropServices.UnmanagedType.ByValTStr, SizeConst = 14)]
        public string cAlternateFileName;
    }

    [System.Runtime.InteropServices.StructLayout(System.Runtime.InteropServices.LayoutKind.Sequential)]
    private struct FileAttributeTagInfo { public uint FileAttributes, ReparseTag; }

    [System.Runtime.InteropServices.DllImport("kernel32.dll", CharSet = System.Runtime.InteropServices.CharSet.Unicode, SetLastError = true)]
    private static extern SafeFindHandle FindFirstFileW(string lpFileName, out Win32FindData lpFindFileData);

    [System.Runtime.InteropServices.DllImport("kernel32.dll", SetLastError = true)]
    [return: System.Runtime.InteropServices.MarshalAs(System.Runtime.InteropServices.UnmanagedType.Bool)]
    private static extern bool FindClose(IntPtr hFindFile);

    [System.Runtime.InteropServices.DllImport("kernel32.dll", CharSet = System.Runtime.InteropServices.CharSet.Unicode, SetLastError = true)]
    private static extern Microsoft.Win32.SafeHandles.SafeFileHandle CreateFileW(
        string lpFileName, uint dwDesiredAccess, uint dwShareMode, IntPtr lpSecurityAttributes,
        uint dwCreationDisposition, uint dwFlagsAndAttributes, IntPtr hTemplateFile);

    [System.Runtime.InteropServices.DllImport("kernel32.dll", SetLastError = true)]
    [return: System.Runtime.InteropServices.MarshalAs(System.Runtime.InteropServices.UnmanagedType.Bool)]
    private static extern bool GetFileInformationByHandleEx(
        Microsoft.Win32.SafeHandles.SafeFileHandle hFile, int FileInformationClass, out FileAttributeTagInfo lpFileInformation, uint dwBufferSize);
}
