using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;
using SteamSentinel.Core.Steam;

namespace SteamSentinel.Core.Utilities;

/// <summary>
/// Resolves a directory already created and owned by this application. Packaged launchers can
/// virtualize AppData writes without a filesystem reparse point. Publish the actual owned path
/// so subsequent content handles can retain strict requested/final-path equality. Never use this
/// helper to accept redirected scan roots, remediation targets, or user recovery destinations.
/// </summary>
public static class OwnedDirectoryPhysicalPath
{
    public static string ResolveForCreation(string directory)
    {
        string requested = Path.TrimEndingDirectorySeparator(Path.GetFullPath(directory));
        if (!Directory.Exists(requested) || !ContentDiscovery.IsLocalSafePath(requested))
            throw new IOException("自有工作目录不是可验证的本地普通目录。");
        using SafeFileHandle root = OpenDirectory(requested);
        _ = DirectoryIdentity(root);
        // A packaged process can read a pre-existing real AppData directory while new child
        // writes go to its package store. Resolve an exclusively created empty child, not the
        // merged root's read view, to determine where this process actually creates content.
        string name = ".steamsentinel-physical-" + Guid.NewGuid().ToString("N");
        string probe = Path.Combine(requested, name);
        if (!CreateDirectory(probe, IntPtr.Zero)) throw new Win32Exception(Marshal.GetLastWin32Error(), "无法确定自有工作目录的创建位置。");
        string? physicalProbe = null;
        try
        {
            physicalProbe = ResolveExisting(probe);
            if (!Path.GetFileName(physicalProbe).Equals(name, StringComparison.Ordinal))
                throw new IOException("自有目录探针身份发生变化。");
            string physicalRoot = Path.GetDirectoryName(physicalProbe) ?? throw new IOException("自有目录探针缺少父目录。");
            if (!ResolveExisting(physicalRoot).Equals(physicalRoot, StringComparison.OrdinalIgnoreCase))
                throw new IOException("自有物理根目录在复核时发生变化。");
            return physicalRoot;
        }
        finally
        {
            // Only this freshly created, uniquely named empty directory is removed. This does
            // not recursively delete anything or modify a user-selected source/destination.
            string cleanup = physicalProbe ?? probe;
            if (Path.GetFileName(cleanup).Equals(name, StringComparison.Ordinal) &&
                Directory.Exists(cleanup) && !Validation.ContainsReparsePoint(cleanup)) Directory.Delete(cleanup, recursive: false);
        }
    }

    public static string ResolveExisting(string directory)
    {
        if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException("临时目录身份校验需要 Windows。");
        string requested = Path.TrimEndingDirectorySeparator(Path.GetFullPath(directory));
        if (!Directory.Exists(requested) || !ContentDiscovery.IsLocalSafePath(requested))
            throw new IOException("自有工作目录不是可验证的本地普通目录。");
        using SafeFileHandle original = OpenDirectory(requested);
        FileInformation originalIdentity = DirectoryIdentity(original);
        string physical = FinalPath(original);
        if (!ContentDiscovery.IsLocalSafePath(physical)) throw new IOException("自有工作目录的最终路径不安全。");
        using SafeFileHandle verified = OpenDirectory(physical);
        FileInformation physicalIdentity = DirectoryIdentity(verified);
        if (!FinalPath(verified).Equals(physical, StringComparison.OrdinalIgnoreCase) ||
            originalIdentity.VolumeSerialNumber != physicalIdentity.VolumeSerialNumber ||
            originalIdentity.FileIndexHigh != physicalIdentity.FileIndexHigh || originalIdentity.FileIndexLow != physicalIdentity.FileIndexLow)
            throw new IOException("自有工作目录在确认物理路径时发生变化。");
        return physical;
    }

    private static SafeFileHandle OpenDirectory(string path)
    {
        // Read attributes only; refuse a final-component reparse and deny rename/deletion while
        // comparing the logical and physical handles. No ACL or integrity label is changed.
        SafeFileHandle handle = CreateFile(path, 0x80, 3, IntPtr.Zero, 3, 0x02000000 | 0x00200000, IntPtr.Zero);
        if (!handle.IsInvalid) return handle;
        int error = Marshal.GetLastWin32Error(); handle.Dispose();
        throw new Win32Exception(error, "无法验证自有工作目录身份。");
    }

    private static FileInformation DirectoryIdentity(SafeFileHandle handle)
    {
        if (!GetFileInformationByHandle(handle, out FileInformation information) ||
            (information.Attributes & (uint)FileAttributes.Directory) == 0 ||
            (information.Attributes & (uint)FileAttributes.ReparsePoint) != 0)
            throw new IOException("自有工作目录句柄不是普通目录。");
        return information;
    }

    private static string FinalPath(SafeFileHandle handle)
    {
        StringBuilder buffer = new(32768);
        uint length = GetFinalPathNameByHandle(handle, buffer, (uint)buffer.Capacity, 0);
        if (length == 0 || length >= buffer.Capacity) throw new IOException("无法取得自有工作目录物理路径。");
        string path = buffer.ToString();
        if (path.StartsWith(@"\\?\", StringComparison.Ordinal)) path = path[4..];
        return Path.TrimEndingDirectorySeparator(path);
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct FileTime { public uint Low, High; }
    [StructLayout(LayoutKind.Sequential)]
    private struct FileInformation
    {
        public uint Attributes;
        public FileTime CreationTime, LastAccessTime, LastWriteTime;
        public uint VolumeSerialNumber, FileSizeHigh, FileSizeLow, NumberOfLinks, FileIndexHigh, FileIndexLow;
    }
    [DllImport("kernel32.dll", EntryPoint = "CreateFileW", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern SafeFileHandle CreateFile(string path, uint access, uint share, IntPtr security, uint disposition, uint flags, IntPtr template);
    [DllImport("kernel32.dll", EntryPoint = "CreateDirectoryW", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CreateDirectory(string path, IntPtr security);
    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetFileInformationByHandle(SafeFileHandle handle, out FileInformation information);
    [DllImport("kernel32.dll", EntryPoint = "GetFinalPathNameByHandleW", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern uint GetFinalPathNameByHandle(SafeFileHandle handle, StringBuilder path, uint size, uint flags);
}
