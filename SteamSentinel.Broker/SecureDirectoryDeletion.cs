using SteamSentinel.Core.Reporting;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace SteamSentinel.Broker;

internal static class SecureDirectoryDeletion
{
    private const uint Delete = 0x00010000;
    private const uint FileReadAttributes = 0x00000080;
    private const uint FileShareRead = 0x00000001;
    private const uint OpenExisting = 3;
    private const uint FileFlagOpenReparsePoint = 0x00200000;
    private const uint FileFlagBackupSemantics = 0x02000000;
    private const int FileAttributeTagInfoClass = 9;
    private const int FileDispositionInfoClass = 4;
    private const uint FileAttributeDirectory = 0x10;
    private const uint FileAttributeReparsePoint = 0x400;
    private const uint FileNameNormalized = 0x0;
    private const uint VolumeNameDos = 0x0;

    public static void DeleteEmpty(string path)
    {
        string requested = Path.TrimEndingDirectorySeparator(Path.GetFullPath(path));
        using SafeFileHandle handle = CreateFile(
            requested,
            Delete | FileReadAttributes,
            FileShareRead,
            IntPtr.Zero,
            OpenExisting,
            FileFlagOpenReparsePoint | FileFlagBackupSemantics,
            IntPtr.Zero);
        if (handle.IsInvalid)
            throw MessageExceptions.Win32(Marshal.GetLastWin32Error(), MessageText.Create("Backend.Broker.SecureDirectoryDeletion.DeleteEmpty.01", (requested)));

        if (!GetFileInformationByHandleEx(
                handle,
                FileAttributeTagInfoClass,
                out FileAttributeTagInfo attributes,
                (uint)Marshal.SizeOf<FileAttributeTagInfo>()))
        {
            throw MessageExceptions.Win32(Marshal.GetLastWin32Error(), MessageText.Create("Backend.Broker.SecureDirectoryDeletion.DeleteEmpty.02"));
        }
        if ((attributes.FileAttributes & FileAttributeDirectory) == 0 ||
            (attributes.FileAttributes & FileAttributeReparsePoint) != 0)
        {
            throw MessageExceptions.Create(MessageText.Create("Backend.Broker.SecureDirectoryDeletion.DeleteEmpty.03"), sourceText => new UnauthorizedAccessException(sourceText));
        }

        string finalPath = GetFinalPath(handle);
        if (!PathsEquivalent(requested, finalPath))
            throw MessageExceptions.Create(MessageText.Create("Backend.Broker.SecureDirectoryDeletion.DeleteEmpty.04", (requested), (finalPath)), sourceText => new UnauthorizedAccessException(sourceText));

        FileDispositionInfo disposition = new() { DeleteFile = true };
        if (!SetFileInformationByHandle(
                handle,
                FileDispositionInfoClass,
                ref disposition,
                (uint)Marshal.SizeOf<FileDispositionInfo>()))
        {
            throw MessageExceptions.Win32(Marshal.GetLastWin32Error(), MessageText.Create("Backend.Broker.SecureDirectoryDeletion.DeleteEmpty.05", (requested)));
        }
    }

    private static string GetFinalPath(SafeFileHandle handle)
    {
        StringBuilder buffer = new(32_768);
        uint length = GetFinalPathNameByHandle(handle, buffer, (uint)buffer.Capacity, FileNameNormalized | VolumeNameDos);
        if (length == 0) throw MessageExceptions.Win32(Marshal.GetLastWin32Error(), MessageText.Create("Backend.Broker.SecureDirectoryDeletion.GetFinalPath.01"));
        if (length >= buffer.Capacity) throw MessageExceptions.Create(MessageText.Create("Backend.Broker.SecureDirectoryDeletion.GetFinalPath.02"), sourceText => new PathTooLongException(sourceText));
        string value = buffer.ToString();
        if (value.StartsWith(@"\\?\UNC\", StringComparison.OrdinalIgnoreCase)) return @"\\" + value[8..];
        return value.StartsWith(@"\\?\", StringComparison.OrdinalIgnoreCase) ? value[4..] : value;
    }

    private static bool PathsEquivalent(string left, string right) =>
        Path.TrimEndingDirectorySeparator(Path.GetFullPath(left))
            .Equals(Path.TrimEndingDirectorySeparator(Path.GetFullPath(right)), StringComparison.OrdinalIgnoreCase);

    [StructLayout(LayoutKind.Sequential)]
    private struct FileAttributeTagInfo
    {
        public uint FileAttributes;
        public uint ReparseTag;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct FileDispositionInfo
    {
        [MarshalAs(UnmanagedType.U1)] public bool DeleteFile;
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern SafeFileHandle CreateFile(
        string fileName,
        uint desiredAccess,
        uint shareMode,
        IntPtr securityAttributes,
        uint creationDisposition,
        uint flagsAndAttributes,
        IntPtr templateFile);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetFileInformationByHandleEx(
        SafeFileHandle file,
        int fileInformationClass,
        out FileAttributeTagInfo fileInformation,
        uint bufferSize);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetFileInformationByHandle(
        SafeFileHandle file,
        int fileInformationClass,
        ref FileDispositionInfo fileInformation,
        uint bufferSize);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern uint GetFinalPathNameByHandle(
        SafeFileHandle file,
        StringBuilder filePath,
        uint filePathLength,
        uint flags);
}
