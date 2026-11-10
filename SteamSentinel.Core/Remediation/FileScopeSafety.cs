using System.ComponentModel;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
using SteamSentinel.Core.Reporting;
using SteamSentinel.Core.Utilities;

namespace SteamSentinel.Core.Remediation;

public sealed record FileScopeSafetyResult(bool Allowed, string ReasonCode, bool Sensitive)
{
    public MessageText Message => FileScopeSafety.MessageFor(ReasonCode);
}

/// <summary>
/// Shared read-only checks. Passing these checks is never consent, a file identity lease,
/// or permission to bypass the operating system's access controls.
/// </summary>
public static class FileScopeSafety
{
    public static MessageText MessageFor(string reasonCode) => MessageText.Create(reasonCode switch
    {
        "Automatic" => "Scope.Automatic",
        "ExplicitConsent" => "Scope.ExplicitConsent",
        "SensitiveConsent" => "Scope.SensitiveConsent",
        "UnsupportedPath" => "Scope.UnsupportedPath",
        "ProductProtected" => "Scope.ProductProtected",
        "RedirectedPath" => "Scope.RedirectedPath",
        "SystemProtected" => "Scope.SystemProtected",
        _ => "Scope.NeedsVerification"
    });

    public static FileScopeSafetyResult EvaluatePath(string path)
    {
        try
        {
            if (!IsLocalFilePath(path)) return new(false, "UnsupportedPath", false);
            string full = Path.TrimEndingDirectorySeparator(Path.GetFullPath(path));
            string windows = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
            bool sensitive = IsWithin(full, windows) ||
                IsWithin(full, Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles)) ||
                IsWithin(full, Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86));
            if (IsWithin(full, AppContext.BaseDirectory) || IsWithin(full, AppPaths.MachineStateRoot) ||
                IsWithin(full, AppPaths.UserStateRoot)) return new(false, "ProductProtected", sensitive);
            if (Validation.ContainsReparsePoint(full)) return new(false, "RedirectedPath", sensitive);
            if (IsCriticalPath(full, windows) || SfcIsFileProtected(IntPtr.Zero, full))
                return new(false, "SystemProtected", true);
            return new(true, sensitive ? "SensitiveConsent" : "ExplicitConsent", sensitive);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException or
            NotSupportedException or Win32Exception or System.Security.SecurityException or DllNotFoundException or EntryPointNotFoundException)
        {
            return new(false, "NeedsVerification", false);
        }
    }

    public static bool IsLocalFilePath(string path)
    {
        if (string.IsNullOrWhiteSpace(path) || path.Any(char.IsControl) || !Path.IsPathFullyQualified(path) ||
            path.StartsWith(@"\\", StringComparison.Ordinal) || path.IndexOfAny(['*', '?', '"', '<', '>', '|']) >= 0)
            return false;
        string full = Path.GetFullPath(path);
        return full.Length > 3 && char.IsAsciiLetter(full[0]) && full[1] == ':' &&
            full[2] == Path.DirectorySeparatorChar && full.IndexOf(':', 2) < 0 && Validation.IsSafeExactTarget(full);
    }

    internal static bool IsWithin(string candidate, string root)
    {
        if (string.IsNullOrWhiteSpace(root)) return false;
        string fullRoot = Path.TrimEndingDirectorySeparator(Path.GetFullPath(root));
        return candidate.Equals(fullRoot, StringComparison.OrdinalIgnoreCase) ||
            candidate.StartsWith(fullRoot + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase);
    }

    private static bool IsCriticalPath(string path, string windows)
    {
        string root = Path.GetPathRoot(path)!;
        if (new[] { "System Volume Information", "$Recycle.Bin", "Boot", "EFI" }
            .Any(name => IsWithin(path, Path.Combine(root, name)))) return true;
        if (path.Equals(Path.Combine(root, "bootmgr"), StringComparison.OrdinalIgnoreCase) ||
            path.Equals(Path.Combine(root, "pagefile.sys"), StringComparison.OrdinalIgnoreCase) ||
            path.Equals(Path.Combine(root, "hiberfil.sys"), StringComparison.OrdinalIgnoreCase) ||
            path.Equals(Path.Combine(root, "swapfile.sys"), StringComparison.OrdinalIgnoreCase)) return true;
        return !string.IsNullOrWhiteSpace(windows) &&
            new[] { @"System32\config", @"System32\drivers", @"System32\DriverStore", "WinSxS", "servicing", "Boot" }
                .Any(relative => IsWithin(path, Path.Combine(windows, relative)));
    }

    /// <summary>Metadata-only snapshot; the Broker must compare again using its locked handle.</summary>
    public static string CaptureIdentity(string path, bool directory = false)
    {
        // A protected directory can be the parent of an otherwise eligible exact file.
        // Capturing that directory's identity grants no right to quarantine the directory.
        bool localDirectory = directory && path.Length >= 3 && Path.IsPathFullyQualified(path) &&
            char.IsAsciiLetter(path[0]) && path[1] == ':' && path[2] == Path.DirectorySeparatorChar &&
            path.IndexOf(':', 2) < 0 && path.IndexOfAny(['*', '?', '"', '<', '>', '|']) < 0 && !path.Any(char.IsControl);
        if ((!localDirectory && !IsLocalFilePath(path)) || Validation.ContainsReparsePoint(path))
            throw MessageExceptions.Create(MessageText.Create("Scope.RedirectedPath"), text => new UnauthorizedAccessException(text));
        string full = Path.TrimEndingDirectorySeparator(Path.GetFullPath(path));
        using SafeFileHandle handle = CreateFile(LocalNativePath.Encode(full), 0x80, 7, IntPtr.Zero, 3,
            0x00200000 | (directory ? 0x02000000u : 0u), IntPtr.Zero);
        if (handle.IsInvalid) throw MessageExceptions.Win32(Marshal.GetLastWin32Error(), MessageText.Create("Scope.NeedsVerification"));
        ValidateHandlePath(handle, full, directory);
        return ReadIdentity(handle);
    }

    public static string ReadIdentity(SafeFileHandle handle)
    {
        if (!GetFileIdInformation(handle, 18, out FileIdInfo info, (uint)Marshal.SizeOf<FileIdInfo>()))
            throw MessageExceptions.Win32(Marshal.GetLastWin32Error(), MessageText.Create("Scope.NeedsVerification"));
        if (info.VolumeSerialNumber == 0 || info.FileIdLow == 0 && info.FileIdHigh == 0)
            throw MessageExceptions.Create(MessageText.Create("Scope.InvalidIdentity"), text => new InvalidDataException(text));
        return $"{info.VolumeSerialNumber:X16}:{info.FileIdLow:X16}{info.FileIdHigh:X16}";
    }

    public static uint ReadLinkCount(SafeFileHandle handle)
    {
        if (!GetFileInformationByHandle(handle, out HandleInfo info))
            throw MessageExceptions.Win32(Marshal.GetLastWin32Error(), MessageText.Create("Scope.NeedsVerification"));
        return info.NumberOfLinks;
    }

    public static bool IsValidIdentity(string? value) => value is { Length: 49 } && value[16] == ':' &&
        value.Where((_, index) => index != 16).All(Uri.IsHexDigit) &&
        value[..16].Any(character => character != '0') && value[17..].Any(character => character != '0');

    public static void ValidateHandlePath(SafeFileHandle handle, string path, bool directory = false)
    {
        if (!GetFileInformationByHandle(handle, out HandleInfo info) || (info.FileAttributes & 0x400) != 0 ||
            ((info.FileAttributes & 0x10) != 0) != directory)
            throw MessageExceptions.Create(MessageText.Create("Scope.RedirectedPath"), text => new UnauthorizedAccessException(text));
        char[] buffer = new char[32768];
        uint count = GetFinalPathNameByHandle(handle, buffer, (uint)buffer.Length, 0);
        if (count == 0 || count >= buffer.Length)
            throw MessageExceptions.Win32(Marshal.GetLastWin32Error(), MessageText.Create("Scope.NeedsVerification"));
        string final = new(buffer, 0, (int)count);
        if (final.StartsWith(@"\\?\", StringComparison.Ordinal)) final = final[4..];
        if (!final.Equals(Path.TrimEndingDirectorySeparator(Path.GetFullPath(path)), StringComparison.OrdinalIgnoreCase) ||
            Validation.ContainsReparsePoint(path))
            throw MessageExceptions.Create(MessageText.Create("Scope.RedirectedPath"), text => new UnauthorizedAccessException(text));
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct FileIdInfo { public ulong VolumeSerialNumber; public ulong FileIdLow; public ulong FileIdHigh; }
    [StructLayout(LayoutKind.Sequential)]
    private struct HandleInfo
    {
        public uint FileAttributes;
        public System.Runtime.InteropServices.ComTypes.FILETIME CreationTime, LastAccessTime, LastWriteTime;
        public uint VolumeSerialNumber, FileSizeHigh, FileSizeLow, NumberOfLinks, FileIndexHigh, FileIndexLow;
    }
    [DllImport("sfc.dll", CharSet = CharSet.Unicode)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SfcIsFileProtected(IntPtr rpcHandle, string path);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true, EntryPoint = "CreateFileW")]
    private static extern SafeFileHandle CreateFile(string path, uint access, uint share, IntPtr security, uint disposition, uint flags, IntPtr template);
    [DllImport("kernel32.dll", SetLastError = true, EntryPoint = "GetFileInformationByHandleEx")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetFileIdInformation(SafeFileHandle handle, int infoClass, out FileIdInfo info, uint size);
    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetFileInformationByHandle(SafeFileHandle handle, out HandleInfo info);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true, EntryPoint = "GetFinalPathNameByHandleW")]
    private static extern uint GetFinalPathNameByHandle(SafeFileHandle handle, [Out] char[] path, uint size, uint flags);
}
