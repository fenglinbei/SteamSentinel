using SteamSentinel.Core.Reporting;
using System.ComponentModel;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
using SteamSentinel.Core.Utilities;

namespace SteamSentinel.Broker;

internal sealed class SecureFileLease : IAsyncDisposable
{
    private readonly FileStream _stream;
    private readonly bool _canIgnoreReadOnly;
    private bool _deleteRequested;

    private SecureFileLease(FileStream stream, string finalPath, bool canIgnoreReadOnly)
    {
        _stream = stream;
        FinalPath = finalPath;
        _canIgnoreReadOnly = canIgnoreReadOnly;
    }

    public string FinalPath { get; }
    public long Length => _stream.Length;

    public static SecureFileLease Open(string path, bool allowPackagedLocalAppDataRedirection = false)
    {
        string requested = Path.GetFullPath(path);
        SafeFileHandle handle = CreateFile(
            requested,
            GenericRead | Delete | FileReadAttributes | FileWriteAttributes,
            FileShareRead,
            IntPtr.Zero,
            OpenExisting,
            FileFlagOpenReparsePoint | FileFlagSequentialScan | FileFlagOverlapped,
            IntPtr.Zero);
        bool canIgnoreReadOnly = !handle.IsInvalid;
        // Read-only disposition requires FILE_WRITE_ATTRIBUTES. Keep ordinary files
        // usable when their ACL grants DELETE but intentionally denies that extra right.
        if (handle.IsInvalid && Marshal.GetLastWin32Error() == ErrorAccessDenied)
        {
            handle.Dispose();
            handle = CreateFile(requested, GenericRead | Delete | FileReadAttributes,
                FileShareRead, IntPtr.Zero, OpenExisting,
                FileFlagOpenReparsePoint | FileFlagSequentialScan | FileFlagOverlapped, IntPtr.Zero);
        }
        if (handle.IsInvalid)
        {
            int error = Marshal.GetLastWin32Error();
            handle.Dispose();
            throw MessageExceptions.Win32(error, MessageText.Create("Backend.Broker.SecureFileLease.Open.01", (requested)));
        }

        try
        {
            if (!GetFileInformationByHandleEx(
                    handle,
                    FileAttributeTagInfoClass,
                    out FileAttributeTagInfo attributes,
                    (uint)Marshal.SizeOf<FileAttributeTagInfo>()))
            {
                throw MessageExceptions.Win32(Marshal.GetLastWin32Error(), MessageText.Create("Backend.Broker.SecureFileLease.Open.02"));
            }
            if ((attributes.FileAttributes & FileAttributeReparsePoint) != 0)
                throw MessageExceptions.Create(MessageText.Create("Backend.Broker.SecureFileLease.Open.03"), sourceText => new UnauthorizedAccessException(sourceText));

            string finalPath = GetFinalPath(handle);
            if (!PathsEquivalent(requested, finalPath) &&
                !(allowPackagedLocalAppDataRedirection && IsPackagedLocalAppDataRedirection(requested, finalPath)))
                throw MessageExceptions.Create(MessageText.Create("Backend.Broker.SecureFileLease.Open.04", (requested), (finalPath)), sourceText => new UnauthorizedAccessException(sourceText));

            FileStream stream = new(handle, FileAccess.Read, 128 * 1024, isAsync: true);
            return new SecureFileLease(stream, finalPath, canIgnoreReadOnly);
        }
        catch
        {
            handle.Dispose();
            throw;
        }
    }

    public async Task<string> ComputeSha256Async(CancellationToken cancellationToken)
    {
        _stream.Position = 0;
        string hash = await Hashing.Sha256StreamAsync(_stream, cancellationToken).ConfigureAwait(false);
        _stream.Position = 0;
        return hash;
    }

    public async Task<T> ReadJsonAsync<T>(CancellationToken cancellationToken)
    {
        _stream.Position = 0;
        T value = await JsonFile.ReadAsync<T>(_stream, FinalPath, cancellationToken).ConfigureAwait(false);
        _stream.Position = 0;
        return value;
    }

    public async Task CopyToAsync(string destination, string expectedSha256, CancellationToken cancellationToken)
    {
        string fullDestination = Path.GetFullPath(destination);
        string parent = Path.GetDirectoryName(fullDestination)
            ?? throw MessageExceptions.Create(MessageText.Create("Backend.Broker.SecureFileLease.CopyToAsync.01"), sourceText => new InvalidOperationException(sourceText));
        if (!Directory.Exists(parent))
            throw MessageExceptions.Create(MessageText.Create("Backend.Broker.SecureFileLease.CopyToAsync.02"), sourceText => new DirectoryNotFoundException(sourceText));
        if (Validation.ContainsReparsePoint(parent))
            throw MessageExceptions.Create(MessageText.Create("Backend.Broker.SecureFileLease.CopyToAsync.03"), sourceText => new UnauthorizedAccessException(sourceText));

        bool completed = false;
        SafeFileHandle destinationHandle = CreateFile(
            fullDestination,
            GenericRead | GenericWrite | Delete | FileReadAttributes,
            0,
            IntPtr.Zero,
            CreateNew,
            FileAttributeNormal | FileFlagOpenReparsePoint | FileFlagSequentialScan |
            FileFlagOverlapped | FileFlagWriteThrough,
            IntPtr.Zero);
        if (destinationHandle.IsInvalid)
        {
            int error = Marshal.GetLastWin32Error();
            destinationHandle.Dispose();
            throw MessageExceptions.Win32(error, MessageText.Create("Backend.Broker.SecureFileLease.CopyToAsync.04", (fullDestination)));
        }
        try
        {
            if (!GetFileInformationByHandleEx(
                    destinationHandle,
                    FileAttributeTagInfoClass,
                    out FileAttributeTagInfo destinationAttributes,
                    (uint)Marshal.SizeOf<FileAttributeTagInfo>()) ||
                (destinationAttributes.FileAttributes & FileAttributeReparsePoint) != 0 ||
                !PathsEquivalent(GetFinalPath(destinationHandle), fullDestination))
            {
                TryMarkDelete(destinationHandle);
                throw MessageExceptions.Create(MessageText.Create("Backend.Broker.SecureFileLease.CopyToAsync.05"), sourceText => new UnauthorizedAccessException(sourceText));
            }

            await using FileStream output = new(destinationHandle, FileAccess.ReadWrite, 128 * 1024, isAsync: true);
            try
            {
                _stream.Position = 0;
                await _stream.CopyToAsync(output, 128 * 1024, cancellationToken).ConfigureAwait(false);
                await output.FlushAsync(cancellationToken).ConfigureAwait(false);
                output.Flush(flushToDisk: true);
                output.Position = 0;
                string copiedHash = await Hashing.Sha256StreamAsync(output, cancellationToken).ConfigureAwait(false);
                if (!copiedHash.Equals(expectedSha256, StringComparison.OrdinalIgnoreCase))
                    throw MessageExceptions.Create(MessageText.Create("Backend.Broker.SecureFileLease.CopyToAsync.06"), sourceText => new IOException(sourceText));
                completed = true;
            }
            catch
            {
                TryMarkDelete(output.SafeFileHandle);
                throw;
            }
        }
        finally
        {
            if (!completed && !destinationHandle.IsClosed) TryMarkDelete(destinationHandle);
            destinationHandle.Dispose();
        }
    }

    public void DeleteOnClose()
    {
        if (!TryMarkDelete(_stream.SafeFileHandle, _canIgnoreReadOnly, out int error))
            throw MessageExceptions.Win32(error, MessageText.Create("Backend.Broker.SecureFileLease.DeleteOnClose.01", (error)));
        _deleteRequested = true;
    }

    private static bool TryMarkDelete(SafeFileHandle handle) => TryMarkDelete(handle, false, out _);

    private static bool TryMarkDelete(SafeFileHandle handle, bool canIgnoreReadOnly, out int error)
    {
        FileDispositionInfo disposition = new() { DeleteFile = true };
        if (SetFileInformationByHandle(
            handle,
            FileDispositionInfoClass,
            ref disposition,
            (uint)Marshal.SizeOf<FileDispositionInfo>()))
        {
            error = 0;
            return true;
        }
        error = Marshal.GetLastWin32Error();
        // Enforce this right ourselves as well: native behavior differs across Windows
        // environments. A fallback handle must never bypass denied attribute writes.
        if (error != ErrorAccessDenied || !canIgnoreReadOnly) return false;
        if (!GetFileInformationByHandleEx(handle, FileAttributeTagInfoClass,
                out FileAttributeTagInfo attributes, (uint)Marshal.SizeOf<FileAttributeTagInfo>()))
        {
            error = Marshal.GetLastWin32Error();
            return false;
        }
        if ((attributes.FileAttributes & FileAttributeReadOnly) == 0) return false;

        // Keep the verified handle, source attributes, sharing rules and image-section
        // check. Do not reopen by path, relax ACLs, or use POSIX deletion semantics.
        FileDispositionInfoEx extended = new()
        {
            Flags = FileDispositionDelete | FileDispositionForceImageSectionCheck | FileDispositionIgnoreReadOnly
        };
        bool deleted = SetFileInformationByHandle(handle, FileDispositionInfoExClass,
            ref extended, (uint)Marshal.SizeOf<FileDispositionInfoEx>());
        error = deleted ? 0 : Marshal.GetLastWin32Error();
        return deleted;
    }

    public async ValueTask DisposeAsync()
    {
        await _stream.DisposeAsync().ConfigureAwait(false);
        if (_deleteRequested && File.Exists(FinalPath))
            throw MessageExceptions.Create(MessageText.Create("Backend.Broker.SecureFileLease.DisposeAsync.01"), sourceText => new IOException(sourceText));
    }

    private static string GetFinalPath(SafeFileHandle handle)
    {
        char[] buffer = new char[32_768];
        uint length = GetFinalPathNameByHandle(handle, buffer, (uint)buffer.Length, FileNameNormalized | VolumeNameDos);
        if (length == 0) throw MessageExceptions.Win32(Marshal.GetLastWin32Error(), MessageText.Create("Backend.Broker.SecureFileLease.GetFinalPath.01"));
        if (length >= buffer.Length) throw MessageExceptions.Create(MessageText.Create("Backend.Broker.SecureFileLease.GetFinalPath.02"), sourceText => new PathTooLongException(sourceText));
        string value = new(buffer, 0, (int)length);
        if (value.StartsWith("\\\\?\\UNC\\", StringComparison.OrdinalIgnoreCase))
            return "\\\\" + value[8..];
        if (value.StartsWith("\\\\?\\", StringComparison.OrdinalIgnoreCase))
            return value[4..];
        return value;
    }

    private static bool PathsEquivalent(string left, string right) =>
        Path.TrimEndingDirectorySeparator(Path.GetFullPath(left)).Equals(
            Path.TrimEndingDirectorySeparator(Path.GetFullPath(right)),
            StringComparison.OrdinalIgnoreCase);

    private static bool IsPackagedLocalAppDataRedirection(string requested, string actual)
    {
        string localAppData = Path.TrimEndingDirectorySeparator(Path.GetFullPath(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData)));
        if (!requested.StartsWith(localAppData + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase))
            return false;

        string packagesPrefix = Path.Combine(localAppData, "Packages") + Path.DirectorySeparatorChar;
        if (!actual.StartsWith(packagesPrefix, StringComparison.OrdinalIgnoreCase)) return false;
        string redirectedRemainder = actual[packagesPrefix.Length..];
        int separator = redirectedRemainder.IndexOf(Path.DirectorySeparatorChar);
        if (separator <= 0) return false;
        string packageFamily = redirectedRemainder[..separator];
        if (packageFamily.IndexOfAny(Path.GetInvalidFileNameChars()) >= 0) return false;
        string relative = Path.GetRelativePath(localAppData, requested);
        string redirected = Path.Combine(
            localAppData,
            "Packages",
            packageFamily,
            "LocalCache",
            "Local",
            relative);
        return PathsEquivalent(actual, redirected);
    }

    private const uint GenericRead = 0x80000000;
    private const uint GenericWrite = 0x40000000;
    private const uint Delete = 0x00010000;
    private const uint FileReadAttributes = 0x00000080;
    private const uint FileWriteAttributes = 0x00000100;
    private const uint FileShareRead = 0x00000001;
    private const uint OpenExisting = 3;
    private const uint CreateNew = 1;
    private const uint FileAttributeNormal = 0x00000080;
    private const uint FileAttributeReadOnly = 0x00000001;
    private const uint FileFlagOverlapped = 0x40000000;
    private const uint FileFlagWriteThrough = 0x80000000;
    private const uint FileFlagOpenReparsePoint = 0x00200000;
    private const uint FileFlagSequentialScan = 0x08000000;
    private const uint FileAttributeReparsePoint = 0x00000400;
    private const int FileAttributeTagInfoClass = 9;
    private const int FileDispositionInfoClass = 4;
    private const int FileDispositionInfoExClass = 21;
    private const int ErrorAccessDenied = 5;
    private const uint FileDispositionDelete = 0x00000001;
    private const uint FileDispositionForceImageSectionCheck = 0x00000004;
    private const uint FileDispositionIgnoreReadOnly = 0x00000010;
    private const uint FileNameNormalized = 0;
    private const uint VolumeNameDos = 0;

    [StructLayout(LayoutKind.Sequential)]
    private struct FileAttributeTagInfo
    {
        public uint FileAttributes;
        public uint ReparseTag;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct FileDispositionInfo
    {
        [MarshalAs(UnmanagedType.U1)]
        public bool DeleteFile;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct FileDispositionInfoEx
    {
        public uint Flags;
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

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern uint GetFinalPathNameByHandle(
        SafeFileHandle file,
        [Out] char[] filePath,
        uint filePathLength,
        uint flags);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetFileInformationByHandle(
        SafeFileHandle file,
        int fileInformationClass,
        ref FileDispositionInfo fileInformation,
        uint bufferSize);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetFileInformationByHandle(
        SafeFileHandle file,
        int fileInformationClass,
        ref FileDispositionInfoEx fileInformation,
        uint bufferSize);

}
