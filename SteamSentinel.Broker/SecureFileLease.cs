using System.ComponentModel;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
using SteamSentinel.Core.Utilities;

namespace SteamSentinel.Broker;

internal sealed class SecureFileLease : IAsyncDisposable
{
    private readonly FileStream _stream;
    private bool _deleteRequested;

    private SecureFileLease(FileStream stream, string finalPath)
    {
        _stream = stream;
        FinalPath = finalPath;
    }

    public string FinalPath { get; }
    public long Length => _stream.Length;

    public static SecureFileLease Open(string path, bool allowPackagedLocalAppDataRedirection = false)
    {
        string requested = Path.GetFullPath(path);
        SafeFileHandle handle = CreateFile(
            requested,
            GenericRead | Delete | FileReadAttributes,
            FileShareRead,
            IntPtr.Zero,
            OpenExisting,
            FileFlagOpenReparsePoint | FileFlagSequentialScan | FileFlagOverlapped,
            IntPtr.Zero);
        if (handle.IsInvalid)
        {
            int error = Marshal.GetLastWin32Error();
            handle.Dispose();
            throw new Win32Exception(error, $"无法锁定目标文件：{requested}");
        }

        try
        {
            if (!GetFileInformationByHandleEx(
                    handle,
                    FileAttributeTagInfoClass,
                    out FileAttributeTagInfo attributes,
                    (uint)Marshal.SizeOf<FileAttributeTagInfo>()))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error(), "无法读取目标文件属性。");
            }
            if ((attributes.FileAttributes & FileAttributeReparsePoint) != 0)
                throw new UnauthorizedAccessException("目标文件是重解析点，已拒绝操作。");

            string finalPath = GetFinalPath(handle);
            if (!PathsEquivalent(requested, finalPath) &&
                !(allowPackagedLocalAppDataRedirection && IsPackagedLocalAppDataRedirection(requested, finalPath)))
                throw new UnauthorizedAccessException($"目标文件解析后的路径与请求路径不一致：请求 {requested}，实际 {finalPath}");

            FileStream stream = new(handle, FileAccess.Read, 128 * 1024, isAsync: true);
            return new SecureFileLease(stream, finalPath);
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
            ?? throw new InvalidOperationException("隔离目标没有父目录。");
        if (!Directory.Exists(parent))
            throw new DirectoryNotFoundException("目标父目录不存在，管理员组件不会自动创建不受保护的父路径。");
        if (Validation.ContainsReparsePoint(parent))
            throw new UnauthorizedAccessException("隔离目标目录包含重解析点。");

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
            throw new Win32Exception(error, $"无法以新文件方式创建目标：{fullDestination}");
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
                throw new UnauthorizedAccessException("目标文件解析后的路径不一致或属于重解析点。");
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
                    throw new IOException("隔离副本哈希校验失败。");
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
        if (!TryMarkDelete(_stream.SafeFileHandle))
            throw new Win32Exception(Marshal.GetLastWin32Error(), "隔离副本已建立，但无法按句柄移除原文件。");
        _deleteRequested = true;
    }

    private static bool TryMarkDelete(SafeFileHandle handle)
    {
        FileDispositionInfo disposition = new() { DeleteFile = true };
        return SetFileInformationByHandle(
            handle,
            FileDispositionInfoClass,
            ref disposition,
            (uint)Marshal.SizeOf<FileDispositionInfo>());
    }

    public async ValueTask DisposeAsync()
    {
        await _stream.DisposeAsync().ConfigureAwait(false);
        if (_deleteRequested && File.Exists(FinalPath))
            throw new IOException("文件删除标记未在句柄关闭后生效。");
    }

    private static string GetFinalPath(SafeFileHandle handle)
    {
        char[] buffer = new char[32_768];
        uint length = GetFinalPathNameByHandle(handle, buffer, (uint)buffer.Length, FileNameNormalized | VolumeNameDos);
        if (length == 0) throw new Win32Exception(Marshal.GetLastWin32Error(), "无法解析目标文件最终路径。");
        if (length >= buffer.Length) throw new PathTooLongException("目标文件最终路径过长。");
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
    private const uint FileShareRead = 0x00000001;
    private const uint OpenExisting = 3;
    private const uint CreateNew = 1;
    private const uint FileAttributeNormal = 0x00000080;
    private const uint FileFlagOverlapped = 0x40000000;
    private const uint FileFlagWriteThrough = 0x80000000;
    private const uint FileFlagOpenReparsePoint = 0x00200000;
    private const uint FileFlagSequentialScan = 0x08000000;
    private const uint FileAttributeReparsePoint = 0x00000400;
    private const int FileAttributeTagInfoClass = 9;
    private const int FileDispositionInfoClass = 4;
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
        [MarshalAs(UnmanagedType.Bool)]
        public bool DeleteFile;
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

}
