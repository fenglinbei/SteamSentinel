using System.Buffers;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using Microsoft.Win32.SafeHandles;
using SteamSentinel.Core.Inspection;
using SteamSentinel.Core.Models;
using SteamSentinel.Core.Steam;

namespace SteamSentinel.Core.Scanning;

public sealed partial class ContentScanner
{
    private async Task RecoverContainerLeafAsync(Stream stream, ContainerContext context, ContainerScanNode node)
    {
        if (context.Options.RecoveryOutputDirectory is not { } directory || node.Sha256 is null) return;
        if (node.Length < 0 || node.Length > context.Budget.Limits.MaximumEntryBytes)
            throw new ScanResourceLimitException("恢复叶子文件超过单项保存上限，已保留内容检查结果。");
        using RecoveryDirectoryLease lease = RecoveryDirectoryLease.OpenExisting(directory);
        string root = lease.Path;
        string name = node.NodeId.ToString("N") + ".scan";
        byte[] buffer = ArrayPool<byte>.Shared.Rent(128 * 1024);
        long reserved = 0;
        RecoveryWriteFile? output = null;
        try
        {
            output = lease.CreateFile(name);
            using IncrementalHash hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
            stream.Position = 0;
            while (true)
            {
                int read = await stream.ReadAsync(buffer, context.Token); if (read == 0) break;
                if (new DriveInfo(Path.GetPathRoot(root)!).AvailableFreeSpace < context.Budget.Limits.ReservedDiskBytes + read)
                    throw new ScanResourceLimitException("恢复内容暂存空间不足，已停止保存。");
                context.Budget.ReserveTemporary(read); reserved = checked(reserved + read);
                context.Budget.ChargeRangeCopy(read); hash.AppendData(buffer, 0, read);
                await output.Stream.WriteAsync(buffer.AsMemory(0, read), context.Token);
            }
            if (reserved != node.Length || !Convert.ToHexString(hash.GetHashAndReset()).Equals(node.Sha256, StringComparison.OrdinalIgnoreCase))
                throw new IOException("恢复副本与已检查内容身份不一致。");
            await output.CommitAsync(context.Token);
            node.RecoveredContentAvailable = true; node.RecoveredContentName = name;
            context.Report.Containers!.RecoveryOutputDirectory = root;
            if (!context.Report.Containers.Checks.Contains("恢复内容仅包含已校验的叶子文件，使用 .scan 名称；中间容器以每层身份与范围记录保留。"))
                context.Report.Containers.Checks.Add("恢复内容仅包含已校验的叶子文件，使用 .scan 名称；中间容器以每层身份与范围记录保留。");
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer, clearArray: true);
            if (output is not null)
            {
                await output.DisposeAsync();
                if (output.DeletedOnClose) context.Budget.ReleaseTemporary(reserved);
            }
        }
    }
}

/// <summary>Holds every directory component against replacement until recovery I/O completes.</summary>
public sealed class RecoveryDirectoryLease : IDisposable
{
    private readonly List<(SafeFileHandle Handle, string Path)> _handles = [];
    private readonly RecoveryDirectoryLease? _parent;
    private bool _disposed;
    public string Path { get; }

    private RecoveryDirectoryLease(string path, RecoveryDirectoryLease? parent = null) { Path = path; _parent = parent; }

    public static RecoveryDirectoryLease OpenExisting(string directory)
    {
        if (!ContentDiscovery.IsLocalSafePath(directory)) throw new IOException("恢复目录不是安全的本地普通目录。");
        string path = System.IO.Path.TrimEndingDirectorySeparator(System.IO.Path.GetFullPath(directory));
        RecoveryDirectoryLease lease = new(path);
        try
        {
            Stack<string> components = new();
            for (string? current = path; current is not null; current = System.IO.Path.GetDirectoryName(current)) components.Push(current);
            while (components.TryPop(out string? component))
            {
                // No FILE_SHARE_WRITE or FILE_SHARE_DELETE: changes to a held component fail closed.
                // FILE_LIST_DIRECTORY makes Windows enforce the sharing reservation;
                // an attributes-only handle does not block a later DELETE open.
                SafeFileHandle handle = NativeCreateFile(component, 0x81, 1, IntPtr.Zero, 3, 0x02200000, IntPtr.Zero);
                if (handle.IsInvalid)
                {
                    int error = Marshal.GetLastWin32Error(); handle.Dispose();
                    throw new Win32Exception(error, "无法锁定恢复目录。");
                }
                lease._handles.Add((handle, component));
                ValidateDirectory(handle, component);
            }
            return lease;
        }
        catch { lease.Dispose(); throw; }
    }

    public RecoveryDirectoryLease CreateDirectory(string name)
    {
        string path = ChildPath(name);
        // FILE_CREATE against the held parent returns the newly created directory's handle
        // in the same operation, with no CreateDirectory/OpenExisting replacement window.
        SafeFileHandle handle = CreateRelative(name, directory: true);
        RecoveryDirectoryLease child = new(path, this);
        child._handles.Add((handle, path));
        try { ValidateDirectory(handle, path); return child; }
        catch { child.Dispose(); throw; }
    }

    public FileStream OpenRead(string name)
    {
        string path = ChildPath(name);
        return RelatedArtifactReader.Open(path);
    }

    public RecoveryWriteFile CreateFile(string name)
    {
        string path = ChildPath(name);
        SafeFileHandle handle = CreateRelative(name, directory: false);
        try
        {
            // Partial files are marked through their own exclusive handle, so process death,
            // cancellation and exceptions cannot delete a later same-name replacement.
            RecoveryWriteFile.SetDelete(handle, true);
            RelatedArtifactReader.ValidatePath(handle, path);
            return new RecoveryWriteFile(this, path, new FileStream(handle, FileAccess.Write, 128 * 1024, isAsync: true));
        }
        catch { handle.Dispose(); throw; }
    }

    internal void Validate()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        _parent?.Validate();
        foreach ((SafeFileHandle handle, string path) in _handles) ValidateDirectory(handle, path);
    }

    private string ChildPath(string name)
    {
        Validate();
        if (string.IsNullOrWhiteSpace(name) || name.Length > 255 || name is "." or ".." || name.IndexOfAny(System.IO.Path.GetInvalidFileNameChars()) >= 0 ||
            name.EndsWith('.') || name.EndsWith(' ') || System.IO.Path.GetFileName(name) != name)
            throw new InvalidDataException("恢复输出文件名无效。");
        return System.IO.Path.Combine(Path, name);
    }

    private SafeFileHandle CreateRelative(string name, bool directory)
    {
        using NativeName native = new(name);
        ObjectAttributes attributes = new()
        {
            Length = (uint)Marshal.SizeOf<ObjectAttributes>(),
            RootDirectory = _handles[^1].Handle.DangerousGetHandle(),
            ObjectName = native.Pointer,
            Attributes = 0x40
        };
        int status = NtCreateFile(out SafeFileHandle handle, directory ? 0x00100081u : 0x40010080u, ref attributes,
            out _, IntPtr.Zero, directory ? 0x10u : 0x80u, directory ? 1u : 0u, 2,
            directory ? 0x00200021u : 0x00200040u, IntPtr.Zero, 0);
        if (status < 0)
        {
            handle.Dispose();
            throw new Win32Exception(unchecked((int)RtlNtStatusToDosError(status)), "无法以独占身份新建恢复内容。");
        }
        return handle;
    }

    private static void ValidateDirectory(SafeFileHandle handle, string path)
    {
        RelatedArtifactReader.ValidatePath(handle, path);
        if (!GetFileInformationByHandleEx(handle, 9, out AttributeTag info, 8) || (info.Attributes & 0x10) == 0)
            throw new IOException("恢复路径不是普通目录。");
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        for (int index = _handles.Count - 1; index >= 0; index--) _handles[index].Handle.Dispose();
    }

    private sealed class NativeName : IDisposable
    {
        private readonly IntPtr _text;
        public IntPtr Pointer { get; }
        internal NativeName(string name)
        {
            _text = Marshal.StringToHGlobalUni(name);
            Pointer = Marshal.AllocHGlobal(Marshal.SizeOf<UnicodeString>());
            Marshal.StructureToPtr(new UnicodeString
            {
                Length = checked((ushort)(name.Length * 2)),
                MaximumLength = checked((ushort)((name.Length + 1) * 2)),
                Buffer = _text
            }, Pointer, false);
        }
        public void Dispose() { Marshal.FreeHGlobal(Pointer); Marshal.FreeHGlobal(_text); }
    }
    [StructLayout(LayoutKind.Sequential)] private struct UnicodeString { public ushort Length; public ushort MaximumLength; public IntPtr Buffer; }
    [StructLayout(LayoutKind.Sequential)]
    private struct ObjectAttributes
    { public uint Length; public IntPtr RootDirectory; public IntPtr ObjectName; public uint Attributes; public IntPtr SecurityDescriptor; public IntPtr SecurityQualityOfService; }
    [StructLayout(LayoutKind.Sequential)] private struct IoStatusBlock { public IntPtr Status; public UIntPtr Information; }
    [StructLayout(LayoutKind.Sequential)] private struct AttributeTag { public uint Attributes; public uint Tag; }
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true, EntryPoint = "CreateFileW")]
    private static extern SafeFileHandle NativeCreateFile(string path, uint access, uint share, IntPtr security, uint disposition, uint flags, IntPtr template);
    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetFileInformationByHandleEx(SafeFileHandle handle, int infoClass, out AttributeTag info, uint size);
    [DllImport("ntdll.dll")]
    private static extern int NtCreateFile(out SafeFileHandle handle, uint access, ref ObjectAttributes attributes, out IoStatusBlock status,
        IntPtr allocationSize, uint fileAttributes, uint share, uint disposition, uint options, IntPtr eaBuffer, uint eaLength);
    [DllImport("ntdll.dll")] private static extern uint RtlNtStatusToDosError(int status);
}

/// <summary>An exclusive, initially delete-pending recovery file; only verified content is committed.</summary>
public sealed class RecoveryWriteFile : IAsyncDisposable
{
    private readonly RecoveryDirectoryLease _directory;
    private readonly string _path;
    private bool _closed;
    private bool _deletePending = true;
    public FileStream Stream { get; }
    public bool DeletedOnClose { get; private set; }
    internal RecoveryWriteFile(RecoveryDirectoryLease directory, string path, FileStream stream)
    { _directory = directory; _path = path; Stream = stream; }

    public async Task CommitAsync(CancellationToken token)
    {
        ObjectDisposedException.ThrowIf(_closed, this);
        await Stream.FlushAsync(token);
        token.ThrowIfCancellationRequested();
        _directory.Validate();
        RelatedArtifactReader.ValidatePath(Stream.SafeFileHandle, _path);
        SetDelete(Stream.SafeFileHandle, false); _deletePending = false;
        try { await Stream.DisposeAsync(); }
        finally { _closed = true; }
    }

    public async ValueTask DisposeAsync()
    {
        if (_closed) return;
        try { await Stream.DisposeAsync(); DeletedOnClose = _deletePending; }
        finally { _closed = true; }
    }

    internal static void SetDelete(SafeFileHandle handle, bool delete)
    {
        byte disposition = delete ? (byte)1 : (byte)0;
        if (!SetFileInformationByHandle(handle, 4, ref disposition, 1))
            throw new Win32Exception(Marshal.GetLastWin32Error(), "无法设置恢复文件的句柄清理状态。");
    }
    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetFileInformationByHandle(SafeFileHandle handle, int infoClass, ref byte info, uint size);
}
