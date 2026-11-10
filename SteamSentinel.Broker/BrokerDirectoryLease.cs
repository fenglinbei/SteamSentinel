using System.ComponentModel;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
using SteamSentinel.Core.Remediation;
using SteamSentinel.Core.Utilities;

namespace SteamSentinel.Broker;

/// <summary>Holds every directory from the volume root to the target parent without delete sharing.</summary>
internal sealed class BrokerDirectoryLease : IDisposable
{
    private readonly List<SafeFileHandle> _handles = [];
    internal string ParentIdentity { get; private set; } = string.Empty;

    private BrokerDirectoryLease() { }

    internal static BrokerDirectoryLease OpenParent(string target, string? expectedIdentity = null)
    {
        if (!Path.IsPathFullyQualified(target) || target.StartsWith(@"\\", StringComparison.Ordinal) ||
            target.Length < 3 || target[1] != ':' || target.IndexOf(':', 2) >= 0)
            throw BrokerScopeText.Denied(BrokerScopeText.ProtectedPath);
        string full = Path.GetFullPath(target);
        string parent = Path.GetDirectoryName(full) ?? throw BrokerScopeText.Denied(BrokerScopeText.ProtectedPath);
        string root = Path.GetPathRoot(full) ?? throw BrokerScopeText.Denied(BrokerScopeText.ProtectedPath);
        BrokerDirectoryLease lease = new();
        try
        {
            string current = root;
            lease.OpenDirectory(current);
            foreach (string segment in parent[root.Length..].Split(Path.DirectorySeparatorChar, StringSplitOptions.RemoveEmptyEntries))
            {
                current = Path.Combine(current, segment);
                lease.OpenDirectory(current);
            }
            lease.ParentIdentity = FileScopeSafety.ReadIdentity(lease._handles[^1]);
            if (expectedIdentity is not null &&
                (!FileScopeSafety.IsValidIdentity(expectedIdentity) ||
                 !lease.ParentIdentity.Equals(expectedIdentity, StringComparison.OrdinalIgnoreCase)))
                throw BrokerScopeText.Denied(BrokerScopeText.IdentityChanged);
            return lease;
        }
        catch { lease.Dispose(); throw; }
    }

    private void OpenDirectory(string path)
    {
        // Metadata-only opens do not participate in normal file sharing checks on Windows.
        // FILE_LIST_DIRECTORY makes the omitted FILE_SHARE_DELETE pin the ancestor itself.
        SafeFileHandle handle = CreateFile(Encode(path), 0x1 | 0x80, 3, IntPtr.Zero, 3,
            0x02000000 | 0x00200000, IntPtr.Zero);
        if (handle.IsInvalid)
        {
            int error = Marshal.GetLastWin32Error();
            handle.Dispose();
            throw BrokerScopeText.Native(error, BrokerScopeText.IdentityChanged);
        }
        try
        {
            if (!GetFileInformationByHandleEx(handle, 9, out AttributeTag attributes, 8) ||
                (attributes.Attributes & (0x400 | 0x10)) != 0x10)
                throw BrokerScopeText.Denied(BrokerScopeText.ProtectedPath);
            char[] buffer = new char[32768];
            uint length = GetFinalPathNameByHandle(handle, buffer, (uint)buffer.Length, 0);
            if (length == 0 || length >= buffer.Length) throw BrokerScopeText.Io(BrokerScopeText.IdentityChanged);
            string final = new(buffer, 0, (int)length);
            if (final.StartsWith(@"\\?\", StringComparison.Ordinal)) final = final[4..];
            if (!Path.TrimEndingDirectorySeparator(Path.GetFullPath(final)).Equals(
                    Path.TrimEndingDirectorySeparator(Path.GetFullPath(path)), StringComparison.OrdinalIgnoreCase))
                throw BrokerScopeText.Denied(BrokerScopeText.IdentityChanged);
            _handles.Add(handle);
        }
        catch { handle.Dispose(); throw; }
    }

    private static string Encode(string path) => path.Length >= 248 ? @"\\?\" + path : path;

    public void Dispose()
    {
        for (int i = _handles.Count - 1; i >= 0; i--) _handles[i].Dispose();
        _handles.Clear();
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct AttributeTag { public uint Attributes; public uint Tag; }
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true, EntryPoint = "CreateFileW")]
    private static extern SafeFileHandle CreateFile(string path, uint access, uint share, IntPtr security, uint disposition, uint flags, IntPtr template);
    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetFileInformationByHandleEx(SafeFileHandle handle, int infoClass, out AttributeTag info, uint size);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true, EntryPoint = "GetFinalPathNameByHandleW")]
    private static extern uint GetFinalPathNameByHandle(SafeFileHandle handle, [Out] char[] path, uint size, uint flags);
}
