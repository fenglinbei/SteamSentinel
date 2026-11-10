using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using Microsoft.Win32.SafeHandles;
using SteamSentinel.Core.Models;
using SteamSentinel.Core.Remediation;

namespace SteamSentinel.Broker;

/// <summary>Restoration information collected from the locked original, never supplied by a plan.</summary>
internal sealed record BrokerFileMetadata(string SecurityDescriptor, int Attributes,
    DateTimeOffset CreationTimeUtc, DateTimeOffset LastWriteTimeUtc)
{
    private const uint SecurityInformation = 1 | 2 | 4 | 8 | 0x10;
    private const int MaximumSecurityDescriptorBytes = 65536;
    private const FileAttributes RestorableAttributes = FileAttributes.ReadOnly | FileAttributes.Hidden |
        FileAttributes.System | FileAttributes.Archive | FileAttributes.Normal | FileAttributes.NotContentIndexed |
        FileAttributes.Temporary;

    internal static BrokerFileMetadata Capture(SafeFileHandle handle, string path, bool hasSecurityAccess = false)
    {
        if (hasSecurityAccess) return CaptureLocked(handle);
        EnsureOnlyDefaultStream(handle);
        using BrokerRestorePrivilege securityPrivilege = BrokerRestorePrivilege.EnableSecurity();
        using SafeFileHandle securityHandle = OpenSecurityHandle(path, handle);
        return CaptureLocked(securityHandle);
    }

    internal static BrokerFileMetadata CaptureLocked(SafeFileHandle handle)
    {
        if (!GetFileInformationByHandle(handle, out ByHandleInformation info))
            throw BrokerScopeText.Native(Marshal.GetLastWin32Error(), BrokerScopeText.MetadataUnavailable);
        if (((FileAttributes)info.Attributes & ~RestorableAttributes) != 0)
            throw BrokerScopeText.Denied(BrokerScopeText.UnsupportedMetadata);
        EnsureOnlyDefaultStream(handle);
        return new(ReadSecurityDescriptor(handle), checked((int)info.Attributes),
            new DateTimeOffset(DateTime.FromFileTimeUtc(info.Creation.ToLong())),
            new DateTimeOffset(DateTime.FromFileTimeUtc(info.LastWrite.ToLong())));
    }

    internal static BrokerFileMetadata FromRecord(QuarantineRecord record)
    {
        if (record.OriginalSecurityDescriptor is not { Length: > 0 and <= MaximumSecurityDescriptorBytes } security ||
            record.OriginalAttributes is not { } attributes || attributes < 0 ||
            ((FileAttributes)attributes & ~RestorableAttributes) != 0 ||
            record.OriginalCreationTimeUtc is not { } created || record.OriginalLastWriteTimeUtc is not { } written)
            throw BrokerScopeText.Invalid(BrokerScopeText.RestoreMetadataInvalid);
        try
        {
            RawSecurityDescriptor parsed = new(security);
            if (parsed.Owner is null || parsed.Group is null)
                throw BrokerScopeText.Invalid(BrokerScopeText.RestoreMetadataInvalid);
            _ = created.UtcDateTime.ToFileTimeUtc();
            _ = written.UtcDateTime.ToFileTimeUtc();
            return new(security, attributes, created, written);
        }
        catch (Exception ex) when (ex is ArgumentException or OverflowException)
        { throw BrokerScopeText.Invalid(BrokerScopeText.RestoreMetadataInvalid, ex); }
    }

    internal void Apply(SafeFileHandle handle, string boundPath)
    {
        FileScopeSafety.ValidateHandlePath(handle, boundPath);
        string destinationIdentity = FileScopeSafety.ReadIdentity(handle);
        if (!FileScopeSafety.CaptureIdentity(boundPath).Equals(destinationIdentity, StringComparison.Ordinal))
            throw BrokerScopeText.Denied(BrokerScopeText.IdentityChanged);
        FileBasicInformation basic = new()
        {
            CreationTime = CreationTimeUtc.UtcDateTime.ToFileTimeUtc(),
            LastWriteTime = LastWriteTimeUtc.UtcDateTime.ToFileTimeUtc(),
            Attributes = checked((uint)Attributes)
        };
        if (!SetFileInformationByHandle(handle, 0, ref basic, (uint)Marshal.SizeOf<FileBasicInformation>()))
            throw BrokerScopeText.Native(Marshal.GetLastWin32Error(), BrokerScopeText.RestoreMetadataInvalid);

        RawSecurityDescriptor descriptor = new(SecurityDescriptor);
        byte[] bytes = new byte[descriptor.BinaryLength];
        descriptor.GetBinaryForm(bytes, 0);
        uint information = 1 | 2 | 4;
        if (descriptor.ControlFlags.HasFlag(ControlFlags.SystemAclPresent))
            information |= 8 | 0x10;
        // SetFileSecurity preserves legacy ACLs without imposing auto-inheritance, while
        // SetSecurityInfo converts each selected ACL to the current inheritance model.
        // Restore the complete descriptor first, then convert only originally auto-inherited
        // components. DACL and SACL can use different inheritance models. The caller
        // holds the destination with FileShare.None and every parent without delete sharing;
        // the exact path is bound to this handle immediately before and after the write.
        // An absent SACL is not a NULL SACL, so do not manufacture one.
        if (!SetFileSecurity(boundPath.Length >= 248 ? @"\\?\" + boundPath : boundPath, information, bytes))
            throw BrokerScopeText.Native(Marshal.GetLastWin32Error(), BrokerScopeText.RestoreMetadataInvalid);
        if (descriptor.ControlFlags.HasFlag(ControlFlags.DiscretionaryAclAutoInherited))
            RestoreAutoInheritedAcl(handle, descriptor.DiscretionaryAcl, discretionary: true,
                descriptor.ControlFlags.HasFlag(ControlFlags.DiscretionaryAclProtected));
        if (descriptor.ControlFlags.HasFlag(ControlFlags.SystemAclAutoInherited))
            RestoreAutoInheritedAcl(handle, descriptor.SystemAcl, discretionary: false,
                descriptor.ControlFlags.HasFlag(ControlFlags.SystemAclProtected));
        FileScopeSafety.ValidateHandlePath(handle, boundPath);
        if (!FileScopeSafety.CaptureIdentity(boundPath).Equals(destinationIdentity, StringComparison.Ordinal))
            throw BrokerScopeText.Denied(BrokerScopeText.IdentityChanged);
        string actualSecurity = ReadSecurityDescriptor(handle);
        bool readActual = GetFileInformationByHandle(handle, out ByHandleInformation actual);
        if (!actualSecurity.Equals(SecurityDescriptor, StringComparison.Ordinal) ||
            !readActual || actual.Attributes != (uint)Attributes ||
            actual.Creation.ToLong() != basic.CreationTime || actual.LastWrite.ToLong() != basic.LastWriteTime)
        {
            IOException mismatch = BrokerScopeText.Io(BrokerScopeText.RestoreMetadataInvalid);
            mismatch.Data["ScopeMetadataDiagnostic"] = System.Text.Json.JsonSerializer.Serialize(new
            {
                expected = this,
                actualSecurity,
                readActual,
                actualAttributes = actual.Attributes,
                actualCreationTime = actual.Creation.ToLong(),
                actualLastWriteTime = actual.LastWrite.ToLong()
            });
            throw mismatch;
        }
    }

    private static void RestoreAutoInheritedAcl(SafeFileHandle handle, RawAcl? acl, bool discretionary, bool protect)
    {
        IntPtr buffer = IntPtr.Zero;
        try
        {
            if (acl is not null)
            {
                byte[] bytes = new byte[acl.BinaryLength];
                acl.GetBinaryForm(bytes, 0);
                buffer = Marshal.AllocHGlobal(bytes.Length);
                Marshal.Copy(bytes, 0, buffer, bytes.Length);
            }
            uint information = discretionary
                ? 4 | (protect ? 0x80000000u : 0x20000000u)
                : 8 | 0x10 | (protect ? 0x40000000u : 0x10000000u);
            uint error = SetSecurityInfo(handle, 1, information, IntPtr.Zero, IntPtr.Zero,
                discretionary ? buffer : IntPtr.Zero, discretionary ? IntPtr.Zero : buffer);
            if (error != 0)
                throw BrokerScopeText.Native(checked((int)error), BrokerScopeText.RestoreMetadataInvalid);
        }
        finally { if (buffer != IntPtr.Zero) Marshal.FreeHGlobal(buffer); }
    }

    private static string ReadSecurityDescriptor(SafeFileHandle handle)
    {
        // Query all concrete descriptor components, including newer SACL types. The aggregate
        // BACKUP_SECURITY_INFORMATION flag is rejected by GetSecurityInfo on supported hosts.
        // Reject components this restoration format cannot round-trip instead of omitting them.
        uint error = GetSecurityInfo(handle, 1, 0x000001FF, out _, out _, out _, out _, out IntPtr descriptor);
        if (error != 0) throw BrokerScopeText.Native(checked((int)error), BrokerScopeText.MetadataUnavailable);
        try
        {
            uint length = GetSecurityDescriptorLength(descriptor);
            if (length is < 20 or > MaximumSecurityDescriptorBytes)
                throw BrokerScopeText.Invalid(BrokerScopeText.MetadataUnavailable);
            byte[] bytes = new byte[length];
            Marshal.Copy(descriptor, bytes, 0, bytes.Length);
            RawSecurityDescriptor raw = new(bytes, 0);
            if (raw.Owner is null || raw.Group is null) throw BrokerScopeText.Invalid(BrokerScopeText.MetadataUnavailable);
            if (raw.SystemAcl is not null && raw.SystemAcl.Cast<GenericAce>().Any(ace =>
                    (int)ace.AceType is not (2 or 3 or 7 or 8 or 13 or 14 or 15 or 16 or 17)))
                throw BrokerScopeText.Denied(BrokerScopeText.UnsupportedMetadata);
            // .NET GetSddlForm(AccessControlSections.All) omits LABEL_SECURITY_INFORMATION.
            // Include it explicitly so a mandatory integrity ACE is not lost from the snapshot.
            if (!ConvertSecurityDescriptorToStringSecurityDescriptor(descriptor, 1, SecurityInformation,
                    out IntPtr text, out uint characters))
                throw BrokerScopeText.Native(Marshal.GetLastWin32Error(), BrokerScopeText.MetadataUnavailable);
            try
            {
                if (characters is < 2 or > MaximumSecurityDescriptorBytes + 1)
                    throw BrokerScopeText.Invalid(BrokerScopeText.MetadataUnavailable);
                string sddl = Marshal.PtrToStringUni(text) ?? throw BrokerScopeText.Invalid(BrokerScopeText.MetadataUnavailable);
                if (sddl.Length > MaximumSecurityDescriptorBytes) throw BrokerScopeText.Invalid(BrokerScopeText.MetadataUnavailable);
                return sddl;
            }
            finally { if (text != IntPtr.Zero) _ = LocalFree(text); }
        }
        finally { if (descriptor != IntPtr.Zero) _ = LocalFree(descriptor); }
    }

    private static SafeFileHandle OpenSecurityHandle(string path, SafeFileHandle original)
    {
        SafeFileHandle handle = CreateFile(path.Length >= 248 ? @"\\?\" + path : path,
            0x00020000 | 0x01000000 | 0x80, 7, IntPtr.Zero, 3, 0x00200000, IntPtr.Zero);
        if (handle.IsInvalid)
        {
            int error = Marshal.GetLastWin32Error(); handle.Dispose();
            throw BrokerScopeText.Native(error, BrokerScopeText.MetadataUnavailable);
        }
        try
        {
            FileScopeSafety.ValidateHandlePath(handle, path);
            if (!FileScopeSafety.ReadIdentity(handle).Equals(FileScopeSafety.ReadIdentity(original), StringComparison.Ordinal))
                throw BrokerScopeText.Denied(BrokerScopeText.IdentityChanged);
            return handle;
        }
        catch { handle.Dispose(); throw; }
    }

    internal static void EnsureOnlyDefaultStream(SafeFileHandle handle)
    {
        int status = NtQueryInformationFile(handle, out IoStatus ioStatus, out uint eaBytes, 4, 7);
        if (status == 0x103)
        {
            // Local file metadata queries normally complete inline. Keep the buffers alive
            // until an asynchronous filter completes the request before inspecting or freeing them.
            if (WaitForSingleObject(handle, uint.MaxValue) != 0)
                throw BrokerScopeText.Invalid(BrokerScopeText.UnsupportedMetadata);
            status = unchecked((int)ioStatus.Status.ToInt64());
        }
        if (status != 0 || ioStatus.Information.ToUInt64() != 4 || eaBytes != 0)
            throw BrokerScopeText.Denied(BrokerScopeText.UnsupportedMetadata);
        for (int size = 4096; size <= 1024 * 1024; size *= 2)
        {
            IntPtr buffer = Marshal.AllocHGlobal(size);
            try
            {
                if (!GetFileInformationByHandleEx(handle, 7, buffer, (uint)size))
                {
                    int error = Marshal.GetLastWin32Error();
                    if (error == 38) return;
                    if (error is 234 or 122) continue;
                    throw BrokerScopeText.Native(error, BrokerScopeText.UnsupportedMetadata);
                }
                int offset = 0;
                while (true)
                {
                    if (offset > size - 24) throw BrokerScopeText.Invalid(BrokerScopeText.UnsupportedMetadata);
                    int next = Marshal.ReadInt32(buffer, offset);
                    int nameBytes = Marshal.ReadInt32(buffer, offset + 4);
                    if (nameBytes <= 0 || (nameBytes & 1) != 0 || nameBytes > size - offset - 24)
                        throw BrokerScopeText.Invalid(BrokerScopeText.UnsupportedMetadata);
                    string name = Marshal.PtrToStringUni(IntPtr.Add(buffer, offset + 24), nameBytes / 2)!;
                    if (!name.Equals("::$DATA", StringComparison.OrdinalIgnoreCase))
                        throw BrokerScopeText.Denied(BrokerScopeText.UnsupportedMetadata);
                    if (next == 0) return;
                    if (next < 24 + nameBytes || next > size - offset)
                        throw BrokerScopeText.Invalid(BrokerScopeText.UnsupportedMetadata);
                    offset += next;
                }
            }
            finally { Marshal.FreeHGlobal(buffer); }
        }
        throw BrokerScopeText.Invalid(BrokerScopeText.UnsupportedMetadata);
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct NativeFileTime
    {
        public uint Low;
        public uint High;
        public readonly long ToLong() => unchecked((long)(((ulong)High << 32) | Low));
    }
    [StructLayout(LayoutKind.Sequential)]
    private struct ByHandleInformation
    {
        public uint Attributes;
        public NativeFileTime Creation;
        public NativeFileTime LastAccess;
        public NativeFileTime LastWrite;
        public uint VolumeSerial;
        public uint SizeHigh;
        public uint SizeLow;
        public uint Links;
        public uint IndexHigh;
        public uint IndexLow;
    }
    [StructLayout(LayoutKind.Sequential)]
    private struct FileBasicInformation
    {
        public long CreationTime;
        public long LastAccessTime;
        public long LastWriteTime;
        public long ChangeTime;
        public uint Attributes;
    }
    [StructLayout(LayoutKind.Sequential)]
    private struct IoStatus { public IntPtr Status; public UIntPtr Information; }
    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetFileInformationByHandle(SafeFileHandle file, out ByHandleInformation info);
    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetFileInformationByHandleEx(SafeFileHandle file, int infoClass, IntPtr info, uint size);
    [DllImport("ntdll.dll")]
    private static extern int NtQueryInformationFile(SafeFileHandle file, out IoStatus ioStatus, out uint information, uint length, int infoClass);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern uint WaitForSingleObject(SafeFileHandle handle, uint milliseconds);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true, EntryPoint = "CreateFileW")]
    private static extern SafeFileHandle CreateFile(string path, uint access, uint share, IntPtr security, uint disposition, uint flags, IntPtr template);
    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetFileInformationByHandle(SafeFileHandle file, int infoClass, ref FileBasicInformation info, uint size);
    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern uint GetSecurityInfo(SafeFileHandle handle, int objectType, uint securityInfo,
        out IntPtr owner, out IntPtr group, out IntPtr dacl, out IntPtr sacl, out IntPtr descriptor);
    [DllImport("advapi32.dll")]
    private static extern uint SetSecurityInfo(SafeFileHandle handle, int objectType, uint securityInfo,
        IntPtr owner, IntPtr group, IntPtr dacl, IntPtr sacl);
    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern uint GetSecurityDescriptorLength(IntPtr descriptor);
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true, EntryPoint = "SetFileSecurityW")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetFileSecurity(string path, uint securityInformation, byte[] descriptor);
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true, EntryPoint = "ConvertSecurityDescriptorToStringSecurityDescriptorW")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool ConvertSecurityDescriptorToStringSecurityDescriptor(IntPtr descriptor, uint revision,
        uint information, out IntPtr text, out uint characters);
    [DllImport("kernel32.dll")]
    private static extern IntPtr LocalFree(IntPtr memory);
}

/// <summary>Only trusted rollback uses this scope, and it restores the original token state.</summary>
internal sealed class BrokerRestorePrivilege : IDisposable
{
    private readonly SafeAccessTokenHandle _token;
    private readonly TokenPrivileges _previous;
    private readonly bool _adjusted;

    private BrokerRestorePrivilege(SafeAccessTokenHandle token, TokenPrivileges previous, bool adjusted)
    { _token = token; _previous = previous; _adjusted = adjusted; }

    internal static BrokerRestorePrivilege EnableWhenAvailable()
        => Enable("SeRestorePrivilege", allowUnavailable: true);

    internal static BrokerRestorePrivilege EnableSecurity()
        => Enable("SeSecurityPrivilege", allowUnavailable: false);

    private static BrokerRestorePrivilege Enable(string privilegeName, bool allowUnavailable)
    {
        if (!OpenProcessToken(GetCurrentProcess(), 0x20 | 0x8, out SafeAccessTokenHandle token))
            throw BrokerScopeText.Native(Marshal.GetLastWin32Error(), BrokerScopeText.RestoreMetadataInvalid);
        try
        {
            if (!LookupPrivilegeValue(null, privilegeName, out Luid luid))
                throw BrokerScopeText.Native(Marshal.GetLastWin32Error(), BrokerScopeText.RestoreMetadataInvalid);
            TokenPrivileges requested = new() { Count = 1, Luid = luid, Attributes = 2 };
            if (!AdjustTokenPrivileges(token, false, ref requested, (uint)Marshal.SizeOf<TokenPrivileges>(), out TokenPrivileges previous, out _))
                throw BrokerScopeText.Native(Marshal.GetLastWin32Error(), BrokerScopeText.RestoreMetadataInvalid);
            int error = Marshal.GetLastWin32Error();
            if (error != 0 && !(allowUnavailable && error == 1300))
                throw BrokerScopeText.Native(error, BrokerScopeText.MetadataUnavailable);
            // A standard user can still restore their own owner/DACL with ordinary access.
            return new(token, previous, error == 0);
        }
        catch { token.Dispose(); throw; }
    }

    public void Dispose()
    {
        if (_token.IsClosed) return;
        try
        {
            if (_adjusted)
            {
                TokenPrivileges previous = _previous;
                if (!AdjustTokenPrivileges(_token, false, ref previous, (uint)Marshal.SizeOf<TokenPrivileges>(), out _, out _))
                    throw BrokerScopeText.Native(Marshal.GetLastWin32Error(), BrokerScopeText.RestoreMetadataInvalid);
            }
        }
        finally { _token.Dispose(); }
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct Luid { public uint Low; public int High; }
    [StructLayout(LayoutKind.Sequential)]
    private struct TokenPrivileges { public uint Count; public Luid Luid; public uint Attributes; }
    [DllImport("kernel32.dll")]
    private static extern IntPtr GetCurrentProcess();
    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool OpenProcessToken(IntPtr process, uint access, out SafeAccessTokenHandle token);
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool LookupPrivilegeValue(string? system, string name, out Luid luid);
    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool AdjustTokenPrivileges(SafeAccessTokenHandle token, bool disableAll, ref TokenPrivileges newState,
        uint length, out TokenPrivileges previous, out uint returnedLength);
}
