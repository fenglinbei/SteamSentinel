using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Principal;
using Microsoft.Win32.SafeHandles;
using SteamSentinel.Core.Models;

namespace SteamSentinel.Core.Remediation;

/// <summary>
/// Only four local SYSTEM_REGISTRY_W stores. Reads never import, request, export or
/// acquire a private key. Changes observed before mutation are refused, but CryptoAPI
/// exposes no atomic state-comparison/delete transaction with other applications.
/// </summary>
public sealed class WindowsBoundCertificateStore : IBoundCertificateStore
{
    private const int MaximumStoreCertificates = 4096;
    private const long MaximumStoreDerBytes = 32L * 1024 * 1024;
    private static readonly TimeSpan MaximumReadDuration = TimeSpan.FromSeconds(10);
    private const uint OpenExisting = 0x4000, ReadOnly = 0x8000, EnumArchived = 0x200;
    private const uint CurrentUser = 0x10000, LocalMachine = 0x20000, UnprotectedRoot = 0x40000000;
    private const uint AddNew = 1;

    public IReadOnlyList<BoundCertificateBackup> ReadMatching(BoundCertificateTarget target)
    {
        BoundCertificateTarget identity = ValidateIdentity(target, requireProperties: false);
        using SafeCertificateStoreHandle store = Open(identity, writable: false);
        using StoreChangeWatch watch = new(store);
        using NativeSnapshot? snapshot = FindUnique(store, identity);
        watch.RequireUnchanged();
        return snapshot is null ? [] : [snapshot.Backup];
    }

    public void RemoveExact(BoundCertificateBackup expected)
    {
        BoundCertificateBackup backup = BoundCertificateRepair.ValidateBackup(expected);
        BoundCertificateTarget target = ValidateIdentity(backup.Target, requireProperties: true);
        using SafeCertificateStoreHandle store = Open(target, writable: true);
        using StoreChangeWatch watch = new(store);
        using NativeSnapshot? current = FindUnique(store, target);
        if (current is null) throw Failure(BoundCertificateProbeStatus.Absent, "删除前指定物理证书已不存在，未继续操作。");
        BoundCertificateRepair.RequireSameState(backup, current.Backup);
        ValidateIdentity(target, requireProperties: true);
        watch.RequireUnchanged();
        // CertDeleteCertificateFromStore always releases the passed reference, even
        // on failure. Detach that exact owned reference before calling the API.
        IntPtr context = current.Context.Detach();
        if (!CertDeleteCertificateFromStore(context))
            throw NativeFailure("精确证书删除未获确认，备份须保留");
        if (ReadMatching(target).Count != 0)
            throw Failure(BoundCertificateProbeStatus.Changed, "删除后该物理证书仍存在或重新出现；未重复删除，备份须保留。");
    }

    public void RestoreNew(BoundCertificateBackup expected)
    {
        BoundCertificateBackup backup = BoundCertificateRepair.ValidateBackup(expected);
        BoundCertificateTarget target = ValidateIdentity(backup.Target, requireProperties: true);
        // Build the entire allowed public state outside every persisted store. Never
        // temporarily add a bare Root certificate and subsequently patch its EKUs.
        using SafeCertificateContextHandle prepared = CreatePublicContext(backup);
        BoundCertificateRepair.RequireSameState(backup, Describe(prepared, target));
        using SafeCertificateStoreHandle store = Open(target, writable: true);
        using StoreChangeWatch watch = new(store);
        using NativeSnapshot? occupied = FindUnique(store, target);
        if (occupied is not null)
            throw Failure(BoundCertificateProbeStatus.Changed, "原物理存储已有该 DER，拒绝覆盖、继承或合并现有属性。");
        ValidateIdentity(target, requireProperties: true);
        watch.RequireUnchanged();
        bool added = CertAddCertificateContextToStore(store, prepared, AddNew, out IntPtr addedContext);
        int error = Marshal.GetLastWin32Error();
        if (addedContext != IntPtr.Zero) CertFreeCertificateContext(addedContext);
        if (!added)
            throw Failure(error == unchecked((int)0x80092005) ? BoundCertificateProbeStatus.Changed : BoundCertificateProbeStatus.Unknown,
                $"证书 ADD_NEW 恢复未获确认（0x{error:X8}）；不替换现有证书、不补写属性，备份须保留并核对当前状态。");
        IReadOnlyList<BoundCertificateBackup> restored = ReadMatching(target);
        if (restored.Count != 1)
            throw Failure(BoundCertificateProbeStatus.Changed, "恢复后的物理证书数量与预期不符；未进一步修改，备份须保留。");
        BoundCertificateRepair.RequireSameState(backup, restored[0]);
    }

    internal static uint FlagsFor(BoundCertificateTarget target, bool writable) => OpenExisting | EnumArchived |
        (writable ? 0 : ReadOnly) | (target.StoreLocation == "CurrentUser" ? CurrentUser : LocalMachine) |
        (target.StoreLocation == "CurrentUser" && target.StoreName == "Root" ? UnprotectedRoot : 0);

    private static BoundCertificateTarget ValidateIdentity(BoundCertificateTarget target, bool requireProperties)
    {
        BoundCertificateTarget identity = BoundCertificateRepair.ValidateTarget(target, requireProperties);
        using WindowsIdentity current = WindowsIdentity.GetCurrent();
        if (!string.Equals(current.User?.Value, identity.TargetUserSid, StringComparison.Ordinal))
            throw Failure(BoundCertificateProbeStatus.Changed, "证书操作的有效用户 SID 已变化，未打开其他账户的证书存储。");
        return identity;
    }

    private static SafeCertificateStoreHandle Open(BoundCertificateTarget target, bool writable)
    {
        // Provider 13 is SYSTEM_REGISTRY_W: never SYSTEM_W's inherited collection.
        // No remote name, relocate flag, CREATE_NEW, key-update or backup privilege flag.
        SafeCertificateStoreHandle store = CertOpenStore(new IntPtr(13), 0, IntPtr.Zero, FlagsFor(target, writable), target.StoreName);
        if (!store.IsInvalid) return store;
        int error = Marshal.GetLastWin32Error(); store.Dispose();
        throw Failure(BoundCertificateProbeStatus.Unknown, $"既有物理证书存储未打开（0x{error:X8}）；未创建存储或改用其他来源。");
    }

    private static NativeSnapshot? FindUnique(SafeCertificateStoreHandle store, BoundCertificateTarget target)
    {
        IntPtr cursor = IntPtr.Zero;
        SafeCertificateContextHandle? match = null;
        Stopwatch elapsed = Stopwatch.StartNew();
        int count = 0; long bytes = 0;
        try
        {
            while (true)
            {
                RequireTime(elapsed);
                IntPtr previous = cursor; cursor = IntPtr.Zero;
                cursor = CertEnumCertificatesInStore(store, previous);
                if (cursor == IntPtr.Zero)
                {
                    int error = Marshal.GetLastWin32Error();
                    if (error != unchecked((int)0x80092004)) throw NativeFailure("物理证书枚举未完整结束", error);
                    break;
                }
                if (++count > MaximumStoreCertificates)
                    throw Failure(BoundCertificateProbeStatus.Unsupported, "物理存储枚举超过 4096 个上下文，未建立唯一目标身份。");
                byte[] der = ReadDer(cursor, MaximumStoreDerBytes - bytes);
                bytes += der.Length;
                if (!Convert.ToHexString(SHA256.HashData(der)).Equals(target.DerSha256, StringComparison.Ordinal)) continue;
                if (match is not null)
                    throw Failure(BoundCertificateProbeStatus.Changed, "同一物理存储含多个相同 DER 上下文，拒绝任意选择或批量删除。");
                IntPtr duplicate = CertDuplicateCertificateContext(cursor);
                if (duplicate == IntPtr.Zero) throw NativeFailure("无法保留精确证书上下文引用");
                match = new(duplicate);
            }
            RequireTime(elapsed);
            if (match is null) return null;
            BoundCertificateBackup backup = Describe(match, target);
            RequireTime(elapsed);
            NativeSnapshot result = new(match, backup); match = null;
            return result;
        }
        finally
        {
            if (cursor != IntPtr.Zero) CertFreeCertificateContext(cursor);
            match?.Dispose();
        }
    }

    private static BoundCertificateBackup Describe(SafeCertificateContextHandle context, BoundCertificateTarget target)
    {
        uint[] before = EnumeratePropertyIds(context);
        List<BoundCertificateProperty> properties = BoundCertificateRepair.ReadPublicProperties(before,
            (id, remaining) => ReadProperty(context, id, remaining));
        uint[] after = EnumeratePropertyIds(context);
        if (!before.Order().SequenceEqual(after.Order()))
            throw Failure(BoundCertificateProbeStatus.Changed, "证书属性集合在读取期间变化，未形成完整备份。");
        return BoundCertificateRepair.CreateBackup(target, ReadDer(context.DangerousGetHandle()), properties);
    }

    private static uint[] EnumeratePropertyIds(SafeCertificateContextHandle context)
    {
        List<uint> ids = [];
        uint previous = 0;
        while (true)
        {
            uint id = CertEnumCertificateContextProperties(context, previous);
            if (id == 0) break;
            if (ids.Contains(id) || ids.Count >= BoundCertificateRepair.MaximumProperties)
                throw Failure(BoundCertificateProbeStatus.Unsupported, "证书属性枚举重复或超过上限。");
            ids.Add(id); previous = id;
        }
        BoundCertificateRepair.ValidatePropertyIds(ids);
        return ids.ToArray();
    }

    private static byte[] ReadProperty(SafeCertificateContextHandle context, uint id, int remaining)
    {
        uint size = 0;
        if (!CertGetCertificateContextProperty(context, id, null, ref size))
            throw NativeFailure("证书公开属性长度无法读取");
        if (size > remaining)
            throw Failure(BoundCertificateProbeStatus.Unsupported, "证书公开属性总量超过 256 KiB，未读取超限属性值。");
        if (size == 0) return [];
        byte[] bytes = new byte[checked((int)size)];
        uint actual = size;
        if (!CertGetCertificateContextProperty(context, id, bytes, ref actual) || actual != size)
            throw Failure(BoundCertificateProbeStatus.Changed, "证书公开属性长度或内容在读取时发生变化。");
        return bytes;
    }

    private static byte[] ReadDer(IntPtr context, long remainingBytes = BoundCertificateRepair.MaximumCertificateBytes)
    {
        NativeCertificateContext native = Marshal.PtrToStructure<NativeCertificateContext>(context);
        if (native.Encoded == IntPtr.Zero || native.EncodedBytes is 0 or > BoundCertificateRepair.MaximumCertificateBytes)
            throw Failure(BoundCertificateProbeStatus.Unsupported, "证书公开 DER 为空或超过 128 KiB，未复制其内容。");
        if (native.EncodedBytes > remainingBytes)
            throw Failure(BoundCertificateProbeStatus.Unsupported, "物理存储公开 DER 将超过 32 MiB 总读取预算，未复制超限上下文或建立唯一目标身份。");
        byte[] der = new byte[checked((int)native.EncodedBytes)];
        Marshal.Copy(native.Encoded, der, 0, der.Length);
        return der;
    }

    private static SafeCertificateContextHandle CreatePublicContext(BoundCertificateBackup backup)
    {
        byte[] der = Convert.FromBase64String(backup.DerBase64);
        IntPtr raw = CertCreateCertificateContext(1, der, checked((uint)der.Length));
        if (raw == IntPtr.Zero) throw NativeFailure("备份公开 DER 不能创建独立内存证书上下文");
        SafeCertificateContextHandle context = new(raw);
        try
        {
            foreach (BoundCertificateProperty property in backup.Properties)
            {
                byte[] value = Convert.FromBase64String(property.ValueBase64);
                IntPtr valuePointer = value.Length == 0 ? IntPtr.Zero : Marshal.AllocHGlobal(value.Length);
                IntPtr blobPointer = IntPtr.Zero;
                try
                {
                    if (value.Length > 0) Marshal.Copy(value, 0, valuePointer, value.Length);
                    // The SDK's setter ABI uses CRYPT_DATA_BLOB for every allowed ID,
                    // including DATE_STAMP (27), whose blob contains an 8-byte FILETIME.
                    // The getter returns those eight bytes directly. Archived uses an
                    // empty but non-null BLOB so this never requests property deletion.
                    blobPointer = Marshal.AllocHGlobal(Marshal.SizeOf<NativeBlob>());
                    Marshal.StructureToPtr(new NativeBlob { Bytes = checked((uint)value.Length), Data = valuePointer }, blobPointer, false);
                    if (!CertSetCertificateContextProperty(context, property.Id, 0, blobPointer))
                        throw NativeFailure("无法在独立内存上下文完整恢复公开属性");
                }
                finally
                {
                    if (blobPointer != IntPtr.Zero) Marshal.FreeHGlobal(blobPointer);
                    if (valuePointer != IntPtr.Zero) Marshal.FreeHGlobal(valuePointer);
                }
            }
            return context;
        }
        catch { context.Dispose(); throw; }
    }

    private static void RequireTime(Stopwatch elapsed)
    {
        if (elapsed.Elapsed > MaximumReadDuration)
            throw Failure(BoundCertificateProbeStatus.Unknown, "精确物理证书枚举超过 10 秒，未沿用不完整状态。");
    }

    private sealed class NativeSnapshot(SafeCertificateContextHandle context, BoundCertificateBackup backup) : IDisposable
    {
        public SafeCertificateContextHandle Context { get; } = context;
        public BoundCertificateBackup Backup { get; } = backup;
        public void Dispose() => Context.Dispose();
    }

    private sealed class StoreChangeWatch : IDisposable
    {
        private readonly EventWaitHandle _change = new(false, EventResetMode.AutoReset);
        public StoreChangeWatch(SafeCertificateStoreHandle store)
        {
            IntPtr signal = _change.SafeWaitHandle.DangerousGetHandle();
            try
            {
                if (!CertControlStore(store, 0, 2, ref signal) || !CertControlStore(store, 0, 1, ref signal))
                    throw NativeFailure("无法监控并同步物理证书存储变化，拒绝使用缓存状态");
            }
            catch { _change.Dispose(); throw; }
        }
        public void RequireUnchanged()
        {
            if (_change.WaitOne(0)) throw Failure(BoundCertificateProbeStatus.Changed, "物理证书存储在核对期间出现变化；未开始删除或恢复。");
        }
        public void Dispose() => _change.Dispose();
    }

    private sealed class SafeCertificateStoreHandle : SafeHandleZeroOrMinusOneIsInvalid
    {
        public SafeCertificateStoreHandle() : base(true) { }
        protected override bool ReleaseHandle() => CertCloseStore(handle, 0);
    }
    private sealed class SafeCertificateContextHandle : SafeHandleZeroOrMinusOneIsInvalid
    {
        public SafeCertificateContextHandle(IntPtr value) : base(true) => SetHandle(value);
        public IntPtr Detach() { IntPtr value = handle; SetHandleAsInvalid(); return value; }
        protected override bool ReleaseHandle() => CertFreeCertificateContext(handle);
    }
    [StructLayout(LayoutKind.Sequential)]
    private struct NativeCertificateContext
    { public uint Encoding; public IntPtr Encoded; public uint EncodedBytes; public IntPtr CertificateInfo; public IntPtr Store; }
    [StructLayout(LayoutKind.Sequential)] private struct NativeBlob { public uint Bytes; public IntPtr Data; }

    private static BoundCertificateRepairException Failure(BoundCertificateProbeStatus status, string message) => BoundCertificateRepair.Failure(status, message);
    private static BoundCertificateRepairException NativeFailure(string message, int? error = null) =>
        Failure(BoundCertificateProbeStatus.Unknown, $"{message}（Windows 0x{(error ?? Marshal.GetLastWin32Error()):X8}）。");

    [DllImport("crypt32.dll", CharSet = CharSet.Unicode, ExactSpelling = true, SetLastError = true)]
    private static extern SafeCertificateStoreHandle CertOpenStore(IntPtr provider, uint encoding, IntPtr cryptProvider, uint flags, string storeName);
    [DllImport("crypt32.dll", SetLastError = true)] private static extern IntPtr CertEnumCertificatesInStore(SafeCertificateStoreHandle store, IntPtr previous);
    [DllImport("crypt32.dll", SetLastError = true)] private static extern IntPtr CertDuplicateCertificateContext(IntPtr context);
    [DllImport("crypt32.dll", SetLastError = true)] private static extern uint CertEnumCertificateContextProperties(SafeCertificateContextHandle context, uint previous);
    [DllImport("crypt32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CertGetCertificateContextProperty(SafeCertificateContextHandle context, uint id, [Out] byte[]? bytes, ref uint size);
    [DllImport("crypt32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CertSetCertificateContextProperty(SafeCertificateContextHandle context, uint id, uint flags, IntPtr data);
    [DllImport("crypt32.dll", SetLastError = true)] private static extern IntPtr CertCreateCertificateContext(uint encoding, byte[] der, uint size);
    [DllImport("crypt32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CertAddCertificateContextToStore(SafeCertificateStoreHandle store, SafeCertificateContextHandle context, uint disposition, out IntPtr added);
    [DllImport("crypt32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CertDeleteCertificateFromStore(IntPtr context);
    [DllImport("crypt32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CertControlStore(SafeCertificateStoreHandle store, uint flags, uint control, ref IntPtr eventHandle);
    [DllImport("crypt32.dll")][return: MarshalAs(UnmanagedType.Bool)] private static extern bool CertFreeCertificateContext(IntPtr context);
    [DllImport("crypt32.dll")][return: MarshalAs(UnmanagedType.Bool)] private static extern bool CertCloseStore(IntPtr store, uint flags);
}
