using SteamSentinel.Core.Reporting;
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
        if (current is null) throw Failure(BoundCertificateProbeStatus.Absent, MessageText.Create("Backend.Core.WindowsBoundCertificateStore.RemoveExact.01"));
        BoundCertificateRepair.RequireSameState(backup, current.Backup);
        ValidateIdentity(target, requireProperties: true);
        watch.RequireUnchanged();
        // CertDeleteCertificateFromStore always releases the passed reference, even
        // on failure. Detach that exact owned reference before calling the API.
        IntPtr context = current.Context.Detach();
        if (!CertDeleteCertificateFromStore(context))
            throw NativeFailure(MessageText.Create("Backend.Core.WindowsBoundCertificateStore.RemoveExact.02"));
        if (ReadMatching(target).Count != 0)
            throw Failure(BoundCertificateProbeStatus.Changed, MessageText.Create("Backend.Core.WindowsBoundCertificateStore.RemoveExact.03"));
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
            throw Failure(BoundCertificateProbeStatus.Changed, MessageText.Create("Backend.Core.WindowsBoundCertificateStore.RestoreNew.01"));
        ValidateIdentity(target, requireProperties: true);
        watch.RequireUnchanged();
        bool added = CertAddCertificateContextToStore(store, prepared, AddNew, out IntPtr addedContext);
        int error = Marshal.GetLastWin32Error();
        if (addedContext != IntPtr.Zero) CertFreeCertificateContext(addedContext);
        if (!added)
            throw Failure(error == unchecked((int)0x80092005) ? BoundCertificateProbeStatus.Changed : BoundCertificateProbeStatus.Unknown,
                MessageText.Create("Backend.Core.WindowsBoundCertificateStore.RestoreNew.02", (System.FormattableString.Invariant($"{error:X8}"))));
        IReadOnlyList<BoundCertificateBackup> restored = ReadMatching(target);
        if (restored.Count != 1)
            throw Failure(BoundCertificateProbeStatus.Changed, MessageText.Create("Backend.Core.WindowsBoundCertificateStore.RestoreNew.03"));
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
            throw Failure(BoundCertificateProbeStatus.Changed, MessageText.Create("Backend.Core.WindowsBoundCertificateStore.ValidateIdentity.01"));
        return identity;
    }

    private static SafeCertificateStoreHandle Open(BoundCertificateTarget target, bool writable)
    {
        // Provider 13 is SYSTEM_REGISTRY_W: never SYSTEM_W's inherited collection.
        // No remote name, relocate flag, CREATE_NEW, key-update or backup privilege flag.
        SafeCertificateStoreHandle store = CertOpenStore(new IntPtr(13), 0, IntPtr.Zero, FlagsFor(target, writable), target.StoreName);
        if (!store.IsInvalid) return store;
        int error = Marshal.GetLastWin32Error(); store.Dispose();
        throw Failure(BoundCertificateProbeStatus.Unknown, MessageText.Create("Backend.Core.WindowsBoundCertificateStore.Open.01", (System.FormattableString.Invariant($"{error:X8}"))));
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
                    if (error != unchecked((int)0x80092004)) throw NativeFailure(MessageText.Create("Backend.Core.WindowsBoundCertificateStore.FindUnique.01"), error);
                    break;
                }
                if (++count > MaximumStoreCertificates)
                    throw Failure(BoundCertificateProbeStatus.Unsupported, MessageText.Create("Backend.Core.WindowsBoundCertificateStore.FindUnique.02"));
                byte[] der = ReadDer(cursor, MaximumStoreDerBytes - bytes);
                bytes += der.Length;
                if (!Convert.ToHexString(SHA256.HashData(der)).Equals(target.DerSha256, StringComparison.Ordinal)) continue;
                if (match is not null)
                    throw Failure(BoundCertificateProbeStatus.Changed, MessageText.Create("Backend.Core.WindowsBoundCertificateStore.FindUnique.03"));
                IntPtr duplicate = CertDuplicateCertificateContext(cursor);
                if (duplicate == IntPtr.Zero) throw NativeFailure(MessageText.Create("Backend.Core.WindowsBoundCertificateStore.FindUnique.04"));
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
            throw Failure(BoundCertificateProbeStatus.Changed, MessageText.Create("Backend.Core.WindowsBoundCertificateStore.Describe.01"));
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
                throw Failure(BoundCertificateProbeStatus.Unsupported, MessageText.Create("Backend.Core.WindowsBoundCertificateStore.EnumeratePropertyIds.01"));
            ids.Add(id); previous = id;
        }
        BoundCertificateRepair.ValidatePropertyIds(ids);
        return ids.ToArray();
    }

    private static byte[] ReadProperty(SafeCertificateContextHandle context, uint id, int remaining)
    {
        uint size = 0;
        if (!CertGetCertificateContextProperty(context, id, null, ref size))
            throw NativeFailure(MessageText.Create("Backend.Core.WindowsBoundCertificateStore.ReadProperty.01"));
        if (size > remaining)
            throw Failure(BoundCertificateProbeStatus.Unsupported, MessageText.Create("Backend.Core.WindowsBoundCertificateStore.ReadProperty.02"));
        if (size == 0) return [];
        byte[] bytes = new byte[checked((int)size)];
        uint actual = size;
        if (!CertGetCertificateContextProperty(context, id, bytes, ref actual) || actual != size)
            throw Failure(BoundCertificateProbeStatus.Changed, MessageText.Create("Backend.Core.WindowsBoundCertificateStore.ReadProperty.03"));
        return bytes;
    }

    private static byte[] ReadDer(IntPtr context, long remainingBytes = BoundCertificateRepair.MaximumCertificateBytes)
    {
        NativeCertificateContext native = Marshal.PtrToStructure<NativeCertificateContext>(context);
        if (native.Encoded == IntPtr.Zero || native.EncodedBytes is 0 or > BoundCertificateRepair.MaximumCertificateBytes)
            throw Failure(BoundCertificateProbeStatus.Unsupported, MessageText.Create("Backend.Core.WindowsBoundCertificateStore.ReadDer.01"));
        if (native.EncodedBytes > remainingBytes)
            throw Failure(BoundCertificateProbeStatus.Unsupported, MessageText.Create("Backend.Core.WindowsBoundCertificateStore.ReadDer.02"));
        byte[] der = new byte[checked((int)native.EncodedBytes)];
        Marshal.Copy(native.Encoded, der, 0, der.Length);
        return der;
    }

    private static SafeCertificateContextHandle CreatePublicContext(BoundCertificateBackup backup)
    {
        byte[] der = Convert.FromBase64String(backup.DerBase64);
        IntPtr raw = CertCreateCertificateContext(1, der, checked((uint)der.Length));
        if (raw == IntPtr.Zero) throw NativeFailure(MessageText.Create("Backend.Core.WindowsBoundCertificateStore.CreatePublicContext.01"));
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
                        throw NativeFailure(MessageText.Create("Backend.Core.WindowsBoundCertificateStore.CreatePublicContext.02"));
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
            throw Failure(BoundCertificateProbeStatus.Unknown, MessageText.Create("Backend.Core.WindowsBoundCertificateStore.RequireTime.01"));
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
                    throw NativeFailure(MessageText.Create("Backend.Core.WindowsBoundCertificateStore.Constructor.01"));
            }
            catch { _change.Dispose(); throw; }
        }
        public void RequireUnchanged()
        {
            if (_change.WaitOne(0)) throw Failure(BoundCertificateProbeStatus.Changed, MessageText.Create("Backend.Core.WindowsBoundCertificateStore.RequireUnchanged.01"));
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

    private static BoundCertificateRepairException Failure(BoundCertificateProbeStatus status, MessageText message) => BoundCertificateRepair.Failure(status, message);
    private static BoundCertificateRepairException NativeFailure(MessageText message, int? error = null) =>
        Failure(BoundCertificateProbeStatus.Unknown, MessageText.Create("Backend.Core.WindowsBoundCertificateStore.NativeFailure", message, (error ?? Marshal.GetLastWin32Error()).ToString("X8", System.Globalization.CultureInfo.InvariantCulture)));

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
