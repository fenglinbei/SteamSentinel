using SteamSentinel.Core.Reporting;
using System.ComponentModel;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace SteamSentinel.Core.Inspection;

public enum SignatureStatus
{
    Valid,
    Unsigned,
    Invalid,
    Error,
    HashMismatch,
    Untrusted,
    Unavailable
}
[method: System.Text.Json.Serialization.JsonConstructor]
public sealed record SignatureResult(SignatureStatus Status, string Detail)
{
    [System.Text.Json.Serialization.JsonIgnore(Condition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull)]
    public SteamSentinel.Core.Models.DisplayMessage? DetailMessage { get => SteamSentinel.Core.Reporting.MessageText.BoundDescriptor(field, Detail); init => field = value; }

    [System.Text.Json.Serialization.JsonIgnore]
    public SteamSentinel.Core.Reporting.MessageText DetailText
    {
        get => new(Detail ?? string.Empty, DetailMessage);
        init
        {
            Detail = value.OriginalText;
            DetailMessage = value.Message;
        }
    }

    public SignatureResult(SignatureStatus Status, SteamSentinel.Core.Reporting.MessageText Detail) : this(Status, Detail.OriginalText)
    {
        DetailMessage = Detail.Message;
    }
}

public static class AuthenticodeVerifier
{
    private static readonly Guid GenericVerifyV2 = new("00AAC56B-CD44-11D0-8CC2-00C04FC295EE");
    // WINTRUST_DATA: CACHE_ONLY is required to prevent code-signature network retrieval.
    // https://learn.microsoft.com/windows/win32/api/wintrust/ns-wintrust-wintrust_data
    internal const uint OfflineProviderFlags = 0x00000010 | 0x00001000;

    /// <summary>
    /// Authenticode using local trust/cache only. The optional read handle binds the
    /// verification to the caller's locked file identity; it remains owned by the caller.
    /// </summary>
    public static SignatureResult VerifyOffline(string filePath, SafeFileHandle? fileHandle = null)
    {
        WinTrustFileInfo? fileInfo = null;
        SafeFileHandle? signatureHandle = null;
        IntPtr pointer = IntPtr.Zero;
        WinTrustData data = default;
        bool handleReferenced = false, verificationRequested = false, structureWritten = false;
        try
        {
            if (!Path.IsPathFullyQualified(filePath) || fileHandle is { IsInvalid: true } or { IsClosed: true })
                return new(SignatureStatus.Error, MessageText.Create("Backend.Core.AuthenticodeVerifier.VerifyOffline.01"));
            fileHandle?.DangerousAddRef(ref handleReferenced);
            if (fileHandle is not null)
            {
                // The Authenticode SIP performs synchronous reads. Supplying the scanner's
                // OVERLAPPED handle can yield TRUST_E_BAD_DIGEST for unchanged signed files.
                // ReOpenFile changes I/O flags on the same locked object without reopening
                // its pathname or altering the caller's stream position/sharing protection.
                signatureHandle = ReOpenFile(fileHandle, 0x80000000, 1, 0x00200000 | 0x08000000);
                if (signatureHandle.IsInvalid)
                    throw MessageExceptions.Win32(Marshal.GetLastWin32Error(), MessageText.Create("Backend.Core.AuthenticodeVerifier.VerifyOffline.02"));
            }
            fileInfo = new(filePath) { FileHandle = signatureHandle?.DangerousGetHandle() ?? IntPtr.Zero };
            pointer = Marshal.AllocHGlobal(Marshal.SizeOf<WinTrustFileInfo>());
            Marshal.StructureToPtr(fileInfo, pointer, false);
            structureWritten = true;
            data = new(pointer) { ProviderFlags = OfflineProviderFlags, StateAction = 1 };
            verificationRequested = true;
            int result = WinVerifyTrust(new IntPtr(-1), GenericVerifyV2, ref data);
            return InterpretOfflineResult(result);
        }
        catch (Exception ex)
        {
            return new(SignatureStatus.Error, MessageText.Create("Backend.Core.AuthenticodeVerifier.VerifyOffline.03") + MessageExceptions.Describe(ex) + MessageText.Create("Backend.Core.AuthenticodeVerifier.VerifyOffline.04"));
        }
        finally
        {
            if (verificationRequested)
            {
                data.StateAction = 2; // Every WTD_STATEACTION_VERIFY is paired with CLOSE.
                try { _ = WinVerifyTrust(new IntPtr(-1), GenericVerifyV2, ref data); }
                catch (Exception) { /* No trust assertion is inferred from cleanup. */ }
            }
            if (pointer != IntPtr.Zero)
            {
                if (structureWritten) Marshal.DestroyStructure<WinTrustFileInfo>(pointer);
                Marshal.FreeHGlobal(pointer);
            }
            fileInfo?.ReleasePathMemory();
            signatureHandle?.Dispose();
            if (handleReferenced) fileHandle!.DangerousRelease();
        }
    }

    internal static SignatureResult InterpretOfflineResult(int result) => result switch
    {
        0 => new(SignatureStatus.Valid, MessageText.Create("Backend.Core.AuthenticodeVerifier.InterpretOfflineResult.01")),
        unchecked((int)0x800B0100) => new(SignatureStatus.Unsigned, MessageText.Create("Backend.Core.AuthenticodeVerifier.InterpretOfflineResult.02")),
        unchecked((int)0x80096010) => new(SignatureStatus.HashMismatch, MessageText.Create("Backend.Core.AuthenticodeVerifier.InterpretOfflineResult.03")),
        unchecked((int)0x800B0109) or unchecked((int)0x800B0111) or unchecked((int)0x800B0004) =>
            new(SignatureStatus.Untrusted, MessageText.Create("Backend.Core.AuthenticodeVerifier.InterpretOfflineResult.04")),
        unchecked((int)0x800B010A) or unchecked((int)0x80092013) or unchecked((int)0x800B010E) =>
            new(SignatureStatus.Unavailable, MessageText.Create("Backend.Core.AuthenticodeVerifier.InterpretOfflineResult.05")),
        _ => new(SignatureStatus.Error, MessageText.Create("Backend.Core.AuthenticodeVerifier.InterpretOfflineResult.06", (System.FormattableString.Invariant($"{result:X8}"))))
    };

    public static SignatureResult Verify(string filePath)
    {
        WinTrustFileInfo fileInfo = new(filePath);
        IntPtr fileInfoPointer = IntPtr.Zero;
        try
        {
            fileInfoPointer = Marshal.AllocHGlobal(Marshal.SizeOf<WinTrustFileInfo>());
            Marshal.StructureToPtr(fileInfo, fileInfoPointer, false);
            WinTrustData data = new(fileInfoPointer);
            int result = WinVerifyTrust(IntPtr.Zero, GenericVerifyV2, ref data);
            return result switch
            {
                0 => new SignatureResult(SignatureStatus.Valid, MessageText.Create("Backend.Core.AuthenticodeVerifier.Verify.01")),
                unchecked((int)0x800B0100) => new SignatureResult(SignatureStatus.Unsigned, MessageText.Create("Backend.Core.AuthenticodeVerifier.Verify.02")),
                _ => new SignatureResult(SignatureStatus.Invalid, MessageText.Create("Backend.Core.AuthenticodeVerifier.Verify.03", (System.FormattableString.Invariant($"{result:X8}"))))
            };
        }
        catch (Exception ex)
        {
            return new SignatureResult(SignatureStatus.Error, MessageExceptions.Describe(ex));
        }
        finally
        {
            if (fileInfoPointer != IntPtr.Zero)
            {
                Marshal.DestroyStructure<WinTrustFileInfo>(fileInfoPointer);
                Marshal.FreeHGlobal(fileInfoPointer);
            }
        }
    }

    [DllImport("wintrust.dll", ExactSpelling = true, SetLastError = true)]
    private static extern int WinVerifyTrust(IntPtr hwnd, [MarshalAs(UnmanagedType.LPStruct)] Guid actionId, ref WinTrustData data);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern SafeFileHandle ReOpenFile(SafeFileHandle original, uint access, uint share, uint flags);

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private sealed class WinTrustFileInfo
    {
        public int StructSize = Marshal.SizeOf<WinTrustFileInfo>();
        public IntPtr FilePath;
        public IntPtr FileHandle = IntPtr.Zero;
        public IntPtr KnownSubject = IntPtr.Zero;

        public WinTrustFileInfo(string filePath)
        {
            FilePath = Marshal.StringToCoTaskMemUni(filePath);
        }

        ~WinTrustFileInfo()
        {
            ReleasePathMemory();
        }

        public void ReleasePathMemory()
        {
            if (FilePath != IntPtr.Zero)
            {
                Marshal.FreeCoTaskMem(FilePath);
                FilePath = IntPtr.Zero;
            }
        }
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct WinTrustData
    {
        public int StructSize;
        public IntPtr PolicyCallbackData;
        public IntPtr SIPClientData;
        public uint UIChoice;
        public uint RevocationChecks;
        public uint UnionChoice;
        public IntPtr FileInfoPointer;
        public uint StateAction;
        public IntPtr StateData;
        public string? URLReference;
        public uint ProviderFlags;
        public uint UIContext;

        public WinTrustData(IntPtr fileInfoPointer)
        {
            StructSize = Marshal.SizeOf<WinTrustData>();
            PolicyCallbackData = IntPtr.Zero;
            SIPClientData = IntPtr.Zero;
            UIChoice = 2;
            RevocationChecks = 0;
            UnionChoice = 1;
            FileInfoPointer = fileInfoPointer;
            StateAction = 0;
            StateData = IntPtr.Zero;
            URLReference = null;
            ProviderFlags = 0x00000010 | 0x00000100;
            UIContext = 0;
        }
    }
}
