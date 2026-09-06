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

public sealed record SignatureResult(SignatureStatus Status, string Detail);

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
                return new(SignatureStatus.Error, "离线签名检查未开始：文件路径或只读身份句柄不可用。");
            fileHandle?.DangerousAddRef(ref handleReferenced);
            if (fileHandle is not null)
            {
                // The Authenticode SIP performs synchronous reads. Supplying the scanner's
                // OVERLAPPED handle can yield TRUST_E_BAD_DIGEST for unchanged signed files.
                // ReOpenFile changes I/O flags on the same locked object without reopening
                // its pathname or altering the caller's stream position/sharing protection.
                signatureHandle = ReOpenFile(fileHandle, 0x80000000, 1, 0x00200000 | 0x08000000);
                if (signatureHandle.IsInvalid)
                    throw new Win32Exception(Marshal.GetLastWin32Error(), "无法为离线签名建立同身份同步只读句柄。");
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
            return new(SignatureStatus.Error, "离线签名检查未完成：" + ex.Message + "；不能据此判定篡改或恶意。");
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
        0 => new(SignatureStatus.Valid, "Authenticode 在当前本地信任与缓存条件下验证通过；未联网、未进行吊销检查，不代表文件或加载组件安全。"),
        unchecked((int)0x800B0100) => new(SignatureStatus.Unsigned, "未取得可验证的 Authenticode 签名；这是离线签名观察，不代表恶意。"),
        unchecked((int)0x80096010) => new(SignatureStatus.HashMismatch, "Authenticode 文件摘要与签名不匹配；属于完整性异常，无法仅凭此结果确定修改原因或恶意性。"),
        unchecked((int)0x800B0109) or unchecked((int)0x800B0111) or unchecked((int)0x800B0004) =>
            new(SignatureStatus.Untrusted, "签名链或签名者不受当前本地策略信任；未联网、未进行吊销检查，不能据此认定文件被修改。"),
        unchecked((int)0x800B010A) or unchecked((int)0x80092013) or unchecked((int)0x800B010E) =>
            new(SignatureStatus.Unavailable, "离线缓存不足以完成本次信任检查；未联网补取证书或吊销信息。"),
        _ => new(SignatureStatus.Error, $"离线 Authenticode 未通过或未完成：0x{result:X8}。本地缓存、证书信任、策略或文件格式均可能影响结果；未联网、未进行吊销检查，不能据此判定篡改或恶意。")
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
                0 => new SignatureResult(SignatureStatus.Valid, "Authenticode 签名有效。"),
                unchecked((int)0x800B0100) => new SignatureResult(SignatureStatus.Unsigned, "文件没有可验证的 Authenticode 签名。"),
                _ => new SignatureResult(SignatureStatus.Invalid, $"签名校验失败：0x{result:X8}")
            };
        }
        catch (Exception ex)
        {
            return new SignatureResult(SignatureStatus.Error, ex.Message);
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
