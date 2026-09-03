using System.Runtime.InteropServices;

namespace SteamSentinel.Core.Inspection;

public enum SignatureStatus
{
    Valid,
    Unsigned,
    Invalid,
    Error
}

public sealed record SignatureResult(SignatureStatus Status, string Detail);

public static class AuthenticodeVerifier
{
    private static readonly Guid GenericVerifyV2 = new("00AAC56B-CD44-11D0-8CC2-00C04FC295EE");

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
