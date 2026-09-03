using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Principal;
using Microsoft.Win32.SafeHandles;

namespace SteamSentinel.Core.Utilities;

public enum ProcessIntegrityLevel
{
    Unknown,
    Untrusted,
    Low,
    Medium,
    High,
    System
}

public static class ProcessIntegrity
{
    public static ProcessIntegrityLevel GetCurrent()
    {
        if (!OpenProcessToken(GetCurrentProcess(), TokenQuery, out SafeAccessTokenHandle token))
            return ProcessIntegrityLevel.Unknown;
        using (token)
        {
            GetTokenInformation(token, TokenIntegrityLevel, IntPtr.Zero, 0, out uint size);
            if (size == 0) return ProcessIntegrityLevel.Unknown;
            IntPtr buffer = Marshal.AllocHGlobal((int)size);
            try
            {
                if (!GetTokenInformation(token, TokenIntegrityLevel, buffer, size, out _))
                    throw new Win32Exception(Marshal.GetLastWin32Error());
                TokenMandatoryLabel label = Marshal.PtrToStructure<TokenMandatoryLabel>(buffer);
                SecurityIdentifier sid = new(label.Label.Sid);
                int rid = int.Parse(sid.Value.Split('-')[^1], System.Globalization.CultureInfo.InvariantCulture);
                return rid switch
                {
                    < 0x1000 => ProcessIntegrityLevel.Untrusted,
                    < 0x2000 => ProcessIntegrityLevel.Low,
                    < 0x3000 => ProcessIntegrityLevel.Medium,
                    < 0x4000 => ProcessIntegrityLevel.High,
                    _ => ProcessIntegrityLevel.System
                };
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct SidAndAttributes
    {
        public IntPtr Sid;
        public uint Attributes;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct TokenMandatoryLabel
    {
        public SidAndAttributes Label;
    }

    private const uint TokenQuery = 0x0008;
    private const int TokenIntegrityLevel = 25;

    [DllImport("kernel32.dll")]
    private static extern IntPtr GetCurrentProcess();

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool OpenProcessToken(
        IntPtr processHandle,
        uint desiredAccess,
        out SafeAccessTokenHandle tokenHandle);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetTokenInformation(
        SafeAccessTokenHandle tokenHandle,
        int tokenInformationClass,
        IntPtr tokenInformation,
        uint tokenInformationLength,
        out uint returnLength);
}
