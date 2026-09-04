using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using Microsoft.Win32.SafeHandles;

namespace SteamSentinel.App.Native;

internal static class RestrictedTokenSecurity
{
    internal static void ConfigureDefaultObjects(SafeAccessTokenHandle restrictedToken)
    {
        // Only the newly created restricted token is changed. Its user, privileges,
        // restricting SIDs and Low mandatory label are not changed here.
        GetTokenInformation(restrictedToken, 1, IntPtr.Zero, 0, out uint size);
        if (size == 0 || size > 65536) throw new Win32Exception(Marshal.GetLastWin32Error(), "无法读取扫描令牌用户。");
        IntPtr userInfo = Marshal.AllocHGlobal((int)size);
        try
        {
            if (!GetTokenInformation(restrictedToken, 1, userInfo, size, out _))
                throw new Win32Exception(Marshal.GetLastWin32Error(), "无法读取扫描令牌用户。");
            IntPtr userSid = Marshal.ReadIntPtr(userInfo);
            SecurityIdentifier user = new(userSid);
            byte[] acl = BuildDefaultDacl(user);
            IntPtr buffer = Marshal.AllocHGlobal(IntPtr.Size + acl.Length);
            try
            {
                // TOKEN_DEFAULT_DACL is a pointer to an ACL, not a security descriptor.
                Marshal.WriteIntPtr(buffer, buffer + IntPtr.Size);
                Marshal.Copy(acl, 0, buffer + IntPtr.Size, acl.Length);
                if (!SetTokenInformation(restrictedToken, 6, buffer, (uint)IntPtr.Size))
                    throw new Win32Exception(Marshal.GetLastWin32Error(), "无法配置受限扫描令牌的对象权限。");
                Marshal.WriteIntPtr(buffer, userSid); // TOKEN_OWNER, always a SID in this token.
                if (!SetTokenInformation(restrictedToken, 4, buffer, (uint)IntPtr.Size))
                    throw new Win32Exception(Marshal.GetLastWin32Error(), "无法配置受限扫描令牌的对象所有者。");
            }
            finally { Marshal.FreeHGlobal(buffer); }
        }
        finally { Marshal.FreeHGlobal(userInfo); }
    }

    internal static byte[] BuildDefaultDacl(SecurityIdentifier user)
    {
        // Do not preserve administrator-only defaults or add Everyone/Users access.
        RawAcl acl = new(2, 2);
        acl.InsertAce(0, new CommonAce(AceFlags.None, AceQualifier.AccessAllowed, 0x10000000, user, false, null));
        SecurityIdentifier system = new(WellKnownSidType.LocalSystemSid, null);
        if (!user.Equals(system))
            acl.InsertAce(1, new CommonAce(AceFlags.None, AceQualifier.AccessAllowed, 0x10000000, system, false, null));
        byte[] bytes = new byte[acl.BinaryLength];
        acl.GetBinaryForm(bytes, 0);
        return bytes;
    }

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetTokenInformation(SafeAccessTokenHandle token, int type, IntPtr buffer, uint length, out uint returned);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetTokenInformation(SafeAccessTokenHandle token, int type, IntPtr buffer, uint length);
}
