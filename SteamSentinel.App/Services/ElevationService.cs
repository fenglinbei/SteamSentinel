using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Principal;
using Microsoft.Win32.SafeHandles;
using SteamSentinel.Core.Utilities;

namespace SteamSentinel.App.Services;

internal sealed record ElevationContext(bool IsElevated, bool CanElevateSameUser)
{
    public static ElevationContext Read()
    {
        using WindowsIdentity identity = WindowsIdentity.GetCurrent();
        bool elevated = new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
        bool splitToken = GetTokenInformation(identity.AccessToken, 18, out int elevationType, sizeof(int), out _) && elevationType == 3;
        return new(elevated, elevated || splitToken);
    }

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetTokenInformation(SafeAccessTokenHandle token, int informationClass,
        out int information, int length, out int returnLength);
}

internal enum ElevationOutcome { Opened, Cancelled }

internal sealed class ElevationService
{
    internal const string WindowArgument = "--administrator-window";
    private readonly Func<InstallationSecurityStatus> _validate;
    private readonly Func<ProcessStartInfo, bool> _start;

    public ElevationService() : this(() => InstallationSecurity.Evaluate(), info =>
    {
        using Process? process = Process.Start(info);
        return process is not null;
    })
    { }

    // Test seams never accept a command, executable path, plan or credentials from the UI.
    internal ElevationService(Func<InstallationSecurityStatus> validate, Func<ProcessStartInfo, bool> start)
    {
        _validate = validate;
        _start = start;
    }

    public ElevationOutcome OpenAdministratorWindow()
    {
        InstallationSecurityStatus installation = _validate();
        if (!installation.IsProtected) throw new UnauthorizedAccessException(installation.Message);
        ProcessStartInfo info = CreateStartInfo();
        try
        {
            if (!_start(info)) throw new InvalidOperationException("Windows 没有返回新窗口进程，请重试。");
            return ElevationOutcome.Opened;
        }
        catch (Win32Exception ex) when (ex.NativeErrorCode == 1223)
        {
            return ElevationOutcome.Cancelled;
        }
    }

    internal static ProcessStartInfo CreateStartInfo()
    {
        ProcessStartInfo info = new()
        {
            FileName = Path.Combine(AppContext.BaseDirectory, "SteamSentinel.exe"),
            WorkingDirectory = AppContext.BaseDirectory,
            UseShellExecute = true,
            Verb = "runas",
            WindowStyle = ProcessWindowStyle.Normal // An interactive window explicitly requested by the user.
        };
        info.ArgumentList.Add(WindowArgument);
        return info;
    }
}
