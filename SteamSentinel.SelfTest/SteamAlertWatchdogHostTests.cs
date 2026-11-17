using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
using SteamSentinel.Core.Remediation;

namespace SteamSentinel.SelfTest;

internal static partial class Program
{
    private static async Task TestSteamAlertWatchdogHostAsync(string root)
    {
        string script = @"C:\ProgramData\SteamAlertUpdater\sa_watch.ps1";
        string simple = $"powershell.exe -NoProfile -ExecutionPolicy Bypass -File \"{script}\"";
        string hidden = $"powershell.exe -NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File \"{script}\"";
        Check("Watchdog host: hidden command is parsed without evaluation", PowerShellScriptHost.TryParse(hidden, out var parsed) &&
            parsed.ScriptPath == script && parsed.CommandLine == hidden && parsed.InstallDir is null && parsed.TaskDir is null);
        Check("Watchdog host: supported file alias and literal directories", PowerShellScriptHost.TryParse(
            hidden.Replace("-File", "-f") + " -InstallDir \"D:\\User Files\\SteamAlertDemo\" -TaskDir C:\\ProgramData\\SteamAlertUpdater -EveryMin 15", out parsed) &&
            parsed.InstallDir == @"D:\User Files\SteamAlertDemo" && parsed.TaskDir == @"C:\ProgramData\SteamAlertUpdater");
        Check("Watchdog host: original direct invocation remains accepted", BoundContentEvidence.IsDirectInvocation(simple, script));
        Check("Watchdog host: hidden direct invocation is accepted", BoundContentEvidence.IsDirectInvocation(hidden, script));
        Check("Watchdog host: malformed window style cannot swallow file argument", !BoundContentEvidence.IsDirectInvocation(
            hidden.Replace("Hidden", "-File"), script));
        Check("Watchdog host: ordinary script syntax is not a malicious identity", PowerShellScriptHost.TryParse(
            simple.Replace("sa_watch.ps1", "backup.ps1"), out _) && !SteamAlertWatchdog.IsScriptHash(new string('A', 64)));
        foreach (string invalid in new[]
        {
            "powershell.exe -Command Write-Host harmless", "powershell.exe -EncodedCommand AA==",
            "pwsh.exe -File \"" + script + "\"", "C:\\Other\\powershell.exe -File \"" + script + "\"",
            hidden + " ; whoami", hidden + " & whoami", hidden + " | whoami", hidden + " `anything",
            hidden + " -InstallDir $env:LOCALAPPDATA", hidden + " -InstallDir \"$(Write-Host text)\"",
            hidden + " -InstallDir D:\\One -InstallDir D:\\Two", hidden + " -i D:\\Abbreviated",
            hidden + " -Unknown value", hidden + " -EveryMin 0", hidden + " -EveryMin -1",
            hidden + " -TaskDir \\server\\share", hidden + " -InstallDir C:\\Demo:stream",
            hidden.Replace("-WindowStyle Hidden", "-WindowStyle Invisible"), hidden.Replace("-NoProfile", "-NoProfile -NoProfile"),
            hidden.Replace("-ExecutionPolicy Bypass", "-ExecutionPolicy -File"), hidden + "\nwhoami",
            "powershell.exe -File sa_watch.ps1", "powershell.exe -File C:\\Path\\..\\sa_watch.ps1",
            "powershell.exe -File C:\\Path\\sa_watch.ps1:alternate", "powershell.exe -File \\\\?\\C:\\Path\\sa_watch.ps1",
            "powershell.exe -File \"C:\\Path\\sa_watch.ps1\"tail", "powershell.exe -File \"C:\\Path\\sa_watch.ps1",
            "powershell.exe -File C:\\Path\\sa_watch.ps1.", "powershell.exe -File C:\\Path\\sa_watch.cmd"
        }) Check("Watchdog host: rejects ambiguous command " + invalid, !PowerShellScriptHost.TryParse(invalid, out _));
        Check("Watchdog host: oversized command rejected", !PowerShellScriptHost.TryParse(simple + new string(' ', 32768), out _));
        Check("Watchdog host: watchdog hash case insensitive", SteamAlertWatchdog.IsScriptHash(SteamAlertWatchdog.WatchdogHash.ToLowerInvariant()));
        Check("Watchdog host: updater and launcher identities", SteamAlertWatchdog.RoleForHash(SteamAlertWatchdog.UpdaterHash) == SteamAlertWatchdog.UpdaterRole &&
            SteamAlertWatchdog.RoleForHash(SteamAlertWatchdog.LauncherHash) == SteamAlertWatchdog.LauncherRole);
        Check("Watchdog host: resident is family but not script", SteamAlertWatchdog.IsFamilyHash(SteamAlertWatchdog.ResidentHash) &&
            !SteamAlertWatchdog.IsScriptHash(SteamAlertWatchdog.ResidentHash));
        Check("Watchdog host: empty or malformed identities are not family", !SteamAlertWatchdog.IsFamilyHash(null) &&
            !SteamAlertWatchdog.IsFamilyHash(" " + SteamAlertWatchdog.WatchdogHash) && !SteamAlertWatchdog.IsScriptHash("sa_watch.ps1"));
        string image = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "System32", "WindowsPowerShell", "v1.0", "powershell.exe");
        Check("Watchdog host: same-name non-system interpreter rejected", !PowerShellScriptHost.IsTrustedImagePath(Path.Combine(root, "powershell.exe")));
        Check("Watchdog host: invalid PID is explicitly unreadable", !PowerShellScriptHost.Read(-1).IsReadable);
        PowerShellScriptHostSnapshot expected = new()
        {
            ProcessId = 1234,
            StartedAtUtc = DateTimeOffset.Parse("2026-11-17T00:00:00Z"),
            ImagePath = image,
            CommandLine = hidden,
            Status = ScriptHostReadStatus.Readable
        };
        Check("Watchdog host: exact snapshot identity", PowerShellScriptHost.SameIdentity(expected, expected with { }));
        Check("Watchdog host: reused PID rejected", !PowerShellScriptHost.SameIdentity(expected, expected with { StartedAtUtc = expected.StartedAtUtc!.Value.AddTicks(1) }));
        Check("Watchdog host: new PID rejected", !PowerShellScriptHost.SameIdentity(expected, expected with { ProcessId = 1235 }));
        Check("Watchdog host: changed command rejected", !PowerShellScriptHost.SameIdentity(expected, expected with { CommandLine = simple }));
        Check("Watchdog host: changed image rejected", !PowerShellScriptHost.SameIdentity(expected, expected with { ImagePath = Path.Combine(root, "powershell.exe") }));
        Check("Watchdog host: unreadable is not success", !PowerShellScriptHost.SameIdentity(expected, expected with { Status = ScriptHostReadStatus.AccessDenied }));
        Check("Watchdog host: exited is not live identity", !PowerShellScriptHost.SameIdentity(expected, expected with { Status = ScriptHostReadStatus.Exited }));

        if (!OperatingSystem.IsWindows() || !File.Exists(image)) { Skip("Watchdog host: controlled Windows native read smoke unavailable"); return; }
        // This controlled child only sleeps. It does not run any sample, persist, download, or touch Steam.
        ProcessStartInfo start = new(image) { UseShellExecute = false, CreateNoWindow = true };
        foreach (string argument in new[] { "-NoProfile", "-NonInteractive", "-Command", "Start-Sleep -Seconds 30" }) start.ArgumentList.Add(argument);
        using Process child = Process.Start(start) ?? throw new InvalidOperationException("Could not start the controlled native read fixture.");
        SafeProcessHandle pinned = child.SafeHandle;
        try
        {
            await Task.Delay(150);
            PowerShellScriptHostSnapshot native = PowerShellScriptHost.Read(pinned, child.Id);
            Check("Watchdog host: native read retains trusted image and command", native.IsReadable &&
                native.CommandLine!.Contains("Start-Sleep -Seconds 30", StringComparison.Ordinal) && PowerShellScriptHost.IsTrustedImagePath(native.ImagePath));
            Check("Watchdog host: native start time matches child", native.StartedAtUtc == new DateTimeOffset(child.StartTime.ToUniversalTime()));
            Check("Watchdog host: native stable same-handle snapshot", PowerShellScriptHost.SameIdentity(native, PowerShellScriptHost.Read(pinned, child.Id)));
            Check("Watchdog host: handle and claimed PID mismatch rejected", PowerShellScriptHost.Read(pinned, child.Id + 1).Status == ScriptHostReadStatus.IdentityChanged);
            Check("Watchdog host: normal inline PowerShell not a script target", !PowerShellScriptHost.TryParse(native.CommandLine, out _));
            Check("Watchdog host: native bounded enumeration retains controlled child", PowerShellScriptHost.ReadAll().Any(item => item.ProcessId == child.Id && item.IsReadable));
            using (SafeProcessHandle queryOnly = WatchdogOpenQueryHandle(0x1000, false, child.Id))
            {
                PowerShellScriptHostSnapshot insufficient = PowerShellScriptHost.Read(queryOnly, child.Id);
                Check("Watchdog host: missing synchronization rights cannot imply a live readable process", !insufficient.IsReadable &&
                    insufficient.Status is ScriptHostReadStatus.AccessDenied or ScriptHostReadStatus.Failed);
            }
            child.Kill();
            await child.WaitForExitAsync();
            PowerShellScriptHostSnapshot exited = PowerShellScriptHost.Read(pinned, child.Id);
            Check("Watchdog host: terminating child is exited immediately without a polling sleep", !exited.IsReadable && exited.Status == ScriptHostReadStatus.Exited);
        }
        finally
        {
            if (!child.HasExited) { child.Kill(); await child.WaitForExitAsync(); }
        }
        ProcessStartInfo exit259Start = new(image) { UseShellExecute = false, CreateNoWindow = true };
        foreach (string argument in new[] { "-NoProfile", "-NonInteractive", "-Command", "exit 259" }) exit259Start.ArgumentList.Add(argument);
        using Process exit259 = Process.Start(exit259Start) ?? throw new InvalidOperationException("Could not start the explicit-exit fixture.");
        SafeProcessHandle exit259Handle = exit259.SafeHandle;
        try
        {
            using CancellationTokenSource deadline = new(TimeSpan.FromSeconds(10));
            await exit259.WaitForExitAsync(deadline.Token);
            Check("Watchdog host: controlled fixture retains the legal STILL_ACTIVE-valued exit code", WatchdogGetExitCode(exit259Handle, out uint code) && code == 259);
            Check("Watchdog host: explicit exit 259 is not mistaken for a live process", PowerShellScriptHost.Read(exit259Handle, exit259.Id).Status == ScriptHostReadStatus.Exited);
        }
        finally
        {
            if (!exit259.HasExited) { exit259.Kill(); await exit259.WaitForExitAsync(); }
        }
    }

    [DllImport("kernel32.dll", EntryPoint = "OpenProcess", SetLastError = true)]
    private static extern SafeProcessHandle WatchdogOpenQueryHandle(uint access, [MarshalAs(UnmanagedType.Bool)] bool inheritHandle, int pid);
    [DllImport("kernel32.dll", EntryPoint = "GetExitCodeProcess", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool WatchdogGetExitCode(SafeProcessHandle handle, out uint exitCode);
}
