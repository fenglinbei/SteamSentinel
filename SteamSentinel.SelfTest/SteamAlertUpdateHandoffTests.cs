using System.Diagnostics;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using SteamSentinel.Core.Remediation;

namespace SteamSentinel.SelfTest;

internal static partial class Program
{
    private static async Task TestSteamAlertUpdateHandoffAsync(string root)
    {
        const int pid = 1234;
        string script = @"C:\Users\Test\AppData\Local\Temp\sa_update_1234.cmd";
        string target = @"C:\Users\Test\AppData\Local\SteamAlertDemo\Application Frame Host.exe";
        string staged = @"C:\Users\Test\AppData\Local\SteamAlertDemo\Application Frame Host.new.exe";
        string backup = target + ".bak";
        string fixture = HandoffFixture(pid, target, staged, backup);
        Check("Update handoff: whole reviewed template extracts exact paths", SteamAlertUpdateHandoff.TryParse(fixture, script, out var parsed) &&
            parsed.WaitProcessId == pid && parsed.TargetExe == target && parsed.StagedExe == staged && parsed.BackupExe == backup && parsed.ScriptPath == script);
        Check("Update handoff: ASCII bytes parse without shell execution", SteamAlertUpdateHandoff.TryParse(Encoding.ASCII.GetBytes(fixture), script, out _));
        Check("Update handoff: explicit UTF8 BOM is decoded without normalization", SteamAlertUpdateHandoff.TryParse(
            new UTF8Encoding(true).GetPreamble().Concat(Encoding.UTF8.GetBytes(fixture)).ToArray(), script, out _));
        Check("Update handoff: command binds exact script path", SteamAlertUpdateHandoff.TryParseCommandLine("cmd.exe /c \"" + script + "\"", out string? commandPath) && commandPath == script);
        string image = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "System32", "cmd.exe");
        Check("Update handoff: trusted system cmd image", SteamAlertUpdateHandoff.IsTrustedImagePath(image));
        Check("Update handoff: fully qualified host command", SteamAlertUpdateHandoff.TryParseCommandLine("\"" + image + "\" /c \"" + script + "\"", out _));
        foreach (string command in new[]
        {
            "cmd.exe /c \"" + script + "\" & whoami", "cmd.exe /c \"" + script + "\" | more",
            "cmd.exe /k \"" + script + "\"", "cmd.exe /d /c \"" + script + "\"",
            "cmd.exe /c " + script, "cmd.exe /c \"\"" + script + "\"\"",
            "cmd.exe /c \"%TEMP%\\sa_update_1234.cmd\"", "cmd.exe /c \"C:\\Temp\\sa_update_1234.cmd:stream\"",
            "cmd.exe /c \"C:\\Temp\\..\\sa_update_1234.cmd\"", "cmd.exe /c \"\\\\server\\share\\sa_update_1234.cmd\"",
            "C:\\Untrusted\\cmd.exe /c \"" + script + "\"", "cmd /c \"" + script + "\"",
            "powershell.exe -File \"" + script + "\"", "cmd.exe /c \"" + script + "\"\nwhoami"
        }) Check("Update handoff: rejects ambiguous command " + command, !SteamAlertUpdateHandoff.TryParseCommandLine(command, out _));

        string[] lines = fixture.Split("\r\n");
        for (int index = 0; index < lines.Length - 1; index++)
        {
            string[] changed = (string[])lines.Clone();
            changed[index] += " rem altered";
            Check("Update handoff: every line is bound, line " + index, !SteamAlertUpdateHandoff.TryParse(string.Join("\r\n", changed), script, out _));
        }
        Check("Update handoff: trailing command rejected", !SteamAlertUpdateHandoff.TryParse(fixture + "whoami\r\n", script, out _));
        Check("Update handoff: altered line endings are not silently normalized", !SteamAlertUpdateHandoff.TryParse(fixture.Replace("\r\n", "\n"), script, out _));
        Check("Update handoff: filename PID must match waited PID", !SteamAlertUpdateHandoff.TryParse(fixture, script.Replace("1234", "1235"), out _));
        Check("Update handoff: filename alone supplies no evidence", !SteamAlertUpdateHandoff.TryParse("@echo off\r\nrem benign updater\r\n", script, out _));
        Check("Update handoff: PID formatting is canonical", !SteamAlertUpdateHandoff.TryParse(fixture, script.Replace("1234", "01234"), out _));
        Check("Update handoff: staged file must stay beside target", !SteamAlertUpdateHandoff.TryParse(HandoffFixture(pid, target,
            @"D:\Elsewhere\Application Frame Host.new.exe", backup), script, out _));
        Check("Update handoff: staged basename must match the reviewed updater", !SteamAlertUpdateHandoff.TryParse(HandoffFixture(pid, target,
            staged.Replace(".new.exe", ".other.exe"), backup), script, out _));
        Check("Update handoff: backup must be exact target plus bak", !SteamAlertUpdateHandoff.TryParse(HandoffFixture(pid, target, staged,
            backup.Replace(".bak", ".old")), script, out _));
        foreach (string marker in new[] { "%TEMP%", "!TEMP!", "&x", "^x", "(x)", "..", "NUL", "x." })
        {
            string alteredTarget = target.Replace("SteamAlertDemo", marker), alteredStaged = staged.Replace("SteamAlertDemo", marker);
            Check("Update handoff: rejects path expansion or alias " + marker, !SteamAlertUpdateHandoff.TryParse(
                HandoffFixture(pid, alteredTarget, alteredStaged, alteredTarget + ".bak"), script, out _));
        }
        Check("Update handoff: script itself cannot use an alternate stream", !SteamAlertUpdateHandoff.TryParse(fixture, script + ":ads", out _));
        Check("Update handoff: oversized script rejected", !SteamAlertUpdateHandoff.TryParse(new byte[SteamAlertUpdateHandoff.MaximumScriptBytes + 1], script, out _));

        string testRoot = Path.Combine(root, "handoff-pure-fixture");
        Directory.CreateDirectory(testRoot);
        string onDisk = Path.Combine(testRoot, "sa_update_1234.cmd"), benign = Path.Combine(testRoot, "Application Frame Host.exe");
        string newFile = Path.Combine(testRoot, "Application Frame Host.new.exe");
        // Text files with EXE extensions cannot execute. The CMD fixture is never launched.
        await File.WriteAllTextAsync(benign, "inert ordinary updater target");
        await File.WriteAllTextAsync(newFile, "inert staged ordinary updater target");
        await File.WriteAllTextAsync(onDisk, HandoffFixture(pid, benign, newFile, benign + ".bak"), new UTF8Encoding(true));
        string hash = Convert.ToHexString(SHA256.HashData(await File.ReadAllBytesAsync(onDisk)));
        Check("Update handoff: exact template plus benign files cannot authorize mutation", await SteamAlertUpdateHandoff.VerifyAsync(onDisk, hash) is null);
        Check("Update handoff: mismatched script hash never authorizes mutation", await SteamAlertUpdateHandoff.VerifyAsync(onDisk, new string('A', 64)) is null);
        bool cancelled = false;
        try { await SteamAlertUpdateHandoff.VerifyAsync(onDisk, hash, new CancellationToken(true)); }
        catch (OperationCanceledException) { cancelled = true; }
        Check("Update handoff: bounded proof respects cancellation", cancelled);

        if (OperatingSystem.IsWindows())
        {
            using Process current = Process.GetCurrentProcess();
            PowerShellScriptHostSnapshot native = PowerShellScriptHost.ReadRaw(current.SafeHandle, current.Id);
            Check("Update handoff: raw native collection retains current identity", native.IsReadable);
            Check("Update handoff: raw identity equality does not broaden WinPS trust", PowerShellScriptHost.SameRawIdentity(native, native) &&
                !PowerShellScriptHost.SameIdentity(native, native) && !PowerShellScriptHost.Read(current.SafeHandle, current.Id).IsReadable);
            Check("Update handoff: enumeration names are bounded", PowerShellScriptHost.ReadAllByNames(["../cmd"]).Single().Status == ScriptHostReadStatus.Unsupported);
        }
    }

    // Independent reference fixture transcribed from the reviewed Updater.TryStart IL.
    private static string HandoffFixture(int pid, string target, string staged, string backup) => string.Join("\r\n", new[]
    {
        "@echo off", "setlocal enableextensions", ":wait", $"tasklist /FI \"PID eq {pid}\" 2>nul | find \"{pid}\" >nul",
        "if not errorlevel 1 (", "  timeout /t 1 /nobreak >nul", "  goto wait", ")",
        $"copy /Y \"{target}\" \"{backup}\" >nul", $"copy /Y \"{staged}\" \"{target}\" >nul", "if errorlevel 1 goto fail",
        $"start \"\" \"{target}\"", "if errorlevel 1 goto fail", $"del \"{staged}\" >nul", "del \"%~f0\" >nul", "exit /b 0", ":fail",
        $"copy /Y \"{backup}\" \"{target}\" >nul", $"start \"\" \"{target}\"", $"del \"{staged}\" >nul", "del \"%~f0\" >nul", "exit /b 1", ""
    });
}
