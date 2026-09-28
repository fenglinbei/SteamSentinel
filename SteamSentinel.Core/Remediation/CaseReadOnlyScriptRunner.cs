using SteamSentinel.Core.Reporting;
using System.Diagnostics;
using System.Text;

namespace SteamSentinel.Core.Remediation;

/// <summary>Only receives scripts constructed by WindowsRemediationStateProbe, never saved case commands.</summary>
public static class CaseReadOnlyScriptRunner
{
    public static async Task<string?> RunAsync(string fixedScript, CancellationToken token)
    {
        if (fixedScript.Length > 64 * 1024) return null;
        string system = Environment.GetFolderPath(Environment.SpecialFolder.System);
        string psHome = Path.Combine(system, "WindowsPowerShell", "v1.0");
        ProcessStartInfo info = new(Path.Combine(psHome, "powershell.exe"))
        {
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            WorkingDirectory = system
        };
        info.Environment.Clear();
        info.Environment["SystemRoot"] = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        info.Environment["WINDIR"] = info.Environment["SystemRoot"];
        info.Environment["PATH"] = system;
        info.Environment["PSModulePath"] = Path.Combine(psHome, "Modules");
        info.Environment["TEMP"] = Path.GetTempPath(); info.Environment["TMP"] = Path.GetTempPath();
        foreach (string argument in new[] { "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "RemoteSigned", "-EncodedCommand",
            Convert.ToBase64String(Encoding.Unicode.GetBytes("$ProgressPreference='SilentlyContinue';$ErrorActionPreference='Stop';" + fixedScript)) }) info.ArgumentList.Add(argument);
        using CancellationTokenSource timeout = CancellationTokenSource.CreateLinkedTokenSource(token);
        timeout.CancelAfter(TimeSpan.FromSeconds(4));
        using Process process = new() { StartInfo = info };
        process.Start();
        async Task<string> ReadBoundedAsync(StreamReader reader)
        {
            char[] buffer = new char[1024]; StringBuilder output = new();
            while (true)
            {
                int count = await reader.ReadAsync(buffer.AsMemory(), timeout.Token).ConfigureAwait(false);
                if (count == 0) break;
                if (output.Length + count > 16 * 1024) throw MessageExceptions.Create(MessageText.Create("Backend.Core.CaseReadOnlyScriptRunner.RunAsync.01"), sourceText => new InvalidDataException(sourceText));
                output.Append(buffer, 0, count);
            }
            return output.ToString();
        }
        Task<string> output = ReadBoundedAsync(process.StandardOutput), error = ReadBoundedAsync(process.StandardError);
        try
        {
            Task exit = process.WaitForExitAsync(timeout.Token);
            await Task.WhenAll(output, error, exit).WaitAsync(timeout.Token).ConfigureAwait(false);
            return process.ExitCode == 0 ? (await output.ConfigureAwait(false)).Trim() : null;
        }
        catch (Exception ex) when (ex is OperationCanceledException or IOException or InvalidDataException or InvalidOperationException)
        {
            timeout.Cancel();
            try { if (!process.HasExited) process.Kill(entireProcessTree: true); }
            catch (Exception killError) when (killError is InvalidOperationException or System.ComponentModel.Win32Exception) { }
            try { await process.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(1)).ConfigureAwait(false); }
            catch (Exception waitError) when (waitError is InvalidOperationException or TimeoutException) { }
            try { await Task.WhenAll(output, error).WaitAsync(TimeSpan.FromSeconds(1)).ConfigureAwait(false); }
            catch (Exception readError) when (readError is OperationCanceledException or IOException or InvalidDataException or TimeoutException) { }
            return null;
        }
    }
}
