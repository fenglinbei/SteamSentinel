using System.Diagnostics;
using System.Text;
using System.Text.Json;

namespace SteamSentinel.Core.Utilities;

public static class PowerShellProbe
{
    public static async Task<JsonDocument?> RunJsonAsync(
        string fixedScript,
        TimeSpan timeout,
        CancellationToken cancellationToken = default)
    {
        string encoded = Convert.ToBase64String(Encoding.Unicode.GetBytes(
            "$ProgressPreference='SilentlyContinue';$ErrorActionPreference='Stop';" + fixedScript));
        ProcessStartInfo startInfo = new()
        {
            FileName = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System),
                "WindowsPowerShell", "v1.0", "powershell.exe"),
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true
        };
        startInfo.ArgumentList.Add("-NoProfile");
        startInfo.ArgumentList.Add("-NonInteractive");
        startInfo.ArgumentList.Add("-ExecutionPolicy");
        startInfo.ArgumentList.Add("RemoteSigned");
        startInfo.ArgumentList.Add("-EncodedCommand");
        startInfo.ArgumentList.Add(encoded);

        using Process process = new() { StartInfo = startInfo };
        process.Start();
        Task<string> outputTask = process.StandardOutput.ReadToEndAsync(cancellationToken);
        Task<string> errorTask = process.StandardError.ReadToEndAsync(cancellationToken);
        using CancellationTokenSource timeoutSource = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeoutSource.CancelAfter(timeout);

        try
        {
            await process.WaitForExitAsync(timeoutSource.Token);
        }
        catch (OperationCanceledException)
        {
            try { process.Kill(entireProcessTree: true); } catch { }
            cancellationToken.ThrowIfCancellationRequested();
            return null;
        }

        string output = await outputTask;
        _ = await errorTask;
        if (process.ExitCode != 0 || string.IsNullOrWhiteSpace(output)) return null;

        try
        {
            return JsonDocument.Parse(output.Trim());
        }
        catch (JsonException)
        {
            return null;
        }
    }
}
