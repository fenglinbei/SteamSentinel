#requires -Version 5.1
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$PublishRoot,
    [Parameter(Mandatory = $true)][string]$ResultsPath
)

$ErrorActionPreference = 'Stop'
$PublishRoot = (Resolve-Path -LiteralPath $PublishRoot).Path
$ResultsPath = [IO.Path]::GetFullPath($ResultsPath)
if ($ResultsPath.StartsWith($PublishRoot.TrimEnd('\') + '\', [StringComparison]::OrdinalIgnoreCase)) {
    throw 'Test results and fixtures must be outside the immutable published payload.'
}
$resultDirectory = Split-Path -Parent $ResultsPath
New-Item -ItemType Directory -Path $resultDirectory -Force | Out-Null
$fixtureRoot = Join-Path $resultDirectory ('startup-fixtures-' + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $fixtureRoot | Out-Null
$tests = [Collections.Generic.List[object]]::new()
$watch = [Diagnostics.Stopwatch]::StartNew()
$isAdministrator = ([Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
$needsElevated = -not $isAdministrator

function Quote-Argument([string]$Value) {
    # CommandLineToArgvW / CRT quoting, including trailing backslashes.
    '"' + [regex]::Replace([regex]::Replace($Value, '(\\*)"', '$1$1\"'), '(\\+)$', '$1$1') + '"'
}
function Invoke-Child([string]$File, [string[]]$Arguments, [int]$TimeoutMs = 45000) {
    $start = [Diagnostics.ProcessStartInfo]::new()
    $start.FileName = $File
    $start.WorkingDirectory = Split-Path -Parent $File
    $start.Arguments = (($Arguments | ForEach-Object { Quote-Argument $_ }) -join ' ')
    $start.UseShellExecute = $false
    $start.CreateNoWindow = $true
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    $process = [Diagnostics.Process]::new()
    $process.StartInfo = $start
    try {
        if (-not $process.Start()) { throw 'Child did not start.' }
        $stdout = $process.StandardOutput.ReadToEndAsync()
        $stderr = $process.StandardError.ReadToEndAsync()
        if (-not $process.WaitForExit($TimeoutMs)) {
            $process.Kill()
            $process.WaitForExit(5000) | Out-Null
            throw 'Startup child exceeded the test timeout.'
        }
        if (-not $stdout.Wait(5000) -or -not $stderr.Wait(5000)) { throw 'Startup output pipes did not close.' }
        [pscustomobject]@{ exitCode = $process.ExitCode; stdout = $stdout.Result; stderr = $stderr.Result }
    }
    finally { $process.Dispose() }
}
function Check([string]$TestName, [scriptblock]$Body) {
    try {
        & $Body
        $tests.Add([pscustomobject]@{ name = $TestName; passed = $true; skipped = $false; error = $null })
        Write-Host "PASS $TestName"
    }
    catch {
        $tests.Add([pscustomobject]@{ name = $TestName; passed = $false; skipped = $false; error = $_.Exception.Message })
        Write-Host "FAIL $TestName : $($_.Exception.Message)"
    }
}
function Assert([bool]$Condition, [string]$Message) { if (-not $Condition) { throw $Message } }
function Write-Text([string]$Path, [string]$Text) { [IO.File]::WriteAllText($Path, $Text, [Text.UTF8Encoding]::new($false)) }
function Write-Manifest([string]$Root) {
    $lines = @(Get-ChildItem -LiteralPath $Root -File -Recurse | Where-Object Name -ne 'SHA256SUMS.txt' | Sort-Object FullName | ForEach-Object {
        '{0} *{1}' -f (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash, $_.FullName.Substring($Root.Length + 1)
    })
    [IO.File]::WriteAllLines((Join-Path $Root 'SHA256SUMS.txt'), [string[]]$lines, [Text.UTF8Encoding]::new($false))
}

try {
    foreach ($entry in @(@('SteamSentinel','app'), @('SteamSentinel.ArchiveWorker','worker'), @('SteamSentinel.Broker','broker'))) {
        foreach ($mode in @('Standard', 'Compat')) {
            $name = "$($entry[0]).$mode"
            if ($entry[1] -eq 'broker' -and -not $isAdministrator) {
                $tests.Add([pscustomobject]@{ name = "real-$name-probe"; passed = $false; skipped = $true; error = 'Requires an elevated test session; the Broker manifest remains requireAdministrator.' })
                continue
            }
            Check "real-$name-probe" {
                $nonce = [Guid]::NewGuid().ToString('N')
                $result = Invoke-Child (Join-Path $PublishRoot ($name + '.exe')) @('--startup-probe', $nonce)
                $expected = "STEAMSENTINEL_STARTUP_READY/1|$($entry[1])|$($mode.ToLowerInvariant())|$nonce"
                Assert ($result.exitCode -eq 0 -and $result.stdout.TrimEnd("`r", "`n") -ceq $expected) "Published host did not acknowledge its exact role, mode and nonce: $($result.exitCode), $($result.stdout), $($result.stderr)"
            }
        }
    }
    Check 'real-native-package-preflight' {
        $result = Invoke-Child (Join-Path $PublishRoot 'SteamSentinel.exe') @('--startup-check') 90000
        Assert ($result.exitCode -eq 0 -and $result.stdout -match '(?m)^STEAMSENTINEL_STARTUP_SELECTED/1\|(standard|compat)\r?$') "Native package preflight failed: $($result.stdout) $($result.stderr)"
    }
    if ($isAdministrator) {
        Check 'real-elevated-broker-preflight' {
            $result = Invoke-Child (Join-Path $PublishRoot 'SteamSentinel.Broker.exe') @('--startup-check') 60000
            Assert ($result.exitCode -eq 0 -and $result.stdout -match 'STEAMSENTINEL_STARTUP_SELECTED/1\|') "Broker preflight failed: $($result.stdout) $($result.stderr)"
        }
    }

    # Synthetic hosts exercise the production native launcher's failure state
    # machine, not hardware CET. They never load product DLLs or execute a plan.
    $fixtureSource = Join-Path $fixtureRoot 'Fixture.cs'
    Write-Text $fixtureSource @'
using System;
using System.IO;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using Microsoft.Win32.SafeHandles;
class Fixture {
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern bool CreateDirectoryW(string path, IntPtr security);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern SafeFileHandle CreateFileW(string path, uint access, uint share, IntPtr security, uint creation, uint flags, IntPtr template);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool WriteFile(SafeFileHandle file, byte[] bytes, uint length, out uint written, IntPtr overlapped);
    static int MakeLongMetadata(string root) {
        string directory = "long-metadata-" + new string('x', 170);
        string relative = directory + "\\metadata.txt";
        string extended = "\\\\?\\" + Path.GetFullPath(root).TrimEnd('\\');
        if (!CreateDirectoryW(extended + "\\" + directory, IntPtr.Zero))
            throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
        byte[] bytes = Encoding.UTF8.GetBytes("SteamSentinel harmless long-path metadata.\n");
        using (SafeFileHandle file = CreateFileW(extended + "\\" + relative, 0x40000000, 1, IntPtr.Zero, 1, 0x80, IntPtr.Zero)) {
            if (file.IsInvalid) throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
            uint written;
            if (!WriteFile(file, bytes, (uint)bytes.Length, out written, IntPtr.Zero) || written != bytes.Length)
                throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
        }
        Console.WriteLine("LONG_METADATA/1|" + relative);
        return 0;
    }
    static int Main(string[] args) {
        if (args.Length == 2 && args[0] == "--make-long-metadata") return MakeLongMetadata(args[1]);
        string path = Assembly.GetExecutingAssembly().Location;
        string root = Path.GetDirectoryName(path);
        string name = Path.GetFileName(path);
        string role = name.Contains("ArchiveWorker") ? "worker" : name.Contains("Broker") ? "broker" : "app";
        string mode = name.Contains(".Compat.") ? "compat" : "standard";
        string scenario = File.ReadAllText(Path.Combine(root, "fixture-case.txt"));
        if (args.Length != 2 || args[0] != "--startup-probe") {
            var lines = new string[args.Length + 1];
            lines[0] = name;
            for (int i = 0; i < args.Length; i++) lines[i + 1] = Convert.ToBase64String(Encoding.UTF8.GetBytes(args[i]));
            File.WriteAllLines(Path.Combine(root, "fixture-business.txt"), lines);
            return scenario == "exit-collision" ? 0x53530001 : 37;
        }
        string ready = "STEAMSENTINEL_STARTUP_READY/1|" + role + "|" + mode + "|" + args[1];
        bool standardApp = mode == "standard" && role == "app";
        if ((scenario == "cet" && standardApp) || (scenario == "worker-cet" && mode == "standard" && role == "worker") || (scenario == "compat-fails" && role == "app") || (scenario == "broker-fails" && role == "broker")) {
            Console.Error.WriteLine("Fatal error.\nYour Windows doesn't fully support CET. Please install all available Windows updates.");
            return unchecked((int)0x80131506);
        }
        if (standardApp && scenario == "unknown") { Console.Error.WriteLine("An unrelated initialization failure."); return unchecked((int)0x80131506); }
        if (standardApp && scenario == "wrong-code") { Console.Error.WriteLine("Your Windows doesn't fully support CET. Please install all available Windows updates."); return 1; }
        if (standardApp && scenario == "ready-then-fatal") { Console.WriteLine(ready); Console.Error.WriteLine("Your Windows doesn't fully support CET. Please install all available Windows updates."); return unchecked((int)0x80131506); }
        if (standardApp && scenario == "timeout") { Thread.Sleep(60000); return 0; }
        if (standardApp && scenario == "overflow") { Console.Write(new string('X', 1024 * 1024)); return 0; }
        if (standardApp && scenario == "no-ready") return 0;
        if (standardApp && scenario == "wrong-nonce") ready += "x";
        Console.WriteLine(ready);
        return 0;
    }
}
'@
    $fixtureExe = Join-Path $fixtureRoot 'Fixture.exe'
    $compiler = Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
    & $compiler '/nologo' '/target:winexe' '/platform:x64' "/out:$fixtureExe" $fixtureSource | Out-Host
    if ($LASTEXITCODE -ne 0) { throw 'Could not compile the harmless .NET Framework test fixture.' }

    function New-Fixture([string]$Scenario) {
        $root = Join-Path $fixtureRoot ($Scenario + '-' + [Guid]::NewGuid().ToString('N'))
        New-Item -ItemType Directory -Path $root | Out-Null
        Copy-Item -LiteralPath (Join-Path $PublishRoot 'SteamSentinel.exe') -Destination (Join-Path $root 'SteamSentinel.exe')
        Copy-Item -LiteralPath (Join-Path $PublishRoot 'SteamSentinel.Broker.exe') -Destination (Join-Path $root 'SteamSentinel.Broker.exe')
        foreach ($role in @('SteamSentinel','SteamSentinel.Broker','SteamSentinel.ArchiveWorker')) {
            foreach ($mode in @('Standard','Compat')) { Copy-Item -LiteralPath $fixtureExe -Destination (Join-Path $root "$role.$mode.exe") }
            foreach ($extension in @('.dll','.deps.json','.runtimeconfig.json')) { Write-Text (Join-Path $root ($role + $extension)) 'Test-only placeholder, never loaded.' }
        }
        foreach ($file in @('SteamSentinel.Core.dll','coreclr.dll','hostfxr.dll','hostpolicy.dll','System.Private.CoreLib.dll')) { Write-Text (Join-Path $root $file) 'Test-only placeholder, never loaded.' }
        Write-Text (Join-Path $root 'fixture-case.txt') $Scenario
        Write-Manifest $root
        return $root
    }
    function Read-StartupReport($Result) {
        $line = @($Result.stdout -split "`n" | Where-Object { $_.StartsWith('Report=') }) | Select-Object -Last 1
        if ([string]::IsNullOrWhiteSpace($line)) { throw 'Missing native report path.' }
        Get-Content -LiteralPath $line.Substring(7).TrimEnd("`r") -Raw -Encoding UTF8
    }

    foreach ($scenario in @('success','cet','worker-cet')) {
        Check "fixture-$scenario-selects-correct-mode" {
            $root = New-Fixture $scenario
            $result = Invoke-Child (Join-Path $root 'SteamSentinel.exe') @('--startup-check')
            $expected = if ($scenario -eq 'success') { 'standard' } else { 'compat' }
            Assert ($result.exitCode -eq 0 -and $result.stdout.Contains("STEAMSENTINEL_STARTUP_SELECTED/1|$expected")) "Wrong selection: $($result.stdout)"
            Assert (-not (Test-Path -LiteralPath (Join-Path $root 'fixture-business.txt'))) 'Preflight entered business code.'
            $report = Read-StartupReport $result
            Assert ($report.Contains("Probe=worker/$expected ready=1")) 'Worker was not checked in the selected mode.'
        }
    }
    foreach ($scenario in @('unknown','wrong-code','ready-then-fatal','timeout','overflow','no-ready','wrong-nonce','compat-fails')) {
        Check "fixture-$scenario-does-not-replay-or-misclassify" {
            $root = New-Fixture $scenario
            $result = Invoke-Child (Join-Path $root 'SteamSentinel.exe') @('--startup-check')
            Assert ($result.exitCode -eq 125) "Expected a diagnosed failure, got $($result.exitCode)."
            $report = Read-StartupReport $result
            if ($scenario -ne 'compat-fails') { Assert (-not $report.Contains('Probe=app/compat')) 'Unrelated failure caused a security downgrade.' }
            else { Assert (([regex]::Matches($report, 'Probe=app/compat')).Count -eq 1) 'Compatibility failure caused repeated retries.' }
            Assert (-not (Test-Path -LiteralPath (Join-Path $root 'fixture-business.txt'))) 'Failed probe entered business code.'
        }
    }
    Check 'fixture-long-path-metadata-is-verified-before-probing' {
        # Keep the .NET Framework fixture hosts at the proven success-case path
        # length; only the metadata directory should exercise extended paths.
        $root = New-Fixture 'success'
        $manifestPath = Join-Path $root 'SHA256SUMS.txt'
        $originalEntries = @(Get-Content -LiteralPath $manifestPath).Count
        $created = Invoke-Child $fixtureExe @('--make-long-metadata', $root)
        $relative = 'long-metadata-' + ('x' * 170) + '\metadata.txt'
        Assert ($created.exitCode -eq 0 -and $created.stdout.TrimEnd("`r", "`n") -ceq ('LONG_METADATA/1|' + $relative)) "Long metadata fixture creation failed: $($created.stderr)"
        Assert ((Join-Path $root $relative).Length -gt 260) 'The fixture did not exceed MAX_PATH.'
        # Hash known inert bytes and append the relative path directly. Windows
        # PowerShell 5.1 cannot safely enumerate the new extended-length directory.
        $bytes = [Text.Encoding]::UTF8.GetBytes("SteamSentinel harmless long-path metadata.`n")
        $sha256 = [Security.Cryptography.SHA256]::Create()
        try { $digest = [BitConverter]::ToString($sha256.ComputeHash($bytes)).Replace('-', '') }
        finally { $sha256.Dispose() }
        [IO.File]::AppendAllText($manifestPath, "$digest *$relative`r`n", [Text.UTF8Encoding]::new($false))
        $result = Invoke-Child (Join-Path $root 'SteamSentinel.exe') @('--startup-check')
        Assert ($result.exitCode -eq 0 -and $result.stdout.Contains('STEAMSENTINEL_STARTUP_SELECTED/1|standard')) "Long metadata was rejected: $($result.stdout) $($result.stderr)"
        $report = Read-StartupReport $result
        Assert ($report -match ('(?m)^ManifestVerified=' + ($originalEntries + 1) + '\r?$')) 'The long metadata file was not included in manifest verification.'
        Assert ($report.Contains('Probe=worker/standard ready=1')) 'Long metadata bypassed normal startup probing.'
        Assert (-not (Test-Path -LiteralPath (Join-Path $root 'fixture-business.txt'))) 'Long-path preflight entered business code.'
    }
    foreach ($scenario in @('tampered','missing','unlisted','traversal','duplicate')) {
        Check "fixture-integrity-$scenario-blocks-before-execution" {
            $root = New-Fixture 'success'
            switch ($scenario) {
                'tampered' { [IO.File]::AppendAllText((Join-Path $root 'SteamSentinel.Standard.exe'), 'tampered') }
                'missing' { Remove-Item -LiteralPath (Join-Path $root 'SteamSentinel.Compat.exe') }
                'unlisted' { Write-Text (Join-Path $root 'Unlisted.dll') 'Not part of package.' }
                'traversal' { [IO.File]::AppendAllText((Join-Path $root 'SHA256SUMS.txt'), ('0' * 64) + " *..\outside.dll`r`n") }
                'duplicate' { $first = Get-Content -LiteralPath (Join-Path $root 'SHA256SUMS.txt') -TotalCount 1; [IO.File]::AppendAllText((Join-Path $root 'SHA256SUMS.txt'), $first + "`r`n") }
            }
            $result = Invoke-Child (Join-Path $root 'SteamSentinel.exe') @('--startup-check')
            Assert ($result.exitCode -eq 125) 'Corrupt or ambiguous package was accepted.'
            $report = Read-StartupReport $result
            Assert (-not $report.Contains('Probe=')) 'Package was executed before validation completed.'
        }
    }
    Check 'fixture-installer-uninstaller-does-not-block-startup' {
        $root = New-Fixture 'success'
        Write-Text (Join-Path $root 'unins000.exe') 'Inno-created placeholder, never executed.'
        $result = Invoke-Child (Join-Path $root 'SteamSentinel.exe') @('--startup-check')
        Assert ($result.exitCode -eq 0) 'The installed uninstaller was incorrectly rejected.'
    }
    Check 'fixture-arguments-are-forwarded-once-without-reinterpretation' {
        $root = New-Fixture 'success'
        $arguments = @('space value', 'C:\path with spaces\', 'literal"quote', '', '中文', '& % !')
        $result = Invoke-Child (Join-Path $root 'SteamSentinel.exe') $arguments
        Assert ($result.exitCode -eq 0) 'UI host was not dispatched.'
        $business = Join-Path $root 'fixture-business.txt'
        $deadline = [DateTime]::UtcNow.AddSeconds(5)
        while (-not (Test-Path -LiteralPath $business) -and [DateTime]::UtcNow -lt $deadline) { Start-Sleep -Milliseconds 50 }
        $actual = @(Get-Content -LiteralPath $business)
        Assert ($actual.Count -eq $arguments.Count + 1 -and $actual[0] -eq 'SteamSentinel.Standard.exe') 'Unexpected business dispatch.'
        for ($i = 0; $i -lt $arguments.Count; $i++) {
            Assert ([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($actual[$i + 1])) -ceq $arguments[$i]) "Argument $i changed."
        }
    }
    Check 'fixture-broker-preserves-mode-and-business-exit-without-replay' {
        $root = New-Fixture 'success'
        $result = Invoke-Child (Join-Path $root 'SteamSentinel.Broker.exe') @('--startup-mode','compat','plan path','plan hash')
        Assert ($result.exitCode -eq 37) 'Broker business exit was lost or retried.'
        $actual = @(Get-Content -LiteralPath (Join-Path $root 'fixture-business.txt'))
        Assert ($actual.Count -eq 3 -and $actual[0] -eq 'SteamSentinel.Broker.Compat.exe') 'Broker dispatched the wrong host or leaked private arguments.'
        Assert ([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($actual[1])) -ceq 'plan path') 'Broker plan argument changed.'
    }
    Check 'fixture-broker-preflight-failure-is-distinct-from-business-failure' {
        $root = New-Fixture 'broker-fails'
        $result = Invoke-Child (Join-Path $root 'SteamSentinel.Broker.exe') @('--startup-check')
        Assert ($result.exitCode -eq 0x53530001) 'Broker did not identify that business never started.'
        Assert (-not (Test-Path -LiteralPath (Join-Path $root 'fixture-business.txt'))) 'Broker preflight executed a plan.'
    }
    Check 'fixture-broker-business-cannot-spoof-preflight-not-started' {
        $root = New-Fixture 'exit-collision'
        $result = Invoke-Child (Join-Path $root 'SteamSentinel.Broker.exe') @('plan path','plan hash')
        Assert ($result.exitCode -eq 126) 'Business exit collided with the reserved preflight result.'
        Assert (Test-Path -LiteralPath (Join-Path $root 'fixture-business.txt')) 'Business fixture was not run.'
    }
}
catch {
    $tests.Add([pscustomobject]@{ name = 'test-harness'; passed = $false; skipped = $false; error = $_.Exception.Message })
}
finally {
    $watch.Stop()
    $result = [ordered]@{
        schema = 'SteamSentinel.UnifiedStartupTests/1'
        passed = @($tests | Where-Object passed).Count
        failed = @($tests | Where-Object { -not $_.passed -and -not $_.skipped }).Count
        skipped = @($tests | Where-Object skipped).Count
        needsElevated = $needsElevated
        elapsedMs = $watch.ElapsedMilliseconds
        hardwareCetFixVerified = $false
        tests = @($tests.ToArray())
    }
    Write-Text $ResultsPath ($result | ConvertTo-Json -Depth 8)
}
[pscustomobject]$result
if ($result.failed -gt 0) { throw "Unified startup verification failed; see $ResultsPath" }
