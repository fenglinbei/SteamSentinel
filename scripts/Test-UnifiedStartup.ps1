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
$utf8NoBom = [Text.UTF8Encoding]::new($false)

function Quote-Argument([string]$Value) {
    # CommandLineToArgvW / CRT quoting, including trailing backslashes.
    '"' + [regex]::Replace([regex]::Replace($Value, '(\\*)"', '$1$1\"'), '(\\+)$', '$1$1') + '"'
}
function Start-Child([string]$File, [string[]]$Arguments, [int]$TimeoutMs = 45000) {
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
        [pscustomobject]@{
            process = $process
            stdout = $stdout
            stderr = $stderr
            timeoutMs = $TimeoutMs
            clock = [Diagnostics.Stopwatch]::StartNew()
            disposed = $false
        }
    }
    catch {
        $process.Dispose()
        throw
    }
}
function Wait-Child($Child) {
    $process = $Child.process
    try {
        $remaining = [int][Math]::Max(0L, [long]$Child.timeoutMs - $Child.clock.ElapsedMilliseconds)
        if (-not $process.WaitForExit($remaining)) {
            try { $process.Kill() } catch {}
            $process.WaitForExit(5000) | Out-Null
            throw 'Startup child exceeded the test timeout.'
        }
        if (-not $Child.stdout.Wait(5000) -or -not $Child.stderr.Wait(5000)) { throw 'Startup output pipes did not close.' }
        [pscustomobject]@{ exitCode = $process.ExitCode; stdout = $Child.stdout.Result; stderr = $Child.stderr.Result }
    }
    finally {
        $Child.disposed = $true
        $process.Dispose()
    }
}
function Stop-Child($Child) {
    if ($null -eq $Child -or $Child.disposed -or $null -eq $Child.process) { return }
    try {
        if (-not $Child.process.HasExited) { $Child.process.Kill() }
    }
    catch {}
    try { $Child.process.Dispose() } catch {}
    $Child.disposed = $true
}
function Invoke-Child([string]$File, [string[]]$Arguments, [int]$TimeoutMs = 45000) {
    $child = Start-Child $File $Arguments $TimeoutMs
    Wait-Child $child
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
function Write-Text([string]$Path, [string]$Text) { [IO.File]::WriteAllText($Path, $Text, $utf8NoBom) }
function Get-BytesSha256([byte[]]$Bytes) {
    $sha256 = [Security.Cryptography.SHA256]::Create()
    try { [BitConverter]::ToString($sha256.ComputeHash($Bytes)).Replace('-', '') }
    finally { $sha256.Dispose() }
}
function Write-Manifest([string]$Root) {
    $lines = @(Get-ChildItem -LiteralPath $Root -File -Recurse | Where-Object Name -ne 'SHA256SUMS.txt' | Sort-Object FullName | ForEach-Object {
        '{0} *{1}' -f (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash, $_.FullName.Substring($Root.Length + 1)
    })
    [IO.File]::WriteAllLines((Join-Path $Root 'SHA256SUMS.txt'), [string[]]$lines, $utf8NoBom)
}

$realEntries = [Collections.Generic.List[object]]::new()
$activeFixtureSlots = [Collections.Generic.List[object]]::new()
$timeoutFixtureCase = $null

try {
    # Phase 1: 并发拉起互不依赖的真实宿主探测，并在子进程启动期间执行导入表静态审计，最终按原顺序写回 $tests。
    foreach ($entry in @(@('SteamSentinel','app'), @('SteamSentinel.ArchiveWorker','worker'), @('SteamSentinel.Broker','broker'))) {
        foreach ($mode in @('Standard', 'Compat')) {
            $name = "$($entry[0]).$mode"
            $testName = "real-$name-probe"
            if ($entry[1] -eq 'broker' -and -not $isAdministrator) {
                $realEntries.Add([pscustomobject]@{
                    kind = 'Skipped'
                    name = $testName
                    result = [pscustomobject]@{ name = $testName; passed = $false; skipped = $true; error = 'Requires an elevated test session; the Broker manifest remains requireAdministrator.' }
                })
                continue
            }
            $nonce = [Guid]::NewGuid().ToString('N')
            $expected = "STEAMSENTINEL_STARTUP_READY/1|$($entry[1])|$($mode.ToLowerInvariant())|$nonce"
            $realEntries.Add([pscustomobject]@{
                kind = 'Child'
                name = $testName
                file = Join-Path $PublishRoot ($name + '.exe')
                arguments = @('--startup-probe', $nonce)
                timeoutMs = 45000
                expected = $expected
                child = $null
                startError = $null
                verify = {
                    param($Item, $Result)
                    Assert ($Result.exitCode -eq 0 -and $Result.stdout.TrimEnd("`r", "`n") -ceq $Item.expected) "Published host did not acknowledge its exact role, mode and nonce: $($Result.exitCode), $($Result.stdout), $($Result.stderr)"
                }
            })
        }
    }
    $realEntries.Add([pscustomobject]@{
        kind = 'Child'
        name = 'real-native-package-preflight'
        file = Join-Path $PublishRoot 'SteamSentinel.exe'
        arguments = @('--startup-check')
        timeoutMs = 90000
        expected = $null
        child = $null
        startError = $null
        verify = {
            param($Item, $Result)
            Assert ($Result.exitCode -eq 0 -and $Result.stdout -match '(?m)^STEAMSENTINEL_STARTUP_SELECTED/1\|(standard|compat)\r?$') "Native package preflight failed: $($Result.stdout) $($Result.stderr)"
        }
    })
    if ($isAdministrator) {
        $realEntries.Add([pscustomobject]@{
            kind = 'Child'
            name = 'real-elevated-broker-preflight'
            file = Join-Path $PublishRoot 'SteamSentinel.Broker.exe'
            arguments = @('--startup-check')
            timeoutMs = 60000
            expected = $null
            child = $null
            startError = $null
            verify = {
                param($Item, $Result)
                Assert ($Result.exitCode -eq 0 -and $Result.stdout -match 'STEAMSENTINEL_STARTUP_SELECTED/1\|') "Broker preflight failed: $($Result.stdout) $($Result.stderr)"
            }
        })
    }

    foreach ($item in $realEntries) {
        if ($item.kind -ne 'Child') { continue }
        try {
            $item.child = Start-Child $item.file $item.arguments $item.timeoutMs
        }
        catch {
            $item.startError = $_.Exception.Message
        }
    }

    # 在已启动的子进程初始化 CLR 期间同步完成无副作用 PE 导入表审计。
    $importAuditPassed = $true
    $importAuditError = $null
    try {
        Add-Type -TypeDefinition @'
using System;
using System.IO;
using System.Text;
public static class WorkerImportAudit {
    static int Rva(byte[] d, int pe, uint rva, int min) {
        int opt = pe + 24, sec = opt + BitConverter.ToUInt16(d, pe + 20), cnt = BitConverter.ToUInt16(d, pe + 6);
        for (int i = 0; i < cnt; i++) {
            int s = sec + i * 40;
            uint va = BitConverter.ToUInt32(d, s + 12), rs = BitConverter.ToUInt32(d, s + 16), ro = BitConverter.ToUInt32(d, s + 20);
            if (rva >= va && (ulong)rva + (uint)min <= (ulong)va + rs) return checked((int)((long)ro + rva - va));
        }
        throw new InvalidDataException("RVA out of bounds.");
    }
    public static void AssertOnlyKernel32(string path) {
        byte[] d = File.ReadAllBytes(path);
        int pe = BitConverter.ToInt32(d, 60), opt = pe + 24;
        if (BitConverter.ToUInt16(d, opt + 68) != 3) throw new InvalidDataException("Expected console subsystem: " + path);
        uint impRva = BitConverter.ToUInt32(d, opt + 120), impSz = BitConverter.ToUInt32(d, opt + 124);
        if (impRva == 0 || impSz < 20) throw new InvalidDataException("Missing imports: " + path);
        int off = Rva(d, pe, impRva, 20), n = 0;
        for (int p = off; p + 20 <= d.Length; p += 20) {
            uint nameRva = BitConverter.ToUInt32(d, p + 12);
            if (nameRva == 0) break;
            int no = Rva(d, pe, nameRva, 1), end = no;
            while (end < d.Length && end - no < 260 && d[end] != 0) end++;
            string dll = Encoding.ASCII.GetString(d, no, end - no);
            if (!String.Equals(dll, "KERNEL32.dll", StringComparison.OrdinalIgnoreCase))
                throw new InvalidDataException("Forbidden GUI/shell import '" + dll + "' in " + path);
            n++;
        }
        if (n == 0 || BitConverter.ToUInt32(d, opt + 216) != 0) throw new InvalidDataException("Invalid import/delay directory: " + path);
    }
}
'@
        foreach ($workerFile in @('SteamSentinel.ArchiveWorker.Standard.exe', 'SteamSentinel.ArchiveWorker.Compat.exe', 'SteamSentinel.ArchiveWorker.exe')) {
            [WorkerImportAudit]::AssertOnlyKernel32((Join-Path $PublishRoot $workerFile))
        }
    }
    catch {
        $importAuditPassed = $false
        $importAuditError = $_.Exception.Message
    }

    foreach ($item in $realEntries) {
        if ($item.kind -eq 'Skipped') {
            $tests.Add($item.result)
            continue
        }
        Check $item.name {
            if ($null -ne $item.startError) { throw $item.startError }
            $result = Wait-Child $item.child
            & $item.verify $item $result
        }
    }
    if ($importAuditPassed) {
        $tests.Add([pscustomobject]@{ name = 'real-worker-no-gui-imports'; passed = $true; skipped = $false; error = $null })
        Write-Host 'PASS real-worker-no-gui-imports'
    }
    else {
        $tests.Add([pscustomobject]@{ name = 'real-worker-no-gui-imports'; passed = $false; skipped = $false; error = $importAuditError })
        Write-Host "FAIL real-worker-no-gui-imports : $importAuditError"
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

    # 预计算所有不变夹具文件的 SHA-256 与排序清单模板，避免每个场景重复哈希 22 个相同文件。
    $placeholderBytes = $utf8NoBom.GetBytes('Test-only placeholder, never loaded.')
    $placeholderHash = Get-BytesSha256 $placeholderBytes
    $launcherExeSource = Join-Path $PublishRoot 'SteamSentinel.exe'
    $brokerExeSource = Join-Path $PublishRoot 'SteamSentinel.Broker.exe'
    $fixtureExeHash = (Get-FileHash -LiteralPath $fixtureExe -Algorithm SHA256).Hash
    $fixedCopySources = [ordered]@{
        'SteamSentinel.exe' = $launcherExeSource
        'SteamSentinel.Broker.exe' = $brokerExeSource
    }
    $fixedFileHashes = [ordered]@{
        'SteamSentinel.exe' = (Get-FileHash -LiteralPath $launcherExeSource -Algorithm SHA256).Hash
        'SteamSentinel.Broker.exe' = (Get-FileHash -LiteralPath $brokerExeSource -Algorithm SHA256).Hash
    }
    $placeholderFiles = [Collections.Generic.List[string]]::new()
    foreach ($role in @('SteamSentinel','SteamSentinel.Broker','SteamSentinel.ArchiveWorker')) {
        foreach ($mode in @('Standard','Compat')) {
            $hostName = "$role.$mode.exe"
            $fixedCopySources[$hostName] = $fixtureExe
            $fixedFileHashes[$hostName] = $fixtureExeHash
        }
        foreach ($extension in @('.dll','.deps.json','.runtimeconfig.json')) {
            $placeholderName = $role + $extension
            $placeholderFiles.Add($placeholderName)
            $fixedFileHashes[$placeholderName] = $placeholderHash
        }
    }
    foreach ($file in @('SteamSentinel.Core.dll','coreclr.dll','hostfxr.dll','hostpolicy.dll','System.Private.CoreLib.dll')) {
        $placeholderFiles.Add($file)
        $fixedFileHashes[$file] = $placeholderHash
    }
    $sortedManifestNames = @(@($fixedFileHashes.Keys) + @('fixture-case.txt') | Sort-Object)

    function New-Fixture([string]$Scenario) {
        $root = Join-Path $fixtureRoot ($Scenario + '-' + [Guid]::NewGuid().ToString('N'))
        [IO.Directory]::CreateDirectory($root) | Out-Null
        foreach ($pair in $fixedCopySources.GetEnumerator()) {
            [IO.File]::Copy($pair.Value, (Join-Path $root $pair.Key), $true)
        }
        foreach ($file in $placeholderFiles) {
            [IO.File]::WriteAllBytes((Join-Path $root $file), $placeholderBytes)
        }
        $scenarioBytes = $utf8NoBom.GetBytes($Scenario)
        [IO.File]::WriteAllBytes((Join-Path $root 'fixture-case.txt'), $scenarioBytes)
        $scenarioHash = Get-BytesSha256 $scenarioBytes
        $lines = [string[]]::new($sortedManifestNames.Count)
        for ($i = 0; $i -lt $sortedManifestNames.Count; $i++) {
            $fileName = $sortedManifestNames[$i]
            $hash = if ($fileName -eq 'fixture-case.txt') { $scenarioHash } else { $fixedFileHashes[$fileName] }
            $lines[$i] = '{0} *{1}' -f $hash, $fileName
        }
        [IO.File]::WriteAllLines((Join-Path $root 'SHA256SUMS.txt'), $lines, $utf8NoBom)
        return $root
    }
    function Read-StartupReport($Result) {
        $line = @($Result.stdout -split "`n" | Where-Object { $_.StartsWith('Report=') }) | Select-Object -Last 1
        if ([string]::IsNullOrWhiteSpace($line)) { throw 'Missing native report path.' }
        Get-Content -LiteralPath $line.Substring(7).TrimEnd("`r") -Raw -Encoding UTF8
    }

    $fixtureCases = [Collections.Generic.List[object]]::new()
    foreach ($scenario in @('success','cet','worker-cet')) {
        $fixtureCases.Add([pscustomobject]@{
            name = "fixture-$scenario-selects-correct-mode"
            scenario = $scenario
            isBackgroundTimeout = $false
            state = $null
            result = $null
            setup = {
                param($Case)
                $root = New-Fixture $Case.scenario
                $child = Start-Child (Join-Path $root 'SteamSentinel.exe') @('--startup-check')
                [pscustomobject]@{ child = $child; root = $root }
            }
            verify = {
                param($Case, $State, $ChildResult)
                $expected = if ($Case.scenario -eq 'success') { 'standard' } else { 'compat' }
                Assert ($ChildResult.exitCode -eq 0 -and $ChildResult.stdout.Contains("STEAMSENTINEL_STARTUP_SELECTED/1|$expected")) "Wrong selection: $($ChildResult.stdout)"
                Assert (-not (Test-Path -LiteralPath (Join-Path $State.root 'fixture-business.txt'))) 'Preflight entered business code.'
                $report = Read-StartupReport $ChildResult
                Assert ($report.Contains("Probe=worker/$expected ready=1")) 'Worker was not checked in the selected mode.'
            }
        })
    }
    foreach ($scenario in @('unknown','wrong-code','ready-then-fatal','timeout','overflow','no-ready','wrong-nonce','compat-fails')) {
        $fixtureCases.Add([pscustomobject]@{
            name = "fixture-$scenario-does-not-replay-or-misclassify"
            scenario = $scenario
            isBackgroundTimeout = ($scenario -eq 'timeout')
            state = $null
            result = $null
            setup = {
                param($Case)
                $root = New-Fixture $Case.scenario
                $child = Start-Child (Join-Path $root 'SteamSentinel.exe') @('--startup-check')
                [pscustomobject]@{ child = $child; root = $root }
            }
            verify = {
                param($Case, $State, $ChildResult)
                Assert ($ChildResult.exitCode -eq 125) "Expected a diagnosed failure, got $($ChildResult.exitCode)."
                $report = Read-StartupReport $ChildResult
                if ($Case.scenario -ne 'compat-fails') { Assert (-not $report.Contains('Probe=app/compat')) 'Unrelated failure caused a security downgrade.' }
                else { Assert (([regex]::Matches($report, 'Probe=app/compat')).Count -eq 1) 'Compatibility failure caused repeated retries.' }
                Assert (-not (Test-Path -LiteralPath (Join-Path $State.root 'fixture-business.txt'))) 'Failed probe entered business code.'
            }
        })
    }
    $fixtureCases.Add([pscustomobject]@{
        name = 'fixture-long-path-metadata-is-verified-before-probing'
        scenario = 'success'
        isBackgroundTimeout = $false
        state = $null
        result = $null
        setup = {
            param($Case)
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
            $digest = Get-BytesSha256 ([Text.Encoding]::UTF8.GetBytes("SteamSentinel harmless long-path metadata.`n"))
            [IO.File]::AppendAllText($manifestPath, "$digest *$relative`r`n", $utf8NoBom)
            $child = Start-Child (Join-Path $root 'SteamSentinel.exe') @('--startup-check')
            [pscustomobject]@{ child = $child; root = $root; originalEntries = $originalEntries }
        }
        verify = {
            param($Case, $State, $ChildResult)
            Assert ($ChildResult.exitCode -eq 0 -and $ChildResult.stdout.Contains('STEAMSENTINEL_STARTUP_SELECTED/1|standard')) "Long metadata was rejected: $($ChildResult.stdout) $($ChildResult.stderr)"
            $report = Read-StartupReport $ChildResult
            Assert ($report -match ('(?m)^ManifestVerified=' + ($State.originalEntries + 1) + '\r?$')) 'The long metadata file was not included in manifest verification.'
            Assert ($report.Contains('Probe=worker/standard ready=1')) 'Long metadata bypassed normal startup probing.'
            Assert (-not (Test-Path -LiteralPath (Join-Path $State.root 'fixture-business.txt'))) 'Long-path preflight entered business code.'
        }
    })
    foreach ($scenario in @('tampered','missing','unlisted','traversal','duplicate')) {
        $fixtureCases.Add([pscustomobject]@{
            name = "fixture-integrity-$scenario-blocks-before-execution"
            scenario = $scenario
            isBackgroundTimeout = $false
            state = $null
            result = $null
            setup = {
                param($Case)
                $root = New-Fixture 'success'
                switch ($Case.scenario) {
                    'tampered' { [IO.File]::AppendAllText((Join-Path $root 'SteamSentinel.Standard.exe'), 'tampered') }
                    'missing' { Remove-Item -LiteralPath (Join-Path $root 'SteamSentinel.Compat.exe') }
                    'unlisted' { Write-Text (Join-Path $root 'Unlisted.dll') 'Not part of package.' }
                    'traversal' { [IO.File]::AppendAllText((Join-Path $root 'SHA256SUMS.txt'), ('0' * 64) + " *..\outside.dll`r`n") }
                    'duplicate' { $first = Get-Content -LiteralPath (Join-Path $root 'SHA256SUMS.txt') -TotalCount 1; [IO.File]::AppendAllText((Join-Path $root 'SHA256SUMS.txt'), $first + "`r`n") }
                }
                $child = Start-Child (Join-Path $root 'SteamSentinel.exe') @('--startup-check')
                [pscustomobject]@{ child = $child; root = $root }
            }
            verify = {
                param($Case, $State, $ChildResult)
                Assert ($ChildResult.exitCode -eq 125) 'Corrupt or ambiguous package was accepted.'
                $report = Read-StartupReport $ChildResult
                Assert (-not $report.Contains('Probe=')) 'Package was executed before validation completed.'
            }
        })
    }
    $fixtureCases.Add([pscustomobject]@{
        name = 'fixture-installer-uninstaller-does-not-block-startup'
        scenario = 'success'
        isBackgroundTimeout = $false
        state = $null
        result = $null
        setup = {
            param($Case)
            $root = New-Fixture 'success'
            Write-Text (Join-Path $root 'unins000.exe') 'Inno-created placeholder, never executed.'
            $child = Start-Child (Join-Path $root 'SteamSentinel.exe') @('--startup-check')
            [pscustomobject]@{ child = $child; root = $root }
        }
        verify = {
            param($Case, $State, $ChildResult)
            Assert ($ChildResult.exitCode -eq 0) 'The installed uninstaller was incorrectly rejected.'
        }
    })
    $fixtureCases.Add([pscustomobject]@{
        name = 'fixture-arguments-are-forwarded-once-without-reinterpretation'
        scenario = 'success'
        isBackgroundTimeout = $false
        state = $null
        result = $null
        setup = {
            param($Case)
            $root = New-Fixture 'success'
            $arguments = @('space value', 'C:\path with spaces\', 'literal"quote', '', '中文', '& % !')
            $child = Start-Child (Join-Path $root 'SteamSentinel.exe') $arguments
            [pscustomobject]@{ child = $child; root = $root; arguments = $arguments }
        }
        verify = {
            param($Case, $State, $ChildResult)
            Assert ($ChildResult.exitCode -eq 0) 'UI host was not dispatched.'
            $business = Join-Path $State.root 'fixture-business.txt'
            $deadline = [DateTime]::UtcNow.AddSeconds(5)
            while (-not (Test-Path -LiteralPath $business) -and [DateTime]::UtcNow -lt $deadline) { Start-Sleep -Milliseconds 50 }
            $actual = @(Get-Content -LiteralPath $business)
            Assert ($actual.Count -eq $State.arguments.Count + 1 -and $actual[0] -eq 'SteamSentinel.Standard.exe') 'Unexpected business dispatch.'
            for ($i = 0; $i -lt $State.arguments.Count; $i++) {
                Assert ([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($actual[$i + 1])) -ceq $State.arguments[$i]) "Argument $i changed."
            }
        }
    })
    $fixtureCases.Add([pscustomobject]@{
        name = 'fixture-broker-preserves-mode-and-business-exit-without-replay'
        scenario = 'success'
        isBackgroundTimeout = $false
        state = $null
        result = $null
        setup = {
            param($Case)
            $root = New-Fixture 'success'
            $child = Start-Child (Join-Path $root 'SteamSentinel.Broker.exe') @('--startup-mode','compat','plan path','plan hash')
            [pscustomobject]@{ child = $child; root = $root }
        }
        verify = {
            param($Case, $State, $ChildResult)
            Assert ($ChildResult.exitCode -eq 37) 'Broker business exit was lost or retried.'
            $actual = @(Get-Content -LiteralPath (Join-Path $State.root 'fixture-business.txt'))
            Assert ($actual.Count -eq 3 -and $actual[0] -eq 'SteamSentinel.Broker.Compat.exe') 'Broker dispatched the wrong host or leaked private arguments.'
            Assert ([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($actual[1])) -ceq 'plan path') 'Broker plan argument changed.'
        }
    })
    $fixtureCases.Add([pscustomobject]@{
        name = 'fixture-broker-preflight-failure-is-distinct-from-business-failure'
        scenario = 'broker-fails'
        isBackgroundTimeout = $false
        state = $null
        result = $null
        setup = {
            param($Case)
            $root = New-Fixture 'broker-fails'
            $child = Start-Child (Join-Path $root 'SteamSentinel.Broker.exe') @('--startup-check')
            [pscustomobject]@{ child = $child; root = $root }
        }
        verify = {
            param($Case, $State, $ChildResult)
            Assert ($ChildResult.exitCode -eq 0x53530001) 'Broker did not identify that business never started.'
            Assert (-not (Test-Path -LiteralPath (Join-Path $State.root 'fixture-business.txt'))) 'Broker preflight executed a plan.'
        }
    })
    $fixtureCases.Add([pscustomobject]@{
        name = 'fixture-broker-business-cannot-spoof-preflight-not-started'
        scenario = 'exit-collision'
        isBackgroundTimeout = $false
        state = $null
        result = $null
        setup = {
            param($Case)
            $root = New-Fixture 'exit-collision'
            $child = Start-Child (Join-Path $root 'SteamSentinel.Broker.exe') @('plan path','plan hash')
            [pscustomobject]@{ child = $child; root = $root }
        }
        verify = {
            param($Case, $State, $ChildResult)
            Assert ($ChildResult.exitCode -eq 126) 'Business exit collided with the reserved preflight result.'
            Assert (Test-Path -LiteralPath (Join-Path $State.root 'fixture-business.txt')) 'Business fixture was not run.'
        }
    })

    # 先第一时间后台拉起等待 20s 探针超时的 fixture-timeout，让它与其余 21 个夹具用例充分重叠。
    $timeoutFixtureCase = $fixtureCases | Where-Object { $_.isBackgroundTimeout } | Select-Object -First 1
    if ($null -ne $timeoutFixtureCase) {
        try {
            $timeoutFixtureCase.state = & $timeoutFixtureCase.setup $timeoutFixtureCase
        }
        catch {
            $timeoutFixtureCase.result = [pscustomobject]@{ name = $timeoutFixtureCase.name; passed = $false; skipped = $false; error = $_.Exception.Message }
        }
    }

    $concurrentFixtureCases = @($fixtureCases | Where-Object { -not $_.isBackgroundTimeout })
    $maxFixtureConcurrency = 4
    $nextCaseIndex = 0
    while ($nextCaseIndex -lt $concurrentFixtureCases.Count -or $activeFixtureSlots.Count -gt 0) {
        while ($activeFixtureSlots.Count -lt $maxFixtureConcurrency -and $nextCaseIndex -lt $concurrentFixtureCases.Count) {
            $case = $concurrentFixtureCases[$nextCaseIndex++]
            try {
                $case.state = & $case.setup $case
                $activeFixtureSlots.Add($case)
            }
            catch {
                $case.result = [pscustomobject]@{ name = $case.name; passed = $false; skipped = $false; error = $_.Exception.Message }
            }
        }

        $reapedAny = $false
        for ($slotIndex = $activeFixtureSlots.Count - 1; $slotIndex -ge 0; $slotIndex--) {
            $slotCase = $activeFixtureSlots[$slotIndex]
            $slotChild = $slotCase.state.child
            if ($slotChild.process.HasExited -or $slotChild.clock.ElapsedMilliseconds -ge $slotChild.timeoutMs) {
                $activeFixtureSlots.RemoveAt($slotIndex)
                $reapedAny = $true
                try {
                    $childResult = Wait-Child $slotChild
                    & $slotCase.verify $slotCase $slotCase.state $childResult
                    $slotCase.result = [pscustomobject]@{ name = $slotCase.name; passed = $true; skipped = $false; error = $null }
                }
                catch {
                    $slotCase.result = [pscustomobject]@{ name = $slotCase.name; passed = $false; skipped = $false; error = $_.Exception.Message }
                }
            }
        }

        if (-not $reapedAny -and $activeFixtureSlots.Count -gt 0 -and
            ($activeFixtureSlots.Count -ge $maxFixtureConcurrency -or $nextCaseIndex -ge $concurrentFixtureCases.Count)) {
            Start-Sleep -Milliseconds 20
        }
    }

    if ($null -ne $timeoutFixtureCase -and $null -eq $timeoutFixtureCase.result) {
        try {
            $timeoutResult = Wait-Child $timeoutFixtureCase.state.child
            & $timeoutFixtureCase.verify $timeoutFixtureCase $timeoutFixtureCase.state $timeoutResult
            $timeoutFixtureCase.result = [pscustomobject]@{ name = $timeoutFixtureCase.name; passed = $true; skipped = $false; error = $null }
        }
        catch {
            $timeoutFixtureCase.result = [pscustomobject]@{ name = $timeoutFixtureCase.name; passed = $false; skipped = $false; error = $_.Exception.Message }
        }
    }

    foreach ($case in $fixtureCases) {
        $tests.Add($case.result)
        if ($case.result.passed) {
            Write-Host "PASS $($case.result.name)"
        }
        else {
            Write-Host "FAIL $($case.result.name) : $($case.result.error)"
        }
    }
}
catch {
    $tests.Add([pscustomobject]@{ name = 'test-harness'; passed = $false; skipped = $false; error = $_.Exception.Message })
}
finally {
    foreach ($item in $realEntries) {
        if ($null -ne $item.PSObject.Properties['child']) { Stop-Child $item.child }
    }
    foreach ($slotCase in $activeFixtureSlots) {
        if ($null -ne $slotCase.state -and $null -ne $slotCase.state.child) { Stop-Child $slotCase.state.child }
    }
    if ($null -ne $timeoutFixtureCase -and $null -ne $timeoutFixtureCase.state -and $null -ne $timeoutFixtureCase.state.child) {
        Stop-Child $timeoutFixtureCase.state.child
    }
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
