#requires -Version 5.1
[CmdletBinding()]
param([Parameter(Mandatory = $true)][string]$ResultsPath)

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path $PSScriptRoot -Parent
$helperSources = @(
    (Join-Path $repoRoot 'installer\SetupHelperMain.cs'),
    (Join-Path $repoRoot 'installer\PayloadMaintenance.cs'),
    (Join-Path $repoRoot 'installer\MachineStateBootstrap.cs')
)
$compilerParams = New-Object CodeDom.Compiler.CompilerParameters
$compilerParams.GenerateInMemory = $true
$compilerParams.TreatWarningsAsErrors = $true
foreach ($assembly in @('System.dll', 'System.Core.dll', 'System.Web.Extensions.dll')) {
    $null = $compilerParams.ReferencedAssemblies.Add($assembly)
}
$combinedSource = [string[]]@($helperSources | ForEach-Object { [IO.File]::ReadAllText($_, [Text.Encoding]::UTF8).TrimStart([char]0xFEFF) })
$compiler = New-Object Microsoft.CSharp.CSharpCodeProvider
try {
    $compiled = $compiler.CompileAssemblyFromSource($compilerParams, $combinedSource)
    if ($compiled.Errors.HasErrors) {
        throw ("SetupHelper test compilation failed: " + ($compiled.Errors | Out-String))
    }
}
finally {
    $compiler.Dispose()
}

$tests = [Collections.Generic.List[object]]::new()
$root = 'C:\Program Files\SteamSentinel'
$watch = [Diagnostics.Stopwatch]::StartNew()
function Fixture {
    foreach ($rule in @([SteamSentinelWorkerFirewall]::GetContract($root))) {
        [pscustomobject]@{
            Name = $rule.Name; ApplicationName = $rule.ApplicationName; Direction = $rule.Direction
            Enabled = $true; Action = 0; Profiles = 2147483647; Protocol = 256
            LocalAddresses = '*'; RemoteAddresses = '*'; InterfaceTypes = 'All'; Interfaces = $null; ServiceName = ''
        }
    }
}
function Test([string]$Name, [scriptblock]$Body) {
    try { & $Body; $tests.Add([pscustomobject]@{ name = $Name; passed = $true }) }
    catch { $tests.Add([pscustomobject]@{ name = $Name; passed = $false; error = $_.Exception.Message }) }
}
function RequireRejected([object[]]$Rules) {
    $rejected = $false
    try { [SteamSentinelWorkerFirewall]::AssertRules($Rules, $root) } catch { $rejected = $true }
    if (-not $rejected) { throw 'Unsafe rule fixture was accepted.' }
}
Test 'Three exact Worker paths each have both directions' {
    $contract = @([SteamSentinelWorkerFirewall]::GetContract($root))
    if ($contract.Count -ne 6 -or @($contract.Name | Select-Object -Unique).Count -ne 6 -or
        @($contract.ApplicationName | Select-Object -Unique).Count -ne 3 -or
        @($contract | Where-Object Direction -eq 1).Count -ne 3 -or @($contract | Where-Object Direction -eq 2).Count -ne 3) {
        throw 'Worker contract does not cover all variants in both directions.'
    }
}
Test 'Complete exact block rules pass without accessing the system firewall' { [SteamSentinelWorkerFirewall]::AssertRules(@(Fixture), $root) }
for ($index = 0; $index -lt 6; $index++) {
    Test "Missing rule $index is rejected" {
        $rules = @(Fixture)
        RequireRejected @($rules | Where-Object { $_.Name -cne $rules[$index].Name })
    }
}
Test 'Duplicate reserved name is rejected' { $rules = @(Fixture); RequireRejected ($rules + $rules[0]) }
foreach ($entry in @(
    @('ApplicationName', 'C:\Other\SteamSentinel.ArchiveWorker.exe'),
    @('Enabled', $false), @('Direction', 2), @('Action', 1), @('Profiles', 1), @('Protocol', 6),
    @('LocalAddresses', '127.0.0.1'), @('RemoteAddresses', 'LocalSubnet'),
    @('InterfaceTypes', 'Wireless'), @('Interfaces', 'Ethernet'), @('ServiceName', 'restricted-service')
)) {
    Test ("Restricted or incorrect " + $entry[0] + ' is rejected') {
        $rules = @(Fixture); $rules[0].($entry[0]) = $entry[1]; RequireRejected $rules
    }
}
Test 'Unrelated rules are retained and ignored' {
    $rules = @(Fixture); $extra = (Fixture)[0]; $extra.Name = 'Unrelated administrator rule'
    [SteamSentinelWorkerFirewall]::AssertRules(($rules + $extra), $root)
}
Test 'Installer configures firewall via pinned SetupHelper without PowerShell and preserves uninstall cleanup' {
    $installer = Get-Content -LiteralPath (Join-Path $repoRoot 'installer\SteamSentinel.iss') -Raw
    if ($installer.Contains('powershell.exe')) { throw 'Installer still invokes PowerShell.' }
    if (-not $installer.Contains('#define SetupHelperHash GetSHA256OfFile(SetupHelperPath)') -or
        -not $installer.Contains('GetVerifiedSetupHelper()') -or
        -not $installer.Contains('firewall --install-root') -or
        -not $installer.Contains('CloseApplicationsFilter=*.exe,*.dll')) {
        throw 'Missing pinned SetupHelper firewall lifecycle or all-host in-use checks.'
    }
    foreach ($macro in @('WorkerRuleOut', 'WorkerRuleIn', 'WorkerStandardRuleOut', 'WorkerStandardRuleIn', 'WorkerCompatRuleOut', 'WorkerCompatRuleIn')) {
        if (-not $installer.Contains('name=""{#' + $macro + '}""')) { throw "Missing uninstall cleanup for $macro" }
    }
}
$watch.Stop()
$result = [ordered]@{
    schema = 'SteamSentinel.WorkerFirewallContractTests/1'
    passed = @($tests | Where-Object passed).Count
    failed = @($tests | Where-Object { -not $_.passed }).Count
    skipped = 0
    elapsedMs = $watch.ElapsedMilliseconds
    systemFirewallAccessed = $false
    tests = @($tests.ToArray())
}
$ResultsPath = [IO.Path]::GetFullPath($ResultsPath)
New-Item -ItemType Directory -Path (Split-Path -Parent $ResultsPath) -Force | Out-Null
[IO.File]::WriteAllText($ResultsPath, ($result | ConvertTo-Json -Depth 6), [Text.UTF8Encoding]::new($false))
Write-Host "Worker firewall contract: $($result.passed) passed, $($result.failed) failed; no system firewall access."
if ($result.failed -ne 0) { throw 'Worker firewall contract tests failed.' }
