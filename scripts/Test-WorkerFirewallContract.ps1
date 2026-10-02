#requires -Version 5.1
[CmdletBinding()]
param([Parameter(Mandatory = $true)][string]$ResultsPath)

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot '..\installer\Verify-WorkerFirewall.ps1')
$tests = [Collections.Generic.List[object]]::new()
$root = 'C:\Program Files\SteamSentinel'
$watch = [Diagnostics.Stopwatch]::StartNew()
function Fixture {
    foreach ($rule in @(Get-WorkerFirewallContract $root)) {
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
    try { Assert-WorkerFirewallRules $Rules $root } catch { $rejected = $true }
    if (-not $rejected) { throw 'Unsafe rule fixture was accepted.' }
}
Test 'Three exact Worker paths each have both directions' {
    $contract = @(Get-WorkerFirewallContract $root)
    if ($contract.Count -ne 6 -or @($contract.Name | Select-Object -Unique).Count -ne 6 -or
        @($contract.ApplicationName | Select-Object -Unique).Count -ne 3 -or
        @($contract | Where-Object Direction -eq 1).Count -ne 3 -or @($contract | Where-Object Direction -eq 2).Count -ne 3) {
        throw 'Worker contract does not cover all variants in both directions.'
    }
}
Test 'Complete exact block rules pass without accessing the system firewall' { Assert-WorkerFirewallRules @(Fixture) $root }
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
    Assert-WorkerFirewallRules ($rules + $extra) $root
}
Test 'Installer creates, removes and verifies every reserved rule' {
    $installer = Get-Content -LiteralPath (Join-Path $PSScriptRoot '..\installer\SteamSentinel.iss') -Raw
    foreach ($macro in @('WorkerRuleOut', 'WorkerRuleIn', 'WorkerStandardRuleOut', 'WorkerStandardRuleIn', 'WorkerCompatRuleOut', 'WorkerCompatRuleIn')) {
        if (-not $installer.Contains("RemoveFirewallRuleIfPresent('{#$macro}');") -or
            -not $installer.Contains("AddAndVerifyFirewallRule('{#$macro}',") -or
            -not $installer.Contains('name=""{#' + $macro + '}""')) { throw "Missing installer lifecycle action for $macro" }
    }
    if (-not $installer.Contains("GetSHA256OfFile(VerifyScript), '{#WorkerFirewallScriptHash}'") -or
        -not $installer.Contains('CloseApplicationsFilter=*.exe,*.dll')) { throw 'Missing verification or all-host in-use checks.' }
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
