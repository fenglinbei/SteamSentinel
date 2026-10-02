#requires -Version 5.1
[CmdletBinding()]
param([string]$InstallRoot)

$ErrorActionPreference = 'Stop'

function Get-WorkerFirewallContract([string]$Root) {
    $rootPath = [IO.Path]::GetFullPath($Root).TrimEnd('\')
    foreach ($entry in @(
        @('SteamSentinel.ArchiveWorker.exe', 'SteamSentinel ArchiveWorker'),
        @('SteamSentinel.ArchiveWorker.Standard.exe', 'SteamSentinel ArchiveWorker Standard'),
        @('SteamSentinel.ArchiveWorker.Compat.exe', 'SteamSentinel ArchiveWorker Compat')
    )) {
        foreach ($direction in @(@('inbound', 1), @('outbound', 2))) {
            [pscustomobject]@{
                Name = $entry[1] + ' ' + $direction[0] + ' block'
                ApplicationName = Join-Path $rootPath $entry[0]
                Direction = $direction[1]
            }
        }
    }
}

function Assert-WorkerFirewallRules([object[]]$Rules, [string]$Root) {
    foreach ($expected in @(Get-WorkerFirewallContract $Root)) {
        $matches = @($Rules | Where-Object { $_.Name -ceq $expected.Name })
        if ($matches.Count -ne 1) { throw "Missing or duplicate ArchiveWorker block rule: $($expected.Name)" }
        $rule = $matches[0]
        $actualPath = [Environment]::ExpandEnvironmentVariables([string]$rule.ApplicationName)
        if ([string]::IsNullOrWhiteSpace($actualPath) -or
            -not [IO.Path]::GetFullPath($actualPath).Equals($expected.ApplicationName, [StringComparison]::OrdinalIgnoreCase) -or
            -not $rule.Enabled -or [int]$rule.Direction -ne $expected.Direction -or
            [int]$rule.Action -ne 0 -or [int]$rule.Profiles -ne 2147483647 -or [int]$rule.Protocol -ne 256 -or
            [string]$rule.LocalAddresses -ne '*' -or [string]$rule.RemoteAddresses -ne '*' -or
            [string]$rule.InterfaceTypes -ne 'All' -or
            @($rule.Interfaces | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) }).Count -ne 0 -or
            -not [string]::IsNullOrEmpty([string]$rule.ServiceName)) {
            throw "ArchiveWorker block rule does not cover its exact host on every profile: $($expected.Name)"
        }
        # COM rejects port access for some non-TCP/UDP rules; any-protocol rules
        # cannot restrict ports. Protocol=256 above is the required invariant.
    }
}

# Dot sourcing exposes only the pure contract/validator for inert fixture tests.
if ($MyInvocation.InvocationName -eq '.') { return }
if ([string]::IsNullOrWhiteSpace($InstallRoot)) { throw 'InstallRoot is required.' }
$policy = New-Object -ComObject HNetCfg.FwPolicy2
try {
    $rules = @($policy.Rules)
    Assert-WorkerFirewallRules $rules $InstallRoot
    Write-Output 'Verified all six exact ArchiveWorker inbound/outbound block rules.'
}
finally {
    if ($null -ne $policy -and [Runtime.InteropServices.Marshal]::IsComObject($policy)) {
        [Runtime.InteropServices.Marshal]::FinalReleaseComObject($policy) | Out-Null
    }
}
