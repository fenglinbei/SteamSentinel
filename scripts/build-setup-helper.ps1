#requires -Version 5.1
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$OutputPath,
    [string]$SourceRoot = ''
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if ($PSVersionTable.PSVersion.Major -ne 5 -or -not [Environment]::Is64BitProcess) {
    throw 'Use x64 Windows PowerShell 5.1 to compile SteamSentinel.SetupHelper.exe.'
}

if ([string]::IsNullOrWhiteSpace($SourceRoot)) {
    $SourceRoot = Split-Path $PSScriptRoot -Parent
}
$sourceRootFull = [IO.Path]::GetFullPath($SourceRoot)
$outputFull = [IO.Path]::GetFullPath($OutputPath)
$outputDir = Split-Path -Parent $outputFull
if (-not (Test-Path -LiteralPath $outputDir -PathType Container)) {
    New-Item -ItemType Directory -Path $outputDir -Force | Out-Null
}

$compiler = Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
if (-not (Test-Path -LiteralPath $compiler -PathType Leaf)) {
    throw "Required .NET Framework 4.8 C# compiler not found: $compiler"
}

$sources = @(
    (Join-Path $sourceRootFull 'installer\SetupHelperMain.cs'),
    (Join-Path $sourceRootFull 'installer\PayloadMaintenance.cs'),
    (Join-Path $sourceRootFull 'installer\MachineStateBootstrap.cs')
)
foreach ($src in $sources) {
    if (-not (Test-Path -LiteralPath $src -PathType Leaf)) {
        throw "SetupHelper source missing: $src"
    }
}

$args = @(
    '/nologo',
    '/target:exe',
    '/platform:x64',
    '/optimize+',
    '/warnaserror+',
    '/reference:System.dll',
    '/reference:System.Core.dll',
    '/reference:System.Web.Extensions.dll',
    "/out:$outputFull"
) + $sources

$buildOutput = & $compiler @args 2>&1
if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $outputFull -PathType Leaf)) {
    throw "SetupHelper compilation failed (exit=$LASTEXITCODE): $($buildOutput | Out-String)"
}

# 断言生产二进制绝不包含 STEAMSENTINEL_INSTALLER_TESTS 测试入口
$bytes = [IO.File]::ReadAllBytes($outputFull)
$assembly = [Reflection.Assembly]::ReflectionOnlyLoad($bytes)
$payloadType = $assembly.GetType('SteamSentinelPayloadMaintenance', $true)
$stateType = $assembly.GetType('SteamSentinelMachineStateBootstrap', $true)
foreach ($forbidden in @('RunForTest', 'RunForTestWithPrevious', 'GetCatalogForTest')) {
    if ($null -ne $payloadType.GetMethod($forbidden)) {
        throw "Production SetupHelper must not expose test-only method: $forbidden"
    }
}
foreach ($forbidden in @('RunForTests', 'RunForTestsWithOptions')) {
    if ($null -ne $stateType.GetMethod($forbidden)) {
        throw "Production SetupHelper must not expose test-only method: $forbidden"
    }
}
$stateRun = $stateType.GetMethod('Run')
if ($null -eq $stateRun -or $stateRun.GetParameters().Count -ne 1) {
    throw 'Production SteamSentinelMachineStateBootstrap.Run signature mismatch.'
}

$sha256 = (Get-FileHash -LiteralPath $outputFull -Algorithm SHA256).Hash
[pscustomobject]@{
    schema = 'SteamSentinel.SetupHelperBuild/1'
    path = $outputFull
    sha256 = $sha256
    bytes = $bytes.Length
}
