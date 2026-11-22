#requires -Version 5.1
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$OutputPath,
    [Parameter(Mandatory = $true)][string]$SigningThumbprint,
    [string]$SourceRoot = '',
    [string]$MinimumEngineVersion = '',
    [int]$ValidDays = 180
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

if ([string]::IsNullOrWhiteSpace($SourceRoot)) {
    $SourceRoot = Split-Path -Parent $PSScriptRoot
}
if ($ValidDays -lt 1 -or $ValidDays -gt 365) {
    throw 'ValidDays must be between 1 and 365.'
}

$managerSource = Get-Content -LiteralPath (Join-Path $SourceRoot 'SteamSentinel.Core\Rules\RulePackageManager.cs') -Raw -Encoding UTF8
if ($managerSource -notmatch 'SigningKeyId = "([A-F0-9]{40})";') {
    throw 'Missing pinned SigningKeyId in RulePackageManager.cs'
}
$expectedThumbprint = $Matches[1]
if ($SigningThumbprint -cne $expectedThumbprint) {
    throw "Signing certificate thumbprint '$SigningThumbprint' differs from embedded key '$expectedThumbprint'."
}

$propsXml = [xml](Get-Content -LiteralPath (Join-Path $SourceRoot 'Directory.Build.props') -Raw -Encoding UTF8)
$productVersion = $propsXml.Project.PropertyGroup.VersionPrefix
if ([string]::IsNullOrWhiteSpace($MinimumEngineVersion)) {
    $MinimumEngineVersion = $productVersion
}

if (Test-Path -LiteralPath $OutputPath) {
    throw "Refusing to overwrite existing rule package: $OutputPath"
}

$certificate = Get-Item -LiteralPath ('Cert:\CurrentUser\My\' + $SigningThumbprint)
if (-not $certificate.HasPrivateKey -or
    $certificate.NotAfter.ToUniversalTime() -le [DateTime]::UtcNow -or
    $certificate.NotBefore.ToUniversalTime() -gt [DateTime]::UtcNow) {
    throw 'A valid publisher certificate with private key in Cert:\CurrentUser\My is required.'
}

$defaultRules = Get-Content -LiteralPath (Join-Path $SourceRoot 'SteamSentinel.Core\Rules\default-rules.json') -Raw -Encoding UTF8 | ConvertFrom-Json
$publishedAt = [DateTimeOffset]::Parse($defaultRules.publishedAtUtc).ToUniversalTime()
$expiresAt = $publishedAt.AddDays($ValidDays)

$payload = [ordered]@{
    schemaVersion = 1
    product = 'SteamSentinel'
    version = [string]$defaultRules.version
    publishedAtUtc = $publishedAt.ToString('yyyy-MM-ddTHH:mm:ssZ')
    expiresAtUtc = $expiresAt.ToString('yyyy-MM-ddTHH:mm:ssZ')
    minimumEngineVersion = $MinimumEngineVersion
    knownHashes = @($defaultRules.knownHashes)
    knownDomains = @($defaultRules.knownDomains)
    knownProcessNames = @($defaultRules.knownProcessNames)
    knownRunValueNames = @($defaultRules.knownRunValueNames)
    knownTaskNames = @($defaultRules.knownTaskNames)
    knownPathTemplates = @($defaultRules.knownPathTemplates)
    suspiciousStrings = @($defaultRules.suspiciousStrings)
    steamInjectionNames = @($defaultRules.steamInjectionNames)
}

$payloadJson = ($payload | ConvertTo-Json -Depth 12 -Compress)
$payloadBytes = [Text.Encoding]::UTF8.GetBytes($payloadJson)
$rsa = [Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($certificate)
try {
    $signature = $rsa.SignData($payloadBytes, [Security.Cryptography.HashAlgorithmName]::SHA256, [Security.Cryptography.RSASignaturePadding]::Pss)
}
finally {
    $rsa.Dispose()
}

$envelope = [ordered]@{
    schemaVersion = 1
    keyId = $SigningThumbprint
    payloadBase64 = [Convert]::ToBase64String($payloadBytes)
    signatureBase64 = [Convert]::ToBase64String($signature)
}

$resolvedOutput = [IO.Path]::GetFullPath($OutputPath)
$parentDir = Split-Path -Parent $resolvedOutput
if (-not [string]::IsNullOrWhiteSpace($parentDir) -and -not (Test-Path -LiteralPath $parentDir)) {
    [IO.Directory]::CreateDirectory($parentDir) | Out-Null
}
[IO.File]::WriteAllText($resolvedOutput, (($envelope | ConvertTo-Json -Compress) + "`r`n"), [Text.UTF8Encoding]::new($false))

[pscustomobject]@{
    file = [IO.Path]::GetFileName($resolvedOutput)
    version = [string]$defaultRules.version
    hashRules = @($defaultRules.knownHashes).Count
    domains = @($defaultRules.knownDomains).Count
    sha256 = (Get-FileHash -LiteralPath $resolvedOutput -Algorithm SHA256).Hash
    keyId = $SigningThumbprint
    expiresAtUtc = $payload.expiresAtUtc
}
