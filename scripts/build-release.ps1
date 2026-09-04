[CmdletBinding()]
param(
    [string]$OutputRoot,
    [switch]$ReplaceExisting,
    [switch]$SkipInstaller,
    [string]$SigningThumbprint,
    [string]$SignToolPath
)

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'code-signing.ps1')
$signingProfile = Get-ReleaseSigningProfile $SigningThumbprint $SignToolPath
$solutionRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path
$workspaceRoot = (Resolve-Path -LiteralPath (Join-Path $solutionRoot '..\..')).Path
if ([string]::IsNullOrWhiteSpace($OutputRoot)) {
    $OutputRoot = Join-Path $workspaceRoot 'outputs'
}
$OutputRoot = [IO.Path]::GetFullPath($OutputRoot)
$version = '0.1.16'
$packageName = "SteamSentinel-$version-win-x64"
$packageDir = Join-Path $OutputRoot $packageName
$archivePath = Join-Path $OutputRoot ($packageName + '.zip')
$sourceArchivePath = Join-Path $OutputRoot "SteamSentinel-$version-source.zip"
$setupPath = Join-Path $OutputRoot "SteamSentinel-$version-setup.exe"
$archiveChecksumPath = Join-Path $OutputRoot "SteamSentinel-$version-RELEASE-SHA256.txt"

function Assert-ChildPath([string]$Candidate, [string]$Parent) {
    $candidateFull = [IO.Path]::GetFullPath($Candidate)
    $parentFull = [IO.Path]::GetFullPath($Parent).TrimEnd('\')
    if (-not $candidateFull.StartsWith($parentFull + '\', [StringComparison]::OrdinalIgnoreCase)) {
        throw "Refusing to operate outside the expected output root: $candidateFull"
    }
}

$targets = @($packageDir, $archivePath, $sourceArchivePath, $archiveChecksumPath)
if (-not $SkipInstaller) { $targets += $setupPath }
foreach ($target in $targets) {
    Assert-ChildPath $target $OutputRoot
    if (Test-Path -LiteralPath $target) {
        if (-not $ReplaceExisting) { throw "Output already exists; refusing to overwrite: $target" }
        Remove-Item -LiteralPath $target -Recurse -Force
    }
}

$stageRoot = Join-Path $workspaceRoot ('work\release-' + [Guid]::NewGuid().ToString('N'))
$runtimeStage = Join-Path $stageRoot 'runtime'
$sourceStage = Join-Path $stageRoot 'source\SteamSentinel'
New-Item -ItemType Directory -Path $runtimeStage, $sourceStage, $OutputRoot, $packageDir -Force | Out-Null

function Invoke-DotNet {
    param([Parameter(ValueFromRemainingArguments = $true)][string[]]$Arguments)
    & dotnet @Arguments
    if ($LASTEXITCODE -ne 0) { throw "dotnet failed with exit code $LASTEXITCODE" }
}

$nuget = 'https://api.nuget.org/v3/index.json'
$solution = Join-Path $solutionRoot 'SteamSentinel.slnx'
Invoke-DotNet restore $solution '--source' $nuget
Invoke-DotNet build $solution '-c' 'Release' '--no-restore'
Invoke-DotNet run '--project' (Join-Path $solutionRoot 'SteamSentinel.SelfTest\SteamSentinel.SelfTest.csproj') '-c' 'Release' '--no-build'
Invoke-DotNet restore $solution '--source' $nuget '-r' 'win-x64'

$publishArgs = @('-c', 'Release', '-r', 'win-x64', '--self-contained', 'true', '--no-restore',
    '-p:PublishSingleFile=false', '-p:PublishTrimmed=false',
    '-p:DebugType=None', '-p:DebugSymbols=false')
Invoke-DotNet publish (Join-Path $solutionRoot 'SteamSentinel.App\SteamSentinel.App.csproj') @publishArgs '-o' $runtimeStage
Invoke-DotNet publish (Join-Path $solutionRoot 'SteamSentinel.ArchiveWorker\SteamSentinel.ArchiveWorker.csproj') @publishArgs '-o' $runtimeStage
Invoke-DotNet publish (Join-Path $solutionRoot 'SteamSentinel.Broker\SteamSentinel.Broker.csproj') @publishArgs '-o' $runtimeStage

Copy-Item -Path (Join-Path $runtimeStage '*') -Destination $packageDir -Recurse
Sign-ReleaseFiles $signingProfile $packageDir @('SteamSentinel.exe', 'SteamSentinel.dll', 'SteamSentinel.Core.dll',
    'SteamSentinel.ArchiveWorker.exe', 'SteamSentinel.ArchiveWorker.dll', 'SteamSentinel.Broker.exe', 'SteamSentinel.Broker.dll')
$signatureStatus = Write-ReleaseSigningInfo $signingProfile $packageDir
Copy-Item -LiteralPath (Join-Path $solutionRoot 'SteamSentinel.App\Assets') -Destination (Join-Path $packageDir 'Assets') -Recurse
Copy-Item -LiteralPath (Join-Path $solutionRoot 'README.md') -Destination (Join-Path $packageDir 'README.md')
Copy-Item -LiteralPath (Join-Path $solutionRoot 'CHANGELOG.md') -Destination (Join-Path $packageDir 'CHANGELOG.md')
Copy-Item -LiteralPath (Join-Path $solutionRoot 'LICENSE') -Destination $packageDir
Copy-Item -LiteralPath (Join-Path $solutionRoot 'NOTICE') -Destination $packageDir
Copy-Item -LiteralPath (Join-Path $solutionRoot 'THIRD-PARTY-NOTICES.md') -Destination $packageDir
Copy-Item -LiteralPath (Join-Path $solutionRoot 'LICENSE-STATUS.md') -Destination $packageDir
Copy-Item -LiteralPath (Join-Path $solutionRoot 'docs\THREAT-MODEL.md') -Destination $packageDir
Copy-Item -LiteralPath (Join-Path $solutionRoot 'docs\TEST-EVIDENCE.md') -Destination $packageDir
Copy-Item -LiteralPath (Join-Path $solutionRoot 'docs\RELEASE-CHECKLIST.md') -Destination $packageDir
Copy-Item -LiteralPath (Join-Path $solutionRoot 'docs\GROUP-TEST-GUIDE.md') -Destination $packageDir
Copy-Item -LiteralPath (Join-Path $solutionRoot 'docs\SAMPLE-COVERAGE-0.1.5.md') -Destination $packageDir
Copy-Item -LiteralPath (Join-Path $solutionRoot 'docs\PASSWORD-REGRESSION-0.1.6.md') -Destination $packageDir
Copy-Item -LiteralPath (Join-Path $solutionRoot 'docs\INSTALLATION-REGRESSION-0.1.7.md') -Destination $packageDir
Copy-Item -LiteralPath (Join-Path $solutionRoot 'docs\WORKER-STARTUP-0.1.8.md') -Destination $packageDir
Copy-Item -LiteralPath (Join-Path $solutionRoot 'docs\SIGNING.md') -Destination $packageDir
Copy-Item -LiteralPath (Join-Path $solutionRoot 'docs\ROADMAP.md') -Destination $packageDir
Copy-Item -LiteralPath (Join-Path $solutionRoot 'docs\COVERAGE-0.1.13.md') -Destination $packageDir
Copy-Item -LiteralPath (Join-Path $solutionRoot 'docs\COVERAGE-0.1.14.md') -Destination $packageDir
Copy-Item -LiteralPath (Join-Path $solutionRoot 'docs\COVERAGE-0.1.15.md') -Destination $packageDir
Copy-Item -LiteralPath (Join-Path $solutionRoot 'docs\COVERAGE-0.1.16.md') -Destination $packageDir
Copy-Item -LiteralPath (Join-Path $solutionRoot 'docs\ICONS.md') -Destination $packageDir

$dotnetRoot = Split-Path -Parent (Get-Command dotnet).Source
$sdkVersion = (& dotnet --version).Trim()
Copy-Item -LiteralPath (Join-Path $dotnetRoot 'LICENSE.txt') -Destination (Join-Path $packageDir 'DOTNET-LICENSE.txt')
Copy-Item -LiteralPath (Join-Path $dotnetRoot 'ThirdPartyNotices.txt') -Destination (Join-Path $packageDir 'DOTNET-THIRD-PARTY-NOTICES.txt')
Copy-Item -LiteralPath (Join-Path $dotnetRoot "sdk\$sdkVersion\Sdks\Microsoft.NET.Sdk.WindowsDesktop\THIRD-PARTY-NOTICES.TXT") -Destination (Join-Path $packageDir 'WINDOWSDESKTOP-THIRD-PARTY-NOTICES.txt')

$versionLines = @(
    'Product=SteamSentinel',
    "Version=$version",
    'Rules=2026.09.04.2',
    'Runtime=win-x64 self-contained .NET 10',
    ('BuiltAtUtc=' + [DateTimeOffset]::UtcNow.ToString('O')),
    "SignatureStatus=$signatureStatus"
)
[IO.File]::WriteAllLines((Join-Path $packageDir 'VERSION.txt'), $versionLines, [Text.UTF8Encoding]::new($false))

$hashLines = Get-ChildItem -LiteralPath $packageDir -Recurse -File |
    Where-Object Name -ne 'SHA256SUMS.txt' |
    Sort-Object FullName |
    ForEach-Object {
        $relative = $_.FullName.Substring($packageDir.Length).TrimStart('\', '/')
        '{0} *{1}' -f (Get-FileHash -Algorithm SHA256 -LiteralPath $_.FullName).Hash, $relative
    }
[IO.File]::WriteAllLines((Join-Path $packageDir 'SHA256SUMS.txt'), $hashLines, [Text.UTF8Encoding]::new($false))

Add-Type -AssemblyName System.IO.Compression.FileSystem
[IO.Compression.ZipFile]::CreateFromDirectory($packageDir, $archivePath, [IO.Compression.CompressionLevel]::Optimal, $true)

Get-ChildItem -LiteralPath $solutionRoot -Recurse -Force -File |
    Where-Object { $_.FullName -notmatch '[\\/](bin|obj|artifacts|\.git)[\\/]' -and $_.Extension -notin @('.pfx', '.p12', '.key') } |
    ForEach-Object {
        $relative = $_.FullName.Substring($solutionRoot.Length).TrimStart('\', '/')
        $destination = Join-Path $sourceStage $relative
        New-Item -ItemType Directory -Path (Split-Path -Parent $destination) -Force | Out-Null
        Copy-Item -LiteralPath $_.FullName -Destination $destination
    }
[IO.Compression.ZipFile]::CreateFromDirectory((Split-Path -Parent $sourceStage), $sourceArchivePath,
    [IO.Compression.CompressionLevel]::Optimal, $false)

if (-not $SkipInstaller) {
    $isccCandidates = @(
        (Get-Command ISCC.exe -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Source -ErrorAction SilentlyContinue),
        (Join-Path $env:LOCALAPPDATA 'Programs\Inno Setup 6\ISCC.exe'),
        'C:\Program Files (x86)\Inno Setup 6\ISCC.exe',
        'C:\Program Files\Inno Setup 6\ISCC.exe'
    ) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) -and (Test-Path -LiteralPath $_) }
    $iscc = $isccCandidates | Select-Object -First 1
    if ([string]::IsNullOrWhiteSpace($iscc)) {
        throw 'Inno Setup 6 compiler was not found. Install it or use -SkipInstaller for development-only builds.'
    }
    $installerScript = Join-Path $solutionRoot 'installer\SteamSentinel.iss'
    $signArgs = @(Get-InnoSigningArguments $signingProfile)
    if ($null -ne $signingProfile) { New-Item -ItemType Directory -Force -Path (Join-Path $OutputRoot 'signing-cache\SteamSentinel') | Out-Null }
    & $iscc "/DPayloadDir=$packageDir" "/DOutputDir=$OutputRoot" "/DAppVersion=$version" @signArgs $installerScript
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $setupPath)) {
        throw "Installer compilation failed with exit code $LASTEXITCODE"
    }
}

$archiveHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $archivePath).Hash
$sourceHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $sourceArchivePath).Hash
$releaseHashes = @(
    "$archiveHash *$([IO.Path]::GetFileName($archivePath))",
    "$sourceHash *$([IO.Path]::GetFileName($sourceArchivePath))"
)
if (-not $SkipInstaller) {
    $setupHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $setupPath).Hash
    $releaseHashes += "$setupHash *$([IO.Path]::GetFileName($setupPath))"
}
[IO.File]::WriteAllLines($archiveChecksumPath, $releaseHashes, [Text.UTF8Encoding]::new($false))

$workRoot = [IO.Path]::GetFullPath((Join-Path $workspaceRoot 'work'))
Assert-ChildPath $stageRoot $workRoot
if (Test-Path -LiteralPath $stageRoot) { Remove-Item -LiteralPath $stageRoot -Recurse -Force }

Write-Host "PACKAGE_DIR=$packageDir"
Write-Host "BINARY_ZIP=$archivePath"
Write-Host "SOURCE_ZIP=$sourceArchivePath"
if (-not $SkipInstaller) { Write-Host "SETUP=$setupPath" }
