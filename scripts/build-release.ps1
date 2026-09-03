[CmdletBinding()]
param(
    [string]$OutputRoot,
    [switch]$ReplaceExisting
)

$ErrorActionPreference = 'Stop'
$solutionRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path
$workspaceRoot = (Resolve-Path -LiteralPath (Join-Path $solutionRoot '..\..')).Path
if ([string]::IsNullOrWhiteSpace($OutputRoot)) {
    $OutputRoot = Join-Path $workspaceRoot 'outputs'
}
$OutputRoot = [IO.Path]::GetFullPath($OutputRoot)
$packageName = 'SteamSentinel-0.1.3-win-x64'
$packageDir = Join-Path $OutputRoot $packageName
$archivePath = Join-Path $OutputRoot ($packageName + '.zip')
$sourceArchivePath = Join-Path $OutputRoot 'SteamSentinel-0.1.3-source.zip'
$archiveChecksumPath = Join-Path $OutputRoot 'SteamSentinel-0.1.3-ARCHIVE-SHA256.txt'

function Assert-ChildPath([string]$Candidate, [string]$Parent) {
    $candidateFull = [IO.Path]::GetFullPath($Candidate)
    $parentFull = [IO.Path]::GetFullPath($Parent).TrimEnd('\')
    if (-not $candidateFull.StartsWith($parentFull + '\', [StringComparison]::OrdinalIgnoreCase)) {
        throw "拒绝操作预期目录之外的路径：$candidateFull"
    }
}

foreach ($target in @($packageDir, $archivePath, $sourceArchivePath, $archiveChecksumPath)) {
    Assert-ChildPath $target $OutputRoot
    if (Test-Path -LiteralPath $target) {
        if (-not $ReplaceExisting) { throw "输出已存在，拒绝覆盖：$target" }
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
    if ($LASTEXITCODE -ne 0) { throw "dotnet 命令失败，退出码 $LASTEXITCODE" }
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
Copy-Item -LiteralPath (Join-Path $solutionRoot 'README.md') -Destination (Join-Path $packageDir 'README.md')
Copy-Item -LiteralPath (Join-Path $solutionRoot 'LICENSE') -Destination $packageDir
Copy-Item -LiteralPath (Join-Path $solutionRoot 'NOTICE') -Destination $packageDir
Copy-Item -LiteralPath (Join-Path $solutionRoot 'THIRD-PARTY-NOTICES.md') -Destination $packageDir
Copy-Item -LiteralPath (Join-Path $solutionRoot 'LICENSE-STATUS.md') -Destination $packageDir
Copy-Item -LiteralPath (Join-Path $solutionRoot 'docs\THREAT-MODEL.md') -Destination $packageDir
Copy-Item -LiteralPath (Join-Path $solutionRoot 'docs\TEST-EVIDENCE.md') -Destination $packageDir
Copy-Item -LiteralPath (Join-Path $solutionRoot 'docs\RELEASE-CHECKLIST.md') -Destination $packageDir

$dotnetRoot = Split-Path -Parent (Get-Command dotnet).Source
$sdkVersion = (& dotnet --version).Trim()
Copy-Item -LiteralPath (Join-Path $dotnetRoot 'LICENSE.txt') -Destination (Join-Path $packageDir 'DOTNET-LICENSE.txt')
Copy-Item -LiteralPath (Join-Path $dotnetRoot 'ThirdPartyNotices.txt') -Destination (Join-Path $packageDir 'DOTNET-THIRD-PARTY-NOTICES.txt')
Copy-Item -LiteralPath (Join-Path $dotnetRoot "sdk\$sdkVersion\Sdks\Microsoft.NET.Sdk.WindowsDesktop\THIRD-PARTY-NOTICES.TXT") -Destination (Join-Path $packageDir 'WINDOWSDESKTOP-THIRD-PARTY-NOTICES.txt')

$versionLines = @(
    'Product=SteamSentinel',
    'Version=0.1.3',
    'Rules=2026.09.03.3',
    'Runtime=win-x64 self-contained .NET 10',
    ('BuiltAtUtc=' + [DateTimeOffset]::UtcNow.ToString('O')),
    'SignatureStatus=UNSIGNED REVIEW BUILD'
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

Get-ChildItem -LiteralPath $solutionRoot -Recurse -File |
    Where-Object { $_.FullName -notmatch '[\\/](bin|obj)[\\/]' } |
    ForEach-Object {
        $relative = $_.FullName.Substring($solutionRoot.Length).TrimStart('\', '/')
        $destination = Join-Path $sourceStage $relative
        New-Item -ItemType Directory -Path (Split-Path -Parent $destination) -Force | Out-Null
        Copy-Item -LiteralPath $_.FullName -Destination $destination
    }
[IO.Compression.ZipFile]::CreateFromDirectory((Split-Path -Parent $sourceStage), $sourceArchivePath,
    [IO.Compression.CompressionLevel]::Optimal, $false)

$archiveHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $archivePath).Hash
$sourceHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $sourceArchivePath).Hash
[IO.File]::WriteAllLines($archiveChecksumPath, @(
    "$archiveHash *$([IO.Path]::GetFileName($archivePath))",
    "$sourceHash *$([IO.Path]::GetFileName($sourceArchivePath))"
), [Text.UTF8Encoding]::new($false))

$workRoot = [IO.Path]::GetFullPath((Join-Path $workspaceRoot 'work'))
Assert-ChildPath $stageRoot $workRoot
if (Test-Path -LiteralPath $stageRoot) { Remove-Item -LiteralPath $stageRoot -Recurse -Force }

Write-Host "PACKAGE_DIR=$packageDir"
Write-Host "BINARY_ZIP=$archivePath"
Write-Host "SOURCE_ZIP=$sourceArchivePath"
