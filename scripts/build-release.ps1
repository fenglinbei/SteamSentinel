[CmdletBinding()]
param(
    [ValidateSet('Preview', 'Release')]
    [string]$Mode = 'Preview',
    [string]$OutputRoot,
    [Alias('AllowTrackedDirtyPreview')]
    [switch]$AllowDirtyPreview,
    [switch]$SkipInstaller,
    [string]$SigningThumbprint,
    [string]$SignToolPath,
    [string]$TimestampUrl
)

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'code-signing.ps1')

function Assert-ChildPath {
    param(
        [Parameter(Mandatory = $true)][string]$Candidate,
        [Parameter(Mandatory = $true)][string]$Parent
    )

    $candidateFull = [IO.Path]::GetFullPath($Candidate)
    $parentFull = [IO.Path]::GetFullPath($Parent).TrimEnd('\')
    if (-not $candidateFull.StartsWith($parentFull + '\', [StringComparison]::OrdinalIgnoreCase)) {
        throw "Refusing to operate outside the expected root: $candidateFull"
    }
}

function Invoke-DotNet {
    param([Parameter(ValueFromRemainingArguments = $true)][string[]]$Arguments)

    & dotnet @Arguments
    if ($LASTEXITCODE -ne 0) { throw "dotnet failed with exit code $LASTEXITCODE" }
}

function Invoke-Git {
    param([Parameter(ValueFromRemainingArguments = $true)][string[]]$Arguments)

    $output = & git -C $script:solutionRoot @Arguments
    if ($LASTEXITCODE -ne 0) { throw "git failed with exit code ${LASTEXITCODE}: git $($Arguments -join ' ')" }
    return $output
}

function Assert-PreviewSourcePathAllowed {
    param([Parameter(Mandatory = $true)][string]$Path)

    $normalized = $Path.Replace('\', '/')
    $allowed =
        $normalized -match '^SteamSentinel\.(App|ArchiveWorker|Broker|Core|SelfTest)/.+\.cs$' -or
        $normalized -match '^SteamSentinel\.(App|ArchiveWorker|Broker|Core|SelfTest)/[^/]+\.csproj$' -or
        $normalized -match '^SteamSentinel\.(App|ArchiveWorker|Broker|Core|SelfTest)/packages\.lock\.json$' -or
        $normalized -eq 'Directory.Build.props' -or
        $normalized -eq 'global.json' -or
        $normalized -eq '.editorconfig' -or
        $normalized -match '^docs/[^/]+\.md$' -or
        $normalized -match '^scripts/[^/]+\.ps1$' -or
        $normalized -match '^\.github/workflows/[^/]+\.(yml|yaml)$'
    if (-not $allowed) {
        throw "Dirty Preview refuses added file outside the source allowlist: $Path"
    }
}

function Get-WorktreeSnapshotTree {
    param([Parameter(Mandatory = $true)][string]$TemporaryIndexPath)

    $oldIndex = $env:GIT_INDEX_FILE
    try {
        $env:GIT_INDEX_FILE = $TemporaryIndexPath
        Invoke-Git read-tree HEAD | Out-Null
        Invoke-Git -Arguments @('add', '-A', '--', '.') | Out-Null
        $addedPaths = @(Invoke-Git -c core.quotepath=false diff --cached --name-only --diff-filter=A --)
        foreach ($path in $addedPaths) { Assert-PreviewSourcePathAllowed -Path $path }
        return (Invoke-Git write-tree).Trim()
    }
    finally {
        if ($null -eq $oldIndex) { Remove-Item Env:GIT_INDEX_FILE -ErrorAction SilentlyContinue }
        else { $env:GIT_INDEX_FILE = $oldIndex }
    }
}

function Assert-UntrackedPreviewAllowlist {
    $untracked = @(& git -C $script:solutionRoot -c core.quotepath=false ls-files --others --exclude-standard)
    if ($LASTEXITCODE -ne 0) { throw "Unable to enumerate untracked files ($LASTEXITCODE)." }
    foreach ($path in $untracked) { Assert-PreviewSourcePathAllowed -Path $path }
}

function Write-Utf8Lines {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string[]]$Lines
    )

    [IO.File]::WriteAllLines($Path, $Lines, [Text.UTF8Encoding]::new($false))
}

$solutionRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path
$workspaceRoot = (Resolve-Path -LiteralPath (Join-Path $solutionRoot '..\..')).Path
$propsPath = Join-Path $solutionRoot 'Directory.Build.props'
[xml]$props = Get-Content -LiteralPath $propsPath -Raw
$version = [string]$props.Project.PropertyGroup.VersionPrefix
$minimumSelfTests = [int]$props.Project.PropertyGroup.SteamSentinelMinimumSelfTests
if ($version -notmatch '^\d+\.\d+\.\d+$') {
    throw "Directory.Build.props has an invalid VersionPrefix: $version"
}
if ($minimumSelfTests -lt 1) { throw 'Directory.Build.props has an invalid SteamSentinelMinimumSelfTests value.' }

$expectedSdk = [string]((Get-Content -LiteralPath (Join-Path $solutionRoot 'global.json') -Raw | ConvertFrom-Json).sdk.version)
$actualSdk = (& dotnet --version).Trim()
if ($LASTEXITCODE -ne 0 -or $actualSdk -ne $expectedSdk) {
    throw "The pinned .NET SDK is required (expected $expectedSdk; actual $actualSdk)."
}

$isPublicRelease = $Mode -eq 'Release'
if ($isPublicRelease -and $SkipInstaller) {
    throw 'Release mode cannot omit the installer. Use Preview mode for development artifacts.'
}
if ($isPublicRelease -and $AllowDirtyPreview) {
    throw 'Release mode never accepts a dirty working tree.'
}
if (-not [string]::IsNullOrWhiteSpace($TimestampUrl) -and [string]::IsNullOrWhiteSpace($SigningThumbprint)) {
    throw 'A timestamp URL is meaningful only when a signing certificate is explicitly selected.'
}

$commit = (Invoke-Git rev-parse 'HEAD^{commit}').Trim()
$shortCommit = (Invoke-Git rev-parse --short=12 HEAD).Trim()
$commitTime = (Invoke-Git show -s '--format=%cI' HEAD).Trim()
$statusLines = @(Invoke-Git status --porcelain=v1 --untracked-files=all)
$isDirty = $statusLines.Count -gt 0
$tag = "v$version"

if ($isPublicRelease) {
    if ($isDirty) { throw 'Release mode requires a completely clean working tree, including untracked files.' }
    $exactTag = (Invoke-Git describe --tags --exact-match --match $tag HEAD).Trim()
    if ($exactTag -ne $tag) { throw "HEAD must be exactly at $tag." }
    $tagType = (Invoke-Git cat-file -t "refs/tags/$tag").Trim()
    if ($tagType -ne 'tag') { throw "Public release tag $tag must be an annotated tag." }
    & git -C $solutionRoot tag -v $tag
    if ($LASTEXITCODE -ne 0) { throw "Public release tag $tag is not cryptographically verified." }
}
elseif ($isDirty -and -not $AllowDirtyPreview) {
    throw 'The working tree is dirty. Commit it, or explicitly use -AllowDirtyPreview for a provenance-labelled preview.'
}
if ($isDirty) { Assert-UntrackedPreviewAllowlist }

if ([string]::IsNullOrWhiteSpace($OutputRoot)) {
    $OutputRoot = if ($isPublicRelease) {
        Join-Path $workspaceRoot 'outputs\releases'
    }
    else {
        Join-Path $workspaceRoot 'previews'
    }
}
$OutputRoot = [IO.Path]::GetFullPath($OutputRoot)
$solutionRootPrefix = $solutionRoot.TrimEnd('\') + '\'
if ($OutputRoot.TrimEnd('\') -eq $solutionRoot.TrimEnd('\') -or
    $OutputRoot.StartsWith($solutionRootPrefix, [StringComparison]::OrdinalIgnoreCase)) {
    throw 'The release output root must be outside the source repository.'
}
$volumeRoot = [IO.Path]::GetPathRoot($OutputRoot).TrimEnd('\')
if ($OutputRoot.TrimEnd('\') -eq $volumeRoot) {
    throw 'A volume root cannot be used as the release output root.'
}
New-Item -ItemType Directory -Path $OutputRoot -Force | Out-Null
$outputRootItem = Get-Item -LiteralPath $OutputRoot
if ($outputRootItem.Attributes -band [IO.FileAttributes]::ReparsePoint) {
    throw 'The release output root must not be a reparse point.'
}

$stageRoot = Join-Path $OutputRoot ('.staging-' + [Guid]::NewGuid().ToString('N'))
$workRoot = Join-Path $stageRoot '_work'
$sourceExtractRoot = Join-Path $workRoot 'source'
$runtimeStage = Join-Path $workRoot 'runtime'
$temporaryIndex = Join-Path $workRoot 'snapshot.index'
New-Item -ItemType Directory -Path $stageRoot, $workRoot, $sourceExtractRoot, $runtimeStage -Force | Out-Null
Assert-ChildPath $stageRoot $OutputRoot

$completed = $false
try {
    if ($isDirty) {
        $sourceTree = Get-WorktreeSnapshotTree -TemporaryIndexPath $temporaryIndex
    }
    else {
        $sourceTree = (Invoke-Git rev-parse 'HEAD^{tree}').Trim()
    }
    $treeShort = $sourceTree.Substring(0, 12)

    if ($isPublicRelease) {
        $buildChannel = 'release'
        $buildId = "$commit.release"
        $artifactVersion = $version
        $bundleName = "SteamSentinel-$version-release-$shortCommit"
    }
    elseif ($isDirty) {
        $buildChannel = 'dirty.preview'
        $buildId = "$commit.dirty.preview.$treeShort"
        $artifactVersion = "$version-preview-$shortCommit-dirty-$treeShort"
        $bundleName = "SteamSentinel-$artifactVersion"
    }
    else {
        $buildChannel = 'preview'
        $buildId = "$commit.preview"
        $artifactVersion = "$version-preview-$shortCommit"
        $bundleName = "SteamSentinel-$artifactVersion"
    }
    $buildIdentity = "$version+$buildId"
    $finalBundlePath = Join-Path $OutputRoot $bundleName
    Assert-ChildPath $finalBundlePath $OutputRoot
    if (Test-Path -LiteralPath $finalBundlePath) {
        throw "Output already exists; immutable artifacts are never overwritten: $finalBundlePath"
    }

    $packageName = "SteamSentinel-$artifactVersion-win-x64"
    $packageDir = Join-Path $stageRoot $packageName
    $archivePath = Join-Path $stageRoot ($packageName + '.zip')
    $sourceArchivePath = Join-Path $stageRoot "SteamSentinel-$artifactVersion-source.zip"
    $setupPath = Join-Path $stageRoot "SteamSentinel-$artifactVersion-setup.exe"
    $checksumPath = Join-Path $stageRoot "SteamSentinel-$artifactVersion-RELEASE-SHA256.txt"
    $metadataPath = Join-Path $stageRoot 'RELEASE-METADATA.json'
    $selfTestPath = Join-Path $stageRoot 'SELFTEST-RESULTS.json'
    New-Item -ItemType Directory -Path $packageDir -Force | Out-Null

    & git -C $solutionRoot archive --format=zip --prefix=SteamSentinel/ -o $sourceArchivePath $sourceTree
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $sourceArchivePath -PathType Leaf)) {
        throw 'git archive failed to create the exact source snapshot.'
    }

    Add-Type -AssemblyName System.IO.Compression.FileSystem
    [IO.Compression.ZipFile]::ExtractToDirectory($sourceArchivePath, $sourceExtractRoot)
    $snapshotRoot = Join-Path $sourceExtractRoot 'SteamSentinel'
    if (-not (Test-Path -LiteralPath (Join-Path $snapshotRoot 'SteamSentinel.slnx') -PathType Leaf)) {
        throw 'The source archive did not contain the expected repository root.'
    }

    [xml]$snapshotProps = Get-Content -LiteralPath (Join-Path $snapshotRoot 'Directory.Build.props') -Raw
    if ([string]$snapshotProps.Project.PropertyGroup.VersionPrefix -ne $version) {
        throw 'The source snapshot version differs from the version used to name artifacts.'
    }

    $signingProfile = Get-ReleaseSigningProfile -Thumbprint $SigningThumbprint `
        -SignToolPath $SignToolPath -TimestampUrl $TimestampUrl -RequirePublicTrust:$isPublicRelease
    $solution = Join-Path $snapshotRoot 'SteamSentinel.slnx'
    $msbuildProperties = @(
        "-p:SteamSentinelSourceRevision=$commit",
        "-p:SteamSentinelBuildChannel=$buildChannel",
        "-p:SteamSentinelBuildId=$buildId",
        '-p:ContinuousIntegrationBuild=true'
    )
    $nuget = 'https://api.nuget.org/v3/index.json'
    Invoke-DotNet restore $solution '--locked-mode' '--source' $nuget '-r' 'win-x64' `
        '-p:NuGetAudit=true' '-p:NuGetAuditMode=all' `
        @msbuildProperties
    Invoke-DotNet build $solution '-c' 'Release' '--no-restore' @msbuildProperties
    Invoke-DotNet run '--project' (Join-Path $snapshotRoot 'SteamSentinel.SelfTest\SteamSentinel.SelfTest.csproj') `
        '-c' 'Release' '--no-build' '--' '--results' $selfTestPath

    if (-not (Test-Path -LiteralPath $selfTestPath -PathType Leaf)) {
        throw 'SelfTest did not create its machine-readable result.'
    }
    $selfTest = Get-Content -LiteralPath $selfTestPath -Raw | ConvertFrom-Json
    if ($null -eq $selfTest.PSObject.Properties['elapsedMs'] -or [long]$selfTest.elapsedMs -lt 0) {
        throw 'SelfTest result is missing a valid elapsedMs value.'
    }
    if ([int]$selfTest.failed -ne 0 -or [int]$selfTest.passed -lt $minimumSelfTests -or [int]$selfTest.skipped -ne 0) {
        throw "SelfTest baseline failed (passed=$($selfTest.passed), failed=$($selfTest.failed), skipped=$($selfTest.skipped))."
    }
    if ($selfTest.version -ne $version -or $selfTest.buildIdentity -ne $buildIdentity) {
        throw "SelfTest provenance mismatch (version=$($selfTest.version), buildIdentity=$($selfTest.buildIdentity))."
    }

    $publishArgs = @(
        '-c', 'Release', '-r', 'win-x64', '--self-contained', 'true', '--no-restore',
        '-p:PublishSingleFile=false', '-p:PublishTrimmed=false',
        '-p:DebugType=None', '-p:DebugSymbols=false'
    ) + $msbuildProperties
    Invoke-DotNet publish (Join-Path $snapshotRoot 'SteamSentinel.App\SteamSentinel.App.csproj') `
        @publishArgs '-o' $runtimeStage
    Invoke-DotNet publish (Join-Path $snapshotRoot 'SteamSentinel.ArchiveWorker\SteamSentinel.ArchiveWorker.csproj') `
        @publishArgs '-o' $runtimeStage
    Invoke-DotNet publish (Join-Path $snapshotRoot 'SteamSentinel.Broker\SteamSentinel.Broker.csproj') `
        @publishArgs '-o' $runtimeStage

    $versionedAssemblies = @(
        'SteamSentinel.dll',
        'SteamSentinel.Core.dll',
        'SteamSentinel.ArchiveWorker.dll',
        'SteamSentinel.Broker.dll'
    )
    foreach ($relative in $versionedAssemblies) {
        $publishedAssembly = Join-Path $runtimeStage $relative
        if (-not (Test-Path -LiteralPath $publishedAssembly -PathType Leaf)) {
            throw "Published assembly is missing: $relative"
        }
        $versionInfo = (Get-Item -LiteralPath $publishedAssembly).VersionInfo
        if ($versionInfo.FileVersion -ne "$version.0" -or $versionInfo.ProductVersion -ne $buildIdentity) {
            throw "Published version mismatch for $relative (FileVersion=$($versionInfo.FileVersion); ProductVersion=$($versionInfo.ProductVersion))."
        }
    }

    Copy-Item -Path (Join-Path $runtimeStage '*') -Destination $packageDir -Recurse
    Sign-ReleaseFiles -Profile $signingProfile -Root $packageDir -RelativeFiles @(
        'SteamSentinel.exe', 'SteamSentinel.dll', 'SteamSentinel.Core.dll',
        'SteamSentinel.ArchiveWorker.exe', 'SteamSentinel.ArchiveWorker.dll',
        'SteamSentinel.Broker.exe', 'SteamSentinel.Broker.dll'
    )
    $signatureStatus = Write-ReleaseSigningInfo -Profile $signingProfile -Root $packageDir

    $packageAssets = Join-Path $packageDir 'SteamSentinel.App\Assets'
    New-Item -ItemType Directory -Path $packageAssets -Force | Out-Null
    Copy-Item -Path (Join-Path $snapshotRoot 'SteamSentinel.App\Assets\*') `
        -Destination $packageAssets -Recurse
    foreach ($name in @('README.md', 'CHANGELOG.md', 'LICENSE', 'NOTICE', 'THIRD-PARTY-NOTICES.md', 'LICENSE-STATUS.md')) {
        Copy-Item -LiteralPath (Join-Path $snapshotRoot $name) -Destination (Join-Path $packageDir $name)
    }
    $packageDocs = Join-Path $packageDir 'docs'
    New-Item -ItemType Directory -Path $packageDocs -Force | Out-Null
    Copy-Item -Path (Join-Path $snapshotRoot 'docs\*') -Destination $packageDocs -Recurse

    $dotnetRoot = Split-Path -Parent (Get-Command dotnet).Source
    Copy-Item -LiteralPath (Join-Path $dotnetRoot 'LICENSE.txt') -Destination (Join-Path $packageDir 'DOTNET-LICENSE.txt')
    Copy-Item -LiteralPath (Join-Path $dotnetRoot 'ThirdPartyNotices.txt') -Destination (Join-Path $packageDir 'DOTNET-THIRD-PARTY-NOTICES.txt')
    Copy-Item -LiteralPath (Join-Path $dotnetRoot "sdk\$actualSdk\Sdks\Microsoft.NET.Sdk.WindowsDesktop\THIRD-PARTY-NOTICES.TXT") `
        -Destination (Join-Path $packageDir 'WINDOWSDESKTOP-THIRD-PARTY-NOTICES.txt')

    $rules = Get-Content -LiteralPath (Join-Path $snapshotRoot 'SteamSentinel.Core\Rules\default-rules.json') -Raw | ConvertFrom-Json
    $builtAtUtc = [DateTimeOffset]::UtcNow.ToString('O')
    Write-Utf8Lines -Path (Join-Path $packageDir 'VERSION.txt') -Lines @(
        'Product=SteamSentinel',
        "Version=$version",
        "BuildIdentity=$buildIdentity",
        "BuildId=$buildId",
        "Commit=$commit",
        "SourceTree=$sourceTree",
        "Mode=$Mode",
        "Dirty=$isDirty",
        "Rules=$($rules.version)",
        'Runtime=win-x64 self-contained .NET 10',
        "Sdk=$actualSdk",
        "BuiltAtUtc=$builtAtUtc",
        "SignatureStatus=$signatureStatus"
    )

    $hashLines = Get-ChildItem -LiteralPath $packageDir -Recurse -File |
        Where-Object Name -ne 'SHA256SUMS.txt' |
        Sort-Object FullName |
        ForEach-Object {
            $relative = $_.FullName.Substring($packageDir.Length).TrimStart('\', '/')
            '{0} *{1}' -f (Get-FileHash -Algorithm SHA256 -LiteralPath $_.FullName).Hash, $relative
        }
    Write-Utf8Lines -Path (Join-Path $packageDir 'SHA256SUMS.txt') -Lines $hashLines
    [IO.Compression.ZipFile]::CreateFromDirectory(
        $packageDir,
        $archivePath,
        [IO.Compression.CompressionLevel]::Optimal,
        $true)

    if (-not $SkipInstaller) {
        $isccCandidates = @(
            (Get-Command ISCC.exe -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Source -ErrorAction SilentlyContinue),
            (Join-Path $env:LOCALAPPDATA 'Programs\Inno Setup 6\ISCC.exe'),
            'C:\Program Files (x86)\Inno Setup 6\ISCC.exe',
            'C:\Program Files\Inno Setup 6\ISCC.exe'
        ) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) -and (Test-Path -LiteralPath $_ -PathType Leaf) }
        $iscc = $isccCandidates | Select-Object -First 1
        if ([string]::IsNullOrWhiteSpace($iscc)) {
            throw 'Inno Setup 6 compiler was not found. Use -SkipInstaller only for a development Preview.'
        }

        $installerScript = Join-Path $snapshotRoot 'installer\SteamSentinel.iss'
        $signArgs = @(Get-InnoSigningArguments -Profile $signingProfile)
        if ($null -ne $signingProfile) {
            New-Item -ItemType Directory -Force -Path (Join-Path $stageRoot 'signing-cache\SteamSentinel') | Out-Null
        }
        & $iscc "/DPayloadDir=$packageDir" "/DOutputDir=$stageRoot" "/DAppVersion=$version" `
            "/DArtifactBaseName=SteamSentinel-$artifactVersion" @signArgs $installerScript
        if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $setupPath -PathType Leaf)) {
            throw "Installer compilation failed with exit code $LASTEXITCODE"
        }
        if ($null -ne $signingProfile) {
            Assert-ReleaseSignature -Profile $signingProfile -Path $setupPath -DisplayName ([IO.Path]::GetFileName($setupPath)) | Out-Null
        }
    }

    $metadata = [ordered]@{
        schemaVersion = 1
        product = 'SteamSentinel'
        version = $version
        buildIdentity = $buildIdentity
        buildId = $buildId
        mode = $Mode
        preview = -not $isPublicRelease
        dirty = $isDirty
        commit = $commit
        commitTime = $commitTime
        sourceTree = $sourceTree
        exactTag = if ($isPublicRelease) { $tag } else { $null }
        sdk = $actualSdk
        runtime = 'win-x64'
        selfContained = $true
        selfTest = [ordered]@{
            passed = [int]$selfTest.passed
            failed = [int]$selfTest.failed
            skipped = [int]$selfTest.skipped
            elapsedMs = [long]$selfTest.elapsedMs
        }
        signing = [ordered]@{
            status = $signatureStatus
            timestampUrl = if ($null -eq $signingProfile) { $null } else { $signingProfile.TimestampUrl }
            certificateThumbprint = if ($null -eq $signingProfile) { $null } else { $signingProfile.Thumbprint }
        }
        source = [ordered]@{
            method = 'git archive'
            includesIgnoredFiles = $false
            status = @($statusLines)
        }
        builtAtUtc = $builtAtUtc
    }
    [IO.File]::WriteAllText($metadataPath, ($metadata | ConvertTo-Json -Depth 6), [Text.UTF8Encoding]::new($false))

    $releaseHashes = Get-ChildItem -LiteralPath $stageRoot -File |
        Where-Object FullName -ne $checksumPath |
        Sort-Object Name |
        ForEach-Object { '{0} *{1}' -f (Get-FileHash -Algorithm SHA256 -LiteralPath $_.FullName).Hash, $_.Name }
    Write-Utf8Lines -Path $checksumPath -Lines $releaseHashes

    if (Test-Path -LiteralPath $workRoot) {
        Assert-ChildPath $workRoot $stageRoot
        Remove-Item -LiteralPath $workRoot -Recurse -Force
    }
    $signingCache = Join-Path $stageRoot 'signing-cache'
    if (Test-Path -LiteralPath $signingCache) {
        Assert-ChildPath $signingCache $stageRoot
        Remove-Item -LiteralPath $signingCache -Recurse -Force
    }

    # Directory.Move is an atomic same-volume rename and fails if the final
    # name appeared after the earlier check; Move-Item would instead nest the
    # staging directory inside an existing directory.
    [IO.Directory]::Move($stageRoot, $finalBundlePath)
    $completed = $true

    Write-Host "BUNDLE=$finalBundlePath"
    Write-Host "PACKAGE_DIR=$(Join-Path $finalBundlePath $packageName)"
    Write-Host "BINARY_ZIP=$(Join-Path $finalBundlePath ([IO.Path]::GetFileName($archivePath)))"
    Write-Host "SOURCE_ZIP=$(Join-Path $finalBundlePath ([IO.Path]::GetFileName($sourceArchivePath)))"
    if (-not $SkipInstaller) { Write-Host "SETUP=$(Join-Path $finalBundlePath ([IO.Path]::GetFileName($setupPath)))" }
    Write-Host "BUILD_ID=$buildId"
}
finally {
    if (-not $completed -and (Test-Path -LiteralPath $stageRoot)) {
        Assert-ChildPath $stageRoot $OutputRoot
        Remove-Item -LiteralPath $stageRoot -Recurse -Force
    }
}
