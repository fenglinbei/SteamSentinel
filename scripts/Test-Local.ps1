#requires -Version 5.1
[CmdletBinding()]
param(
    [ValidateSet('L1', 'L2', 'L3')]
    [string]$Tier = 'L1',

    [string[]]$Filter,

    [ValidateSet('Debug', 'Release')]
    [string]$Configuration = 'Debug',

    [switch]$NoBuild,

    [switch]$NoParallel,

    [switch]$SkipFormat,

    [switch]$SkipInstaller,

    [string]$OutputRoot
)

$ErrorActionPreference = 'Stop'
$repoRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path
$solutionPath = Join-Path $repoRoot 'SteamSentinel.slnx'
$selfTestProject = Join-Path $repoRoot 'SteamSentinel.SelfTest\SteamSentinel.SelfTest.csproj'
$propsPath = Join-Path $repoRoot 'Directory.Build.props'

[xml]$props = Get-Content -LiteralPath $propsPath -Raw -Encoding UTF8
$version = [string]$props.Project.PropertyGroup.VersionPrefix
$targetFramework = [string]$props.Project.PropertyGroup.TargetFramework
$minimumSelfTests = [int]$props.Project.PropertyGroup.SteamSentinelMinimumSelfTests
if ($version -notmatch '^\d+\.\d+\.\d+$' -or [string]::IsNullOrWhiteSpace($targetFramework) -or $minimumSelfTests -lt 1) {
    throw "Directory.Build.props 中的构建契约无效: Version=$version, TargetFramework=$targetFramework, MinimumSelfTests=$minimumSelfTests"
}

$filterTerms = @()
if ($null -ne $Filter -and $Filter.Count -gt 0) {
    $filterTerms = @(
        $Filter |
        ForEach-Object { $_ -split ',' } |
        ForEach-Object { $_.Trim() } |
        Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
    )
}

function Invoke-SolutionBuild {
    Write-Host "[$Tier] 正在构建解决方案 ($Configuration)..."
    & dotnet build $solutionPath -c $Configuration
    if ($LASTEXITCODE -ne 0) {
        throw "dotnet build 失败（退出码 $LASTEXITCODE）。"
    }
}

function Invoke-FormatCheck {
    Write-Host "[$Tier] 正在检查代码空白格式 (dotnet format whitespace)..."
    & dotnet format whitespace $solutionPath --verify-no-changes --no-restore
    if ($LASTEXITCODE -ne 0) {
        throw "代码格式校验失败（退出码 $LASTEXITCODE）。请运行 dotnet format whitespace SteamSentinel.slnx 修复。"
    }
}

function Invoke-SelfTest([string[]]$Arguments) {
    $selfTestExe = Join-Path $repoRoot ("SteamSentinel.SelfTest\bin\$Configuration\$targetFramework\SteamSentinel.SelfTest.exe")
    if (Test-Path -LiteralPath $selfTestExe -PathType Leaf) {
        & $selfTestExe @Arguments
    }
    else {
        & dotnet run --project $selfTestProject -c $Configuration --no-build -- @Arguments
    }
    if ($LASTEXITCODE -ne 0) {
        throw "SteamSentinel.SelfTest 执行失败（退出码 $LASTEXITCODE）。"
    }
}

function Assert-JsonFile([string]$Path, [string]$Label) {
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "$Label 未生成结果文件: $Path"
    }
    Get-Content -LiteralPath $Path -Raw -Encoding UTF8 | ConvertFrom-Json
}

function Invoke-TierL1 {
    if (-not $NoBuild) {
        Invoke-SolutionBuild
    }

    $testArgs = [Collections.Generic.List[string]]::new()
    if ($filterTerms.Count -gt 0) {
        $joinedFilter = $filterTerms -join ','
        Write-Host "[L1] 正在运行筛选自检 (--filter $joinedFilter --timings)..."
        $testArgs.Add('--filter')
        $testArgs.Add($joinedFilter)
        $testArgs.Add('--timings')
    }
    else {
        Write-Host '[L1] 正在运行快速自检 (--fast --timings)...'
        $testArgs.Add('--fast')
        $testArgs.Add('--timings')
    }

    if ($NoParallel) {
        $testArgs.Add('--no-parallel')
    }

    if (-not [string]::IsNullOrWhiteSpace($OutputRoot)) {
        $outDir = [IO.Path]::GetFullPath($OutputRoot)
        New-Item -ItemType Directory -Path $outDir -Force | Out-Null
        $testArgs.Add('--results')
        $testArgs.Add((Join-Path $outDir 'SELFTEST-L1-RESULTS.json'))
    }

    Invoke-SelfTest -Arguments $testArgs.ToArray()
}

function Invoke-TierL2([bool]$ForceTempOutput = $false) {
    if ($filterTerms.Count -gt 0) {
        throw '-Filter 仅支持在 -Tier L1 下使用；L2/L3 必须运行完整无筛选的全量自检以校验门禁基线。'
    }

    if (-not $NoBuild) {
        Invoke-SolutionBuild
    }

    if (-not $SkipFormat) {
        Invoke-FormatCheck
    }

    $cleanupTemp = $ForceTempOutput -or [string]::IsNullOrWhiteSpace($OutputRoot)
    if ($cleanupTemp) {
        $outDir = Join-Path ([IO.Path]::GetTempPath()) ('SteamSentinel-TestLocal-L2-' + [Guid]::NewGuid().ToString('N'))
    }
    else {
        $outDir = [IO.Path]::GetFullPath($OutputRoot)
    }
    New-Item -ItemType Directory -Path $outDir -Force | Out-Null

    try {
        $resultsPath = Join-Path $outDir 'SELFTEST-RESULTS.json'
        $watchdogPath = Join-Path $outDir 'WATCHDOG-RESULTS.json'
        $fpPath = Join-Path $outDir 'FINDING-PRIORITY-UI-RESULTS.json'

        $testArgs = [Collections.Generic.List[string]]::new()
        $testArgs.AddRange([string[]]@(
            '--results', $resultsPath,
            '--watchdog-results', $watchdogPath,
            '--finding-priority-results', $fpPath,
            '--timings'
        ))
        if ($NoParallel) {
            $testArgs.Add('--no-parallel')
        }

        Write-Host "[$Tier] 正在运行完整自检并导出三份门禁报告..."
        Invoke-SelfTest -Arguments $testArgs.ToArray()

        $selfTest = Assert-JsonFile -Path $resultsPath -Label 'SelfTest 全量报告'
        if ($null -eq $selfTest.PSObject.Properties['elapsedMs'] -or [long]$selfTest.elapsedMs -lt 0) {
            throw 'SelfTest 结果缺少有效 elapsedMs 字段。'
        }
        if ([int]$selfTest.failed -ne 0 -or [int]$selfTest.skipped -ne 0 -or [int]$selfTest.passed -lt $minimumSelfTests) {
            throw "SelfTest 未达门禁基线: passed=$($selfTest.passed) (要求 >= $minimumSelfTests), failed=$($selfTest.failed), skipped=$($selfTest.skipped)"
        }
        if ($selfTest.version -ne $version -or [string]::IsNullOrWhiteSpace($selfTest.buildIdentity)) {
            throw "SelfTest 版本或构建身份不匹配: version=$($selfTest.version), buildIdentity=$($selfTest.buildIdentity)"
        }

        $watchdog = Assert-JsonFile -Path $watchdogPath -Label 'Watchdog 专项报告'
        if ([int]$watchdog.passed -lt 314 -or [int]$watchdog.failed -ne 0 -or [int]$watchdog.skipped -ne 0 -or @($watchdog.failures).Count -ne 0) {
            throw "Watchdog 门禁未通过: passed=$($watchdog.passed) (要求 >= 314), failed=$($watchdog.failed), skipped=$($watchdog.skipped)"
        }

        $fp = Assert-JsonFile -Path $fpPath -Label 'FindingPriority UI 专项报告'
        if ([int]$fp.passed -lt 141 -or [int]$fp.failed -ne 0 -or [int]$fp.skipped -ne 0 -or @($fp.failures).Count -ne 0) {
            throw "FindingPriority UI 门禁未通过: passed=$($fp.passed) (要求 >= 141), failed=$($fp.failed), skipped=$($fp.skipped)"
        }

        Write-Host ("[$Tier PASS] SelfTest={0} (min {1}, failed=0, skipped=0) | Watchdog={2} (>=314) | FindingPriority={3} (>=141)" -f `
            $selfTest.passed, $minimumSelfTests, $watchdog.passed, $fp.passed)
    }
    finally {
        if ($cleanupTemp -and (Test-Path -LiteralPath $outDir)) {
            Remove-Item -LiteralPath $outDir -Recurse -Force
        }
    }
}

function Invoke-TierL3 {
    if ($filterTerms.Count -gt 0) {
        throw '-Filter 仅支持在 -Tier L1 下使用；L3 必须运行完整门禁与预览构建。'
    }

    $principal = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Tier L3 需要以管理员权限运行 PowerShell，因为 build-release.ps1 必须执行安装器文件/ACL 与机器状态强制验证。'
    }

    Invoke-TierL2 -ForceTempOutput $true

    $statusLines = @(& git -C $repoRoot status --porcelain=v1 --untracked-files=all)
    if ($LASTEXITCODE -ne 0) {
        throw "无法检查 Git 工作树状态（退出码 $LASTEXITCODE）。"
    }
    $isDirty = $statusLines.Count -gt 0

    $releaseScript = Join-Path $PSScriptRoot 'build-release.ps1'
    $releaseParams = @{
        Mode = 'Preview'
    }
    if ($isDirty) {
        Write-Host '[L3] 检测到本地未提交改动，将附加 -AllowDirtyPreview 构建带源码树指纹的 Preview 产物。'
        $releaseParams['AllowDirtyPreview'] = $true
    }
    if ($SkipInstaller) {
        $releaseParams['SkipInstaller'] = $true
    }
    if (-not [string]::IsNullOrWhiteSpace($OutputRoot)) {
        $releaseParams['OutputRoot'] = [IO.Path]::GetFullPath($OutputRoot)
    }

    Write-Host '[L3] 正在调用 scripts/build-release.ps1 -Mode Preview...'
    & $releaseScript @releaseParams
}

$totalClock = [Diagnostics.Stopwatch]::StartNew()
Push-Location $repoRoot
try {
    switch ($Tier) {
        'L1' { Invoke-TierL1 }
        'L2' { Invoke-TierL2 }
        'L3' { Invoke-TierL3 }
    }
}
finally {
    Pop-Location
    $totalClock.Stop()
    Write-Host "[$Tier] 总耗时: $($totalClock.ElapsedMilliseconds) ms"
}
