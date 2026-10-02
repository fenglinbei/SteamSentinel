#requires -Version 5.1
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$PublishRoot,
    [Parameter(Mandatory = $true)][string]$BuildRoot,
    [Parameter(Mandatory = $true)][string]$Version,
    [Parameter(Mandatory = $true)][string]$BuildIdentity,
    [string]$SourceRoot = (Join-Path $PSScriptRoot '..')
)

$ErrorActionPreference = 'Stop'
$SourceRoot = (Resolve-Path -LiteralPath $SourceRoot).Path
$PublishRoot = (Resolve-Path -LiteralPath $PublishRoot).Path
$BuildRoot = [IO.Path]::GetFullPath($BuildRoot)
if ($Version -notmatch '^\d+\.\d+\.\d+$' -or $BuildIdentity -notmatch '^[A-Za-z0-9.+_-]+$') {
    throw 'A numeric product version and a safe, explicit build identity are required.'
}
foreach ($path in @($SourceRoot, $PublishRoot, $BuildRoot)) {
    if ($path -match '["%!\r\n]' -or (Test-Path -LiteralPath $path -PathType Leaf)) {
        throw 'Build directories must not contain command expansion characters or name a file.'
    }
}
if ($BuildRoot.TrimEnd('\') -eq $PublishRoot.TrimEnd('\') -or
    $BuildRoot.StartsWith($PublishRoot.TrimEnd('\') + '\', [StringComparison]::OrdinalIgnoreCase)) {
    throw 'The native build directory must be separate from the published payload.'
}
if (Test-Path -LiteralPath $BuildRoot) {
    if (@(Get-ChildItem -LiteralPath $BuildRoot -Force).Count -ne 0) {
        throw 'Use a new, empty native build directory to prevent stale host reuse.'
    }
}
New-Item -ItemType Directory -Path $BuildRoot -Force | Out-Null
foreach ($path in @($SourceRoot, $PublishRoot, $BuildRoot)) {
    if ((Get-Item -LiteralPath $path).Attributes -band [IO.FileAttributes]::ReparsePoint) {
        throw 'Build and payload roots must not be reparse points.'
    }
}

[xml]$props = Get-Content -LiteralPath (Join-Path $SourceRoot 'Directory.Build.props') -Raw -Encoding UTF8
$runtimeVersion = [string]$props.Project.PropertyGroup.SteamSentinelRuntimeFrameworkVersion
$sdkVersion = [string]((Get-Content -LiteralPath (Join-Path $SourceRoot 'global.json') -Raw | ConvertFrom-Json).sdk.version)
$dotnet = (Get-Command dotnet -ErrorAction Stop).Source
$dotnetRoot = Split-Path -Parent $dotnet
$hostModel = Join-Path $dotnetRoot "sdk\$sdkVersion\Microsoft.NET.HostModel.dll"
if (-not (Test-Path -LiteralPath $hostModel -PathType Leaf)) { throw 'The pinned SDK HostModel assembly is missing.' }
$nugetRoot = if ([string]::IsNullOrWhiteSpace($env:NUGET_PACKAGES)) { Join-Path $env:USERPROFILE '.nuget\packages' } else { $env:NUGET_PACKAGES }
$templateCandidates = @(
    (Join-Path $nugetRoot "microsoft.netcore.app.host.win-x64\$runtimeVersion\runtimes\win-x64\native\apphost.exe"),
    (Join-Path $dotnetRoot "packs\Microsoft.NETCore.App.Host.win-x64\$runtimeVersion\runtimes\win-x64\native\apphost.exe")
)
$template = $templateCandidates | Where-Object { Test-Path -LiteralPath $_ -PathType Leaf } | Select-Object -First 1
if ([string]::IsNullOrWhiteSpace($template)) { throw "The pinned .NET $runtimeVersion apphost template is missing; restore the application first." }
foreach ($role in @('SteamSentinel', 'SteamSentinel.Broker', 'SteamSentinel.ArchiveWorker')) {
    foreach ($extension in @('.dll', '.deps.json', '.runtimeconfig.json')) {
        if (-not (Test-Path -LiteralPath (Join-Path $PublishRoot ($role + $extension)) -PathType Leaf)) {
            throw "Incomplete shared managed payload: $role$extension"
        }
    }
}

function Write-BuildText([string]$Path, [string]$Text) {
    if ([IO.Path]::GetExtension($Path) -eq '.cmd') { $Text = ($Text -replace '\r?\n', "`r`n") + "`r`n" }
    [IO.File]::WriteAllText($Path, $Text, [Text.UTF8Encoding]::new($false))
}
function Invoke-BuildDotNet {
    param([Parameter(ValueFromRemainingArguments = $true)][string[]]$Arguments)
    & $dotnet @Arguments | Out-Host
    if ($LASTEXITCODE -ne 0) { throw "Unified startup helper failed (dotnet exit $LASTEXITCODE)." }
}

# Use the SDK API in a separate managed tool, so this script also works in Windows
# PowerShell 5.1. It never republishes or substitutes any managed product assembly.
$escapedHostModel = [Security.SecurityElement]::Escape($hostModel)
Write-BuildText (Join-Path $BuildRoot 'HostBuilder.csproj') @"
<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <OutputType>Exe</OutputType><TargetFramework>net10.0</TargetFramework>
    <UseAppHost>false</UseAppHost><ImplicitUsings>enable</ImplicitUsings><Nullable>enable</Nullable>
    <EnableDefaultCompileItems>false</EnableDefaultCompileItems><RestorePackagesWithLockFile>false</RestorePackagesWithLockFile>
  </PropertyGroup>
  <ItemGroup><Compile Include="HostBuilder.cs" /><Reference Include="Microsoft.NET.HostModel"><HintPath>$escapedHostModel</HintPath></Reference></ItemGroup>
</Project>
"@
Write-BuildText (Join-Path $BuildRoot 'NuGet.Config') '<configuration><packageSources><clear /></packageSources></configuration>'
Write-BuildText (Join-Path $BuildRoot 'HostBuilder.cs') @'
using Microsoft.NET.HostModel.AppHost;
using System.Text.Json;

static class HostBuilder
{
    static int Rva(byte[] data, int pe, uint rva, int bytes)
    {
        int optional = pe + 24;
        int sections = optional + BitConverter.ToUInt16(data, pe + 20);
        int count = BitConverter.ToUInt16(data, pe + 6);
        for (int i = 0; i < count; i++)
        {
            int section = sections + i * 40;
            uint address = BitConverter.ToUInt32(data, section + 12);
            uint rawBytes = BitConverter.ToUInt32(data, section + 16);
            uint rawOffset = BitConverter.ToUInt32(data, section + 20);
            if (rva >= address && (ulong)rva + (uint)bytes <= (ulong)address + rawBytes)
            {
                long offset = (long)rawOffset + rva - address;
                if (offset < 0 || offset + bytes > data.LongLength) throw new InvalidDataException("PE range is out of bounds.");
                return checked((int)offset);
            }
        }
        throw new InvalidDataException("PE RVA is not backed by file data.");
    }

    static bool Cet(string path)
    {
        byte[] data = File.ReadAllBytes(path);
        if (data.Length < 64 || BitConverter.ToUInt16(data, 0) != 0x5a4d) throw new InvalidDataException("Invalid DOS header: " + path);
        int pe = BitConverter.ToInt32(data, 60);
        if (pe < 64 || pe > data.Length - 264 || BitConverter.ToUInt32(data, pe) != 0x4550 ||
            BitConverter.ToUInt16(data, pe + 4) != 0x8664 || BitConverter.ToUInt16(data, pe + 24) != 0x20b)
            throw new InvalidDataException("Expected a Windows x64 PE32+ host: " + path);
        int debugDirectory = pe + 24 + 112 + 6 * 8;
        uint debugRva = BitConverter.ToUInt32(data, debugDirectory);
        uint debugBytes = BitConverter.ToUInt32(data, debugDirectory + 4);
        if (debugRva == 0 || debugBytes == 0) return false;
        if (debugBytes % 28 != 0 || debugBytes > 28 * 1024) throw new InvalidDataException("Invalid PE debug directory.");
        int directory = Rva(data, pe, debugRva, checked((int)debugBytes));
        bool cet = false;
        for (int i = 0; i < debugBytes / 28; i++)
        {
            int entry = directory + i * 28;
            if (BitConverter.ToUInt32(data, entry + 12) != 20) continue; // IMAGE_DEBUG_TYPE_EX_DLLCHARACTERISTICS
            uint size = BitConverter.ToUInt32(data, entry + 16), offset = BitConverter.ToUInt32(data, entry + 24);
            if (size < 4 || offset > data.Length - 4) throw new InvalidDataException("Invalid extended DLL characteristics.");
            cet |= (BitConverter.ToUInt32(data, checked((int)offset)) & 1) != 0; // IMAGE_DLLCHARACTERISTICS_EX_CET_COMPAT
        }
        return cet;
    }

    static void RequireCet(string path, bool expected)
    {
        if (Cet(path) != expected) throw new InvalidDataException($"Unexpected CET_COMPAT value for {path}; expected {expected}.");
    }

    static void Main(string[] args)
    {
        if (args.Length != 4) throw new ArgumentException("Expected mode, template, payload and output manifest.");
        string template = args[1], root = args[2];
        string[] roles = ["SteamSentinel", "SteamSentinel.Broker", "SteamSentinel.ArchiveWorker"];
        if (args[0] == "generate")
        {
            RequireCet(template, true);
            foreach (string role in roles)
                foreach (bool compat in new[] { false, true })
                {
                    string destination = Path.Combine(root, role + (compat ? ".Compat.exe" : ".Standard.exe"));
                    HostWriter.CreateAppHost(template, destination, role + ".dll",
                        windowsGraphicalUserInterface: role != "SteamSentinel.ArchiveWorker",
                        assemblyToCopyResourcesFrom: Path.Combine(root, role + ".dll"), disableCetCompat: compat);
                    RequireCet(destination, !compat);
                }
            File.Copy(Path.Combine(root, "SteamSentinel.ArchiveWorker.Standard.exe"), Path.Combine(root, "SteamSentinel.ArchiveWorker.exe"), true);
        }
        else if (args[0] != "verify") throw new ArgumentException("Unknown host-builder mode.");
        List<object> hosts = [];
        foreach (string role in roles)
            foreach (bool compat in new[] { false, true })
            {
                string file = role + (compat ? ".Compat.exe" : ".Standard.exe");
                RequireCet(Path.Combine(root, file), !compat);
                hosts.Add(new { path = file, managedDll = role + ".dll", cetCompat = !compat, kind = "managed-apphost" });
            }
        RequireCet(Path.Combine(root, "SteamSentinel.ArchiveWorker.exe"), true);
        hosts.Add(new { path = "SteamSentinel.ArchiveWorker.exe", managedDll = "SteamSentinel.ArchiveWorker.dll", cetCompat = true, kind = "legacy-standard-alias" });
        if (args[0] == "verify")
            foreach (string file in new[] { "SteamSentinel.exe", "SteamSentinel.Broker.exe" })
            {
                RequireCet(Path.Combine(root, file), false);
                hosts.Add(new { path = file, managedDll = (string?)null, cetCompat = false, kind = "native-launcher" });
            }
        File.WriteAllText(args[3], JsonSerializer.Serialize(hosts, new JsonSerializerOptions { WriteIndented = true }));
    }
}
'@
$helperProject = Join-Path $BuildRoot 'HostBuilder.csproj'
$helperDll = Join-Path $BuildRoot 'bin\Release\net10.0\HostBuilder.dll'
$hostManifestPath = Join-Path $BuildRoot 'host-manifest.json'
Invoke-BuildDotNet restore $helperProject '--configfile' (Join-Path $BuildRoot 'NuGet.Config') `
    '-p:ImportDirectoryBuildProps=false' '-p:ImportDirectoryBuildTargets=false'
Invoke-BuildDotNet build $helperProject '-c' 'Release' '--nologo' '--no-restore' `
    '-p:ImportDirectoryBuildProps=false' '-p:ImportDirectoryBuildTargets=false'
Invoke-BuildDotNet $helperDll 'generate' $template $PublishRoot $hostManifestPath

$vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
if (-not (Test-Path -LiteralPath $vswhere -PathType Leaf)) { throw 'Visual Studio C++ Build Tools (vswhere) are required.' }
$visualStudio = (& $vswhere '-latest' '-products' '*' '-requires' 'Microsoft.VisualStudio.Component.VC.Tools.x86.x64' '-property' 'installationPath' | Select-Object -First 1)
if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($visualStudio)) { throw 'An x64 Visual C++ toolchain was not found.' }
$vcvars = Join-Path $visualStudio 'VC\Auxiliary\Build\vcvars64.bat'
$nativeSource = Join-Path $SourceRoot 'native\SteamSentinel.Launcher.cpp'
$icon = (Join-Path $SourceRoot 'SteamSentinel.App\Assets\App.ico').Replace('\', '\\')
$manifest = Join-Path $SourceRoot 'SteamSentinel.App\app.manifest'
$versionTuple = $Version.Replace('.', ',') + ',0'
$resourcePath = Join-Path $BuildRoot 'Launcher.rc'
Write-BuildText $resourcePath @"
#pragma code_page(65001)
#include <windows.h>
1 ICON "$icon"
VS_VERSION_INFO VERSIONINFO
 FILEVERSION $versionTuple
 PRODUCTVERSION $versionTuple
 FILEFLAGSMASK 0x3fL
 FILEFLAGS 0x0L
 FILEOS VOS_NT_WINDOWS32
 FILETYPE VFT_APP
 FILESUBTYPE 0x0L
BEGIN
  BLOCK "StringFileInfo"
  BEGIN
    BLOCK "040904b0"
    BEGIN
      VALUE "CompanyName", "SteamSentinel contributors\0"
      VALUE "FileDescription", "SteamSentinel unified startup launcher\0"
      VALUE "FileVersion", "$Version.0\0"
      VALUE "InternalName", "SteamSentinel.Launcher\0"
      VALUE "LegalCopyright", "Copyright 2026 fenglinbei\0"
      VALUE "OriginalFilename", "SteamSentinel.exe\0"
      VALUE "ProductName", "SteamSentinel\0"
      VALUE "ProductVersion", "$BuildIdentity\0"
    END
  END
  BLOCK "VarFileInfo"
  BEGIN
    VALUE "Translation", 0x409, 1200
  END
END
"@
$nativeExe = Join-Path $BuildRoot 'SteamSentinel.Launcher.exe'
$resourceOutput = Join-Path $BuildRoot 'Launcher.res'
$objectOutput = Join-Path $BuildRoot 'Launcher.obj'
$compileScript = Join-Path $BuildRoot 'compile-native.cmd'
Write-BuildText $compileScript @"
@echo off
chcp 65001 >nul
call "$vcvars" >nul
if errorlevel 1 exit /b %errorlevel%
rc.exe /nologo /c65001 /fo "$resourceOutput" "$resourcePath"
if errorlevel 1 exit /b %errorlevel%
cl.exe /nologo /std:c++17 /W4 /WX /utf-8 /EHsc /MT /O2 /DUNICODE /D_UNICODE /DWIN32_LEAN_AND_MEAN /DNOMINMAX /Fo"$objectOutput" /Fe"$nativeExe" "$nativeSource" "$resourceOutput" /link bcrypt.lib shell32.lib user32.lib advapi32.lib ole32.lib /SUBSYSTEM:WINDOWS /CETCOMPAT:NO /DYNAMICBASE /NXCOMPAT /INCREMENTAL:NO /MANIFEST:EMBED /MANIFESTINPUT:"$manifest"
exit /b %errorlevel%
"@
& $env:ComSpec '/d' '/c' $compileScript | Out-Host
if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $nativeExe -PathType Leaf)) {
    throw "Native startup compilation failed (exit $LASTEXITCODE)."
}
foreach ($file in @('SteamSentinel.exe', 'SteamSentinel.Broker.exe')) {
    Copy-Item -LiteralPath $nativeExe -Destination (Join-Path $PublishRoot $file) -Force
}
Invoke-BuildDotNet $helperDll 'verify' $template $PublishRoot $hostManifestPath
$hosts = @(Get-Content -LiteralPath $hostManifestPath -Raw | ConvertFrom-Json)
if ($hosts.Count -ne 9) { throw 'Unified startup must contain exactly nine verified executable entries.' }
[pscustomobject][ordered]@{
    schema = 'SteamSentinel.UnifiedStartup/1'
    mode = 'unified'
    version = $Version
    buildIdentity = $BuildIdentity
    runtimeFrameworkVersion = $runtimeVersion
    templateSha256 = (Get-FileHash -LiteralPath $template -Algorithm SHA256).Hash
    nativeSourceSha256 = (Get-FileHash -LiteralPath $nativeSource -Algorithm SHA256).Hash
    nativeRuntime = 'MSVC static /MT'
    hosts = $hosts
}
