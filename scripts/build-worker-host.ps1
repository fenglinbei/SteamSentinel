#requires -Version 5.1
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$SourcePath,
    [Parameter(Mandatory = $true)][string]$OutputPath,
    [Parameter(Mandatory = $true)][string]$BuildDirectory,
    [Parameter(Mandatory = $true)][string]$Version,
    [Parameter(Mandatory = $true)][string]$BuildIdentity,
    [Parameter(Mandatory = $true)][string]$OriginalFilename,
    [object]$CetCompat = $true,
    [object]$SelfContainedOnly = $false,
    [Parameter(Mandatory = $true)][string]$ManifestPath,
    [switch]$Optional,
    [switch]$Incremental
)

$ErrorActionPreference = 'Stop'

function Convert-ToBool([object]$Value, [string]$ParameterName) {
    if ($Value -is [bool]) { return [bool]$Value }
    if ($Value -is [int] -or $Value -is [long]) { return ([long]$Value) -ne 0 }
    $text = ([string]$Value).Trim()
    if ($text -match '^\$?(true|1)$') { return $true }
    if ($text -match '^\$?(false|0)$') { return $false }
    throw "Invalid boolean value for ${ParameterName}: $Value"
}

$expectCetCompat = Convert-ToBool $CetCompat 'CetCompat'
$isSelfContainedOnly = Convert-ToBool $SelfContainedOnly 'SelfContainedOnly'

$SourcePath = [IO.Path]::GetFullPath($SourcePath)
$OutputPath = [IO.Path]::GetFullPath($OutputPath)
$BuildDirectory = [IO.Path]::GetFullPath($BuildDirectory)
$ManifestPath = [IO.Path]::GetFullPath($ManifestPath)

if (-not (Test-Path -LiteralPath $SourcePath -PathType Leaf)) {
    throw "Worker host source is missing: $SourcePath"
}
if (-not (Test-Path -LiteralPath $ManifestPath -PathType Leaf)) {
    throw "Worker host manifest is missing: $ManifestPath"
}
if ($Version -notmatch '^\d+\.\d+\.\d+$' -or $BuildIdentity -notmatch '^[A-Za-z0-9.+_-]+$') {
    throw 'A numeric product version and a safe, explicit build identity are required.'
}
if ($OriginalFilename -notmatch '^[A-Za-z0-9._-]+$' -or $OriginalFilename -match '["%!\r\n]') {
    throw "Invalid OriginalFilename: $OriginalFilename"
}
foreach ($p in @($SourcePath, $OutputPath, $BuildDirectory, $ManifestPath)) {
    if ($p -match '["%!\r\n]') {
        throw "Path contains unsupported command characters: $p"
    }
}

Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

public static class SteamSentinelWorkerHostPeInspector
{
    static int RvaToOffset(byte[] data, int pe, uint rva, int minBytes)
    {
        int optional = pe + 24;
        int sectionTable = optional + BitConverter.ToUInt16(data, pe + 20);
        int sectionCount = BitConverter.ToUInt16(data, pe + 6);
        for (int i = 0; i < sectionCount; i++)
        {
            int s = sectionTable + i * 40;
            uint virtualSize = BitConverter.ToUInt32(data, s + 8);
            uint virtualAddr = BitConverter.ToUInt32(data, s + 12);
            uint rawSize = BitConverter.ToUInt32(data, s + 16);
            uint rawOffset = BitConverter.ToUInt32(data, s + 20);
            uint span = Math.Min(virtualSize, rawSize);
            if (span == 0) span = rawSize;
            if (rva >= virtualAddr && (ulong)rva + (uint)minBytes <= (ulong)virtualAddr + span)
            {
                long off = (long)rawOffset + rva - virtualAddr;
                if (off < 0 || off + minBytes > data.LongLength) throw new InvalidDataException("PE range is out of bounds.");
                return checked((int)off);
            }
        }
        throw new InvalidDataException("PE RVA is not backed by file data: 0x" + rva.ToString("X"));
    }

    static string ReadAsciiZ(byte[] data, int offset, int maxLen)
    {
        int end = offset;
        int limit = Math.Min(data.Length, offset + maxLen);
        while (end < limit && data[end] != 0) end++;
        return Encoding.ASCII.GetString(data, offset, end - offset);
    }

    public static void Verify(string path, bool expectedCetCompat)
    {
        byte[] data = File.ReadAllBytes(path);
        if (data.Length < 64 || BitConverter.ToUInt16(data, 0) != 0x5A4D)
            throw new InvalidDataException("Invalid DOS header: " + path);
        int pe = BitConverter.ToInt32(data, 60);
        if (pe < 64 || pe > data.Length - 264 || BitConverter.ToUInt32(data, pe) != 0x4550 ||
            BitConverter.ToUInt16(data, pe + 4) != 0x8664 || BitConverter.ToUInt16(data, pe + 24) != 0x020B)
            throw new InvalidDataException("Expected Windows x64 PE32+ executable: " + path);

        int optional = pe + 24;
        ushort subsystem = BitConverter.ToUInt16(data, optional + 68);
        if (subsystem != 3)
            throw new InvalidDataException("Worker host must use console subsystem (3); observed " + subsystem);

        uint numDataDirs = BitConverter.ToUInt32(data, optional + 108);
        if (numDataDirs < 14)
            throw new InvalidDataException("Unexpected PE data directory count.");

        // 1. Check Import Table: must ONLY import KERNEL32.dll.
        uint importRva = BitConverter.ToUInt32(data, optional + 112 + 1 * 8);
        uint importSize = BitConverter.ToUInt32(data, optional + 112 + 1 * 8 + 4);
        if (importRva == 0 || importSize < 20)
            throw new InvalidDataException("Missing PE import directory: " + path);
        int importOffset = RvaToOffset(data, pe, importRva, 20);
        List<string> imports = new List<string>();
        for (int pos = importOffset; pos + 20 <= data.Length; pos += 20)
        {
            uint ilt = BitConverter.ToUInt32(data, pos);
            uint ts = BitConverter.ToUInt32(data, pos + 4);
            uint fwd = BitConverter.ToUInt32(data, pos + 8);
            uint nameRva = BitConverter.ToUInt32(data, pos + 12);
            uint iat = BitConverter.ToUInt32(data, pos + 16);
            if (ilt == 0 && ts == 0 && fwd == 0 && nameRva == 0 && iat == 0) break;
            if (nameRva == 0) break;
            string dll = ReadAsciiZ(data, RvaToOffset(data, pe, nameRva, 1), 260);
            imports.Add(dll);
            if (!String.Equals(dll, "KERNEL32.dll", StringComparison.OrdinalIgnoreCase))
                throw new InvalidDataException("Worker host contains forbidden PE import '" + dll + "' in " + path);
        }
        if (imports.Count == 0)
            throw new InvalidDataException("Worker host has no imports: " + path);

        // 2. Reject Delay-Load imports so GUI DLLs cannot be hidden there.
        uint delayRva = BitConverter.ToUInt32(data, optional + 112 + 13 * 8);
        if (delayRva != 0)
            throw new InvalidDataException("Worker host must not declare delay-load imports: " + path);

        // 3. Verify CET_COMPAT characteristic matches requested mode.
        uint debugRva = BitConverter.ToUInt32(data, optional + 112 + 6 * 8);
        uint debugBytes = BitConverter.ToUInt32(data, optional + 112 + 6 * 8 + 4);
        bool cet = false;
        if (debugRva != 0 && debugBytes != 0)
        {
            if (debugBytes % 28 != 0 || debugBytes > 28 * 1024)
                throw new InvalidDataException("Invalid PE debug directory.");
            int directory = RvaToOffset(data, pe, debugRva, checked((int)debugBytes));
            for (int i = 0; i < debugBytes / 28; i++)
            {
                int entry = directory + i * 28;
                if (BitConverter.ToUInt32(data, entry + 12) != 20) continue;
                uint size = BitConverter.ToUInt32(data, entry + 16), offset = BitConverter.ToUInt32(data, entry + 24);
                if (size < 4 || offset > data.Length - 4) throw new InvalidDataException("Invalid extended DLL characteristics.");
                cet |= (BitConverter.ToUInt32(data, checked((int)offset)) & 1) != 0;
            }
        }
        if (cet != expectedCetCompat)
            throw new InvalidDataException("Unexpected CET_COMPAT value for " + path + "; expected " + expectedCetCompat + ", actual " + cet);
    }
}
'@

function Test-WorkerHostBinary([string]$Path, [bool]$ExpectedCet) {
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return $false }
    try {
        [SteamSentinelWorkerHostPeInspector]::Verify($Path, $ExpectedCet)
        return $true
    } catch {
        return $false
    }
}

if ($Incremental -and (Test-Path -LiteralPath $OutputPath -PathType Leaf)) {
    $outTime = (Get-Item -LiteralPath $OutputPath).LastWriteTimeUtc
    $srcTime = (Get-Item -LiteralPath $SourcePath).LastWriteTimeUtc
    $manTime = (Get-Item -LiteralPath $ManifestPath).LastWriteTimeUtc
    if ($outTime -ge $srcTime -and $outTime -ge $manTime -and (Test-WorkerHostBinary -Path $OutputPath -ExpectedCet $expectCetCompat)) {
        Write-Host "Worker host is up to date: $OutputPath"
        exit 0
    }
}

$vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
$visualStudio = $null
if (Test-Path -LiteralPath $vswhere -PathType Leaf) {
    # 先等待 vswhere.exe 完整退出再筛选，避免 Select-Object -First 1 提前中止管道导致 $LASTEXITCODE = -1
    $vsCandidates = @(& $vswhere '-latest' '-products' '*' '-requires' 'Microsoft.VisualStudio.Component.VC.Tools.x86.x64' '-property' 'installationPath' 2>$null)
    if ($LASTEXITCODE -eq 0) {
        $visualStudio = $vsCandidates | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Select-Object -First 1
    }
}
$vcvars = if ([string]::IsNullOrWhiteSpace($visualStudio)) { $null } else { Join-Path $visualStudio 'VC\Auxiliary\Build\vcvars64.bat' }
if ([string]::IsNullOrWhiteSpace($vcvars) -or -not (Test-Path -LiteralPath $vcvars -PathType Leaf)) {
    if ($Optional) {
        Write-Host 'Visual Studio x64 C++ Build Tools not found; skipping optional native worker host replacement.'
        exit 0
    }
    throw 'Visual Studio C++ Build Tools (vcvars64.bat) are required to build the native worker host.'
}

New-Item -ItemType Directory -Path (Split-Path -Parent $OutputPath) -Force | Out-Null
New-Item -ItemType Directory -Path $BuildDirectory -Force | Out-Null

$versionTuple = $Version.Replace('.', ',') + ',0'
$rcPath = Join-Path $BuildDirectory 'WorkerHost.rc'
$resPath = Join-Path $BuildDirectory 'WorkerHost.res'
$objPath = Join-Path $BuildDirectory 'WorkerHost.obj'
$cmdPath = Join-Path $BuildDirectory 'compile-worker-host.cmd'

$rcText = @"
#pragma code_page(65001)
#include <windows.h>
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
      VALUE "FileDescription", "SteamSentinel isolated archive worker host\0"
      VALUE "FileVersion", "$Version.0\0"
      VALUE "InternalName", "SteamSentinel.ArchiveWorker\0"
      VALUE "LegalCopyright", "Copyright 2026 fenglinbei\0"
      VALUE "OriginalFilename", "$OriginalFilename\0"
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
[IO.File]::WriteAllText($rcPath, $rcText, [Text.UTF8Encoding]::new($false))

$defines = '/DUNICODE /D_UNICODE /DWIN32_LEAN_AND_MEAN /DNOMINMAX'
if ($isSelfContainedOnly) { $defines += ' /DSTEAMSENTINEL_SELF_CONTAINED_ONLY' }
$cetFlag = if ($expectCetCompat) { '/CETCOMPAT' } else { '/CETCOMPAT:NO' }

$cmdText = @"
@echo off
chcp 65001 >nul
call "$vcvars" >nul
if errorlevel 1 exit /b %errorlevel%
rc.exe /nologo /c65001 /fo "$resPath" "$rcPath"
if errorlevel 1 exit /b %errorlevel%
cl.exe /nologo /std:c++17 /W4 /WX /utf-8 /EHsc /MT /O2 $defines /Fo"$objPath" /Fe"$OutputPath" "$SourcePath" "$resPath" /link kernel32.lib /SUBSYSTEM:CONSOLE /DYNAMICBASE /NXCOMPAT /HIGHENTROPYVA /INCREMENTAL:NO $cetFlag /MANIFEST:EMBED /MANIFESTINPUT:"$ManifestPath"
exit /b %errorlevel%
"@
[IO.File]::WriteAllText($cmdPath, ($cmdText -replace '\r?\n', "`r`n") + "`r`n", [Text.UTF8Encoding]::new($false))

& $env:ComSpec '/d' '/c' $cmdPath | Out-Host
if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $OutputPath -PathType Leaf)) {
    throw "Native worker host compilation failed (exit $LASTEXITCODE)."
}

[SteamSentinelWorkerHostPeInspector]::Verify($OutputPath, $expectCetCompat)
Write-Host "Built and verified zero-USER32 native worker host ($OriginalFilename, CET_COMPAT=$expectCetCompat, SelfContainedOnly=$isSelfContainedOnly): $OutputPath"
