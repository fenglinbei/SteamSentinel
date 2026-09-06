[CmdletBinding()]
param(
    [ValidateSet('Small', 'Large')]
    [string] $Profile = 'Small',
    [string] $OutputDirectory,
    [string] $RarExe = 'D:\SteamSentinel-v020-validation-20260906\tools\rar723\Rar.exe',
    [string] $SevenZipExe
)

# Development-only, generated inert data. This script creates and lists archives; it never
# extracts an archive, starts an SFX, or executes any generated leaf or recovered content.
# Its only password is deliberately public and must never enter a product scan report.
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$password = 'fixture-only-2026'
$bufferBytes = 128 * 1024
if (-not $OutputDirectory) {
    $OutputDirectory = 'D:\SteamSentinel-v020-validation-20260906\topology-' + $Profile.ToLowerInvariant()
}
$OutputDirectory = [IO.Path]::GetFullPath($OutputDirectory)
if (-not [IO.Path]::IsPathFullyQualified($OutputDirectory) -or
    -not [IO.Path]::GetPathRoot($OutputDirectory).Equals('D:\', [StringComparison]::OrdinalIgnoreCase) -or
    $OutputDirectory.Equals('D:\', [StringComparison]::OrdinalIgnoreCase)) {
    throw 'The corpus must be created in a dedicated directory on D:, never on the system drive or at a drive root.'
}
for ($ancestor = $OutputDirectory; $ancestor; $ancestor = [IO.Path]::GetDirectoryName($ancestor)) {
    if ((Test-Path -LiteralPath $ancestor) -and
        ((Get-Item -LiteralPath $ancestor -Force).Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        throw "Refusing a reparse point in the corpus directory: $ancestor"
    }
}
if ((Test-Path -LiteralPath $OutputDirectory) -and @(Get-ChildItem -LiteralPath $OutputDirectory -Force).Count -gt 0) {
    throw 'The output directory is not empty. Choose a new directory; this script never overwrites or deletes an existing corpus.'
}
if (-not $SevenZipExe) {
    $SevenZipExe = (Get-Command 7z.exe -ErrorAction Stop).Source
    $shim = [IO.Path]::ChangeExtension($SevenZipExe, '.shim')
    if (Test-Path -LiteralPath $shim -PathType Leaf) {
        $target = Get-Content -LiteralPath $shim | Where-Object { $_ -match '^path\s*=\s*(.+)$' } | Select-Object -First 1
        if ($target -match '^path\s*=\s*(.+)$') { $SevenZipExe = $Matches[1].Trim().Trim('"') }
    }
}
$RarExe = [IO.Path]::GetFullPath($RarExe)
$SevenZipExe = [IO.Path]::GetFullPath($SevenZipExe)
$sfxModule = Join-Path ([IO.Path]::GetDirectoryName($RarExe)) 'Default.SFX'
foreach ($tool in @($RarExe, $SevenZipExe, $sfxModule)) {
    if (-not (Test-Path -LiteralPath $tool -PathType Leaf)) { throw "Required archive creation tool missing: $tool" }
}
$rarSignature = Get-AuthenticodeSignature -LiteralPath $RarExe
if ($rarSignature.Status -ne 'Valid' -or $rarSignature.SignerCertificate.Subject -notmatch 'win\.rar') {
    throw 'The RAR creator must have a currently valid win.rar Authenticode signature.'
}
$requiredFree = if ($Profile -eq 'Large') { 12GB } else { 128MB }
if ([IO.DriveInfo]::new('D:\').AvailableFreeSpace -lt $requiredFree) { throw 'Insufficient free space on D: for this corpus.' }
[IO.Directory]::CreateDirectory($OutputDirectory) | Out-Null
$folders = @{}
foreach ($name in @('01-leaves', '02-sfx', '03-disguised', '04-volumes', '05-header-rar', '06-aes-zip', '07-mp4', 'logs')) {
    $folders[$name] = Join-Path $OutputDirectory $name
    [IO.Directory]::CreateDirectory($folders[$name]) | Out-Null
}

function Get-Identity([string] $Path) {
    $file = Get-Item -LiteralPath $Path
    if ($file.Attributes -band [IO.FileAttributes]::SparseFile) { throw "A corpus file must never be sparse: $Path" }
    [ordered]@{
        Path = $file.FullName
        Length = [long] $file.Length
        Sha256 = (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash
        Sparse = $false
    }
}

function Get-ToolIdentity([string] $Path) {
    $identity = Get-Identity $Path
    $file = Get-Item -LiteralPath $Path
    $signature = Get-AuthenticodeSignature -LiteralPath $Path
    $identity.Version = $file.VersionInfo.FileVersion
    $identity.AuthenticodeStatus = $signature.Status.ToString()
    $identity.Signer = if ($signature.SignerCertificate) { $signature.SignerCertificate.Subject } else { $null }
    $identity
}

$tools = [ordered]@{
    Rar = Get-ToolIdentity $RarExe
    SevenZip = Get-ToolIdentity $SevenZipExe
    SfxModule = Get-ToolIdentity $sfxModule
    PowerShellVersion = $PSVersionTable.PSVersion.ToString()
    RuntimeVersion = [Environment]::Version.ToString()
}
$sevenZipDll = Join-Path ([IO.Path]::GetDirectoryName($SevenZipExe)) '7z.dll'
if (Test-Path -LiteralPath $sevenZipDll -PathType Leaf) { $tools.SevenZipDll = Get-ToolIdentity $sevenZipDll }
$runs = [Collections.Generic.List[object]]::new()

function Invoke-ArchiveTool([string] $Executable, [string[]] $Arguments, [string] $WorkingDirectory, [string] $Step) {
    if ($Arguments.Count -eq 0 -or $Arguments[0] -notin @('a', 'lb', 'l')) {
        throw 'Only archive creation and passive listing operations are allowed in this fixture generator.'
    }
    $expected = if ($Executable -eq $RarExe) { $tools.Rar.Sha256 } else { $tools.SevenZip.Sha256 }
    if ((Get-FileHash -LiteralPath $Executable -Algorithm SHA256).Hash -ne $expected) { throw 'An archive tool changed during corpus generation.' }
    Write-Host "[$([DateTimeOffset]::UtcNow.ToString('u'))] $Step"
    $start = [Diagnostics.ProcessStartInfo]::new()
    $start.FileName = $Executable
    $start.WorkingDirectory = $WorkingDirectory
    $start.UseShellExecute = $false
    $start.CreateNoWindow = $true
    $start.Environment['TEMP'] = $OutputDirectory
    $start.Environment['TMP'] = $OutputDirectory
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    foreach ($argument in $Arguments) { $start.ArgumentList.Add($argument) }
    $process = [Diagnostics.Process]::new()
    $process.StartInfo = $start
    $elapsed = [Diagnostics.Stopwatch]::StartNew()
    try {
        if (-not $process.Start()) { throw 'Archive creator did not start.' }
        $stdout = $process.StandardOutput.ReadToEndAsync()
        $stderr = $process.StandardError.ReadToEndAsync()
        $process.WaitForExit()
        $outputText = $stdout.GetAwaiter().GetResult()
        $errorText = $stderr.GetAwaiter().GetResult()
        [IO.File]::WriteAllText((Join-Path $folders.logs ($Step + '.stdout.txt')), $outputText)
        [IO.File]::WriteAllText((Join-Path $folders.logs ($Step + '.stderr.txt')), $errorText)
        $runs.Add([ordered]@{ Step = $Step; Executable = $Executable; Arguments = $Arguments; ExitCode = $process.ExitCode;
            ElapsedMilliseconds = $elapsed.ElapsedMilliseconds; Operation = $Arguments[0] })
        if ($process.ExitCode -ne 0) { throw "Archive creation/listing failed in $Step with exit code $($process.ExitCode): $errorText $outputText" }
        return $outputText
    }
    finally { $process.Dispose() }
}

function Write-RandomLeaf([string] $Path, [long] $Length) {
    $buffer = [byte[]]::new($bufferBytes)
    $rng = [Security.Cryptography.RandomNumberGenerator]::Create()
    $hash = [Security.Cryptography.IncrementalHash]::CreateHash([Security.Cryptography.HashAlgorithmName]::SHA256)
    $stream = [IO.FileStream]::new($Path, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::Read, $bufferBytes)
    try {
        [long] $remaining = $Length
        while ($remaining -gt 0) {
            $count = [int] [Math]::Min([long] $buffer.Length, $remaining)
            $rng.GetBytes($buffer)
            $stream.Write($buffer, 0, $count)
            $hash.AppendData($buffer, 0, $count)
            $remaining -= $count
        }
        $stream.Flush($true)
        return [Convert]::ToHexString($hash.GetHashAndReset())
    }
    finally { $stream.Dispose(); $hash.Dispose(); $rng.Dispose() }
}

function Put-U16([byte[]] $Buffer, [int] $Offset, [uint16] $Value) { [BitConverter]::GetBytes($Value).CopyTo($Buffer, $Offset) }
function Put-U32([byte[]] $Buffer, [int] $Offset, [uint32] $Value) { [BitConverter]::GetBytes($Value).CopyTo($Buffer, $Offset) }
function Put-U64([byte[]] $Buffer, [int] $Offset, [uint64] $Value) { [BitConverter]::GetBytes($Value).CopyTo($Buffer, $Offset) }

function New-InertPeHeader {
    # Structurally valid DOS/COFF/PE32+ headers and one non-executable .rdata section.
    # EntryPoint is zero, no imports or executable section are present, and this file is never run.
    $data = [byte[]]::new(1024)
    $data[0] = 0x4d; $data[1] = 0x5a
    Put-U32 $data 0x3c 0x80
    $data[0x80] = 0x50; $data[0x81] = 0x45
    Put-U16 $data 0x84 0x8664
    Put-U16 $data 0x86 1
    Put-U16 $data 0x94 0xf0
    Put-U16 $data 0x96 0x22
    Put-U16 $data 0x98 0x20b
    Put-U32 $data (0x98 + 8) 0x200
    Put-U64 $data (0x98 + 24) 0x140000000
    Put-U32 $data (0x98 + 32) 0x1000
    Put-U32 $data (0x98 + 36) 0x200
    Put-U16 $data (0x98 + 40) 6
    Put-U16 $data (0x98 + 48) 6
    Put-U32 $data (0x98 + 56) 0x2000
    Put-U32 $data (0x98 + 60) 0x200
    Put-U16 $data (0x98 + 68) 3
    Put-U16 $data (0x98 + 70) 0x160
    Put-U64 $data (0x98 + 72) 0x100000
    Put-U64 $data (0x98 + 80) 0x1000
    Put-U64 $data (0x98 + 88) 0x100000
    Put-U64 $data (0x98 + 96) 0x1000
    Put-U32 $data (0x98 + 108) 16
    [Text.Encoding]::ASCII.GetBytes('.rdata').CopyTo($data, 0x188)
    Put-U32 $data (0x188 + 8) 0x100
    Put-U32 $data (0x188 + 12) 0x1000
    Put-U32 $data (0x188 + 16) 0x200
    Put-U32 $data (0x188 + 20) 0x200
    Put-U32 $data (0x188 + 36) 0x40000040
    [Text.Encoding]::ASCII.GetBytes('SteamSentinel inert PE header fixture. No executable section. Never execute.').CopyTo($data, 0x200)
    return ,$data
}

function Write-Mp4Box([IO.Stream] $Stream, [string] $Type, [byte[]] $Payload) {
    [uint32] $size = 8 + $Payload.Length
    $header = [byte[]]::new(8)
    $header[0] = [byte] (($size -shr 24) -band 255)
    $header[1] = [byte] (($size -shr 16) -band 255)
    $header[2] = [byte] (($size -shr 8) -band 255)
    $header[3] = [byte] ($size -band 255)
    [Text.Encoding]::ASCII.GetBytes($Type).CopyTo($header, 4)
    $Stream.Write($header, 0, $header.Length)
    $Stream.Write($Payload, 0, $Payload.Length)
}

function Get-RangeHash([string] $Path, [long] $Offset, [long] $Length) {
    $stream = [IO.FileStream]::new($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read, $bufferBytes)
    $hash = [Security.Cryptography.IncrementalHash]::CreateHash([Security.Cryptography.HashAlgorithmName]::SHA256)
    $buffer = [byte[]]::new($bufferBytes)
    try {
        if ($Offset -lt 0 -or $Length -lt 0 -or $Offset -gt $stream.Length -or $Length -gt $stream.Length - $Offset) { throw 'Range outside owned fixture.' }
        $stream.Position = $Offset
        [long] $remaining = $Length
        while ($remaining -gt 0) {
            $read = $stream.Read($buffer, 0, [int] [Math]::Min([long] $buffer.Length, $remaining))
            if ($read -eq 0) { throw 'Unexpected EOF in generated range.' }
            $hash.AppendData($buffer, 0, $read)
            $remaining -= $read
        }
        return [Convert]::ToHexString($hash.GetHashAndReset())
    }
    finally { $stream.Dispose(); $hash.Dispose() }
}

Write-Host "Generating $Profile inert corpus in $OutputDirectory"
$leaves = [Collections.Generic.List[object]]::new()
$leafDirectory = $folders['01-leaves']
$pePath = Join-Path $leafDirectory 'leaf-0000-inert-header.exe'
[IO.File]::WriteAllBytes($pePath, (New-InertPeHeader))
$textPath = Join-Path $leafDirectory 'leaf-0001-inert-note.txt'
$note = [Text.Encoding]::UTF8.GetBytes(('SteamSentinel A01 inert topology fixture. No code, URLs, callbacks, or scripts.' + [Environment]::NewLine) * 52)
[IO.File]::WriteAllBytes($textPath, $note)
foreach ($path in @($pePath, $textPath)) {
    $identity = Get-Identity $path
    $leaves.Add([ordered]@{ RelativePath = [IO.Path]::GetFileName($path); Path = $path; Length = $identity.Length; Sha256 = $identity.Sha256; Sparse = $false })
}
[long] $leafTargetBytes = if ($Profile -eq 'Large') { 1200MB } else { 6MB }
[long] $randomTotal = $leafTargetBytes - $leaves[0].Length - $leaves[1].Length
[long] $baseLength = [long] [Math]::Floor($randomTotal / 165)
[long] $extraBytes = $randomTotal - $baseLength * 165
for ($index = 2; $index -lt 167; $index++) {
    $name = 'leaf-{0:D4}-inert-data.bin' -f $index
    $path = Join-Path $leafDirectory $name
    [long] $length = $baseLength + [long] ($index - 2 -lt $extraBytes)
    $sha256 = Write-RandomLeaf $path $length
    if ((Get-Item -LiteralPath $path).Attributes -band [IO.FileAttributes]::SparseFile) { throw 'A random leaf unexpectedly became sparse.' }
    $leaves.Add([ordered]@{ RelativePath = $name; Path = $path; Length = $length; Sha256 = $sha256; Sparse = $false })
    if ($index % 32 -eq 0) { Write-Host "Generated $($index + 1) / 167 inert leaves" }
}
if (($leaves | ForEach-Object { [long] $_.Length } | Measure-Object -Sum).Sum -ne $leafTargetBytes) { throw 'Leaf byte total does not match the requested real data size.' }

$sfxPath = Join-Path $folders['02-sfx'] 'pc.exe'
$commonRar = @('-cfg-', '-m0', '-s-', '-mt2', '-ep1', '-r-', '-o-', '-idq', '-y')
$null = Invoke-ArchiveTool $RarExe (@('a') + $commonRar + @(('-sfx' + $sfxModule), $sfxPath, '*')) $leafDirectory '01-create-rar-sfx'
$listedLeaves = Invoke-ArchiveTool $RarExe @('lb', '-cfg-', $sfxPath) $leafDirectory '02-list-sfx-leaves'
$listed = @($listedLeaves -split '\r?\n' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
if ($listed.Count -ne 167 -or @(Compare-Object @($leaves.RelativePath | Sort-Object) @($listed | Sort-Object)).Count -ne 0) {
    throw 'The SFX directory does not contain exactly the 167 generated leaves.'
}
[long] $sfxOffset = (Get-Item -LiteralPath $sfxModule).Length
$sfxStream = [IO.File]::OpenRead($sfxPath)
try {
    $sfxStream.Position = $sfxOffset
    $magic = [byte[]]::new(8)
    $sfxStream.ReadExactly($magic)
    if ([Convert]::ToHexString($magic) -ne '526172211A070100') { throw 'The SFX RAR5 payload does not start immediately after the official module.' }
}
finally { $sfxStream.Dispose() }

$disguisedRar = Join-Path $folders['03-disguised'] 'pc.rar'
$jpgPath = Join-Path $folders['03-disguised'] 'pc.jpg'
$null = Invoke-ArchiveTool $RarExe (@('a') + $commonRar + @($disguisedRar, 'pc.exe')) $folders['02-sfx'] '03-wrap-sfx-in-rar'
Move-Item -LiteralPath $disguisedRar -Destination $jpgPath
[long] $volumeBytes = [long] [Math]::Ceiling(((Get-Item -LiteralPath $jpgPath).Length + 65536) / 3.0)
$volumeTarget = Join-Path $folders['04-volumes'] 'pc.rar'
$null = Invoke-ArchiveTool $RarExe (@('a') + $commonRar + @(('-v' + $volumeBytes.ToString([Globalization.CultureInfo]::InvariantCulture) + 'b'), $volumeTarget, 'pc.jpg')) $folders['03-disguised'] '04-create-real-three-volume-rar'
$volumes = @(Get-ChildItem -LiteralPath $folders['04-volumes'] -File | Sort-Object Name)
if ($volumes.Count -ne 3 -or ($volumes.Name -join ',') -ne 'pc.part1.rar,pc.part2.rar,pc.part3.rar') {
    throw 'RAR did not produce exactly pc.part1.rar, pc.part2.rar and pc.part3.rar.'
}
$outerRar = Join-Path $folders['05-header-rar'] 'pc.rar'
$null = Invoke-ArchiveTool $RarExe (@('a') + $commonRar + @(('-hp' + $password), $outerRar, '*.rar')) $folders['04-volumes'] '05-create-header-encrypted-rar'
$listedVolumes = Invoke-ArchiveTool $RarExe @('lb', '-cfg-', ('-p' + $password), $outerRar) $folders['04-volumes'] '06-list-encrypted-rar-members'
if (@($listedVolumes -split '\r?\n' | Where-Object { $_.Trim() }).Count -ne 3) { throw 'The encrypted outer RAR does not contain three volumes.' }
$zipPath = Join-Path $folders['06-aes-zip'] 'pc.zip'
$null = Invoke-ArchiveTool $SevenZipExe @('a', '-tzip', '-mx=0', '-mem=AES256', ('-p' + $password), '-y', '-bd', '-bb0', $zipPath, 'pc.rar') $folders['05-header-rar'] '07-create-aes256-zip'
$zipListing = Invoke-ArchiveTool $SevenZipExe @('l', '-slt', ('-p' + $password), $zipPath) $folders['05-header-rar'] '08-list-aes256-zip'
if ($zipListing -notmatch 'AES-256' -or $zipListing -notmatch 'Encrypted = \+') { throw 'The ZIP listing did not confirm AES-256 encryption.' }

$mp4Path = Join-Path $folders['07-mp4'] 'pc.mp4'
$mediaPrefix = Join-Path $folders['07-mp4'] 'media-prefix.mp4'
$prefixStream = [IO.FileStream]::new($mediaPrefix, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
try {
    Write-Mp4Box $prefixStream 'ftyp' ([byte[]] (105, 115, 111, 109, 0, 0, 0, 0, 105, 115, 111, 109, 105, 115, 111, 50))
    Write-Mp4Box $prefixStream 'mdat' ([Text.Encoding]::ASCII.GetBytes('Inert media box payload. No playable track.'))
    Write-Mp4Box $prefixStream 'moov' ([byte[]]::new(0))
    $prefixStream.Flush($true)
}
finally { $prefixStream.Dispose() }
[long] $zipOffset = (Get-Item -LiteralPath $mediaPrefix).Length
$mp4 = [IO.FileStream]::new($mp4Path, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None, $bufferBytes)
try {
    foreach ($path in @($mediaPrefix, $zipPath)) {
        $input = [IO.FileStream]::new($path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read, $bufferBytes)
        try { $input.CopyTo($mp4, $bufferBytes) } finally { $input.Dispose() }
    }
    $mp4.Flush($true)
}
finally { $mp4.Dispose() }

Write-Host 'Hashing completed layers and writing the expected topology manifest'
$layers = [Collections.Generic.List[object]]::new()
function Add-Layer([string] $Name, [string] $Path, [string] $Format, [string[]] $Members, [Nullable[long]] $ParentOffset = $null) {
    $identity = Get-Identity $Path
    $layers.Add([ordered]@{ Name = $Name; Path = $identity.Path; Length = $identity.Length; Sha256 = $identity.Sha256;
        ParentOffset = $ParentOffset; Format = $Format; ExpectedMembers = $Members; Sparse = $false })
}
Add-Layer 'rar-sfx' $sfxPath 'PE + RAR5 SFX' @($leaves.RelativePath)
Add-Layer 'disguised-rar' $jpgPath 'RAR5 renamed to .jpg' @('pc.exe')
foreach ($volume in $volumes) { Add-Layer $volume.BaseName $volume.FullName 'RAR5 native volume' @('pc.jpg') }
Add-Layer 'header-encrypted-rar' $outerRar 'RAR5 encrypted headers and data' @($volumes.Name)
Add-Layer 'aes256-zip' $zipPath 'ZIP AES-256 Store' @('pc.rar') $zipOffset
Add-Layer 'mp4-zip-overlay' $mp4Path 'MP4 boxes followed by ZIP' @('embedded ZIP at the exact MP4 box boundary')
$sfxLength = (Get-Item -LiteralPath $sfxPath).Length
$zipIdentity = Get-Identity $zipPath
[long] $logicalTotal = $leafTargetBytes + (Get-Item -LiteralPath $sfxPath).Length + (Get-Item -LiteralPath $jpgPath).Length +
    ($volumes | Measure-Object Length -Sum).Sum + (Get-Item -LiteralPath $outerRar).Length + (Get-Item -LiteralPath $zipPath).Length
if ($Profile -eq 'Large' -and ($leafTargetBytes -lt 1.1GB -or $logicalTotal -le 4GB -or
    @($sfxPath, $jpgPath, $outerRar, $zipPath, $mp4Path | Where-Object { (Get-Item -LiteralPath $_).Length -le 1GB }).Count -ne 0)) {
    throw 'The large profile failed its real-size or cumulative logical byte requirements.'
}
$manifest = [ordered]@{
    SchemaVersion = 1
    Name = 'A01-inert-topology-' + $Profile.ToLowerInvariant()
    Profile = $Profile
    RootFile = $mp4Path
    Password = $password
    PasswordIsPublicFixtureData = $true
    CreatedAtUtc = [DateTimeOffset]::UtcNow.ToString('O')
    LeafCount = $leaves.Count
    LeafTotalBytes = $leafTargetBytes
    CumulativeLogicalBytes = $logicalTotal
    Leaves = $leaves.ToArray()
    Layers = $layers.ToArray()
    EmbeddedRanges = @(
        [ordered]@{ ParentPath = $sfxPath; Format = 'RAR5'; Offset = $sfxOffset; Length = $sfxLength - $sfxOffset;
            Sha256 = Get-RangeHash $sfxPath $sfxOffset ($sfxLength - $sfxOffset) },
        [ordered]@{ ParentPath = $mp4Path; Format = 'ZIP'; Offset = $zipOffset; Length = $zipIdentity.Length; Sha256 = $zipIdentity.Sha256 }
    )
    NativeRarVolumeCount = $volumes.Count
    NativeRarVolumeSizeBytes = $volumeBytes
    SfxIsOfficialRarModule = $true
    Compression = 'RAR m0 non-solid; ZIP Store with AES-256. Real random file bytes; no sparse files or large arrays.'
    Encryption = 'Header RAR and outer ZIP use the public fixture password; inner RAR SFX, disguised RAR and native volumes are unencrypted.'
    MediaPrefix = 'Well-formed ftyp, mdat and moov top-level boxes. No playable media track is claimed.'
    ExecutionAudit = [ordered]@{ GeneratedFilesExecuted = @(); SfxExecuted = $false; ExtractionUsed = $false;
        CommandsAllowed = @('a', 'lb', 'l'); ArchiveToolRuns = $runs.ToArray(); MaximumManagedWriteBufferBytes = $bufferBytes }
    Tools = $tools
}
$manifestPath = Join-Path $OutputDirectory 'manifest.json'
[IO.File]::WriteAllText($manifestPath, ($manifest | ConvertTo-Json -Depth 12), [Text.UTF8Encoding]::new($false))
Write-Host "MANIFEST=$manifestPath"
Write-Host "ROOT_FILE=$mp4Path"
Write-Host "LEAVES=$($leaves.Count); LEAF_BYTES=$leafTargetBytes; LOGICAL_BYTES=$logicalTotal"
