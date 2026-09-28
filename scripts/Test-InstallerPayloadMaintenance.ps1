# Exercise the actual installer maintenance core against new, inert temporary fixtures.
# The production script has no caller-selected installation root; this test-only build does.
[CmdletBinding()]
param([Parameter(Mandatory=$true)][string]$ResultsPath)
Set-StrictMode -Version Latest;$ErrorActionPreference='Stop'
if($PSVersionTable.PSVersion.Major-ne5-or-not[Environment]::Is64BitProcess){throw 'Use x64 Windows PowerShell 5.1.'}
$source=Join-Path (Split-Path $PSScriptRoot -Parent) 'installer\PayloadMaintenance.cs'
$ResultsPath=[IO.Path]::GetFullPath($ResultsPath)
if(Test-Path -LiteralPath $ResultsPath){throw 'Preserve existing test results.'}
$sourceHash=(Get-FileHash -LiteralPath $source -Algorithm SHA256).Hash
$parameters=New-Object CodeDom.Compiler.CompilerParameters
$parameters.CompilerOptions='/define:STEAMSENTINEL_INSTALLER_TESTS'
$parameters.GenerateInMemory=$true
foreach($assembly in @('System.dll','System.Core.dll')){$null=$parameters.ReferencedAssemblies.Add($assembly)}
Add-Type -TypeDefinition ([IO.File]::ReadAllText($source)) -CompilerParameters $parameters
Add-Type -TypeDefinition @'
using System;
using System.Text;
using System.Runtime.InteropServices;
public static class InstallerShortPathTests {
 [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
 public static extern uint GetShortPathName(string input, StringBuilder output, uint length);
}
'@
$started=[DateTime]::UtcNow;$clock=[Diagnostics.Stopwatch]::StartNew()
$fixtureRoot=Join-Path ([IO.Path]::GetTempPath()) ('SteamSentinel-InstallerTests-'+[guid]::NewGuid().ToString('N'))
$identity=[Security.Principal.WindowsIdentity]::GetCurrent().User
$security=New-Object Security.AccessControl.DirectorySecurity
$security.SetOwner($identity);$security.SetAccessRuleProtection($true,$false)
foreach($sid in @($identity.Value,'S-1-5-18','S-1-5-32-544')|Select-Object -Unique){$security.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new($sid),[Security.AccessControl.FileSystemRights]::FullControl,([Security.AccessControl.InheritanceFlags]::ContainerInherit-bor[Security.AccessControl.InheritanceFlags]::ObjectInherit),[Security.AccessControl.PropagationFlags]::None,[Security.AccessControl.AccessControlType]::Allow))}
[IO.Directory]::CreateDirectory($fixtureRoot,$security)|Out-Null
$results=New-Object 'Collections.Generic.List[object]'
$shortPathExamples=New-Object 'Collections.Generic.List[object]'
function Check([bool]$Condition,[string]$Message){if(-not$Condition){throw $Message}}
function Hash([string]$Path){return(Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash}
function Bytes([string]$Value){return,[Text.Encoding]::UTF8.GetBytes($Value)}
function WriteBytes([string]$Path,[byte[]]$Value){$parent=[IO.Path]::GetDirectoryName($Path);if(-not[IO.Directory]::Exists($parent)){[IO.Directory]::CreateDirectory($parent)|Out-Null};[IO.File]::WriteAllBytes($Path,$Value)}
function Fixture([string]$Name){
 $base=Join-Path $fixtureRoot $Name;[IO.Directory]::CreateDirectory($base)|Out-Null;$root=Join-Path $base 'app';[IO.Directory]::CreateDirectory($root)|Out-Null
 WriteBytes (Join-Path $root 'current.dll') (Bytes 'inert current payload, never executable')
 WriteBytes (Join-Path $root 'docs\guide.txt') (Bytes 'inert guide')
 $manifest=Join-Path $base 'incoming.txt'
 $text=(Hash (Join-Path $root 'current.dll'))+' *current.dll'+"`r`n"+(Hash (Join-Path $root 'docs\guide.txt'))+' *docs\guide.txt'+"`r`n"
 WriteBytes $manifest (Bytes $text);[IO.File]::Copy($manifest,(Join-Path $root 'SHA256SUMS.txt'))
 return [pscustomobject]@{name=$Name;base=$base;root=$root;manifest=$manifest;manifestHash=(Hash $manifest);catalog=[LegacyEntry[]]@()}
}
function AddLegacy($Fixture,[string]$Relative='obsolete.dll',[string]$Text='inert obsolete payload'){
 $p=Join-Path $Fixture.root $Relative;WriteBytes $p (Bytes $Text)
 $e=[LegacyEntry]::new($Relative,[long](Get-Item -LiteralPath $p).Length,(Hash $p));$Fixture.catalog=[LegacyEntry[]]@($Fixture.catalog+$e);return $p
}
function RunCore($Fixture,[string]$Mode,[Action]$Callback=$null){return [SteamSentinelPayloadMaintenance]::RunForTest($Mode,$Fixture.root,$Fixture.manifest,$Fixture.manifestHash,[LegacyEntry[]]$Fixture.catalog,$Callback)}
function Reject([scriptblock]$Operation,[string[]]$Codes){
 try{$null=& $Operation}catch{
  $errorObject=$_.Exception;while($null-ne$errorObject-and$errorObject.GetType().Name-ne'MaintenanceException'){$errorObject=$errorObject.InnerException}
  if($null-eq$errorObject){throw};if([string]$errorObject.Code-notin$Codes){throw ('Unexpected rejection code: '+$errorObject.Code+'; expected '+($Codes-join','))};return [string]$errorObject.Code
 };throw 'Operation unexpectedly succeeded.'
}
function Test([string]$Name,[scriptblock]$Body){
 $timer=[Diagnostics.Stopwatch]::StartNew();try{& $Body;$results.Add([pscustomobject]@{name=$Name;passed=$true;elapsedMs=$timer.ElapsedMilliseconds;error=$null});Write-Host ('PASS: '+$Name)}catch{$results.Add([pscustomobject]@{name=$Name;passed=$false;elapsedMs=$timer.ElapsedMilliseconds;error=$_.Exception.ToString();position=$_.InvocationInfo.PositionMessage;stack=$_.ScriptStackTrace});Write-Host ('FAIL: '+$Name+' - '+$_.Exception.Message)}
}
function AddUsersWrite([string]$Path){$acl=Get-Acl -LiteralPath $Path;$acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new('S-1-5-32-545'),[Security.AccessControl.FileSystemRights]::Write,[Security.AccessControl.AccessControlType]::Allow));Set-Acl -LiteralPath $Path -AclObject $acl}
function AssertUnchanged([string]$Path,[string]$Expected){Check (Test-Path -LiteralPath $Path -PathType Leaf) 'Preserved file was removed.';Check ((Hash $Path)-eq$Expected) 'Preserved file content changed.'}
function RealShortPath([string]$Path){
 $buffer=[Text.StringBuilder]::new(32768);$n=[InstallerShortPathTests]::GetShortPathName($Path,$buffer,[uint32]$buffer.Capacity)
 Check ($n-gt0-and$n-lt$buffer.Capacity) 'GetShortPathName failed.';$short=$buffer.ToString()
 Check ($short-match'\\[^\\]*~[^\\]*') 'Fixture has no real 8.3 alias; this coverage must not be skipped.'
 $shortPathExamples.Add([pscustomobject]@{input=$Path;short=$short});return $short
}
function AddHistoricalImages($Fixture){
 $Fixture.catalog=[SteamSentinelPayloadMaintenance]::GetCatalogForTest()
 foreach($name in @('App.ico','App.png')){
  $p=Join-Path $Fixture.root ('Assets\'+$name);$original=Join-Path (Split-Path $PSScriptRoot -Parent) ('SteamSentinel.App\Assets\'+$name)
  WriteBytes $p ([IO.File]::ReadAllBytes($original))
  $entry=@($Fixture.catalog|Where-Object{$_.RelativePath-ceq('Assets\'+$name)})
  Check ($entry.Count-eq1-and$entry[0].Bytes-eq(Get-Item -LiteralPath $p).Length-and$entry[0].Sha256-ceq(Hash $p)) 'Historical image differs from the production catalog.'
 }
}
try{
 Test 'A real short incoming manifest path passes all three phases' {
  $f=Fixture 'short-manifest';$f.manifest=RealShortPath $f.manifest
  foreach($mode in @('Preflight','Retire','Verify')){$null=RunCore $f $mode}
 }
 Test 'A real short installation path retires only approved bytes and verifies' {
  $f=Fixture 'short-root';$old=AddLegacy $f;$h=Hash (Join-Path $f.root 'current.dll');$f.root=RealShortPath $f.root
  $null=RunCore $f 'Preflight';Check (Test-Path -LiteralPath $old) 'Preflight removed old bytes.';$null=RunCore $f 'Retire'
  Check (-not(Test-Path -LiteralPath $old)) 'Approved old bytes remain.';AssertUnchanged (Join-Path $f.root 'current.dll') $h;$null=RunCore $f 'Verify'
 }
 Test 'A missing installation leaf below a real short parent passes preflight only' {
  $f=Fixture 'short-fresh';$f.root=Join-Path (RealShortPath $f.base) 'not-installed';$f.manifest=RealShortPath $f.manifest
  $null=RunCore $f 'Preflight';Check (-not(Test-Path -LiteralPath $f.root)) 'Preflight created an installation.';$null=Reject {RunCore $f 'Retire'} @('InstallationMissing')
 }
 Test 'A real short TEMP is accepted by the bounded test entry point' {
  $savedTemp=$env:TEMP;$savedTmp=$env:TMP
  try{$short=RealShortPath $fixtureRoot;$env:TEMP=$short;$env:TMP=$short;$f=Fixture 'short-temp';$null=RunCore $f 'Verify'}finally{$env:TEMP=$savedTemp;$env:TMP=$savedTmp}
 }
 Test 'A short manifest alias through a junction is rejected without touching its target' {
  $f=Fixture 'short-manifest-junction';$link=Join-Path $f.base 'redirected-directory';New-Item -ItemType Junction -Path $link -Target (Join-Path $f.root 'docs')|Out-Null
  $target=Join-Path $f.root 'docs\guide.txt';$h=Hash $target;$f.manifest=Join-Path (RealShortPath $link) 'guide.txt';$null=Reject {RunCore $f 'Preflight'} @('UnsafePath');AssertUnchanged $target $h
 }
 Test 'A short installation-root junction is rejected before retirement' {
  $f=Fixture 'short-root-junction';$old=AddLegacy $f;$h=Hash $old;$link=Join-Path $f.base 'redirected-installation';New-Item -ItemType Junction -Path $link -Target $f.root|Out-Null
  $f.root=RealShortPath $link;$null=Reject {RunCore $f 'Retire'} @('UnsafePath');AssertUnchanged $old $h
 }
 Test 'A short junction ancestor cannot conceal a missing fresh-install leaf' {
  $f=Fixture 'short-parent-junction';$link=Join-Path $f.base 'redirected-parent';New-Item -ItemType Junction -Path $link -Target $f.root|Out-Null
  $f.root=Join-Path (RealShortPath $link) 'missing-leaf';$null=Reject {RunCore $f 'Preflight'} @('UnsafePath');Check (-not(Test-Path -LiteralPath $f.root)) 'Rejected preflight created a target.'
 }
 Test 'A hard-linked incoming manifest remains rejected through its short alias' {
  $f=Fixture 'short-hardlink';$h=Hash $f.manifest;$link=Join-Path $f.base 'linked-manifest.txt';New-Item -ItemType HardLink -Path $link -Target $f.manifest|Out-Null
  $f.manifest=RealShortPath $link;$null=Reject {RunCore $f 'Preflight'} @('UnsafePath');AssertUnchanged $link $h
 }
 foreach($suffix in @('..\incoming.txt','.\incoming.txt','incoming.txt:stream','incoming.txt.','incoming.txt ','CON.txt','COM1.txt','a\\incoming.txt','a/incoming.txt')){
  $badSuffix=$suffix
  Test ('Absolute manifest syntax is rejected before normalization: '+$badSuffix) {
   $f=Fixture ('bad-absolute-'+[guid]::NewGuid().ToString('N'));$f.manifest=$f.base+'\'+$badSuffix
   try{$null=RunCore $f 'Preflight';throw 'Unsafe syntax was accepted.'}catch{
    $e=$_.Exception;while($null-ne$e-and$e.GetType().Name-ne'MaintenanceException'){$e=$e.InnerException}
    Check ($null-ne$e-and$e.Code-eq'UnsafePath'-and$e.RelativePath-eq'<incoming-manifest-path>') 'Missing path-specific rejection.'
    Check ($e.Message.Contains('Stage=NormalizePath; Input=')-and$e.Message.Contains($f.base)-and$e.Message.Length-le2300) 'Missing or unbounded normalization diagnostic.'
   }
  }
 }
 Test 'UNC and device manifest paths remain rejected' {
  $f=Fixture 'non-dos-paths';foreach($bad in @('\\localhost\c$\incoming.txt','\\?\C:\incoming.txt','\\.\C:\incoming.txt','C:incoming.txt')){$f.manifest=$bad;$null=Reject {RunCore $f 'Preflight'} @('UnsafePath')}
 }
 Test 'Production catalog retires the two byte-exact historical images' {
  $f=Fixture 'historical-images';AddHistoricalImages $f;$h=Hash (Join-Path $f.root 'current.dll');$null=RunCore $f 'Preflight'
  Check ((Test-Path -LiteralPath (Join-Path $f.root 'Assets\App.ico'))-and(Test-Path -LiteralPath (Join-Path $f.root 'Assets\App.png'))) 'Preflight removed images.'
  $null=RunCore $f 'Retire';Check (-not(Test-Path -LiteralPath (Join-Path $f.root 'Assets\App.ico'))-and-not(Test-Path -LiteralPath (Join-Path $f.root 'Assets\App.png'))) 'Historical images remain.'
  AssertUnchanged (Join-Path $f.root 'current.dll') $h;$null=RunCore $f 'Verify'
 }
 Test 'A modified historical image preserves both old image files' {
  $f=Fixture 'historical-image-tamper';AddHistoricalImages $f;$a=Join-Path $f.root 'Assets\App.ico';$ah=Hash $a;$b=Join-Path $f.root 'Assets\App.png';[IO.File]::AppendAllText($b,'tamper');$bh=Hash $b
  $null=Reject {RunCore $f 'Retire'} @('LegacyContentMismatch');AssertUnchanged $a $ah;AssertUnchanged $b $bh
 }
 Test 'An unknown historical image name prevents any image retirement' {
  $f=Fixture 'historical-image-unknown';AddHistoricalImages $f;$a=Join-Path $f.root 'Assets\App.ico';$ah=Hash $a;$extra=Join-Path $f.root 'Assets\Other.png';WriteBytes $extra (Bytes 'unreviewed image');$h=Hash $extra
  $null=Reject {RunCore $f 'Retire'} @('UnknownFile');AssertUnchanged $a $ah;AssertUnchanged $extra $h
 }
 Test 'A historical image included in the incoming manifest is not retired' {
  $f=Fixture 'historical-image-current';AddHistoricalImages $f
  foreach($name in @('App.ico','App.png')){[IO.File]::AppendAllText($f.manifest,(Hash (Join-Path $f.root ('Assets\'+$name)))+' *Assets\'+$name+"`r`n",[Text.UTF8Encoding]::new($false))}
  $f.manifestHash=Hash $f.manifest;[IO.File]::Copy($f.manifest,(Join-Path $f.root 'SHA256SUMS.txt'),$true);$null=RunCore $f 'Retire';$null=RunCore $f 'Verify'
 }
 Test 'Fresh preflight neither creates an installation nor allows retirement before install' {
  $f=Fixture 'fresh';$f.root=Join-Path $f.base 'not-installed';$null=RunCore $f 'Preflight';Check (-not(Test-Path -LiteralPath $f.root)) 'Preflight created the install root.';$null=Reject {RunCore $f 'Retire'} @('InstallationMissing');$null=Reject {RunCore $f 'Verify'} @('InstallationMissing')
 }
 Test 'Current nested payload verifies without deleting or rewriting it' {
  $f=Fixture 'current';$h=Hash (Join-Path $f.root 'current.dll');$acl=(Get-Acl -LiteralPath $f.root).Sddl
  $null=RunCore $f 'Preflight';$null=RunCore $f 'Retire';$null=RunCore $f 'Verify'
  AssertUnchanged (Join-Path $f.root 'current.dll') $h;Check ((Get-Acl -LiteralPath $f.root).Sddl-ceq$acl) 'Root ACL was rewritten.'
 }
 Test 'Exact approved obsolete bytes retire while current payload survives' {
  $f=Fixture 'exact';$old=AddLegacy $f;$h=Hash (Join-Path $f.root 'current.dll');$null=RunCore $f 'Preflight';Check (Test-Path -LiteralPath $old) 'Preflight deleted a file.';$null=RunCore $f 'Retire';Check (-not(Test-Path -LiteralPath $old)) 'Obsolete file remains.';AssertUnchanged (Join-Path $f.root 'current.dll') $h;$null=RunCore $f 'Verify'
 }
 Test 'Both approved obsolete entries retire only after validation' {
  $f=Fixture 'two-approved';$a=AddLegacy $f 'obsolete-a.dll' 'old a';$b=AddLegacy $f 'SIGNER.cer' 'old public certificate fixture';$null=RunCore $f 'Retire';Check (-not(Test-Path -LiteralPath $a)-and-not(Test-Path -LiteralPath $b)) 'Approved pair not retired.';$null=RunCore $f 'Verify'
 }
 Test 'Unknown DLL refuses retirement and preserves approved old bytes' {
  $f=Fixture 'unknown-dll';$old=AddLegacy $f;$h=Hash $old;$unknown=Join-Path $f.root 'unknown.dll';WriteBytes $unknown (Bytes 'unknown inert DLL');$u=Hash $unknown;$null=Reject {RunCore $f 'Retire'} @('UnknownFile');AssertUnchanged $old $h;AssertUnchanged $unknown $u
 }
 Test 'Unknown old flattened documentation is not blindly deleted' {
  $f=Fixture 'unknown-doc';$p=Join-Path $f.root 'COVERAGE-0.1.11.md';WriteBytes $p (Bytes 'unreviewed local notes');$h=Hash $p;$null=Reject {RunCore $f 'Preflight'} @('UnknownFile');AssertUnchanged $p $h
 }
 Test 'Catalog filename with different content is preserved and refused' {
  $f=Fixture 'tamper';$p=AddLegacy $f;WriteBytes $p (Bytes 'tampered obsolete bytes');$h=Hash $p;$null=Reject {RunCore $f 'Retire'} @('LegacyContentMismatch','FileChanged');AssertUnchanged $p $h
 }
 Test 'Second bad catalog entry prevents deletion of the first' {
  $f=Fixture 'atomic-validation';$a=AddLegacy $f 'obsolete-a.dll' 'old a';$ah=Hash $a;$b=AddLegacy $f 'obsolete-b.dll' 'old b';WriteBytes $b (Bytes 'bad b');$bh=Hash $b;$null=Reject {RunCore $f 'Retire'} @('LegacyContentMismatch','FileChanged');AssertUnchanged $a $ah;AssertUnchanged $b $bh
 }
 Test 'A catalog path in the incoming payload is preserved, including SIGNER.cer' {
  $f=Fixture 'current-signer';$p=AddLegacy $f 'SIGNER.cer' 'current public certificate fixture';$h=Hash $p
  [IO.File]::AppendAllText($f.manifest,$h+' *SIGNER.cer'+"`r`n",[Text.UTF8Encoding]::new($false));$f.manifestHash=Hash $f.manifest;[IO.File]::Copy($f.manifest,(Join-Path $f.root 'SHA256SUMS.txt'),$true)
  $null=RunCore $f 'Retire';AssertUnchanged $p $h;$null=RunCore $f 'Verify'
 }
 Test 'Current incoming catalog path is preserved even when its previous approved hash differs' {
  $f=Fixture 'current-path';$p=AddLegacy $f 'current.dll' 'legacy version of current name';WriteBytes $p (Bytes 'inert current payload, never executable');$h=Hash $p;$null=RunCore $f 'Retire';AssertUnchanged $p $h;$null=RunCore $f 'Verify'
 }
 Test 'Tampered incoming manifest fails its expected hash before retirement' {
  $f=Fixture 'manifest-hash';$p=AddLegacy $f;$h=Hash $p;[IO.File]::AppendAllText($f.manifest,'tamper',[Text.Encoding]::UTF8);$null=Reject {RunCore $f 'Retire'} @('InvalidManifest');AssertUnchanged $p $h
 }
 Test 'Duplicate incoming manifest path is refused' {
  $f=Fixture 'manifest-duplicate';[IO.File]::AppendAllText($f.manifest,(Hash (Join-Path $f.root 'current.dll'))+' *CURRENT.dll'+"`r`n",[Text.Encoding]::UTF8);$f.manifestHash=Hash $f.manifest;$null=Reject {RunCore $f 'Preflight'} @('InvalidManifest','UnsafePath')
 }
 foreach($bad in @('..\outside.dll','C:\outside.dll','current.dll:stream')){
  $badPath=$bad
  Test ('Incoming manifest rejects unsafe path '+$badPath) {
   $f=Fixture ('unsafe-'+[guid]::NewGuid().ToString('N'));WriteBytes $f.manifest (Bytes (('A'*64)+' *'+$badPath+"`r`n"));$f.manifestHash=Hash $f.manifest;$null=Reject {RunCore $f 'Preflight'} @('InvalidManifest','UnsafePath')
  }
 }
 Test 'Users-writable installation root is refused without fixing its ACL' {
  $f=Fixture 'root-write';$p=AddLegacy $f;$h=Hash $p;AddUsersWrite $f.root;$acl=(Get-Acl -LiteralPath $f.root).Sddl;$null=Reject {RunCore $f 'Retire'} @('UnsafePermissions');AssertUnchanged $p $h;Check ((Get-Acl -LiteralPath $f.root).Sddl-ceq$acl) 'Unsafe root ACL was rewritten.'
 }
 Test 'Users-writable nested directory is refused' {
  $f=Fixture 'directory-write';$p=AddLegacy $f;$h=Hash $p;AddUsersWrite (Join-Path $f.root 'docs');$null=Reject {RunCore $f 'Retire'} @('UnsafePermissions');AssertUnchanged $p $h
 }
 Test 'Users-writable catalog file is refused without deletion or permission repair' {
  $f=Fixture 'file-write';$p=AddLegacy $f;$h=Hash $p;AddUsersWrite $p;$acl=(Get-Acl -LiteralPath $p).Sddl;$null=Reject {RunCore $f 'Retire'} @('UnsafePermissions');AssertUnchanged $p $h;Check ((Get-Acl -LiteralPath $p).Sddl-ceq$acl) 'Unsafe file ACL was rewritten.'
 }
 Test 'An external open handle blocks retirement without deleting any approved entry' {
  $f=Fixture 'busy';$a=AddLegacy $f 'obsolete-a.dll' 'old a';$b=AddLegacy $f 'obsolete-b.dll' 'old b';$ah=Hash $a;$bh=Hash $b;$held=[IO.File]::Open($b,'Open','Read','Read')
  try{$null=Reject {RunCore $f 'Retire'} @('FileBusy');AssertUnchanged $a $ah;AssertUnchanged $b $bh}finally{$held.Dispose()}
 }
 Test 'Pinned obsolete file rejects racing replacement and retirement uses its original handle' {
  $f=Fixture 'rename-race';$p=AddLegacy $f;$replacement=Join-Path $f.base 'replacement.dll';WriteBytes $replacement (Bytes 'replacement must survive');$rh=Hash $replacement;$state=[pscustomobject]@{callback=0;blocked=$false}
  $callback=[Action]{ $state.callback++;try{[IO.File]::Move($p,$p+'.moved')}catch [IO.IOException]{$state.blocked=$true} }
  $null=RunCore $f 'Retire' $callback;Check ($state.callback-eq1-and$state.blocked) 'Pinned file could be renamed.';Check (-not(Test-Path -LiteralPath $p)-and-not(Test-Path -LiteralPath ($p+'.moved'))) 'Unexpected retired/renamed state.';AssertUnchanged $replacement $rh
 }
 Test 'Pinned obsolete file rejects racing content writes' {
  $f=Fixture 'write-race';$p=AddLegacy $f;$state=[pscustomobject]@{callback=0;blocked=$false};$callback=[Action]{$state.callback++;try{[IO.File]::WriteAllBytes($p,(Bytes 'race'))}catch [IO.IOException]{$state.blocked=$true}}
  $null=RunCore $f 'Retire' $callback;Check ($state.callback-eq1-and$state.blocked) 'Pinned file accepted a writer.';Check (-not(Test-Path -LiteralPath $p)) 'Validated original not retired.'
 }
 Test 'ACL changed during the pinned retirement window refuses every deletion' {
  $f=Fixture 'acl-race';$a=AddLegacy $f 'obsolete-a.dll' 'old a';$b=AddLegacy $f 'obsolete-b.dll' 'old b';$ah=Hash $a;$bh=Hash $b;$state=[pscustomobject]@{callback=0};$callback=[Action]{$state.callback++;AddUsersWrite $b}
  $null=Reject {RunCore $f 'Retire' $callback} @('UnsafePermissions','FileChanged');Check ($state.callback-eq1) 'Race callback was not reached.';AssertUnchanged $a $ah;AssertUnchanged $b $bh
 }
 Test 'Directory junction below the installation root refuses traversal and preserves the target' {
  $f=Fixture 'child-junction';$target=Join-Path $f.base 'external';[IO.Directory]::CreateDirectory($target)|Out-Null;$sentinel=Join-Path $target 'outside.txt';WriteBytes $sentinel (Bytes 'outside must survive');$h=Hash $sentinel
  New-Item -ItemType Junction -Path (Join-Path $f.root 'redirect') -Target $target|Out-Null;$null=Reject {RunCore $f 'Retire'} @('UnsafePath','UnknownFile');AssertUnchanged $sentinel $h
 }
 Test 'Junction installation root is refused rather than modifying its target' {
  $f=Fixture 'root-junction';$original=$f.root;$h=Hash (Join-Path $original 'current.dll');$f.root=Join-Path $f.base 'app-link';New-Item -ItemType Junction -Path $f.root -Target $original|Out-Null;$null=Reject {RunCore $f 'Retire'} @('UnsafePath');AssertUnchanged (Join-Path $original 'current.dll') $h
 }
 Test 'Dangling junction installation root is refused rather than accepted as a fresh install' {
  $f=Fixture 'dangling-root';$target=Join-Path $f.base 'empty-target';[IO.Directory]::CreateDirectory($target)|Out-Null;$f.root=Join-Path $f.base 'dangling-app';New-Item -ItemType Junction -Path $f.root -Target $target|Out-Null;[IO.Directory]::Delete($target,$false)
  $null=Reject {RunCore $f 'Preflight'} @('UnsafePath');Check (([IO.File]::GetAttributes($f.root)-band[IO.FileAttributes]::ReparsePoint)-ne0) 'Rejected junction was removed or changed.'
 }
 Test 'Absolute root and incoming-manifest ADS paths are rejected before filesystem access' {
  $f=Fixture 'absolute-ads';$original=$f.root;$f.root=$original+':stream';$null=Reject {RunCore $f 'Preflight'} @('UnsafePath');$f.root=$original;$f.manifest+=':stream';$null=Reject {RunCore $f 'Preflight'} @('UnsafePath')
 }
 Test 'Hard-linked catalog file is refused and both names retain their bytes' {
  $f=Fixture 'hardlink';$p=AddLegacy $f;$h=Hash $p;$other=Join-Path $f.base 'outside-hardlink.dll';New-Item -ItemType HardLink -Path $other -Target $p|Out-Null;$null=Reject {RunCore $f 'Retire'} @('UnsafePath');AssertUnchanged $p $h;AssertUnchanged $other $h
 }
 Test 'Postflight refuses a missing required payload file' {
  $f=Fixture 'verify-missing';[IO.File]::Delete((Join-Path $f.root 'current.dll'));$null=Reject {RunCore $f 'Verify'} @('NewPayloadMissing')
 }
 Test 'Postflight refuses wrong current payload bytes' {
  $f=Fixture 'verify-tampered';$p=Join-Path $f.root 'current.dll';WriteBytes $p (Bytes 'wrong current bytes');$h=Hash $p;$null=Reject {RunCore $f 'Verify'} @('NewPayloadMismatch');AssertUnchanged $p $h
 }
 Test 'Postflight refuses missing installed integrity manifest' {
  $f=Fixture 'verify-manifest-missing';[IO.File]::Delete((Join-Path $f.root 'SHA256SUMS.txt'));$null=Reject {RunCore $f 'Verify'} @('NewPayloadMissing')
 }
 Test 'Postflight refuses altered installed manifest despite a trusted incoming manifest' {
  $f=Fixture 'verify-manifest-tampered';$p=Join-Path $f.root 'SHA256SUMS.txt';WriteBytes $p (Bytes 'changed installed manifest');$h=Hash $p;$null=Reject {RunCore $f 'Verify'} @('NewPayloadMismatch');AssertUnchanged $p $h
 }
 Test 'Postflight refuses unknown extras while preserving their bytes' {
  $f=Fixture 'verify-extra';$p=Join-Path $f.root 'extra.txt';WriteBytes $p (Bytes 'not in payload');$h=Hash $p;$null=Reject {RunCore $f 'Verify'} @('UnknownFile');AssertUnchanged $p $h
 }
 Test 'Postflight refuses an approved but still-unretired obsolete file' {
  $f=Fixture 'verify-obsolete';$p=AddLegacy $f;$h=Hash $p;$null=Reject {RunCore $f 'Verify'} @('UnknownFile','NewPayloadMismatch');AssertUnchanged $p $h
 }
 Test 'Only precise Inno metadata names are accepted without trusting a wildcard' {
  $f=Fixture 'metadata';foreach($name in @('unins000.exe','unins000.dat','unins000.msg')){WriteBytes (Join-Path $f.root $name) (Bytes ('inert '+$name))};$null=RunCore $f 'Verify';$p=Join-Path $f.root 'unins001.exe';WriteBytes $p (Bytes 'unexpected second uninstaller');$h=Hash $p;$null=Reject {RunCore $f 'Verify'} @('UnknownFile');AssertUnchanged $p $h
 }
}finally{
 $clock.Stop();$failed=@($results.ToArray()|Where-Object{-not$_.passed}).Count;$passed=$results.Count-$failed
 $report=[ordered]@{schema='SteamSentinel.InstallerPayloadMaintenanceTests/1';startedUtc=$started.ToString('o');completedUtc=[DateTime]::UtcNow.ToString('o');passed=$passed;failed=$failed;skipped=0;elapsedMs=$clock.ElapsedMilliseconds;sourcePath=$source;sourceSha256=$sourceHash;testScriptSha256=(Hash $PSCommandPath);powershell=$PSVersionTable.PSVersion.ToString();fixtureRoot=$fixtureRoot;fixturesPreserved=$true;productionRootTouched=$false;vmOperated=$false;testOnlyCompilationSymbol='STEAMSENTINEL_INSTALLER_TESTS';shortPathExamples=$shortPathExamples.ToArray();tests=$results.ToArray()}
 $json=$report|ConvertTo-Json -Depth 8;$enc=[Text.UTF8Encoding]::new($true);$data=$enc.GetPreamble()+$enc.GetBytes($json);$stream=[IO.File]::Open($ResultsPath,'CreateNew','Write','Read');try{$stream.Write($data,0,$data.Length);$stream.Flush($true)}finally{$stream.Dispose()}
 Write-Host ('Passed '+$passed+', failed '+$failed+', skipped 0. Results: '+$ResultsPath)
}
if(@($results.ToArray()|Where-Object{-not$_.passed}).Count){exit 1};exit 0
