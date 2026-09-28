# Real, inert filesystem/ACL and isolated-HKCU tests of the installer state core.
# No VM or production ProgramData / installer registration is used.
#Requires -RunAsAdministrator
[CmdletBinding()]
param([Parameter(Mandatory=$true)][string]$ResultsPath,[string]$FixtureParent)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
if($PSVersionTable.PSVersion.Major -ne 5 -or -not [Environment]::Is64BitProcess){throw 'Use elevated x64 Windows PowerShell 5.1.'}
$repo=Split-Path $PSScriptRoot -Parent
$source=Join-Path $repo 'installer\MachineStateBootstrap.cs'
$ResultsPath=[IO.Path]::GetFullPath($ResultsPath)
if(Test-Path -LiteralPath $ResultsPath){throw 'Preserve existing test results.'}
if(-not $FixtureParent){$FixtureParent=Join-Path $repo 'artifacts\installer-machine-state-tests'}
$FixtureParent=[IO.Path]::GetFullPath($FixtureParent).TrimEnd('\')
if($FixtureParent -notmatch '^[A-Za-z]:\\' -or $FixtureParent.Substring(2) -match '[:*?"\r\n]'){throw 'Explicit local fixture parent required.'}
foreach($forbidden in @($env:windir,$env:ProgramData,$env:ProgramFiles,${env:ProgramFiles(x86)})){
 if($forbidden -and ($FixtureParent -eq $forbidden -or $FixtureParent.StartsWith($forbidden.TrimEnd('\')+'\',[StringComparison]::OrdinalIgnoreCase))){throw 'Production system fixture parent refused.'}
}
for($c=$FixtureParent;$c;$c=[IO.Path]::GetDirectoryName($c)){
 if((Test-Path -LiteralPath $c) -and ((Get-Item -LiteralPath $c -Force).Attributes -band [IO.FileAttributes]::ReparsePoint)){throw 'Fixture ancestor is redirected.'}
}
$sourceBytes=[IO.File]::ReadAllBytes($source)
$digest=[Security.Cryptography.SHA256]::Create();try{$sourceHash=([BitConverter]::ToString($digest.ComputeHash($sourceBytes))).Replace('-','')}finally{$digest.Dispose()}
$parameters=New-Object CodeDom.Compiler.CompilerParameters
$parameters.CompilerOptions='/define:STEAMSENTINEL_INSTALLER_TESTS'
$parameters.GenerateInMemory=$true
foreach($assembly in @('System.dll','System.Core.dll','System.Web.Extensions.dll')){$null=$parameters.ReferencedAssemblies.Add($assembly)}
Add-Type -TypeDefinition ([Text.Encoding]::UTF8.GetString($sourceBytes).TrimStart([char]0xfeff)) -CompilerParameters $parameters
Add-Type -TypeDefinition @'
using System;
using System.IO;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using Microsoft.Win32.SafeHandles;
public static class StateFixtureNative {
 [StructLayout(LayoutKind.Sequential)] struct SA { public int length; public IntPtr descriptor; [MarshalAs(UnmanagedType.Bool)]public bool inherit; }
 [StructLayout(LayoutKind.Sequential)] struct Info { public uint Attributes; public System.Runtime.InteropServices.ComTypes.FILETIME C,A,W; public uint Volume,SizeHigh,SizeLow,Links,High,Low; }
 [DllImport("advapi32.dll",CharSet=CharSet.Unicode,SetLastError=true)]static extern bool ConvertStringSecurityDescriptorToSecurityDescriptor(string s,uint r,out IntPtr sd,out uint n);
 [DllImport("advapi32.dll",SetLastError=true)]static extern bool GetSecurityDescriptorDacl(IntPtr sd,out bool p,out IntPtr d,out bool def);
 [DllImport("advapi32.dll")]static extern uint SetSecurityInfo(SafeFileHandle h,uint type,uint info,IntPtr owner,IntPtr group,IntPtr dacl,IntPtr sacl);
 [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)]static extern bool CreateDirectory(string p,ref SA a);
 [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)]static extern SafeFileHandle CreateFile(string p,uint a,uint s,IntPtr sa,uint c,uint f,IntPtr t);
 [DllImport("kernel32.dll",SetLastError=true)]static extern bool GetFileInformationByHandle(SafeFileHandle h,out Info i);
 [DllImport("kernel32.dll")]static extern IntPtr LocalFree(IntPtr p);
 static string root;
 public static void Initialize(string value) { if(root!=null)throw new InvalidOperationException();root=Path.GetFullPath(value).TrimEnd('\\'); }
 static string Guard(string p) { string f=Path.GetFullPath(p);if(!f.StartsWith(root+"\\",StringComparison.OrdinalIgnoreCase))throw new InvalidOperationException("Fixture escaped isolated root");return f; }
 public static void NewDirectory(string p,string sddl) {
  p=Guard(p);IntPtr sd;uint n;if(!ConvertStringSecurityDescriptorToSecurityDescriptor(sddl,1,out sd,out n))throw new Win32Exception(Marshal.GetLastWin32Error());
  try{var sa=new SA{length=Marshal.SizeOf(typeof(SA)),descriptor=sd};if(!CreateDirectory(p,ref sa))throw new Win32Exception(Marshal.GetLastWin32Error());}finally{LocalFree(sd);}
  // Ensure Windows records the same DACL through its modern setter, without propagating into descendants.
  Dacl(p,sddl);
 }
 public static void Dacl(string p,string sddl) {
  p=Guard(p);using(SafeFileHandle h=CreateFile(p,0x02000000,3,IntPtr.Zero,3,0x02200000,IntPtr.Zero)){
   if(h.IsInvalid)throw new Win32Exception(Marshal.GetLastWin32Error());IntPtr sd;uint n;
   if(!ConvertStringSecurityDescriptorToSecurityDescriptor(sddl,1,out sd,out n))throw new Win32Exception(Marshal.GetLastWin32Error());
   try{bool present,def;IntPtr d;if(!GetSecurityDescriptorDacl(sd,out present,out d,out def)||!present)throw new InvalidOperationException("DACL required");
    uint flags=4;if((new RawSecurityDescriptor(sddl).ControlFlags & ControlFlags.DiscretionaryAclProtected)!=0)flags|=0x80000000;
    uint rc=SetSecurityInfo(h,1,flags,IntPtr.Zero,IntPtr.Zero,d,IntPtr.Zero);if(rc!=0)throw new Win32Exception((int)rc);
   }finally{LocalFree(sd);}
  }
 }
 public static SafeFileHandle Busy(string p) {var h=CreateFile(Guard(p),1,0,IntPtr.Zero,3,0x02200000,IntPtr.Zero);if(h.IsInvalid)throw new Win32Exception(Marshal.GetLastWin32Error());return h;}
 public static void WriteStream(string directory,byte[] bytes) {
  string p=Guard(directory)+":inert-stream";using(var h=CreateFile(p,0x40000000,1,IntPtr.Zero,1,0x02000000,IntPtr.Zero)){
   if(h.IsInvalid)throw new Win32Exception(Marshal.GetLastWin32Error());using(var stream=new FileStream(h,FileAccess.Write)){stream.Write(bytes,0,bytes.Length);stream.Flush(true);}
  }
 }
 public static byte[] ReadStream(string directory) {
  string p=Guard(directory)+":inert-stream";using(var h=CreateFile(p,0x80000000,1,IntPtr.Zero,3,0x02000000,IntPtr.Zero)){
   if(h.IsInvalid)throw new Win32Exception(Marshal.GetLastWin32Error());using(var stream=new FileStream(h,FileAccess.Read)){if(stream.Length>1024)throw new InvalidOperationException();byte[] b=new byte[stream.Length];int n=stream.Read(b,0,b.Length);if(n!=b.Length)throw new EndOfStreamException();return b;}
  }
 }
 public static string Identity(string p) {using(var h=CreateFile(Guard(p),0x80,7,IntPtr.Zero,3,0x02200000,IntPtr.Zero)){if(h.IsInvalid)throw new Win32Exception(Marshal.GetLastWin32Error());Info i;if(!GetFileInformationByHandle(h,out i))throw new Win32Exception(Marshal.GetLastWin32Error());return i.Volume.ToString("X8")+":"+i.High.ToString("X8")+i.Low.ToString("X8");}}
}
'@
$timer=[Diagnostics.Stopwatch]::StartNew();$started=[DateTime]::UtcNow
$fixtureRoot=Join-Path $FixtureParent ([guid]::NewGuid().ToString('N'))
$private='O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)'
$security=New-Object Security.AccessControl.DirectorySecurity;$security.SetSecurityDescriptorSddlForm($private)
$null=[IO.Directory]::CreateDirectory($FixtureParent)
$null=[IO.Directory]::CreateDirectory($fixtureRoot,$security)
[StateFixtureNative]::Initialize($fixtureRoot)
$currentSid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$trusted=[string[]]@('S-1-5-18','S-1-5-32-544',$currentSid)
$domainSid=([Security.Principal.SecurityIdentifier]::new($currentSid)).AccountDomainSid.Value
$tests=New-Object 'Collections.Generic.List[object]'
$fixtures=New-Object 'Collections.Generic.List[object]'
function Check([bool]$Condition,[string]$Message){if(-not $Condition){throw $Message}}
function Hash([string]$Path){return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash}
function Text([string]$Path,[string]$Value){[IO.File]::WriteAllText($Path,$Value,[Text.UTF8Encoding]::new($false))}
function LegacySddl([string]$Relative,[string]$Group='BA'){
 $read=if($Relative -ne 'BrokerTemp'){'(A;OICI;0x1200a9;;;BU)'}else{''}
 return 'O:BAG:'+ $Group +'D:AI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)'+$read+'(A;OICIID;FA;;;SY)(A;OICIID;FA;;;BA)(A;OICIIOID;GA;;;CO)(A;OICIID;0x1200a9;;;BU)(A;CIID;0x116;;;BU)'
}
function SafeSddl([string]$Relative){return $private+$(if($Relative -ne 'BrokerTemp'){'(A;OICI;0x1200a9;;;BU)'}else{''})}
function Fixture([string]$Name,[string]$Kind='legacy',[string[]]$Children=@('Quarantine','Results','BrokerTemp')){
 $base=Join-Path $fixtureRoot $Name;[StateFixtureNative]::NewDirectory($base,$private)
 # Reproduce ProgramData inheritance inside an otherwise private test case, so inherited
 # CO/Users ACEs are real Windows inheritance, rather than invented flags on a safe parent.
 $legacyParent='O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICIIO;GA;;;CO)(A;OICI;0x1200a9;;;BU)(A;CI;0x116;;;BU)'
 $parent=Join-Path $base 'state-parent';[StateFixtureNative]::NewDirectory($parent,$legacyParent)
 $install=Join-Path $base 'installed';[StateFixtureNative]::NewDirectory($install,$private)
 Text (Join-Path $install 'VERSION.txt') "Product=SteamSentinel`r`nVersion=0.2.0`r`nSourceTree=89ca1eb20274fa6faed5f2a8f678c17c3c60914a`r`n"
 Text (Join-Path $install 'inert.txt') 'Harmless source-proof fixture, not executable.'
 $f=[pscustomobject]@{name=$Name;base=$base;parent=$parent;root=(Join-Path $parent 'SteamSentinel');install=$install;registry=('Software\SteamSentinelMachineStateTests\'+[guid]::NewGuid().ToString('D'));manifestHash='';results=@()}
 RefreshManifest $f
 if($Kind -ne 'absent'){
  $s=if($Kind -eq 'legacy'){LegacySddl 'root'}else{SafeSddl 'root'};[StateFixtureNative]::NewDirectory($f.root,$s)
  foreach($child in $Children){$s=if($Kind -eq 'legacy'){LegacySddl $child}else{SafeSddl $child};[StateFixtureNative]::NewDirectory((Join-Path $f.root $child),$s)}
 }
 $fixtures.Add($f);return $f
}
function RefreshManifest($f){$m='';foreach($name in @('VERSION.txt','inert.txt')){$m+=(Hash (Join-Path $f.install $name))+' *'+$name+"`r`n"};Text (Join-Path $f.install 'SHA256SUMS.txt') $m;$f.manifestHash=Hash (Join-Path $f.install 'SHA256SUMS.txt')}
function Run($f,[string]$Mode='Prepare',[Action[string]]$Hook=$null){
 try{$r=[SteamSentinelMachineStateBootstrap]::RunForTests($Mode,$f.parent,$f.install,$f.registry,$trusted,[string[]]@($f.manifestHash),$Hook);$f.results+=@($r);return $r}
 catch{$x=$_.Exception;while($x -and $x.GetType().Name -ne 'MachineStateException'){$x=$x.InnerException};if($x){$f.results+=@($x.Result)};throw}
}
function Reject([scriptblock]$Body,[string[]]$Codes=@()){
 try{$null=& $Body}catch{$x=$_.Exception;while($x -and $x.GetType().Name -ne 'MachineStateException'){$x=$x.InnerException};if(-not $x){throw};if($Codes.Count -and $x.Result.ReasonCode -notin $Codes){throw ('Unexpected reason: '+$x.Result.ReasonCode)};Check (-not $x.Result.Succeeded) 'Rejected result claims success';return $x.Result};throw 'Operation unexpectedly succeeded.'
}
function Snapshot($f){
 $rows=@();if(Test-Path -LiteralPath $f.root){$paths=@($f.root)+@(Get-ChildItem -LiteralPath $f.root -Force -Recurse|ForEach-Object{$_.FullName});foreach($p in $paths){$i=Get-Item -LiteralPath $p -Force;$dir=$i -is [IO.DirectoryInfo];$rows+=@([ordered]@{path=$p.Substring($f.root.Length);directory=$dir;attributes=[int]$i.Attributes;sddl=(Get-Acl -LiteralPath $p).Sddl;sha256=if($dir){$null}else{Hash $p}})}};return ($rows|ConvertTo-Json -Depth 8 -Compress)
}
function AllSafe($f){foreach($name in @('','Quarantine','Results','BrokerTemp')){$p=if($name){Join-Path $f.root $name}else{$f.root};$acl=Get-Acl -LiteralPath $p;Check $acl.AreAccessRulesProtected 'Target DACL remains inheritable';$sd=[Security.AccessControl.RawSecurityDescriptor]::new($acl.Sddl);Check ($sd.Owner.Value -eq 'S-1-5-32-544') 'Owner changed';foreach($ace in $sd.DiscretionaryAcl){if($ace.SecurityIdentifier.Value -eq 'S-1-5-32-545'){Check ($name -ne 'BrokerTemp' -and $ace.AccessMask -eq 0x1200a9) 'Users received unexpected rights'}}};$r=Run $f 'Verify';Check $r.Succeeded 'Final verification failed'}
function Test([string]$Name,[scriptblock]$Body){$w=[Diagnostics.Stopwatch]::StartNew();try{& $Body;$tests.Add([pscustomobject]@{name=$Name;passed=$true;elapsedMs=$w.ElapsedMilliseconds;error=$null});Write-Host ('PASS: '+$Name)}catch{$tests.Add([pscustomobject]@{name=$Name;passed=$false;elapsedMs=$w.ElapsedMilliseconds;error=$_.Exception.ToString();position=$_.InvocationInfo.PositionMessage;stack=$_.ScriptStackTrace});Write-Host ('FAIL: '+$Name+' - '+$_.Exception.Message)}}
try{
 Test 'Verified old source migrates the exact four empty legacy directories' {$f=Fixture 'legacy-all';$ids=@{};foreach($n in @('','Quarantine','Results','BrokerTemp')){$p=if($n){Join-Path $f.root $n}else{$f.root};$ids[$n]=[StateFixtureNative]::Identity($p)};$r=Run $f;Check $r.Succeeded 'Migration did not succeed';AllSafe $f;foreach($n in $ids.Keys){$p=if($n){Join-Path $f.root $n}else{$f.root};Check ([StateFixtureNative]::Identity($p) -eq $ids[$n]) 'Directory was replaced'}}
 Test 'Inspect reports migration without modifying ACLs or data' {$f=Fixture 'inspect';$before=Snapshot $f;$r=Run $f 'Inspect';Check $r.MigrationRequired 'Legacy tree was not identified';Check ((Snapshot $f) -ceq $before) 'Inspect changed state'}
 Test 'Verify does not silently migrate a legacy tree' {$f=Fixture 'verify-legacy';$before=Snapshot $f;$null=Reject {Run $f 'Verify'};Check ((Snapshot $f) -ceq $before) 'Verify changed state'}
 Test 'Fresh state root creates only the four protected directories' {$f=Fixture 'fresh' 'absent';$r=Run $f;Check $r.Succeeded 'Fresh prepare failed';Check (-not $r.MigrationRequired) 'Fresh creation claimed legacy migration';AllSafe $f;Check (@(Get-ChildItem $f.root -Force).Count -eq 3) 'Unexpected new entry'}
 Test 'Mixed safe and legacy nodes preserve the safe node exact descriptor' {$f=Fixture 'mixed';$p=Join-Path $f.root 'Results';[StateFixtureNative]::Dacl($p,(SafeSddl 'Results'));$safe=(Get-Acl $p).Sddl;$null=Run $f;Check ((Get-Acl $p).Sddl -ceq $safe) 'Safe node ACL changed';AllSafe $f}
 Test 'Missing fixed child is created only within the same empty migration' {$f=Fixture 'missing-one' 'legacy' @('Quarantine','Results');$null=Run $f;AllSafe $f}
 Test 'Legacy root with all fixed children absent is safely completed' {$f=Fixture 'missing-all' 'legacy' @();$null=Run $f;AllSafe $f}
 Test 'Safe nonempty state is verified without rewriting bytes or ACLs' {$f=Fixture 'safe-data' 'safe';$p=Join-Path $f.root 'Quarantine\record.json';Text $p '{"inert":true}';$before=Snapshot $f;$null=Run $f;Check ((Snapshot $f) -ceq $before) 'Safe data or ACL changed'}
 Test 'Repeated prepare of migrated state does not rewrite descriptors' {$f=Fixture 'repeat';$null=Run $f;$before=Snapshot $f;$null=Run $f;Check ((Snapshot $f) -ceq $before) 'Repeated prepare rewrote state'}
 foreach($where in @('root','Quarantine','Results','BrokerTemp')){$relative=$where;Test ('Legacy data in '+$relative+' refuses migration and is preserved'){$f=Fixture ('data-'+$relative);$p=if($relative -eq 'root'){Join-Path $f.root 'record.json'}else{Join-Path (Join-Path $f.root $relative) 'record.json'};Text $p '{"inert":true}';$before=Snapshot $f;$null=Reject {Run $f};Check ((Snapshot $f) -ceq $before) 'Rejected data tree changed'}}
 Test 'Unknown empty directory is not re-ACLed or accepted' {$f=Fixture 'unknown-directory';$p=Join-Path $f.root 'UserNotes';[StateFixtureNative]::NewDirectory($p,$private);$before=Snapshot $f;$null=Reject {Run $f};Check ((Snapshot $f) -ceq $before) 'Unknown directory or sibling changed'}
 Test 'Legacy hard-linked file is refused with both names preserved' {$f=Fixture 'hardlink';$a=Join-Path $f.base 'outside.txt';Text $a 'inert hardlink';$b=Join-Path $f.root 'Quarantine\linked.txt';New-Item -ItemType HardLink -Path $b -Target $a|Out-Null;$h=Hash $a;$before=Snapshot $f;$null=Reject {Run $f};Check ((Hash $a) -eq $h -and (Hash $b) -eq $h -and (Snapshot $f) -ceq $before) 'Hardlink was changed'}
 Test 'Directory named stream refuses migration without consuming its bytes' {$f=Fixture 'named-stream';$p=Join-Path $f.root 'Results';[StateFixtureNative]::WriteStream($p,[Text.Encoding]::UTF8.GetBytes('inert ADS'));Check ([Text.Encoding]::UTF8.GetString([StateFixtureNative]::ReadStream($p)) -eq 'inert ADS') 'ADS fixture missing';$before=Snapshot $f;$null=Reject {Run $f};Check ([Text.Encoding]::UTF8.GetString([StateFixtureNative]::ReadStream($p)) -eq 'inert ADS' -and (Snapshot $f) -ceq $before) 'Named stream or tree changed'}
 Test 'Junction child refuses traversal and preserves its external target' {$f=Fixture 'junction' 'legacy' @('Quarantine','Results');$external=Join-Path $f.base 'outside';[StateFixtureNative]::NewDirectory($external,$private);$sentinel=Join-Path $external 'inert.txt';Text $sentinel 'outside survives';$h=Hash $sentinel;New-Item -ItemType Junction -Path (Join-Path $f.root 'BrokerTemp') -Target $external|Out-Null;$s=(Get-Acl $f.root).Sddl;$null=Reject {Run $f};Check ((Hash $sentinel) -eq $h -and (Get-Acl $f.root).Sddl -ceq $s) 'Junction target or root changed'}
 Test 'Extra allow principal on a weak directory is refused' {$f=Fixture 'extra-allow';$s=(LegacySddl 'root')+'(A;OICI;FR;;;WD)';[StateFixtureNative]::Dacl($f.root,$s);$before=Snapshot $f;$null=Reject {Run $f};Check ((Snapshot $f) -ceq $before) 'Unknown ACE was normalized away'}
 Test 'A deny ACE is not discarded to match a legacy template' {$f=Fixture 'deny-ace';$s=(LegacySddl 'root').Replace('D:AI','D:AI(D;OICI;WD;;;BU)');[StateFixtureNative]::Dacl($f.root,$s);$before=Snapshot $f;$null=Reject {Run $f};Check ((Snapshot $f) -ceq $before) 'Deny ACE was changed'}
 Test 'Additional Users delete right is not accepted as known legacy' {$f=Fixture 'extra-right';$sd=[Security.AccessControl.RawSecurityDescriptor]::new((Get-Acl $f.parent).Sddl);$matches=0;foreach($ace in $sd.DiscretionaryAcl){if($ace.SecurityIdentifier.Value -eq 'S-1-5-32-545' -and [int]$ace.AceFlags -eq 2){$ace.AccessMask=$ace.AccessMask -bor 0x10000;$matches++}};Check ($matches -eq 1) 'Exact parent Users write ACE missing';[StateFixtureNative]::Dacl($f.parent,$sd.GetSddlForm([Security.AccessControl.AccessControlSections]::All));[StateFixtureNative]::Dacl($f.root,(LegacySddl 'root'));$actual=[Security.AccessControl.RawSecurityDescriptor]::new((Get-Acl $f.root).Sddl);Check (@($actual.DiscretionaryAcl|Where-Object{$_.SecurityIdentifier.Value -eq 'S-1-5-32-545' -and [int]$_.AceFlags -eq 18 -and ($_.AccessMask -band 0x10000)}).Count -eq 1) 'Fixture did not retain inherited Users DELETE';$before=Snapshot $f;$null=Reject {Run $f};Check ((Snapshot $f) -ceq $before) 'Extra rights were silently migrated'}
 Test 'Wrong legacy owner is not taken over' {$f=Fixture 'wrong-owner';$a=Get-Acl $f.root;$a.SetOwner([Security.Principal.SecurityIdentifier]::new($currentSid));Set-Acl $f.root $a;$before=Snapshot $f;$null=Reject {Run $f};Check ((Snapshot $f) -ceq $before) 'Owner or ACL was taken over'}
 Test 'Local SAM primary group is preserved during accepted migration' {$f=Fixture 'sam-group';foreach($n in @('','Quarantine','Results','BrokerTemp')){$p=if($n){Join-Path $f.root $n}else{$f.root};$a=Get-Acl $p;$a.SetGroup([Security.Principal.SecurityIdentifier]::new($domainSid+'-513'));Set-Acl $p $a};$null=Run $f;foreach($n in @('','Quarantine','Results','BrokerTemp')){$p=if($n){Join-Path $f.root $n}else{$f.root};Check ((Get-Acl $p).GetGroup([Security.Principal.SecurityIdentifier]).Value -eq $domainSid+'-513') 'Primary group changed'}}
 Test 'Unapproved manifest refuses legacy mutation' {$f=Fixture 'unapproved-manifest';$f.manifestHash='A'*64;$before=Snapshot $f;$null=Reject {Run $f};Check ((Snapshot $f) -ceq $before) 'Unapproved source changed state'}
 Test 'Tampered actual old payload refuses legacy mutation' {$f=Fixture 'tampered-payload';Text (Join-Path $f.install 'inert.txt') 'different bytes';$before=Snapshot $f;$null=Reject {Run $f};Check ((Snapshot $f) -ceq $before) 'Tampered source changed state'}
 Test 'Wrong old product version is not accepted despite approved manifest hash' {$f=Fixture 'wrong-version';Text (Join-Path $f.install 'VERSION.txt') "Product=SteamSentinel`r`nVersion=0.2.1`r`nSourceTree=89ca1eb20274fa6faed5f2a8f678c17c3c60914a`r`n";RefreshManifest $f;$before=Snapshot $f;$null=Reject {Run $f};Check ((Snapshot $f) -ceq $before) 'Wrong version changed state'}
 Test 'Writable source directory cannot prove an approved legacy payload' {$f=Fixture 'source-acl';[StateFixtureNative]::Dacl($f.install,($private+'(A;OICI;FW;;;BU)'));$before=Snapshot $f;$null=Reject {Run $f};Check ((Snapshot $f) -ceq $before) 'Unsafe source changed state'}
 Test 'State attribute change during source verification is not adopted' {$f=Fixture 'source-race';$acl=(Get-Acl $f.root).Sddl;$hook=[Action[string]]{param($stage)if($stage -eq 'after-source'){[IO.File]::SetAttributes($f.root,([IO.File]::GetAttributes($f.root) -bor [IO.FileAttributes]::ReadOnly))}};$r=Reject {Run $f 'Prepare' $hook} @('LegacyStateChanged');Check (-not $r.Pending -and $r.ChangedDirectories.Count -eq 0) 'Source race reached mutation or pending';Check ((Get-Acl $f.root).Sddl -ceq $acl) 'Source race changed root security'}
 Test 'Inspect refuses data added during source verification without writing pending state' {$f=Fixture 'inspect-source-race';$acl=(Get-Acl $f.root).Sddl;$p=Join-Path $f.root 'Results\late-inert.txt';$hook=[Action[string]]{param($stage)if($stage -eq 'after-source'){Text $p 'inert concurrent data'}};$r=Reject {Run $f 'Inspect' $hook} @('LegacyStateContainsData');Check (-not $r.Pending -and $r.ChangedDirectories.Count -eq 0) 'Inspect wrote pending state or ACL';Check ((Get-Acl $f.root).Sddl -ceq $acl -and [IO.File]::ReadAllText($p) -eq 'inert concurrent data') 'Inspect changed the concurrently supplied data'}
 Test 'Directory sharing conflict fails without changing any node' {$f=Fixture 'busy';$before=Snapshot $f;$held=[StateFixtureNative]::Busy((Join-Path $f.root 'Results'));try{$null=Reject {Run $f}}finally{$held.Dispose()};Check ((Snapshot $f) -ceq $before) 'Busy tree was modified'}
 Test 'Parent ACL change does not propagate into unprocessed children' {$f=Fixture 'no-propagation';$children=@{};foreach($n in @('Quarantine','Results','BrokerTemp')){$children[$n]=(Get-Acl (Join-Path $f.root $n)).Sddl};$hook=[Action[string]]{param($stage)if($stage -eq 'after-change:root'){foreach($n in $children.Keys){Check ((Get-Acl (Join-Path $f.root $n)).Sddl -ceq $children[$n]) 'Parent propagated ACL into child'};throw 'intentional-stop-after-root'}};$null=Reject {Run $f 'Prepare' $hook};foreach($n in $children.Keys){Check ((Get-Acl (Join-Path $f.root $n)).Sddl -ceq $children[$n]) 'Unprocessed child changed'}}
 foreach($stageName in @('root','Quarantine','Results','BrokerTemp')){$stage=$stageName;Test ('Failure after '+$stage+' retains pending and resumes from same identities'){$f=Fixture ('pending-'+$stage);$hook=[Action[string]]{param($event)if($event -eq ('after-change:'+$stage)){throw 'intentional interruption'}};$r=Reject {Run $f 'Prepare' $hook};Check $r.Pending 'Interrupted migration lost pending state';$null=Run $f;AllSafe $f}}
 Test 'Pending recovery refuses newly inserted inert data without deleting it' {$f=Fixture 'pending-data';$hook=[Action[string]]{param($stage)if($stage -eq 'after-change:root'){throw 'interrupt'}};$null=Reject {Run $f 'Prepare' $hook};$p=Join-Path $f.root 'Results\record.txt';Text $p 'new inert data';$before=Snapshot $f;$null=Reject {Run $f};Check ((Snapshot $f) -ceq $before) 'Pending recovery rewrote or deleted unknown data'}
 Test 'Pending recovery refuses replaced directory identity despite identical ACL' {$f=Fixture 'pending-identity';$hook=[Action[string]]{param($stage)if($stage -eq 'after-change:root'){throw 'interrupt'}};$null=Reject {Run $f 'Prepare' $hook};$p=Join-Path $f.root 'Results';$s=(Get-Acl $p).Sddl;$id=[StateFixtureNative]::Identity($p);$held=Join-Path $f.base 'preserved-original-results';Check ($p.StartsWith($fixtureRoot+'\') -and $held.StartsWith($fixtureRoot+'\')) 'Move escaped fixture';[IO.Directory]::Move($p,$held);[StateFixtureNative]::NewDirectory($p,$s);Check ([StateFixtureNative]::Identity($p) -ne $id) 'Replacement has same identity';$before=Snapshot $f;$null=Reject {Run $f};Check ((Snapshot $f) -ceq $before) 'Replaced pending identity was accepted'}
 Test 'Pending recovery preserves the exact originally safe node descriptor' {$f=Fixture 'pending-safe-change';$p=Join-Path $f.root 'Results';[StateFixtureNative]::Dacl($p,(SafeSddl 'Results'));$hook=[Action[string]]{param($stage)if($stage -eq 'after-change:root'){throw 'interrupt'}};$null=Reject {Run $f 'Prepare' $hook};$a=Get-Acl $p;$a.SetGroup([Security.Principal.SecurityIdentifier]::new($domainSid+'-513'));Set-Acl $p $a;$before=Snapshot $f;$null=Reject {Run $f} @('LegacyStateChanged');Check ((Snapshot $f) -ceq $before) 'Changed safe original descriptor was adopted'}
 Test 'Pending recovery does not recreate a recorded newly created directory that disappeared' {$f=Fixture 'pending-created-missing' 'legacy' @('Quarantine','Results');$hook=[Action[string]]{param($stage)if($stage -eq 'after-change:BrokerTemp'){throw 'interrupt after creation'}};$r=Reject {Run $f 'Prepare' $hook};Check ($r.Pending -and $r.CreatedDirectories.Contains('BrokerTemp')) 'Fixture did not record newly created child';$p=Join-Path $f.root 'BrokerTemp';$held=Join-Path $f.base 'preserved-created-broker';Check ($p.StartsWith($fixtureRoot+'\') -and $held.StartsWith($fixtureRoot+'\')) 'Move escaped fixture';$id=[StateFixtureNative]::Identity($p);[IO.Directory]::Move($p,$held);$before=Snapshot $f;$null=Reject {Run $f} @('LegacyStateChanged');Check (-not (Test-Path -LiteralPath $p) -and [StateFixtureNative]::Identity($held) -eq $id -and (Snapshot $f) -ceq $before) 'Recovery recreated or replaced the recorded object'}
 Test 'Malformed isolated pending journal refuses recovery without rewriting state' {$f=Fixture 'pending-journal-bytes';$hook=[Action[string]]{param($stage)if($stage -eq 'after-change:root'){throw 'interrupt'}};$null=Reject {Run $f 'Prepare' $hook};$key=[Microsoft.Win32.Registry]::CurrentUser.OpenSubKey($f.registry,$true);try{$key.SetValue('Journal',[byte[]]@(1,2,3),[Microsoft.Win32.RegistryValueKind]::Binary);$key.Flush()}finally{$key.Dispose()};$before=Snapshot $f;$null=Reject {Run $f} @('MigrationJournalUnsafe');Check ((Snapshot $f) -ceq $before) 'Malformed journal changed state'}
 Test 'Untrusted create-link access on isolated journal prevents recovery' {$f=Fixture 'pending-journal-acl';$hook=[Action[string]]{param($stage)if($stage -eq 'after-change:root'){throw 'interrupt'}};$null=Reject {Run $f 'Prepare' $hook};$key=[Microsoft.Win32.Registry]::CurrentUser.OpenSubKey($f.registry,$true);try{$a=$key.GetAccessControl();$rule=[Security.AccessControl.RegistryAccessRule]::new([Security.Principal.SecurityIdentifier]::new('S-1-5-32-545'),[Security.AccessControl.RegistryRights]::CreateLink,[Security.AccessControl.AccessControlType]::Allow);$a.AddAccessRule($rule);$key.SetAccessControl($a);Check (@($key.GetAccessControl().Access|Where-Object{$_.RegistryRights -band [Security.AccessControl.RegistryRights]::CreateLink}).Count -gt 0) 'Journal unsafe ACE fixture missing'}finally{$key.Dispose()};$before=Snapshot $f;$null=Reject {Run $f} @('MigrationJournalUnsafe');Check ((Snapshot $f) -ceq $before) 'Unsafe journal changed state'}
 Test 'Final concurrent unknown entry prevents completion and stays preserved' {$f=Fixture 'late-entry';$p=Join-Path $f.root 'unexpected.txt';$hook=[Action[string]]{param($stage)if($stage -eq 'before-complete'){Text $p 'inert concurrent entry'}};$r=Reject {Run $f 'Prepare' $hook};Check $r.Pending 'Incomplete final observation lost pending';Check ([IO.File]::ReadAllText($p) -eq 'inert concurrent entry') 'Concurrent entry disappeared'}
 Test 'Failure before pending cannot change directory ACLs' {$f=Fixture 'before-pending';$before=Snapshot $f;$hook=[Action[string]]{param($stage)if($stage -eq 'before-pending'){throw 'before pending failure'}};$null=Reject {Run $f 'Prepare' $hook};Check ((Snapshot $f) -ceq $before) 'Mutation preceded durable pending'}
 Test 'Production compilation does not expose the alternate test-root entrypoint' {$compiler=[Microsoft.CSharp.CSharpCodeProvider]::new();$options=[CodeDom.Compiler.CompilerParameters]::new();$options.GenerateInMemory=$true;$options.TreatWarningsAsErrors=$true;foreach($a in @('System.dll','System.Core.dll','System.Web.Extensions.dll')){$null=$options.ReferencedAssemblies.Add($a)};try{$compiled=$compiler.CompileAssemblyFromSource($options,[Text.Encoding]::UTF8.GetString($sourceBytes).TrimStart([char]0xfeff));Check (-not $compiled.Errors.HasErrors) ($compiled.Errors|Out-String);$type=$compiled.CompiledAssembly.GetType('SteamSentinelMachineStateBootstrap',$true);Check ($null -eq $type.GetMethod('RunForTests')) 'Test-only arbitrary root API leaked into production';Check ($type.GetMethod('Run').GetParameters().Count -eq 1) 'Production entrypoint unexpectedly accepts paths'}finally{$compiler.Dispose()}}
}finally{
 $timer.Stop();$failed=@($tests.ToArray()|Where-Object{-not $_.passed}).Count
 $r=[ordered]@{schema='SteamSentinel.InstallerMachineStateTests/1';startedUtc=$started.ToString('o');completedUtc=[DateTime]::UtcNow.ToString('o');passed=$tests.Count-$failed;failed=$failed;skipped=0;elapsedMs=$timer.ElapsedMilliseconds;sourcePath=$source;sourceSha256=$sourceHash;testScriptSha256=(Hash $PSCommandPath);powershell=$PSVersionTable.PSVersion.ToString();fixtureRoot=$fixtureRoot;fixturesPreserved=$true;productionRootTouched=$false;productionRegistryTouched=$false;vmOperated=$false;testOnlyCompilationSymbol='STEAMSENTINEL_INSTALLER_TESTS';tests=$tests.ToArray();fixtureResults=$fixtures.ToArray()}
 $json=$r|ConvertTo-Json -Depth 24;$enc=[Text.UTF8Encoding]::new($true);$b=$enc.GetPreamble()+$enc.GetBytes($json);$s=[IO.File]::Open($ResultsPath,'CreateNew','Write','Read');try{$s.Write($b,0,$b.Length);$s.Flush($true)}finally{$s.Dispose()}
 Write-Host ('Passed '+$r.passed+', failed '+$r.failed+', skipped 0. Results: '+$ResultsPath)
}
if($failed){exit 1};exit 0
