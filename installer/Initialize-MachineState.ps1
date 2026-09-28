[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][ValidateSet('Inspect','Prepare','Verify')][string]$Mode,
    [Parameter(Mandatory=$true)][ValidatePattern('^[A-Fa-f0-9]{64}$')][string]$ExpectedSourceSha256,
    [Parameter(Mandatory=$true)][string]$LogPath,
    [Parameter(Mandatory=$true)][string]$DisplayLogPath,
    [ValidateSet('en','zhHans')][string]$Language='en'
)
# Installer-only entry point. No alternate state/install root, registry location or source catalog.
Set-StrictMode -Version Latest; $ErrorActionPreference='Stop'
$jsonStream=$null;$displayStream=$null;$result=$null;$actual=$null;$exitCode=20
$pins=[Collections.Generic.List[IDisposable]]::new()
function Escape-Display([string]$Value) {
    $text=[regex]::Replace($Value,'[\x00-\x1f\x7f]',{param($m)'\u{0:X4}'-f[int][char]$m.Value})
    if($text.Length-gt1500){$text=$text.Substring(0,1500)};return $text
}
try {
    if($PSVersionTable.PSVersion.Major-ne5 -or -not[Environment]::Is64BitProcess){throw 'Windows PowerShell 5.1 x64 is required.'}
    $identity=[Security.Principal.WindowsIdentity]::GetCurrent()
    if(-not[Security.Principal.WindowsPrincipal]::new($identity).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){throw 'Administrative installation is required.'}
    $root=[IO.Path]::GetFullPath($PSScriptRoot).TrimEnd('\')
    $fullLog=[IO.Path]::GetFullPath($LogPath);$fullDisplay=[IO.Path]::GetFullPath($DisplayLogPath)
    if([IO.Path]::GetDirectoryName($fullLog)-ne$root -or [IO.Path]::GetDirectoryName($fullDisplay)-ne$root -or
       [IO.Path]::GetFileName($fullLog)-notmatch('^machine-state-'+$Mode+'-[0-9]+\.json$') -or
       $fullDisplay-ne[IO.Path]::ChangeExtension($fullLog,'.txt')){throw 'Unexpected installer log paths.'}
    Add-Type -TypeDefinition @'
using System;using System.IO;using System.Text;using System.Runtime.InteropServices;using Microsoft.Win32.SafeHandles;
public static class SteamSentinelInstallerTempPin {
 [StructLayout(LayoutKind.Sequential)]struct A {public uint Attributes,Tag;}
 [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)]static extern SafeFileHandle CreateFile(string p,uint a,uint s,IntPtr sd,uint c,uint f,IntPtr t);
 [DllImport("kernel32.dll",SetLastError=true)]static extern bool GetFileInformationByHandleEx(SafeFileHandle h,int c,out A a,uint n);
 [DllImport("kernel32.dll",CharSet=CharSet.Unicode)]static extern uint GetFinalPathNameByHandle(SafeFileHandle h,StringBuilder s,uint n,uint f);
 public static SafeFileHandle Open(string path){var h=CreateFile(path,0x20080,3,IntPtr.Zero,3,0x02200000,IntPtr.Zero);if(h.IsInvalid){h.Dispose();throw new IOException("Temporary ancestor cannot be pinned.");}
 try{A a;var b=new StringBuilder(32768);uint n=GetFinalPathNameByHandle(h,b,(uint)b.Capacity,0);if(!GetFileInformationByHandleEx(h,9,out a,8)||(a.Attributes&0x10)==0||(a.Attributes&0x400)!=0||n==0||n>=b.Capacity||!String.Equals(b.ToString(),@"\\?\"+path,StringComparison.OrdinalIgnoreCase))throw new IOException("Temporary ancestor is redirected.");return h;}catch{h.Dispose();throw;}}
}
'@
    for($cursor=$root;$cursor;$cursor=[IO.Path]::GetDirectoryName($cursor.TrimEnd('\'))){$pins.Add([SteamSentinelInstallerTempPin]::Open($cursor))}
    # The per-install temporary directory may be owned by the current elevated installer account.
    # This exception applies only to that directory, never to old machine state or installed files.
    $allowed=@('S-1-5-18','S-1-5-32-544',$identity.User.Value)
    $acl=Get-Acl -LiteralPath $root
    if($acl.GetOwner([Security.Principal.SecurityIdentifier]).Value-notin$allowed -or
       $null-eq[Security.AccessControl.RawSecurityDescriptor]::new($acl.GetSecurityDescriptorBinaryForm(),0).DiscretionaryAcl){throw 'Installer temporary directory is not protected.'}
    $mask=2-bor4-bor16-bor256-bor65536-bor64-bor262144-bor524288-bor0x10000000-bor0x40000000
    foreach($rule in $acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])){
        if($rule.AccessControlType-eq'Allow' -and -not($rule.PropagationFlags-band[Security.AccessControl.PropagationFlags]::InheritOnly) -and
           ([int]$rule.FileSystemRights-band$mask) -and $rule.IdentityReference.Value-notin$allowed){throw 'Installer temporary directory has an untrusted writer.'}
    }
    $jsonStream=[IO.File]::Open($fullLog,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read)
    $displayStream=[IO.File]::Open($fullDisplay,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read)
    $source=Join-Path $root 'MachineStateBootstrap.cs'
    if((Get-Item -LiteralPath $source -Force).Attributes-band[IO.FileAttributes]::ReparsePoint){throw 'Machine-state source is redirected.'}
    $stream=[IO.File]::Open($source,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
    try{
        if($stream.Length-le0 -or $stream.Length-gt256KB){throw 'Machine-state source exceeds its bounded size.'}
        $memory=[IO.MemoryStream]::new();try{$stream.CopyTo($memory);$bytes=$memory.ToArray()}finally{$memory.Dispose()}
    }finally{$stream.Dispose()}
    $hash=[Security.Cryptography.SHA256]::Create();try{$actual=[BitConverter]::ToString($hash.ComputeHash($bytes)).Replace('-','')}finally{$hash.Dispose()}
    if($actual-ne$ExpectedSourceSha256){throw 'Machine-state source integrity check failed.'}
    # Compile the exact hashed bytes. Production never defines the test compilation symbol.
    Add-Type -TypeDefinition ([Text.UTF8Encoding]::new($false,$true).GetString($bytes).TrimStart([char]0xFEFF))
    $result=[SteamSentinelMachineStateBootstrap]::Run($Mode)
    if($null-eq$result -or -not$result.Succeeded){throw 'State verification did not return an accepted result.'}
    $exitCode=0
}catch{
    $failure=$_.Exception;while($failure.InnerException){$failure=$failure.InnerException}
    if($failure.GetType().Name-eq'MachineStateException' -and $null-ne$failure.Result){$result=$failure.Result}
    else{$result=[pscustomobject]@{Schema='SteamSentinel.MachineStateBootstrap/1';Mode=$Mode;Succeeded=$false;ReasonCode='StateOperationFailed';RelativePath='';Detail=$failure.GetType().Name;Win32Error=0;MigrationRequired=$false;Pending=$false;JournalId=$null;SourceManifestSha256=$null;JournalSha256=$null;JournalComplete=$false;PreviouslyRestrictedDirectories=@();ChangedDirectories=@();CreatedDirectories=@();Before=@();After=@();Operations=@()}}
}finally{
    try{
        if($null-ne$result){
            $en=@{
                StateReady='Protected application state directories are ready.'
                StateDirectoriesWillBeCreated='Setup will create protected application state directories.'
                StateDirectoriesCreated='Protected application state directories were created.'
                LegacyStateMigrationRequired='Empty state directories from a verified earlier installation were found. Setup will restrict write access to System and Administrators. Old data is not migrated automatically.'
                LegacyStateMigrated='Write access on the verified empty legacy directories was restricted. No old data was imported or deleted.'
                LegacyStateContainsData='An unsafe old state directory contains data or an unknown item. Setup stopped and preserved it. Keep the log for support review.'
                LegacyStateUnsupportedAcl='An existing state directory has an unrecognized owner or permission pattern. Its permissions were not automatically accepted.'
                LegacyStateChanged='A state directory changed during verification. Setup stopped; existing data was not accepted or deleted.'
                LegacyStateBusy='A state directory is in use. Close the application and retry; no process was terminated.'
                LegacyStateMigrationPending='An earlier permission migration did not complete. Setup must revalidate the complete empty directory tree before continuing.'
                LegacySourceMismatch='The existing installation does not match an approved old package. Automatic state migration was refused.'
                LegacySourceChanged='The old installation changed during verification. Setup stopped.'
                UnsafeStatePermissions='An existing state directory permits untrusted changes. Setup stopped.'
                UnsafeStatePath='A required path is redirected or is not the expected object. Setup stopped.'
                StateDirectoryMissing='A required protected state directory is missing.'
                StateAccessDenied='The required state directory cannot be opened safely with the necessary permissions.'
                MigrationJournalUnsafe='The protected installer migration record failed its integrity or permission checks.'
                MigrationJournalWriteFailed='The protected pending record could not be durably verified. Setup stopped.'
                StatePermissionsChangeFailed='A directory permission change could not be verified. Already restricted permissions were not rolled back.'
                StateCreateFailed='A required protected directory could not be created.'
                StateEnumerationFailed='The bounded directory inspection could not complete. Setup stopped.'
                StateIdentityUnavailable='The local account identity needed for legacy permission verification is unavailable.'
                StateAdministratorRequired='Administrative installation is required.'
                InvalidStateMode='The requested state-check mode is invalid.'
                StateOperationFailed='Application state preparation could not complete. Keep the setup log for review.'
            }
            $zh=@{
                StateReady='受保护的应用状态目录已就绪。'
                StateDirectoriesWillBeCreated='安装将创建受保护的应用状态目录。'
                StateDirectoriesCreated='已创建受保护的应用状态目录。'
                LegacyStateMigrationRequired='检测到经核验旧版留下的无数据状态目录。安装将限制这些目录的写入权限，仅允许系统和管理员写入；不会自动迁移旧数据。'
                LegacyStateMigrated='已收紧经核验的旧版无数据目录权限；未导入或删除旧数据。'
                LegacyStateContainsData='旧的不安全状态目录含有数据或未知项目。安装已停止并保留原件，请保留日志供支持人员复核。'
                LegacyStateUnsupportedAcl='已有状态目录的所有者或权限模式未经审定，未自动接受这些权限。'
                LegacyStateChanged='状态目录在核验期间发生变化。安装已停止，未接受或删除已有数据。'
                LegacyStateBusy='状态目录正在使用中，请关闭程序后重试；未终止任何进程。'
                LegacyStateMigrationPending='上次权限迁移尚未完成，继续前必须重新核验整个固定目录树无数据。'
                LegacySourceMismatch='已有安装与审定旧包不符，已拒绝自动迁移状态权限。'
                LegacySourceChanged='已有安装在核验期间发生变化，安装已停止。'
                UnsafeStatePermissions='已有状态目录允许不可信修改，安装已停止。'
                UnsafeStatePath='必需路径发生重解析跳转或并非预期对象，安装已停止。'
                StateDirectoryMissing='缺少必需的受保护状态目录。'
                StateAccessDenied='无法以所需权限安全打开状态目录。'
                MigrationJournalUnsafe='受保护的安装器迁移记录未通过完整性或权限检查。'
                MigrationJournalWriteFailed='无法持久化并核验受保护的待完成记录，安装已停止。'
                StatePermissionsChangeFailed='无法核验目录权限更改；未回放已经移除的旧写权限。'
                StateCreateFailed='无法创建必需的受保护目录。'
                StateEnumerationFailed='无法完成有界目录检查，安装已停止。'
                StateIdentityUnavailable='无法取得核验旧权限所需的本机账户身份。'
                StateAdministratorRequired='安装需要管理员权限。'
                InvalidStateMode='状态检查模式无效。'
                StateOperationFailed='无法完成应用状态准备，请保留安装日志供复核。'
            }
            $changed=@($result.ChangedDirectories | ForEach-Object { $_ })
            $created=@($result.CreatedDirectories | ForEach-Object { $_ })
            $previous=@($result.PreviouslyRestrictedDirectories | ForEach-Object { $_ })
            $before=@($result.Before | ForEach-Object { $_ })
            $after=@($result.After | ForEach-Object { $_ })
            $operations=@($result.Operations | ForEach-Object { $_ })
            $map=if($Language-eq'zhHans'){$zh}else{$en};$code=[string]$result.ReasonCode
            if($code-notmatch'^[A-Za-z]{1,64}$'){$code='StateOperationFailed';$exitCode=20}
            $lines=[Collections.Generic.List[string]]::new();$lines.Add($code);$lines.Add(('migrationRequired='+[int][bool]$result.MigrationRequired))
            $lines.Add($(if($map.ContainsKey($code)){$map[$code]}else{$map.StateOperationFailed}))
            $lines.Add(('Mode={0}; Pending={1}; ChangedThisRun={2}; CreatedThisRun={3}; PreviouslyRestricted={4}; Win32={5}'-f$Mode,[int][bool]$result.Pending,$changed.Count,$created.Count,$previous.Count,$result.Win32Error))
            $stateRoot=Join-Path ([Environment]::GetFolderPath([Environment+SpecialFolder]::CommonApplicationData)) 'SteamSentinel'
            $installRoot=Join-Path ([Environment]::GetFolderPath([Environment+SpecialFolder]::ProgramFiles)) 'SteamSentinel'
            $lines.Add(('StateRoot='+(Escape-Display $stateRoot)))
            $lines.Add(('InstallationRoot='+(Escape-Display $installRoot)))
            if($result.RelativePath){$lines.Add(('Path='+(Escape-Display $result.RelativePath)))}
            foreach($operation in $operations){$lines.Add((Escape-Display $operation))}
            if(-not$result.Succeeded -and ($changed.Count+$created.Count+$previous.Count)-gt0){
                $lines.Add($(if($Language-eq'zhHans'){'迁移未完成，已收紧权限不会恢复为旧写权限；安装已停止。'}else{'Migration did not complete. Restricted permissions were not restored to the old writable permissions. Setup has stopped.'}))
            }
            $evidence=[ordered]@{schema=$result.Schema;mode=$result.Mode;succeeded=$result.Succeeded;reasonCode=$result.ReasonCode;relativePath=$result.RelativePath;detail=$result.Detail;win32Error=$result.Win32Error;stateRoot=$stateRoot;installationRoot=$installRoot;componentSha256=$actual;expectedComponentSha256=$ExpectedSourceSha256;migrationRequired=$result.MigrationRequired;pending=$result.Pending;journalId=$result.JournalId;sourceManifestSha256=$result.SourceManifestSha256;journalSha256=$result.JournalSha256;journalComplete=$result.JournalComplete;previouslyRestrictedDirectories=$previous;changedDirectories=$changed;createdDirectories=$created;before=$before;after=$after;operations=$operations}
            $json=$evidence|ConvertTo-Json -Depth 10 -Compress
            if([Text.Encoding]::UTF8.GetByteCount($json)-gt262144 -or $lines.Count-gt32){throw 'State evidence exceeded its bounded budget.'}
            foreach($entry in @(@{Stream=$jsonStream;Text=$json},@{Stream=$displayStream;Text=($lines-join[Environment]::NewLine)})){
                if($entry.Stream){$writer=[IO.StreamWriter]::new($entry.Stream,[Text.UTF8Encoding]::new($true),1024,$true);try{$writer.WriteLine($entry.Text);$writer.Flush();$entry.Stream.Flush($true)}finally{$writer.Dispose()}}
            }
        }
    }finally{if($jsonStream){$jsonStream.Dispose()};if($displayStream){$displayStream.Dispose()};for($i=$pins.Count-1;$i-ge0;$i--){$pins[$i].Dispose()}}
}
exit $exitCode
