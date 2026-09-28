[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][ValidateSet('Preflight','Retire','Verify')][string]$Mode,
    [Parameter(Mandatory=$true)][string]$IncomingManifestPath,
    [Parameter(Mandatory=$true)][ValidatePattern('^[A-Fa-f0-9]{64}$')][string]$ExpectedManifestSha256,
    [Parameter(Mandatory=$true)][ValidatePattern('^[A-Fa-f0-9]{64}$')][string]$ExpectedSourceSha256,
    [Parameter(Mandatory=$true)][string]$LogPath,
    [ValidateSet('en','zhHans')][string]$Language='en'
)
# Installer-only entry point: there is no caller-supplied application root or retirement catalog.
Set-StrictMode -Version Latest; $ErrorActionPreference='Stop'
$log=$null; $exitCode=21; $lines=[Collections.Generic.List[string]]::new()
try {
    if ($PSVersionTable.PSVersion.Major-ne5 -or -not[Environment]::Is64BitProcess) { throw 'Windows PowerShell 5.1 x64 is required.' }
    $root=[IO.Path]::GetFullPath($PSScriptRoot).TrimEnd('\')
    $fullLog=[IO.Path]::GetFullPath($LogPath)
    if ([IO.Path]::GetDirectoryName($fullLog)-ne$root -or [IO.Path]::GetFileName($fullLog)-notmatch'^payload-maintenance-(Preflight|Retire|Verify)-[0-9]+\.log$') { throw 'Unexpected installer log path.' }
    for($cursor=$root;$cursor;$cursor=[IO.Path]::GetDirectoryName($cursor.TrimEnd('\'))) {
        if((Get-Item -LiteralPath $cursor -Force).Attributes-band[IO.FileAttributes]::ReparsePoint){throw 'Installer temporary directory is redirected.'}
    }
    $log=[IO.File]::Open($fullLog,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read)
    $source=Join-Path $root 'PayloadMaintenance.cs'
    if((Get-Item -LiteralPath $source -Force).Attributes-band[IO.FileAttributes]::ReparsePoint){throw 'Maintenance source is redirected.'}
    $stream=[IO.File]::Open($source,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
    try {
        if($stream.Length-le0 -or $stream.Length-gt256KB){throw 'Maintenance source size differs.'}
        $memory=[IO.MemoryStream]::new();try{$stream.CopyTo($memory);$bytes=$memory.ToArray()}finally{$memory.Dispose()}
    } finally {$stream.Dispose()}
    $sha=[Security.Cryptography.SHA256]::Create();try{$actual=[BitConverter]::ToString($sha.ComputeHash($bytes)).Replace('-','')}finally{$sha.Dispose()}
    if($actual-ne$ExpectedSourceSha256){throw 'Maintenance source integrity check failed.'}
    # Compile the exact hashed bytes. The test-only symbol is never defined by this production wrapper.
    Add-Type -TypeDefinition ([Text.UTF8Encoding]::new($false,$true).GetString($bytes).TrimStart([char]0xFEFF))
    foreach($line in [SteamSentinelPayloadMaintenance]::Run($Mode,$IncomingManifestPath,$ExpectedManifestSha256)){$lines.Add($line)}
    $exitCode=0
} catch {
    $errorObject=$_.Exception
    while($errorObject.InnerException){$errorObject=$errorObject.InnerException}
    $code='InternalFailure';$path='';$detail=$errorObject.Message
    if($errorObject.GetType().Name-eq'MaintenanceException') {
        $code=$errorObject.Code;$path=$errorObject.RelativePath
        foreach($operation in $errorObject.Operations){$lines.Add($operation)}
    }
    $en=@{
        InvalidManifest='The incoming file list failed validation.';UnsafePath='A file or directory path is unsafe or redirected.'
        UnsafePermissions='An existing file or directory permits untrusted changes. Its permissions were not modified.'
        UnknownFile='An unrecognized obsolete file was preserved. Review it before retrying the upgrade.'
        LegacyContentMismatch='A known obsolete filename has different content. The file was preserved for review.'
        NewPayloadMissing='A required new file is missing.';NewPayloadMismatch='A new file failed its integrity check.'
        FileBusy='A file is in use. Close the application and retry.';FileChanged='A file changed during verification.'
        DeleteFailed='An approved obsolete file could not be removed. Setup did not complete.'
        InstallationMissing='The installation directory is missing.';AccessDenied='The required file access or administrative permission is unavailable.'
        InternalFailure='The installation file check could not complete. Review the setup log.'
    }
    $zh=@{
        InvalidManifest='新版文件清单未通过验证。';UnsafePath='文件或目录路径不安全，或存在重解析跳转。'
        UnsafePermissions='已有文件或目录允许不可信修改；未更改其权限。'
        UnknownFile='发现未识别的旧文件，已保留原件。请复核后再重试升级。'
        LegacyContentMismatch='已知旧文件的名称相同但内容不符，已保留原件供复核。'
        NewPayloadMissing='缺少新版必需文件。';NewPayloadMismatch='新版文件未通过完整性校验。'
        FileBusy='文件正在使用中，请关闭程序后重试。';FileChanged='文件在验证期间发生变化。'
        DeleteFailed='无法移除已核实的旧文件，安装未完成。';InstallationMissing='安装目录不存在。'
        AccessDenied='缺少所需的文件访问权限或管理员权限。';InternalFailure='安装文件检查未能完成，请查看安装日志。'
    }
    $messages=if($Language-eq'zhHans'){$zh}else{$en};$message=if($messages.ContainsKey($code)){$messages[$code]}else{$messages.InternalFailure}
    $lines.Add($message);$lines.Add(('Code={0}; Path={1}; Mode={2}'-f$code,$path,$Mode));$lines.Add(('Diagnostic='+$detail))
} finally {
    if($log){try{$writer=[IO.StreamWriter]::new($log,[Text.UTF8Encoding]::new($true),1024,$true);try{foreach($line in $lines){$writer.WriteLine($line)};$writer.Flush();$log.Flush($true)}finally{$writer.Dispose()}}finally{$log.Dispose()}}
}
foreach($line in $lines){Write-Output $line}
exit $exitCode
