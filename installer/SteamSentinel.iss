#ifndef PayloadDir
  #error PayloadDir must be supplied by the release build.
#endif
#ifndef OutputDir
  #error OutputDir must be supplied by the release build.
#endif
#ifndef AppVersion
#define AppVersion "0.3.0"
#endif
#ifndef ArtifactBaseName
#define ArtifactBaseName "SteamSentinel-" + AppVersion
#endif

#define AppName "SteamSentinel Steam 红信安全工具"
#define WorkerRuleOut "SteamSentinel ArchiveWorker outbound block"
#define WorkerRuleIn "SteamSentinel ArchiveWorker inbound block"
#define WorkerStandardRuleOut "SteamSentinel ArchiveWorker Standard outbound block"
#define WorkerStandardRuleIn "SteamSentinel ArchiveWorker Standard inbound block"
#define WorkerCompatRuleOut "SteamSentinel ArchiveWorker Compat outbound block"
#define WorkerCompatRuleIn "SteamSentinel ArchiveWorker Compat inbound block"
#define WorkerFirewallScriptHash GetSHA256OfFile(SourcePath + "Verify-WorkerFirewall.ps1")
#define MachineStateScriptHash GetSHA256OfFile(SourcePath + "Initialize-MachineState.ps1")
#define MachineStateSourceHash GetSHA256OfFile(SourcePath + "MachineStateBootstrap.cs")
#define PayloadScriptHash GetSHA256OfFile(SourcePath + "Maintain-InstallPayload.ps1")
#define PayloadSourceHash GetSHA256OfFile(SourcePath + "PayloadMaintenance.cs")
#define IncomingManifestHash GetSHA256OfFile(PayloadDir + "\SHA256SUMS.txt")
; The incoming checksum manifest verifies all bytes at install time. Reject an
; incomplete unified launch layout before an installer can be distributed.
#if !FileExists(PayloadDir + "\SteamSentinel.exe") || !FileExists(PayloadDir + "\SteamSentinel.Broker.exe") || !FileExists(PayloadDir + "\SteamSentinel.ArchiveWorker.exe")
  #error The native launchers and legacy Worker alias are required.
#endif
#if !FileExists(PayloadDir + "\SteamSentinel.Standard.exe") || !FileExists(PayloadDir + "\SteamSentinel.Compat.exe")
  #error Both UI runtime hosts are required.
#endif
#if !FileExists(PayloadDir + "\SteamSentinel.Broker.Standard.exe") || !FileExists(PayloadDir + "\SteamSentinel.Broker.Compat.exe")
  #error Both Broker runtime hosts are required.
#endif
#if !FileExists(PayloadDir + "\SteamSentinel.ArchiveWorker.Standard.exe") || !FileExists(PayloadDir + "\SteamSentinel.ArchiveWorker.Compat.exe")
  #error Both ArchiveWorker runtime hosts are required.
#endif

[Setup]
AppId={{9C3982D3-D18D-4B4E-A516-E8653A383683}
AppName={cm:ProductName}
AppVersion={#AppVersion}
VersionInfoVersion={#AppVersion}.0
VersionInfoProductVersion={#AppVersion}
VersionInfoDescription=SteamSentinel Setup
VersionInfoProductName=SteamSentinel
AppPublisher=fenglinbei
AppPublisherURL=https://github.com/fenglinbei/SteamSentinel
AppSupportURL=https://github.com/fenglinbei/SteamSentinel/issues
DefaultDirName={autopf}\SteamSentinel
DefaultGroupName=SteamSentinel
DisableDirPage=yes
DisableProgramGroupPage=yes
UsePreviousAppDir=no
PrivilegesRequired=admin
PrivilegesRequiredOverridesAllowed=
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
MinVersion=10.0.19041
OutputDir={#OutputDir}
OutputBaseFilename={#ArtifactBaseName}-setup
Compression=lzma2/ultra64
SolidCompression=yes
WizardStyle=modern
SetupLogging=yes
ShowLanguageDialog=yes
LanguageDetectionMethod=uilanguage
CloseApplications=yes
; Restart Manager checks each destination payload path, including every host variant.
CloseApplicationsFilter=*.exe,*.dll
RestartApplications=no
UninstallDisplayIcon={app}\SteamSentinel.exe
SetupIconFile={#PayloadDir}\SteamSentinel.App\Assets\App.ico
LicenseFile={#PayloadDir}\LICENSE
#ifdef EnableSigning
SignTool=steamSentinelSign
SignedUninstaller=yes
SignedUninstallerDir={#OutputDir}\signing-cache\SteamSentinel
#endif

[Languages]
Name: "en"; MessagesFile: "compiler:Default.isl"
Name: "zhHans"; MessagesFile: "ChineseSimplified.isl"

[CustomMessages]
en.ProductName=SteamSentinel Steam Security Tool
zhHans.ProductName=SteamSentinel Steam 红信安全工具
en.SystemToolStartFailed=Could not start the system tool for %1. Setup has stopped; SteamSentinel will not start automatically.
zhHans.SystemToolStartFailed=无法启动系统工具以完成%1。安装已停止，SteamSentinel 不会自动启动。
en.SystemToolFailed=%1 failed (exit code %2). Setup has stopped; SteamSentinel will not start automatically.
zhHans.SystemToolFailed=%1失败（退出码 %2）。安装已停止，SteamSentinel 不会自动启动。
en.FirewallReadFailed=Could not check the ArchiveWorker firewall rule. Setup has stopped; SteamSentinel will not start automatically.
zhHans.FirewallReadFailed=无法检查 ArchiveWorker 防火墙规则。安装已停止，SteamSentinel 不会自动启动。
en.RemoveWorkerRule=removing the previous ArchiveWorker firewall rule
zhHans.RemoveWorkerRule=删除旧 ArchiveWorker 防火墙规则
en.AddWorkerRule=creating the ArchiveWorker %1 network block rule
zhHans.AddWorkerRule=建立 ArchiveWorker %1 网络阻断规则
en.FirewallVerifyStartFailed=Could not start firewall verification. Setup has stopped; SteamSentinel will not start automatically.
zhHans.FirewallVerifyStartFailed=无法启动防火墙规则复核。安装已停止，SteamSentinel 不会自动启动。
en.FirewallVerifyFailed=The ArchiveWorker firewall rule could not be verified after creation. Setup has stopped; SteamSentinel will not start automatically.
zhHans.FirewallVerifyFailed=ArchiveWorker 防火墙规则建立后无法复核。安装已停止，SteamSentinel 不会自动启动。
en.WorkerMissing=ArchiveWorker is missing, so its network block could not be created. Setup has stopped; SteamSentinel will not start automatically.
zhHans.WorkerMissing=ArchiveWorker 组件缺失，无法建立网络阻断。安装已停止，SteamSentinel 不会自动启动。
en.StateScriptInvalid=The installation state-check component failed its integrity check. Setup has stopped.
zhHans.StateScriptInvalid=安装状态检查组件未通过完整性校验，安装已停止。
en.StatePreparation=preparing protected application state directories
zhHans.StatePreparation=准备受保护的应用状态目录
en.StateVerification=verifying protected application state directories
zhHans.StateVerification=复核受保护的应用状态目录
en.StatePrepareFailed=The application state directories could not be prepared safely. Setup stopped before replacing program files. Details below identify the reason and any empty directories whose permissions were already restricted. Existing data was not accepted or removed.
zhHans.StatePrepareFailed=无法安全准备应用状态目录，安装已在替换程序文件之前停止。以下详情说明具体原因及已经收紧权限的空目录。已有数据未被接纳或删除。
en.StateInspectionFailed=The application state could not be checked. Setup will repeat the checks before replacing any program files.
zhHans.StateInspectionFailed=应用状态预检未完成。安装将在替换程序文件前重新执行检查。
en.StateLogMissing=The state-directory diagnostic log is missing or invalid. Setup has stopped.
zhHans.StateLogMissing=状态目录诊断日志缺失或无效，安装已停止。
en.LegacyStateReady=Empty state directories from a verified earlier installation were found. Setup will restrict write access to System and Administrators. Scan reports and quarantined data will not be migrated automatically.
zhHans.LegacyStateReady=检测到已核验旧版留下的无数据状态目录。安装将限制这些目录的写入权限，仅允许系统和管理员写入。扫描报告和隔离数据不会被自动迁移。
en.PayloadPrepareFailed=The existing installation files could not be prepared safely. Setup stopped before replacing files.
zhHans.PayloadPrepareFailed=现有安装文件未通过安全预检，安装已在替换文件之前停止。
en.PayloadCheckFailed=Installation file verification did not complete. SteamSentinel will not start automatically.
zhHans.PayloadCheckFailed=安装文件核验未完成，SteamSentinel 不会自动启动。
en.PayloadComponentInvalid=The installation file-maintenance component failed its integrity check.
zhHans.PayloadComponentInvalid=安装文件维护组件未通过完整性校验。
en.PayloadLogMissing=The file-maintenance diagnostic log could not be read. Setup has stopped.
zhHans.PayloadLogMissing=无法读取文件维护诊断日志，安装已停止。

[Files]
; Replace matching payload files; the bound maintenance helper separately retires
; only approved obsolete bytes and verifies the complete installed file set.
Source: "{#PayloadDir}\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "Initialize-MachineState.ps1"; Flags: dontcopy
Source: "MachineStateBootstrap.cs"; Flags: dontcopy
Source: "Maintain-InstallPayload.ps1"; Flags: dontcopy
Source: "PayloadMaintenance.cs"; Flags: dontcopy
Source: "Verify-WorkerFirewall.ps1"; Flags: dontcopy
Source: "{#PayloadDir}\SHA256SUMS.txt"; DestName: "incoming-payload-sha256.txt"; Flags: dontcopy
; No blind deletion of the 17 formerly listed root documentation files. Without
; an approved historical content hash, these are preserved and preflight refuses.

[Dirs]
; The bound bootstrap creates missing directories and can migrate only verified legacy empty directories.
; Never change permissions through [Dirs]. Preserve application state on uninstall.
Name: "{commonappdata}\SteamSentinel"; Flags: uninsneveruninstall
Name: "{commonappdata}\SteamSentinel\Quarantine"; Flags: uninsneveruninstall
Name: "{commonappdata}\SteamSentinel\Results"; Flags: uninsneveruninstall
Name: "{commonappdata}\SteamSentinel\BrokerTemp"; Flags: uninsneveruninstall

[Icons]
Name: "{autoprograms}\SteamSentinel"; Filename: "{app}\SteamSentinel.exe"; WorkingDir: "{app}"
Name: "{autodesktop}\SteamSentinel"; Filename: "{app}\SteamSentinel.exe"; WorkingDir: "{app}"; Tasks: desktopicon

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked

[Code]
var
  PayloadLogSequence: Integer;
  StateLogSequence: Integer;

procedure CheckInstallPayload(const Mode: String);
var
  ScriptPath, SourceFile, ManifestPath, LogPath, Details: String;
  Lines: TArrayOfString;
  ResultCode, I: Integer;
begin
  ExtractTemporaryFile('Maintain-InstallPayload.ps1');
  ExtractTemporaryFile('PayloadMaintenance.cs');
  ExtractTemporaryFile('incoming-payload-sha256.txt');
  ScriptPath := ExpandConstant('{tmp}\Maintain-InstallPayload.ps1');
  SourceFile := ExpandConstant('{tmp}\PayloadMaintenance.cs');
  ManifestPath := ExpandConstant('{tmp}\incoming-payload-sha256.txt');
  if (CompareText(GetSHA256OfFile(ScriptPath), '{#PayloadScriptHash}') <> 0) or
     (CompareText(GetSHA256OfFile(SourceFile), '{#PayloadSourceHash}') <> 0) or
     (CompareText(GetSHA256OfFile(ManifestPath), '{#IncomingManifestHash}') <> 0) then
    RaiseException(CustomMessage('PayloadComponentInvalid'));
  PayloadLogSequence := PayloadLogSequence + 1;
  LogPath := ExpandConstant('{tmp}\payload-maintenance-') + Mode + '-' + IntToStr(PayloadLogSequence) + '.log';
  if not Exec(ExpandConstant('{sys}\WindowsPowerShell\v1.0\powershell.exe'),
    '-NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "' + ScriptPath +
    '" -Mode ' + Mode + ' -IncomingManifestPath "' + ManifestPath +
    '" -ExpectedManifestSha256 {#IncomingManifestHash} -ExpectedSourceSha256 {#PayloadSourceHash}' +
    ' -LogPath "' + LogPath + '" -Language ' + ActiveLanguage,
    '', SW_HIDE, ewWaitUntilTerminated, ResultCode) then
    RaiseException(CustomMessage('PayloadCheckFailed'));
  if not LoadStringsFromFile(LogPath, Lines) then
    RaiseException(CustomMessage('PayloadLogMissing'));
  Details := '';
  for I := 0 to GetArrayLength(Lines) - 1 do
  begin
    Log('Payload ' + Mode + ': ' + Lines[I]);
    if I < 12 then Details := Details + Lines[I] + #13#10;
  end;
  if ResultCode <> 0 then
    RaiseException(CustomMessage('PayloadCheckFailed') + #13#10 + Details);
end;

procedure RunRequiredHidden(const FileName, Parameters, Purpose: String);
var
  ResultCode: Integer;
begin
  if not Exec(FileName, Parameters, '', SW_HIDE, ewWaitUntilTerminated, ResultCode) then
    RaiseException(FmtMessage(CustomMessage('SystemToolStartFailed'), [Purpose]));
  if ResultCode <> 0 then
    RaiseException(FmtMessage(CustomMessage('SystemToolFailed'), [Purpose, IntToStr(ResultCode)]));
end;

function RunMachineState(const Mode, Purpose: String; var MigrationRequired: Boolean): String;
var
  ScriptPath, SourcePath, JsonPath, DisplayPath, Details: String;
  Lines, JsonLines: TArrayOfString;
  ResultCode, I: Integer;
begin
  MigrationRequired := False;
  ExtractTemporaryFile('Initialize-MachineState.ps1');
  ExtractTemporaryFile('MachineStateBootstrap.cs');
  ScriptPath := ExpandConstant('{tmp}\Initialize-MachineState.ps1');
  SourcePath := ExpandConstant('{tmp}\MachineStateBootstrap.cs');
  if (CompareText(GetSHA256OfFile(ScriptPath), '{#MachineStateScriptHash}') <> 0) or
     (CompareText(GetSHA256OfFile(SourcePath), '{#MachineStateSourceHash}') <> 0) then
    RaiseException(CustomMessage('StateScriptInvalid'));
  StateLogSequence := StateLogSequence + 1;
  JsonPath := ExpandConstant('{tmp}\machine-state-') + Mode + '-' + IntToStr(StateLogSequence) + '.json';
  DisplayPath := ExpandConstant('{tmp}\machine-state-') + Mode + '-' + IntToStr(StateLogSequence) + '.txt';
  if not Exec(ExpandConstant('{sys}\WindowsPowerShell\v1.0\powershell.exe'),
    '-NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "' + ScriptPath +
    '" -Mode ' + Mode + ' -ExpectedSourceSha256 {#MachineStateSourceHash}' +
    ' -LogPath "' + JsonPath + '" -DisplayLogPath "' + DisplayPath + '" -Language ' + ActiveLanguage,
    '', SW_HIDE, ewWaitUntilTerminated, ResultCode) then
    RaiseException(FmtMessage(CustomMessage('SystemToolStartFailed'), [Purpose]));
  if not LoadStringsFromFile(DisplayPath, Lines) then
    RaiseException(CustomMessage('StateLogMissing'));
  if (GetArrayLength(Lines) < 3) or (GetArrayLength(Lines) > 32) then
    RaiseException(CustomMessage('StateLogMissing'));
  if (Lines[1] <> 'migrationRequired=0') and (Lines[1] <> 'migrationRequired=1') then
    RaiseException(CustomMessage('StateLogMissing'));
  MigrationRequired := Lines[1] = 'migrationRequired=1';
  Details := '';
  for I := 0 to GetArrayLength(Lines) - 1 do
  begin
    if Length(Lines[I]) > 2048 then
      RaiseException(CustomMessage('StateLogMissing'));
    Log('MachineState ' + Mode + ': ' + Lines[I]);
    if (I >= 2) and (I < 14) then Details := Details + Lines[I] + #13#10;
  end;
  if not LoadStringsFromFile(JsonPath, JsonLines) then
    RaiseException(CustomMessage('StateLogMissing'));
  if (GetArrayLength(JsonLines) < 1) or (GetArrayLength(JsonLines) > 4096) then
    RaiseException(CustomMessage('StateLogMissing'));
  for I := 0 to GetArrayLength(JsonLines) - 1 do
  begin
    if Length(JsonLines[I]) > 262144 then
      RaiseException(CustomMessage('StateLogMissing'));
    Log('MachineStateEvidence ' + Mode + ': ' + JsonLines[I]);
  end;
  if ResultCode <> 0 then
    RaiseException(Details + FmtMessage(CustomMessage('SystemToolFailed'), [Purpose, IntToStr(ResultCode)]));
  Result := Details;
end;

procedure CheckMachineState(const Mode, Purpose: String);
var
  MigrationRequired: Boolean;
begin
  RunMachineState(Mode, Purpose, MigrationRequired);
end;

procedure AppendReadyMemoSection(var Memo: String; const Section, NewLine: String);
begin
  if Section <> '' then
  begin
    if Memo <> '' then Memo := Memo + NewLine + NewLine;
    Memo := Memo + Section;
  end;
end;

function UpdateReadyMemo(Space, NewLine, MemoUserInfoInfo, MemoDirInfo, MemoTypeInfo,
  MemoComponentsInfo, MemoGroupInfo, MemoTasksInfo: String): String;
var
  MigrationRequired: Boolean;
begin
  Result := '';
  AppendReadyMemoSection(Result, MemoUserInfoInfo, NewLine);
  AppendReadyMemoSection(Result, MemoDirInfo, NewLine);
  AppendReadyMemoSection(Result, MemoTypeInfo, NewLine);
  AppendReadyMemoSection(Result, MemoComponentsInfo, NewLine);
  AppendReadyMemoSection(Result, MemoGroupInfo, NewLine);
  AppendReadyMemoSection(Result, MemoTasksInfo, NewLine);
  try
    { Read-only observation only. PrepareToInstall repeats all checks before any migration. }
    RunMachineState('Inspect', CustomMessage('StateVerification'), MigrationRequired);
    if MigrationRequired then
      Result := Result + NewLine + NewLine + CustomMessage('LegacyStateReady');
  except
    Log(GetExceptionMessage);
    Result := Result + NewLine + NewLine + CustomMessage('StateInspectionFailed') +
      NewLine + GetExceptionMessage;
  end;
end;

function PrepareToInstall(var NeedsRestart: Boolean): String;
begin
  Result := '';
  try
    CheckInstallPayload('Preflight');
  except
    Log(GetExceptionMessage);
    Result := CustomMessage('PayloadPrepareFailed') + #13#10 + GetExceptionMessage;
    Exit;
  end;
  try
    CheckMachineState('Prepare', CustomMessage('StatePreparation'));
  except
    Log(GetExceptionMessage);
    Result := CustomMessage('StatePrepareFailed') + #13#10 + GetExceptionMessage;
  end;
end;

procedure RemoveFirewallRuleIfPresent(const RuleName: String);
var
  ResultCode: Integer;
begin
  if not Exec(ExpandConstant('{sys}\netsh.exe'),
    'advfirewall firewall show rule name="' + RuleName + '"', '', SW_HIDE,
    ewWaitUntilTerminated, ResultCode) then
    RaiseException(CustomMessage('FirewallReadFailed'));
  if ResultCode = 0 then
    RunRequiredHidden(ExpandConstant('{sys}\netsh.exe'),
      'advfirewall firewall delete rule name="' + RuleName + '"', CustomMessage('RemoveWorkerRule'));
end;

procedure AddAndVerifyFirewallRule(const RuleName, Direction, WorkerPath: String);
var
  ResultCode: Integer;
begin
  RunRequiredHidden(ExpandConstant('{sys}\netsh.exe'),
    'advfirewall firewall add rule name="' + RuleName + '" dir=' + Direction +
    ' action=block enable=yes profile=any program="' + WorkerPath + '"',
    FmtMessage(CustomMessage('AddWorkerRule'), [Direction]));
  if not Exec(ExpandConstant('{sys}\netsh.exe'),
    'advfirewall firewall show rule name="' + RuleName + '"', '', SW_HIDE,
    ewWaitUntilTerminated, ResultCode) then
    RaiseException(CustomMessage('FirewallVerifyStartFailed'));
  if ResultCode <> 0 then
    RaiseException(CustomMessage('FirewallVerifyFailed'));
end;

procedure ConfigureWorkerFirewall;
var
  WorkerPath, StandardPath, CompatPath, VerifyScript: String;
begin
  WorkerPath := ExpandConstant('{app}\SteamSentinel.ArchiveWorker.exe');
  StandardPath := ExpandConstant('{app}\SteamSentinel.ArchiveWorker.Standard.exe');
  CompatPath := ExpandConstant('{app}\SteamSentinel.ArchiveWorker.Compat.exe');
  if not FileExists(WorkerPath) or not FileExists(StandardPath) or not FileExists(CompatPath) then
    RaiseException(CustomMessage('WorkerMissing'));
  RemoveFirewallRuleIfPresent('{#WorkerRuleOut}');
  RemoveFirewallRuleIfPresent('{#WorkerRuleIn}');
  AddAndVerifyFirewallRule('{#WorkerRuleOut}', 'out', WorkerPath);
  AddAndVerifyFirewallRule('{#WorkerRuleIn}', 'in', WorkerPath);
  RemoveFirewallRuleIfPresent('{#WorkerStandardRuleOut}');
  RemoveFirewallRuleIfPresent('{#WorkerStandardRuleIn}');
  AddAndVerifyFirewallRule('{#WorkerStandardRuleOut}', 'out', StandardPath);
  AddAndVerifyFirewallRule('{#WorkerStandardRuleIn}', 'in', StandardPath);
  RemoveFirewallRuleIfPresent('{#WorkerCompatRuleOut}');
  RemoveFirewallRuleIfPresent('{#WorkerCompatRuleIn}');
  AddAndVerifyFirewallRule('{#WorkerCompatRuleOut}', 'out', CompatPath);
  AddAndVerifyFirewallRule('{#WorkerCompatRuleIn}', 'in', CompatPath);
  ExtractTemporaryFile('Verify-WorkerFirewall.ps1');
  VerifyScript := ExpandConstant('{tmp}\Verify-WorkerFirewall.ps1');
  if CompareText(GetSHA256OfFile(VerifyScript), '{#WorkerFirewallScriptHash}') <> 0 then
    RaiseException(CustomMessage('PayloadComponentInvalid'));
  RunRequiredHidden(ExpandConstant('{sys}\WindowsPowerShell\v1.0\powershell.exe'),
    '-NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "' + VerifyScript +
    '" -InstallRoot "' + ExpandConstant('{app}') + '"', CustomMessage('FirewallVerifyFailed'));
end;

procedure CurStepChanged(CurStep: TSetupStep);
begin
  if CurStep = ssPostInstall then
  begin
    CheckInstallPayload('Retire');
    CheckInstallPayload('Verify');
    CheckMachineState('Verify', CustomMessage('StateVerification'));
    ConfigureWorkerFirewall;
  end;
end;

[Run]
Filename: "{app}\SteamSentinel.exe"; Description: "{cm:LaunchProgram,SteamSentinel}"; Flags: nowait postinstall skipifsilent

[UninstallRun]
Filename: "{sys}\netsh.exe"; Parameters: "advfirewall firewall delete rule name=""{#WorkerRuleOut}"""; Flags: runhidden waituntilterminated; RunOnceId: "RemoveWorkerOutboundRule"
Filename: "{sys}\netsh.exe"; Parameters: "advfirewall firewall delete rule name=""{#WorkerRuleIn}"""; Flags: runhidden waituntilterminated; RunOnceId: "RemoveWorkerInboundRule"
Filename: "{sys}\netsh.exe"; Parameters: "advfirewall firewall delete rule name=""{#WorkerStandardRuleOut}"""; Flags: runhidden waituntilterminated; RunOnceId: "RemoveWorkerStandardOutboundRule"
Filename: "{sys}\netsh.exe"; Parameters: "advfirewall firewall delete rule name=""{#WorkerStandardRuleIn}"""; Flags: runhidden waituntilterminated; RunOnceId: "RemoveWorkerStandardInboundRule"
Filename: "{sys}\netsh.exe"; Parameters: "advfirewall firewall delete rule name=""{#WorkerCompatRuleOut}"""; Flags: runhidden waituntilterminated; RunOnceId: "RemoveWorkerCompatOutboundRule"
Filename: "{sys}\netsh.exe"; Parameters: "advfirewall firewall delete rule name=""{#WorkerCompatRuleIn}"""; Flags: runhidden waituntilterminated; RunOnceId: "RemoveWorkerCompatInboundRule"
