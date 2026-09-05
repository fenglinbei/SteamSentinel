#ifndef PayloadDir
  #error PayloadDir must be supplied by the release build.
#endif
#ifndef OutputDir
  #error OutputDir must be supplied by the release build.
#endif
#ifndef AppVersion
#define AppVersion "0.1.19"
#endif
#ifndef ArtifactBaseName
#define ArtifactBaseName "SteamSentinel-" + AppVersion
#endif

#define AppName "SteamSentinel Steam 红信安全工具"
#define WorkerRuleOut "SteamSentinel ArchiveWorker outbound block"
#define WorkerRuleIn "SteamSentinel ArchiveWorker inbound block"

[Setup]
AppId={{9C3982D3-D18D-4B4E-A516-E8653A383683}
AppName={#AppName}
AppVersion={#AppVersion}
VersionInfoVersion={#AppVersion}.0
VersionInfoProductVersion={#AppVersion}
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
CloseApplications=yes
RestartApplications=no
UninstallDisplayIcon={app}\SteamSentinel.exe
SetupIconFile={#PayloadDir}\SteamSentinel.App\Assets\App.ico
LicenseFile={#PayloadDir}\LICENSE
#ifdef EnableSigning
SignTool=steamSentinelSign
SignedUninstaller=yes
SignedUninstallerDir={#OutputDir}\signing-cache\SteamSentinel
#endif

[Files]
; Replace the complete self-contained payload so SHA256SUMS describes the
; installed bytes exactly. Rollback prevention remains a public-release gate.
Source: "{#PayloadDir}\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[InstallDelete]
; Releases before 0.1.17 flattened documentation into the application root.
; The new payload preserves docs\ paths so README links and integrity manifests agree.
Type: files; Name: "{app}\COVERAGE-0.1.11.md"
Type: files; Name: "{app}\COVERAGE-0.1.12.md"
Type: files; Name: "{app}\COVERAGE-0.1.13.md"
Type: files; Name: "{app}\COVERAGE-0.1.14.md"
Type: files; Name: "{app}\COVERAGE-0.1.15.md"
Type: files; Name: "{app}\COVERAGE-0.1.16.md"
Type: files; Name: "{app}\GROUP-TEST-GUIDE.md"
Type: files; Name: "{app}\ICONS.md"
Type: files; Name: "{app}\INSTALLATION-REGRESSION-0.1.7.md"
Type: files; Name: "{app}\PASSWORD-REGRESSION-0.1.6.md"
Type: files; Name: "{app}\RELEASE-CHECKLIST.md"
Type: files; Name: "{app}\ROADMAP.md"
Type: files; Name: "{app}\SAMPLE-COVERAGE-0.1.5.md"
Type: files; Name: "{app}\SIGNING.md"
Type: files; Name: "{app}\TEST-EVIDENCE.md"
Type: files; Name: "{app}\THREAT-MODEL.md"
Type: files; Name: "{app}\WORKER-STARTUP-0.1.8.md"

[Dirs]
Name: "{commonappdata}\SteamSentinel"; Permissions: admins-full system-full users-readexec
Name: "{commonappdata}\SteamSentinel\Quarantine"; Permissions: admins-full system-full users-readexec
Name: "{commonappdata}\SteamSentinel\Results"; Permissions: admins-full system-full users-readexec
Name: "{commonappdata}\SteamSentinel\BrokerTemp"; Permissions: admins-full system-full

[Icons]
Name: "{autoprograms}\SteamSentinel"; Filename: "{app}\SteamSentinel.exe"; WorkingDir: "{app}"
Name: "{autodesktop}\SteamSentinel"; Filename: "{app}\SteamSentinel.exe"; WorkingDir: "{app}"; Tasks: desktopicon

[Tasks]
Name: "desktopicon"; Description: "创建桌面快捷方式"; GroupDescription: "附加图标："; Flags: unchecked

[Code]
procedure RunRequiredHidden(const FileName, Parameters, Purpose: String);
var
  ResultCode: Integer;
begin
  if not Exec(FileName, Parameters, '', SW_HIDE, ewWaitUntilTerminated, ResultCode) then
    RaiseException(Format('无法启动系统工具以完成%s。安装已停止，SteamSentinel 不会自动启动。', [Purpose]));
  if ResultCode <> 0 then
    RaiseException(Format('%s失败（退出码 %d）。安装已停止，SteamSentinel 不会自动启动。', [Purpose, ResultCode]));
end;

procedure RemoveFirewallRuleIfPresent(const RuleName: String);
var
  ResultCode: Integer;
begin
  if not Exec(ExpandConstant('{sys}\netsh.exe'),
    'advfirewall firewall show rule name="' + RuleName + '"', '', SW_HIDE,
    ewWaitUntilTerminated, ResultCode) then
    RaiseException('无法检查 ArchiveWorker 防火墙规则。安装已停止，SteamSentinel 不会自动启动。');
  if ResultCode = 0 then
    RunRequiredHidden(ExpandConstant('{sys}\netsh.exe'),
      'advfirewall firewall delete rule name="' + RuleName + '"', '删除旧 ArchiveWorker 防火墙规则');
end;

procedure AddAndVerifyFirewallRule(const RuleName, Direction, WorkerPath: String);
var
  ResultCode: Integer;
begin
  RunRequiredHidden(ExpandConstant('{sys}\netsh.exe'),
    'advfirewall firewall add rule name="' + RuleName + '" dir=' + Direction +
    ' action=block enable=yes profile=any program="' + WorkerPath + '"',
    '建立 ArchiveWorker ' + Direction + ' 网络阻断规则');
  if not Exec(ExpandConstant('{sys}\netsh.exe'),
    'advfirewall firewall show rule name="' + RuleName + '"', '', SW_HIDE,
    ewWaitUntilTerminated, ResultCode) then
    RaiseException('无法启动防火墙规则复核。安装已停止，SteamSentinel 不会自动启动。');
  if ResultCode <> 0 then
    RaiseException('ArchiveWorker 防火墙规则建立后无法复核。安装已停止，SteamSentinel 不会自动启动。');
end;

procedure ConfigureWorkerFirewall;
var
  WorkerPath: String;
begin
  WorkerPath := ExpandConstant('{app}\SteamSentinel.ArchiveWorker.exe');
  if not FileExists(WorkerPath) then
    RaiseException('ArchiveWorker 组件缺失，无法建立网络阻断。安装已停止，SteamSentinel 不会自动启动。');
  RemoveFirewallRuleIfPresent('{#WorkerRuleOut}');
  RemoveFirewallRuleIfPresent('{#WorkerRuleIn}');
  AddAndVerifyFirewallRule('{#WorkerRuleOut}', 'out', WorkerPath);
  AddAndVerifyFirewallRule('{#WorkerRuleIn}', 'in', WorkerPath);
end;

procedure CurStepChanged(CurStep: TSetupStep);
begin
  if CurStep = ssPostInstall then
  begin
    ConfigureWorkerFirewall;
  end;
end;

[Run]
Filename: "{app}\SteamSentinel.exe"; Description: "启动 SteamSentinel"; Flags: nowait postinstall skipifsilent

[UninstallRun]
Filename: "{sys}\netsh.exe"; Parameters: "advfirewall firewall delete rule name=""{#WorkerRuleOut}"""; Flags: runhidden waituntilterminated; RunOnceId: "RemoveWorkerOutboundRule"
Filename: "{sys}\netsh.exe"; Parameters: "advfirewall firewall delete rule name=""{#WorkerRuleIn}"""; Flags: runhidden waituntilterminated; RunOnceId: "RemoveWorkerInboundRule"
