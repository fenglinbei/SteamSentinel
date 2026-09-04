#ifndef PayloadDir
  #error PayloadDir must be supplied by the release build.
#endif
#ifndef OutputDir
  #error OutputDir must be supplied by the release build.
#endif
#ifndef AppVersion
#define AppVersion "0.1.16"
#endif

#define AppName "SteamSentinel Steam 红信安全工具"
#define WorkerRuleOut "SteamSentinel ArchiveWorker outbound block"
#define WorkerRuleIn "SteamSentinel ArchiveWorker inbound block"

[Setup]
AppId={{9C3982D3-D18D-4B4E-A516-E8653A383683}
AppName={#AppName}
AppVersion={#AppVersion}
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
MinVersion=10.0.17763
OutputDir={#OutputDir}
OutputBaseFilename=SteamSentinel-{#AppVersion}-setup
Compression=lzma2/ultra64
SolidCompression=yes
WizardStyle=modern
SetupLogging=yes
CloseApplications=yes
RestartApplications=no
UninstallDisplayIcon={app}\SteamSentinel.exe
SetupIconFile={#PayloadDir}\Assets\App.ico
LicenseFile={#PayloadDir}\LICENSE
#ifdef EnableSigning
SignTool=fenglinbei
SignedUninstaller=yes
SignedUninstallerDir={#OutputDir}\signing-cache\SteamSentinel
#endif

[Files]
Source: "{#PayloadDir}\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

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

[Run]
Filename: "{sys}\netsh.exe"; Parameters: "advfirewall firewall delete rule name=""{#WorkerRuleOut}"""; Flags: runhidden waituntilterminated
Filename: "{sys}\netsh.exe"; Parameters: "advfirewall firewall delete rule name=""{#WorkerRuleIn}"""; Flags: runhidden waituntilterminated
Filename: "{sys}\netsh.exe"; Parameters: "advfirewall firewall add rule name=""{#WorkerRuleOut}"" dir=out action=block enable=yes profile=any program=""{app}\SteamSentinel.ArchiveWorker.exe"""; Flags: runhidden waituntilterminated
Filename: "{sys}\netsh.exe"; Parameters: "advfirewall firewall add rule name=""{#WorkerRuleIn}"" dir=in action=block enable=yes profile=any program=""{app}\SteamSentinel.ArchiveWorker.exe"""; Flags: runhidden waituntilterminated
Filename: "{app}\SteamSentinel.exe"; Description: "启动 SteamSentinel"; Flags: nowait postinstall skipifsilent

[UninstallRun]
Filename: "{sys}\netsh.exe"; Parameters: "advfirewall firewall delete rule name=""{#WorkerRuleOut}"""; Flags: runhidden waituntilterminated; RunOnceId: "RemoveWorkerOutboundRule"
Filename: "{sys}\netsh.exe"; Parameters: "advfirewall firewall delete rule name=""{#WorkerRuleIn}"""; Flags: runhidden waituntilterminated; RunOnceId: "RemoveWorkerInboundRule"
