; AEROCX Blackout - Windows-installatieprogramma (Inno Setup 6.3 of nieuwer)
;
; Bouwen (vanuit de hoofdmap van de repo, na het bouwen van dist\aerocx-blackout-windows.exe):
;   iscc /DAppVersion=1.2.0 /DNumVersion=1.2.0 packaging\windows\blackout.iss
; Ondertekenen gebeurt in .github/workflows/release.yml: eerst de exe, daarna dit installatieprogramma.
;
; Uitvoer: dist\AEROCX-Blackout-Setup.exe
; - installeert per gebruiker, zonder beheerder (admin): %LOCALAPPDATA%\Programs\AEROCX Blackout
; - snelkoppeling in Start (en op het bureaublad)
; - automatisch starten bij aanmelden (HKCU\...\Run, met -background)
; - firewallregel alleen als het installatieprogramma als beheerder draait; anders vraagt Windows het zelf
; - start na de installatie met -open (de browser opent)

#ifndef AppVersion
  #define AppVersion "0.0.0"
#endif
#ifndef NumVersion
  #define NumVersion "0.0.0"
#endif
#define AppName "AEROCX Blackout"
#define AppExe "aerocx-blackout.exe"
#define AppPublisher "AEROCX Consulting Group CommV"
#define AppUrl "https://blackout.aerocx.be/"

[Setup]
AppId={{6F2B7C1E-8A4D-4E5B-9C3F-AE0C5B1A7D42}
AppName={#AppName}
AppVersion={#AppVersion}
AppVerName={#AppName} {#AppVersion}
AppPublisher={#AppPublisher}
AppPublisherURL={#AppUrl}
AppSupportURL={#AppUrl}
AppUpdatesURL=https://github.com/AEROCX-Consulting/blackout/releases/latest
AppCopyright=Copyright (c) 2026 {#AppPublisher}
VersionInfoVersion={#NumVersion}
VersionInfoProductName={#AppName}
VersionInfoCompany={#AppPublisher}
VersionInfoDescription={#AppName} installatie
DefaultDirName={localappdata}\Programs\{#AppName}
DisableDirPage=yes
DisableProgramGroupPage=yes
DisableReadyPage=yes
DisableWelcomePage=no
PrivilegesRequired=lowest
UsedUserAreasWarning=no
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
MinVersion=10.0
OutputDir=..\..\dist
OutputBaseFilename=AEROCX-Blackout-Setup
SetupIconFile=..\icon.ico
UninstallDisplayIcon={app}\icon.ico
UninstallDisplayName={#AppName}
Compression=lzma2/max
SolidCompression=yes
WizardStyle=modern
ShowLanguageDialog=no
CloseApplications=yes
RestartApplications=no

[Languages]
Name: "dutch"; MessagesFile: "compiler:Languages\Dutch.isl"
Name: "english"; MessagesFile: "compiler:Default.isl"

[CustomMessages]
dutch.StartNow=AEROCX Blackout nu starten (opent in je browser)
english.StartNow=Start AEROCX Blackout now (opens in your browser)

[Files]
Source: "..\..\dist\aerocx-blackout-windows.exe"; DestDir: "{app}"; DestName: "{#AppExe}"; Flags: ignoreversion
Source: "..\icon.ico"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\portable\windows\LEESMIJ.txt"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{userprograms}\{#AppName}"; Filename: "{app}\{#AppExe}"; Parameters: "-open"; WorkingDir: "{app}"; IconFilename: "{app}\icon.ico"; Comment: "AEROCX Blackout openen in je browser"
Name: "{userdesktop}\{#AppName}"; Filename: "{app}\{#AppExe}"; Parameters: "-open"; WorkingDir: "{app}"; IconFilename: "{app}\icon.ico"; Comment: "AEROCX Blackout openen in je browser"

[Registry]
; Automatisch starten bij aanmelden (zelfde waarde als "aerocx-blackout.exe -autostart=on").
Root: HKCU; Subkey: "Software\Microsoft\Windows\CurrentVersion\Run"; ValueType: string; ValueName: "{#AppName}"; ValueData: """{app}\{#AppExe}"" -background"; Flags: uninsdeletevalue

[Run]
; Firewall: alleen als dit installatieprogramma beheerdersrechten heeft. Anders vraagt Windows het
; zelf de eerste keer dat de app het netwerk gebruikt.
Filename: "{sys}\netsh.exe"; Parameters: "advfirewall firewall delete rule name=""{#AppName}"""; Flags: runhidden waituntilterminated; Check: IsAdmin
Filename: "{sys}\netsh.exe"; Parameters: "advfirewall firewall add rule name=""{#AppName}"" dir=in action=allow program=""{app}\{#AppExe}"" enable=yes profile=private,domain"; Flags: runhidden waituntilterminated; Check: IsAdmin
Filename: "{app}\{#AppExe}"; Parameters: "-open"; WorkingDir: "{app}"; Description: "{cm:StartNow}"; Flags: nowait postinstall skipifsilent

[UninstallRun]
Filename: "{sys}\taskkill.exe"; Parameters: "/F /IM {#AppExe}"; Flags: runhidden waituntilterminated; RunOnceId: "StopApp"
Filename: "{sys}\netsh.exe"; Parameters: "advfirewall firewall delete rule name=""{#AppName}"""; Flags: runhidden waituntilterminated; RunOnceId: "DelFirewall"; Check: IsAdmin

; Je gegevens en sleutels in %APPDATA%\AEROCX Blackout blijven bij verwijderen bewust bewaard.

[Code]
// Stop een draaiende versie netjes voor de bestanden vervangen worden (bij bijwerken).
procedure StopRunningApp();
var
  ResultCode: Integer;
begin
  Exec(ExpandConstant('{sys}\WindowsPowerShell\v1.0\powershell.exe'),
    '-NoProfile -NonInteractive -WindowStyle Hidden -Command "try { Invoke-WebRequest -UseBasicParsing -TimeoutSec 3 -Method Post -Uri http://127.0.0.1:8474/api/quit | Out-Null; Start-Sleep -Seconds 1 } catch { }"',
    '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  Exec(ExpandConstant('{sys}\taskkill.exe'), '/F /IM {#AppExe}', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
end;

function PrepareToInstall(var NeedsRestart: Boolean): String;
begin
  StopRunningApp();
  Result := '';
end;
