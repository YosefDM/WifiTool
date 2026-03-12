; ============================================================
; WifiTool Inno Setup Script
; Builds the Windows installer: WifiTool-Setup.exe
;
; Prerequisites (on the build machine):
;   - Inno Setup 6  (https://jrsoftware.org/isinfo.php)
;   - dist\WifiTool\  produced by PyInstaller (WifiTool.spec)
;   - installer\assets\aircrack-ng\  — extracted aircrack-ng Windows binaries
;   - installer\assets\hashcat\      — extracted hashcat binaries
;   - installer\assets\npcap-installer.exe — Npcap installer
;
; Run the build helper to download assets and compile:
;   powershell -ExecutionPolicy Bypass -File installer\build_installer.ps1
; ============================================================

#define MyAppName      "WifiTool"
#define MyAppVersion   "1.3.0"
#define MyAppPublisher "WifiTool Project"
#define MyAppURL       "https://github.com/YosefDM/WifiTool"
#define MyAppExeName   "WifiTool.exe"
#define MyToolsSubdir  "tools"

[Setup]
AppId={{A9B5C3D2-4E6F-7890-ABCD-EF0123456789}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
AppPublisherURL={#MyAppURL}
AppSupportURL={#MyAppURL}
AppUpdatesURL={#MyAppURL}
DefaultDirName={autopf}\{#MyAppName}
DefaultGroupName={#MyAppName}
AllowNoIcons=yes
; Output location (relative to the .iss file)
OutputDir=Output
OutputBaseFilename=WifiTool-Setup-{#MyAppVersion}
Compression=lzma2/ultra64
SolidCompression=yes
WizardStyle=modern
; Require Administrator — needed for monitor mode and packet capture
PrivilegesRequired=admin
; 64-bit install directory on 64-bit Windows
ArchitecturesInstallIn64BitMode=x64compatible

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; \
  GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked

[Files]
; ---- WifiTool application (PyInstaller one-folder bundle) ----------------
Source: "..\dist\WifiTool\*"; DestDir: "{app}"; \
  Flags: ignoreversion recursesubdirs createallsubdirs

; ---- aircrack-ng Windows binaries (airodump-ng, aireplay-ng, aircrack-ng)
Source: "assets\aircrack-ng\*"; \
  DestDir: "{app}\{#MyToolsSubdir}\aircrack-ng"; \
  Flags: ignoreversion recursesubdirs createallsubdirs

; ---- hashcat GPU password cracker ----------------------------------------
Source: "assets\hashcat\*"; \
  DestDir: "{app}\{#MyToolsSubdir}\hashcat"; \
  Flags: ignoreversion recursesubdirs createallsubdirs

; ---- Bundled wordlist (WPA2-filtered passwords from common-password-list) ---
Source: "assets\wordlists\wifitool-wordlist.txt"; \
  DestDir: "{app}\wordlists"; Flags: ignoreversion

; ---- Npcap installer — runs interactively, deleted from {tmp} after install
Source: "assets\npcap-installer.exe"; DestDir: "{tmp}"; \
  Flags: deleteafterinstall

[Icons]
Name: "{group}\{#MyAppName}";             Filename: "{app}\{#MyAppExeName}"
Name: "{group}\{cm:UninstallProgram,{#MyAppName}}"; Filename: "{uninstallexe}"
Name: "{commondesktop}\{#MyAppName}";     Filename: "{app}\{#MyAppExeName}"; \
  Tasks: desktopicon

[Run]
; Launch the Npcap interactive installer only if Npcap is not already present.
; Skipping on upgrades avoids the kernel-driver restart prompt.
; /dot11_support=yes pre-selects "Support raw 802.11 traffic (monitor mode)".
; Silent install (/S) requires the paid Npcap OEM licence — not used here.
Filename: "{tmp}\npcap-installer.exe"; \
  Parameters: "/dot11_support=yes"; \
  StatusMsg: "Please complete the Npcap setup wizard (monitor mode is pre-selected)..."; \
  Flags: waituntilterminated; \
  Check: NpcapNotInstalled

; Offer to launch WifiTool after installation finishes
Filename: "{app}\{#MyAppExeName}"; \
  Description: "{cm:LaunchProgram,{#StringChange(MyAppName, '&', '&&')}}"; \
  Flags: nowait postinstall skipifsilent

[Code]
// -------------------------------------------------------------------------
// PATH helpers — add/remove the bundled tool directories from the system
// PATH environment variable so that WifiTool.exe can call the tools by name.
// -------------------------------------------------------------------------

function NpcapNotInstalled: Boolean;
begin
  // Npcap places wpcap.dll in the Npcap sub-directory of System32.
  // If the file exists, Npcap is already installed — skip the installer
  // to avoid a kernel-driver reload and the associated restart prompt.
  Result := not FileExists(ExpandConstant('{sys}\Npcap\wpcap.dll'));
end;

function EnvAddPath(const NewDir: string): Boolean;
var
  OldPath: string;
begin
  RegQueryStringValue(HKEY_LOCAL_MACHINE,
    'SYSTEM\CurrentControlSet\Control\Session Manager\Environment',
    'Path', OldPath);
  // Only add if not already present (case-insensitive)
  if Pos(';' + Uppercase(NewDir) + ';',
         ';' + Uppercase(OldPath) + ';') = 0 then
  begin
    RegWriteExpandStringValue(HKEY_LOCAL_MACHINE,
      'SYSTEM\CurrentControlSet\Control\Session Manager\Environment',
      'Path', OldPath + ';' + NewDir);
    Result := True;
  end
  else
    Result := False;
end;

procedure EnvRemovePath(const Dir: string);
var
  OldPath, NewPath: string;
begin
  if not RegQueryStringValue(HKEY_LOCAL_MACHINE,
      'SYSTEM\CurrentControlSet\Control\Session Manager\Environment',
      'Path', OldPath) then
    Exit;
  NewPath := OldPath;
  // Remove ';Dir' variant
  StringChangeEx(NewPath, ';' + Dir, '', True);
  // Remove 'Dir;' variant (if it was at the start)
  StringChangeEx(NewPath, Dir + ';', '', True);
  if NewPath <> OldPath then
    RegWriteExpandStringValue(HKEY_LOCAL_MACHINE,
      'SYSTEM\CurrentControlSet\Control\Session Manager\Environment',
      'Path', NewPath);
end;

procedure CurStepChanged(CurStep: TSetupStep);
begin
  if CurStep = ssPostInstall then
  begin
    EnvAddPath(ExpandConstant('{app}\{#MyToolsSubdir}\aircrack-ng'));
    EnvAddPath(ExpandConstant('{app}\{#MyToolsSubdir}\hashcat'));
  end;
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
begin
  if CurUninstallStep = usPostUninstall then
  begin
    EnvRemovePath(ExpandConstant('{app}\{#MyToolsSubdir}\aircrack-ng'));
    EnvRemovePath(ExpandConstant('{app}\{#MyToolsSubdir}\hashcat'));
  end;
end;
