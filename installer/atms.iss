; ATMS — AI Threat Modeling Studio
; Inno Setup script
;
; Builds a single ATMS-Setup-X.Y.Z.exe that the end user double-clicks. The
; wizard installs the portable atms.exe into Program Files, drops Start Menu
; and (optional) Desktop shortcuts, optionally adds the install directory to
; the user's PATH, and registers an uninstaller in Add/Remove Programs.
;
; Built from the repo root via `python scripts/build_installer.py` which
; first runs PyInstaller to produce dist\atms.exe, then invokes ISCC.exe
; on this script.
;
; Tested with Inno Setup 6.x.

#define MyAppName "AI Threat Modeling Studio"
#define MyAppShortName "ATMS"
; v0.14.5: hard-error if the build script forgot to pass the version.
; Previously fell back to "0.5.0" — silently shipped mislabeled
; installers when the build pipeline broke. Better to fail loudly.
#ifndef MyAppVersion
  #error "MyAppVersion not defined. Pass /DMyAppVersion=X.Y.Z to ISCC (build_installer.py does this automatically)."
#endif
#define MyAppPublisher "anguiz7z"
#define MyAppURL "https://github.com/anguiz7z/AITMS"
#define MyAppExeName "atms.exe"

[Setup]
AppId={{C7FBE0F2-9D31-4F37-9DCD-AC7A1A8A2A21}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppVerName={#MyAppName} {#MyAppVersion}
AppPublisher={#MyAppPublisher}
AppPublisherURL={#MyAppURL}
AppSupportURL={#MyAppURL}/issues
AppUpdatesURL={#MyAppURL}/releases
DefaultDirName={autopf}\ATMS
DefaultGroupName=ATMS
DisableProgramGroupPage=yes
LicenseFile=..\LICENSE
OutputDir=..\dist
OutputBaseFilename=ATMS-Setup-{#MyAppVersion}
SetupIconFile=
Compression=lzma2/ultra64
SolidCompression=yes
WizardStyle=modern
PrivilegesRequired=lowest
PrivilegesRequiredOverridesAllowed=dialog
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
MinVersion=10.0.17763
UninstallDisplayName={#MyAppName} {#MyAppVersion}
UninstallDisplayIcon={app}\{#MyAppExeName}
ChangesEnvironment=yes
DisableWelcomePage=no

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "Create a &Desktop shortcut"; GroupDescription: "Additional shortcuts:"; Flags: unchecked
Name: "addtopath"; Description: "Add ATMS to my PATH (lets me run 'atms' from any terminal)"; GroupDescription: "Convenience:"; Flags: unchecked

[Files]
Source: "..\dist\{#MyAppExeName}"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\samples\*.yaml"; DestDir: "{app}\samples"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "..\samples\test_diagram.vsdx"; DestDir: "{app}\samples"; Flags: ignoreversion
Source: "..\README.md"; DestDir: "{app}"; Flags: ignoreversion isreadme
Source: "..\USAGE.md"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\AI_DEPENDENCIES.md"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\LICENSE"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\CHANGELOG.md"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{group}\ATMS Web UI"; Filename: "{app}\{#MyAppExeName}"; Parameters: "web"; Comment: "Launches the ATMS local web UI on http://127.0.0.1:8765"
Name: "{group}\ATMS Command Prompt"; Filename: "{cmd}"; Parameters: "/K cd /D ""{app}"" && echo Type 'atms.exe ^<command^>' to run ATMS. Try 'atms.exe --help' or 'atms.exe selftest'."
Name: "{group}\Documentation (README)"; Filename: "{app}\README.md"
Name: "{group}\Open Samples Folder"; Filename: "{app}\samples"
Name: "{group}\Uninstall ATMS"; Filename: "{uninstallexe}"
Name: "{autodesktop}\ATMS Web UI"; Filename: "{app}\{#MyAppExeName}"; Parameters: "web"; Tasks: desktopicon

[Run]
Filename: "{app}\{#MyAppExeName}"; Parameters: "selftest"; Description: "Run a self-test (verifies the installation)"; Flags: postinstall nowait skipifsilent runascurrentuser
Filename: "{app}\{#MyAppExeName}"; Parameters: "web"; Description: "Launch ATMS Web UI now"; Flags: postinstall nowait skipifsilent runascurrentuser unchecked

[Code]
const
  EnvironmentKey = 'Environment';

procedure EnvAddPath(Path: string);
var
  Paths: string;
begin
  if not RegQueryStringValue(HKEY_CURRENT_USER, EnvironmentKey, 'Path', Paths) then
    Paths := '';
  if (Pos(';' + Uppercase(Path) + ';', ';' + Uppercase(Paths) + ';') > 0) then
    exit;
  if (Length(Paths) > 0) and (Paths[Length(Paths)] <> ';') then
    Paths := Paths + ';';
  Paths := Paths + Path;
  RegWriteStringValue(HKEY_CURRENT_USER, EnvironmentKey, 'Path', Paths);
end;

procedure EnvRemovePath(Path: string);
var
  Paths: string;
  P: Integer;
begin
  if not RegQueryStringValue(HKEY_CURRENT_USER, EnvironmentKey, 'Path', Paths) then
    exit;
  P := Pos(';' + Uppercase(Path) + ';', ';' + Uppercase(Paths) + ';');
  if P = 0 then
    exit;
  // Remove the segment from Paths
  Delete(Paths, P, Length(Path) + 1);
  RegWriteStringValue(HKEY_CURRENT_USER, EnvironmentKey, 'Path', Paths);
end;

procedure CurStepChanged(CurStep: TSetupStep);
begin
  if CurStep = ssPostInstall then begin
    if WizardIsTaskSelected('addtopath') then
      EnvAddPath(ExpandConstant('{app}'));
  end;
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
begin
  if CurUninstallStep = usPostUninstall then
    EnvRemovePath(ExpandConstant('{app}'));
end;
