[Setup]
AppId=AI.Unlocker
AppName=AI Unlocker
AppVersion={#AppVersion}
AppPublisher=Brent
DefaultDirName={localappdata}\Programs\AI Unlocker
DisableDirPage=yes
UsePreviousAppDir=no
DisableProgramGroupPage=yes
UsePreviousTasks=yes
LicenseFile=LICENSE
PrivilegesRequired=lowest
ArchitecturesAllowed=x64compatible
MinVersion=10.0
OutputDir={#BuildOutput}
OutputBaseFilename=setup
SetupIconFile=icon.ico
UninstallDisplayIcon={app}\ag_unlocker.exe
VersionInfoDescription=AI Unlocker Setup
VersionInfoVersion={#AppVersion}
CloseApplications=yes
CloseApplicationsFilter=ag_unlocker.exe
RestartApplications=no
SetupMutex=AI.Unlocker.Setup
WizardStyle=modern

[Languages]
Name: "russian"; MessagesFile: "compiler:Languages\Russian.isl"
Name: "english"; MessagesFile: "compiler:Default.isl"

[CustomMessages]
russian.LaunchAfterSetup=Запустить AI Unlocker после установки
english.LaunchAfterSetup=Launch AI Unlocker after installation
russian.ViewLicense=Открыть текст лицензии на GitHub
english.ViewLicense=View license on GitHub
russian.CreateDesktopShortcut=Создать ярлык на рабочем столе
english.CreateDesktopShortcut=Create a desktop shortcut

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopShortcut}"; GroupDescription: "{cm:AdditionalIcons}"

[Files]
Source: "{#AppExecutable}"; DestDir: "{app}"; DestName: "ag_unlocker.exe"; Flags: ignoreversion nocompression

[Icons]
Name: "{userprograms}\AI Unlocker"; Filename: "{app}\ag_unlocker.exe"; WorkingDir: "{app}"

Name: "{userdesktop}\AI Unlocker"; Filename: "{app}\ag_unlocker.exe"; WorkingDir: "{app}"; Tasks: desktopicon

[Run]
Filename: "{app}\ag_unlocker.exe"; Parameters: "--updated"; Description: "{cm:LaunchAfterSetup}"; Flags: postinstall nowait skipifsilent runasoriginaluser

[Code]
procedure OpenLicense(Sender: TObject; const Link: string; LinkType: TSysLinkType);
var
  ResultCode: Integer;
begin
  ShellExecAsOriginalUser('open', 'https://github.com/confeden/Antigravity/blob/main/LICENSE',
                          '', '', SW_SHOWNORMAL, ewNoWait, ResultCode);
end;

procedure InitializeWizard();
var
  LicenseLink: TNewLinkLabel;
  LinkSpace: Integer;
begin
  LicenseLink := TNewLinkLabel.Create(WizardForm);
  LicenseLink.Parent := WizardForm.LicenseMemo.Parent;
  LinkSpace := ScaleY(22);
  LicenseLink.SetBounds(WizardForm.LicenseMemo.Left, WizardForm.LicenseMemo.Top,
                        WizardForm.LicenseMemo.Width, LinkSpace);
  LicenseLink.Caption := '<a id="license">' + ExpandConstant('{cm:ViewLicense}') + '</a>';
  LicenseLink.OnLinkClick := @OpenLicense;
  WizardForm.LicenseMemo.Top := WizardForm.LicenseMemo.Top + LinkSpace;
  WizardForm.LicenseMemo.Height := WizardForm.LicenseMemo.Height - LinkSpace;
end;

function ManagedStartupShortcut(): Boolean;
var
  Name: String;
  Shell, Link: Variant;
begin
  Result := False;
  Name := ExpandConstant('{userstartup}\AI Unlocker.lnk');
  if not FileExists(Name) then Exit;
  Shell := CreateOleObject('WScript.Shell');
  Link := Shell.CreateShortcut(Name);
  Result := Link.Description = 'AI Unlocker (startup)';
end;

procedure CurStepChanged(Step: TSetupStep);
var
  Shell, Link: Variant;
begin
  if Step <> ssPostInstall then Exit;
  if not ManagedStartupShortcut() then Exit;
  Shell := CreateOleObject('WScript.Shell');
  Link := Shell.CreateShortcut(ExpandConstant('{userstartup}\AI Unlocker.lnk'));
  Link.TargetPath := ExpandConstant('{app}\ag_unlocker.exe');
  Link.WorkingDirectory := ExpandConstant('{app}');
  Link.Save;
end;

function InitializeUninstall(): Boolean;
var
  ExitCode: Integer;
begin
  Result := True;
  if not FileExists(ExpandConstant('{localappdata}\AGUnlocker\paid-proxy-enabled')) then Exit;
  if not ShellExec('runas', ExpandConstant('{app}\ag_unlocker.exe'), '--clear-paid-mode',
                   '', SW_HIDE, ewWaitUntilTerminated, ExitCode) then Result := False
  else Result := ExitCode = 0;
  if not Result then
    MsgBox('Let AI Unlocker disable paid routing before uninstalling.',
           mbError, MB_OK);
end;

procedure CurUninstallStepChanged(Step: TUninstallStep);
begin
  if Step <> usUninstall then Exit;
  if ManagedStartupShortcut() then
    if not DeleteFile(ExpandConstant('{userstartup}\AI Unlocker.lnk')) then
      Log('Could not remove the AI Unlocker startup shortcut');
end;
