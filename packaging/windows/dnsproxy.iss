#ifndef BundleDir
  #error BundleDir is required
#endif
#ifndef AppVersion
  #error AppVersion is required
#endif
#ifndef OutputDir
  #error OutputDir is required
#endif
#ifndef TargetArch
  #error TargetArch is required
#endif

[Setup]
AppId={{439B9015-B446-4C7E-95F1-923143B86B53}
AppName=DNSProxy
AppVersion={#AppVersion}
VersionInfoVersion={#AppVersion}.0
AppPublisher=DNSProxy contributors
AppPublisherURL=https://github.com/fantuz/DNSProxy
AppSupportURL=https://github.com/fantuz/DNSProxy/issues
DefaultDirName={autopf}\DNSProxy
DefaultGroupName=DNSProxy
PrivilegesRequired=admin
#if TargetArch == "arm64"
ArchitecturesAllowed=arm64
ArchitecturesInstallIn64BitMode=arm64
MinVersion=10.0.22000
#else
ArchitecturesAllowed=x64os
ArchitecturesInstallIn64BitMode=x64os
MinVersion=10.0
#endif
OutputDir={#OutputDir}
OutputBaseFilename=dnsp-modern-{#AppVersion}-windows-{#TargetArch}-setup
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
WizardSizePercent=120
DisableProgramGroupPage=yes
DisableDirPage=yes
UsePreviousAppDir=yes
CloseApplications=yes
RestartApplications=no
LicenseFile={#BundleDir}\LICENSE
UninstallDisplayIcon={app}\bin\dnsp-modern.exe

[Files]
; The elevated setup uses its own trusted helpers before replacing program files.
Source: "{#BundleDir}\Setup-DNSProxy.ps1"; Flags: dontcopy
Source: "{#BundleDir}\Install-DNSProxyService.ps1"; Flags: dontcopy
Source: "{#BundleDir}\ServiceFiles.ps1"; Flags: dontcopy
Source: "{#BundleDir}\*"; DestDir: "{app}\bin"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{group}\Start DNSProxy in a console"; Filename: "{app}\bin\Start-DNSProxy.cmd"; WorkingDir: "{app}\bin"
Name: "{group}\Windows guide"; Filename: "{app}\bin\WINDOWS.md"
Name: "{group}\Windows Services"; Filename: "{sys}\mmc.exe"; Parameters: """{sys}\services.msc"""
Name: "{group}\Uninstall DNSProxy"; Filename: "{uninstallexe}"

[Code]
var
  ServerPage: TInputOptionWizardPage;
  OptionsPage: TInputQueryWizardPage;
  IPv6Box, AutoStartBox, StartNowBox: TNewCheckBox;
  ExistingService, Prepared, Applied: Boolean;
  SetupFailure: Integer;
  ConfigPath, ErrorPath: String;

function SelectedParameter(const Name, Default: String): Boolean;
var
  Value: String;
begin
  Value := ExpandConstant('{param:' + Name + '|' + Default + '}');
  if (Value <> '0') and (Value <> '1') then RaiseException('Use 0 or 1 for /' + Name + '.');
  Result := Value = '1';
end;

function Flag(Value: Boolean): String;
begin
  if Value then Result := '1' else Result := '0';
end;

procedure WriteOptions;
var
  Lines: TArrayOfString;
begin
  SetArrayLength(Lines, 7);
  Lines[0] := 'Service=' + Flag(ServerPage.Values[0]);
  Lines[1] := 'Port=' + OptionsPage.Values[0];
  Lines[2] := 'Upstream=' + OptionsPage.Values[1];
  Lines[3] := 'BootstrapAddress=' + OptionsPage.Values[2];
  Lines[4] := 'IPv6=' + Flag(IPv6Box.Checked);
  Lines[5] := 'AutoStart=' + Flag(AutoStartBox.Checked);
  Lines[6] := 'StartNow=' + Flag(StartNowBox.Checked);
  if not SaveStringsToUTF8File(ConfigPath, Lines, False) then
    RaiseException('Cannot write setup options.');
end;

function RunHelper(const Action, Script: String): String;
var
  ExitCode: Integer;
  ErrorText: AnsiString;
  Parameters: String;
begin
  Result := '';
  DeleteFile(ErrorPath);
  Parameters := '-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "' + Script +
    '" -Action ' + Action + ' -ResultFile "' + ErrorPath + '"';
  if ConfigPath <> '' then Parameters := Parameters + ' -ConfigFile "' + ConfigPath + '"';
  if not Exec(ExpandConstant('{sys}\WindowsPowerShell\v1.0\powershell.exe'), Parameters,
      '', SW_HIDE, ewWaitUntilTerminated, ExitCode) then
    Result := 'Windows PowerShell could not be started.'
  else if ExitCode <> 0 then
  begin
    if LoadStringFromFile(ErrorPath, ErrorText) then Result := String(ErrorText)
    else Result := 'Service setup failed. Review the setup log and Windows Services.';
  end;
end;

procedure InitializeWizard;
begin
  ConfigPath := ExpandConstant('{tmp}\dnsproxy-options.ini');
  ErrorPath := ExpandConstant('{tmp}\dnsproxy-error.txt');
  ExtractTemporaryFile('Setup-DNSProxy.ps1');
  ExtractTemporaryFile('Install-DNSProxyService.ps1');
  ExtractTemporaryFile('ServiceFiles.ps1');
  ExistingService := RegKeyExists(HKLM64, 'SYSTEM\CurrentControlSet\Services\DNSProxy') and
    FileExists(ExpandConstant('{commonappdata}\DNSProxy\installation.json'));
  ServerPage := CreateInputOptionPage(wpLicense, 'Windows service',
    'Choose how to run DNSProxy.',
    'The application and Start Menu shortcuts are always installed. The optional service runs in the background. ' +
    'Adapter DNS settings remain unchanged. Test the resolver before pointing Windows at it.', False, False);
  ServerPage.Add('Register DNSProxy as a Windows service');
  ServerPage.Values[0] := ExistingService or SelectedParameter('SERVICE', '0');
  if ExistingService then
  begin
    ServerPage.CheckListBox.Enabled := False;
    ServerPage.SubCaptionLabel.Caption := 'The existing service and its configuration will be retained.';
  end;
  OptionsPage := CreateInputQueryPage(ServerPage.ID, 'Service options',
    'Configure the local DNS server.',
    'Listeners are local only. The bootstrap IP must belong to the selected HTTPS provider.');
  OptionsPage.Add('DNS port:', False);
  OptionsPage.Add('HTTPS upstream URL:', False);
  OptionsPage.Add('Numeric bootstrap IP:', False);
  OptionsPage.Values[0] := ExpandConstant('{param:PORT|53}');
  OptionsPage.Values[1] := ExpandConstant('{param:UPSTREAM|https://cloudflare-dns.com/dns-query}');
  OptionsPage.Values[2] := ExpandConstant('{param:BOOTSTRAP|1.1.1.1}');
  IPv6Box := TNewCheckBox.Create(WizardForm);
  IPv6Box.Parent := OptionsPage.Surface;
  IPv6Box.SetBounds(0, OptionsPage.Edits[2].Top + OptionsPage.Edits[2].Height + ScaleY(12), OptionsPage.SurfaceWidth, ScaleY(20));
  IPv6Box.Caption := 'Also listen on IPv6 loopback (::1)';
  IPv6Box.Checked := SelectedParameter('IPV6', '1');
  AutoStartBox := TNewCheckBox.Create(WizardForm);
  AutoStartBox.Parent := OptionsPage.Surface;
  AutoStartBox.SetBounds(0, IPv6Box.Top + ScaleY(25), OptionsPage.SurfaceWidth, ScaleY(20));
  AutoStartBox.Caption := 'Start automatically with Windows';
  AutoStartBox.Checked := SelectedParameter('AUTOSTART', '1');
  StartNowBox := TNewCheckBox.Create(WizardForm);
  StartNowBox.Parent := OptionsPage.Surface;
  StartNowBox.SetBounds(0, AutoStartBox.Top + ScaleY(25), OptionsPage.SurfaceWidth, ScaleY(20));
  StartNowBox.Caption := 'Start the service after installation';
  StartNowBox.Checked := SelectedParameter('STARTNOW', '1');
end;

function ShouldSkipPage(PageID: Integer): Boolean;
begin
  Result := (PageID = OptionsPage.ID) and (ExistingService or not ServerPage.Values[0]);
end;

function NextButtonClick(CurPageID: Integer): Boolean;
var
  Error: String;
begin
  Result := True;
  if (CurPageID = OptionsPage.ID) and ServerPage.Values[0] and not ExistingService then
  begin
    WriteOptions;
    Error := RunHelper('Validate', ExpandConstant('{tmp}\Setup-DNSProxy.ps1'));
    if Error <> '' then
    begin
      SuppressibleMsgBox(Error, mbError, MB_OK, IDOK);
      Result := False;
    end;
  end;
end;

function PrepareToInstall(var NeedsRestart: Boolean): String;
begin
  Result := '';
  if CompareText(RemoveBackslashUnlessRoot(ExpandFileName(WizardDirValue)),
      ExpandConstant('{autopf}\DNSProxy')) <> 0 then
  begin
    Result := 'Install DNSProxy in the protected default Program Files folder.';
    Exit;
  end;
  WriteOptions;
  Prepared := True;
  Result := RunHelper('Prepare', ExpandConstant('{tmp}\Setup-DNSProxy.ps1'));
end;

procedure CurStepChanged(CurStep: TSetupStep);
var
  Error: String;
begin
  if CurStep = ssPostInstall then
  begin
    Error := RunHelper('Apply', ExpandConstant('{tmp}\Setup-DNSProxy.ps1'));
    if Error <> '' then
    begin
      SetupFailure := 1;
      RaiseException(Error);
    end;
    Applied := True;
  end;
end;

procedure DeinitializeSetup;
var
  Error: String;
begin
  if Prepared and not Applied then
  begin
    Error := RunHelper('Resume', ExpandConstant('{tmp}\Setup-DNSProxy.ps1'));
    if Error <> '' then Log('Service recovery needs attention: ' + Error);
  end;
end;

function GetCustomSetupExitCode: Integer;
begin
  Result := SetupFailure;
end;

function InitializeUninstall: Boolean;
var
  Error: String;
begin
  ConfigPath := '';
  ErrorPath := ExpandConstant('{tmp}\dnsproxy-uninstall-error.txt');
  Error := RunHelper('CheckRemove', ExpandConstant('{app}\bin\Setup-DNSProxy.ps1'));
  Result := Error = '';
  if not Result then SuppressibleMsgBox(Error, mbError, MB_OK, IDOK);
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
var
  Error: String;
begin
  if CurUninstallStep = usUninstall then
  begin
    Error := RunHelper('Remove', ExpandConstant('{app}\bin\Setup-DNSProxy.ps1'));
    if Error <> '' then RaiseException(Error);
  end;
end;
