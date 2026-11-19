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
AppVerName=DNSProxy {#AppVersion}
UninstallDisplayName=DNSProxy
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
#ifdef GuiBundleDir
OutputBaseFilename=dnsp-modern-{#AppVersion}-windows-{#TargetArch}-gui-setup
#else
OutputBaseFilename=dnsp-modern-{#AppVersion}-windows-{#TargetArch}-setup
#endif
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
WizardSizePercent=120
DisableProgramGroupPage=yes
DisableDirPage=yes
UsePreviousAppDir=yes
CloseApplications=yes
RestartApplications=no
SetupLogging=yes
LicenseFile={#BundleDir}\LICENSE
UninstallDisplayIcon={app}\bin\dnsp-modern.exe

#ifdef GuiBundleDir
[Types]
Name: "full"; Description: "Desktop interface and resolver"
Name: "compact"; Description: "Resolver only"
Name: "custom"; Description: "Custom installation"; Flags: iscustom

[Components]
Name: "core"; Description: "DNSProxy resolver and service utilities"; Types: full compact custom; Flags: fixed
Name: "gui"; Description: "Desktop interface with private Python/GTK runtime"; Types: full
#endif

[Files]
; The elevated setup uses its own trusted helpers before replacing program files.
Source: "{#BundleDir}\Setup-DNSProxy.ps1"; Flags: dontcopy
Source: "{#BundleDir}\Install-DNSProxyService.ps1"; Flags: dontcopy
Source: "{#BundleDir}\ServiceFiles.ps1"; Flags: dontcopy
Source: "{#BundleDir}\*"; DestDir: "{app}\bin"; Flags: ignoreversion recursesubdirs createallsubdirs
#ifdef GuiBundleDir
Source: "{#GuiBundleDir}\*"; DestDir: "{app}\gui"; Components: gui; Flags: ignoreversion recursesubdirs createallsubdirs
#endif

[Icons]
Name: "{group}\Start DNSProxy in a console"; Filename: "{app}\bin\Start-DNSProxy.cmd"; WorkingDir: "{app}\bin"; Check: ConsoleMode
Name: "{group}\Windows guide"; Filename: "{app}\bin\WINDOWS.md"
Name: "{group}\Windows Services"; Filename: "{sys}\mmc.exe"; Parameters: """{sys}\services.msc"""; Check: ServiceMode
Name: "{group}\Uninstall DNSProxy"; Filename: "{uninstallexe}"
#ifdef GuiBundleDir
Name: "{group}\DNSProxy desktop"; Filename: "{app}\gui\runtime\bin\pythonw.exe"; Parameters: "-I -B ""{app}\gui\app\gui-bootstrap.py"""; WorkingDir: "{app}\gui"; Components: gui

[Run]
Filename: "{app}\gui\runtime\bin\pythonw.exe"; Parameters: "-I -B ""{app}\gui\app\gui-bootstrap.py"""; Description: "Open DNSProxy desktop"; Flags: postinstall nowait skipifsilent runasoriginaluser; Components: gui
#endif

[InstallDelete]
Type: files; Name: "{group}\Start DNSProxy in a console.lnk"; Check: ServiceMode
Type: files; Name: "{group}\Windows Services.lnk"; Check: ConsoleMode
#ifdef GuiBundleDir
; These are installer-owned runtime/application trees, never per-user state.
Type: filesandordirs; Name: "{app}\gui\app"; Check: ReplaceGui
Type: filesandordirs; Name: "{app}\gui\runtime"; Check: ReplaceGui
Type: filesandordirs; Name: "{app}\gui\runtime-package-metadata"; Check: ReplaceGui
#endif

[Code]
var
  ServerPage: TInputOptionWizardPage;
  OptionsPage, MetricsPage: TInputQueryWizardPage;
  IPv6Box, AutoStartBox, StartNowBox: TNewCheckBox;
  ExistingService, Prepared, Applied: Boolean;
  SetupFailure: Integer;
  ConfigPath, ErrorPath: String;

function GuiSelected: Boolean;
begin
#ifdef GuiBundleDir
  Result := WizardIsComponentSelected('gui');
#else
  Result := False;
#endif
end;

function ReplaceGui: Boolean;
begin
  Result := GuiSelected and DirExists(ExpandConstant('{app}\gui'));
end;

function GuiProcessKind(Entry: Variant; const Prefix: String): Integer;
var
  Filename, ProcessName: String;
begin
  Result := 0;
  try
    if VarIsNull(Entry.ExecutablePath) then Exit;
    Filename := Entry.ExecutablePath;
    Filename := GetShortName(Filename);
    ProcessName := Entry.Name;
    ProcessName := Lowercase(ProcessName);
  except
    { A process may exit between the WMI snapshot and property access. }
    Exit;
  end;
  if CompareText(Copy(Filename, 1, Length(Prefix)), Prefix) <> 0 then Exit;
  if (ProcessName = 'gdbus.exe') or (ProcessName = 'dbus-daemon.exe') then Result := 2
  else Result := 1;
end;

function CloseGuiRuntime(StopHelpers: Boolean): String;
var
  Locator, Services, Processes, Entry: Variant;
  Index, Status: Integer;
  Prefix: String;
begin
  Result := '';
  Prefix := AddBackslash(GetShortName(ExpandConstant('{app}\gui\runtime')));
  if not DirExists(ExpandConstant('{app}\gui\runtime')) then Exit;
  try
    Locator := CreateOleObject('WbemScripting.SWbemLocator');
    Services := Locator.ConnectServer('', 'root\CIMV2');
    Processes := Services.ExecQuery('SELECT * FROM Win32_Process');
    for Index := 0 to Processes.Count - 1 do
    begin
      Entry := Processes.ItemIndex(Index);
      if GuiProcessKind(Entry, Prefix) = 1 then
      begin
        Result := 'Close DNSProxy desktop and utilities using its private runtime before continuing.';
        Exit;
      end;
    end;
    if not StopHelpers then Exit;
    { Only orphan helpers belonging to this installed runtime may be stopped. }
    for Index := 0 to Processes.Count - 1 do
    begin
      Entry := Processes.ItemIndex(Index);
      if GuiProcessKind(Entry, Prefix) = 2 then
      begin
        Status := Entry.Terminate(0);
        if (Status <> 0) and (Status <> 9) then
        begin
          Result := 'Close the private GTK background helpers and retry.';
          Exit;
        end;
        Sleep(100);
      end;
    end;
  except
    Result := 'Could not verify whether the private desktop runtime is in use. Close desktop processes and retry. ' + GetExceptionMessage;
  end;
end;

function ServiceMode: Boolean;
begin
  Result := ServerPage.Values[0];
end;

function ConsoleMode: Boolean;
begin
  Result := not ServiceMode;
end;

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
  SetArrayLength(Lines, 8);
  Lines[0] := 'Service=' + Flag(ServerPage.Values[0]);
  Lines[1] := 'Port=' + OptionsPage.Values[0];
  Lines[2] := 'Upstream=' + OptionsPage.Values[1];
  Lines[3] := 'BootstrapAddress=' + OptionsPage.Values[2];
  Lines[4] := 'IPv6=' + Flag(IPv6Box.Checked);
  Lines[5] := 'AutoStart=' + Flag(AutoStartBox.Checked);
  Lines[6] := 'StartNow=' + Flag(StartNowBox.Checked);
  Lines[7] := 'MetricsPort=' + MetricsPage.Values[0];
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
    Log('Service helper ' + Action + ' failed: ' + Result);
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
#ifdef GuiBundleDir
  ServerPage := CreateInputOptionPage(wpSelectComponents, 'Windows service',
#else
  ServerPage := CreateInputOptionPage(wpLicense, 'Windows service',
#endif
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
  MetricsPage := CreateInputQueryPage(OptionsPage.ID, 'Local traffic monitoring',
    'Choose whether desktop monitoring can read this service.',
    'Metrics are read-only and listen only on 127.0.0.1. Use 0 to disable monitoring. Existing service settings are retained on upgrade.');
  MetricsPage.Add('Loopback metrics port (0 disables):', False);
#ifdef GuiBundleDir
  MetricsPage.Values[0] := ExpandConstant('{param:METRICSPORT|9090}');
#else
  MetricsPage.Values[0] := ExpandConstant('{param:METRICSPORT|0}');
#endif
end;

function ShouldSkipPage(PageID: Integer): Boolean;
begin
  Result := ((PageID = OptionsPage.ID) or (PageID = MetricsPage.ID)) and
    (ExistingService or not ServerPage.Values[0]);
end;

function NextButtonClick(CurPageID: Integer): Boolean;
var
  Error: String;
begin
  Result := True;
  if ((CurPageID = OptionsPage.ID) or (CurPageID = MetricsPage.ID)) and ServerPage.Values[0] and not ExistingService then
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
  if DirExists(ExpandConstant('{app}\gui')) and not GuiSelected then
  begin
    Result := 'This installation includes the desktop interface. Use the GUI setup with its desktop component selected, or uninstall it through Windows Apps first.';
    Exit;
  end;
  Result := CloseGuiRuntime(False);
  if Result <> '' then Exit;
  WriteOptions;
  Prepared := True;
  Result := RunHelper('Prepare', ExpandConstant('{tmp}\Setup-DNSProxy.ps1'));
  if Result = '' then Result := CloseGuiRuntime(True);
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
      SuppressibleMsgBox(Error, mbError, MB_OK, IDOK);
      Exit;
    end;
    Applied := True;
  end;
end;

procedure CurPageChanged(CurPageID: Integer);
begin
  if (CurPageID = wpFinished) and (SetupFailure <> 0) then
    WizardForm.FinishedLabel.Caption := 'DNSProxy program files were installed, but Windows service setup failed. ' +
      'Review the error and setup log, then rerun setup or remove DNSProxy through Windows Apps.';
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
  Error := CloseGuiRuntime(False);
  if Error <> '' then
  begin
    SuppressibleMsgBox(Error, mbError, MB_OK, IDOK);
    Result := False;
    Exit;
  end;
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
    Error := CloseGuiRuntime(True);
    if Error <> '' then
    begin
      SuppressibleMsgBox(Error, mbError, MB_OK, IDOK);
      Abort;
    end;
    Error := RunHelper('Remove', ExpandConstant('{app}\bin\Setup-DNSProxy.ps1'));
    if Error <> '' then
    begin
      SuppressibleMsgBox(Error, mbError, MB_OK, IDOK);
      Abort;
    end;
  end;
end;
