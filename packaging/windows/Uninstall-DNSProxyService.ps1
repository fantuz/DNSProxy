#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding()]
param([ValidatePattern('^[A-Za-z0-9_-]{1,64}$')][string]$ServiceName = 'DNSProxy')
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'ServiceFiles.ps1')
$program = Join-Path $env:ProgramFiles $ServiceName
$state = Join-Path $env:ProgramData $ServiceName
$record = Get-Content -LiteralPath (Join-Path $state 'installation.json') -Raw | ConvertFrom-Json
$service = Get-CimInstance Win32_Service -Filter "Name='$ServiceName'"
if ($record.SchemaVersion -ne 1 -or $record.ServiceName -ne $ServiceName -or
    $record.BinaryPath -ne (Join-Path $program 'dnsp-modern.exe') -or
    ($service -and ($service.PathName -ne $record.Command -or $service.StartName -ne 'NT AUTHORITY\LocalService'))) {
    throw 'Installation ownership check failed; no service or files were removed.'
}
# Adapter integration is added separately. Its state must be restored before removal.
if (Test-Path -LiteralPath (Join-Path $state 'dns-state.json')) {
    throw 'Restore DNS adapter configuration before uninstalling the service.'
}
if ($service) {
    Stop-Service $ServiceName
    (Get-Service $ServiceName).WaitForStatus('Stopped', [TimeSpan]::FromSeconds(15))
    & sc.exe delete $ServiceName
    if ($LASTEXITCODE) { throw "Service deletion failed: $LASTEXITCODE" }
}
# Files may still be held briefly while SCM releases the stopped process.
for ($attempt=0; $attempt -lt 20; $attempt++) {
    try { Remove-ServiceDirectory $program; break }
    catch { if ($attempt -eq 19) { throw }; Start-Sleep -Milliseconds 100 }
}
# Do not follow reparse points planted in the service-writable log directory.
Remove-ServiceDirectory $state
