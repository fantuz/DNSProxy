#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='Medium')]
param(
    [ValidateSet('Enable','Restore','Status','Recover')][string]$Action = 'Status',
    [ValidatePattern('^[A-Za-z0-9_-]{1,64}$')][string]$ServiceName = 'DNSProxy',
    [Guid[]]$AdapterGuid = @()
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'DNSProxyDns.psm1') -Force
$stateDirectory = Join-Path $env:ProgramData $ServiceName
$statePath = Join-Path $stateDirectory 'dns-state.json'
$program = Join-Path $env:ProgramFiles $ServiceName
$installedScript = Join-Path $program 'Set-DNSProxyDns.ps1'
$taskName = "$ServiceName-DNS-Recovery"
$taskExe = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
$taskArguments = '-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "{0}" -Action Recover -ServiceName {1}' -f $installedScript,$ServiceName
$record = Get-Content -LiteralPath (Join-Path $stateDirectory 'installation.json') -Raw | ConvertFrom-Json
if ($record.SchemaVersion -ne 1 -or $record.ServiceName -ne $ServiceName -or
    $record.BinaryPath -ne (Join-Path $program 'dnsp-modern.exe')) { throw 'Service installation ownership check failed.' }
if (-not (Test-Path -LiteralPath $installedScript)) { throw 'Reinstall the service using a bundle that includes DNS integration.' }

function Find-Adapter([string]$Guid) {
    $matches = @(Get-NetAdapter -IncludeHidden | Where-Object { $_.InterfaceGuid -eq [Guid]$Guid })
    if ($matches.Count -ne 1) { throw "Adapter $Guid is absent; reconnect it and retry restoration." }
    return $matches[0]
}

function Read-AdapterDns([string]$Guid, [string]$Family) {
    $adapter = Find-Adapter $Guid
    $protocol = if ($Family -eq 'IPv4') { 'Tcpip' } else { 'Tcpip6' }
    $key = "HKLM:\SYSTEM\CurrentControlSet\Services\$protocol\Parameters\Interfaces\{$Guid}"
    if (-not (Test-Path -LiteralPath $key)) { throw "Missing $Family configuration for adapter $Guid." }
    # Get-DnsClientServerAddress returns effective servers, including DHCP/RA.
    # Snapshot the configured NameServer separately so automatic mode is restored
    # as automatic, rather than pinning today's DHCP/RA addresses permanently.
    $value = (Get-Item -LiteralPath $key).GetValue('NameServer', '')
    if ($value -isnot [string]) { throw 'Unsupported DNS registry representation.' }
    $servers = @($value -split '[,;\s]+' | Where-Object { $_ })
    foreach ($server in $servers) { $null = [Net.IPAddress]::Parse($server) }
    $effective = @(Get-DnsClientServerAddress -InterfaceIndex $adapter.ifIndex -AddressFamily $Family).ServerAddresses
    if ($servers.Count -and (@($effective) -join ',') -ne ($servers -join ',')) {
        throw "Configured and effective $Family DNS disagree; check policy/profile management."
    }
    return @{Mode=$(if ($servers.Count) {'Static'} else {'Automatic'}); Servers=$servers}
}

function Write-AdapterDns([string]$Guid, [string]$Family, $Setting) {
    $adapter = Find-Adapter $Guid
    $inputObject = Get-DnsClientServerAddress -InterfaceIndex $adapter.ifIndex -AddressFamily $Family
    if ($Setting.Mode -eq 'Automatic') { $inputObject | Set-DnsClientServerAddress -ResetServerAddresses }
    else { $inputObject | Set-DnsClientServerAddress -ServerAddresses @($Setting.Servers) }
}

function Test-Resolver {
    $service = Get-CimInstance Win32_Service -Filter "Name='$ServiceName'"
    if (-not $service -or $service.State -ne 'Running' -or $service.PathName -ne $record.Command -or
        $service.StartMode -ne 'Auto' -or $service.StartName -ne 'NT AUTHORITY\LocalService' -or
        $record.Port -ne 53 -or '127.0.0.1' -notin $record.ListenAddress -or '::1' -notin $record.ListenAddress) {
        throw 'Enable DNS only with the owned automatic service running on both loopback addresses, port 53.'
    }
    $null = [Net.IPAddress]::Parse($record.BootstrapAddress)
    foreach ($server in @('127.0.0.1','::1')) {
        $null = Resolve-DnsName example.com -Type A -Server $server -DnsOnly -NoHostsFile -QuickTimeout
        $null = Resolve-DnsName example.com -Type A -Server $server -DnsOnly -NoHostsFile -QuickTimeout -TcpOnly
    }
}

$backend = @{
    Read = { param($g,$f) Read-AdapterDns $g $f }
    Write = { param($g,$f,$s) Write-AdapterDns $g $f $s }
    Health = { Test-Resolver }
    Arm = {
        if (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue) { throw 'Recovery task already exists; inspect it before proceeding.' }
        $job = New-ScheduledTaskAction -Execute $taskExe -Argument $taskArguments
        $timer = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(2) -RepetitionInterval (New-TimeSpan -Minutes 1)
        $boot = New-ScheduledTaskTrigger -AtStartup
        $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
        $settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -ExecutionTimeLimit (New-TimeSpan -Minutes 1) -MultipleInstances IgnoreNew -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
        $null = Register-ScheduledTask -TaskName $taskName -Action $job -Trigger @($timer,$boot) -Principal $principal -Settings $settings
    }
    Disarm = {
        $existing = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
        if ($existing) {
            if (@($existing.Actions).Count -ne 1 -or $existing.Actions[0].Execute -ne $taskExe -or
                $existing.Actions[0].Arguments -ne $taskArguments) { throw 'Recovery task ownership check failed.' }
            Unregister-ScheduledTask -TaskName $taskName -Confirm:$false
        }
    }
}

if ($Action -eq 'Status') {
    Get-NetAdapter -Physical | Select-Object Name,InterfaceGuid,Status
    if (Test-Path -LiteralPath $statePath) { Read-DnsState $statePath | ConvertTo-Json -Depth 12 }
    else { Write-Output 'No DNSProxy adapter configuration is active.' }
    return
}
if ($Action -eq 'Recover' -and (Test-Path -LiteralPath $statePath)) {
    $pending = Read-DnsState $statePath
    if ($pending.Phase -eq 'Active') { return }
    if ([DateTime]::UtcNow -lt [DateTime]::Parse($pending.Deadline).ToUniversalTime()) { return }
}
if (-not $PSCmdlet.ShouldProcess($ServiceName, "$Action DNS configuration for selected adapters")) { return }
# Serialize configuration and recovery. A repeating watchdog retries a busy lock;
# termination/reboot releases it, while the durable Pending record remains.
$lock = $null
try {
    $lock = [IO.File]::Open((Join-Path $stateDirectory 'dns.lock'), 'OpenOrCreate', 'ReadWrite', 'None')
    if ($Action -eq 'Recover' -and (Test-Path -LiteralPath $statePath)) {
        if ((Read-DnsState $statePath).Phase -eq 'Active') { return }
    }
    if ($Action -in @('Restore','Recover')) {
        if ($Action -eq 'Restore' -and (Test-Path -LiteralPath $statePath) -and
            -not (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue)) { & $backend.Arm }
        Restore-DnsTransaction $statePath $backend
        return
    }
    if (-not $AdapterGuid.Count) { throw 'Use -Action Status to list adapters, then explicitly select -AdapterGuid.' }
    if (@(Get-DnsClientNrptPolicy -Effective).Count) { throw 'NRPT policy is present; automatic integration is not supported.' }
    if ((Get-CimInstance Win32_ComputerSystem).PartOfDomain) { throw 'Domain-managed hosts require manual DNS integration.' }
    foreach ($protocol in @('Tcpip','Tcpip6')) {
        $global = Get-Item "HKLM:\SYSTEM\CurrentControlSet\Services\$protocol\Parameters"
        if ($global.GetValue('NameServer','')) { throw 'Global DNS settings require manual integration.' }
    }
    foreach ($guid in $AdapterGuid) {
        $adapter = Find-Adapter $guid.ToString()
        if (-not $adapter.HardwareInterface -or $adapter.Status -ne 'Up' -or $adapter.MediaType -notin @('802.3','Native 802.11')) {
            throw 'Only connected physical Ethernet/Wi-Fi adapters are supported; VPNs and virtual adapters require manual setup.'
        }
        if (-not (Get-NetAdapterBinding -Name $adapter.Name -ComponentID ms_tcpip).Enabled -or
            -not (Get-NetAdapterBinding -Name $adapter.Name -ComponentID ms_tcpip6).Enabled) {
            throw 'Both IPv4 and IPv6 bindings must be enabled for automatic integration.'
        }
    }
    Enable-DnsTransaction $statePath @($AdapterGuid | ForEach-Object { $_.ToString() }) $backend
} finally { if ($lock) { $lock.Dispose() } }
