#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][ValidateSet('Validate','Prepare','Apply','Resume','CheckRemove','Remove')][string]$Action,
    [string]$ConfigFile = '',
    [string]$ResultFile = ''
)
$ErrorActionPreference = 'Stop'
# Use OS-known protected folders and native tools, never caller-supplied
# ProgramFiles/ProgramData/PATH values at this elevated installer boundary.
$env:ProgramFiles = [Environment]::GetFolderPath('ProgramFiles')
$env:ProgramData = [Environment]::GetFolderPath('CommonApplicationData')
$env:SystemRoot = [Environment]::GetFolderPath('Windows')
$env:Path = (Join-Path $env:SystemRoot 'System32') + ';' + $env:SystemRoot
# Setup may be launched from PowerShell 7. Windows PowerShell must load its own
# built-in management modules, rather than inherit incompatible pwsh assemblies.
$env:PSModulePath = "$PSHOME\Modules;" + [Environment]::GetEnvironmentVariable('PSModulePath', 'Machine')
$app = Join-Path $env:ProgramFiles 'DNSProxy'
$bin = Join-Path $app 'bin'
$state = Join-Path $env:ProgramData 'DNSProxy'
$recordPath = Join-Path $state 'installation.json'
$resumePath = Join-Path $state 'setup-resume.json'
$uninstallKey = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\{439B9015-B446-4C7E-95F1-923143B86B53}_is1'

function Assert-RegularPath([string]$Path) {
    # Never follow a junction supplied by a service-writable or unrelated tree.
    $current = [IO.Path]::GetFullPath($Path)
    while ($current -and (Test-Path -LiteralPath $current)) {
        if ((Get-Item -LiteralPath $current -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) {
            throw "Reparse points are not supported in setup-owned paths: $current"
        }
        $current = [IO.Path]::GetDirectoryName($current)
    }
}

function Get-OwnedRecord {
    Assert-RegularPath $recordPath
    Assert-RegularPath $bin
    $service = Get-CimInstance Win32_Service -Filter "Name='DNSProxy'"
    if (-not (Test-Path -LiteralPath $recordPath)) {
        if ($service -or (Test-Path -LiteralPath $state)) { throw 'An existing service or state directory is not owned by this setup. Restore DNS and uninstall the portable service first.' }
        return $null
    }
    $record = Get-Content -LiteralPath $recordPath -Raw | ConvertFrom-Json
    if ($record.SchemaVersion -ne 1 -or $record.ManagedBy -ne 'InnoSetup' -or
        $record.ServiceName -ne 'DNSProxy' -or $record.BinaryPath -ne (Join-Path $bin 'dnsp-modern.exe') -or
        -not $service -or $service.PathName -ne $record.Command -or
        $service.StartName -ne 'NT AUTHORITY\LocalService') {
        throw 'Service installation ownership check failed. No service was changed.'
    }
    if (Test-Path -LiteralPath (Join-Path $state 'dns-state.json')) {
        throw "Restore adapter DNS before upgrading or uninstalling: & '$bin\Set-DNSProxyDns.ps1' -Action Restore"
    }
    return $record
}

function Read-SetupOptions {
    $values = @{}
    foreach ($line in Get-Content -LiteralPath $ConfigFile -Encoding UTF8) {
        $pair = $line -split '=', 2
        if ($pair.Count -ne 2 -or $pair[0] -notin @('Service','Port','Upstream','BootstrapAddress','IPv6','AutoStart','StartNow') -or $values.ContainsKey($pair[0])) {
            throw 'Invalid setup options file.'
        }
        $values[$pair[0]] = $pair[1]
    }
    if ($values.Count -ne 7) { throw 'Incomplete setup options.' }
    foreach ($name in @('Service','IPv6','AutoStart','StartNow')) {
        if ($values[$name] -notin @('0','1')) { throw "Invalid $name selection." }
    }
    $arguments = @{
        Port=$values.Port; Upstream=$values.Upstream; BootstrapAddress=$values.BootstrapAddress
        ListenAddress=@('127.0.0.1'); StartupType=$(if ($values.AutoStart -eq '1') {'Automatic'} else {'Manual'})
        NoStart=($values.StartNow -eq '0')
    }
    if ($values.IPv6 -eq '1') { $arguments.ListenAddress += '::1' }
    # Parameter binding and the same validator as the portable installer reject
    # malformed ports, credentials, argument injection and non-numeric bootstrap.
    & (Join-Path $PSScriptRoot 'Install-DNSProxyService.ps1') @arguments -ValidateOnly
    return @{Enabled=($values.Service -eq '1'); Arguments=$arguments}
}

function Assert-FreeListeners($Arguments) {
    $sockets = @()
    try {
        foreach ($address in $Arguments.ListenAddress) {
            $ip = [Net.IPAddress]::Parse($address)
            foreach ($kind in @([Net.Sockets.SocketType]::Dgram, [Net.Sockets.SocketType]::Stream)) {
                $protocol = if ($kind -eq [Net.Sockets.SocketType]::Dgram) { [Net.Sockets.ProtocolType]::Udp } else { [Net.Sockets.ProtocolType]::Tcp }
                $socket = New-Object Net.Sockets.Socket($ip.AddressFamily, $kind, $protocol)
                $sockets += $socket
                $socket.ExclusiveAddressUse = $true
                if ($ip.AddressFamily -eq [Net.Sockets.AddressFamily]::InterNetworkV6) { $socket.DualMode = $false }
                $socket.Bind((New-Object Net.IPEndPoint($ip, [int]$Arguments.Port)))
            }
        }
    } catch { throw "The selected DNS port/listeners are unavailable. Choose another port or resolve the conflict. $_" }
    finally { foreach ($socket in $sockets) { $socket.Dispose() } }
}

function Resume-OwnedService {
    if (Test-Path -LiteralPath $resumePath) {
        $null = Get-OwnedRecord
        Assert-RegularPath $resumePath
        $resume = Get-Content -LiteralPath $resumePath -Raw | ConvertFrom-Json
        if ($resume.WasRunning -eq $true) {
            Start-Service DNSProxy
            $controller = Get-Service DNSProxy
            try { $controller.WaitForStatus('Running', [TimeSpan]::FromSeconds(20)) }
            finally { $controller.Dispose() }
        }
        Remove-Item -LiteralPath $resumePath
    }
}

function Remove-ObsoleteBundleFiles {
    $previous = "$ConfigFile.previous"
    if (-not (Test-Path -LiteralPath $previous)) { return }
    $current = @{}
    foreach ($line in Get-Content -LiteralPath (Join-Path $bin 'SHA256SUMS')) {
        $parts = $line -split '  ', 2
        if ($parts.Count -eq 2) { $current[$parts[1]] = $true }
    }
    foreach ($line in Get-Content -LiteralPath $previous) {
        $parts = $line -split '  ', 2
        if ($parts.Count -ne 2 -or $parts[0] -notmatch '^[a-f0-9]{64}$' -or $current.ContainsKey($parts[1])) { continue }
        $path = [IO.Path]::GetFullPath((Join-Path $bin $parts[1]))
        if (-not $path.StartsWith($bin + '\', [StringComparison]::OrdinalIgnoreCase)) { throw 'Invalid previous bundle manifest path.' }
        Assert-RegularPath $path
        # Delete only obsolete installer-owned bytes; retain modified/unowned data.
        if ((Test-Path -LiteralPath $path -PathType Leaf) -and (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash -eq $parts[0]) {
            Remove-Item -LiteralPath $path
        }
    }
    Remove-Item -LiteralPath $previous
}

try {
    Assert-RegularPath $app
    if ($Action -eq 'Validate') { $null = Read-SetupOptions; exit 0 }
    if ($Action -eq 'Resume') { Resume-OwnedService; exit 0 }
    if ($Action -in @('CheckRemove','Remove')) {
        $record = Get-OwnedRecord
        if ($record -and $Action -eq 'Remove') { & (Join-Path $bin 'Uninstall-DNSProxyService.ps1') -KeepProgramFiles }
        exit 0
    }
    $options = Read-SetupOptions
    $record = Get-OwnedRecord
    if ($Action -eq 'Prepare') {
        if (Test-Path -LiteralPath $app) {
            $registered = Get-ItemProperty -LiteralPath $uninstallKey -ErrorAction SilentlyContinue
            if (-not $registered -or $registered.'Inno Setup: App Path' -ne $app) {
                throw 'The destination already exists outside this installer. Uninstall the portable installation first.'
            }
        }
        if ($record -and -not $options.Enabled) { throw 'Keep the existing service selected. To remove it, uninstall DNSProxy through Windows Apps.' }
        if (-not $record -and $options.Enabled) { Assert-FreeListeners $options.Arguments }
        if (Test-Path -LiteralPath (Join-Path $bin 'SHA256SUMS')) {
            Copy-Item -LiteralPath (Join-Path $bin 'SHA256SUMS') -Destination "$ConfigFile.previous"
        }
        if ($record) {
            $controller = Get-Service DNSProxy
            try {
                if (-not (Test-Path -LiteralPath $resumePath)) {
                    @{WasRunning=($controller.Status -eq 'Running')} | ConvertTo-Json | Set-Content -LiteralPath $resumePath -Encoding UTF8
                }
                Stop-Service DNSProxy
                $controller.WaitForStatus('Stopped', [TimeSpan]::FromSeconds(20))
            } finally { $controller.Dispose() }
        }
    } elseif ($Action -eq 'Apply') {
        if ($record) { Resume-OwnedService }
        elseif ($options.Enabled) {
            $arguments = $options.Arguments
            & (Join-Path $bin 'Install-DNSProxyService.ps1') @arguments -UseInstalledFiles
        }
        Remove-ObsoleteBundleFiles
    }
} catch {
    if ($ResultFile) { [IO.File]::WriteAllText($ResultFile, [string]$_) }
    Write-Error -ErrorAction Continue $_
    exit 1
}
