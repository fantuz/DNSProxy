#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding()]
param(
    [ValidatePattern('^[A-Za-z0-9_-]{1,64}$')][string]$ServiceName = 'DNSProxy',
    [ValidateRange(1,65535)][int]$Port = 53,
    [ValidateRange(0,65535)][int]$MetricsPort = 0,
    [string[]]$ListenAddress = @('127.0.0.1', '::1'),
    [string]$Upstream = 'https://cloudflare-dns.com/dns-query',
    [string]$BootstrapAddress = '1.1.1.1',
    [string[]]$BlocklistFile = @(),
    [string[]]$AllowlistFile = @(),
    [ValidateSet('refused','nxdomain','nodata','null')][string]$BlockResponse = 'refused',
    [ValidateRange(0,86400000)][ValidateScript({ $_ -eq 0 -or $_ -ge 100 })][int]$BlocklistReloadMs = 5000,
    [ValidateSet('Automatic','Manual')][string]$StartupType = 'Automatic',
    [switch]$NoStart,
    # Used by the machine-wide setup wizard, whose files are already installed.
    [switch]$UseInstalledFiles,
    [switch]$ValidateOnly
)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'ServiceFiles.ps1')
$uri = [Uri]$Upstream
if (-not $uri.IsAbsoluteUri -or $uri.Scheme -ne 'https' -or $Upstream -match '[\s"]' -or $uri.UserInfo) {
    throw 'Use an HTTPS upstream URL without credentials, whitespace, or quotation marks.'
}
if ($uri.Fragment -or $uri.Port -lt 1) { throw 'Use an HTTPS endpoint without a fragment and with a valid port.' }
if ($BootstrapAddress) {
    $null = [Net.IPAddress]::Parse($BootstrapAddress)
    if ($uri.HostNameType -in @('IPv4','IPv6') -or $BootstrapAddress.Contains('%')) { throw 'A bootstrap IP requires a hostname and an unscoped IP address.' }
}
if ($MetricsPort -and $MetricsPort -eq $Port) { throw 'DNS and loopback metrics ports must differ.' }
if ($ListenAddress.Count -lt 1 -or $ListenAddress.Count -gt 8) { throw 'Choose one to eight listen addresses.' }
foreach ($address in $ListenAddress) {
    if (-not [Net.IPAddress]::IsLoopback([Net.IPAddress]::Parse($address))) {
        throw 'The managed local service accepts loopback listeners only.'
    }
}
$sources = @($BlocklistFile) + @($AllowlistFile)
if ($sources.Count -gt 64 -or ($AllowlistFile.Count -and -not $BlocklistFile.Count)) {
    throw 'Use at least one blocklist and at most 64 policy files in total.'
}
$total = 0L
foreach ($path in $sources) {
    $item = Get-Item -LiteralPath $path
    if ($item.PSIsContainer -or $item.PSProvider.Name -ne 'FileSystem') { throw 'Policy inputs must be regular files.' }
    $total += $item.Length
    if ($total -gt 64MB) { throw 'Policy files exceed 64 MiB in total.' }
}
if ($ValidateOnly) { return }
$program = Join-Path $env:ProgramFiles $ServiceName
if ($UseInstalledFiles) {
    $expected = Join-Path $program 'bin'
    if ($ServiceName -ne 'DNSProxy' -or [IO.Path]::GetFullPath($PSScriptRoot) -ne $expected -or $sources.Count) {
        throw 'Setup registration requires the installed DNSProxy bin directory, without portable policy inputs.'
    }
    $program = $expected
}
$state = Join-Path $env:ProgramData $ServiceName
if ((Get-Service -Name $ServiceName -ErrorAction SilentlyContinue) -or
    ((Test-Path -LiteralPath $program) -and -not $UseInstalledFiles) -or (Test-Path -LiteralPath $state)) {
    throw 'Service or managed directories already exist. Use the uninstall script before replacing this installation.'
}
if (-not (Test-Path -LiteralPath (Join-Path $PSScriptRoot 'dnsp-modern.exe'))) { throw 'Run this script from the extracted portable bundle.' }
# Executable/DLL/config files are administrator-owned; LocalService can only read
# them. Only its separate log directory is writable by the service account.
function Protect-Directory([string]$Path, [switch]$ServiceWrite) {
    $acl = New-Object Security.AccessControl.DirectorySecurity
    $acl.SetAccessRuleProtection($true, $false)
    foreach ($entry in @(@('S-1-5-18','FullControl'), @('S-1-5-32-544','FullControl'),
                         @('S-1-5-19', $(if ($ServiceWrite) {'Modify'} else {'ReadAndExecute'})))) {
        $sid = New-Object Security.Principal.SecurityIdentifier($entry[0])
        $rule = New-Object Security.AccessControl.FileSystemAccessRule($sid, $entry[1], 'ContainerInherit,ObjectInherit', 'None', 'Allow')
        $acl.AddAccessRule($rule)
    }
    if ($UseInstalledFiles -and -not $ServiceWrite) {
        $sid = New-Object Security.Principal.SecurityIdentifier('S-1-5-32-545')
        $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($sid, 'ReadAndExecute', 'ContainerInherit,ObjectInherit', 'None', 'Allow')))
    }
    Set-Acl -LiteralPath $Path -AclObject $acl
}
$created = $false
$programCreated = $false
$stateCreated = $false
try {
    if (-not $UseInstalledFiles) {
        $null = New-Item -ItemType Directory -Path $program
        $programCreated = $true
    }
    Protect-Directory $program
    $null = New-Item -ItemType Directory -Path $state
    $stateCreated = $true
    Protect-Directory $state
    $logs = Join-Path $state 'logs'
    $null = New-Item -ItemType Directory -Path $logs
    Protect-Directory $logs -ServiceWrite
    if (-not $UseInstalledFiles) { Get-ChildItem -LiteralPath $PSScriptRoot | Copy-Item -Destination $program -Recurse }
    $binary = Join-Path $program 'dnsp-modern.exe'
    $policyArgs = @()
    if ($sources.Count) {
        $policyDirectory = Join-Path $program 'policy'
        $null = New-Item -ItemType Directory -Path $policyDirectory
        for ($i=0; $i -lt $sources.Count; $i++) {
            $target = Join-Path $policyDirectory "list-$i.txt"
            Copy-Item -LiteralPath $sources[$i] -Destination $target
            $policyArgs += $(if ($i -lt $BlocklistFile.Count) {'--blocklist'} else {'--allowlist'}), $target
        }
        & $binary @policyArgs --check-blocklists
        if ($LASTEXITCODE) { throw 'Policy validation failed; no service was installed.' }
    }
    $log = Join-Path $logs 'service.log'
    $options = @{Port=$Port; Upstream=$Upstream; BootstrapAddress=$BootstrapAddress; MetricsPort=$MetricsPort; ListenAddress=$ListenAddress}
    $command = Get-ResolverServiceCommand $binary $ServiceName $log $options
    foreach ($argument in $policyArgs) { $command += ' "' + $argument + '"' }
    if ($sources.Count) { $command += ' --block-response ' + $BlockResponse + ' --blocklist-reload-ms ' + $BlocklistReloadMs }
    $credential = New-Object Management.Automation.PSCredential('NT AUTHORITY\LocalService', (New-Object Security.SecureString))
    $controller = New-Service -Name $ServiceName -BinaryPathName $command -StartupType $StartupType -Credential $credential -DisplayName "DNSProxy ($ServiceName)"
    $created = $true
    $controller.Dispose()
    & sc.exe failure $ServiceName reset= 86400 actions= 'restart/3000/restart/10000/none/0'
    if ($LASTEXITCODE) { throw "Recovery configuration failed: $LASTEXITCODE" }
    & sc.exe failureflag $ServiceName 1
    if ($LASTEXITCODE) { throw "Failure flag configuration failed: $LASTEXITCODE" }
    # State is not service-writable and is used to verify ownership on uninstall.
    @{ SchemaVersion=1; ServiceName=$ServiceName; BinaryPath=$binary; Command=$command; Port=$Port;
       ListenAddress=$ListenAddress; BootstrapAddress=$BootstrapAddress; Upstream=$Upstream; MetricsPort=$MetricsPort;
       ManagedBy=$(if ($UseInstalledFiles) {'InnoSetup'} else {'PowerShell'}) } |
        ConvertTo-Json -Depth 4 | Set-Content -LiteralPath (Join-Path $state 'installation.json') -Encoding UTF8
    if (-not $NoStart) {
        Start-Service $ServiceName
        (Get-Service $ServiceName).WaitForStatus('Running', [TimeSpan]::FromSeconds(15))
    }
    Get-Service $ServiceName
    Write-Output "Log: $log"
} catch {
    $failure = $_
    if ($created) {
        Stop-Service $ServiceName -ErrorAction SilentlyContinue
        & sc.exe delete $ServiceName | Out-Null
    }
    # Only folders created by this invocation are removed; pre-existing paths were rejected.
    for ($attempt=0; $attempt -lt 20; $attempt++) {
        if ($programCreated) { try { Remove-ServiceDirectory $program } catch {} }
        if ($stateCreated) { try { Remove-ServiceDirectory $state } catch {} }
        if ((-not $programCreated -or -not (Test-Path -LiteralPath $program)) -and
            (-not $stateCreated -or -not (Test-Path -LiteralPath $state))) { break }
        Start-Sleep -Milliseconds 100
    }
    throw $failure
}
