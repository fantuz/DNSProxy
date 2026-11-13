#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding()]
param(
    [ValidatePattern('^[A-Za-z0-9_-]{1,64}$')][string]$ServiceName = 'DNSProxy',
    [ValidateRange(1,65535)][int]$Port = 53,
    [string[]]$ListenAddress = @('127.0.0.1', '::1'),
    [string]$Upstream = 'https://cloudflare-dns.com/dns-query',
    [string]$BootstrapAddress = '1.1.1.1',
    [switch]$NoStart
)
$ErrorActionPreference = 'Stop'
$uri = [Uri]$Upstream
if (-not $uri.IsAbsoluteUri -or $uri.Scheme -ne 'https' -or $Upstream -match '[\s"]' -or $uri.UserInfo) {
    throw 'Use an HTTPS upstream URL without credentials, whitespace, or quotation marks.'
}
$null = [Net.IPAddress]::Parse($BootstrapAddress)
if ($ListenAddress.Count -lt 1 -or $ListenAddress.Count -gt 8) { throw 'Choose one to eight listen addresses.' }
foreach ($address in $ListenAddress) {
    if (-not [Net.IPAddress]::IsLoopback([Net.IPAddress]::Parse($address))) {
        throw 'The managed local service accepts loopback listeners only.'
    }
}
$program = Join-Path $env:ProgramFiles $ServiceName
$state = Join-Path $env:ProgramData $ServiceName
if ((Get-Service -Name $ServiceName -ErrorAction SilentlyContinue) -or
    (Test-Path -LiteralPath $program) -or (Test-Path -LiteralPath $state)) {
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
    Set-Acl -LiteralPath $Path -AclObject $acl
}
$created = $false
$programCreated = $false
$stateCreated = $false
try {
    $null = New-Item -ItemType Directory -Path $program
    $programCreated = $true
    Protect-Directory $program
    $null = New-Item -ItemType Directory -Path $state
    $stateCreated = $true
    Protect-Directory $state
    $logs = Join-Path $state 'logs'
    $null = New-Item -ItemType Directory -Path $logs
    Protect-Directory $logs -ServiceWrite
    Get-ChildItem -LiteralPath $PSScriptRoot | Copy-Item -Destination $program -Recurse
    $binary = Join-Path $program 'dnsp-modern.exe'
    $log = Join-Path $logs 'service.log'
    # Every configurable argument is validated above; paths are quoted separately.
    $command = '"{0}" --service {1} --service-log "{2}" -p {3} -s {4} --bootstrap-address {5} --cache-entries 256' -f $binary,$ServiceName,$log,$Port,$Upstream,$BootstrapAddress
    foreach ($address in $ListenAddress) { $command += ' -l ' + $address }
    $credential = New-Object Management.Automation.PSCredential('NT AUTHORITY\LocalService', (New-Object Security.SecureString))
    $controller = New-Service -Name $ServiceName -BinaryPathName $command -StartupType Automatic -Credential $credential -DisplayName "DNSProxy ($ServiceName)"
    $created = $true
    $controller.Dispose()
    & sc.exe failure $ServiceName reset= 86400 actions= 'restart/3000/restart/10000/none/0'
    if ($LASTEXITCODE) { throw "Recovery configuration failed: $LASTEXITCODE" }
    & sc.exe failureflag $ServiceName 0
    if ($LASTEXITCODE) { throw "Failure flag configuration failed: $LASTEXITCODE" }
    # State is not service-writable and is used to verify ownership on uninstall.
    @{ SchemaVersion=1; ServiceName=$ServiceName; BinaryPath=$binary; Command=$command; Port=$Port;
       ListenAddress=$ListenAddress; BootstrapAddress=$BootstrapAddress; Upstream=$Upstream } |
        ConvertTo-Json -Depth 4 | Set-Content -LiteralPath (Join-Path $state 'installation.json') -Encoding UTF8
    if (-not $NoStart) {
        Start-Service $ServiceName
        (Get-Service $ServiceName).WaitForStatus('Running', [TimeSpan]::FromSeconds(15))
    }
    Get-Service $ServiceName
    Write-Output "Log: $log"
} catch {
    if ($created) {
        Stop-Service $ServiceName -ErrorAction SilentlyContinue
        & sc.exe delete $ServiceName | Out-Null
    }
    # Only folders created by this invocation are removed; pre-existing paths were rejected.
    for ($attempt=0; $attempt -lt 20; $attempt++) {
        if ($programCreated) { Remove-Item -LiteralPath $program -Recurse -Force -ErrorAction SilentlyContinue }
        if ($stateCreated) { Remove-Item -LiteralPath $state -Recurse -Force -ErrorAction SilentlyContinue }
        if ((-not $programCreated -or -not (Test-Path -LiteralPath $program)) -and
            (-not $stateCreated -or -not (Test-Path -LiteralPath $state))) { break }
        Start-Sleep -Milliseconds 100
    }
    throw
}
