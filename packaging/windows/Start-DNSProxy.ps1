[CmdletBinding()]
param(
    [ValidateRange(1, 65535)][int]$Port = 53,
    [string]$Upstream = 'https://cloudflare-dns.com/dns-query',
    [string]$BootstrapAddress = '1.1.1.1',
    [switch]$RunAsAdministrator
)
$ErrorActionPreference = 'Stop'
$uri = [Uri]$Upstream
if (-not $uri.IsAbsoluteUri -or $uri.Scheme -ne 'https' -or $Upstream -match '[\s"]' -or $uri.UserInfo) {
    throw 'Upstream must be an HTTPS URL without credentials, whitespace or quotation marks.'
}
$null = [Net.IPAddress]::Parse($BootstrapAddress)
$binary = Join-Path $PSScriptRoot 'dnsp-modern.exe'
$arguments = @('-l', '127.0.0.1', '-p', "$Port", '-s', $Upstream,
               '--bootstrap-address', $BootstrapAddress, '--cache-entries', '256', '-m', '9090')
if ($RunAsAdministrator) {
    $process = Start-Process -FilePath $binary -ArgumentList $arguments -Verb RunAs -Wait -PassThru
    exit $process.ExitCode
}
& $binary @arguments
exit $LASTEXITCODE
