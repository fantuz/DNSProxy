# Runs in Windows PowerShell 5.1. Synthetic adapters, real durable state files.
# OS command boundaries are replaced; no hosted-runner network is reconfigured.
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
Import-Module (Join-Path $PSScriptRoot '../packaging/windows/DNSProxyDns.psm1') -Force
$root = Join-Path ([IO.Path]::GetTempPath()) ('dnsp-dns-' + [Guid]::NewGuid())
$null = New-Item -ItemType Directory $root
$path = Join-Path $root 'state.json'
$guid = '12345678-1234-1234-1234-123456789abc'
function Assert($ok, [string]$message) { if (-not $ok) { throw $message } }
function Fails([scriptblock]$code) {
    $failed = $false
    try { & $code } catch { $failed = $true }
    Assert $failed 'Expected operation to fail'
}
function Reset-Fixture {
    Remove-Item -LiteralPath $path -ErrorAction SilentlyContinue
    $script:settings = @{
        IPv4=@{Mode='Automatic'; Servers=@()}
        IPv6=@{Mode='Static'; Servers=@('2001:db8::2','2001:db8::1')}
    }
    $script:armed = $false; $script:writes = 0; $script:healthCalls = 0
    $script:failWrite = 0; $script:failHealth = 0; $script:failArm = $false
    $script:backend = @{
        Read = { param($g,$f) Assert ($g -eq $guid) 'Unexpected adapter identity'; return $script:settings[$f] }
        Write = { param($g,$f,$s)
            $script:writes++
            Assert ($script:armed) 'DNS changed without durable recovery task'
            Assert (Test-Path $path) 'DNS changed without durable snapshot'
            if ($script:writes -eq $script:failWrite) { throw 'Injected write failure' }
            $script:settings[$f] = $s
        }
        Arm = { if ($script:failArm) { throw 'Injected task failure' }; $script:armed = $true }
        Disarm = { $script:armed = $false }
        Health = { $script:healthCalls++; if ($script:healthCalls -eq $script:failHealth) { throw 'Injected health failure' } }
    }
}
function Assert-Original {
    Assert ($script:settings.IPv4.Mode -eq 'Automatic') 'DHCP mode not restored'
    Assert (@($script:settings.IPv4.Servers).Count -eq 0) 'DHCP DNS addresses were pinned'
    Assert (($script:settings.IPv6.Servers -join ',') -eq '2001:db8::2,2001:db8::1') 'IPv6 static order not restored'
}
try {
    Reset-Fixture
    Enable-DnsTransaction $path @($guid) $backend
    Assert ((Read-DnsState $path).Phase -eq 'Active') 'Missing committed state'
    Assert (-not $script:armed) 'Committed transaction kept watchdog active'
    Assert ($script:settings.IPv4.Servers[0] -eq '127.0.0.1') 'Wrong IPv4 target'
    Assert ($script:settings.IPv6.Servers[0] -eq '::1') 'Wrong IPv6 target'
    $snapshot = Get-Content $path -Raw
    Fails { Enable-DnsTransaction $path @($guid) $backend }
    Assert ((Get-Content $path -Raw) -eq $snapshot) 'Repeat setup replaced recovery state'
    $script:armed = $true # manual restore also operates with a durable state file
    Restore-DnsTransaction $path $backend
    Assert-Original
    Assert (-not (Test-Path $path)) 'Successful restore retained state'

    foreach ($failure in @('write','health','arm')) {
        Reset-Fixture
        switch ($failure) {
            write { $script:failWrite = 2 }
            health { $script:failHealth = 2 }
            arm { $script:failArm = $true }
        }
        Fails { Enable-DnsTransaction $path @($guid) $backend }
        Assert-Original
        Assert (-not (Test-Path $path)) "Failed $failure transaction retained completed state"
    }
    Reset-Fixture
    $script:failHealth = 1
    Fails { Enable-DnsTransaction $path @($guid) $backend }
    Assert ($script:writes -eq 0 -and -not (Test-Path $path)) 'Preflight changed settings'

    Reset-Fixture
    Enable-DnsTransaction $path @($guid) $backend
    $script:settings.IPv4 = @{Mode='Static'; Servers=@('192.0.2.4')}
    $script:armed = $true
    Fails { Restore-DnsTransaction $path $backend }
    Assert ($script:settings.IPv4.Servers[0] -eq '192.0.2.4') 'Restore overwrote administrator drift'
    Assert (($script:settings.IPv6.Servers -join ',') -eq '2001:db8::2,2001:db8::1') 'Other family not recovered'
    Assert (Test-Path $path) 'Incomplete restore lost its record'
    $script:settings.IPv4 = @{Mode='Static'; Servers=@('127.0.0.1')}
    Restore-DnsTransaction $path $backend
    Assert-Original

    # A killed process leaves a Pending snapshot and only some writes applied.
    Reset-Fixture
    Enable-DnsTransaction $path @($guid) $backend
    $saved = Get-Content $path -Raw | ConvertFrom-Json
    $saved.Phase = 'Pending'
    $saved | ConvertTo-Json -Depth 12 | Set-Content $path
    $script:settings.IPv6 = @{Mode='Static'; Servers=@('2001:db8::2','2001:db8::1')}
    $script:armed = $true
    Restore-DnsTransaction $path $backend
    Assert-Original
    Write-Output 'Windows DNS transaction checks passed (apply/restore, DHCP, IPv6, write/health/task failure, drift and interrupted setup).'
} finally { Remove-Item -LiteralPath $root -Recurse -Force }
