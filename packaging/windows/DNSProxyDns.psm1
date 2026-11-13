# Transaction engine. The Windows boundary is supplied by the caller so failure
# recovery can be exercised without changing the CI runner's network adapter.
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Test-DnsSettingEqual($Left, $Right) {
    return ($Left.Mode -ceq $Right.Mode -and
        ((@($Left.Servers) -join '|') -ceq (@($Right.Servers) -join '|')))
}

function Write-DnsState([string]$Path, $State) {
    $temporary = $Path + '.new'
    $bytes = [Text.Encoding]::UTF8.GetBytes(($State | ConvertTo-Json -Depth 12))
    $file = [IO.FileStream]::new($temporary, [IO.FileMode]::Create,
        [IO.FileAccess]::Write, [IO.FileShare]::None, 4096, [IO.FileOptions]::WriteThrough)
    try { $file.Write($bytes, 0, $bytes.Length); $file.Flush($true) } finally { $file.Dispose() }
    if ([IO.File]::Exists($Path)) { [IO.File]::Replace($temporary, $Path, $null) }
    else { [IO.File]::Move($temporary, $Path) }
}

function Read-DnsState([string]$Path) {
    $state = Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json
    if ($state.Version -ne 1 -or $state.Phase -notin @('Pending','Active','Restoring') -or
        @($state.Entries).Count -lt 1) { throw 'Unsupported DNS recovery record; retain it for manual recovery.' }
    foreach ($entry in $state.Entries) {
        $null = [Guid]::Parse($entry.Guid)
        if ($entry.Family -notin @('IPv4','IPv6') -or
            $entry.Before.Mode -notin @('Automatic','Static') -or $entry.After.Mode -ne 'Static' -or
            (@($entry.After.Servers) -join ',') -ne $(if ($entry.Family -eq 'IPv4') {'127.0.0.1'} else {'::1'})) {
            throw 'Invalid DNS recovery record; no adapter was changed.'
        }
        foreach ($address in $entry.Before.Servers) { $null = [Net.IPAddress]::Parse($address) }
    }
    return $state
}

function Restore-DnsTransaction([string]$Path, [hashtable]$Backend) {
    if (-not (Test-Path -LiteralPath $Path)) { & $Backend.Disarm; return }
    $state = Read-DnsState $Path
    $state.Phase = 'Restoring'
    Write-DnsState $Path $state
    $failures = @()
    # Restore independently: one disconnected/replaced adapter must not prevent
    # recovery of other adapters. GUIDs, never saved interface indexes, identify them.
    foreach ($entry in $state.Entries) {
        try {
            $current = & $Backend.Read $entry.Guid $entry.Family
            if (Test-DnsSettingEqual $current $entry.Before) { continue }
            if (-not (Test-DnsSettingEqual $current $entry.After)) {
                throw 'DNS configuration changed outside DNSProxy; refusing to overwrite it.'
            }
            & $Backend.Write $entry.Guid $entry.Family $entry.Before
            if (-not (Test-DnsSettingEqual (& $Backend.Read $entry.Guid $entry.Family) $entry.Before)) {
                throw 'Restored DNS configuration could not be verified.'
            }
        } catch { $failures += "$($entry.Guid)/$($entry.Family): $_" }
    }
    if ($failures.Count) { throw ($failures -join "`n") }
    & $Backend.Disarm
    Remove-Item -LiteralPath $Path
}

function Enable-DnsTransaction([string]$Path, [string[]]$AdapterGuids, [hashtable]$Backend) {
    if (Test-Path -LiteralPath $Path) { throw 'DNS recovery state already exists. Restore it before starting a new transaction.' }
    & $Backend.Health
    $entries = @()
    foreach ($guid in ($AdapterGuids | Select-Object -Unique)) {
        foreach ($family in @('IPv4','IPv6')) {
            $before = & $Backend.Read $guid $family
            $after = @{Mode='Static'; Servers=@($(if ($family -eq 'IPv4') {'127.0.0.1'} else {'::1'}))}
            # Already-loopback DNS with no ownership record cannot be safely adopted.
            if (Test-DnsSettingEqual $before $after) { throw 'Adapter already points to DNSProxy without a recovery record.' }
            $entries += @{Guid=$guid; Family=$family; Before=$before; After=$after}
        }
    }
    if (-not $entries.Count) { throw 'Select at least one physical Ethernet or Wi-Fi adapter.' }
    $state = @{Version=1; Phase='Pending'; Deadline=[DateTime]::UtcNow.AddMinutes(2).ToString('o'); Entries=$entries}
    Write-DnsState $Path $state
    try {
        # The task is durable and administrator-owned before the first DNS write.
        & $Backend.Arm
        foreach ($entry in $entries) {
            if (-not (Test-DnsSettingEqual (& $Backend.Read $entry.Guid $entry.Family) $entry.Before)) {
                throw 'DNS settings changed during preflight; aborting.'
            }
            & $Backend.Write $entry.Guid $entry.Family $entry.After
            if (-not (Test-DnsSettingEqual (& $Backend.Read $entry.Guid $entry.Family) $entry.After)) {
                throw 'Applied DNS settings could not be verified.'
            }
        }
        & $Backend.Health
        if ([DateTime]::UtcNow -ge [DateTime]::Parse($state.Deadline).ToUniversalTime()) { throw 'DNS configuration deadline expired.' }
        $state.Phase = 'Active'
        Write-DnsState $Path $state
    } catch {
        $original = $_
        try { Restore-DnsTransaction $Path $Backend }
        catch { throw "Setup failed: $original`nRecovery needs attention (record retained): $_" }
        throw $original
    }
    # A leftover task sees Active and does nothing, including after a reboot.
    & $Backend.Disarm
}

Export-ModuleMember -Function Enable-DnsTransaction,Restore-DnsTransaction,Read-DnsState,Test-DnsSettingEqual
