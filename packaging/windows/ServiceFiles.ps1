# Shared installer cleanup. Called only after the owned service has stopped.
# .NET Framework's recursive Delete attempts to unmount directory junctions and
# can fail with ERROR_INVALID_PARAMETER. Delete each reparse point directly.
function Remove-ServiceDirectory([string]$Path) {
    $directory = [IO.DirectoryInfo]::new($Path)
    if (-not $directory.Exists) { return }
    if ($directory.Attributes -band [IO.FileAttributes]::ReparsePoint) {
        $directory.Delete()
        return
    }
    foreach ($entry in $directory.GetFileSystemInfos()) {
        if ($entry.Attributes -band [IO.FileAttributes]::ReparsePoint) {
            $entry.Delete() # Deletes the link itself, without recursive traversal.
        } elseif ($entry -is [IO.DirectoryInfo]) {
            Remove-ServiceDirectory $entry.FullName
        } else {
            $entry.Attributes = $entry.Attributes -band (-bnot [IO.FileAttributes]::ReadOnly)
            $entry.Delete()
        }
    }
    $directory.Delete()
}

function Get-ResolverServiceCommand($Binary, $Name, $Log, $Options) {
    $command = '"{0}" --service {1} --service-log "{2}" -p {3} -s {4}' -f $Binary,$Name,$Log,$Options.Port,$Options.Upstream
    if ($Options.BootstrapAddress) { $command += ' --bootstrap-address ' + $Options.BootstrapAddress }
    $command += ' --cache-entries 256'
    if ($Options.MetricsPort) { $command += ' -m ' + $Options.MetricsPort }
    foreach ($address in $Options.ListenAddress) { $command += ' -l ' + $address }
    return $command
}

function Enter-ServiceMaintenance([string]$Name) {
    $mutex = [Threading.Mutex]::new($false, "Global\DNSProxy-Service-$Name")
    try {
        try { $owned = $mutex.WaitOne(0) } catch [Threading.AbandonedMutexException] { $owned = $true }
        if (-not $owned) { throw 'Another DNSProxy service maintenance operation is running.' }
        return $mutex
    } catch { $mutex.Dispose(); throw }
}

function Exit-ServiceMaintenance($Mutex) {
    if ($Mutex) { $Mutex.ReleaseMutex(); $Mutex.Dispose() }
}
