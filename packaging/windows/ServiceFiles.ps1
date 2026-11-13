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
