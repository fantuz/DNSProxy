#Requires -Version 5.1
[CmdletBinding(DefaultParameterSetName='Change')]
param(
    [ValidatePattern('^[A-Za-z0-9_-]{1,64}$')][string]$ServiceName = 'DNSProxy',
    [Parameter(ParameterSetName='Change')][ValidateRange(1,65535)][int]$Port,
    [Parameter(ParameterSetName='Change')][ValidateRange(0,65535)][int]$MetricsPort,
    [Parameter(ParameterSetName='Change')][string]$Upstream,
    [Parameter(ParameterSetName='Change')][AllowEmptyString()][string]$BootstrapAddress,
    [Parameter(ParameterSetName='Change')][string[]]$ListenAddress,
    [Parameter(ParameterSetName='Change')][ValidateSet('Automatic','Manual')][string]$StartupType,
    [Parameter(ParameterSetName='Change')][string]$ProbeName = 'example.com',
    [Parameter(Mandatory,ParameterSetName='Dialog')][switch]$Interactive,
    [Parameter(Mandatory,ParameterSetName='Recovery')][switch]$Recover
)
$ErrorActionPreference = 'Stop'
$program = Join-Path ([Environment]::GetFolderPath('ProgramFiles')) $ServiceName
$state = Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) $ServiceName
$recordPath = Join-Path $state 'installation.json'
$journal = Join-Path $state 'service-change.json'
$identity = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $identity.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    if (-not $Interactive -or $PSCommandPath -ne (Join-Path $program 'bin\Set-DNSProxyService.ps1')) {
        throw 'Open Windows PowerShell as administrator to change the service.'
    }
    $engine = Join-Path ([Environment]::GetFolderPath('Windows')) 'System32\WindowsPowerShell\v1.0\powershell.exe'
    Start-Process -FilePath $engine -Verb RunAs -ArgumentList ('-NoProfile -STA -WindowStyle Hidden -ExecutionPolicy Bypass -File "{0}" -Interactive -ServiceName {1}' -f $PSCommandPath,$ServiceName)
    return
}
. (Join-Path $PSScriptRoot 'ServiceFiles.ps1')
Import-Module (Join-Path $PSScriptRoot 'DNSProxyDns.psm1') -Force

function Get-OwnedService {
    $service = Get-CimInstance Win32_Service -Filter "Name='$ServiceName'"
    if (-not $service -or $service.StartName -ne 'NT AUTHORITY\LocalService') { throw 'Service account or registration differs from the installation record.' }
    return $service
}

function Set-Registration($Service, $Command, $Mode) {
    $result = Invoke-CimMethod -InputObject $Service -MethodName Change -Arguments @{PathName=$Command; StartMode=$Mode}
    if ($result.ReturnValue -ne 0) { throw "Windows service change failed with code $($result.ReturnValue)." }
}

function Set-Running([bool]$Running) {
    $c = Get-Service $ServiceName
    try {
        if ($Running -and $c.Status -ne 'Running') { Start-Service $ServiceName }
        if (-not $Running -and $c.Status -ne 'Stopped') { Stop-Service $ServiceName }
        $target = if ($Running) { 'Running' } else { 'Stopped' }
        $c.WaitForStatus($target, [TimeSpan]::FromSeconds(20))
    } finally { $c.Dispose() }
}

function Read-Exact($Stream, [int]$Count) {
    $bytes = [byte[]]::new($Count)
    for ($offset = 0; $offset -lt $Count; $offset += $n) {
        $n = $Stream.Read($bytes, $offset, $Count-$offset)
        if ($n -eq 0) { throw 'Incomplete DNS reply during the service check.' }
    }
    return ,$bytes
}

function New-ProbeQuestion([string]$Name) {
    $labels = $Name.TrimEnd('.').Split('.')
    $question = [Collections.Generic.List[byte]]::new()
    foreach ($label in $labels) {
        if ($label -notmatch '^[A-Za-z0-9_-]{1,63}$') { throw 'Enter a valid ASCII DNS probe name.' }
        $question.Add([byte]$label.Length)
        $question.AddRange([Text.Encoding]::ASCII.GetBytes($label))
    }
    if ($question.Count -gt 254) { throw 'DNS probe name is too long.' }
    $question.AddRange([byte[]]@(0,0,1,0,1))
    return ,$question.ToArray()
}

function Test-ServiceDns($Options, [byte[]]$Question) {
    foreach ($address in $Options.ListenAddress) {
        $ip = [Net.IPAddress]::Parse($address)
        $endpoint = [Net.IPEndPoint]::new($ip, $Options.Port)
        foreach ($transport in @('UDP','TCP')) {
            $id = [Guid]::NewGuid().ToByteArray()
            [byte[]]$query = @($id[0],$id[1],1,0,0,1,0,0,0,0,0,0) + $Question
            if ($transport -eq 'UDP') {
                $client = [Net.Sockets.UdpClient]::new($ip.AddressFamily)
                try {
                    $client.Client.ReceiveTimeout = 5000
                    $client.Connect($endpoint)
                    $null = $client.Send($query, $query.Length)
                    $peer = $endpoint
                    $reply = $client.Receive([ref]$peer)
                } finally { $client.Dispose() }
            } else {
                $client = [Net.Sockets.TcpClient]::new($ip.AddressFamily)
                try {
                    if (-not $client.ConnectAsync($ip, $Options.Port).Wait(5000)) { throw 'DNS/TCP connect timed out.' }
                    $stream = $client.GetStream()
                    $stream.ReadTimeout = 5000
                    $stream.WriteTimeout = 5000
                    [byte[]]$frame = @(($query.Length -shr 8),($query.Length -band 255)) + $query
                    $stream.Write($frame, 0, $frame.Length)
                    $size = Read-Exact $stream 2
                    $reply = Read-Exact $stream (256 * $size[0] + $size[1])
                } finally { $client.Dispose() }
            }
            if ($reply.Length -lt $query.Length -or $reply[0] -ne $id[0] -or $reply[1] -ne $id[1] -or
                ($reply[2] -band 250) -ne 128 -or ($reply[3] -band 15) -notin @(0,3) -or
                $reply[4] -ne 0 -or $reply[5] -ne 1) { throw "DNS health check failed on $transport $endpoint." }
            for ($i = 0; $i -lt $Question.Length; $i++) {
                if ($reply[12+$i] -ne $Question[$i]) { throw 'DNS health reply contained a different question.' }
            }
        }
    }
}

function Restore-Change($Change) {
    $service = Get-OwnedService
    if ($Change.Before.BinaryPath -ne $record.BinaryPath -or $Change.Before.ServiceName -ne $ServiceName -or
        $service.PathName -cnotin @($Change.Before.Command,$Change.AfterCommand) -or
        $record.Command -cnotin @($Change.Before.Command,$Change.AfterCommand)) { throw 'The service changed outside this operation. Inspect the saved recovery record.' }
    Set-Running $false
    Set-Registration $service $Change.Before.Command $Change.BeforeMode
    Set-Running $Change.WasRunning
    Write-DnsState $recordPath $Change.Before
    Remove-Item -LiteralPath $journal
}

function Show-ServiceOptions($Options) {
    Add-Type -AssemblyName System.Windows.Forms
    $form = [Windows.Forms.Form]::new()
    $form.Text = 'Modify DNSProxy service'
    $form.AutoSize = $true
    $form.AutoSizeMode = 'GrowAndShrink'
    $form.StartPosition = 'CenterScreen'
    $grid = [Windows.Forms.TableLayoutPanel]::new()
    $grid.AutoSize = $true
    $grid.Padding = [Windows.Forms.Padding]::new(14)
    $grid.ColumnCount = 2
    $form.Controls.Add($grid)
    $fields = [ordered]@{Port='DNS port'; MetricsPort='Metrics port (0 disables)'; Upstream='HTTPS upstream URL';
        BootstrapAddress='Bootstrap IP'; ListenAddress='Loopback addresses (comma separated)'; StartupType='Startup type'; ProbeName='DNS health check name'}
    $boxes = @{}
    foreach ($key in $fields.Keys) {
        $label = [Windows.Forms.Label]::new()
        $label.Text = $fields[$key]
        $label.AutoSize = $true
        if ($key -eq 'StartupType') {
            $field = [Windows.Forms.ComboBox]::new()
            $field.DropDownStyle = 'DropDownList'
            $field.Items.AddRange(@('Automatic','Manual'))
        } else { $field = [Windows.Forms.TextBox]::new() }
        $field.Width = 310
        $field.Text = @($Options[$key]) -join ','
        $grid.Controls.Add($label)
        $grid.Controls.Add($field)
        $boxes[$key] = $field
    }
    foreach ($name in @('Cancel','Apply')) {
        $button = [Windows.Forms.Button]::new()
        $button.Text = $name
        if ($name -eq 'Apply') { $button.DialogResult = 'OK'; $form.AcceptButton = $button }
        else { $button.DialogResult = 'Cancel'; $form.CancelButton = $button }
        $grid.Controls.Add($button)
    }
    try {
        if ($form.ShowDialog() -ne 'OK') { return $false }
        foreach ($key in $fields.Keys) { $Options[$key] = $boxes[$key].Text.Trim() }
        $Options.ListenAddress = @($Options.ListenAddress -split '\s*,\s*')
        return $true
    } finally { $form.Dispose() }
}

$maintenance = $lock = $null
try {
    $maintenance = Enter-ServiceMaintenance $ServiceName
    $record = Get-Content -LiteralPath $recordPath -Raw | ConvertFrom-Json
    $bin = if ($record.ManagedBy -eq 'InnoSetup' -and $ServiceName -eq 'DNSProxy') { Join-Path $program 'bin' }
           elseif (-not $record.ManagedBy -or $record.ManagedBy -eq 'PowerShell') { $program }
           else { throw 'Unsupported installation ownership record.' }
    if ($record.SchemaVersion -ne 1 -or $record.ServiceName -ne $ServiceName -or
        $record.BinaryPath -ne (Join-Path $bin 'dnsp-modern.exe') -or $PSScriptRoot -ne $bin) { throw 'Run the installed service settings tool for this service.' }
    $lock = [IO.File]::Open((Join-Path $state 'dns.lock'), 'OpenOrCreate', 'ReadWrite', 'None')
    if (Test-Path -LiteralPath (Join-Path $state 'setup-resume.json')) { throw 'Finish the pending installer operation first.' }
    if (Test-Path -LiteralPath $journal) {
        $pending = Get-Content -LiteralPath $journal -Raw | ConvertFrom-Json
        Restore-Change $pending
        if ($Recover) { return }
        $record = Get-Content -LiteralPath $recordPath -Raw | ConvertFrom-Json
    }
    if ($Recover) { return }
    $svc = Get-OwnedService
    if ($svc.PathName -cne $record.Command -or $svc.State -notin @('Running','Stopped') -or $svc.StartMode -notin @('Auto','Manual')) {
        throw 'The registered service command or state differs from the supported installation.'
    }
    $mode = if ($svc.StartMode -eq 'Auto') { 'Automatic' } else { 'Manual' }
    $options = @{Port=$record.Port; MetricsPort=[int]$record.MetricsPort; Upstream=$record.Upstream;
        BootstrapAddress=$record.BootstrapAddress; ListenAddress=@($record.ListenAddress); StartupType=$mode; ProbeName='example.com'}
    $log = Join-Path $state 'logs\service.log'
    $prefix = Get-ResolverServiceCommand $record.BinaryPath $ServiceName $log $options
    if (-not $record.Command.StartsWith($prefix,[StringComparison]::Ordinal)) { throw 'Unrecognized service command. Inspect the registered settings.' }
    $suffix = $record.Command.Substring($prefix.Length)
    if ($suffix -and -not $suffix.StartsWith(' "--blocklist" ')) { throw 'Unrecognized service options after the registered listeners.' }
    if ($Interactive) {
        if (-not (Show-ServiceOptions $options)) { return }
    } else {
        foreach ($key in @('Port','MetricsPort','Upstream','BootstrapAddress','ListenAddress','StartupType','ProbeName')) {
            if ($PSBoundParameters.ContainsKey($key)) { $options[$key] = $PSBoundParameters[$key] }
        }
    }
    $question = New-ProbeQuestion $options.ProbeName
    $options.Remove('ProbeName')
    if (([Uri]$options.Upstream).Host -ne ([Uri]$record.Upstream).Host -and $options.BootstrapAddress -eq $record.BootstrapAddress -and
        -not $PSBoundParameters.ContainsKey('BootstrapAddress') -and $options.BootstrapAddress) {
        throw 'Supply the bootstrap IP for the new upstream hostname, or explicitly clear it.'
    }
    & (Join-Path $bin 'Install-DNSProxyService.ps1') @options -ValidateOnly
    $options.Port = [int]$options.Port
    $options.MetricsPort = [int]$options.MetricsPort
    $adapterState = Join-Path $state 'dns-state.json'
    if (Test-Path -LiteralPath $adapterState) {
        $dns = Read-DnsState $adapterState
        if ($dns.Phase -ne 'Active' -or $options.Port -ne 53 -or $options.StartupType -ne 'Automatic' -or
            '127.0.0.1' -notin $options.ListenAddress -or '::1' -notin $options.ListenAddress -or
            (-not $options.BootstrapAddress -and ([Uri]$options.Upstream).HostNameType -eq 'Dns')) {
            throw 'Keep the active adapter DNS service on both loopback addresses at port 53 with automatic startup and independent upstream resolution.'
        }
    }
    $command = (Get-ResolverServiceCommand $record.BinaryPath $ServiceName $log $options) + $suffix
    if ($command -ceq $record.Command -and $mode -eq $options.StartupType) { return }
    $current = if ($svc.State -eq 'Running') { $record } else { $null }
    Assert-FreeListeners $options $current
    $change = @{Before=$record; BeforeMode=$mode; AfterCommand=$command; WasRunning=($svc.State -eq 'Running')}
    Write-DnsState $journal $change
    try {
        Set-Running $false
        Set-Registration $svc $command $options.StartupType
        Set-Running $true
        Test-ServiceDns $options $question
        if (-not $change.WasRunning) { Set-Running $false }
        $updated = Get-Content -LiteralPath $recordPath -Raw | ConvertFrom-Json
        foreach ($key in @('Port','MetricsPort','ListenAddress','Upstream','BootstrapAddress')) {
            $updated | Add-Member -NotePropertyName $key -NotePropertyValue $options[$key] -Force
        }
        $updated.Command = $command
        Write-DnsState $recordPath $updated
        Remove-Item -LiteralPath $journal
    } catch {
        $failure = $_
        Restore-Change $change
        throw "Service modification failed. Previous settings restored. $failure"
    }
    if ($Interactive) { [void][Windows.Forms.MessageBox]::Show('Service settings applied and DNS verified.', 'DNSProxy') }
} catch {
    if ($Interactive) {
        Add-Type -AssemblyName System.Windows.Forms
        [void][Windows.Forms.MessageBox]::Show([string]$_, 'DNSProxy service settings')
    }
    throw
} finally {
    if ($lock) { $lock.Dispose() }
    Exit-ServiceMaintenance $maintenance
}
