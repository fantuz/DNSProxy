#Requires -Version 5.1
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][ValidateSet('amd64','arm64')][string]$Architecture,
    [string]$GuiBundleDir = ''
)
$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot
$version = (Get-Content -LiteralPath (Join-Path $root 'VERSION') -Raw).Trim()
if ($version -notmatch '^\d+\.\d+\.\d+$') { throw 'Invalid VERSION.' }
$temporary = if ($env:RUNNER_TEMP) { $env:RUNNER_TEMP } else { [IO.Path]::GetTempPath() }
$compilerDirectory = Join-Path $temporary 'dnsp-inno-6.6.1'
$compiler = Join-Path $compilerDirectory 'ISCC.exe'
# Pin the official compiler independently of runner image changes. The same x86
# build tool can compile either payload and runs on ARM64 under Windows emulation.
if (-not (Test-Path -LiteralPath $compiler)) {
    $setup = Join-Path $temporary 'innosetup-6.6.1.exe'
    Invoke-WebRequest -UseBasicParsing -Uri 'https://github.com/jrsoftware/issrc/releases/download/is-6_6_1/innosetup-6.6.1.exe' -OutFile $setup
    if ((Get-FileHash -LiteralPath $setup -Algorithm SHA256).Hash -ne 'd243ce440c02705530699554fb9612b9b2bd7a2a90629cdb7f41e66f5faeb91f') {
        throw 'The official Inno Setup download did not match its pinned SHA-256.'
    }
    $process = Start-Process -FilePath $setup -ArgumentList @('/VERYSILENT','/SUPPRESSMSGBOXES','/NORESTART','/SP-','/NOICONS',"/DIR=`"$compilerDirectory`"") -Wait -PassThru
    if ($process.ExitCode -ne 0) { throw "Compiler installation failed: $($process.ExitCode)" }
}
$extra = @()
$suffix = ''
if ($GuiBundleDir) {
    $GuiBundleDir = [IO.Path]::GetFullPath($GuiBundleDir)
    $source = (& git -C $root rev-parse HEAD).Trim()
    if ($LASTEXITCODE) { throw 'Cannot identify the checked-out source.' }
    & python "$root\scripts\build-windows-gui-bundle.py" --validate-bundle $GuiBundleDir --version $version --source-sha $source --architecture $Architecture
    if ($LASTEXITCODE) { throw 'The desktop bundle does not match this source/version.' }
    $extra += "/DGuiBundleDir=$GuiBundleDir"
    $suffix = '-gui'
}
& $compiler "/DBundleDir=$root\dist\windows" "/DOutputDir=$root\dist" "/DAppVersion=$version" "/DTargetArch=$Architecture" @extra "$root\packaging\windows\dnsproxy.iss"
if ($LASTEXITCODE) { throw "Installer compilation failed: $LASTEXITCODE" }
$installer = Join-Path $root "dist\dnsp-modern-$version-windows-$Architecture$suffix-setup.exe"
$digest = (Get-FileHash -LiteralPath $installer -Algorithm SHA256).Hash.ToLowerInvariant()
[IO.File]::WriteAllText("$installer.sha256", "$digest  $([IO.Path]::GetFileName($installer))`n")
